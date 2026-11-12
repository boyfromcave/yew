#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or https://www.opensource.org/licenses/mit-license.php .
"""YEW-REAL: yewd against a real ycash6 (D-9, any-to-any sends) regtest stack.

node 0  plain ycashd wallet: miner, attestor set, YED pool (quotes)
node 1  the pair under test: ycashd -disablewallet backend + yewd + yewd-signer (YEWD_BIN)
node 2  plain ycashd wallet: the receiver of the matrix sends
node 3  plain ycashd wallet: the observer (imports yewd's z_exportwallet dump: the node's view of the same keys)

YCASH6_QA=<ycash6>/qa/rpc-tests ZCASHD=<ycashd> YEWD_BIN_PAIR=<yewd> python yew_real_run.py --tmpdir=... --portseed=...
Phases, in the order given: --phases=addr,matrix,yed,restore (default); also `nodefees` (ycash6's own
z_sendmany over the same 16 shapes); `matrix` after `yed` runs the matrix at the attested price.
"""
import json
import os
import shutil
import sys
import time
from decimal import Decimal

QA = os.environ['YCASH6_QA']
sys.path.insert(0, QA)
YEWD = os.environ['YEWD_BIN_PAIR']
os.environ['YEWD_BIN'] = YEWD

from test_framework import kogany, util, yellowback_util                       # noqa: E402
from test_framework.authproxy import JSONRPCException                         # noqa: E402
from test_framework.test_framework import BitcoinTestFramework                # noqa: E402
from test_framework.util import (                                             # noqa: E402
    VAULT_BRANCH_ID, assert_equal, connect_nodes_bi, nuparams, stop_node, sync_blocks,
    sync_mempools, wait_and_assert_operationid_status, z_sendmany_opid)
from test_framework.yellowback_attest import wait_for_spender                 # noqa: E402
from test_framework.yellowback_util import MIN_MINT, YCASH_UPGRADE_ARGS, activate_yed_late  # noqa: E402

PAIR = 1
_orig_start = util.start_node


def start_node_sel(i, dirname, extra_args=None, *a, **k):
    """YEWD_BIN only for the pair node: the harness checks the variable at each start."""
    if i == PAIR:
        os.environ['YEWD_BIN'] = YEWD
    else:
        os.environ.pop('YEWD_BIN', None)
    try:
        return _orig_start(i, dirname, extra_args, *a, **k)
    finally:
        os.environ['YEWD_BIN'] = YEWD


util.start_node = start_node_sel
yellowback_util.start_node = start_node_sel

ACTIVATION = 210
FALCON = 220
ECC, SAP, FN, SLH = 'ECC', 'Sapling', 'PQ-FN-DSA', 'PQ-SLH-DSA'
KINDS = (ECC, SAP, FN, SLH)
PQ_SEND_LIMIT = 10 * 10**8        # the app's absolute bound on a PQ send's fee (YEW-PR-body: 10 YEC)
OUT = os.environ.get('YEW_REAL_OUT', '.')
RESULTS = {'cells': [], 'balance_checks': [], 'findings': [], 'notes': []}


def zat(x):
    return int((Decimal(str(x)) * 100000000).to_integral_value())


def coins(z):
    return Decimal(z) / 100000000


def save():
    with open(os.path.join(OUT, 'results.json'), 'w') as f:
        json.dump(RESULTS, f, indent=1, default=str)


def note(msg):
    print('NOTE: ' + msg)
    RESULTS['notes'].append(msg)
    save()


def finding(sev, msg):
    print('FINDING %s: %s' % (sev, msg))
    RESULTS['findings'].append((sev, msg))
    save()


class YewRealRun(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 4
        self.setup_clean_chain = True
        self.yed_args = {}

    def add_options(self, parser):
        parser.add_option('--phases', dest='phases', default='addr,matrix,yed,restore')

    def node_args(self, i):
        a = ([] if os.environ.get('YEW_REAL_PRECANOPY') else list(YCASH_UPGRADE_ARGS)) + \
            [nuparams(VAULT_BRANCH_ID, ACTIVATION), '-pqfalconheight=%d' % FALCON, '-exportdir=%s' % self.exportdir, '-txindex']
        return a + self.yed_args.get(i, [])

    def setup_network(self, split=False):
        self.exportdir = os.path.join(self.options.tmpdir, 'export')
        os.makedirs(self.exportdir, exist_ok=True)
        self.nodes = [start_node_sel(i, self.options.tmpdir, self.node_args(i)) for i in range(self.num_nodes)]
        for a, b in self.edges():
            connect_nodes_bi(self.nodes, a, b)
        self.is_network_split = False
        self.sync_all()

    def edges(self):
        return ((0, 1), (0, 2), (0, 3), (1, 2))

    # --- helpers ---
    def backend(self):
        d = os.path.join(self.options.tmpdir, 'node%d' % PAIR, 'backend')
        return kogany.KoganyRPC('http://127.0.0.1:%d/' % kogany.yewd_backend_rpc_port(PAIR),
                                cookie=os.path.join(d, 'regtest', '.cookie'))

    def mine(self, n=1):
        self.sync_all()
        h = self.nodes[0].generate(n)
        self.sync_all()
        return h

    def spk(self, addr):
        return self.nodes[0].validateaddress(addr)['scriptPubKey']

    def kind_node(self, node, addr):
        v = node.validateaddress(addr)
        if v.get('isvalid') and 'pqscheme' in v:
            return {2: FN, 1: SLH}[v['pqscheme']]
        if v.get('isvalid'):
            return ECC
        assert node.z_validateaddress(addr)['isvalid'], addr
        return SAP

    def fee_and_raw(self, txid):
        n0 = self.nodes[0]
        raw = n0.getrawtransaction(txid, 1)
        vin = 0
        prevs = []
        for i in raw['vin']:
            p = n0.getrawtransaction(i['txid'], 1)['vout'][i['vout']]
            prevs.append(p)
            vin += zat(p['value'])
        vout = sum(zat(o['value']) for o in raw['vout'])
        return vin + zat(raw.get('valueBalance', 0)) - vout, raw, prevs

    # --- the oracle: the chain's own UTXO set for a set of scripts (backend blocks + mempool) ---
    def chain_utxos(self, spks):
        """{(txid, n): (spk, zat, height)} of every unspent output paying one of ``spks``, from the backend's
        blocks read whole (getblock 2) and its mempool. No wallet code is involved."""
        b = self.backend()
        tip = b.getblockcount()
        utxo = {}
        spent = set()
        txs = []
        for h in range(1, tip + 1):
            blk = b.getblock(b.getblockhash(h), 2)
            for tx in blk['tx']:
                txs.append((tx, h))
        for txid in b.getrawmempool():
            txs.append((b.getrawtransaction(txid, 1), None))
        for tx, h in txs:
            for i in tx['vin']:
                if 'txid' in i:
                    spent.add((i['txid'], i['vout']))
            for o in tx['vout']:
                if o['scriptPubKey']['hex'] in spks:
                    utxo[(tx['txid'], o['n'])] = (o['scriptPubKey']['hex'], zat(o['value']), h)
        return {k: v for k, v in utxo.items() if k not in spent}

    # --- phase 1 ---
    def phase_addr(self):
        n0, n1, n2, n3 = self.nodes
        b = self.backend()
        print('=== phase addr: node and yewd versions, addresses of every type')
        RESULTS['versions'] = {'backend': b.getnetworkinfo()['subversion'], 'yewd_getinfo': n1.getinfo().get('version')}
        h = n1.help('getnewaddress')
        RESULTS['getnewaddress_help_names_d9'] = ('sqf' in h and 'sqs' in h)
        hb = n0.help('getnewaddress')
        RESULTS['node_getnewaddress_help_names_d9'] = ('sqf' in hb and 'sqs' in hb)
        self.mine(ACTIVATION + 1 - n0.getblockcount())
        src = {ECC: n1.getnewaddress(), SAP: n1.z_getnewaddress('sapling'), SLH: n1.getnewaddress('', 'pqslh')}
        self.mine(FALCON + 2 - n0.getblockcount())
        src[FN] = n1.getnewaddress('', 'pq')
        dst = {ECC: n2.getnewaddress(), SAP: n2.z_getnewaddress('sapling'), SLH: n2.getnewaddress('', 'pqslh'),
               FN: n2.getnewaddress('', 'pq')}
        self.src, self.dst = src, dst
        RESULTS['addresses'] = {'yewd': src, 'node2': dst}
        prefix = {SLH: 'rqs', FN: 'rqf'}
        for k in KINDS:
            a = src[k]
            vy = n1.validateaddress(a) if k != SAP else n1.z_validateaddress(a)
            vb = b.validateaddress(a) if k != SAP else b.z_validateaddress(a)
            v0 = n0.validateaddress(a) if k != SAP else n0.z_validateaddress(a)
            RESULTS.setdefault('validate', {})[k] = {'yewd': vy, 'backend': vb, 'node0': v0}
            assert vb['isvalid'] and v0['isvalid'] and vy['isvalid'], (k, vb, v0, vy)
            if k in prefix:
                if not a.startswith(prefix[k]) or len(a) != 53:
                    finding('HIGH', 'yewd %s address %s lacks the D-9 prefix %s / length 53' % (k, a, prefix[k]))
                for f in ('pqscheme', 'pqschemename', 'pqkeyhash', 'scriptPubKey'):
                    if f in vb and vy.get(f) != vb.get(f):
                        finding('HIGH', 'validateaddress %s field %s: yewd %r, node %r' % (k, f, vy.get(f), vb.get(f)))
                assert_equal(vb['pqscheme'], {SLH: 1, FN: 2}[k])
            for f in vb:
                if f in vy and vy[f] != vb[f] and f not in ('ismine', 'iswatchonly'):
                    finding('MEDIUM', 'validateaddress %s field %s differs: yewd %r node %r' % (k, f, vy[f], vb[f]))
            assert vy.get('ismine', True), (k, vy)
        print(json.dumps(RESULTS['validate'], indent=1, default=str)[:3000])
        save()

    # --- phase 2 ---
    def yewd_view(self):
        n1 = self.nodes[1]
        v = {'z_gettotalbalance': n1.z_gettotalbalance(), 'getwalletinfo': n1.getwalletinfo(),
             'listaddresses': n1.listaddresses()}
        per = {}
        for k in KINDS:
            a = self.src[k]
            per[k] = {'z_getbalance': Decimal(n1.z_getbalance(a))}
            if k == SAP:
                per[k]['unspent'] = sum(Decimal(u['amount']) for u in n1.z_listunspent(1, 9999999, False, [a]))
            else:
                per[k]['unspent'] = sum(Decimal(u['amount']) for u in n1.listunspent(1, 9999999, [a]))
        v['per_address'] = per
        return v

    def oracle_view(self):
        """The node's view: chain UTXOs of yewd's PQ addresses, all of yewd's transparent ECC keys found in the
        dump, and the observer node 3's import of yewd's dump (transparent, PQ, Sapling)."""
        n1, n3 = self.nodes[1], self.nodes[3]
        name = 'dump%d' % int(time.time() * 1000)
        path = n1.z_exportwallet(name)
        o = {'dump': path}
        try:
            r = n3.z_importwallet(path)
            o['import'] = r
        except JSONRPCException as e:
            o['import_error'] = e.error
        o['n3_total'] = n3.z_gettotalbalance(1)
        o['n3_listaddresses'] = n3.listaddresses()
        per = {}
        for k in KINDS:
            a = self.src[k]
            try:
                per[k] = Decimal(n3.z_getbalance(a, 1))
            except JSONRPCException as e:
                per[k] = 'err: %s' % e.error.get('message')
        o['n3_per_address'] = per
        # chain oracle for PQ and the named ECC address
        spks = {self.spk(self.src[k]): k for k in (ECC, FN, SLH)}
        u = self.chain_utxos(set(spks))
        chain = {k: 0 for k in (ECC, FN, SLH)}
        for (_, _), (s, z, h) in u.items():
            if h is not None:
                chain[spks[s]] += z
        o['chain_confirmed_zat'] = chain
        return o

    def compare(self, label):
        y = self.yewd_view()
        o = self.oracle_view()
        rec = {'label': label, 'yewd': y, 'oracle': o, 'agree': True, 'diffs': []}
        for k in (ECC, FN, SLH):
            if zat(y['per_address'][k]['unspent']) != o['chain_confirmed_zat'][k]:
                rec['diffs'].append('%s listunspent %s vs chain %s' % (k, y['per_address'][k]['unspent'], coins(o['chain_confirmed_zat'][k])))
            if zat(y['per_address'][k]['z_getbalance']) != o['chain_confirmed_zat'][k]:
                rec['diffs'].append('%s z_getbalance %s vs chain %s' % (k, y['per_address'][k]['z_getbalance'], coins(o['chain_confirmed_zat'][k])))
        for k in KINDS:
            nv = o['n3_per_address'][k]
            if not isinstance(nv, Decimal) or nv != y['per_address'][k]['z_getbalance']:
                rec['diffs'].append('%s yewd z_getbalance %s vs observer node %s' % (k, y['per_address'][k]['z_getbalance'], nv))
        yt, nt = y['z_gettotalbalance'], o['n3_total']
        for f in ('transparent', 'private', 'total', 'transparent_ecc', 'transparent_pq'):
            if f in nt and str(yt.get(f)) != str(nt.get(f)):
                rec['diffs'].append('z_gettotalbalance.%s yewd %s vs observer node %s' % (f, yt.get(f), nt.get(f)))
        if 'pq_by_scheme' in nt and yt.get('pq_by_scheme') != nt.get('pq_by_scheme'):
            rec['diffs'].append('pq_by_scheme yewd %s vs observer %s' % (yt.get('pq_by_scheme'), nt.get('pq_by_scheme')))
        rec['agree'] = not rec['diffs']
        RESULTS['balance_checks'].append(rec)
        print('  balances (%s): %s %s' % (label, 'AGREE' if rec['agree'] else 'DIFFER', '; '.join(rec['diffs'])))
        save()
        return rec

    def phase_matrix(self):
        n0, n1, n2, n3 = self.nodes
        src, dst = self.src, self.dst
        print('=== phase matrix: fund yewd: five 1-YEC coins at ECC and each PQ address, five 1-YEC notes')
        for _ in range(5):
            for k in (ECC, FN, SLH):
                n0.sendtoaddress(src[k], 1)
        fund = n0.getnewaddress()
        for _ in range(5):
            n0.sendtoaddress(fund, 2)
        self.mine(1)
        for _ in range(5):
            wait_and_assert_operationid_status(n0, z_sendmany_opid(n0, fund, [(src[SAP], 1)]))
        self.mine(1)
        self.compare('funded')
        expect_in = getattr(self, 'expect_in', None) or {k: Decimal(0) for k in KINDS}
        self.expect_in = expect_in
        priced = getattr(self, 'yed_done', False)
        amount = Decimal('0.10')
        for s in KINDS:
            for d in KINDS:
                amount += Decimal('0.01')
                cell = {'src': s, 'dst': d, 'amount': str(amount), 'priced': priced}
                RESULTS['cells'].append(cell)
                try:
                    opid = z_sendmany_opid(n1, src[s], [(dst[d], amount)])
                    txid = wait_and_assert_operationid_status(n1, opid)
                except (JSONRPCException, AssertionError) as e:
                    cell['error'] = getattr(e, 'error', str(e))
                    finding('HIGH', 'yewd z_sendmany %s -> %s failed: %s' % (s, d, cell['error']))
                    save()
                    continue
                cell['txid'] = txid
                sync_mempools(self.nodes)
                cell['accepted'] = txid in n0.getrawmempool() and txid in n2.getrawmempool()
                fee, raw, prevs = self.fee_and_raw(txid)
                cell['fee_zat'] = fee
                cell['size'] = len(n0.getrawtransaction(txid)) // 2
                src_spk = self.spk(src[s]) if s != SAP else None
                in_kinds = sorted({p['scriptPubKey']['type'] for p in prevs})
                cell['input_types'] = in_kinds + (['sapling'] * len(raw.get('vShieldedSpend', [])) and ['sapling-spends:%d' % len(raw.get('vShieldedSpend', []))])
                outs = [(o['scriptPubKey'].get('addresses', [None])[0], zat(o['value']), o['scriptPubKey']['hex']) for o in raw['vout']]
                cell['outputs'] = outs
                cell['shielded_outputs'] = len(raw.get('vShieldedOutput', []))
                # change rule (D-4): PQ source -> change only to the source; Sapling source -> no transparent change;
                # ECC source -> change to an own key (ycash6 default: a fresh key)
                others = [o for o in outs if o[0] != dst[d]]
                if s in (FN, SLH):
                    ok = all(o[2] == src_spk for o in others) and all(p['scriptPubKey']['hex'] == src_spk for p in prevs)
                elif s == SAP:
                    ok = not others and not prevs
                else:
                    ok = all(n1.validateaddress(o[0]).get('ismine') for o in others)
                cell['change_ok'] = ok
                if not ok:
                    finding('HIGH', 'change rule broken %s -> %s txid %s outputs %s' % (s, d, txid, outs))
                if s in (FN, SLH) and fee > PQ_SEND_LIMIT:
                    finding('HIGH', 'PQ send fee %d above the 10 YEC limit (%s -> %s)' % (fee, s, d))
                expect_in[d] += amount
                print('  %-10s -> %-10s %s fee %d size %d accepted %s change_ok %s' % (s, d, amount, fee, cell['size'], cell['accepted'], ok))
                save()
            self.compare('after %s sends (mempool)' % s)
        print('mine the matrix')
        blk = self.mine(1)[0]
        for c in RESULTS['cells']:
            if 'txid' in c and c.get('priced') == priced:
                c['mined'] = c['txid'] in self.backend().getblock(blk)['tx']
                if not c['mined']:
                    finding('HIGH', 'not mined: %s -> %s %s' % (c['src'], c['dst'], c['txid']))
        for d in KINDS:
            got = Decimal(n2.z_getbalance(dst[d]))
            RESULTS.setdefault('receiver', {})[d] = {'expected': str(expect_in[d]), 'node2': str(got)}
            if got != expect_in[d]:
                finding('HIGH', 'receiver %s got %s expected %s' % (d, got, expect_in[d]))
        self.compare('matrix mined')
        save()

    # --- phase 4: YED and vaults ---
    def phase_yed(self):
        print('=== phase yed: activate YED late (node 0 pool), vault_lock from each source, yed_mint, yed_send')
        activate_yed_late(self, [0], self.edges())
        self.yed_done = True
        n0, n1, n2, n3 = self.nodes
        src = self.src
        RESULTS['yed'] = {}
        setid = n0.set_create({'seats': 3, 'unlockthreshold': 2, 'cancelthreshold': 1, 'slashthreshold': 2,
                               'maturity': 2, 'livenesswindow': 50, 'bondmin': 1, 'ratewindow': 20})['setid']
        self.mine(1)
        for k in KINDS:
            p = {'tag': 'TEST', 'setid': setid, 'delay': 5, 'ownerheight': n0.getblockcount() + 1000,
                 'amount': Decimal('0.3'), 'from': src[k]}
            try:
                r = n1.vault_lock(p)
                sync_mempools(self.nodes)
                fee, raw, prevs = self.fee_and_raw(r['txid'])
                RESULTS['yed']['vault_lock_' + k] = {'txid': r['txid'], 'fee': fee, 'accepted': r['txid'] in n0.getrawmempool(),
                                                     'inputs': sorted({p['scriptPubKey']['type'] for p in prevs}),
                                                     'spends': len(raw.get('vShieldedSpend', [])),
                                                     'outs': [(o['scriptPubKey']['type'], str(o['value'])) for o in raw['vout']]}
                print('  vault_lock from %s: %s fee %d' % (k, r['txid'], fee))
            except JSONRPCException as e:
                RESULTS['yed']['vault_lock_' + k] = {'error': e.error}
                finding('HIGH', 'yewd vault_lock from %s refused: %s' % (k, e.error))
            save()
        self.mine(1)
        self.compare('after vault locks')
        # the node's own price for the same PQ-funded locks (node 0's wallet, its own PQ addresses)
        for k, t in ((FN, 'pq'), (SLH, 'pqslh')):
            a = n0.getnewaddress('', t)
            n0.sendtoaddress(a, 1)
            self.mine(1)
            p = {'tag': 'TEST', 'setid': setid, 'delay': 5, 'ownerheight': n0.getblockcount() + 1000,
                 'amount': Decimal('0.3'), 'from': a}
            r = n0.vault_lock(p)
            fee, raw, prevs = self.fee_and_raw(r['txid'])
            RESULTS['yed']['node_vault_lock_' + k] = {'txid': r['txid'], 'fee': fee, 'size': len(n0.getrawtransaction(r['txid'])) // 2}
            mine = RESULTS['yed'].get('vault_lock_' + k, {})
            print('  node vault_lock from %s: fee %d (yewd %s)' % (k, fee, mine.get('fee')))
            if mine.get('fee') is not None and mine['fee'] != fee:
                finding('MEDIUM', 'vault_lock from %s: yewd fee %d, ycash6 fee %d for the same shape' % (k, mine['fee'], fee))
            self.mine(1)
        print('  fund yewd for the mints: 20 YEC at its ECC address, 20 YEC in notes at its Sapling address')
        n0.sendtoaddress(src[ECC], 20)
        fund = n0.getnewaddress()
        n0.sendtoaddress(fund, 21)
        self.mine(1)
        wait_and_assert_operationid_status(n0, z_sendmany_opid(n0, fund, [(src[SAP], 20)]))
        self.mine(1)
        for frm, label in (('', 'default'), (src[ECC], 'ECC'), (src[SAP], 'Sapling')):
            if label == 'ECC':
                n0.sendtoaddress(src[ECC], 20)     # the default mint may have taken the earlier coin
                self.mine(1)
            try:
                res = n1.yed_mint(MIN_MINT, 48, frm, '', False)
                sync_mempools(self.nodes)
                self.mine(1)
                txid = wait_for_spender(n1, res['carrierTxid'])
                self.mine(1)
                info = n1.yed_gettxinfo(txid)
                RESULTS['yed']['mint_' + label] = {'carrier': res['carrierTxid'], 'mint': txid, 'assigned': info.get('assigned'),
                                                   'fundedFrom': res.get('fundedFrom')}
                print('  yed_mint from %s: mint %s' % (label, txid))
            except (JSONRPCException, AssertionError, Exception) as e:
                RESULTS['yed']['mint_' + label] = {'error': getattr(e, 'error', repr(e))}
                finding('HIGH', 'yewd yed_mint from %s failed: %s' % (label, getattr(e, 'error', repr(e))))
            save()
        bal = n1.yed_getbalance()
        RESULTS['yed']['balance_after_mints'] = bal
        toks = n1.yed_listunspent()
        RESULTS['yed']['tokens'] = toks
        print('  yed balance', bal, 'tokens', len(toks))
        # the token outputs, plain-YEC sends from every source must leave them unspent
        tok_outs = [(t['txid'], t['vout']) for t in toks]
        holders = set()
        for t in toks:
            o = n0.getrawtransaction(t['txid'], 1)['vout'][t['vout']]
            holders.add(o['scriptPubKey']['addresses'][0])
        RESULTS['yed']['holders'] = sorted(holders)
        # plain YEC to a holder key, then spend from it: only the plain coin may go
        for hkey in sorted(holders):
            try:
                n0.sendtoaddress(hkey, Decimal('0.5'))
                self.mine(1)
                txid = wait_and_assert_operationid_status(n1, z_sendmany_opid(n1, hkey, [(self.dst[ECC], Decimal('0.2'))]))
                sync_mempools(self.nodes)
                raw = n0.getrawtransaction(txid, 1)
                spent = [(i['txid'], i['vout']) for i in raw['vin']]
                bad = [o for o in tok_outs if o in spent]
                RESULTS['yed'].setdefault('holder_spend', []).append({'holder': hkey, 'txid': txid, 'spent_tokens': bad})
                if bad:
                    finding('CRITICAL', 'yewd spent a YED token as plain YEC: %s (tx %s)' % (bad, txid))
            except JSONRPCException as e:
                RESULTS['yed'].setdefault('holder_spend', []).append({'holder': hkey, 'error': e.error})
            save()
        self.mine(1)
        # every source with sendtoaddress-style selection (sendmany through yewd), large enough to need many coins
        try:
            total = Decimal(n1.getbalance())
            txid = n1.sendtoaddress(self.dst[ECC], (total - Decimal('0.1')).quantize(Decimal('0.00000001')))
            raw = n0.getrawtransaction(txid, 1)
            spent = [(i['txid'], i['vout']) for i in raw['vin']]
            bad = [o for o in tok_outs if o in spent]
            RESULTS['yed']['sweep_sendtoaddress'] = {'txid': txid, 'spent_tokens': bad, 'getbalance': str(total)}
            if bad:
                finding('CRITICAL', 'yewd sendtoaddress spent YED token(s) %s' % bad)
        except JSONRPCException as e:
            RESULTS['yed']['sweep_sendtoaddress'] = {'error': e.error}
        self.mine(1)
        for o in tok_outs:
            if self.backend().gettxout(o[0], o[1]) is None:
                finding('CRITICAL', 'token output %s:%d is spent' % o)
        # yed_send to node 2
        try:
            r = n1.yed_send(n2.yed_getnewaddress(), 500)
            self.mine(1)
            RESULTS['yed']['yed_send'] = {'r': r, 'node2_yed': n2.yed_getbalance(), 'yewd_yed': n1.yed_getbalance()}
        except JSONRPCException as e:
            RESULTS['yed']['yed_send'] = {'error': e.error}
            finding('HIGH', 'yewd yed_send failed: %s' % e.error)
        self.compare('after YED')
        # a mint the wallet cannot cover (YEW-REAL finding 5): yewd refuses before any carrier; the
        # node's own wallet (node 2, a few YEC) is tried the same way, for the record
        big = 20_000_00   # 20,000.00 YED: far above either wallet's YEC at the test price
        for label, node in (('yewd', n1), ('node2', n2)):
            self.mine(1)
            before = set(n0.getrawmempool())
            row = {}
            try:
                row['answer'] = node.yed_mint(big, 48, '', '', False)
            except JSONRPCException as e:
                row['error'] = e.error
            time.sleep(2)
            sync_mempools(self.nodes)
            row['new_mempool_txs'] = sorted(set(n0.getrawmempool()) - before)
            RESULTS['yed']['unaffordable_mint_' + label] = row
            print('  unaffordable mint on %s: %s' % (label, json.dumps(row, default=str)[:400]))
            if label == 'yewd' and row['new_mempool_txs']:
                finding('MEDIUM', 'yewd broadcast %s for a mint it cannot cover' % row['new_mempool_txs'])
        self.mine(1)
        save()

    # --- phase 5: restore from the seed ---
    def phase_restore(self):
        print('=== phase restore: wipe yewd, restore from the phrase, rescan')
        n1 = self.nodes[1]
        before = self.yewd_view()
        before_yed = n1.yed_getbalance() if 'yed' in RESULTS else None
        path = n1.z_exportwallet('restore%d' % int(time.time()))
        RESULTS['restore'] = {'dump': path}
        mfile = path        # -mnemonicfile takes a z_exportwallet file's recovery_phrase line
        stop_node(n1, PAIR)
        wdat = os.path.join(self.options.tmpdir, 'node%d' % PAIR, 'regtest', 'wallet.dat')
        if os.path.exists(wdat):
            os.remove(wdat)
        RESULTS['restore']['wallet_dat_removed'] = True
        self.nodes[PAIR] = n1 = start_node_sel(PAIR, self.options.tmpdir, self.node_args(PAIR) + ['-mnemonicfile=%s' % mfile, '-rescan'])
        for a, b in self.edges():
            if PAIR in (a, b):
                connect_nodes_bi(self.nodes, a, b)
        sync_blocks(self.nodes)
        # the restored wallet issues the same keys again in order
        again = {ECC: n1.getnewaddress(), SAP: n1.z_getnewaddress('sapling'), SLH: n1.getnewaddress('', 'pqslh'), FN: n1.getnewaddress('', 'pq')}
        RESULTS['restore']['reissued'] = again
        for k in KINDS:
            if again[k] != self.src[k]:
                finding('HIGH', 'restore: first %s address %s differs from the original %s' % (k, again[k], self.src[k]))
        after = self.yewd_view()
        RESULTS['restore']['before'] = before
        RESULTS['restore']['after'] = after
        diffs = []
        for f in ('transparent', 'private', 'total', 'transparent_ecc', 'transparent_pq', 'pq_by_scheme'):
            if str(before['z_gettotalbalance'].get(f)) != str(after['z_gettotalbalance'].get(f)):
                diffs.append('%s: before %s after %s' % (f, before['z_gettotalbalance'].get(f), after['z_gettotalbalance'].get(f)))
        if before_yed is not None:
            ay = n1.yed_getbalance()
            RESULTS['restore']['yed_before'], RESULTS['restore']['yed_after'] = before_yed, ay
            if before_yed.get('confirmedCents') != ay.get('confirmedCents'):
                diffs.append('yed confirmedCents before %s after %s' % (before_yed.get('confirmedCents'), ay.get('confirmedCents')))
        RESULTS['restore']['diffs'] = diffs
        if diffs:
            finding('HIGH', 'restore from seed: balances differ: %s' % '; '.join(diffs))
        print('  restore diffs:', diffs)
        self.compare('after restore')
        save()

    # --- the node's own fees for the same 16 shapes (node 0's plain ycash6 wallet -> node 2) ---
    def phase_nodefees(self):
        n0, n1, n2, n3 = self.nodes
        dst = self.dst
        priced = getattr(self, 'yed_done', False)
        print('=== phase nodefees: ycash6 z_sendmany from its own address of each type (priced %s)' % priced)
        own = {ECC: n0.getnewaddress(), SAP: n0.z_getnewaddress('sapling'), FN: n0.getnewaddress('', 'pq'),
               SLH: n0.getnewaddress('', 'pqslh')}
        for _ in range(5):
            for k in (ECC, FN, SLH):
                n0.sendtoaddress(own[k], 1)
        fund = n0.getnewaddress()
        for _ in range(5):
            n0.sendtoaddress(fund, 2)
        self.mine(1)
        for _ in range(5):
            wait_and_assert_operationid_status(n0, z_sendmany_opid(n0, fund, [(own[SAP], 1)]))
        self.mine(1)
        rows = RESULTS.setdefault('node_cells', [])
        amount = Decimal('0.20')
        for s in KINDS:
            for d in KINDS:
                amount += Decimal('0.01')
                row = {'src': s, 'dst': d, 'priced': priced}
                try:
                    txid = wait_and_assert_operationid_status(n0, z_sendmany_opid(n0, own[s], [(dst[d], amount)]))
                    fee, raw, prevs = self.fee_and_raw(txid)
                    row.update(txid=txid, fee_zat=fee, size=len(n0.getrawtransaction(txid)) // 2)
                    if getattr(self, 'expect_in', None) is not None:
                        self.expect_in[d] += amount
                    else:
                        self.expect_in = {k: Decimal(0) for k in KINDS}
                        self.expect_in[d] += amount
                except (JSONRPCException, AssertionError) as e:
                    row['error'] = getattr(e, 'error', str(e))
                rows.append(row)
                mine = [c for c in RESULTS['cells'] if c['src'] == s and c['dst'] == d and c.get('priced') == priced]
                print('  node %-10s -> %-10s fee %s size %s (yewd %s)' % (s, d, row.get('fee_zat'), row.get('size'),
                                                                         mine[0].get('fee_zat') if mine else None))
                save()
            self.mine(1)

    def run_test(self):
        phases = self.options.phases.split(',')
        self.phase_addr()
        for ph in phases:
            if ph != 'addr':
                getattr(self, 'phase_' + ph)()
        save()
        print('findings:', json.dumps(RESULTS['findings'], indent=1, default=str))


if __name__ == '__main__':
    YewRealRun().main()
