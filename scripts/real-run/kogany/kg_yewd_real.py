#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or https://www.opensource.org/licenses/mit-license.php .
"""KG-YEWD-REAL: yewd with koganyd as its node (the kogany line's product configuration), beside ycashd peers.

node 0  plain ycashd wallet: mines the first 200 blocks, attestor set, YED pool (quotes)
node 1  the pair under test: koganyd (--features ycash) backend + yewd + yewd-signer (YEWD_BIN + YEWD_KOGANY,
        ycash6's column-3 harness); its generate is the harness's solved generate (YEWD_SOLVE=1): kogany's
        getblocktemplate, the (48,5) solver, submitblock to kogany
node 2  plain ycashd wallet: the receiver of the matrix sends
node 3  plain ycashd wallet: the observer (imports yewd's z_exportwallet dump: the node's view of the same keys)

YCASH6_QA=<ycash6>/qa/rpc-tests ZCASHD=<ycashd> YEWD_BIN_PAIR=<yewd> KOGANYD=<koganyd> python kg_yewd_real.py --tmpdir=... --portseed=...
Phases: --phases=addr,matrix,restart,yed,facade,kparity,restore (default all).
"""
import json
import os
import re
import shutil
import sys
import time
from decimal import Decimal

QA = os.environ['YCASH6_QA']
sys.path.insert(0, QA)
YEWD = os.environ['YEWD_BIN_PAIR']
os.environ['YEWD_BIN'] = YEWD
os.environ['YEWD_KOGANY'] = os.environ['KOGANYD']
os.environ.setdefault('YEWD_SOLVE', '1')

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
RESULTS = {'cells': [], 'balance_checks': [], 'findings': [], 'notes': [], 'mined': {'kogany': 0, 'ycashd': 0}}
# YEW-REAL's matrix fees against ycash6 (wt/handoff/YEW-REAL.md, run6), zat
YEW_REAL_FEES = {
    (ECC, ECC): 1000, (ECC, SAP): 1500, (ECC, FN): 1500, (ECC, SLH): 1500,
    (SAP, ECC): 1500, (SAP, SAP): 1000, (SAP, FN): 2000, (SAP, SLH): 2000,
    (FN, ECC): 5500, (FN, SAP): 6500, (FN, FN): 5500, (FN, SLH): 5500,
    (SLH, ECC): 27000, (SLH, SAP): 28000, (SLH, FN): 27000, (SLH, SLH): 27000}


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
        parser.add_option('--phases', dest='phases', default='addr,matrix,restart,yed,facade,kparity,restore')

    def node_args(self, i):
        a = ([] if os.environ.get('YEW_REAL_PRECANOPY') else list(YCASH_UPGRADE_ARGS)) + \
            [nuparams(VAULT_BRANCH_ID, ACTIVATION), '-pqfalconheight=%d' % FALCON, '-exportdir=%s' % self.exportdir,
             '-acceptnonstdtxn=0'] + ([] if i == PAIR else ['-txindex']) + \
            (['-experimentalfeatures', '-insightexplorer'] if i == 3 else [])     # node 3: the address index kparity compares with
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
        """koganyd, the pair's backend (cookie in backend/rpc/.cookie)."""
        d = os.path.join(self.options.tmpdir, 'node%d' % PAIR, 'backend')
        return kogany.KoganyRPC('http://127.0.0.1:%d/' % kogany.yewd_backend_rpc_port(PAIR),
                                cookie=os.path.join(d, 'rpc', '.cookie'))

    def mine(self, n=1, by=PAIR):
        """``by`` PAIR: kogany mines (the harness's solved generate through yewd); 0: ycashd node 0."""
        self.sync_all()
        h = self.nodes[by].generate(n)
        RESULTS['mined']['kogany' if by == PAIR else 'ycashd'] += len(h)
        self.sync_all()
        tips = [nd.getbestblockhash() for nd in self.nodes] + [self.backend().getbestblockhash()]
        if len(set(tips)) != 1:
            finding('HIGH', 'tips differ after %d blocks by %s: %s' % (n, by, tips))
        return h

    def wait_kogany_mempool(self, txid, timeout=60):
        b = self.backend()
        end = time.time() + timeout
        while time.time() < end:
            if txid in b.getrawmempool():
                return True
            time.sleep(0.25)
        return False

    def kogany_index(self, addr):
        b = self.backend()
        try:
            bal = b.getaddressbalance({'addresses': [addr]})
            utx = b.getaddressutxos({'addresses': [addr]})
            return {'balance': int(bal['balance']), 'received': int(bal.get('received', 0)),
                    'utxo_sum': sum(int(u['satoshis']) for u in utx), 'utxos': len(utx)}
        except JSONRPCException as e:
            return {'error': e.error}

    def statehashes(self, label):
        b, n0 = self.backend(), self.nodes[0]
        rec = {'label': label}
        for name, call in (('vault', lambda r: r.vault_getinfo().get('statehash')),
                           ('yed', lambda r: r.yed_getstatehash()),
                           ('set_getinfo', lambda r: r.set_getinfo(self.vault_setid)),
                           ('yed_getactivation', lambda r: r.yed_getactivation()),
                           ('tip', lambda r: r.getbestblockhash())):
            vals = {}
            for who, r in (('kogany', b), ('ycashd', n0)):
                try:
                    vals[who] = call(r)
                except JSONRPCException as e:
                    vals[who] = 'err %s %s' % (e.error.get('code'), e.error.get('message'))
            rec[name] = vals
            if vals['kogany'] != vals['ycashd']:
                finding('HIGH', '%s: %s differs: kogany %r ycashd %r' % (label, name, vals['kogany'], vals['ycashd']))
        RESULTS.setdefault('statehashes', []).append(rec)
        save()
        return rec

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
        b = self.nodes[0]        # ycashd -txindex: the chain read whole, no wallet and no kogany code
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
        self.block_spent = set()
        for tx, h in txs:
            for i in tx['vin']:
                if 'txid' in i:
                    spent.add((i['txid'], i['vout']))
                    if h is not None:
                        self.block_spent.add((i['txid'], i['vout']))
            for o in tx['vout']:
                if o['scriptPubKey']['hex'] in spks:
                    utxo[(tx['txid'], o['n'])] = (o['scriptPubKey']['hex'], zat(o['value']), h)
        self.block_utxo = {k: v for k, v in utxo.items() if k not in self.block_spent and v[2] is not None}
        return {k: v for k, v in utxo.items() if k not in spent}

    # --- phase 1 ---
    def phase_addr(self):
        n0, n1, n2, n3 = self.nodes
        b = self.backend()
        print('=== phase addr: node and yewd versions, addresses of every type')
        try:
            bv = b.getinfo()
        except JSONRPCException as e:
            bv = e.error
        RESULTS['versions'] = {'backend_getinfo': bv, 'ycashd': n0.getnetworkinfo()['subversion'], 'yewd_getinfo': n1.getinfo().get('version')}
        RESULTS['peers_kogany'] = [p.get('addr') for p in b.getpeerinfo()]
        h = n1.help('getnewaddress')
        RESULTS['getnewaddress_help_names_d9'] = ('sqf' in h and 'sqs' in h)
        hb = n0.help('getnewaddress')
        RESULTS['node_getnewaddress_help_names_d9'] = ('sqf' in hb and 'sqs' in hb)
        self.mine(200 - n0.getblockcount(), by=0)
        self.mine(ACTIVATION + 1 - n0.getblockcount())     # kogany mines across the vault activation
        RESULTS['backend_upgrades'] = b.getblockchaininfo().get('upgrades')
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
            # koganyd's own answer against ycashd's (a client reading koganyd directly), wallet fields aside
            strip = lambda v: {f: x for f, x in v.items() if f not in ('ismine', 'iswatchonly', 'account')}
            if strip(vb) != strip(v0):
                finding('LOW', 'validateaddress %s: koganyd %r, ycashd %r' % (k, strip(vb), strip(v0)))
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
        blocks_only = {k: 0 for k in (ECC, FN, SLH)}
        for (_, _), (s, z, h) in self.block_utxo.items():
            blocks_only[spks[s]] += z
        o['chain_blocks_only_zat'] = blocks_only
        o['kogany_index'] = {k: self.kogany_index(self.src[k]) for k in (ECC, FN, SLH)}
        return o

    def compare(self, label):
        y = self.yewd_view()
        o = self.oracle_view()
        rec = {'label': label, 'yewd': y, 'oracle': o, 'agree': True, 'diffs': []}
        for k in (ECC, FN, SLH):
            ki = o['kogany_index'][k]
            if 'error' in ki:
                rec['diffs'].append('%s kogany getaddressbalance error %s' % (k, ki['error']))
            else:
                # the index counts mempool-free confirmed outputs; yewd's z_getbalance (minconf 1)
                # the index is the confirmed state (as ycashd's insight index): blocks only, mempool spends not subtracted
                if ki['balance'] != o['chain_blocks_only_zat'][k] or ki['utxo_sum'] != ki['balance']:
                    rec['diffs'].append('%s kogany index balance %d utxos %d vs chain (blocks only) %d' % (k, ki['balance'], ki['utxo_sum'], o['chain_blocks_only_zat'][k]))
                if o['chain_blocks_only_zat'][k] == o['chain_confirmed_zat'][k] and ki['balance'] != zat(y['per_address'][k]['z_getbalance']):
                    rec['diffs'].append('%s yewd z_getbalance %s vs kogany getaddressbalance %s' % (k, y['per_address'][k]['z_getbalance'], coins(ki['balance'])))
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
        expect_in = {k: Decimal(0) for k in KINDS}
        amount = Decimal('0.10')
        for s in KINDS:
            for d in KINDS:
                amount += Decimal('0.01')
                cell = {'src': s, 'dst': d, 'amount': str(amount)}
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
                cell['in_kogany_mempool'] = self.wait_kogany_mempool(txid)
                if not cell['in_kogany_mempool']:
                    finding('HIGH', '%s -> %s %s not in kogany\'s mempool' % (s, d, txid))
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
                cell['yew_real_fee'] = YEW_REAL_FEES[(s, d)]
                if fee != YEW_REAL_FEES[(s, d)]:
                    finding('MEDIUM', 'fee %s -> %s: %d through kogany, %d in YEW-REAL against ycash6' % (s, d, fee, YEW_REAL_FEES[(s, d)]))
                expect_in[d] += amount
                print('  %-10s -> %-10s %s fee %d size %d accepted %s change_ok %s' % (s, d, amount, fee, cell['size'], cell['accepted'], ok))
                save()
            self.compare('after %s sends (mempool)' % s)
        print('mine the matrix')
        blk = self.mine(1)[0]
        for c in RESULTS['cells']:
            if 'txid' in c:
                c['mined'] = c['txid'] in self.backend().getblock(blk)['tx'] and c['txid'] in n0.getblock(blk)['tx']
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
        self.attest_setid = activate_yed_late(self, [0, PAIR], self.edges())
        n0, n1, n2, n3 = self.nodes
        src = self.src
        RESULTS['yed'] = {}
        setid = n0.set_create({'seats': 3, 'unlockthreshold': 2, 'cancelthreshold': 1, 'slashthreshold': 2,
                               'maturity': 2, 'livenesswindow': 50, 'bondmin': 1, 'ratewindow': 20})['setid']
        n0.sendtoaddress(src[ECC], 1)      # the matrix and restart phases emptied the named ECC address
        self.mine(1)
        self.vault_setid = setid
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
        self.statehashes('after vault locks')
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
        self.statehashes('after mints')
        try:
            RESULTS['yed']['yed_getinfo'] = {'kogany': self.backend().yed_getinfo(), 'ycashd': n0.yed_getinfo()}
        except JSONRPCException as e:
            RESULTS['yed']['yed_getinfo'] = {'error': e.error}
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
        # redeem one position (the default mint's vault)
        m = RESULTS['yed'].get('mint_default', {}).get('mint')
        if m:
            try:
                r = n1.yed_redeem(m)
                RESULTS['yed']['yed_redeem'] = {'r': r}
                txid = r.get('txid') if isinstance(r, dict) else r
                if txid:
                    RESULTS['yed']['yed_redeem']['in_kogany_mempool'] = self.wait_kogany_mempool(txid)
                self.mine(1)
                RESULTS['yed']['yed_redeem']['yewd_yed_after'] = n1.yed_getbalance()
                print('  yed_redeem %s: %s' % (m, r))
            except JSONRPCException as e:
                RESULTS['yed']['yed_redeem'] = {'error': e.error}
                finding('MEDIUM', 'yewd yed_redeem %s failed: %s' % (m, e.error))
        self.statehashes('after yed_send and redeem')
        self.compare('after YED')
        save()


    # --- phase restart: koganyd and yewd stopped with unconfirmed sends, started again ---
    def phase_restart(self):
        print('=== phase restart: unconfirmed sends, stop the pair (yewd + koganyd), start it again')
        n0, n1, n2, n3 = self.nodes
        src, dst = self.src, self.dst
        rec = {'sends': []}
        RESULTS['restart'] = rec
        for s, d in ((ECC, ECC), (FN, SAP), (SAP, FN), (SLH, ECC)):
            txid = wait_and_assert_operationid_status(n1, z_sendmany_opid(n1, src[s], [(dst[d], Decimal('0.05'))]))
            rec['sends'].append({'src': s, 'dst': d, 'txid': txid, 'in_kogany_mempool': self.wait_kogany_mempool(txid)})
        sync_mempools(self.nodes)
        before = {'tb0': n1.z_gettotalbalance(0), 'tb1': n1.z_gettotalbalance(1),
                  'per': {k: str(n1.z_getbalance(src[k], 0)) for k in KINDS}}
        rec['before'] = before
        stop_node(n1, PAIR)
        self.nodes[PAIR] = n1 = start_node_sel(PAIR, self.options.tmpdir, self.node_args(PAIR))
        for a, b in self.edges():
            if PAIR in (a, b):
                connect_nodes_bi(self.nodes, a, b)
        sync_blocks(self.nodes)
        time.sleep(5)
        rec['kogany_mempool_after_restart'] = sorted(self.backend().getrawmempool())
        after = {'tb0': n1.z_gettotalbalance(0), 'tb1': n1.z_gettotalbalance(1),
                 'per': {k: str(n1.z_getbalance(src[k], 0)) for k in KINDS}}
        rec['after'] = after
        for f in ('tb0', 'tb1', 'per'):
            if json.dumps(before[f], sort_keys=True, default=str) != json.dumps(after[f], sort_keys=True, default=str):
                finding('HIGH', 'restart: yewd %s before %s after %s' % (f, before[f], after[f]))
        # a send right after the restart must not reuse a coin an unconfirmed send spent
        try:
            txid = wait_and_assert_operationid_status(n1, z_sendmany_opid(n1, src[FN], [(dst[ECC], Decimal('0.02'))]))
            rec['post_restart_send'] = {'txid': txid, 'in_kogany_mempool': self.wait_kogany_mempool(txid)}
        except (JSONRPCException, AssertionError) as e:
            rec['post_restart_send'] = {'error': getattr(e, 'error', str(e))}
            finding('HIGH', 'restart: send after restart failed: %s' % rec['post_restart_send']['error'])
        # whatever kogany lost, the pending sends must reach a block exactly once (ycashd still has them)
        for _ in range(3):
            self.mine(1)
            pend = [x['txid'] for x in rec['sends'] if n0.getrawtransaction(x['txid'], 1).get('confirmations', 0) == 0]
            if not pend:
                break
        for x in rec['sends'] + ([rec['post_restart_send']] if 'txid' in rec.get('post_restart_send', {}) else []):
            r = n0.getrawtransaction(x['txid'], 1)
            x['confirmations'] = r.get('confirmations', 0)
            if not x['confirmations']:
                finding('HIGH', 'restart: %s still unconfirmed after 3 kogany blocks' % x['txid'])
        rec['mined_mempool_left'] = {'kogany': self.backend().getrawmempool(), 'ycashd': n0.getrawmempool()}
        self.compare('after restart and mining')
        save()

    # --- phase facade: yewd vs a ycashd wallet for the calls users type ---
    @staticmethod
    def shape(v):
        if isinstance(v, dict):
            return {k: YewRealRun.shape(x) for k, x in sorted(v.items())}
        if isinstance(v, list):
            return [YewRealRun.shape(v[0])] if v else []
        return type(v).__name__

    @staticmethod
    def paths(v, pre=''):
        out = set()
        if isinstance(v, dict):
            for k, x in v.items():
                out.add(pre + '.' + k)
                out |= YewRealRun.paths(x, pre + '.' + k)
        elif isinstance(v, list):
            for x in v:
                out |= YewRealRun.paths(x, pre + '[]')
        return out

    def both(self, label, fn, ref=2):
        out = {}
        for who, nd in (('yewd', self.nodes[PAIR]), ('ycashd', self.nodes[ref])):
            try:
                out[who] = {'ok': fn(nd)}
            except JSONRPCException as e:
                out[who] = {'code': e.error.get('code'), 'message': e.error.get('message')}
        y, c = out['yewd'], out['ycashd']
        if 'ok' in y and 'ok' in c:
            same = self.shape(y['ok']) == self.shape(c['ok'])
        else:
            same = y.get('code') == c.get('code') and y.get('message') == c.get('message')
        rec = {'call': label, 'yewd': y, 'ycashd': c, 'same': same}
        if 'ok' in y and 'ok' in c and not same:
            py, pc = self.paths(y['ok']), self.paths(c['ok'])
            rec['only_yewd'], rec['only_ycashd'] = sorted(py - pc), sorted(pc - py)
            print('    paths only in yewd %s; only in ycashd %s' % (rec['only_yewd'], rec['only_ycashd']))
        RESULTS.setdefault('facade', []).append(rec)
        print('  %-48s %s' % (label, 'same' if same else 'DIFFERS: yewd %s | ycashd %s' % (
            json.dumps(y, default=str)[:300], json.dumps(c, default=str)[:300])))
        return rec

    def phase_facade(self):
        print('=== phase facade: yewd vs ycashd node 2 for the calls users type')
        n0 = self.nodes[0]
        for t in ('', 'p2pkh', 'pq', 'pqslh', 'PQ', 'bogus'):
            r = self.both('getnewaddress %r' % t, lambda nd: nd.getnewaddress(t))
            for w in ('yewd', 'ycashd'):
                if 'ok' in r[w]:
                    r[w]['ok'] = r[w]['ok'][:3] + '..(%d)' % len(r[w]['ok'])
            r['same'] = (r['yewd'].get('ok') == r['ycashd'].get('ok')) if 'ok' in r['yewd'] else r['same']
        self.both("getnewaddress '' 'pq'", lambda nd: nd.getnewaddress('', 'pq')[:3])
        self.both("getnewaddress 'pq' 'x'", lambda nd: nd.getnewaddress('pq', 'x'))
        self.both("z_getnewaddress sapling", lambda nd: nd.z_getnewaddress('sapling')[:16])
        self.both("z_getnewaddress sprout", lambda nd: nd.z_getnewaddress('sprout'))
        self.both("z_getnewaddress bogus", lambda nd: nd.z_getnewaddress('bogus'))
        self.both('z_gettotalbalance', lambda nd: nd.z_gettotalbalance())
        self.both('z_gettotalbalance 0 true', lambda nd: nd.z_gettotalbalance(0, True))
        self.both('z_gettotalbalance -1', lambda nd: nd.z_gettotalbalance(-1))
        self.both('listaddresses', lambda nd: nd.listaddresses())
        self.both('getwalletinfo', lambda nd: nd.getwalletinfo())
        self.both('getbalance', lambda nd: nd.getbalance())
        bad_t = 'smBadAddressXXXXXXXXXXXXXXXXXXXXXX'
        self.both('z_sendmany bad from', lambda nd: nd.z_sendmany(bad_t, [{'address': self.dst[ECC], 'amount': 0.1}]))
        self.both('z_sendmany not-mine from', lambda nd: nd.z_sendmany(n0.getnewaddress(), [{'address': self.dst[ECC], 'amount': 0.1}]))
        self.both('z_sendmany bad to', lambda nd: nd.z_sendmany('ANY_TADDR', [{'address': bad_t, 'amount': 0.1}]))
        self.both('z_sendmany zero amount', lambda nd: nd.z_sendmany('ANY_TADDR', [{'address': self.dst[ECC], 'amount': 0}]))
        self.both('z_sendmany negative', lambda nd: nd.z_sendmany('ANY_TADDR', [{'address': self.dst[ECC], 'amount': -1}]))
        self.both('z_sendmany empty', lambda nd: nd.z_sendmany('ANY_TADDR', []))
        def too_much(nd):
            opid = nd.z_sendmany('ANY_TADDR', [{'address': self.dst[ECC], 'amount': 100000}])
            for _ in range(120):
                st = nd.z_getoperationstatus([opid])
                if st and st[0]['status'] in ('failed', 'success'):
                    r = st[0]
                    return {'status': r['status'], 'error': r.get('error', {}).get('code'),
                            'message': re.sub(r'have [0-9.]+', 'have N', r.get('error', {}).get('message', ''))}
                time.sleep(0.5)
            return 'timeout'
        r = self.both('z_sendmany too much', too_much)
        r['same'] = r['yewd'].get('ok') == r['ycashd'].get('ok')
        print('    same (status, code, message modulo balance): %s %s' % (r['same'], r['yewd'].get('ok')))
        self.both('set_getinfo (no setid)', lambda nd: nd.set_getinfo())
        self.both('z_getbalance foreign taddr', lambda nd: nd.z_getbalance(self.nodes[0].getnewaddress()))
        self.both('listunspent minconf 1', lambda nd: nd.listunspent(1, 9999999)[:1])
        for who, other in (('listaddresses', lambda nd: nd.listaddresses()), ('getwalletinfo', lambda nd: nd.getwalletinfo())):
            self.both(who + ' vs node 0', other, ref=0)
        self.both('z_getoperationstatus', lambda nd: nd.z_getoperationstatus()[:1])
        # sendtoaddress refusal when only post-quantum coins can pay: each wallet with its own split
        for who, nd in (('yewd', self.nodes[PAIR]), ('ycashd', self.nodes[2])):
            tb = nd.z_gettotalbalance(1)
            RESULTS.setdefault('pq_only_split', {})[who] = tb
        def pq_only(nd):
            tb = nd.z_gettotalbalance(1)
            ecc = Decimal(str(tb.get('transparent_ecc', tb['transparent'])))
            pq = Decimal(str(tb.get('transparent_pq', 0)))
            if pq <= 0:
                raise AssertionError('no PQ coins in this wallet: %s' % tb)
            return nd.sendtoaddress(self.dst[ECC], (ecc + pq / 2).quantize(Decimal('0.00000001')))
        r = self.both('sendtoaddress (only PQ coins can pay)', pq_only)
        import re as _re
        def norm(m):
            return _re.sub(r'[0-9]+\.[0-9]+', 'N', m or '')
        if 'code' in r['yewd'] and 'code' in r['ycashd']:
            r['same_modulo_amount'] = r['yewd']['code'] == r['ycashd']['code'] and norm(r['yewd']['message']) == norm(r['ycashd']['message'])
            print('    same modulo the amount: %s' % r['same_modulo_amount'])
        def pq_only_many(nd):
            tb = nd.z_gettotalbalance(1)
            ecc = Decimal(str(tb.get('transparent_ecc', tb['transparent'])))
            pq = Decimal(str(tb.get('transparent_pq', 0)))
            return nd.sendmany('', {self.dst[ECC]: (ecc + pq / 2).quantize(Decimal('0.00000001'))})
        r = self.both('sendmany (only PQ coins can pay)', pq_only_many)
        if 'code' in r['yewd'] and 'code' in r['ycashd']:
            r['same_modulo_amount'] = r['yewd']['code'] == r['ycashd']['code'] and norm(r['yewd']['message']) == norm(r['ycashd']['message'])
            print('    same modulo the amount: %s' % r['same_modulo_amount'])
        save()

    # --- phase kparity: koganyd read RPCs vs ycashd node 0, post-quantum addresses (lane KG-YEWD-FIX) ---
    @staticmethod
    def vdiff(a, b, pre=''):
        """Paths where a and b differ: ('only_kogany'|'only_ycashd'|'value', path, a, b)."""
        out = []
        if isinstance(a, dict) and isinstance(b, dict):
            for k in sorted(set(a) | set(b)):
                if k not in b:
                    out.append(('only_kogany', pre + '.' + k, a[k], None))
                elif k not in a:
                    out.append(('only_ycashd', pre + '.' + k, None, b[k]))
                else:
                    out += YewRealRun.vdiff(a[k], b[k], pre + '.' + k)
        elif isinstance(a, list) and isinstance(b, list):
            if len(a) != len(b):
                out.append(('value', pre + '#len', len(a), len(b)))
            for i, (x, y) in enumerate(zip(a, b)):
                out += YewRealRun.vdiff(x, y, '%s[%d]' % (pre, i))
        elif str(a) != str(b):
            out.append(('value', pre or '.', a, b))
        return out

    def kp(self, label, fn, keys_only=False, ref=0):
        out = {}
        for who, r in (('kogany', self.backend()), ('ycashd', self.nodes[ref])):
            try:
                out[who] = {'ok': fn(r)}
            except JSONRPCException as e:
                out[who] = {'code': e.error.get('code'), 'message': e.error.get('message')}
            except Exception as e:      # noqa: BLE001 - a transport failure is a result here
                out[who] = {'code': 'exception', 'message': repr(e)}
        k, c = out['kogany'], out['ycashd']
        if 'ok' in k and 'ok' in c:
            d = self.vdiff(k['ok'], c['ok'])
            if keys_only:
                d = [x for x in d if x[0] != 'value']
        else:
            d = [] if (k.get('code'), k.get('message')) == (c.get('code'), c.get('message')) else [('answer', '', k, c)]
        rec = {'call': label, 'kogany': k, 'ycashd': c, 'diffs': [list(map(lambda v: json.dumps(v, default=str)[:200], x)) for x in d]}
        RESULTS.setdefault('kparity', []).append(rec)
        print('  %-58s %s' % (label, 'same' if not d else 'DIFFERS (%d)' % len(d)))
        for x in d[:12]:
            print('     %s %s kogany=%s ycashd=%s' % (x[0], x[1], json.dumps(x[2], default=str)[:120], json.dumps(x[3], default=str)[:120]))
        return rec

    def phase_kparity(self):
        print('=== phase kparity: koganyd vs ycashd node 0, the read RPCs both serve, post-quantum addresses')
        self.sync_all()
        n0 = self.nodes[0]
        addrs = {k: self.src[k] for k in (ECC, FN, SLH)}
        addrs['node2 ' + FN], addrs['node2 ' + SLH] = self.dst[FN], self.dst[SLH]
        try:
            addrs['YED holder pq'] = n0.yed_getnewaddress('pq')
        except JSONRPCException as e:
            note('kparity: yed_getnewaddress pq: %s' % e.error)
        holders = RESULTS.get('yed', {}).get('holders') or []
        for h in holders[:2]:
            addrs['YED holder ' + h[:3]] = h
        for name, a in addrs.items():
            self.kp('validateaddress %s' % name, lambda r: r.validateaddress(a))
            self.kp('z_validateaddress %s' % name, lambda r: r.z_validateaddress(a))
            q = {'addresses': [a]}
            self.kp('getaddressbalance %s' % name, lambda r: r.getaddressbalance(q), ref=3)
            self.kp('getaddressutxos %s' % name, lambda r: r.getaddressutxos(q), ref=3)
            self.kp('getaddressutxos chainInfo %s' % name, lambda r: r.getaddressutxos({'addresses': [a], 'chainInfo': True}), ref=3)
            self.kp('getaddresstxids %s' % name, lambda r: r.getaddresstxids(q), ref=3)
            self.kp('getaddressdeltas %s' % name, lambda r: r.getaddressdeltas(q), ref=3)
            self.kp('getaddressmempool %s' % name, lambda r: r.getaddressmempool(q), ref=3)
        hs = [a for n, a in addrs.items() if n.startswith('YED')]
        if hs:
            self.kp('yed_listtokens holders', lambda r: r.yed_listtokens(hs))
        self.kp('getinfo (keys)', lambda r: r.getinfo(), keys_only=True)
        self.kp('getblockchaininfo (keys)', lambda r: r.getblockchaininfo(), keys_only=True)
        self.kp('getnetworkinfo (keys)', lambda r: r.getnetworkinfo(), keys_only=True)
        self.kp('getmininginfo (keys)', lambda r: r.getmininginfo(), keys_only=True)
        self.kp('yed_getinfo', lambda r: r.yed_getinfo())
        self.kp('yed_getactivation', lambda r: r.yed_getactivation())
        self.kp('yed_getstats', lambda r: r.yed_getstats())
        self.kp('vault_getinfo', lambda r: r.vault_getinfo())
        self.kp('set_list', lambda r: r.set_list())
        if getattr(self, 'vault_setid', None):
            self.kp('set_getinfo setid', lambda r: r.set_getinfo(self.vault_setid))
        self.kp('vault_list', lambda r: r.vault_list())
        vl = n0.vault_list()
        owners = sorted({v.get('owner') for v in vl if isinstance(v, dict) and v.get('owner')})
        for o in owners[:3]:
            self.kp('vault_list owner %s' % str(o)[:12], lambda r: r.vault_list({'owner': o}))
        for v in vl[:3]:
            if isinstance(v, dict) and v.get('script'):
                self.kp('vault_decodescript %s' % v.get('outpoint', '')[:12], lambda r: r.vault_decodescript(v['script']))
        self.kp('yed_listvaults', lambda r: r.yed_listvaults())
        lv = n0.yed_listvaults()
        rows = lv if isinstance(lv, list) else lv.get('vaults', [])
        for v in rows[:2]:
            t = v.get('txid') or v.get('vaultTxid')
            if t:
                self.kp('yed_getvault %s' % t[:12], lambda r: r.yed_getvault(t))
                self.kp('yed_gettxinfo %s' % t[:12], lambda r: r.yed_gettxinfo(t))
        self.kp('yed_listclaimable', lambda r: r.yed_listclaimable())
        self.kp('yed_listattestors', lambda r: r.yed_listattestors())
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
                note('restore: next %s address %s is not the original %s (expected: the next unused key, as ycashd)' % (k, again[k], self.src[k]))
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

    def run_test(self):
        phases = self.options.phases.split(',')
        self.phase_addr()
        if 'matrix' in phases:
            self.phase_matrix()
        if 'restart' in phases:
            self.phase_restart()
        if 'yed' in phases:
            self.phase_yed()
        if 'facade' in phases:
            self.phase_facade()
        if 'kparity' in phases:
            self.phase_kparity()
        if 'restore' in phases:
            self.phase_restore()
        save()
        print('findings:', json.dumps(RESULTS['findings'], indent=1, default=str))


if __name__ == '__main__':
    YewRealRun().main()
