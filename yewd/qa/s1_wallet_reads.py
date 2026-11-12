#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or https://www.opensource.org/licenses/mit-license.php .

"""
yewd S1 exit gate (workspace plan docs/plans/kogany/kogany-yellowback-plan.md section 3b S1): the
read-only wallet subset of both contract suites, served by yewd in front of a wallet-less node,
then the soak (a node restart, a yewd restart, invalidateblock reorgs of 2 and 10 blocks) with
consistent balances.

Runs on ycash6's functional framework (YellowbackTestFramework, seven nodes): nodes 0-5 are the
standard topology on plain ycashd; node 6 is the pair under test, a ycashd -disablewallet backend
with yewd in front of it (the harness's YEWD_BIN mode, test_framework/kogany.py). Node 6's wallet
is created first (yewd -initwallet) and the backend mines to its coinbase address
(-mineraddress, -minetolocalwallet=0: hazard H8). The plain user node (0) pays it YEC, a
post-quantum YEC address, a Sapling note and YED, and mints a vault whose owner is node 6's
(vault_getnewowner), so every read has something to read. Results are checked against
doc/yellowback-rpc-contract.json and doc/vault-rpc-contract.json (the suites' own checkers), and the
stock wallet reads against the plain ycashd wallet's answers (key sets) and against the chain.

    YCASH6_QA=<ycash6>/qa/rpc-tests ZCASHD=<ycashd> YEWD_BIN=<yewd> \\
        <venv>/bin/python yewd/qa/s1_wallet_reads.py --tmpdir=<dir> [--nocleanup]
"""

import os
import signal
import subprocess
import sys
import time
from decimal import Decimal

QA = os.environ.get('YCASH6_QA')
if not QA:
    sys.exit('set YCASH6_QA to ycash6 qa/rpc-tests (the harness with YEWD_BIN, ycash6 vaults/kogany-compat)')
sys.path.insert(0, QA)
if not os.environ.get('YEWD_BIN'):
    sys.exit('set YEWD_BIN to the yewd binary')

from test_framework import util, kogany                                       # noqa: E402
from test_framework import yellowback_util as yu                              # noqa: E402
from test_framework.authproxy import JSONRPCException                         # noqa: E402
from test_framework.util import assert_equal, assert_greater_than             # noqa: E402
from test_framework.vault_contract import Contract as VaultContract           # noqa: E402
from test_framework.yellowback_attest import wallet_mint                      # noqa: E402
from test_framework.yellowback_util import (                                  # noqa: E402
    POOLS, REF_LAG, USER, YellowbackTestFramework, build_mint_tx,
)
import yellowback_rpc_contract as yrc                                         # noqa: E402

YEWD = 6                    # the pair under test
COIN = 100_000_000

# Only node YEWD is a pair: util.start_node makes every node a pair while YEWD_BIN is set, so the
# other nodes start with it unset. It stays set otherwise, so stop_node reaps node 6's backend and
# sync_blocks does not wait for fullyNotified (a -disablewallet ycashd never reports it).
_start_node = util.start_node


def _start_node_one_pair(i, *a, **kw):
    if i == YEWD:
        return _start_node(i, *a, **kw)
    saved = os.environ.pop('YEWD_BIN')
    try:
        return _start_node(i, *a, **kw)
    finally:
        os.environ['YEWD_BIN'] = saved


util.start_node = _start_node_one_pair
yu.start_node = _start_node_one_pair


def zat(v):
    return int(Decimal(v) * COIN)


def wait_until(pred, what, timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if pred():
                return
        except (JSONRPCException, OSError):
            pass
        time.sleep(0.25)
    raise AssertionError('timed out waiting for ' + what)


class YewdS1(YellowbackTestFramework):

    def __init__(self):
        super().__init__(num_nodes=7)
        self.mine_address = None
        self.report = {'yed': set(), 'vault': set(), 'stock': set()}

    # --- node 6: the pair -------------------------------------------------------------------

    def node_args(self, i, extra=None):
        args = super().node_args(i, extra)
        if i == YEWD:
            args = args + ['-mineraddress=%s' % self.mine_address, '-minetolocalwallet=0']
        return args

    def setup_network(self, split=False):
        datadir = os.path.join(self.options.tmpdir, 'node%d' % YEWD)
        out = subprocess.check_output([os.environ['YEWD_BIN'], '-datadir=' + datadir, '-conf=ycash.conf', '-regtest', '-initwallet'])
        import json
        self.mine_address = json.loads(out)['mineaddress']
        print('node %d: yewd wallet created, coinbase address %s' % (YEWD, self.mine_address))
        super().setup_network(split)

    def plain_settle(self):
        """The plain wallets have seen the tip (the fullyNotified wait the YEWD_BIN mode skips)."""
        for i, n in enumerate(self.nodes):
            if i != YEWD and n is not None:
                wait_until(lambda: n.getblockchaininfo()['fullyNotified'], 'node %d fullyNotified' % i)

    def sync(self):
        self.sync_all()
        self.plain_settle()

    def mine_on(self, i, n=1):
        h = self.nodes[i].generate(n)
        self.sync()
        return h

    # --- checks -------------------------------------------------------------------------------

    def same_keys(self, got, ref, what, ycashd_only=(), yewd_only=()):
        g, r = set(got), set(ref)
        missing = r - g - set(ycashd_only)
        extra = g - r - set(yewd_only)
        assert not missing and not extra, '%s: yewd lacks %s, adds %s' % (what, sorted(missing), sorted(extra))

    def consistent(self, y, label):
        """The wallet agrees with itself and with the chain: getbalance = mature confirmed coins +
        trusted, listunspent(1) rows are unspent outputs of the node's chain, the processed tip is the
        node's (the barrier)."""
        coins = y.listunspent(1)
        for c in coins:
            out = y.gettxout(c['txid'], c['vout'], False)
            assert out is not None, '%s: listunspent row %s:%d is not an unspent output of the node' % (label, c['txid'], c['vout'])
            assert_equal(zat(out['value']), c['amountZat'])
        assert_equal(zat(y.getbalance('*', 1)), sum(c['amountZat'] for c in coins if c['confirmations'] >= 1))
        for n in y.z_listunspent(1):
            assert n['confirmations'] >= 1
        # every listed transaction's confirmations is the node's view
        for c in coins[:20]:
            tx = y.gettransaction(c['txid'])
            if tx['confirmations'] > 0:
                assert_equal(tx['confirmations'], y.getblock(tx['blockhash'])['confirmations'])
            else:
                assert c['txid'] in y.getrawmempool()

    def snapshot(self, y):
        return {
            'balance': y.getbalance(),
            'balance1': y.getbalance('*', 1),
            'unspent': sorted((c['txid'], c['vout'], c['amountZat'], c['confirmations'] > 0) for c in y.listunspent(0)),
            'z': y.z_getbalance(self.zaddr),
            'znotes': sorted((n['txid'], n['outindex']) for n in y.z_listunspent(1)),
            'yed': {k: v for k, v in y.yed_getbalance().items() if k != 'height'},
            'yedunspent': sorted((r['txid'], r['vout'], r['cents']) for r in y.yed_listunspent()),
            'positions': sorted((p['txid'], p['status']) for p in y.yed_listpositions()),
            'vaults': sorted(v['outpoint'] for v in y.vault_list({'mine': True})),
        }

    # --- the run ------------------------------------------------------------------------------

    def run_test(self):
        nodes = self.nodes
        user, y = nodes[USER], nodes[YEWD]
        yc = yrc.Contract(yrc.CONTRACT)
        vc = VaultContract(os.path.join(QA, '..', '..', 'doc', 'vault-rpc-contract.json'))

        print('the pair answers; the wallet follows the chain (the coinbase address, H8)')
        assert_equal(y.getbestblockhash(), user.getbestblockhash())
        info = y.getwalletinfo()
        self.same_keys(info, user.getwalletinfo(), 'getwalletinfo')
        assert_equal(len(info['mnemonic_seedfp']), 64)

        print('activate Yellowback at $50 (pools mine), then node 6 mines its own coinbase')
        self.activate(POOLS, quote_usd=50)
        self.mine_round_robin(POOLS, REF_LAG + 1)
        self.sync()
        cb = self.mine_on(YEWD, 2)
        cbtx = y.getblock(cb[0])['tx'][0]
        t = y.gettransaction(cbtx)
        assert_equal((t['generated'], t['details'][0]['category'], t['details'][0]['address']), (True, 'immature', self.mine_address))
        ref_cb = user.gettransaction(user.getblock(user.getblockhash(1))['tx'][0])
        self.same_keys(t, ref_cb, 'gettransaction (coinbase)')
        self.same_keys(t['details'][0], ref_cb['details'][0], 'gettransaction.details (coinbase)')
        assert_equal(y.getbalance(), 0)
        assert_greater_than(zat(y.getwalletinfo()['immature_balance']), 0)

        print('YEC: transparent receipts, minconf, listunspent, gettransaction, getreceivedbyaddress')
        a1 = y.getnewaddress()
        assert a1 != self.mine_address
        txid = user.sendtoaddress(a1, 5)
        self.sync_all()
        assert_equal(y.getbalance(), 0)                      # a foreign mempool payment is not trusted
        assert_equal(y.getbalance('*', 0), 0)
        assert_equal([c['txid'] for c in y.listunspent(0)], [txid])
        assert_equal(y.listunspent(), [])
        assert_equal(y.gettransaction(txid)['confirmations'], 0)
        assert_equal(y.gettransaction(txid)['status'], 'waiting')
        self.mine_on(POOLS[0])
        assert_equal(y.getbalance(), 5)
        rows = y.listunspent()
        assert_equal(len(rows), 1)
        user_rows = user.listunspent()
        self.same_keys(rows[0], user_rows[0], 'listunspent row')
        assert_equal((rows[0]['address'], rows[0]['amountZat'], rows[0]['generated']), (a1, 5 * COIN, False))
        tx = y.gettransaction(txid)
        self.same_keys(tx, user.gettransaction(txid), 'gettransaction (received)', ycashd_only=('fee',))
        assert_equal((tx['amount'], tx['confirmations'], tx['status']), (5, 1, 'mined'))
        assert_equal([(d['category'], d['address'], d['amount']) for d in tx['details']], [('receive', a1, 5)])
        assert_equal(tx['hex'], user.getrawtransaction(txid))
        assert_equal(y.getreceivedbyaddress(a1), 5)
        assert_equal(y.getreceivedbyaddress(a1, 2), 0)
        assert_equal(y.getreceivedbyaddress(self.mine_address), 0)      # coinbase is not "received"
        assert_equal(y.getbalance('*', 1, False, True), 5 * COIN)     # inZat
        assert_equal(y.listlockunspent(), [])
        try:
            y.gettransaction('11' * 32)
            raise AssertionError('gettransaction of a foreign txid')
        except JSONRPCException as e:
            assert_equal(e.error['code'], -5)
        v = y.validateaddress(a1)
        self.same_keys(v, user.validateaddress(user.getnewaddress()), 'validateaddress (mine)')
        assert_equal((v['ismine'], v['iswatchonly']), (True, False))
        assert_equal(y.validateaddress(user.getnewaddress())['ismine'], False)
        gi = y.getinfo()
        self.same_keys(gi, user.getinfo(), 'getinfo')
        assert_equal(gi['balance'], y.getbalance())
        for m in ('getbalance', 'listunspent', 'gettransaction', 'getwalletinfo', 'getreceivedbyaddress', 'listlockunspent',
                  'getnewaddress', 'validateaddress', 'getinfo'):
            self.report['stock'].add(m)

        print('PQ: getnewaddress "" "pq" (rq...), a payment to it, vault_getnewowner')
        pq = y.getnewaddress('', 'pq')
        assert pq.startswith('rq') and len(pq) == 53, pq
        pq_tx = user.sendtoaddress(pq, 2)
        self.sync_all()
        self.mine_on(POOLS[1])
        assert_equal(y.getbalance(), 7)
        assert_equal([r['address'] for r in y.listunspent(1, 9999999, [pq])], [pq])
        assert_equal(y.gettransaction(pq_tx)['details'][0]['address'], pq)
        owner = vc.call(y, 'vault_getnewowner')
        assert_equal(owner['owner'], '01' + owner['keyhash'])
        vc.error('unknown post-quantum scheme', y, 'vault_getnewowner', 3)
        self.report['vault'].update(['vault_getnewowner'])
        self.report['stock'].add('getnewaddress "" "pq"')

        print('K-25 amended for beta2: z_gettotalbalance and listaddresses, by address type')
        tb = y.z_gettotalbalance()
        self.same_keys(tb, user.z_gettotalbalance(), 'z_gettotalbalance')
        assert_equal(Decimal(tb['transparent']), Decimal(tb['transparent_ecc']) + Decimal(tb['transparent_pq']))
        assert_equal(sum(Decimal(s['transparent_pq']) for s in tb['pq_by_scheme']), Decimal(tb['transparent_pq']))
        assert_greater_than(Decimal(tb['transparent_pq']), Decimal(0))
        upq = user.getnewaddress('', 'pq')
        ula = user.listaddresses()
        la = y.listaddresses()
        pq_rows = [e for src in la for e in src.get('pq', [])]
        assert pq in [e['address'] for e in pq_rows], la
        upq_rows = [e for src in ula for e in src.get('pq', []) if e['address'] == upq]
        self.same_keys(pq_rows[0], upq_rows[0], 'listaddresses.pq', ycashd_only=('yed_holder',), yewd_only=('yed_holder',))
        for src in la:
            assert src['source'] in [u['source'] for u in ula] or src['source'] in ('imported', 'legacy_random'), src
        self.report['stock'].update(['z_gettotalbalance', 'listaddresses'])

        print('Sapling: z_getnewaddress (a diversified address of the one account), a note with a memo')
        self.zaddr = y.z_getnewaddress()
        z2 = y.z_getnewaddress()
        assert self.zaddr != z2
        zv = y.z_validateaddress(self.zaddr)
        assert_equal(zv['ismine'], True)
        self.same_keys(zv, user.z_validateaddress(user.z_getnewaddress()), 'z_validateaddress')
        assert_equal(user.z_validateaddress(self.zaddr)['ismine'], False)
        # answered by yewd itself (a -disablewallet ycash6 stops on z_validateaddress): the same fields as ycashd's
        # beta2 audit L-4 (final-run D-4): a post-quantum address of each scheme, the wallet's own and another's
        pqs = [y.getnewaddress('', 'pq'), y.getnewaddress('', 'pqslh'), user.getnewaddress('', 'pq'), user.getnewaddress('', 'pqslh')]
        for a in pqs:
            assert_equal(y.z_validateaddress(a)['ismine'], a in pqs[:2])
        for a in (self.zaddr, a1, user.getnewaddress(), 'nonsense', *pqs):
            mine = {k: v for k, v in y.z_validateaddress(a).items() if k != 'ismine'}
            theirs = {k: v for k, v in user.z_validateaddress(a).items() if k != 'ismine'}
            assert_equal(mine, theirs)
        src = user.getnewaddress()
        user.sendtoaddress(src, 3)
        self.sync_all()
        self.mine_on(POOLS[2])
        uz = user.z_getnewaddress()
        op = user.z_sendmany(src, [{'address': self.zaddr, 'amount': Decimal('1.25'), 'memo': b'hello yewd'.hex()},
                                   {'address': uz, 'amount': Decimal('0.5')}], 1, None, 'AllowFullyTransparent')
        wait_until(lambda: user.z_getoperationstatus([op])[0]['status'] == 'success', 'z_sendmany')
        ztx = user.z_getoperationresult([op])[0]['result']['txid']
        self.sync_all()
        assert_equal(y.z_getbalance(self.zaddr, 0), Decimal('1.25'))
        assert_equal(y.z_getbalance(self.zaddr), 0)
        self.mine_on(POOLS[0])
        assert_equal(y.z_getbalance(self.zaddr), Decimal('1.25'))
        assert_equal(y.z_getbalance(z2), 0)
        notes = y.z_listunspent()
        assert_equal(len(notes), 1)
        self.same_keys(notes[0], user.z_listunspent()[0], 'z_listunspent row', yewd_only=('memoStr',))
        assert_equal((notes[0]['txid'], notes[0]['address'], notes[0]['amount'], notes[0]['memoStr'], notes[0]['change']),
                     (ztx, self.zaddr, Decimal('1.25'), 'hello yewd', False))
        assert_equal(y.getwalletinfo()['shielded_balance'], '1.25')
        try:
            y.z_getbalance(uz)
            raise AssertionError('z_getbalance of a foreign address')
        except JSONRPCException as e:
            assert_equal(e.error['code'], -5)
        self.report['stock'].update(['z_getnewaddress', 'z_getbalance', 'z_listunspent', 'z_validateaddress'])

        print('YED: addresses, a transfer in, balances, history (yellowback-rpc-contract.json)')
        yaddr = yc.check('yed_getnewaddress', y.yed_getnewaddress())
        assert yaddr.startswith('yr'), yaddr
        val = yc.check('yed_validateaddress', y.yed_validateaddress(yaddr))
        assert_equal((val['isvalid'], val['ismine'], val['type']), (True, True, 'p2pkh'))
        assert_equal(val, user.yed_validateaddress(yaddr) | {'ismine': True})
        bad = yc.check('yed_validateaddress', y.yed_validateaddress(y.getnewaddress()))
        assert_equal((bad['isvalid'], bad['reason']), (False, 'not-a-yellowback-address'))
        labelled = yc.check('yed_getnewaddress', y.yed_getnewaddress('', 'savings'))
        yrc.assert_rpc_error('takes no label', y.yed_getnewaddress, 'pqowner', 'x')
        rows = {r['address']: r for r in yc.check('yed_listaddresses', y.yed_listaddresses(True))}
        assert_equal((rows[labelled]['label'], rows[labelled]['confirmedCents'], rows[labelled]['txCount'], rows[labelled]['lastUsed']),
                     ('savings', 0, 0, None))
        assert_equal(yc.check('yed_listaddresses', y.yed_listaddresses()), [])
        assert_equal(yc.check('yed_getbalance', y.yed_getbalance())['confirmedCents'], 0)
        assert_equal(yc.check('yed_listunspent', y.yed_listunspent()), [])
        assert_equal(yc.check('yed_listpositions', y.yed_listpositions()), [])
        assert_equal(yc.check('yed_listtransactions', y.yed_listtransactions()), [])
        wallet_mint(self, user, 10000, 48)
        self.mine_on(POOLS[1])
        sent = user.yed_send(yaddr, 4000)
        self.sync_all()
        b = yc.check('yed_getbalance', y.yed_getbalance())
        assert_equal((b['confirmedCents'], b['unconfirmedCents']), (0, 4000))
        self.mine_on(POOLS[2])
        b = yc.check('yed_getbalance', y.yed_getbalance())
        assert_equal((b['confirmedCents'], b['spendableCents'], b['unconfirmedCents'], b['height']), (4000, 4000, 0, y.getblockcount()))
        un = yc.check('yed_listunspent', y.yed_listunspent())
        assert_equal([(r['address'], r['cents'], r['spentUnconfirmed'], r['locked']) for r in un], [(yaddr, 4000, False, False)])
        tokens = y.yed_listtokens([yaddr])
        assert_equal([(t['txid'], t['vout'], t['cents']) for t in tokens], [(r['txid'], r['vout'], r['cents']) for r in un])
        hist = yc.check('yed_listtransactions', y.yed_listtransactions())
        assert_equal([(h['type'], h['amountCents'], h['txid']) for h in hist], [('receive', 4000, sent['txid'] if isinstance(sent, dict) else sent)])
        rows = {r['address']: r for r in yc.check('yed_listaddresses', y.yed_listaddresses())}
        assert_equal((rows[yaddr]['confirmedCents'], rows[yaddr]['txCount']), (4000, 1))
        assert rows[yaddr]['lastUsed'] is not None

        print('YED: a vault whose owner is node 6 (vault_getnewowner), minted raw by the user node')
        est = user.yed_estimatecollateral(10000, 48)
        ref = int(est['refHeight'])
        payee = user.yed_getfeepayee(ref)['default']['payoutAddress']
        holder = y.yed_getnewaddress()
        token_spk = bytes.fromhex(y.validateaddress(y.yed_validateaddress(holder)['transparentAddress'])['scriptPubKey'])
        mint_hex, _ = build_mint_tx(user, 10000, 48, ref, int(est['requiredZat']), fee_addr=payee, owner_pubkey=owner['owner'],
                                    token_script=token_spk)
        mint_txid = user.sendrawtransaction(mint_hex)
        self.sync_all()
        assert_equal(yc.check('yed_getbalance', y.yed_getbalance())['unconfirmedCents'], 10000)
        self.mine_on(POOLS[0])
        pos = yc.check('yed_listpositions', y.yed_listpositions())
        assert_equal([(p['txid'], p['status'], p['mintedCents'], p['ownerHash']) for p in pos], [(mint_txid, 'ACTIVE', 10000, owner['keyhash'])])
        assert_equal(pos[0]['canRedeem'], True)
        assert_greater_than(pos[0]['earlyRedeemFeeZat'], 0)                       # in term, IT-9
        assert_equal(yc.check('yed_listpositions', y.yed_listpositions('VOID')), [])
        assert_equal(yc.check('yed_getbalance', y.yed_getbalance())['confirmedCents'], 14000)
        hist = yc.check('yed_listtransactions', y.yed_listtransactions())
        assert_equal(sorted(h['type'] for h in hist), ['mint', 'receive'])
        assert_equal(hist[0]['txid'], mint_txid)                                    # newest first
        assert_equal(len(yc.check('yed_listtransactions', y.yed_listtransactions(1, 1))), 1)
        yrc.assert_rpc_error('count and skip must be', y.yed_listtransactions, -1)

        print('the vault primitive: vault_list with the wallet column, set_getinfo, set_listsigned (vault-rpc-contract.json)')
        owner2 = vc.call(y, 'vault_getnewowner')
        h = user.getblockcount()
        lk = user.vault_lock({'tag': 'TEST', 'setid': self.attestor_set, 'delay': 3, 'ownerheight': h + 200, 'amount': 1,
                              'owner': owner2['owner']})
        self.sync_all()
        self.mine_on(POOLS[1])
        mine_rows = vc.call(y, 'vault_list', {'mine': True})
        assert_equal(sorted(r['outpoint'] for r in mine_rows), sorted([lk['outpoint'], '%s:0' % mint_txid]))
        assert all(r['wallet'] for r in mine_rows)
        everything = vc.call(y, 'vault_list')
        assert_equal(sorted(r['outpoint'] for r in everything if r['wallet']), sorted(r['outpoint'] for r in mine_rows))
        assert_equal([r['wallet'] for r in vc.call(user, 'vault_list', {'owner': owner2['owner']})], [False])   # not the user's
        assert_equal(vc.call(y, 'vault_list', {'owner': owner2['owner']})[0]['wallet'], True)
        si = vc.call(y, 'set_getinfo', self.attestor_set)
        assert all(m['wallet'] is False for m in si['memberlist'])
        listed = vc.call(y, 'set_listsigned')
        assert_equal(listed, {'restored': False, 'records': []})
        self.report['vault'].update(['vault_list', 'set_getinfo', 'set_listsigned'])
        self.report['yed'].update(yc.checked)

        print('soak: consistency, then a node restart, a yewd restart, reorgs of 2 and 10 blocks')
        self.consistent(y, 'before')
        base = self.snapshot(y)
        self.restart_backend()
        y = self.nodes[YEWD]
        self.consistent(y, 'node restart')
        assert_equal(self.snapshot(y), base)
        self.restart_yewd()
        y = self.nodes[YEWD]
        self.consistent(y, 'yewd restart')
        assert_equal(self.snapshot(y), base)
        for depth in (2, 10):
            self.reorg(depth)
            y = self.nodes[YEWD]
        self.consistent(y, 'after the reorgs')

        n47 = sorted(self.report['vault'] & set(vc.methods)) + sorted(m for m in yc.checked if m.startswith('yed_'))
        print('contract methods checked through yewd: %s' % ', '.join(sorted(set(n47))))
        print('stock wallet reads checked against ycashd: %s' % ', '.join(sorted(self.report['stock'])))

    # --- soak steps ---------------------------------------------------------------------------

    def backend_rpc(self):
        cookie = os.path.join(self.options.tmpdir, 'node%d' % YEWD, 'backend', 'regtest', '.cookie')
        return kogany.KoganyRPC('http://127.0.0.1:%d/' % kogany.yewd_backend_rpc_port(YEWD), cookie=cookie)

    def restart_backend(self):
        """The node alone restarts (yewd keeps running and follows it: -28 meanwhile, H5)."""
        p = kogany.YEWD_BACKENDS[YEWD]
        argv = list(p.args)
        self.backend_rpc().stop()
        p.wait(60)
        y = self.nodes[YEWD]
        try:
            y.getbalance()
            raise AssertionError('yewd answered with its backend down')
        except JSONRPCException as e:
            assert_equal(e.error['code'], -28)
        kogany.YEWD_BACKENDS[YEWD] = subprocess.Popen(argv)
        wait_until(lambda: self.backend_rpc().getblockcount() >= 0, 'the backend to restart')
        for a, b in self.live_edges():
            if YEWD in (a, b):
                util.connect_nodes_bi(self.nodes, a, b)
        wait_until(lambda: y.getbalance() is not None, 'yewd to answer again')
        self.sync()

    def restart_yewd(self):
        """yewd alone restarts (the backend keeps running): the wallet reloads its state file."""
        p = util.bitcoind_processes[YEWD]
        argv = list(p.args)
        p.send_signal(signal.SIGTERM)
        p.wait(30)
        log = open(os.path.join(self.options.tmpdir, 'node%d' % YEWD, 'yewd.log'), 'ab')
        util.bitcoind_processes[YEWD] = subprocess.Popen(argv, stdout=log, stderr=log)
        url = util.rpc_url(YEWD)
        util.wait_for_bitcoind_start(util.bitcoind_processes[YEWD], url, YEWD)
        self.nodes[YEWD] = util.get_rpc_proxy(url, YEWD)

    def reorg(self, depth):
        """invalidateblock `depth` blocks under node 6 (forwarded to its backend), check the
        wallet rewound to the fork point, reconsiderblock, check it is back."""
        user, y = self.nodes[USER], self.nodes[YEWD]
        print('  reorg of %d blocks' % depth)
        # wallet activity in the blocks to be invalidated: a payment and node 6's own coinbases
        pay = user.sendtoaddress(y.getnewaddress(), 1)
        self.sync_all()
        self.mine_on(POOLS[0])
        self.mine_on(YEWD, depth - 1)
        self.consistent(y, 'before the %d-block reorg' % depth)
        before = self.snapshot(y)
        tip = y.getblockcount()
        fork = tip - depth
        target = y.getblockhash(fork + 1)
        y.invalidateblock(target)
        assert_equal(y.getblockcount(), fork)
        self.consistent(y, 'during the %d-block reorg' % depth)
        tx = y.gettransaction(pay)
        assert_equal(tx['confirmations'], 0)                     # back in the backend's mempool
        assert pay in y.getrawmempool()
        assert_equal(zat(y.getbalance('*', 1)), zat(before['balance1']) - COIN)
        for c in y.listunspent(0):
            if c['generated']:
                assert y.getblock(y.gettransaction(c['txid'])['blockhash'])['height'] <= fork
        y.reconsiderblock(target)
        wait_until(lambda: y.getblockcount() == tip, 'node 6 back at the tip')
        self.sync()
        self.consistent(y, 'after the %d-block reorg' % depth)
        assert_equal(self.snapshot(y), before)


if __name__ == '__main__':
    YewdS1().main()
