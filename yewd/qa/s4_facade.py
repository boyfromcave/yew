#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or https://www.opensource.org/licenses/mit-license.php .

"""
yewd S4 exit gate, the façade leg (workspace plan docs/plans/kogany/kogany-yellowback-plan.md section 3b
S4): the façade's method table against a plain ycashd wallet node, method by method.

Runs on ycash6's functional framework (YellowbackTestFramework, seven nodes, Yellowback live): node 0
(the user) is a plain ycashd wallet node, the reference; node 6 is the pair under test (a ycashd
-disablewallet backend + yewd + its signer; its wallet created first, the backend mining to it, H8).

  * arity: every method of the façade's table (the 47, R7, the 34 stock RPCs, the three raw helpers)
    called with too few and too many arguments answers what ycashd answers, code and message;
  * help: `help <method>` is ycashd's text for every one, and the `help` listing holds ycashd's lines
    for the K-25 set (the diff of the listings is empty);
  * errors: the documented error of each stock RPC S4 adds, provoked on both, same code and message;
  * the raw helpers served by the façade: decoderawtransaction / decodescript equal ycashd's JSON for a
    transparent, a coinbase, a Sapling and a vault transaction; createrawtransaction equal hex;
  * the stock RPCs S4 adds, exercised: settxfee, addmultisigaddress (the same address as ycashd's),
    z_getnewdiversifiedaddress, z_listreceivedbyaddress, z_sendmany t->z, z->t, z->z with its operations
    (z_getoperationstatus / result / z_listoperationids), z_exportwallet read by ycashd's importwallet and
    ycashd's dump read by yewd's z_importwallet, z_importpqkey, backupwallet and its restore (-wallet),
    encryptwallet (the pair stops), the locked wallet's refusals, walletpassphrase, walletlock.

    YCASH6_QA=<ycash6>/qa/rpc-tests ZCASHD=<ycashd> YEWD_BIN=<yewd> \\
        <venv>/bin/python yewd/qa/s4_facade.py --tmpdir=<dir> --portseed=<n>
"""

import json
import os
import re
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
from test_framework.util import assert_equal, assert_greater_than, bitcoind_processes, wait_and_assert_operationid_status  # noqa: E402
from test_framework.yellowback_util import POOLS, REF_LAG, USER, YellowbackTestFramework  # noqa: E402

YEWD = 6
COIN = 100_000_000
HERE = os.path.dirname(os.path.abspath(__file__))
TABLE = json.load(open(os.path.join(HERE, '..', 'facade', 'src', 'ycashd_rpc.json')))
PASS = 's4-facade-pass'

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

# F-S2-9: a backend that listens before it writes its cookie answers 401 (a warm-up).
_kcall = kogany.KoganyRPC.__call__


def _kcall_warmup(self, *args):
    try:
        return _kcall(self, *args)
    except JSONRPCException as e:
        if e.error.get('code') == -342 and 'non-JSON response 401' in e.error.get('message', ''):
            raise JSONRPCException({'code': -28, 'message': 'the backend has not written its cookie yet'})
        raise


kogany.KoganyRPC.__call__ = _kcall_warmup


def zat(v):
    return int(Decimal(v) * COIN)


def err(fn, *args):
    try:
        fn(*args)
    except JSONRPCException as e:
        return e.error
    raise AssertionError('%s%r did not fail' % (getattr(fn, '_service_name', fn), args))


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


def k25_lines(listing, methods):
    out = set()
    for line in listing.splitlines():
        m = line.split(' ')[0] if line and not line.startswith('==') else None
        if m in methods:
            out.add(line)
    return out


class YewdS4Facade(YellowbackTestFramework):

    def __init__(self):
        super().__init__(num_nodes=7)
        self.mine_address = None
        self.counts = {'arity': 0, 'help': 0, 'errors': 0, 'raw': 0}

    def node_args(self, i, extra=None):
        args = super().node_args(i, extra)
        if i == USER:
            # the reference's encryptwallet is enabled (its help text and arity answer depend on it);
            # yewd allows encryption unless -developerencryptwallet=0 (F-S4-3)
            args = args + ['-experimentalfeatures', '-developerencryptwallet']
        if i == YEWD and self.mine_address:
            args = args + ['-mineraddress=%s' % self.mine_address, '-minetolocalwallet=0']
        return args

    def setup_network(self, split=False):
        datadir = os.path.join(self.options.tmpdir, 'node%d' % YEWD)
        out = subprocess.check_output([os.environ['YEWD_BIN'], '-datadir=' + datadir, '-conf=ycash.conf', '-regtest', '-initwallet'])
        self.mine_address = json.loads(out)['mineaddress']
        super().setup_network(split)

    def settle(self):
        self.sync_all()
        for i, n in enumerate(self.nodes):
            if i != YEWD and n is not None:
                wait_until(lambda: n.getblockchaininfo()['fullyNotified'], 'node %d fullyNotified' % i)

    def restart_pair(self, extra=()):
        self.nodes[YEWD] = _start_node(YEWD, self.options.tmpdir, self.node_args(YEWD, list(extra)) + self.clock_args())
        self.reconnect(YEWD)
        self.settle()
        return self.nodes[YEWD]

    def same_error(self, ref, y, method, *args):
        def one(n, who):
            try:
                getattr(n, method)(*args)
            except JSONRPCException as e:
                return e.error
            raise AssertionError('%s %s%r did not fail' % (who, method, args))
        a, b = one(ref, 'ycashd'), one(y, 'yewd')
        assert_equal((b['code'], b['message']), (a['code'], a['message']))
        self.counts['errors'] += 1
        return a

    # --------------------------------------------------------------------------------------------

    def run_test(self):
        nodes = self.nodes
        ref, y = nodes[USER], nodes[YEWD]
        methods = sorted(TABLE['methods'])

        print('activate Yellowback (pools mine); fund the pair')
        self.activate(POOLS, quote_usd=50)
        self.mine_round_robin(POOLS, REF_LAG + 1)
        self.settle()
        ref.sendtoaddress(y.getnewaddress(), 40)
        self.settle()
        self.mine(POOLS[0])
        self.settle()

        print('arity: %d methods, too few and too many arguments, against ycashd' % len(methods))
        for m in methods:
            info = TABLE['methods'][m]
            counts = [info['max'] + 1]
            if info['min'] > 0:
                counts.append(info['min'] - 1)
            for k in counts:
                if m in ('walletlock', 'walletpassphrase'):
                    continue              # ycashd checks them only on an encrypted wallet (below)
                a = err(getattr(ref, m), *([None] * k))
                b = err(getattr(y, m), *([None] * k))
                assert_equal((b['code'], b['message']), (a['code'], a['message']))
                self.counts['arity'] += 1

        print('help: the texts and the K-25 lines of the listing')
        for m in methods:
            assert_equal(y.help(m), ref.help(m))
            self.counts['help'] += 1
        want, got = k25_lines(ref.help(), set(methods)), k25_lines(y.help(), set(methods))
        assert_equal(sorted(got ^ want), [])

        print('errors: the documented error of each stock RPC, on both')
        s = self.same_error
        s(ref, y, 'walletpassphrase', 'x', 1)                 # -15, unencrypted
        s(ref, y, 'walletlock')
        s(ref, y, 'settxfee', 'abc')
        s(ref, y, 'settxfee', -1)
        s(ref, y, 'backupwallet', 'a/b')
        s(ref, y, 'z_exportwallet', 'a.b')
        s(ref, y, 'importwallet', '/nonexistent/dump')
        s(ref, y, 'z_importwallet', '/nonexistent/dump')
        s(ref, y, 'z_importpqkey', 'x')
        s(ref, y, 'z_importpqkey', '9:' + '00' * 48)
        s(ref, y, 'z_importpqkey', '1:00')
        s(ref, y, 'addmultisigaddress', 0, [])
        s(ref, y, 'addmultisigaddress', 2, [ref.validateaddress(ref.getnewaddress())['pubkey']])
        s(ref, y, 'addmultisigaddress', 1, ['zz'])
        s(ref, y, 'z_getnewdiversifiedaddress', 'nonsense')
        s(ref, y, 'z_listreceivedbyaddress', 'nonsense')
        s(ref, y, 'z_sendmany', 'ANY_TADDR', [])
        s(ref, y, 'z_sendmany', 'ANY_TADDR', [{'address': 'nonsense', 'amount': 1}])
        s(ref, y, 'z_sendmany', 'ANY_TADDR', [{'address': ref.getnewaddress(), 'amount': 1, 'bogus': 1}])
        s(ref, y, 'z_sendmany', 'nonsense', [{'address': ref.getnewaddress(), 'amount': 1}])
        s(ref, y, 'z_sendmany', 'ANY_TADDR', [{'address': ref.getnewaddress(), 'amount': -1}])
        s(ref, y, 'z_sendmany', 'ANY_TADDR', [{'address': ref.getnewaddress(), 'amount': 1}], 1, None, 'Bogus')
        s(ref, y, 'z_getoperationstatus', 'notanarray')
        s(ref, y, 'decoderawtransaction', 'zz')
        s(ref, y, 'decoderawtransaction', '00')
        s(ref, y, 'decodescript', 'zz')
        s(ref, y, 'createrawtransaction', None, {})
        s(ref, y, 'createrawtransaction', [], {'nonsense': 1})
        s(ref, y, 'createrawtransaction', [{'txid': 'zz', 'vout': 0}], {})
        assert_equal(y.createrawtransaction([{'txid': 'aa', 'vout': 0}], {}), ref.createrawtransaction([{'txid': 'aa', 'vout': 0}], {}))
        s(ref, y, 'createrawtransaction', [{'txid': '11' * 32}], {})
        s(ref, y, 'createrawtransaction', [], {}, -1)
        s(ref, y, 'createrawtransaction', [], {}, 0, 1)
        s(ref, y, 'encryptwallet', '')

        print('raw helpers: decoderawtransaction and decodescript equal ycashd\'s; createrawtransaction equal hex')
        tip = ref.getblock(ref.getbestblockhash())
        samples = [tip['tx'][0]]                                              # a coinbase
        txid = ref.sendtoaddress(ref.getnewaddress(), 1)                      # a transparent spend (scriptSigs)
        samples.append(txid)
        for t in samples:
            h = ref.getrawtransaction(t)
            assert_equal(y.decoderawtransaction(h), ref.decoderawtransaction(h))
            self.counts['raw'] += 1
        for sc in ['51', '6a0401020304', '76a914' + '11' * 20 + '88ac', 'a914' + '22' * 20 + '87', '',
                   '52' + '21' + '02' + '33' * 32 + '21' + '03' + '44' * 32 + '52ae', '4c', 'b175']:
            assert_equal(y.decodescript(sc), ref.decodescript(sc))
            self.counts['raw'] += 1
        u = ref.listunspent()[0]
        args = ([{'txid': u['txid'], 'vout': u['vout']}], {ref.getnewaddress(): Decimal('0.5')})
        assert_equal(y.createrawtransaction(*args), ref.createrawtransaction(*args))
        assert_equal(y.createrawtransaction(*args, 7, ref.getblockcount() + 50), ref.createrawtransaction(*args, 7, ref.getblockcount() + 50))
        self.counts['raw'] += 2

        print('settxfee, getwalletinfo.paytxfee')
        assert_equal(y.settxfee(Decimal('0.0001')), True)
        assert_equal(y.getwalletinfo()['paytxfee'], Decimal('0.0001'))
        y.settxfee(0)

        print('addmultisigaddress: the same P2SH address as ycashd for the same keys; validateaddress shows the script')
        pks = sorted([ref.validateaddress(ref.getnewaddress())['pubkey'], y.validateaddress(y.getnewaddress())['pubkey']])
        ma = y.addmultisigaddress(1, pks)
        assert_equal(ma, ref.addmultisigaddress(1, pks))
        va = y.validateaddress(ma)
        assert_equal((va['isscript'], va['script'], va['sigsrequired']), (True, 'multisig', 1))
        assert_equal(va['hex'], ref.validateaddress(ma)['hex'])

        print('z_sendmany t->z, z->t, z->z; the operations')
        ys = y.z_getnewaddress('sapling')
        div = y.z_getnewdiversifiedaddress(ys)
        assert div != ys and div.startswith('yregtestsapling')
        taddr = y.getnewaddress()
        ref.sendtoaddress(taddr, Decimal('20.001'))
        self.settle()
        self.mine(POOLS[0])
        self.settle()
        before = set(y.z_listoperationids())
        opid = y.z_sendmany(taddr, [{'address': ys, 'amount': Decimal('20')}], 1, None)
        assert opid.startswith('opid-')
        st = y.z_getoperationstatus([opid])
        assert_equal([s['id'] for s in st], [opid])
        assert_equal(set(y.z_listoperationids()) - before, {opid})
        txid = wait_and_assert_operationid_status(y, opid)
        assert_equal(y.z_getoperationresult([opid]), [])                 # taken by the wait
        self.settle()
        self.mine(POOLS[1])
        self.settle()
        assert_equal(y.z_getbalance(ys), Decimal('20'))
        rows = y.z_listreceivedbyaddress(ys)
        assert_equal([(r['txid'], r['pool'], r['amountZat']) for r in rows], [(txid, 'sapling', 20 * COIN)])
        h = ref.getrawtransaction(txid)
        assert_equal(y.decoderawtransaction(h), ref.decoderawtransaction(h))    # a Sapling transaction
        self.counts['raw'] += 1
        to_t = ref.getnewaddress()
        opid = y.z_sendmany(ys, [{'address': to_t, 'amount': Decimal('3')}], 1, None, 'AllowRevealedRecipients')
        t2 = wait_and_assert_operationid_status(y, opid)
        self.settle()
        self.mine(POOLS[2])
        self.settle()
        assert_equal(y.z_getbalance(ys), Decimal('20') - Decimal(y.decoderawtransaction(y.getrawtransaction(t2))['valueBalance']))   # the change came back to ys
        to_z = ref.z_getnewaddress('sapling')
        opid = y.z_sendmany(ys, [{'address': to_z, 'amount': Decimal('1'), 'memo': 'abcd'}], 1, None)
        wait_and_assert_operationid_status(y, opid)
        self.settle()
        self.mine(POOLS[2])
        self.settle()
        assert_equal(ref.getreceivedbyaddress(to_t), Decimal('3'))
        assert_equal(ref.z_getbalance(to_z), Decimal('1'))
        assert_equal([n['memo'][:4] for n in ref.z_listunspent(1, 9999, False, [to_z])], ['abcd'])
        assert ref.getrawtransaction(t2, 1)['vShieldedSpend']
        # a failed operation: more than the address holds
        opid = y.z_sendmany(ys, [{'address': to_t, 'amount': Decimal('1000')}], 1, None, 'AllowRevealedRecipients')
        res = None
        for _ in range(60):
            res = y.z_getoperationresult([opid])
            if res:
                break
            time.sleep(0.5)
        assert_equal((res[0]['status'], res[0]['error']['code']), ('failed', -8))
        assert res[0]['error']['message'].startswith('Insufficient funds: have '), res[0]

        print('z_importpqkey, the dumps: z_exportwallet read by ycashd, ycashd\'s read by yewd')
        own = ref.vault_getnewowner()
        dump_ref = ref.z_exportwallet('refdump')
        line = [l for l in open(dump_ref).read().splitlines() if ('owner=' + own['owner']) in l][0]
        r = y.z_importpqkey(line, False)
        assert_equal((r['pqkeyid'], r['added'], r['index']), (own['owner'], True, None))
        assert_equal(y.z_importpqkey(line, False)['added'], False)
        assert_equal(err(y.z_importpqkey, line.replace('owner=01', 'owner=02'))['code'], -5)
        yown = y.vault_getnewowner()
        ya = y.getnewaddress()
        dump_y = y.z_exportwallet('yewddump')
        text = open(dump_y).read()
        assert ('owner=' + yown['owner']) in text and ('addr=' + ya) in text
        assert 'recovery_phrase="' in text and '# End of dump' in text
        assert_equal(err(y.z_exportwallet, 'yewddump')['code'], -8)        # never overwritten
        ref.importwallet(dump_y)
        assert_equal(ref.validateaddress(ya)['ismine'], True)
        assert_equal([v['outpoint'] for v in ref.vault_list({'owner': yown['owner']})], [])
        rk = ref.getnewaddress()
        dump_ref2 = ref.z_exportwallet('refdump2')
        y.z_importwallet(dump_ref2)
        assert_equal(y.validateaddress(rk)['ismine'], True)
        assert_equal(y.getwalletinfo().get('has_external_imports'), True)

        print('backupwallet, then a restore of the backup (-wallet)')
        zb = y.z_getbalance(ys)
        bk = y.backupwallet('pairbackup')
        assert os.path.exists(bk)
        later = y.getnewaddress()
        self.stop_pair()
        self.wipe_pair_wallet()
        y = self.restart_pair(['-wallet=' + bk, '-rescan'])
        assert_equal(y.validateaddress(ya)['ismine'], True)
        assert_equal(y.z_getbalance(ys), zb)
        assert later not in [r['address'] for r in y.listunspent(0)]

        print('encryptwallet stops the pair; locked, it refuses; walletpassphrase; walletlock')
        assert_equal(err(y.walletpassphrase, PASS, 10)['code'], -15)
        y.encryptwallet(PASS)
        self.wait_pair_stopped()
        y = self.restart_pair()
        for m, args in (('vault_getnewowner', ()), ('getnewaddress', ()), ('z_exportwallet', ('lockeddump',)),
                        ('sendtoaddress', (ref.getnewaddress(), 1)), ('dumpprivkey', (ya,))):
            e = err(getattr(y, m), *args)
            assert_equal(e['code'], -13)
            assert 'walletpassphrase' in e['message'], (m, e)
        assert_equal(y.getwalletinfo()['unlocked_until'], 0)
        for k in (0, 3):
            e = err(y.walletpassphrase, *([None] * k))
            assert_equal(e['code'], -32602)
            assert e['message'].endswith('\n\n' + TABLE['methods']['walletpassphrase']['help']), e
        assert_equal(err(y.walletpassphrase, 'wrong', 60)['code'], -14)
        y.walletpassphrase(PASS, 600)
        assert_greater_than(y.getwalletinfo()['unlocked_until'], 0)
        y.vault_getnewowner()
        y.sendtoaddress(ref.getnewaddress(), 1)
        y.walletlock()
        assert_equal(err(y.vault_getnewowner)['code'], -13)
        assert_equal(err(y.encryptwallet, PASS)['code'], -15)

        print('S4 façade leg: %(arity)d arity checks, %(help)d help texts, %(errors)d error pairs, %(raw)d raw helper answers equal ycashd\'s' % self.counts)

    # --- the pair's process -----------------------------------------------------------------------

    def stop_pair(self):
        util.stop_node(self.nodes[YEWD], YEWD)
        self.nodes[YEWD] = None

    def wait_pair_stopped(self, timeout=60):
        p = bitcoind_processes[YEWD]
        deadline = time.time() + timeout
        while p.poll() is None:
            assert time.time() < deadline, 'the pair did not stop after encryptwallet'
            time.sleep(0.25)
        del bitcoind_processes[YEWD]
        kogany.wait_yewd_backend(YEWD)
        self.nodes[YEWD] = None

    def wipe_pair_wallet(self):
        import shutil
        d = os.path.join(self.options.tmpdir, 'node%d' % YEWD, 'regtest')
        for sub in ('yewd', 'signer'):
            shutil.rmtree(os.path.join(d, sub), ignore_errors=True)


if __name__ == '__main__':
    YewdS4Facade().main()
