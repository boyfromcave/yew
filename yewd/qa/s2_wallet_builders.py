#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or https://www.opensource.org/licenses/mit-license.php .

"""
yewd S2 exit gate (workspace plan docs/plans/kogany/kogany-yellowback-plan.md section 3b S2): the
build-and-send subset of both contract suites, served by yewd in front of a wallet-less node, every
signature made in the yewd-signer process (K-24).

Runs on ycash6's functional framework (YellowbackTestFramework, seven nodes): nodes 0-5 are the
standard topology on plain ycashd; node 6 is the pair under test (ycashd -disablewallet + yewd, the
harness's YEWD_BIN mode), as in yewd/qa/s1_wallet_reads.py. Each build RPC is called on node 6 and,
where the result is a chain object, the same request is made of the plain ycashd wallet of node 0;
the two transactions confirm in the same network, and what the chain records for them is compared
(set_getinfo, vault_list rows, the act's decoded fields, yed_gettxinfo), with every node's
vault_getinfo.statehash and yed_getstatehash equal at each checkpoint (plan section 4.3 rule 3:
parity is the same state from the same requests, not the same bytes).

Stages: YEC (sendtoaddress, sendmany, lockunspent, getrawchangeaddress, signrawtransaction), sets
(set_create, set_join both ways, set_signact, set_sendact, set_heartbeat, set_buildact, set_leave),
vaults (vault_lock, vault_buildunlock, set_signunlock, vault_send, vault_buildcancel, set_signcancel,
vault_release, vault_refee, vault_ownerspend, the sign-once refusal, set_importsigned,
set_acknowledgerestore), YED (yed_send, yed_sendmany, yed_redeem when the builders serve them).

    YCASH6_QA=<ycash6>/qa/rpc-tests ZCASHD=<ycashd> YEWD_BIN=<yewd> \\
        <venv>/bin/python yewd/qa/s2_wallet_builders.py --tmpdir=<dir> [--nocleanup] [--portseed=<n>]
"""

import json
import os
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

from test_framework import util                                               # noqa: E402
from test_framework import yellowback_util as yu                              # noqa: E402
from test_framework.authproxy import JSONRPCException                         # noqa: E402
from test_framework.util import assert_equal                                  # noqa: E402
from test_framework.vault_contract import Contract as VaultContract           # noqa: E402
from test_framework.yellowback_attest import wallet_mint                      # noqa: E402
from test_framework.yellowback_util import POOLS, REF_LAG, USER, YellowbackTestFramework  # noqa: E402
import yellowback_rpc_contract as yrc                                         # noqa: E402

YEWD = 6
COIN = 100_000_000

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


def rpc_error(fn, *args):
    try:
        fn(*args)
    except JSONRPCException as e:
        return e.error
    raise AssertionError('%s%r did not fail' % (getattr(fn, '_service_name', fn), args))


def strip(d, keys):
    return {k: v for k, v in d.items() if k not in keys}


class YewdS2(YellowbackTestFramework):

    def __init__(self):
        super().__init__(num_nodes=7)
        self.mine_address = None
        self.served = {'vault': set(), 'yed': set(), 'stock': set()}

    def node_args(self, i, extra=None):
        args = super().node_args(i, extra)
        if i == YEWD:
            args = args + ['-mineraddress=%s' % self.mine_address, '-minetolocalwallet=0']
        return args

    def setup_network(self, split=False):
        datadir = os.path.join(self.options.tmpdir, 'node%d' % YEWD)
        out = subprocess.check_output([os.environ['YEWD_BIN'], '-datadir=' + datadir, '-conf=ycash.conf', '-regtest', '-initwallet'])
        self.mine_address = json.loads(out)['mineaddress']
        print('node %d: yewd wallet created, coinbase address %s' % (YEWD, self.mine_address))
        super().setup_network(split)

    def plain_settle(self):
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

    def confirm(self, *txids):
        """Mine one block on a pool and check every txid confirmed in it, on every node."""
        self.sync()
        self.mine_on(POOLS[0])
        for t in txids:
            for i, n in enumerate(self.nodes):
                if n is None:
                    continue
                raw = n.getrawtransaction(t, 1)
                assert raw.get('confirmations', 0) >= 1, 'node %d: %s did not confirm' % (i, t)
        self.checkpoint('after %s' % ','.join(t[:8] for t in txids))

    # --- the run ------------------------------------------------------------------------------

    def run_test(self):
        nodes = self.nodes
        user, y = nodes[USER], nodes[YEWD]
        self.vc = VaultContract(os.path.join(QA, '..', '..', 'doc', 'vault-rpc-contract.json'))
        self.yc = yrc.Contract(yrc.CONTRACT)

        print('activate Yellowback at $50, then node 6 mines coinbases and is paid YEC')
        self.activate(POOLS, quote_usd=50)
        self.mine_round_robin(POOLS, REF_LAG + 1)
        self.sync()
        self.mine_on(YEWD, 2)
        for _ in range(4):
            user.sendtoaddress(y.getnewaddress(), 25)
        self.sync()
        self.mine_on(POOLS[1])
        assert_equal(y.getbalance(), 100)

        self.stage_yec(user, y)
        set_id = self.stage_sets(user, y)
        self.stage_vaults(user, y, set_id)
        self.stage_yed(user, y)

        print('served and checked through yewd: vault %s; yed %s; stock %s' % (
            ', '.join(sorted(self.served['vault'])), ', '.join(sorted(self.served['yed'])), ', '.join(sorted(self.served['stock']))))
        print('the 47 built and checked here: %d' % len(self.served['vault'] | self.served['yed']))

    # --- YEC ------------------------------------------------------------------------------------

    def stage_yec(self, user, y):
        print('YEC: sendtoaddress, sendmany, lockunspent, getrawchangeaddress, signrawtransaction')
        a = user.getnewaddress()
        t1 = y.sendtoaddress(a, 3)
        t2 = y.sendmany('', {user.getnewaddress(): Decimal('1.5'), user.getnewaddress(): 2})
        self.sync()
        assert t1 in user.getrawmempool() and t2 in user.getrawmempool()
        self.confirm(t1, t2)
        assert_equal(user.getreceivedbyaddress(a), 3)
        tx = y.gettransaction(t1)
        assert_equal((tx['amount'], tx['confirmations']), (-3, 1))
        assert tx['fee'] < 0
        e = rpc_error(y.sendtoaddress, 'nonsense', 1)
        assert_equal(e['code'], -5)
        e = rpc_error(y.sendtoaddress, a, 0)
        assert_equal(e['code'], -3)
        e = rpc_error(y.sendtoaddress, a, 100000)
        assert_equal(e['code'], -6)
        # lockunspent: a locked coin is not spent
        coins = y.listunspent()
        assert y.lockunspent(False, [{'txid': coins[0]['txid'], 'vout': coins[0]['vout']}])
        assert_equal([(r['txid'], r['vout']) for r in y.listlockunspent()], [(coins[0]['txid'], coins[0]['vout'])])
        assert all((c['txid'], c['vout']) != (coins[0]['txid'], coins[0]['vout']) for c in y.listunspent())
        assert y.lockunspent(True)
        assert_equal(y.listlockunspent(), [])
        ch = y.getrawchangeaddress()
        assert y.validateaddress(ch)['ismine']
        # signrawtransaction: the node builds, the wallet (its signer) signs
        coin = y.listunspent()[0]
        raw = user.createrawtransaction([{'txid': coin['txid'], 'vout': coin['vout']}], {user.getnewaddress(): coin['amount'] - Decimal('0.0001')})
        signed = y.signrawtransaction(raw)
        assert_equal(signed['complete'], True)
        unsigned = y.signrawtransaction(raw, [], [])          # with keys given (none): the node verifies only
        assert_equal(unsigned['complete'], False)
        t3 = user.sendrawtransaction(signed['hex'])
        self.confirm(t3)
        self.served['stock'].update(['sendtoaddress', 'sendmany', 'lockunspent', 'getrawchangeaddress', 'signrawtransaction'])

    # --- sets -----------------------------------------------------------------------------------

    def stage_sets(self, user, y):
        vc = self.vc
        print('sets: set_create on yewd and on ycashd with the same parameters')
        spec = {'seats': 3, 'unlockthreshold': 2, 'cancelthreshold': 1, 'slashthreshold': 2, 'maturity': 2}
        ys = vc.call(y, 'set_create', dict(spec))
        us = vc.call(user, 'set_create', dict(spec))
        self.confirm(ys['txid'], us['txid'])
        yi, ui = vc.call(y, 'set_getinfo', ys['setid']), vc.call(user, 'set_getinfo', us['setid'])
        ignore = ('setid', 'admitkey', 'memberlist')
        assert_equal(strip(yi, ignore), strip(ui, ignore))
        vc.error('the set parameters are out of range', y, 'set_create', dict(spec, seats=16))
        vc.error('unknown set', y, 'set_join', '11' * 32, 1, 600)
        sid = ys['setid']

        print('sets: set_join (yewd holds the admit key: complete at once), a ycashd member signed in by yewd')
        h = y.getblockcount()
        j1 = vc.call(y, 'set_join', sid, 1, h + 500)
        assert_equal((j1['complete'], j1['type']), (True, 'join'))
        self.confirm(j1['txid'])
        j2 = vc.call(user, 'set_join', sid, 1, h + 500)
        assert_equal(j2['complete'], False)
        s2 = vc.call(y, 'set_signact', j2['hex'], sid)           # the admit key (fewer than slashthreshold current)
        assert_equal(s2['complete'], True)
        t = vc.call(user, 'set_sendact', s2['hex'])
        self.confirm(t)
        self.mine_on(POOLS[1], 2)                                 # maturity
        self.member_user = j2['memberkey']
        self.member_yewd = j1['memberkey']
        # a third member: a second key of the user's wallet, cosigned by the two current members (yewd and the user)
        j3 = vc.call(user, 'set_join', sid, 1, h + 500)
        assert_equal(j3['complete'], False)
        s3 = vc.call(y, 'set_signact', j3['hex'])
        s3 = vc.call(user, 'set_signact', s3['hex'])
        assert_equal(s3['complete'], True)
        t = vc.call(user, 'set_sendact', s3['hex'])
        self.confirm(t)
        self.mine_on(POOLS[1], 2)
        info = vc.call(y, 'set_getinfo', sid)
        assert_equal((info['members'], info['current']), (3, 3))
        assert_equal(sorted(m['wallet'] for m in info['memberlist']), [False, False, True])

        print('sets: set_heartbeat, set_buildact + set_signact + set_sendact (a remove), dryrun previews')
        hb = vc.call(y, 'set_heartbeat', sid)
        assert_equal(hb['memberkey'], self.member_yewd)
        self.confirm(hb['txid'])
        b = vc.call(y, 'set_buildact', 'heartbeat', {'setid': sid, 'memberkey': self.member_yewd})
        assert_equal((b['complete'], b['required']), (False, 1))
        b = vc.call(y, 'set_signact', b['hex'])
        assert_equal(b['complete'], True)
        pv = vc.call(y, 'set_sendact', b['hex'], {'dryrun': True})
        assert_equal(pv['wouldrefuse'], None)
        assert_equal(pv['act']['type'], 'heartbeat')
        t = vc.call(y, 'set_sendact', b['hex'])
        self.confirm(t)
        vc.error('unknown act type', y, 'set_buildact', 'bogus', {})
        vc.error('the transaction carries no YV act', y, 'set_signact', user.createrawtransaction([], {user.getnewaddress(): 1}))
        self.served['vault'].update(['set_create', 'set_join', 'set_signact', 'set_sendact', 'set_heartbeat', 'set_buildact'])
        return sid

    # --- vaults ---------------------------------------------------------------------------------

    def stage_vaults(self, user, y, sid):
        vc = self.vc
        print('vaults: vault_lock on yewd and on ycashd with the same request')
        h = y.getblockcount()
        req = {'tag': 'TEST', 'setid': sid, 'delay': 4, 'ownerheight': h + 30, 'amount': 6}
        yv = vc.call(y, 'vault_lock', dict(req))
        uv = vc.call(user, 'vault_lock', dict(req))
        self.confirm(yv['txid'], uv['txid'])
        yrow = [r for r in vc.call(y, 'vault_list', {'setid': sid}) if r['outpoint'] == yv['outpoint']][0]
        urow = [r for r in vc.call(user, 'vault_list', {'setid': sid}) if r['outpoint'] == uv['outpoint']][0]
        ignore = ('txid', 'outpoint', 'script', 'owner', 'wallet', 'height')
        assert_equal(strip(yrow, ignore), strip(urow, ignore))
        assert_equal((yrow['wallet'], yrow['owner']), (True, yv['owner']))
        vc.error('vault parameters out of range', y, 'vault_lock', dict(req, delay=0))
        vc.error('ownerkey-removed', y, 'vault_lock', dict(req, ownerkey='02' * 33))
        vc.error('appheight on a tag no module governs', y, 'vault_lock', dict(req, appheight=h + 50))

        print('vaults: vault_buildunlock on yewd, set_signunlock by yewd and the user, vault_send on yewd')
        dest = user.getnewaddress()
        bu = vc.call(y, 'vault_buildunlock', yv['outpoint'], [{'address': dest, 'amount': 2}])
        assert_equal((bu['build'], bu['required']), ('new', 2))
        again = vc.call(y, 'vault_buildunlock', yv['outpoint'], [{'address': dest, 'amount': 2}])
        assert_equal((again['build'], again['hex']), ('reused', bu['hex']))
        vc.error('already built a different unlock', y, 'vault_buildunlock', yv['outpoint'], [{'address': dest, 'amount': 1}])
        s1 = vc.call(y, 'set_signunlock', bu['hex'])
        assert_equal((s1['signatures'], s1['complete'], s1['sighash']), (1, False, bu['sighash']))
        s2 = vc.call(user, 'set_signunlock', s1['hex'])
        assert_equal(s2['complete'], True)
        pv = vc.call(y, 'vault_send', s2['hex'], {'dryrun': True})
        assert_equal((pv['wouldrefuse'], pv['template']['kind'], pv['template']['selector']), (None, 'vault', 1))
        sent = vc.call(y, 'vault_send', s2['hex'])
        self.confirm(sent)
        recs = vc.call(y, 'set_listsigned')
        assert_equal([(r['setid'], r['prevout'], r['role'], r['sighash']) for r in recs['records']],
                     [(sid, yv['outpoint'], 1, bu['sighash'])])
        intent = '%s:0' % sent
        rows = {r['outpoint']: r for r in vc.call(y, 'vault_list', {'setid': sid})}
        assert_equal((rows[intent]['kind'], rows[intent]['valuezat']), ('intent', 2 * COIN))
        assert_equal(rows['%s:1' % sent]['valuezat'], 4 * COIN)     # the re-lock

        print('vaults: the same unlock by ycashd, compared; yewd cancels the ycashd intent (one cancel signature)')
        ub = vc.call(user, 'vault_buildunlock', uv['outpoint'], [{'address': y.getnewaddress(), 'amount': 2}])
        u1 = vc.call(user, 'set_signunlock', ub['hex'])
        u2 = vc.call(y, 'set_signunlock', u1['hex'])
        assert_equal(u2['complete'], True)
        usent = vc.call(user, 'vault_send', u2['hex'])
        self.confirm(usent)
        urows = {r['outpoint']: r for r in vc.call(user, 'vault_list', {'setid': sid})}
        ign = ('txid', 'outpoint', 'script', 'owner', 'wallet', 'height', 'recipienthash', 'vaulthash', 'origin',
               'matureheight')
        assert_equal(strip(urows['%s:0' % usent], ign), strip(rows[intent], ign))
        bc = vc.call(y, 'vault_buildcancel', '%s:0' % usent)
        assert_equal(bc['required'], 1)
        sc = vc.call(y, 'set_signcancel', bc['hex'])
        assert_equal(sc['complete'], True)
        cancel = vc.call(y, 'vault_send', sc['hex'])
        self.confirm(cancel)
        assert '%s:0' % cancel in {r['outpoint'] for r in vc.call(y, 'vault_list', {'setid': sid})}
        vc.error('the template input is not an intent', y, 'set_signcancel', bu['hex'])
        vc.error('the template input is not a vault', y, 'set_signunlock', bc['hex'])

        print('vaults: the sign-once record refuses a second, different unlock of a signed vault')
        relock = '%s:1' % sent
        x = vc.call(y, 'vault_buildunlock', relock, [{'address': dest, 'amount': 1}])
        vc.call(y, 'set_signunlock', x['hex'])
        x2 = vc.call(y, 'vault_buildunlock', relock, [{'address': dest, 'amount': Decimal('0.5')}], True)
        vc.error('set-sign-once', y, 'set_signunlock', x2['hex'])
        vc.error('set-sign-once', y, 'set_importsigned', [{'setid': sid, 'prevout': relock, 'role': 1, 'sighash': x2['sighash']}])
        imp = vc.call(y, 'set_importsigned', [{'setid': sid, 'prevout': relock, 'role': 1, 'sighash': x['sighash']}])
        assert_equal((imp['imported'], imp['present']), (0, 1))
        ack = vc.call(y, 'set_acknowledgerestore')
        assert_equal(ack['restored'], False)

        print('vaults: vault_release of the intent after its delay (to the user), vault_refee')
        self.mine_on(POOLS[2], 4)
        vc.error('not an unspent intent output', y, 'vault_release', '%s:0' % cancel)
        rel = vc.call(user, 'vault_release', intent)
        self.confirm(rel)
        rf = vc.call(y, 'vault_refee', x['hex'])
        assert_equal(rf['sighash'], x['sighash'])

        print('vaults: vault_ownerspend (the SLH-DSA owner spend, made in the signer) after ownerheight')
        while y.getblockcount() <= h + 30:
            self.mine_on(POOLS[0])
        o = vc.call(y, 'vault_ownerspend', relock, y.getnewaddress())
        assert_equal(o['selector'], 2)
        self.confirm(o['txid'])
        self.served['vault'].update(['vault_lock', 'vault_buildunlock', 'set_signunlock', 'vault_send', 'vault_buildcancel',
                                     'set_signcancel', 'vault_release', 'vault_refee', 'vault_ownerspend', 'set_importsigned',
                                     'set_acknowledgerestore', 'set_listsigned'])

    # --- YED ------------------------------------------------------------------------------------

    def stage_yed(self, user, y):
        try:
            y.yed_estimatesend(y.yed_getnewaddress(), 100)
        except JSONRPCException as e:
            if e.error['code'] == -32601:
                print('YED: the YED builders are not served yet (%s)' % e.error['message'])
                return
            raise
        print('YED: a transfer in, yed_send out, compared with ycashd')
        wallet_mint(self, user, 10000, 48)
        self.mine_on(POOLS[1])
        ya = y.yed_getnewaddress()
        user.yed_send(ya, 5000)
        self.confirm(user.getrawmempool()[0]) if user.getrawmempool() else self.mine_on(POOLS[0])
        ua = user.yed_getnewaddress()
        r = self.yc.check('yed_send', y.yed_send(ua, 1500))
        self.confirm(r['txid'])
        ti = user.yed_gettxinfo(r['txid'])
        assert_equal(ti['type'], 'transfer')
        self.served['yed'].add('yed_send')


if __name__ == '__main__':
    YewdS2().main()
