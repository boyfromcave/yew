#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or https://www.opensource.org/licenses/mit-license.php .

"""
yewd S3 exit gate (workspace plan docs/plans/kogany/kogany-yellowback-plan.md section 3b S3): the
roles' scripts with their role nodes being a wallet-less node + yewd + its signer (the harness's
YEWD_BIN mode, as yewd/qa/s2_wallet_builders.py runs one pair), every other node a plain ycashd.

    --stage=<name>     which script, unchanged (its run_test is the script's own):
        attest_wallet  yellowback_attest_wallet.py, nodes 6 and 7 (the attestor wallets) as pairs:
                       yed_registerattestor, yed_signattestation and its guard across a restart and a
                       reorg, importprivkey (register_and_arm imports seq 2-4's keys into node 6),
                       yed_revive, set_leave, yed_withdrawbond's refusals, dumpprivkey
        attest_bond    yellowback_attest_bond.py, node 0 (the user, who registers) as a pair
        attest_agent   yellowback_attest_agent.py, nodes 6 and 7 as pairs (needs YELLOWBACK_ATTEST_BIN)
        cancel_agent   yellowback_cancel_agent.py, node 6 as a pair (needs YELLOWBACK_ATTEST_BIN)
        roles          this file's own steps, re-expressing the role steps whose scripts drive a
                       wallet the pair cannot be yet (yellowback_cancel_limit.py's armed mint, notice
                       and claim on one node): yewd node 6 registers and attests, ycashd mints and
                       claims, yewd co-signs and cancels the claim (yed_signcancelcosign,
                       yed_buildcancel, set_signcancel, vault_send), reports an equivocation
                       (yed_reportequivocation, wait and pending), leaves and withdraws its bond
                       (yed_withdrawbond), signs a binding (signmessage, checked by verifymessage),
                       and runs x402's rpcWalletSigner call set; yed_getstatehash and
                       vault_getinfo.statehash equal on every node at each checkpoint
    --pairs=6,7        override the stage's pair nodes

    YCASH6_QA=<ycash6>/qa/rpc-tests ZCASHD=<ycashd> YEWD_BIN=<yewd> \\
        <venv>/bin/python yewd/qa/s3_roles.py --stage=attest_wallet --tmpdir=<dir> --portseed=<n>
"""

import importlib
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


def _arg(name, default=None):
    for a in list(sys.argv[1:]):
        if a.startswith('--%s=' % name):
            sys.argv.remove(a)
            return a.split('=', 1)[1]
    return default


STAGE = _arg('stage', 'roles')
STAGES = {
    'attest_wallet': ('yellowback_attest_wallet', 'YellowbackAttestWalletTest', [6, 7]),
    'attest_bond': ('yellowback_attest_bond', None, [0]),
    'attest_agent': ('yellowback_attest_agent', None, [6, 7]),
    'cancel_agent': ('yellowback_cancel_agent', None, [6]),
    'roles': (None, None, [6, 7]),
}
if STAGE not in STAGES:
    sys.exit('unknown --stage=%s (one of %s)' % (STAGE, ', '.join(STAGES)))
_pairs = _arg('pairs')
PAIRS = [int(x) for x in _pairs.split(',')] if _pairs else STAGES[STAGE][2]

from test_framework import util, kogany                                       # noqa: E402
from test_framework import yellowback_util as yu                              # noqa: E402
from test_framework.authproxy import JSONRPCException                         # noqa: E402

_start_node = util.start_node


class PairProxy:
    """A pair node's RPC proxy. The harness skips the fullyNotified wait for every node under
    YEWD_BIN (a -disablewallet backend never reports it), which leaves the plain ycashd nodes of a
    mixed run without their wallet-notification wait (their wallet can lag a block it has: finding
    F-S3-1). So the wait is kept, and a pair answers fullyNotified for itself: yewd brings its wallet
    to the tip at every wallet call (the barrier, H1)."""

    def __init__(self, inner):
        self.__dict__['_inner'] = inner

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def __setattr__(self, name, value):
        setattr(self._inner, name, value)

    def getblockchaininfo(self, *a):
        r = self._inner.getblockchaininfo(*a)
        r['fullyNotified'] = True
        return r

    def getmempoolinfo(self, *a):
        r = self._inner.getmempoolinfo(*a)
        r['fullyNotified'] = True
        return r


util._yewd_skips_notified = lambda: False


def _start_node_pairs(i, *a, **kw):
    if i in PAIRS:
        return PairProxy(_start_node(i, *a, **kw))
    saved = os.environ.pop('YEWD_BIN')
    try:
        return _start_node(i, *a, **kw)
    finally:
        os.environ['YEWD_BIN'] = saved


util.start_node = _start_node_pairs
yu.start_node = _start_node_pairs

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


def pair_mixin(base):
    """The pair plumbing on any YellowbackTestFramework: each pair node's wallet is created first
    (yewd -initwallet) and its backend mines to that wallet's coinbase address (H8); the plain
    nodes' fullyNotified wait is kept for them only."""

    class Paired(base):
        def setup_network(self, *a, **kw):
            self.mine_addresses = {}
            for i in PAIRS:
                datadir = os.path.join(self.options.tmpdir, 'node%d' % i)
                out = subprocess.check_output([os.environ['YEWD_BIN'], '-datadir=' + datadir, '-conf=ycash.conf',
                                               '-regtest', '-initwallet'])
                self.mine_addresses[i] = json.loads(out)['mineaddress']
                print('node %d: yewd wallet created, coinbase address %s' % (i, self.mine_addresses[i]))
            return super().setup_network(*a, **kw)

        def node_args(self, i, extra=None):
            args = super().node_args(i, extra)
            if i in PAIRS and getattr(self, 'mine_addresses', None) and i in self.mine_addresses:
                args = args + ['-mineraddress=%s' % self.mine_addresses[i], '-minetolocalwallet=0']
            return args

    Paired.__name__ = base.__name__ + 'OnYewd'
    return Paired


def run_script():
    module, cls_name, _ = STAGES[STAGE]
    m = importlib.import_module(module)
    if cls_name is None:
        cands = [v for k, v in vars(m).items() if isinstance(v, type) and issubclass(v, yu.YellowbackTestFramework)
                 and v.__module__ == m.__name__]
        assert len(cands) == 1, cands
        cls = cands[0]
    else:
        cls = getattr(m, cls_name)
    print('S3 stage %s: %s.%s with nodes %s as backend + yewd' % (STAGE, module, cls.__name__, PAIRS))
    pair_mixin(cls)().main()


# --------------------------------------------------------------------------------- the roles stage

def roles_main():
    from test_framework.util import assert_equal, hex_str_to_bytes, bytes_to_hex_str   # noqa: E402
    from test_framework.yellowback_util import (                                       # noqa: E402
        BOND_MATURITY, POOLS, REF_LAG, STOCK, USER, YellowbackTestFramework, assert_same_statehash, set_quote,
        usd_to_micro,
    )
    from test_framework.yellowback_attest import (                                     # noqa: E402
        attestor_keys, build_register_tx, send_and_lock, sign_attestation,
        verify_attestation, wallet_claim, wallet_mint,
    )

    A, B = PAIRS[0], PAIRS[1]
    CLAIMANT = 5

    def rpc_error(fn, *args):
        try:
            fn(*args)
        except JSONRPCException as e:
            return e.error
        raise AssertionError('%s%r did not fail' % (getattr(fn, '_service_name', fn), args))

    class YewdS3Roles(pair_mixin(YellowbackTestFramework)):

        def __init__(self):
            super().__init__(num_nodes=8)
            self.served = set()

        def price(self, usd):
            for i in POOLS:
                set_quote(self.nodes[i], usd)

        def check(self, what):
            self.sync_all()
            judged = [n for i, n in enumerate(self.nodes) if i != STOCK]
            assert_same_statehash(judged, what)
            hashes = set(n.vault_getinfo()['statehash'] for n in judged)
            assert_equal(len(hashes), 1)
            print('  checkpoint %s: yed_getstatehash and vault_getinfo.statehash equal on %d nodes (pairs %s among them)'
                  % (what, len(judged), PAIRS))

        def mine_n(self, n, i=None):
            for _ in range(n):
                self.mine(POOLS[0] if i is None else i)

        def run_test(self):
            nodes = self.nodes
            user, claimant, wa, wb = nodes[USER], nodes[CLAIMANT], nodes[A], nodes[B]
            print('activate at $50; fund the yewd attestor wallets (nodes %d, %d)' % (A, B))
            self.activate(POOLS, quote_usd=50)
            self.mine_round_robin(POOLS, REF_LAG + 1)
            for n in (wa, wb, claimant):
                for _ in range(4):                 # several coins: a build locks its fee inputs
                    user.sendtoaddress(n.getnewaddress(), 10)
            self.sync_all()
            self.mine(POOLS[0])
            assert_equal(wa.getbalance(), 40)

            print('yed_registerattestor on both pairs: the refusals, then one join each, mined in its own block')
            assert 'bond-below-min' in rpc_error(wa.yed_registerattestor, 2, 0)['message']
            reg = {}
            for i, n in ((A, wa), (B, wb)):
                r = n.yed_registerattestor(10, 60)
                self.sync_all()
                self.mine(POOLS[0])
                rec = [x for x in user.yed_listattestors() if x['attestorPubKey'] == r['attestorPubKey']]
                assert_equal(len(rec), 1)
                reg[i] = (int(rec[0]['seq']), r)
                assert_equal(rec[0]['bondKeyAddress'], r['bondKeyAddress'])
                assert_equal(n.validateaddress(r['bondKeyAddress'])['ismine'], True)
            sa, sb = reg[A][0], reg[B][0]
            self.served.add('yed_registerattestor')
            self.mine_n(BOND_MATURITY + 1)
            for s in (sa, sb):
                assert_equal([x['status'] for x in user.yed_listattestors() if int(x['seq']) == s], ['ELIGIBLE'])
            self.check('registered')

            print('yed_signattestation on yewd: the vector of the node\'s chain, the guard, the restart')
            cited = wa.getblockcount() - REF_LAG
            s1 = wa.yed_signattestation(sa, usd_to_micro(50), cited)
            assert verify_attestation(hex_str_to_bytes(reg[A][1]['attestorPubKey']), hex_str_to_bytes(s1['hex']),
                                      wa.getblockhash(cited))
            assert_equal(wa.yed_signattestation(sa, usd_to_micro(50), cited)['reused'], True)
            e = rpc_error(wa.yed_signattestation, sa, usd_to_micro(51), cited)
            assert_equal((e['code'], e['message']), (-26, 'equivocation-guard: seq %d already signed %d for height %d'
                                                     % (sa, usd_to_micro(50), cited)))
            assert 'attest-key-not-held' in rpc_error(wa.yed_signattestation, sb, usd_to_micro(50))['message']
            assert 'attest-unknown-seq' in rpc_error(wa.yed_signattestation, 99, usd_to_micro(50))['message']
            assert 'attest-range' in rpc_error(wa.yed_signattestation, sa, 1)['message']
            assert 'attest-stale' in rpc_error(wa.yed_signattestation, sa, usd_to_micro(50), wa.getblockcount() + 1)['message']
            self.restart(A)
            wa = nodes[A]
            self.sync_all(blocks_only=True)
            assert 'equivocation-guard' in rpc_error(wa.yed_signattestation, sa, usd_to_micro(52), cited)['message']
            assert_equal(wa.yed_signattestation(sa, usd_to_micro(50), cited)['hex'], s1['hex'])
            self.served.add('yed_signattestation')

            print('signmessage on yewd, verifymessage on ycashd and on the backend')
            msg = 'yewd binding of seq %d' % sa
            sig = wa.signmessage(reg[A][1]['bondKeyAddress'], msg)
            assert user.verifymessage(reg[A][1]['bondKeyAddress'], sig, msg)
            assert wa.verifymessage(reg[A][1]['bondKeyAddress'], sig, msg)          # forwarded to the backend
            assert_equal(user.signmessage(user.getnewaddress(), msg) != sig, True)
            assert_equal(rpc_error(wa.signmessage, user.getnewaddress(), msg)['code'], -4)
            self.served.add('signmessage')

            print('dumpprivkey / importprivkey: a yewd key into ycashd and a ycashd key into yewd')
            wif = wa.dumpprivkey(reg[A][1]['bondKeyAddress'])
            claimant.importprivkey(wif, 'from-yewd', False)
            assert_equal(claimant.validateaddress(reg[A][1]['bondKeyAddress'])['ismine'], True)
            other = user.getnewaddress()
            wb.importprivkey(user.dumpprivkey(other), 'from-ycashd', True)
            assert_equal(wb.validateaddress(other)['ismine'], True)
            assert_equal(rpc_error(wb.importprivkey, 'notakey')['code'], -5)
            self.served |= {'dumpprivkey', 'importprivkey'}

            print('a vault minted by ycashd, the price falls, ycashd node %d claims it (unarmed: two attestors)' % CLAIMANT)
            mint = wallet_mint(self, user, 10000, 48)
            self.sync_all()
            self.mine(POOLS[1])
            vault = mint['txid']
            assert_equal(user.yed_getvault(vault)['status'], 'ACTIVE')
            # the claimant needs the vault's debt in YED: the user sends it
            user.yed_send(claimant.yed_getnewaddress(), 10000)
            self.sync_all()
            self.mine(POOLS[1])
            self.price(Decimal('15'))
            self.mine_round_robin(POOLS, 70)
            self.sync_all()
            assert user.yed_getvault(vault)['claimable'], user.yed_getvault(vault)
            claimed = wallet_claim(self, claimant, vault)
            self.sync_all()
            self.mine(POOLS[2])
            v = user.yed_getvault(vault)
            assert_equal(v['status'], 'CLAIMING')
            rows = dict((x['role'], x) for x in v['intents'])
            intent = '%s:%d' % (rows['claimant']['txid'], rows['claimant']['vout'])
            self.check('claimed')

            print('yewd co-signs and cancels the claim: yed_signcancelcosign, yed_buildcancel, set_signcancel, vault_send')
            e = rpc_error(wa.yed_signcancelcosign, intent)
            assert e['message'].startswith('price-required'), e
            e = rpc_error(wa.yed_signcancelcosign, intent, usd_to_micro(15))
            assert e['message'].startswith('cancel-statement-claimable'), e
            cos = wa.yed_signcancelcosign(intent, usd_to_micro(50))
            assert_equal((cos['seq'], cos['priceMicroUsd'], cos['citedHeight'], cos['reused']),
                         (sa, usd_to_micro(50), claimed['refHeight'], False))
            assert_equal(len(hex_str_to_bytes(cos['cosig'])), 69)
            again = wa.yed_signcancelcosign(intent)
            assert_equal((again['priceMicroUsd'], again['reused']), (usd_to_micro(50), True))
            e = rpc_error(wa.yed_signcancelcosign, intent, usd_to_micro(60))
            assert e['message'].startswith('equivocation-guard'), e
            e = rpc_error(wa.yed_buildcancel, intent)
            assert e['message'].startswith('cancel-cosign-needed'), e
            built = wa.yed_buildcancel(intent, [cos['cosig'], 'zz'])
            assert_equal((built['cancelsRequired'], built['cosigners']), (1, [sa]))
            assert 'cancel-cosign-malformed' in built['warnings'][0]
            assert_equal(built['refund']['cents'], 10000)
            again = wa.yed_buildcancel(intent, [cos['cosig']])
            assert_equal(again['carrierTxid'], built['carrierTxid'])          # one carrier for one co-signature set
            signed = wa.set_signcancel(built['hex'], {'acknowledgerestore': True})
            assert_equal(signed['complete'], True)
            cancel = wa.vault_send(signed['hex'])
            self.sync_all()
            self.mine(POOLS[0])
            for n in self.enforcing_nodes():
                pos = n.yed_getvault(cancel)
                assert_equal((pos['status'], pos['cancelCount']), ('ACTIVE', 1))
            assert_equal(user.yed_gettxinfo(cancel)['type'], 'claim_cancel')
            self.served |= {'yed_signcancelcosign', 'yed_buildcancel'}
            self.check('cancelled by yewd')

            print('a raw attestor whose key the test holds; two prices for one height reported by yewd')
            hot = attestor_keys(1)
            hex_, _lt = build_register_tx(user, hot[0][1], None, 10 * 100000000, 0)
            send_and_lock(user, hex_)
            self.sync_all()
            self.mine(POOLS[0])
            self.mine_n(BOND_MATURITY)
            rawseq = int([x for x in user.yed_listattestors() if x['attestorPubKey'] == hot[0][1]][0]['seq'])
            h = user.getblockcount() - REF_LAG
            bh = user.getblockhash(h)
            a1 = sign_attestation(hot[0][0], rawseq, usd_to_micro(50), h, bh)
            a2 = sign_attestation(hot[0][0], rawseq, usd_to_micro(51), h, bh)
            e = rpc_error(wb.yed_reportequivocation, bytes_to_hex_str(a1), bytes_to_hex_str(a1))
            assert_equal((e['code'], e['message']), (-26, 'not-equivocation: the prices are equal'))
            assert_equal(rpc_error(wb.yed_reportequivocation, 'abcd', bytes_to_hex_str(a1))['code'], -8)
            pend = wb.yed_reportequivocation(bytes_to_hex_str(a1), bytes_to_hex_str(a2), False)
            assert_equal((pend['pending'], pend['txid'], pend['priceA'], pend['priceB']),
                         (True, '', usd_to_micro(50), usd_to_micro(51)))
            self.sync_all()
            self.mine(POOLS[0])
            deadline = time.time() + 60
            while time.time() < deadline:
                st = [x['status'] for x in user.yed_listattestors() if int(x['seq']) == rawseq][0]
                if st == 'EJECTED':
                    break
                self.sync_all()
                self.mine(POOLS[0])
                time.sleep(0.5)
            assert_equal([x['status'] for x in user.yed_listattestors() if int(x['seq']) == rawseq], ['EJECTED'])
            e = rpc_error(wb.yed_reportequivocation, bytes_to_hex_str(a1), bytes_to_hex_str(a2))
            assert 'not-equivocation: the bond of seq %d is frozen' % rawseq in e['message'], e
            self.served.add('yed_reportequivocation')
            self.check('equivocation reported by yewd')

            print('yed_revive refusal; set_leave, then yed_withdrawbond after the exit delay')
            assert 'not-dormant' in rpc_error(wb.yed_revive, sb, usd_to_micro(50))['message']
            self.served.add('yed_revive')
            setid = user.yed_getinfo()['upgrade']['attestorSetId']
            assert 'bond-locked' in rpc_error(wb.yed_withdrawbond, sb)['message']
            assert 'attest-key-not-held' in rpc_error(wb.yed_withdrawbond, sa)['message']
            assert 'attest-unknown-seq' in rpc_error(wb.yed_withdrawbond, 77)['message']
            lt = int([x for x in user.yed_listattestors() if int(x['seq']) == sb][0]['bondLocktime'])
            while user.getblockcount() < lt:
                self.mine(POOLS[0])
            left = wb.set_leave(setid, reg[B][1]['attestorPubKey'])
            self.sync_all()
            self.mine(POOLS[0])
            while user.getblockcount() + 1 < left['bondspendableat']:
                assert 'bond-locked' in rpc_error(wb.yed_withdrawbond, sb)['message']
                self.mine(POOLS[0])
            self.sync_all()
            # S4 (F-S2-8): the bond withdrawn to a Sapling address of the pair, one note
            zb = wb.z_getnewaddress('sapling')
            wd = wb.yed_withdrawbond(sb, zb)
            assert_equal((wd['seq'], wd['bondZat'], wd['to']), (sb, 10 * 100000000, zb))
            raw = wb.getrawtransaction(wd['txid'], 1)        # still in the mempool
            assert_equal((len(raw['vin']), len(raw['vout']), len(raw['vShieldedOutput'])), (1, 0, 2))
            self.sync_all()
            self.mine(POOLS[0])
            assert_equal(wb.z_getbalance(zb), Decimal(wd['bondOut']) / 100000000)
            assert 'bond-spent' in rpc_error(wb.yed_withdrawbond, sb)['message']
            self.served.add('yed_withdrawbond')
            self.check('bond withdrawn by yewd')

            self.x402_calls(wa, user)

            print('S3 served and exercised through yewd: %s' % ', '.join(sorted(self.served)))
            self.check('end')

        def x402_calls(self, w, user):
            """x402's rpcWalletSigner (packages/ycash/src/exact/client/rpcWalletSigner.ts) call set
            against the pair: getrawchangeaddress, listunspent, gettxout, lockunspent,
            createrawtransaction with the expiry, signrawtransaction, the verify-only
            signrawtransaction with empty keys (the facilitator, rpc.ts:184), sendrawtransaction;
            the YED leg's yed_getnewaddress and yed_listunspent."""
            print('x402 rpcWalletSigner call set on yewd')
            change = w.getrawchangeaddress()
            pay_to = user.getnewaddress()
            coins = [c for c in w.listunspent(1) if c['spendable'] and c['scriptPubKey'].startswith('76a914')]
            coin = max(coins, key=lambda c: c['amount'])
            assert w.gettxout(coin['txid'], coin['vout'], True) is not None
            assert w.lockunspent(False, [{'txid': coin['txid'], 'vout': coin['vout']}])
            amount = Decimal('0.0025')
            fee = Decimal('0.0001')
            expiry = w.getblockcount() + 20
            raw = w.createrawtransaction([{'txid': coin['txid'], 'vout': coin['vout']}],
                                         {pay_to: str(amount), change: str(coin['amount'] - amount - fee)}, 0, expiry)
            signed = w.signrawtransaction(raw)
            assert_equal(signed['complete'], True)
            verified = w.signrawtransaction(signed['hex'], [], [])
            assert_equal(verified['complete'], True)
            assert_equal(user.signrawtransaction(signed['hex'], [], [])['complete'], True)
            txid = user.sendrawtransaction(signed['hex'])
            w.lockunspent(True, [{'txid': coin['txid'], 'vout': coin['vout']}])
            self.sync_all()
            self.mine(POOLS[0])
            assert_equal(user.getrawtransaction(txid, 1)['expiryheight'], expiry)
            assert w.yed_getnewaddress().startswith('y')
            w.yed_listunspent()
            self.served.add('x402:rpcWalletSigner')

    YewdS3Roles().main()


if __name__ == '__main__':
    if STAGE == 'roles':
        roles_main()
    else:
        run_script()
