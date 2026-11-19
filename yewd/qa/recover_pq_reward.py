#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or https://www.opensource.org/licenses/mit-license.php .

"""
Recovering a mining reward paid to a YEW address, end to end on regtest (beta4 item 7).

A pool pays block rewards (getcoinbasetemplatefor) to the post-quantum addresses the YEW app and web
wallet show for a recovery phrase: four FN-DSA-512 (Falcon) rewards (one left immature) and one SLH-DSA
reward.
Once mature, the phrase is restored in a fresh yewd (-mnemonicfile) and the rewards are moved to
Sapling at the exact amount, then sent on to an ECC and a post-quantum address. Coinbase must be
shielded on every node that can enforce it (-regtestshieldcoinbase: the ycashd backends; a koganyd
backend never enforces it on regtest, so the koganyd column is run with YEWD_YCASH6_PEER=1, a ycash6
peer with the flag that must accept every transaction and block).

The YEW side: the addresses are the app's own `receive_address(PqFalcon | PqSlh)` of the phrase,
printed by `yewd/signer/tests/yew_phrase_address.rs` (which also checks that they are key 0 of each
scheme in yewd's derivation). Pass them in YEWD_YEW_ADDRESSES (that test's JSON line), or the
script runs the test itself (cargo, from this checkout).

The two ways to move the reward, both checked when the yewd under test has them:
  - z_sendmany from the address with a round amount: the refusal names the exact amount; sent;
  - z_shieldcoinbase from the address (a yewd extension since beta4: ycashd refuses a post-quantum
    source): the wallet computes the amount, honours `limit`. A yewd without the extension (beta3)
    answers ycashd's refusal, recorded, and the rest is moved with z_sendmany.

Every call and answer of the recovering wallet is written to $YEWD_RECOVER_EVIDENCE (default
<tmpdir>/recover_evidence.txt).

Run from ycash6's qa/rpc-tests (its test framework), one column per run:

    cd <ycash6>/qa/rpc-tests && ZCASHD=<ycashd> YEWD_BIN=<yewd> [YEWD_KOGANY=<koganyd> YEWD_YCASH6_PEER=1] \\
        <venv>/bin/python <yew>/yewd/qa/recover_pq_reward.py --srcdir=<dir of ycashd> --tmpdir=<dir> --portseed=<n>
"""

import json
import os
import re
import subprocess
import sys
import time
from decimal import Decimal

QA = os.environ.get('YCASH6_QA') or os.getcwd()
sys.path.insert(0, QA)

import wallet_pq_coinbase_spend as base                                       # noqa: E402
from test_framework.authproxy import JSONRPCException                         # noqa: E402
from test_framework.test_framework import BitcoinTestFramework                # noqa: E402
from test_framework.util import (                                             # noqa: E402
    assert_equal, bytes_to_hex_str, connect_nodes_bi, nuparams, start_node, sync_blocks, sync_mempools)
from test_framework.yellowback_util import (                                  # noqa: E402
    VAULT_BRANCH_ID, YCASH_BLOSSOM_BRANCH_ID, YCASH_BRANCH_ID, YCASH_CANOPY_BRANCH_ID,
    YCASH_HEARTWOOD_BRANCH_ID)

try:
    from test_framework import kogany
except ImportError:
    kogany = None

COIN = 100000000
HERE = os.path.dirname(os.path.abspath(__file__))
PHRASE = os.environ.get('YEWD_YEW_PHRASE') or (
    'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about')
# the fees of one input, from the 2026-11-18 fast-testnet report (re-verified here)
FEE_ONE_FALCON = 6500
FEE_ONE_SLH = 28000
EXACT = re.compile(r'send exactly ([0-9.]+) to shielded recipients \(the ([0-9.]+) selected less the fee ([0-9.]+)\)')


def zat(x):
    return int(Decimal(str(x)) * COIN)


def yec(z):
    return Decimal(z) / COIN


def app_addresses():
    """The YEW app's Falcon and SLH-DSA receive addresses of PHRASE (regtest)."""
    if os.environ.get('YEWD_YEW_ADDRESSES'):
        return json.loads(os.environ['YEWD_YEW_ADDRESSES'])
    out = subprocess.run(
        ['cargo', 'test', '--locked', '--manifest-path', os.path.join(HERE, '..', 'Cargo.toml'), '-p', 'yewd-signer',
         '--test', 'yew_phrase_address', '--', '--nocapture'],
        env=dict(os.environ, YEWD_YEW_PHRASE=PHRASE, YEWD_YEW_NETWORK='regtest'),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True).stdout.decode()
    line = [l for l in out.splitlines() if l.startswith('yew-app-addresses ')][0]
    return json.loads(line.split(' ', 1)[1])


def peer():
    col = kogany.YEWD_COLUMN[0] if kogany is not None and hasattr(kogany, 'YEWD_COLUMN') else None
    return col if col is not None and col.with_peer and col.alive() else None


class RecoverPQReward(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.cache_behavior = 'clean'

    def node_args(self):
        return [
            nuparams(YCASH_BRANCH_ID, 1),
            nuparams(YCASH_BLOSSOM_BRANCH_ID, 1),
            nuparams(YCASH_HEARTWOOD_BRANCH_ID, 1),
            nuparams(YCASH_CANOPY_BRANCH_ID, 1),
            nuparams(VAULT_BRANCH_ID, 4),
            '-pqfalconheight=4',
            '-regtestshieldcoinbase',
        ]

    def setup_network(self, split=False):
        assert os.environ.get('YEWD_BIN'), 'a yewd column: set YEWD_BIN'
        # node 0: the pool. Node 1 (the restoring yewd) starts once the rewards are mature.
        self.nodes = [start_node(0, self.options.tmpdir, self.node_args()), None]
        self.is_network_split = False
        self.evidence = os.environ.get('YEWD_RECOVER_EVIDENCE') or os.path.join(self.options.tmpdir,
                                                                                'recover_evidence.txt')
        self.backend = 'koganyd' if os.environ.get('YEWD_KOGANY') else 'ycashd -disablewallet'

    # ---- the record --------------------------------------------------------------------------------------------

    def note(self, text):
        print(text)
        with open(self.evidence, 'a', encoding='utf8') as f:
            f.write(text + '\n')

    def call(self, method, *params, node=1, expect_error=None):
        """One RPC on node `node`, recorded with its answer. `expect_error`: the code a refusal must carry."""
        n = self.nodes[node]
        shown = json.dumps(params, default=str)
        try:
            r = getattr(n, method)(*params)
        except JSONRPCException as e:
            self.note('$ %s %s %s\n-> error %s %s' % ('yewd' if node == 1 else 'pool', method, shown,
                                                       e.error['code'], e.error['message']))
            if expect_error is None or e.error['code'] != expect_error:
                raise
            return e.error
        self.note('$ %s %s %s\n-> %s' % ('yewd' if node == 1 else 'pool', method, shown,
                                          json.dumps(r, default=str, sort_keys=True)))
        assert expect_error is None, 'expected error %s' % expect_error
        return r

    # ---- chain helpers -----------------------------------------------------------------------------------------

    def live(self):
        return [n for n in self.nodes if n is not None]

    def sync(self):
        sync_blocks(self.live())
        sync_mempools(self.live())

    def mine(self, n=1):
        self.sync()
        self.nodes[0].generate(n)
        self.sync()
        time.sleep(1)

    def pool_block(self, address):
        """One block paying its whole reward to `address`, as a pool builds it. Returns (txid, zat)."""
        self.sync()
        gbt = self.nodes[0].getblocktemplate()
        ref = {'previousblockhash': gbt['previousblockhash'], 'txids': [t['hash'] for t in gbt['transactions']]}
        res = self.nodes[0].getcoinbasetemplatefor(address, ref)
        block = base.block_from(gbt, res['data'])
        assert_equal(self.nodes[0].submitblock(bytes_to_hex_str(block.serialize())), None)
        self.sync()
        self.note('# pool: block %d pays %s YEC to %s (coinbase %s)' % (gbt['height'], yec(res['amount']), address,
                                                                        res['hash']))
        return res['hash'], res['amount']        # getcoinbasetemplatefor answers zat

    def operation(self, opid):
        """The operation's final state (recorded)."""
        for _ in range(600):
            r = self.nodes[1].z_getoperationresult([opid])
            if r:
                self.note('-> operation %s' % json.dumps(r[0], default=str, sort_keys=True))
                return r[0]
            time.sleep(0.2)
        raise AssertionError('operation %s timed out' % opid)

    def shape(self, txid):
        """(inputs, transparent outputs, Sapling outputs, value in zat, fee in zat) of a sent transaction, from the
        pool node's mempool or chain (so the network accepted it)."""
        self.sync()
        tx = self.nodes[0].getrawtransaction(txid, 1)
        value_in = 0
        for vin in tx['vin']:
            parent = self.nodes[0].getrawtransaction(vin['txid'], 1)
            value_in += parent['vout'][vin['vout']]['valueZat']
        fee = value_in - sum(v['valueZat'] for v in tx['vout']) + tx['valueBalanceZat']
        s = (len(tx['vin']), len(tx['vout']), len(tx['vShieldedOutput']), value_in, fee)
        self.note('# tx %s: %d inputs, %d transparent outputs, %d Sapling outputs, in %s, fee %s'
                  % (txid, s[0], s[1], s[2], yec(s[3]), yec(s[4])))
        return s

    def accepted(self, txid):
        """The transaction is in the pool node's mempool; with a ycash6 peer, in the peer's too."""
        self.sync()
        assert txid in self.nodes[0].getrawmempool(), txid
        p = peer()
        if p is not None:
            deadline = time.time() + 120
            while txid not in p.rpc.getrawmempool():
                assert time.time() < deadline, 'the enforcing ycash6 peer does not hold %s' % txid
                time.sleep(0.2)
            self.note('# the ycash6 peer (-regtestshieldcoinbase) holds %s in its mempool' % txid)

    def sendmany_exact(self, src, zaddr, round_amount):
        """z_sendmany with a round amount: the refusal names the exact amount; that is sent. Returns
        (txid, exact zat, fee zat)."""
        opid = self.call('z_sendmany', src, [{'address': zaddr, 'amount': round_amount}], 1)
        r = self.operation(opid)
        assert_equal(r['status'], 'failed')
        assert_equal(r['error']['code'], -4)
        m = EXACT.search(r['error']['message'])
        assert m, r['error']['message']
        exact, selected, fee = zat(m.group(1)), zat(m.group(2)), zat(m.group(3))
        assert_equal(exact, selected - fee)
        opid = self.call('z_sendmany', src, [{'address': zaddr, 'amount': yec(exact)}], 1)
        r = self.operation(opid)
        assert_equal(r['status'], 'success')
        txid = r['result']['txid']
        self.accepted(txid)
        n_in, n_out, n_z, value_in, paid = self.shape(txid)
        assert_equal((n_out, value_in, paid), (0, selected, fee))
        return txid, exact, fee

    # ---- the run -----------------------------------------------------------------------------------------------

    def run_test(self):
        addrs = app_addresses()
        falcon, slh = addrs['falcon'], addrs['slh']
        self.note('# backend: %s; yewd: %s' % (self.backend, os.environ['YEWD_BIN']))
        self.note('# the YEW app shows for the phrase: Falcon %s, SLH-DSA %s (yew_phrase_address.rs: key 0 of '
                  'each scheme in yewd)' % (falcon, slh))

        # 1. a pool pays three Falcon rewards and one SLH-DSA reward to the YEW addresses; they mature
        self.mine(5)
        rewards = [self.pool_block(falcon), self.pool_block(falcon), self.pool_block(slh), self.pool_block(falcon)]
        self.mine(101)
        late = self.pool_block(falcon)      # one more, still immature at the restore
        self.mine(2)

        # 2. the phrase restored in a fresh yewd
        phrase_file = os.path.join(self.options.tmpdir, 'yew-phrase.txt')
        with open(phrase_file, 'w', encoding='utf8') as f:
            f.write(PHRASE + '\n')
        self.nodes[1] = start_node(1, self.options.tmpdir, self.node_args() + ['-mnemonicfile=' + phrase_file])
        connect_nodes_bi(self.nodes, 0, 1)
        self.sync()
        for _ in range(600):
            if not self.nodes[1].getwalletinfo()['restore_in_progress']:
                break
            time.sleep(0.5)
        info = self.call('getwalletinfo')
        assert_equal(info['restore_in_progress'], False)
        assert_equal(self.call('validateaddress', falcon)['ismine'], True)
        assert_equal(self.call('validateaddress', slh)['ismine'], True)
        mature_falcon = [r for r in rewards if r is not rewards[2]]
        got = sorted((u['txid'], zat(u['amount']), u['generated']) for u in self.call('listunspent', 1, 9999999,
                                                                                      [falcon]))
        assert_equal(got, sorted((t, z, True) for t, z in mature_falcon))
        assert_equal(zat(info['immature_balance']), late[1])

        zaddr = self.call('z_getnewaddress', 'sapling')
        ecc = self.call('getnewaddress')

        # 3. the reward cannot go to a transparent address (the wallet says so; nothing is sent)
        before = self.nodes[0].getrawmempool()
        opid = self.call('z_sendmany', falcon, [{'address': ecc, 'amount': 1}], 1)
        r = self.operation(opid)
        assert_equal((r['status'], r['error']['code']), ('failed', -6))
        assert 'coinbase' in r['error']['message'], r['error']['message']
        if self.extension():        # beta4: the refusal names the exact amount (the C++ lines' text)
            assert 'send exactly' in r['error']['message'], r['error']['message']
        assert_equal(self.nodes[0].getrawmempool(), before)

        # 4. z_sendmany, exact amount: one Falcon reward
        txid, exact, fee = self.sendmany_exact(falcon, zaddr, 1)
        assert_equal(fee, FEE_ONE_FALCON)
        self.mine()

        # 5. z_shieldcoinbase from the post-quantum address (the yewd extension), else z_sendmany
        r = self.call('z_shieldcoinbase', falcon, zaddr, None, 1) if self.extension() else None
        if r is not None:
            assert_equal((r['shieldingUTXOs'], r['remainingUTXOs']), (1, 1))
            op = self.operation(r['opid'])
            assert_equal(op['status'], 'success')
            assert_equal(op['method'], 'z_shieldcoinbase')
            self.accepted(op['result']['txid'])
            n_in, n_out, n_z, value_in, paid = self.shape(op['result']['txid'])
            assert_equal((n_in, n_out, paid), (1, 0, FEE_ONE_FALCON))
            assert_equal(value_in, zat(r['shieldingValue']))
            self.mine()
            r = self.call('z_shieldcoinbase', falcon, zaddr)
            assert_equal((r['shieldingUTXOs'], r['remainingUTXOs']), (1, 0))
            op = self.operation(r['opid'])
            assert_equal(op['status'], 'success')
            self.accepted(op['result']['txid'])
            assert_equal(self.shape(op['result']['txid'])[4], FEE_ONE_FALCON)
            r = self.call('z_shieldcoinbase', slh, zaddr)
            op = self.operation(r['opid'])
            assert_equal(op['status'], 'success')
            self.accepted(op['result']['txid'])
            assert_equal(self.shape(op['result']['txid'])[4], FEE_ONE_SLH)
            self.mine()
            # what is left is immature: named, with the blocks it still needs
            e = self.call('z_shieldcoinbase', falcon, zaddr, expect_error=-6)
            assert e['message'].startswith('Could not find any coinbase funds to shield. The address holds 6.25 YEC '
                                           'of immature mining rewards'), e['message']
            e = self.call('z_shieldcoinbase', falcon, ecc, expect_error=-25)
            assert_equal(e['message'], 'Cannot shield coinbase output to a p2pkh address.')
        else:
            # beta3: the rest with z_sendmany (two Falcon rewards in one call, then the SLH-DSA one)
            txid, exact, fee = self.sendmany_exact(falcon, zaddr, 7)
            txid, exact, fee = self.sendmany_exact(slh, zaddr, 1)
            assert_equal(fee, FEE_ONE_SLH)
            self.mine()

        # 6. send on from Sapling to an ECC and a post-quantum address of the wallet
        self.mine(10)
        pq = self.call('getnewaddress', 'pq')
        for to in (ecc, pq):
            opid = self.call('z_sendmany', zaddr, [{'address': to, 'amount': 5}])
            op = self.operation(opid)
            assert_equal(op['status'], 'success')
            self.accepted(op['result']['txid'])
        self.mine()
        assert_equal(zat(self.call('getreceivedbyaddress', ecc)), 5 * COIN)
        got = self.call('listunspent', 1, 9999999, [pq])
        assert_equal([zat(u['amount']) for u in got if not u['generated']], [5 * COIN])
        self.call('z_gettotalbalance')
        self.note('# done: the rewards at the YEW addresses were moved to Sapling and sent on (%s backend)'
                  % self.backend)

    def extension(self):
        """Whether this yewd serves z_shieldcoinbase from a post-quantum address (beta4); a beta3 yewd answers
        ycashd's refusal (recorded)."""
        e = None
        try:
            # an address that is not the wallet's: the extension refuses it as not its own, beta3 as a PQ source
            self.nodes[1].z_shieldcoinbase(self.foreign_pq(), self.nodes[1].z_getnewaddress('sapling'))
        except JSONRPCException as x:
            e = x.error
        self.note('# z_shieldcoinbase from a foreign post-quantum address -> %s' % json.dumps(e))
        return e is not None and 'cannot spend from a post-quantum address' not in e['message']

    def foreign_pq(self):
        return self.nodes[0].getnewaddress('pq')     # node 0 is a yewd pair too


if __name__ == '__main__':
    RecoverPQReward().main()
