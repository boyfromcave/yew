#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or https://www.opensource.org/licenses/mit-license.php .

"""
A post-quantum miner shields its coinbase, on real nodes in every column (beta3): ycash6's
qa/rpc-tests/wallet_pq_coinbase_spend.py, every step and assertion unchanged, on the upgrade
schedule koganyd's regtest can run.

Why a wrapper and not the script itself. ycash6's script puts Heartwood and Canopy at 3. koganyd's
regtest refuses that schedule at start ("checkpoints must be provided for block heights below the
mandatory checkpoint height": Zakura checkpoints every block below Canopy, and a regtest list holds
only genesis), so in the pair columns the script cannot start. Here every upgrade through Canopy is
at 1, as kogany's own cross-line scripts (crates/kogany-rpc/qa) run it; Vault and FN-DSA-512 stay at
4, so the script's heights (rewards at 6 to 10, maturity at 101 confirmations) are the same.

Where the coinbase rule is enforced. ycashd enforces coinbase-must-be-shielded on regtest only with
-regtestshieldcoinbase; koganyd's regtest never does (zakura-chain `Parameters::new_regtest`,
`with_unshielded_coinbase_spends(true)`, no switch), and the harness drops the flag for a kogany
backend (it matches the `-regtest` prefix of the ignored arguments). So in the pair columns koganyd
proves only that the spend is valid without the rule; the rule is judged by ycashd:

    ycash6       plain ycashd wallets; nodes 0 and 1 enforce the rule (the reference answers)
    pair-ycashd  yewd in front of ycashd -disablewallet backends (YEWD_BIN without YEWD_KOGANY);
                 the backends of nodes 0 and 1 enforce the rule, so every spend yewd builds there is
                 accepted by an enforcing ycashd mempool and block validation
    pair         yewd in front of koganyd: the same requests and answers, the transaction accepted
                 and mined by koganyd
    pair-mixed   pair, with a ycashd -disablewallet peer on node 0's arguments (so with
                 -regtestshieldcoinbase) judging every transaction and block of the shielded network;
                 checked here as well: each spend is in the peer's mempool before it is mined, and in
                 the peer's tip block after

Each column writes what the wallet answered (every refusal's code and message, every sent
transaction's shape: inputs, transparent outputs, Sapling outputs, value in, fee) to
$YEWD_PARITY_RECORD (default <tmpdir>/pq_coinbase_record.jsonl); s5_parity.py compares the records across
columns field by field (the txids differ and are not compared).

Run by s5_parity.py (cwd = ycash6 qa/rpc-tests), or by hand:

    cd <ycash6>/qa/rpc-tests && ZCASHD=<ycashd> [YEWD_BIN=<yewd> [YEWD_KOGANY=<koganyd> [YEWD_YCASH6_PEER=1]]] \\
        <venv>/bin/python <yew>/yewd/qa/parity/yewd_pq_coinbase_spend.py --srcdir=<dir of ycashd> --tmpdir=<dir>
"""

import json
import os
import sys
import time

QA = os.environ.get('YCASH6_QA') or os.getcwd()
sys.path.insert(0, QA)

import wallet_pq_coinbase_spend as base                                       # noqa: E402
from test_framework.util import connect_nodes_bi, nuparams, start_nodes      # noqa: E402
from test_framework.yellowback_util import (                                  # noqa: E402
    VAULT_BRANCH_ID, YCASH_BLOSSOM_BRANCH_ID, YCASH_BRANCH_ID, YCASH_CANOPY_BRANCH_ID,
    YCASH_HEARTWOOD_BRANCH_ID)

try:
    from test_framework import kogany
except ImportError:                     # a ycash6 without the pair harness: the ycash6 column only
    kogany = None


def peer():
    """The ycash6 peer of the pair-mixed column, or None."""
    col = kogany.YEWD_COLUMN[0] if kogany is not None else None
    return col if col is not None and col.with_peer and col.alive() else None


class YewdPQCoinbaseSpend(base.WalletPQCoinbaseSpendTest):
    def setup_network(self, split=False):
        common = [
            nuparams(YCASH_BRANCH_ID, 1),
            nuparams(YCASH_BLOSSOM_BRANCH_ID, 1),
            nuparams(YCASH_HEARTWOOD_BRANCH_ID, 1),
            nuparams(YCASH_CANOPY_BRANCH_ID, 1),
            nuparams(VAULT_BRANCH_ID, 4),
            '-pqfalconheight=4',
        ]
        shield = common + ['-regtestshieldcoinbase']
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir, extra_args=[shield, shield, common, common])
        connect_nodes_bi(self.nodes, 0, 1)
        connect_nodes_bi(self.nodes, 2, 3)
        self.is_network_split = False
        self.record_path = os.environ.get('YEWD_PARITY_RECORD') or os.path.join(self.options.tmpdir,
                                                                          'pq_coinbase_record.jsonl')
        self.records = []
        self.judged = 0
        p = peer()
        if p is not None:
            assert '-regtestshieldcoinbase' in p.ycashd_args, p.ycashd_args
            print('yewd_pq_coinbase_spend: the ycash6 peer enforces coinbase-must-be-shielded')

    def record(self, **kw):
        kw['network'] = 'shielded' if self.pool is self.nodes[0] else 'unshielded'
        kw['seq'] = len(self.records)
        self.records.append(kw)
        with open(self.record_path, 'a', encoding='utf8') as f:
            f.write(json.dumps(kw, sort_keys=True) + '\n')

    def refused(self, src, outs, code, fee=None):
        message = super().refused(src, outs, code, fee)
        self.record(kind='refused', outs=len(outs), fee=str(fee) if fee is not None else None, code=code,
                    message=message)
        return message

    def send(self, src, outs, fee=None):
        txid, tx = super().send(src, outs, fee)
        value_in, paid = self.value_of(tx)
        self.record(kind='sent', outs=len(outs), fee=str(fee) if fee is not None else None, vin=len(tx['vin']),
                    vout=len(tx['vout']), shielded_outputs=len(tx['vShieldedOutput']), value_in=value_in,
                    fee_paid=paid)
        p = peer()
        if p is not None and self.pool is self.nodes[0]:
            # the enforcing ycashd holds the spend in its mempool (the harness's mempool point fed it)
            deadline = time.time() + 120
            while txid not in p.rpc.getrawmempool():
                assert time.time() < deadline, 'the ycash6 peer does not hold %s' % txid
                time.sleep(0.2)
            self.pending = getattr(self, 'pending', []) + [txid]
        return txid, tx

    def mine(self, n=1):
        super().mine(n)
        p = peer()
        pending = getattr(self, 'pending', [])
        if p is not None and self.pool is self.nodes[0] and pending:
            tip = self.pool.getbestblockhash()
            deadline = time.time() + 120
            while p.rpc.getbestblockhash() != tip:
                assert time.time() < deadline, 'the ycash6 peer did not accept block %s' % tip
                time.sleep(0.2)
            mined = set()
            for h in range(self.pool.getblockcount() - n + 1, self.pool.getblockcount() + 1):
                mined |= set(p.rpc.getblock(p.rpc.getblockhash(h))['tx'])
            for t in pending:
                assert t in mined, 'the ycash6 peer\'s blocks lack %s' % t
            self.judged += len(pending)
            print('  the ycash6 peer (coinbase must be shielded) accepted the block(s) holding %s' % ', '.join(pending))
            self.pending = []

    def run_test(self):
        super().run_test()
        if peer() is not None:
            assert self.judged >= 5, self.judged       # the shielded network's five coinbase spends
            print('yewd_pq_coinbase_spend: %d spends judged by the enforcing ycash6 peer' % self.judged)


if __name__ == '__main__':
    YewdPQCoinbaseSpend().main()
