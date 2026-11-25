#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or https://www.opensource.org/licenses/mit-license.php .

"""
yewd signs every transaction it builds under the NEXT block's consensus branch id
(getblockchaininfo.consensus.nextblock), Yugen (0x59474e30) included (decision Y-W11).

Before the fix every yewd transparent, post-quantum and Sapling send failed once Yugen was active
(`old-consensus-branch-id (Expected 59474e30, found 6d5b7a31)`): the librustzcash6 pin had no
BranchId::Yugen and the Sapling build's parameters knew no Yugen height.

Node 0 is the pair under test (ycashd -disablewallet + yewd, the harness's YEWD_BIN mode); node 1
is a plain ycashd wallet that receives and mines. Vault at 16, Falcon at 20, Yugen at 160. Each of
ECC -> ECC, ECC -> Sapling, Sapling -> ECC, Sapling -> Sapling, PQ (SLH-DSA) -> ECC and
PQ (FN-DSA) -> Sapling is sent from yewd under Vault (before activation) and again under Yugen
(after it, including the activation block itself), accepted by the node, mined, and received.

    YCASH6_QA=<ycash6>/qa/rpc-tests ZCASHD=<ycashd> YEWD_BIN=<yewd> YUGEN_LEAFVERIFY=<yugen-leafverify> \\
        <venv>/bin/python yewd/qa/yugen_branch_sends.py --tmpdir=<dir>
"""

import os
import sys
from decimal import Decimal

QA = os.environ.get('YCASH6_QA')
if not QA:
    sys.exit('set YCASH6_QA to ycash6 qa/rpc-tests (branch yugen/node)')
sys.path.insert(0, QA)
if not os.environ.get('YEWD_BIN'):
    sys.exit('set YEWD_BIN to the yewd binary')

from test_framework import util                                                # noqa: E402
from test_framework.test_framework import BitcoinTestFramework                 # noqa: E402
from test_framework.util import (                                              # noqa: E402
    VAULT_BRANCH_ID, assert_equal, connect_nodes_bi, nuparams, start_nodes, sync_blocks,
    sync_mempools, wait_and_assert_operationid_status,
)
from test_framework.yellowback_util import YCASH_UPGRADE_ARGS                  # noqa: E402

YUGEN_BRANCH_ID = 0x59474E30
VAULT_H, FALCON_H, YUGEN_H = 16, 20, 160
VERIFIER = '-yugenverifier=' + os.environ.get('YUGEN_LEAFVERIFY', os.path.join(
    QA, '..', '..', 'contrib', 'yugen-leafverify', 'target', 'release', 'yugen-leafverify'))
ARGS = list(YCASH_UPGRADE_ARGS) + [nuparams(VAULT_BRANCH_ID, VAULT_H), nuparams(YUGEN_BRANCH_ID, YUGEN_H),
                                   '-pqfalconheight=%d' % FALCON_H, VERIFIER]
YEWD = 0

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


class YugenBranchSends(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 2
        self.setup_clean_chain = True

    def setup_network(self, split=False):
        self.nodes = start_nodes(2, self.options.tmpdir, [ARGS] * 2)
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False

    def mine(self, n=1):
        sync_mempools(self.nodes)
        self.nodes[1].generate(n)
        sync_blocks(self.nodes)

    def nextblock(self):
        return int(self.nodes[0].getblockchaininfo()['consensus']['nextblock'], 16)

    def zsend(self, frm, to, amount, policy):
        y = self.nodes[0]
        opid = y.z_sendmany(frm, [{'address': to, 'amount': amount}], 1, None, policy)
        return wait_and_assert_operationid_status(y, opid, timeout=600)

    def round(self, label, want_branch):
        y, n1 = self.nodes
        assert_equal(self.nextblock(), want_branch)
        amt = Decimal('0.05')
        sends = [
            ('ECC -> ECC', lambda: y.sendtoaddress(self.dst['ecc'], amt), 'ecc'),
            ('ECC -> Sapling', lambda: self.zsend(self.src['ecc'], self.dst['sap'], amt, 'AllowFullyTransparent'), 'sap'),
            ('Sapling -> ECC', lambda: self.zsend(self.src['sap'], self.dst['ecc'], amt, 'AllowRevealedRecipients'), 'ecc'),
            ('Sapling -> Sapling', lambda: self.zsend(self.src['sap'], self.dst['sap'], amt, 'FullPrivacy'), 'sap'),
            ('PQ-SLH -> ECC', lambda: self.zsend(self.src['slh'], self.dst['ecc'], amt, 'AllowFullyTransparent'), 'ecc'),
            ('PQ-Falcon -> Sapling', lambda: self.zsend(self.src['fn'], self.dst['sap'], amt, 'AllowFullyTransparent'), 'sap'),
        ]
        for name, send, kind in sends:
            assert_equal(self.nextblock(), want_branch)
            before = self.received(kind)
            txid = send()
            sync_mempools(self.nodes)
            assert txid in n1.getrawmempool(), '%s %s: not relayed' % (label, name)
            self.mine(1)
            assert txid in n1.getblock(n1.getbestblockhash())['tx'], '%s %s: not mined' % (label, name)
            assert_equal(self.received(kind) - before, amt)
            print('  %-6s %-22s ok (branch %08x) %s' % (label, name, want_branch, txid))

    def received(self, kind):
        n1 = self.nodes[1]
        if kind == 'sap':
            return Decimal(n1.z_getbalance(self.dst['sap']))
        return n1.getreceivedbyaddress(self.dst['ecc'])

    def run_test(self):
        y, n1 = self.nodes
        n1.generate(FALCON_H + 1)
        self.mine(100)
        self.src = {'ecc': y.getnewaddress(), 'sap': y.z_getnewaddress('sapling'),
                    'slh': y.getnewaddress('', 'pqslh'), 'fn': y.getnewaddress('', 'pq')}
        self.dst = {'ecc': n1.getnewaddress(), 'sap': n1.z_getnewaddress('sapling')}
        for _ in range(6):
            for k in ('ecc', 'slh', 'fn'):
                n1.sendtoaddress(self.src[k], 1)
        self.mine(1)
        tz = n1.getnewaddress()
        n1.sendtoaddress(tz, 3)
        self.mine(1)
        wait_and_assert_operationid_status(n1, n1.z_sendmany(tz, [{'address': self.src['sap'], 'amount': 2}], 1, None,
                                                             'AllowFullyTransparent'))
        self.mine(1)
        assert n1.getblockcount() + 1 + 6 < YUGEN_H, 'the Vault round must end before Yugen'
        print('Vault round (next block %d)' % (n1.getblockcount() + 1))
        self.round('Vault', VAULT_BRANCH_ID)
        # up to the block before Yugen: the next block is the activation block itself
        self.mine(YUGEN_H - 1 - n1.getblockcount())
        assert_equal(n1.getblockcount() + 1, YUGEN_H)
        print('Yugen round (next block %d = activation)' % YUGEN_H)
        self.round('Yugen', YUGEN_BRANCH_ID)


if __name__ == '__main__':
    YugenBranchSends().main()
