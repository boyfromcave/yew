#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or https://www.opensource.org/licenses/mit-license.php .

"""
yewd S6, the gap parity checks (beta3 item 14; the gaps found by the parity suite,
wt/handoff/KG-YEWD-VAULT-PARITY.md): each check states ycashd's own behaviour, passes on a plain
ycashd first, then on yewd.

Two nodes on ycash6's functional framework. Node 1 is always a plain ycashd (the miner and the
peer). Node 0 is the wallet under test: a plain ycashd when YEWD_BIN is unset (the reference
column), the pair (ycashd -disablewallet + yewd, the harness's YEWD_BIN mode) when it is set.

    YCASH6_QA=<ycash6>/qa/rpc-tests ZCASHD=<ycashd> [YEWD_BIN=<yewd>] \\
        <venv>/bin/python yewd/qa/s6_gaps.py --tmpdir=<dir> --portseed=<n> [--checks a,b]

Checks (--checks, default all), in the order of the gaps' user impact:

  lock_lifetime   a vault_lock funded by default, from a transparent or a post-quantum address
                  holds no coin lock once accepted (ycash6 src/rpc/vault.cpp FundScope, Broadcast;
                  audit L-1); a coin locked with lockunspent stays locked.
"""

import os
import sys
import time
from decimal import Decimal

QA = os.environ.get('YCASH6_QA')
if not QA:
    sys.exit('set YCASH6_QA to ycash6 qa/rpc-tests (the harness with YEWD_BIN)')
sys.path.insert(0, QA)

from test_framework import util                                               # noqa: E402
from test_framework.authproxy import JSONRPCException                         # noqa: E402
from test_framework.test_framework import BitcoinTestFramework                # noqa: E402
from test_framework.util import (                                             # noqa: E402
    VAULT_BRANCH_ID,
    assert_equal,
    connect_nodes_bi,
    nuparams,
    start_node,
    sync_blocks,
    sync_mempools,
)

UNDER_TEST = 0
ACTIVATION = 210
FALCON = 215
DELAY = 5
CHECKS = ('lock_lifetime',)
YEWD = bool(os.environ.get('YEWD_BIN'))

_start_node = util.start_node


def _start_node_one_pair(i, *a, **kw):
    """Only node 0 becomes a pair under YEWD_BIN; node 1 stays a plain ycashd."""
    saved = os.environ.get('YEWD_BIN')
    if i == UNDER_TEST or saved is None:
        return _start_node(i, *a, **kw)
    os.environ.pop('YEWD_BIN')
    try:
        return _start_node(i, *a, **kw)
    finally:
        os.environ['YEWD_BIN'] = saved


util.start_node = _start_node_one_pair


def outpoints(entries):
    return {(e['txid'], e['vout']) for e in entries}


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


class GapParity(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 2
        self.setup_clean_chain = True

    def add_options(self, parser):
        parser.add_option('--checks', dest='checks', default=','.join(CHECKS),
                          help='comma-separated checks to run (%s)' % ', '.join(CHECKS))

    def node_args(self, i):
        return [nuparams(VAULT_BRANCH_ID, ACTIVATION), '-pqfalconheight=%d' % FALCON, '-debug=vault']

    def setup_network(self, split=False):
        self.nodes = [util.start_node(i, self.options.tmpdir, self.node_args(i)) for i in range(self.num_nodes)]
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False
        self.sync_all()

    def mine(self, n=1):
        self.sync_all()
        hashes = self.nodes[1].generate(n)
        self.sync_all()
        return hashes

    def sync_all(self, do_mempool_sync=True):
        sync_blocks(self.nodes)
        if do_mempool_sync:
            sync_mempools(self.nodes)

    def params(self, amount, source=None):
        p = {'tag': 'TEST', 'setid': self.setid, 'delay': DELAY,
             'ownerheight': self.nodes[0].getblockcount() + 1000, 'amount': amount}
        if source is not None:
            p['from'] = source
        return p

    def inputs_of(self, node, txid):
        return {(i['txid'], i['vout']) for i in node.getrawtransaction(txid, 1)['vin']}

    def run_test(self):
        n0, n1 = self.nodes
        print('column: %s' % ('yewd' if YEWD else 'ycashd'))
        print('activation; node 0 funded from node 1; a released set')
        self.mine(ACTIVATION - n1.getblockcount())
        for _ in range(4):
            n1.sendtoaddress(n0.getnewaddress(), 20)
        self.mine(1)
        self.setid = n1.set_create({'seats': 3, 'unlockthreshold': 2, 'cancelthreshold': 1, 'slashthreshold': 2,
                                    'maturity': 2, 'livenesswindow': 50, 'bondmin': 1, 'ratewindow': 20})['setid']
        self.mine(1)
        assert_equal(n0.set_getinfo(self.setid)['released'], True)
        for name in self.options.checks.split(','):
            if name not in CHECKS:
                raise AssertionError('unknown check %r' % name)
            getattr(self, name)()
        print('all checks passed (%s)' % ('yewd' if YEWD else 'ycashd'))

    # ------------------------------------------------------------------ the checks

    def lock_lifetime(self):
        """Audit L-1 (ycash6 vault.cpp FundScope; qa wallet_beta2_followups2.py lock_lifetime)."""
        print('lock_lifetime: an accepted vault_lock holds no coin lock')
        n0 = self.nodes[0]
        ecc = n0.getnewaddress()
        pq = n0.getnewaddress('', 'pqslh')
        kept = n0.getnewaddress()
        n0.sendtoaddress(ecc, 10)
        n0.sendtoaddress(pq, 10)
        n0.sendtoaddress(kept, 3)
        self.mine(1)
        kept_op = [(u['txid'], u['vout']) for u in n0.listunspent(1, 9999999, [kept])]
        assert_equal(len(kept_op), 1)
        n0.lockunspent(False, [{'txid': kept_op[0][0], 'vout': kept_op[0][1]}])
        locked_before = outpoints(n0.listlockunspent())
        assert kept_op[0] in locked_before
        txids = {}
        for name, source in (('ecc', ecc), ('pq', pq), ('default', None)):
            txids[name] = n0.vault_lock(self.params(Decimal('1'), source))['txid']
            assert txids[name] in n0.getrawmempool(), name
            ins = self.inputs_of(n0, txids[name])
            assert ins, name
            assert_equal(outpoints(n0.listlockunspent()), locked_before)
            assert not (ins & outpoints(n0.listunspent(0))), name
            assert_equal(n0.gettransaction(txids[name])['confirmations'], 0)
        self.mine(1)
        for name in txids:
            assert_equal(n0.gettransaction(txids[name])['confirmations'], 1)
        assert_equal(outpoints(n0.listlockunspent()), locked_before)
        n0.lockunspent(True, [{'txid': kept_op[0][0], 'vout': kept_op[0][1]}])
        assert_equal(n0.listlockunspent(), [])


if __name__ == '__main__':
    GapParity().main()
