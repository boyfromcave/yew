#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or https://www.opensource.org/licenses/mit-license.php .

"""
yewd S4 exit gate, the contract legs (workspace plan docs/plans/kogany/kogany-yellowback-plan.md
section 3b S4): ycash6's two contract suites, unchanged, with **every** node a pair (a ycashd
-disablewallet backend + yewd + its signer: the harness's YEWD_BIN mode, test_framework/kogany.py).

    --suite=vault        qa/rpc-tests/vault_rpc_contract.py (two nodes)
    --suite=yellowback   qa/rpc-tests/yellowback_rpc_contract.py (six nodes)

The harness's pair start is used as it is, with the two steps it does not take yet (both for the
harness chunk, README "Harness mode"):
  * H8: each pair's wallet is created before its backend starts (yewd -initwallet) and the backend
    mines to that wallet's coinbase address (-mineraddress, -minetolocalwallet=0); a restart reuses it;
  * F-S2-9: a backend that listens before it writes its cookie answers 401, treated as warm-up.
Nothing else is patched: the suites' run_test, setup and checkers are their own.

    YCASH6_QA=<ycash6>/qa/rpc-tests ZCASHD=<ycashd> YEWD_BIN=<yewd> \\
        <venv>/bin/python yewd/qa/s4_contract.py --suite=vault --tmpdir=<dir> --portseed=<n>
"""

import importlib
import json
import os
import subprocess
import sys

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


SUITES = {
    'vault': ('vault_rpc_contract', 'VaultRpcContractTest'),
    'yellowback': ('yellowback_rpc_contract', 'YellowbackRpcContractTest'),
}
SUITE = _arg('suite', 'vault')
if SUITE not in SUITES:
    sys.exit('unknown --suite=%s (one of %s)' % (SUITE, ', '.join(SUITES)))

from test_framework import kogany                                             # noqa: E402
from test_framework.authproxy import JSONRPCException                         # noqa: E402

# H8: the wallet first, then the backend mining to it.
_pair_argv = kogany.yewd_pair_argv


def _pair_argv_h8(yewd_bin, ycashd_bin, datadir, i, args):
    out = subprocess.check_output([yewd_bin, '-datadir=' + datadir, '-conf=ycash.conf', '-regtest', '-initwallet'])
    addr = json.loads(out)['mineaddress']
    args = [a for a in args if not a.startswith(('-mineraddress=', '-minetolocalwallet'))]
    # ycashd takes a P2PKH -mineraddress as the default -yellowbackpayoutaddress (MINER-2, init.cpp), which a
    # wallet node mining to its keypool never has: a Yellowback-live node that names no payout address gets no
    # coinbase address (the suites mine on such a node only before the attestor set exists; F-S4-1)
    live = any(a.startswith('-yellowbackattestorset=') for a in args)
    payout = any(a.startswith('-yellowbackpayoutaddress=') for a in args)
    if live and not payout:
        return _pair_argv(yewd_bin, ycashd_bin, datadir, i, list(args))
    return _pair_argv(yewd_bin, ycashd_bin, datadir, i, list(args) + ['-mineraddress=%s' % addr, '-minetolocalwallet=0'])


kogany.yewd_pair_argv = _pair_argv_h8

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

if __name__ == '__main__':
    module, cls = SUITES[SUITE]
    m = importlib.import_module(module)
    print('S4 contract leg: %s.%s, every node backend + yewd' % (module, cls))
    getattr(m, cls)().main()
