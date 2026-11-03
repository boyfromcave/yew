#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or https://www.opensource.org/licenses/mit-license.php .

"""
Generate yewd/facade/src/ycashd_rpc.json: ycashd's help text and accepted argument counts for every
method of the façade's wallet table (workspace plan §3b S4: "wrong arity gives ycashd's error with the
usage text"), read from a plain ycash6 wallet node on regtest with Yellowback live.

ycash6 checks arity in the RPC table before the handler runs (`src/rpc/server.cpp` `CRPCTable::execute`,
from the parameter lists of `src/rpc/client.cpp`): a call with too few or too many arguments answers
-32602 "Not enough|Too many parameters for method `<m>`. Needed exactly <n> | at least <a> and at most <b>,
but received <k>" followed by a blank line and the method's help text. The bounds are read from that answer to
a call with MAX_PROBE null arguments (or none), which never reaches the handler.
The `help` listing (no topic) is kept too, for the `help` diff of the exit gate.

    YCASH6_QA=<ycash6>/qa/rpc-tests ZCASHD=<ycashd> <venv>/bin/python yewd/qa/gen_ycashd_rpc_table.py \\
        --tmpdir=<dir> --portseed=<n> [--out=yewd/facade/src/ycashd_rpc.json]
"""

import json
import os
import re
import sys

QA = os.environ.get('YCASH6_QA')
if not QA:
    sys.exit('set YCASH6_QA to ycash6 qa/rpc-tests')
sys.path.insert(0, QA)
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, '..', 'facade', 'src', 'ycashd_rpc.json')
for a in list(sys.argv[1:]):
    if a.startswith('--out='):
        OUT = a.split('=', 1)[1]
        sys.argv.remove(a)

from test_framework.authproxy import JSONRPCException                         # noqa: E402
from test_framework.test_framework import BitcoinTestFramework                # noqa: E402
from test_framework import yellowback_util as yu                              # noqa: E402

MAX_PROBE = 12


def methods():
    sys.path.insert(0, os.path.join(HERE, '..', '..'))
    table = os.path.join(HERE, '..', 'facade', 'src', 'methods.rs')
    names = []
    import re
    with open(table) as f:
        src = f.read()
    for block in ('VAULT_WALLET', 'YED_WALLET', 'PQ_WALLET', 'STOCK_WALLET', 'ROLE_WALLET', 'GATE_WALLET'):
        body = src.split('pub const %s' % block, 1)[1].split('];', 1)[0]
        names += re.findall(r'\("([a-z_]+)",', body)
    for block in ('LOCAL',):
        body = src.split('pub const %s' % block, 1)[1].split('];', 1)[0]
        names += re.findall(r'"([a-z_]+)"', body)
    return names


class GenTable(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 1
        self.cache_behavior = 'clean'

    def setup_network(self, split=False):
        export = os.path.join(self.options.tmpdir, 'export')
        os.makedirs(export, exist_ok=True)
        self.nodes = yu.start_nodes_with_attestor_set(
            1, self.options.tmpdir,
            lambda i: yu.yellowback_node_args(['-experimentalfeatures', '-developerencryptwallet', '-exportdir=' + export]),
            [])
        self.is_network_split = False

    def run_test(self):
        n = self.nodes[0]
        out = {'_source': 'ycashd %s, regtest, Yellowback live, -experimentalfeatures -developerencryptwallet'
                          % n.getnetworkinfo().get('subversion', ''),
               '_help': n.help(), 'methods': {}}
        for m in methods():
            text = n.help(m)
            lo, hi, tail = None, None, False
            for k in (MAX_PROBE, 0):
                try:
                    getattr(n, m)(*([None] * k))
                except JSONRPCException as e:
                    msg = e.error.get('message', '')
                    mm = re.match(r'(Not enough|Too many) parameters for method `[a-z_]+`. Needed (?:exactly (\d+)|at least (\d+) and at most (\d+)), but received', msg)
                    if e.error.get('code') == -32602 and mm:
                        if mm.group(2) is not None:
                            lo = hi = int(mm.group(2))
                        else:
                            lo, hi = int(mm.group(3)), int(mm.group(4))
                        # the help text follows unless the handler's help branch returns instead of throwing
                        # (walletlock and walletpassphrase on an unencrypted wallet)
                        tail = msg.endswith('\n\n' + text)
                        assert tail or '\n\n' not in msg, (m, msg[:200])
                        break
            out['methods'][m] = {'help': text, 'min': lo, 'max': hi, 'helptail': tail}
            print('%-28s %s..%s' % (m, lo, hi))
        # walletlock and walletpassphrase have help text only on an encrypted wallet: encrypt, restart, read
        from test_framework.util import bitcoind_processes, start_node
        n.encryptwallet('gen-ycashd-rpc-table')
        bitcoind_processes[0].wait()
        del bitcoind_processes[0]
        export = os.path.join(self.options.tmpdir, 'export')
        n = self.nodes[0] = start_node(0, self.options.tmpdir, yu.yellowback_node_args(
            ['-experimentalfeatures', '-developerencryptwallet', '-exportdir=' + export]))
        for m in ('walletlock', 'walletpassphrase'):
            out['methods'][m]['help'] = n.help(m)
            out['methods'][m]['helptail'] = True
            print('%-28s help read from an encrypted wallet' % m)
        with open(OUT, 'w') as f:
            json.dump(out, f, indent=1, sort_keys=True)
            f.write('\n')
        print('wrote %s' % OUT)


if __name__ == '__main__':
    GenTable().main()
