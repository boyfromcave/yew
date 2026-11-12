#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or https://www.opensource.org/licenses/mit-license.php .
"""WEB-REAL: the regtest stack the browser wallet runs against, held open for a driver.

node 0  ycashd wallet: miner, attestor set, YED pool, lightwalletd's backend (-insightexplorer -txindex)
node 1  ycashd wallet: the receiver (its four address types are the send destinations)
lightwalletd-dd --yellowback on 127.0.0.1:<lwdport> (plaintext gRPC); the gRPC-web front is started
by the caller (run-stack.sh: an Envoy container).

When the stack is up it writes <tmpdir>/stack.json (the two nodes' ycash-cli command lines, the
receiver's addresses, lightwalletd's port) and holds. While <tmpdir>/automine exists node 0 mines a
block every AUTOMINE_SECS (default 5). Touch <tmpdir>/stop to end; every node and lightwalletd stop.

YCASH6_QA=... ZCASHD=... LWD_BIN=... python web_real_stack.py --tmpdir=... --portseed=... --lwdport=...
"""
import json
import os
import subprocess
import sys
import time

QA = os.environ['YCASH6_QA']
sys.path.insert(0, QA)
os.environ.pop('YEWD_BIN', None)

from test_framework.test_framework import BitcoinTestFramework                # noqa: E402
from test_framework.util import (                                             # noqa: E402
    VAULT_BRANCH_ID, connect_nodes_bi, nuparams, rpc_port, start_nodes)
from test_framework.yellowback_util import YCASH_UPGRADE_ARGS, activate_yed_late  # noqa: E402

ACTIVATION = 210
FALCON = 220


class WebRealStack(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.yed_args = {}

    def add_options(self, parser):
        parser.add_option('--lwdport', dest='lwdport', type='int', default=29467)

    def node_args(self, i):
        a = list(YCASH_UPGRADE_ARGS) + [nuparams(VAULT_BRANCH_ID, ACTIVATION), '-pqfalconheight=%d' % FALCON, '-txindex']
        if i == 0:
            a += ['-experimentalfeatures', '-insightexplorer']
        return a + self.yed_args.get(i, [])

    def setup_network(self, split=False):
        self.nodes = start_nodes(2, self.options.tmpdir, extra_args=[self.node_args(i) for i in range(2)])
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False
        self.sync_all()

    def conf(self, i):
        d = {}
        for line in open(os.path.join(self.options.tmpdir, 'node%d' % i, 'ycash.conf'), encoding='utf8'):
            if '=' in line:
                k, v = line.strip().split('=', 1)
                d[k] = v
        return d

    def run_test(self):
        n0, n1 = self.nodes
        n0.generate(FALCON + 2)
        self.sync_all()
        print('activate YED (node 0 the pool)', flush=True)
        activate_yed_late(self, [0], ((0, 1),))
        n0, n1 = self.nodes
        # node 0 needs private funds for the Sapling funding of the browser wallet
        n0.generate(5)
        self.sync_all()
        dst = {'ecc': n1.getnewaddress(), 'sapling': n1.z_getnewaddress('sapling'),
               'pq_slh': n1.getnewaddress('', 'pqslh'), 'pq_falcon': n1.getnewaddress('', 'pq')}
        print('destinations', dst, flush=True)
        c = self.conf(0)
        lwd_dir = os.path.join(self.options.tmpdir, 'lwd')
        os.makedirs(lwd_dir, exist_ok=True)
        lwd = subprocess.Popen([os.environ['LWD_BIN'], '--rpcuser', c['rpcuser'], '--rpcpassword', c['rpcpassword'],
                                '--rpchost', '127.0.0.1', '--rpcport', str(rpc_port(0)), '--no-tls-very-insecure',
                                '--grpc-bind-addr', '0.0.0.0:%d' % self.options.lwdport,
                                '--http-bind-addr', '127.0.0.1:%d' % (self.options.lwdport + 1),
                                '--data-dir', lwd_dir, '--log-file', os.path.join(lwd_dir, 'lwd.log'), '--yellowback'])
        cli = os.environ['ZCASHD'].replace('ycashd', 'ycash-cli')
        state = {'cli0': [cli, '-datadir=%s' % os.path.join(self.options.tmpdir, 'node0')],
                 'cli1': [cli, '-datadir=%s' % os.path.join(self.options.tmpdir, 'node1')],
                 'lwdport': self.options.lwdport, 'dst': dst, 'activation': ACTIVATION, 'falcon': FALCON}
        stop = os.path.join(self.options.tmpdir, 'stop')
        auto = os.path.join(self.options.tmpdir, 'automine')
        secs = float(os.environ.get('AUTOMINE_SECS', '5'))
        try:
            time.sleep(5)
            assert lwd.poll() is None, 'lightwalletd exited'
            with open(os.path.join(self.options.tmpdir, 'stack.json'), 'w') as f:
                json.dump(state, f, indent=1)
            print('STACK READY', json.dumps(state), flush=True)
            last = 0.0
            while not os.path.exists(stop):
                assert lwd.poll() is None, 'lightwalletd exited'
                if os.path.exists(auto) and time.time() - last >= secs:
                    try:
                        n0.generate(1)
                    except Exception as e:  # noqa: BLE001 (a busy node: try again next round)
                        print('automine:', e, flush=True)
                    last = time.time()
                time.sleep(0.5)
            print('stop file seen', flush=True)
        finally:
            lwd.terminate()
            lwd.wait()


if __name__ == '__main__':
    WebRealStack().main()
