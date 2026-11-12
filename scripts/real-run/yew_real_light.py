#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or https://www.opensource.org/licenses/mit-license.php .
"""YEW-REAL, the light leg: ycash6 (D-9) + lightwalletd-dd (--yellowback) + the YEW core's app API
(yew core/tests/real_run.rs) on regtest, Yellowback live (the core's dry run needs it).

node 0  plain ycashd wallet: miner, attestor set, YED pool, lightwalletd's backend (-insightexplorer -txindex)
node 1  plain ycashd wallet: the receiver (its four address types are the matrix's destinations)

YCASH6_QA=... ZCASHD=... LWD_BIN=... YEW_TREE=<yew worktree> python yew_real_light.py --tmpdir=... --portseed=...
"""
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


class YewRealLight(BitcoinTestFramework):

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
        print('activate YED (node 0 the pool)')
        activate_yed_late(self, [0], ((0, 1),))
        n0, n1 = self.nodes
        dst = {'ecc': n1.getnewaddress(), 'sapling': n1.z_getnewaddress('sapling'),
               'pq_slh': n1.getnewaddress('', 'pqslh'), 'pq_falcon': n1.getnewaddress('', 'pq')}
        print('destinations', dst)
        c = self.conf(0)
        lwd_dir = os.path.join(self.options.tmpdir, 'lwd')
        os.makedirs(lwd_dir, exist_ok=True)
        lwd = subprocess.Popen([os.environ['LWD_BIN'], '--rpcuser', c['rpcuser'], '--rpcpassword', c['rpcpassword'],
                                '--rpchost', '127.0.0.1', '--rpcport', str(rpc_port(0)), '--no-tls-very-insecure',
                                '--grpc-bind-addr', '127.0.0.1:%d' % self.options.lwdport,
                                '--http-bind-addr', '127.0.0.1:%d' % (self.options.lwdport + 1),
                                '--data-dir', lwd_dir, '--log-file', os.path.join(lwd_dir, 'lwd.log'), '--yellowback'])
        try:
            time.sleep(5)
            assert lwd.poll() is None, 'lightwalletd exited'
            cli = '%s -datadir=%s' % (os.environ['ZCASHD'].replace('ycashd', 'ycash-cli'), os.path.join(self.options.tmpdir, 'node0'))
            env = dict(os.environ, YEW_REAL='1', YEW_REAL_SERVER='127.0.0.1:%d' % self.options.lwdport,
                       YEW_REAL_CLI=cli, YEW_REAL_DIR=os.path.join(self.options.tmpdir, 'app'),
                       YEW_REAL_PARAMS=os.path.expanduser('~/Library/Application Support/ZcashParams'),
                       YEW_REAL_DST=','.join('%s=%s' % kv for kv in dst.items()),
                       CARGO_TARGET_DIR=os.path.join(os.environ['YEW_TREE'], 'target'))
            # ycash-cli with a space in the params path would break the split: the CLI needs no params
            r = subprocess.run(['cargo', 'test', '-j', '3', '-p', 'yew-core', '--test', 'real_run', '--',
                                '--ignored', '--nocapture'], cwd=os.environ['YEW_TREE'], env=env)
            print('driver exit', r.returncode)
        finally:
            lwd.terminate()
            lwd.wait()


if __name__ == '__main__':
    YewRealLight().main()
