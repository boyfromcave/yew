#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or https://www.opensource.org/licenses/mit-license.php .
"""Real-stack run, the pre-Canopy leg (YEW-REAL finding 1): Sapling notes created before Canopy
(pre-ZIP-212) are spent after it, by yewd and by the YEW core, and the node accepts and mines them.

Regtest with Canopy at CANOPY (not at 1), Vault at ACTIVATION.
node 0  plain ycashd wallet: miner, attestor set, YED pool, lightwalletd's backend; pays the notes
node 1  the yewd pair (ycash6 -disablewallet + yewd + yewd-signer)

Before Canopy node 0 pays three 1-YEC notes to yewd's Sapling address and three to the core's (the
fixed regtest phrase's default address, from the driver's address phase). After Canopy, before
Vault: yewd z_sendmany from its Sapling address to node 0 (Canopy branch). After Vault and the YED
activation: yewd again (Vault branch), then the core's driver (private -> post-quantum twice,
private -> private).

YCASH6_QA=... ZCASHD=... YEWD_BIN_PAIR=... LWD_BIN=... YEW_TREE=<yew tree> \
  python yew_real_precanopy.py --tmpdir=... --portseed=... --lwdport=...
"""
import json
import os
import subprocess
import sys
import time
from decimal import Decimal

QA = os.environ['YCASH6_QA']
sys.path.insert(0, QA)
YEWD = os.environ['YEWD_BIN_PAIR']
os.environ['YEWD_BIN'] = YEWD

from test_framework import util, yellowback_util                              # noqa: E402
from test_framework.authproxy import JSONRPCException                         # noqa: E402
from test_framework.test_framework import BitcoinTestFramework                # noqa: E402
from test_framework.util import (                                             # noqa: E402
    VAULT_BRANCH_ID, connect_nodes_bi, nuparams, rpc_port, sync_blocks, sync_mempools,
    wait_and_assert_operationid_status, z_sendmany_opid)
from test_framework.yellowback_util import (                                  # noqa: E402
    YCASH_BLOSSOM_BRANCH_ID, YCASH_BRANCH_ID, YCASH_CANOPY_BRANCH_ID, YCASH_HEARTWOOD_BRANCH_ID,
    activate_yed_late)

PAIR = 1
CANOPY = 150
ACTIVATION = 210
FALCON = 220
_orig_start = util.start_node


def start_node_sel(i, dirname, extra_args=None, *a, **k):
    """YEWD_BIN only for the pair node: the harness checks the variable at each start."""
    if i == PAIR:
        os.environ['YEWD_BIN'] = YEWD
    else:
        os.environ.pop('YEWD_BIN', None)
    try:
        return _orig_start(i, dirname, extra_args, *a, **k)
    finally:
        os.environ['YEWD_BIN'] = YEWD


util.start_node = start_node_sel
yellowback_util.start_node = start_node_sel
RESULTS = {'yewd': [], 'core': []}


class YewRealPreCanopy(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.yed_args = {}

    def add_options(self, parser):
        parser.add_option('--lwdport', dest='lwdport', type='int', default=29467)

    def node_args(self, i):
        a = [nuparams(YCASH_BRANCH_ID, 1), nuparams(YCASH_BLOSSOM_BRANCH_ID, 1),
             nuparams(YCASH_HEARTWOOD_BRANCH_ID, 1), nuparams(YCASH_CANOPY_BRANCH_ID, CANOPY),
             nuparams(VAULT_BRANCH_ID, ACTIVATION), '-pqfalconheight=%d' % FALCON, '-txindex']
        if i == 0:
            a += ['-experimentalfeatures', '-insightexplorer']
        return a + self.yed_args.get(i, [])

    def setup_network(self, split=False):
        self.nodes = [start_node_sel(i, self.options.tmpdir, self.node_args(i)) for i in range(2)]
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False
        self.sync_all()

    def mine(self, n=1):
        sync_mempools(self.nodes)
        self.nodes[0].generate(n)
        sync_blocks(self.nodes)

    def cargo(self, env):
        r = subprocess.run(['cargo', 'test', '-j', '3', '-p', 'yew-core', '--test', 'real_run', '--',
                            '--ignored', '--nocapture', '--exact', 'real_stack_pre_canopy_notes'],
                           cwd=os.environ['YEW_TREE'], env=env, capture_output=True, text=True)
        sys.stdout.write(r.stdout)
        sys.stderr.write(r.stderr[-4000:])
        return r.returncode, [ln for ln in r.stdout.splitlines() if ln.startswith('REAL ')]

    def yewd_send(self, label, to, amount):
        n0, n1 = self.nodes
        row = {'cell': label, 'height': n0.getblockcount() + 1, 'amount': str(amount)}
        try:
            txid = wait_and_assert_operationid_status(n1, z_sendmany_opid(n1, self.yz, [(to, amount)]))
            sync_mempools(self.nodes)
            row['txid'] = txid
            row['accepted'] = txid in n0.getrawmempool()
            self.mine(1)
            row['mined'] = n0.getrawtransaction(txid, 1).get('confirmations', 0) > 0
            raw = n0.getrawtransaction(txid, 1)
            row['sapling_spends'] = len(raw.get('vShieldedSpend', []))
        except (JSONRPCException, AssertionError) as e:
            row['error'] = getattr(e, 'error', str(e))
        print('YEWD', json.dumps(row))
        RESULTS['yewd'].append(row)

    def run_test(self):
        n0, n1 = self.nodes
        env = dict(os.environ, CARGO_TARGET_DIR=os.path.join(os.environ['YEW_TREE'], 'target'),
                   YEW_REAL_PHASE='address')
        env.pop('YEW_REAL', None)
        rc, lines = self.cargo(env)
        assert rc == 0, 'driver address phase failed'
        core_z = json.loads(next(ln for ln in lines if ln.startswith('REAL zaddr '))[len('REAL zaddr '):])
        self.yz = n1.z_getnewaddress('sapling')
        print('core', core_z, 'yewd', self.yz)
        n0.generate(130)
        sync_blocks(self.nodes)
        print('node 0 balance at 130:', n0.getbalance())
        fund = n0.getnewaddress()
        for _ in range(6):
            n0.sendtoaddress(fund, Decimal('1.01'))
        self.mine(1)
        # the 6.x wallet learns of a block asynchronously
        for _ in range(120):
            if n0.z_getbalance(fund, 1) >= Decimal('6.06'):
                break
            time.sleep(0.5)
        for z in (self.yz, core_z):
            for _ in range(3):
                opid = z_sendmany_opid(n0, fund, [(z, 1)])
                for _ in range(240):
                    r = n0.z_getoperationresult([opid])
                    if r:
                        break
                    time.sleep(0.5)
                assert r and r[0]['status'] == 'success', r
                self.mine(1)
        h = n0.getblockcount()
        assert h < CANOPY, h
        print('six notes paid at height %d (Canopy at %d): pre-ZIP-212' % (h, CANOPY))
        RESULTS['notes_height'] = h
        self.mine(CANOPY + 5 - h)
        print('yewd balance', n1.z_getbalance(self.yz))
        self.yewd_send('yewd sapling->ecc (Canopy branch)', n0.getnewaddress(), Decimal('0.5'))
        self.mine(FALCON + 2 - n0.getblockcount())
        print('activate YED (node 0 the pool)')
        activate_yed_late(self, [0], ((0, 1),))
        n0, n1 = self.nodes
        self.yewd_send('yewd sapling->sapling (Vault branch)', n0.z_getnewaddress('sapling'), Decimal('0.4'))
        self.yewd_send('yewd sapling->pq_slh (Vault branch)', n0.getnewaddress('', 'pqslh'), Decimal('0.3'))
        RESULTS['yewd_balance'] = str(n1.z_getbalance(self.yz))
        dst = {'sapling': n0.z_getnewaddress('sapling'), 'pq_slh': n0.getnewaddress('', 'pqslh'),
               'pq_falcon': n0.getnewaddress('', 'pq')}
        c = {}
        for line in open(os.path.join(self.options.tmpdir, 'node0', 'ycash.conf'), encoding='utf8'):
            if '=' in line:
                k, v = line.strip().split('=', 1)
                c[k] = v
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
            cli = '%s -datadir=%s' % (os.environ['ZCASHD'].replace('ycashd', 'ycash-cli'),
                                      os.path.join(self.options.tmpdir, 'node0'))
            env.update(YEW_REAL_PHASE='spend', YEW_REAL_SERVER='127.0.0.1:%d' % self.options.lwdport,
                       YEW_REAL_CLI=cli, YEW_REAL_DIR=os.path.join(self.options.tmpdir, 'app'),
                       YEW_REAL_PARAMS=os.path.expanduser('~/Library/Application Support/ZcashParams'),
                       YEW_REAL_DST=','.join('%s=%s' % kv for kv in dst.items()))
            rc, lines = self.cargo(env)
            RESULTS['core'] = lines
            print('driver exit', rc)
        finally:
            lwd.terminate()
            lwd.wait()
        out = os.environ.get('YEW_REAL_OUT')
        if out:
            with open(os.path.join(out, 'precanopy.json'), 'w', encoding='utf8') as f:
                json.dump(RESULTS, f, indent=1)


if __name__ == '__main__':
    YewRealPreCanopy().main()
