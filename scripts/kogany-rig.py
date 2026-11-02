#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""The kogany client rig (workspace kogany plan W9-c): a regtest kogany node and its ycash6 test rig.

kogany (`zakurad`, built with `--features ycash`) is wallet-less (kogany plan K-3): it serves the
read and node-state RPCs, never solves Equihash and holds no keys. The rig therefore pairs it with
a ycash6 `ycashd` sidecar (`connect=` kogany, `listen=0`: kogany is its only peer), the test rig of
plan W9-a: the sidecar's wallet funds and signs, its `generate` mines, and every block and every
transaction it makes reaches the network through kogany, which validates them. A client under test
is pointed at kogany (and only at the sidecar for what needs a wallet), so its reads come from
kogany. Stdlib only; one file, kept identical in every client repository that uses it (lightwalletd-dd,
chain-viz, x402-ycash, yew, hawkeye).

    kogany-rig.py up --zakurad Z --ycashd Y --dir D [--vault 110] [--blocks N]
                     [--lightwalletd LWD [--lightwalletd-sidecar]] [--port-base P]
    kogany-rig.py mine N [POOL]         sync the mempools, generate N on the sidecar, wait for kogany
    kogany-rig.py cli --node I -- METHOD [ARGS...]   node 0 = the sidecar, any other = kogany
    kogany-rig.py price P                no-op (the rig has no quoting pools); accepted for tools
                                         that drive yellowback-devnet
    kogany-rig.py status | down
    kogany-rig.py follow --zakurad Z --dir D --peer-p2p PORT --peer-rpc URL [--vault 110] -- CMD...

`--dir` (or `KOGANY_RIG_DIR`, or `YELLOWBACK_DEVNET_DIR`, so a test written against the
yellowback-devnet tool can drive the rig unchanged) holds `rig.json`: the ports, the processes and
the `rpc` table `{"0": sidecar, "1": kogany}` (`url`, `port`, `user`, `password`), the shape the
devnet's `devnet.json` has, so a client test that reads node 0 from it reads the sidecar.

`up` starts kogany, then the sidecar dialling it, mines `--blocks` (default: two past the Vault
activation) and waits until kogany's tip equals the sidecar's. Both run Yellowback with the same
attestor set id (`--attestor-set`, default 0x11 x 32; no attestor joins it, so YED never arms:
the `yed_*` reads answer from a live, empty index). With `--lightwalletd` it also starts
lightwalletd-dd (`--yellowback`) against kogany, and with `--lightwalletd-sidecar` a second one
against the sidecar, a reference for byte-for-byte comparisons.

`follow` is the rig for a client test that starts its own ycashd (Hawkeye's regtest tests): it
starts kogany, has the test's node dial kogany as soon as its RPC answers (`addnode onetry`),
runs CMD, records every tip the test's node reaches while CMD runs, and afterwards checks that
kogany holds every one of them on its best chain (kogany validated every block the test made).
Exit: CMD's status, else 3 when kogany did not follow.
"""

import argparse
import base64
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

NUPARAMS = ['5ba81b19', '76b809bb', '374d694f', '8e471bd6', '66314da3', '19bd2d2f']
ACTIVATION_KEYS = ['Overwinter', 'Sapling', 'Ycash', 'Blossom', 'Heartwood', 'Canopy']
VAULT_BRANCH = '6d5b7a31'
DEFAULT_SET = '11' * 32
PORT_NAMES = ('kp2p', 'kv2', 'krpc', 'yp2p', 'yrpc', 'lwd', 'lwdhttp', 'lwd2', 'lwd2http')


class RigError(Exception):
    pass


def rpc(url, method, params=(), user=None, password=None, timeout=120):
    body = json.dumps({'jsonrpc': '1.0', 'id': 1, 'method': method, 'params': list(params)}).encode()
    req = urllib.request.Request(url, data=body, headers={'content-type': 'application/json'})
    if user is not None:
        req.add_header('Authorization', 'Basic ' + base64.b64encode(('%s:%s' % (user, password)).encode()).decode())
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            answer = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            answer = json.loads(raw or b'{}')
        except ValueError:
            raise RigError('%s: HTTP %s %r' % (method, e.code, raw[:200]))
    if answer.get('error'):
        err = answer['error']
        raise RigError('%s: %s (%s)' % (method, err.get('message'), err.get('code')))
    return answer.get('result')


class Node:
    def __init__(self, entry):
        self.url = entry['url']
        self.user = entry.get('user')
        self.password = entry.get('password')

    def __call__(self, method, *params, timeout=120):
        return rpc(self.url, method, params, self.user, self.password, timeout)


def wait_for(what, predicate, timeout=120, step=0.5):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            value = predicate()
            if value:
                return value
        except Exception as e:  # noqa: BLE001 - polled until the deadline
            last = e
        time.sleep(step)
    raise RigError('timed out (%d s) waiting for %s%s' % (timeout, what, ': %s' % last if last else ''))


def free_ports(names):
    socks = []
    try:
        for _ in names:
            s = socket.socket()
            s.bind(('127.0.0.1', 0))
            socks.append(s)
        return {name: s.getsockname()[1] for name, s in zip(names, socks)}
    finally:
        for s in socks:
            s.close()


def rig_dir(args):
    d = args.dir or os.environ.get('KOGANY_RIG_DIR') or os.environ.get('YELLOWBACK_DEVNET_DIR')
    if not d:
        raise RigError('no rig directory: --dir, KOGANY_RIG_DIR or YELLOWBACK_DEVNET_DIR')
    return os.path.abspath(d)


def load(args):
    path = os.path.join(rig_dir(args), 'rig.json')
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        raise RigError('%s: no rig here (kogany-rig.py up first)' % path)


def save(state):
    path = os.path.join(state['dir'], 'rig.json')
    with open(path + '.tmp', 'w', encoding='utf-8') as f:
        json.dump(state, f, indent=2)
    os.replace(path + '.tmp', path)
    # the same table as the devnet's devnet.json, for tests written against yellowback-devnet
    with open(os.path.join(state['dir'], 'devnet.json'), 'w', encoding='utf-8') as f:
        json.dump(state, f, indent=2)


def spawn(argv, log, env=None):
    out = open(log, 'ab')
    return subprocess.Popen(argv, stdout=out, stderr=subprocess.STDOUT, env=env, start_new_session=True)


def zakurad_toml(root, ports, peers, vault, attestor_set):
    heights = '\n'.join(['%s = 1' % k for k in ACTIVATION_KEYS] + ['Vault = %d' % vault])
    return '''[network]
listen_addr = "127.0.0.1:{kp2p}"
initial_testnet_peers = {peers}
p2p_stack = "legacy"
cache_dir = "{root}/network"
identity_dir = "{root}/identity"

[network.network]
regtest = true

[network.network.params.activation_heights]
{heights}

[network.zakura]
listen_addr = "127.0.0.1:{kv2}"

[rpc]
listen_addr = "127.0.0.1:{krpc}"
enable_cookie_auth = false
cookie_dir = "{root}/rpc"

[state]
cache_dir = "{root}/state"
ephemeral = false

[mempool]
debug_enable_at_height = 0

[mining]
internal_miner = false

[yellowback]
attestor_set = "{attestor_set}"

[tracing]
use_color = false
filter = "info"
'''.format(root=root, peers=json.dumps(peers), heights=heights, attestor_set=attestor_set, **ports)


def start_zakurad(binary, workdir, ports, peers, vault, attestor_set):
    root = os.path.join(workdir, 'zakurad')
    os.makedirs(root, exist_ok=True)
    conf = os.path.join(workdir, 'zakurad.toml')
    with open(conf, 'w', encoding='utf-8') as f:
        f.write(zakurad_toml(root, ports, peers, vault, attestor_set))
    env = dict(os.environ)
    for k in ('KOGANY_VAULT_RPC_MOCK', 'KOGANY_YED_RPC_MOCK'):  # the real index, never the fixtures
        env.pop(k, None)
    p = spawn([binary, '-c', conf, 'start'], os.path.join(workdir, 'zakurad.log'), env)
    kogany = Node({'url': 'http://127.0.0.1:%d/' % ports['krpc']})

    def up():
        if p.poll() is not None:
            raise RigError('zakurad exited with %s; see %s' % (p.returncode, os.path.join(workdir, 'zakurad.log')))
        return kogany('getblockcount', timeout=5) is not None
    wait_for('kogany RPC', up, 120)
    return p, kogany


def start_lightwalletd(binary, workdir, name, rpc_port, user, password, grpc, http):
    data = os.path.join(workdir, name)
    os.makedirs(data, exist_ok=True)
    log = os.path.join(workdir, name + '.log')
    p = spawn([binary, '--rpcuser', user, '--rpcpassword', password, '--rpchost', '127.0.0.1',
               '--rpcport', str(rpc_port), '--no-tls-very-insecure',
               '--grpc-bind-addr', '127.0.0.1:%d' % grpc, '--http-bind-addr', '127.0.0.1:%d' % http,
               '--data-dir', data, '--log-file', log, '--yellowback'],
              os.path.join(workdir, name + '.out'))

    def listening():
        if p.poll() is not None:
            raise RigError('%s exited with %s; see %s' % (name, p.returncode, log))
        with socket.create_connection(('127.0.0.1', grpc), timeout=2):
            return True
    wait_for('%s on %d' % (name, grpc), listening, 60)
    return p


def cmd_up(args):
    workdir = rig_dir(args)
    if os.path.exists(os.path.join(workdir, 'rig.json')):
        raise RigError('%s already holds a rig (kogany-rig.py down first)' % workdir)
    shutil.rmtree(workdir, ignore_errors=True)
    os.makedirs(workdir)
    ports = ({k: args.port_base + i for i, k in enumerate(PORT_NAMES)} if args.port_base
             else free_ports(PORT_NAMES))
    state = {'dir': workdir, 'num_nodes': 2, 'pools': [0], 'vault_height': args.vault,
             'attestor_set': args.attestor_set, 'ports': ports, 'pids': {}, 'binaries': {
                 'zakurad': os.path.abspath(args.zakurad), 'ycashd': os.path.abspath(args.ycashd)},
             'rpc': {
                 '0': {'url': 'http://127.0.0.1:%d/' % ports['yrpc'], 'port': ports['yrpc'], 'user': 'rig',
                       'password': 'rig', 'role': 'sidecar'},
                 '1': {'url': 'http://127.0.0.1:%d/' % ports['krpc'], 'port': ports['krpc'], 'user': 'kogany',
                       'password': 'kogany', 'role': 'kogany'}}}
    save(state)
    try:
        z, kogany = start_zakurad(args.zakurad, workdir, ports, [], args.vault, args.attestor_set)
        state['pids']['zakurad'] = z.pid
        save(state)
        ydir = os.path.join(workdir, 'ycashd')
        os.makedirs(ydir)
        with open(os.path.join(ydir, 'ycash.conf'), 'w', encoding='utf-8') as f:
            f.write('regtest=1\nserver=1\nshowmetrics=0\nprinttoconsole=0\nrpcuser=rig\nrpcpassword=rig\n'
                    'rpcallowip=127.0.0.1\nlistenonion=0\ndiscover=0\ndnsseed=0\ntxindex=1\n'
                    # the address index lightwalletd-dd's transparent views read (getaddress*); -insightexplorer,
                    # since -lightwalletd stalls the first generate on ycash6 6.22.0-rc1 (65cb4ae0f)
                    'experimentalfeatures=1\ninsightexplorer=1\n'
                    'port=%d\nrpcport=%d\nlisten=0\nconnect=127.0.0.1:%d\n' % (ports['yp2p'], ports['yrpc'], ports['kp2p']))
        yargs = [args.ycashd, '-datadir=' + ydir, '-i-am-aware-zcashd-will-be-replaced-by-zebrad-and-zallet-in-2025']
        yargs += ['-nuparams=%s:1' % b for b in NUPARAMS]
        yargs += ['-nuparams=%s:%d' % (VAULT_BRANCH, args.vault), '-yellowbackattestorset=' + args.attestor_set]
        y = spawn(yargs, os.path.join(workdir, 'ycashd.log'))
        state['pids']['ycashd'] = y.pid
        save(state)
        sidecar = Node(state['rpc']['0'])
        wait_for('sidecar RPC', lambda: sidecar('getblockcount', timeout=5) is not None, 300)
        wait_for('the sidecar connected to kogany', lambda: sidecar('getpeerinfo'), 60)
        blocks = args.blocks if args.blocks is not None else args.vault + 2
        if blocks:
            mine(state, blocks)
        if args.lightwalletd:
            p = start_lightwalletd(args.lightwalletd, workdir, 'lightwalletd', ports['krpc'], 'kogany', 'kogany',
                                   ports['lwd'], ports['lwdhttp'])
            state['pids']['lightwalletd'] = p.pid
            state['lightwalletd'] = '127.0.0.1:%d' % ports['lwd']
            if args.lightwalletd_sidecar:
                p = start_lightwalletd(args.lightwalletd, workdir, 'lightwalletd-sidecar', ports['yrpc'], 'rig', 'rig',
                                       ports['lwd2'], ports['lwd2http'])
                state['pids']['lightwalletd-sidecar'] = p.pid
                state['lightwalletd_sidecar'] = '127.0.0.1:%d' % ports['lwd2']
            save(state)
        print(json.dumps({'dir': workdir, 'height': kogany('getblockcount'), 'kogany': state['rpc']['1']['url'],
                          'sidecar': state['rpc']['0']['url'], 'lightwalletd': state.get('lightwalletd'),
                          'lightwalletd_sidecar': state.get('lightwalletd_sidecar'),
                          'zakurad': kogany('getnetworkinfo').get('subversion')}, indent=2))
    except Exception:
        down(state)
        raise


def sync_mempools(state, timeout=60):
    """Every transaction in kogany's mempool also in the sidecar's (kogany relays; a late relay is
    handed over by `sendrawtransaction`), so `generate` mines what the clients sent to kogany."""
    sidecar, kogany = Node(state['rpc']['0']), Node(state['rpc']['1'])
    deadline = time.time() + timeout
    handed = False
    while True:
        missing = set(kogany('getrawmempool')) - set(sidecar('getrawmempool'))
        if not missing:
            return
        if time.time() > deadline:
            raise RigError('the sidecar lacks kogany mempool transactions %s' % sorted(missing))
        if not handed and time.time() > deadline - timeout / 2:
            handed = True
            for txid in missing:
                try:
                    sidecar('sendrawtransaction', kogany('getrawtransaction', txid))
                except RigError as e:
                    print('handing %s to the sidecar: %s' % (txid, e), file=sys.stderr)
        time.sleep(0.3)


def mine(state, n):
    sidecar, kogany = Node(state['rpc']['0']), Node(state['rpc']['1'])
    sync_mempools(state)
    hashes = sidecar('generate', n, timeout=120 + 10 * n)
    tip = hashes[-1]
    wait_for('kogany at the sidecar tip %s' % tip, lambda: kogany('getbestblockhash') == tip, 120)
    return sidecar('getblockcount')


def down(state):
    for name in ('lightwalletd-sidecar', 'lightwalletd', 'ycashd', 'zakurad'):
        pid = state.get('pids', {}).get(name)
        if not pid:
            continue
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            continue
        for _ in range(100):
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.2)
        else:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    path = os.path.join(state['dir'], 'rig.json')
    if os.path.exists(path):
        os.replace(path, path + '.down')


def print_result(value):
    if isinstance(value, str):
        print(value)
    elif value is None:
        pass
    else:
        print(json.dumps(value, indent=2))


def cmd_cli(args):
    state = load(args)
    node = Node(state['rpc']['0' if args.node == 0 else '1'])
    params = []
    for a in args.call[1:]:
        try:
            params.append(json.loads(a))
        except ValueError:
            params.append(a)
    print_result(node(args.call[0], *params))


def cmd_follow(args):
    workdir = rig_dir(args)
    shutil.rmtree(workdir, ignore_errors=True)
    os.makedirs(workdir)
    ports = free_ports(PORT_NAMES)
    z, kogany = start_zakurad(args.zakurad, workdir, ports, ['127.0.0.1:%d' % args.peer_p2p], args.vault,
                              args.attestor_set)
    peer = Node({'url': args.peer_rpc, 'user': args.peer_user, 'password': args.peer_password})
    tips, stop = [], threading.Event()

    def watch():
        dialled = False
        while not stop.is_set():
            try:
                if not dialled:
                    peer('addnode', '127.0.0.1:%d' % ports['kp2p'], 'onetry', timeout=5)
                    dialled = True
                tip = peer('getbestblockhash', timeout=5)
                if not tips or tips[-1] != tip:
                    tips.append(tip)
            except Exception:  # noqa: BLE001 - the test's node is not up yet, or already gone
                pass
            stop.wait(0.25)
    t = threading.Thread(target=watch, daemon=True)
    t.start()
    try:
        status = subprocess.call(args.command)
    finally:
        stop.set()
        t.join()
    try:
        report = follow_report(kogany, tips)
    finally:
        z.terminate()
        try:
            z.wait(30)
        except subprocess.TimeoutExpired:
            z.kill()
    print(json.dumps(report, indent=2))
    with open(os.path.join(workdir, 'follow.json'), 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)
    if status:
        return status
    return 0 if report['followed'] else 3


def follow_report(kogany, tips):
    report = {'peer_tips_seen': len(tips), 'last_peer_tip': tips[-1] if tips else None}
    if not tips:
        report.update(followed=False, reason='the test node never answered')
        return report
    try:
        wait_for('kogany at %s' % tips[-1], lambda: kogany('getblock', tips[-1], 1), 90)
    except RigError as e:
        report['wait'] = str(e)
    missing = []
    for h in tips:
        try:
            b = kogany('getblock', h, 1)
            if b.get('confirmations', 0) < 1:
                missing.append(h)
        except RigError:
            missing.append(h)
    report.update(kogany_height=kogany('getblockcount'), kogany_tip=kogany('getbestblockhash'),
                  missing_on_kogany=missing, followed=not missing)
    return report


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--dir', help='the rig directory (else KOGANY_RIG_DIR or YELLOWBACK_DEVNET_DIR)')
    sub = ap.add_subparsers(dest='cmd', required=True)
    up = sub.add_parser('up')
    up.add_argument('--zakurad', required=True)
    up.add_argument('--ycashd', required=True)
    up.add_argument('--dir', dest='dir_up')
    up.add_argument('--vault', type=int, default=110, help='the Vault activation height (default 110)')
    up.add_argument('--blocks', type=int, help='blocks the sidecar mines at start (default: Vault + 2)')
    up.add_argument('--attestor-set', default=DEFAULT_SET)
    up.add_argument('--lightwalletd', help='lightwalletd-dd binary: serve kogany (--yellowback)')
    up.add_argument('--lightwalletd-sidecar', action='store_true', help='also a lightwalletd-dd on the sidecar')
    up.add_argument('--port-base', type=int, default=0)
    m = sub.add_parser('mine')
    m.add_argument('n', type=int)
    m.add_argument('pool', nargs='?', help='ignored (yellowback-devnet compatibility)')
    c = sub.add_parser('cli')
    c.add_argument('--node', type=int, default=0)
    c.add_argument('call', nargs=argparse.REMAINDER)
    p = sub.add_parser('price')
    p.add_argument('price', nargs='?')
    sub.add_parser('status')
    sub.add_parser('down')
    f = sub.add_parser('follow')
    f.add_argument('--zakurad', required=True)
    f.add_argument('--dir', dest='dir_up')
    f.add_argument('--vault', type=int, default=110)
    f.add_argument('--attestor-set', default=DEFAULT_SET)
    f.add_argument('--peer-p2p', type=int, required=True)
    f.add_argument('--peer-rpc', required=True)
    f.add_argument('--peer-user', default='u')
    f.add_argument('--peer-password', default='p')
    f.add_argument('command', nargs=argparse.REMAINDER)
    args = ap.parse_args(argv)
    if getattr(args, 'dir_up', None):
        args.dir = args.dir_up
    try:
        if args.cmd == 'up':
            cmd_up(args)
        elif args.cmd == 'mine':
            print('mined %d -> %d' % (args.n, mine(load(args), args.n)))
        elif args.cmd == 'cli':
            if args.call and args.call[0] == '--':
                args.call = args.call[1:]
            if not args.call:
                raise RigError('cli: no method')
            cmd_cli(args)
        elif args.cmd == 'price':
            print('price %s: no quoting pools in the kogany rig (no-op)' % args.price)
        elif args.cmd == 'status':
            print(json.dumps(load(args), indent=2))
        elif args.cmd == 'down':
            down(load(args))
        elif args.cmd == 'follow':
            if args.command and args.command[0] == '--':
                args.command = args.command[1:]
            if not args.command:
                raise RigError('follow: no command')
            return cmd_follow(args)
    except RigError as e:
        print('kogany-rig: %s' % e, file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
