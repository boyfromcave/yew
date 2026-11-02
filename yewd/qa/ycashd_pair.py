#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or https://www.opensource.org/licenses/mit-license.php .

"""
A stand-in `ycashd` for tools that start their own node (Hawkeye's regtest tests, a devnet):
`ycashd_pair.py -datadir=<d> <ycashd args>` starts the pair the harness's YEWD_BIN mode starts
(plan §3b S0 "Harness mode") and is, to its caller, one ycashd with a wallet:

  1. `yewd -datadir=<d> -conf=ycash.conf -regtest -initwallet` creates the wallet and names its
     coinbase address (H8);
  2. the backend, `ZCASHD -disablewallet -datadir=<d>/backend <args> -mineraddress=<it>
     -minetolocalwallet=0`, from a copy of `<d>/ycash.conf` without the RPC credentials and with
     the RPC port moved (cookie authentication);
  3. this process becomes `yewd -datadir=<d> -conf=ycash.conf -regtest -backendrpcport=<p>
     -backendrpccookiefile=<d>/backend/regtest/.cookie -stopbackend`, on the caller's RPC port with
     the caller's credentials. A watchdog stops the backend when it exits (a kill -9 included).

`-version` is answered by ZCASHD. Environment: ZCASHD (the ycash6 binary), YEWD_BIN (yewd),
YEWD_PAIR_PORT_OFFSET (default 1000: the backend's RPC port is the caller's plus it).
"""

import json
import os
import subprocess
import sys


def conf_lines(path):
    with open(path) as f:
        return [l.rstrip('\n') for l in f]


def main(argv):
    zcashd = os.environ['ZCASHD']
    yewd = os.environ['YEWD_BIN']
    if any(a in ('-version', '--version') for a in argv):
        os.execv(zcashd, [zcashd] + argv)
    datadir = next(a.split('=', 1)[1] for a in argv if a.startswith('-datadir='))
    conf = os.path.join(datadir, 'ycash.conf')
    lines = conf_lines(conf)
    kv = dict(l.split('=', 1) for l in lines if '=' in l and not l.lstrip().startswith('#'))
    rpcport = int(kv.get('rpcport', '18832'))
    backend_port = rpcport + int(os.environ.get('YEWD_PAIR_PORT_OFFSET', '1000'))
    out = subprocess.check_output([yewd, '-datadir=' + datadir, '-conf=ycash.conf', '-regtest', '-initwallet'])
    mine = json.loads(out)['mineaddress']
    bdir = os.path.join(datadir, 'backend')
    os.makedirs(bdir, exist_ok=True)
    with open(os.path.join(bdir, 'ycash.conf'), 'w') as f:
        for l in lines:
            k = l.split('=', 1)[0].strip()
            if k in ('rpcuser', 'rpcpassword', 'rpcport', 'rpcauth'):
                continue
            f.write(l + '\n')
        f.write('rpcport=%d\n' % backend_port)
    bargs = [a for a in argv if not a.startswith('-datadir=')]
    backend = subprocess.Popen([zcashd, '-datadir=' + bdir, '-disablewallet', '-mineraddress=' + mine,
                                '-minetolocalwallet=0'] + bargs,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    me = os.getpid()
    # the watchdog: the backend dies with this process (which becomes yewd), however it ends
    subprocess.Popen(['/bin/sh', '-c', 'while kill -0 %d 2>/dev/null; do sleep 1; done; kill %d 2>/dev/null'
                      % (me, backend.pid)], start_new_session=True,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    cookie = os.path.join(bdir, 'regtest', '.cookie')
    os.execv(yewd, [yewd, '-datadir=' + datadir, '-conf=ycash.conf', '-regtest',
                    '-backendrpcport=%d' % backend_port, '-backendrpccookiefile=' + cookie, '-stopbackend'])


if __name__ == '__main__':
    main(sys.argv[1:])
