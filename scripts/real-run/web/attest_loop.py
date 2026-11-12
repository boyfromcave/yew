#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or https://www.opensource.org/licenses/mit-license.php .
"""Keep node 0's attestation pool fresh: every few seconds, for each attestor seq the node's wallet
holds, yed_signattestation <seq> <price µUSD> then yed_addattestation (devnet doc section 2, by hand).
attest_loop.py <price micro-USD> <seq,...>; stops when $STOP_FILE exists."""
import os, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import drive as d
price, seqs = int(sys.argv[1]), [int(x) for x in sys.argv[2].split(',')]
last = None
while not os.path.exists(os.environ['STOP_FILE']):
    try:
        h = d.cli(0, 'getblockcount')
        if h != last:
            for s in seqs:
                d.cli(0, 'yed_addattestation', d.cli(0, 'yed_signattestation', s, price)['hex'])
            last = h
    except Exception as e:  # noqa: BLE001
        print('attest:', str(e)[:200], flush=True)
    time.sleep(2)
