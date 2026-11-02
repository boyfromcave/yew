#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or https://www.opensource.org/licenses/mit-license.php .

"""
yewd S5, hazards H3/H4 on kogany (workspace plan §3b S4 hazards): one pair, kogany + yewd
(the harness's YEWD_KOGANY mode). Checks that yewd holds both indexer streams (ChainTipChange,
MempoolChange) open to kogany's indexer listener, and that a block mined on kogany directly (never
through the façade) is answered by the façade at once.

    YCASH6_QA=<ycash6>/qa/rpc-tests ZCASHD=<ycashd> YEWD_BIN=<yewd> YEWD_KOGANY=<zakurad> \\
        KOGANY_LIVE=W1-Y1,W2-b <venv>/bin/python yewd/qa/s5_streams.py <tmpdir> [portseed]
"""

import os
import subprocess
import sys
import time

sys.path.insert(0, os.environ['YCASH6_QA'])
from test_framework import kogany, util  # noqa: E402
from test_framework.util import PortSeed, initialize_chain_clean, start_node, stop_nodes, wait_bitcoinds  # noqa: E402


def main():
    tmp = sys.argv[1]
    PortSeed.n = int(sys.argv[2]) if len(sys.argv) > 2 else 7601
    assert os.environ.get('YEWD_KOGANY'), 'set YEWD_KOGANY (column 3)'
    os.makedirs(tmp, exist_ok=True)
    os.environ['PATH'] = os.path.dirname(os.environ['ZCASHD']) + ':' + os.environ['PATH']
    initialize_chain_clean(tmp, 1)
    n = start_node(0, tmp)
    try:
        port = kogany.yewd_backend_indexer_port(0)
        pid = util.bitcoind_processes[0].pid
        deadline = time.time() + 30
        while True:
            out = subprocess.run(['lsof', '-nP', '-a', '-p', str(pid), '-iTCP'], capture_output=True, text=True).stdout
            streams = [l for l in out.splitlines() if ':%d' % port in l and 'ESTABLISHED' in l]
            if len(streams) >= 2:
                break
            assert time.time() < deadline, 'yewd holds %d indexer stream(s), want 2' % len(streams)
            time.sleep(0.5)
        backend = kogany.KoganyRPC('http://127.0.0.1:%d/' % kogany.yewd_backend_rpc_port(0),
                                   cookie=os.path.join(tmp, 'node0', 'backend', 'rpc', '.cookie'))
        backend.generate(1)
        assert n.getblockcount() == 1
        print('s5_streams: ok: yewd holds both indexer streams (port %d); a kogany-mined block is seen' % port)
    finally:
        stop_nodes([n])
        wait_bitcoinds()


if __name__ == '__main__':
    main()
