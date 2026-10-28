#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or https://www.opensource.org/licenses/mit-license.php .
"""The devnet operator for the device integration tests (README "Running on a simulator /
emulator"): the M1/M2 flows print "fund this" / "mine" lines for a person at the keyboard; the
quantum flow (app/integration_test/q_flow_test.dart) asks this small HTTP server instead, so it
runs unattended on the iOS simulator and the Android emulator.

    scripts/devnet-operator.py [--port 2398]          (YELLOWBACK_DEVNET_DIR / _PORTSEED, YEW_DEVNET_TOOL)

It binds 127.0.0.1 only (the iOS simulator shares the host's loopback; the Android emulator
reaches it as 10.0.2.2) and runs a fixed set of devnet-tool actions, never a command line:

    GET /height                       the tip of node 0
    GET /mine?n=1                     n pool blocks (re-quoting the price first, round-robin 2-4)
    GET /yec?to=<addr>&amount=<YEC>   sendtoaddress from YEW_DEVNET_FUND_NODE (default 0), then a block
    GET /yed?to=<addr>&cents=<n>      yed_send from node 0, then a block
    GET /price?usd=<p>                the price the next pool blocks quote

Every answer is JSON: {"ok": true, ...} or {"ok": false, "error": "..."}.
"""
import argparse
import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))


def workspace():
    d = HERE
    while d != "/" and not os.path.exists(os.path.join(d, "repos.yaml")):
        d = os.path.dirname(d)
    return d


WS = workspace()
PY = os.environ.get("YEW_DEVNET_PYTHON", os.path.join(WS, ".venv", "bin", "python"))
TOOL = os.environ.get("YEW_DEVNET_TOOL", os.path.join(WS, "wt", "q-dd", "contrib", "yellowback", "devnet", "yellowback-devnet"))
FUND_NODE = os.environ.get("YEW_DEVNET_FUND_NODE", "0")
LOCK = threading.Lock()   # one devnet action at a time
STATE = {"price": os.environ.get("YEW_DEVNET_PRICE", "50"), "pool": 0}


def tool(*args):
    repo = os.path.abspath(os.path.join(os.path.dirname(TOOL), "..", "..", ".."))
    out = subprocess.run([PY, TOOL, *args], cwd=repo, capture_output=True, text=True, timeout=300)
    if out.returncode != 0:
        raise RuntimeError("yellowback-devnet %s: %s%s" % (" ".join(args), out.stdout, out.stderr))
    return out.stdout.strip().strip('"')


def cli(node, *args):
    return tool("cli", "--node", str(node), "--", *args)


def wait_mempool(txid, nodes=(2, 3, 4), timeout=60):
    start = time.time()
    while not all(txid in json.loads(cli(n, "getrawmempool")) for n in nodes):
        if time.time() - start > timeout:
            raise RuntimeError("%s not in the pools' mempools after %ds" % (txid, timeout))
        time.sleep(0.3)


def mine(n=1):
    h = None
    for _ in range(n):
        tool("price", STATE["price"])
        pool = 2 + STATE["pool"] % 3
        STATE["pool"] += 1
        h = int(tool("mine", "1", str(pool)).rsplit("-> ", 1)[-1].strip())
    return h


def handle(path, q):
    one = lambda k, d=None: (q.get(k) or [d])[0]
    if path == "/height":
        return {"height": int(cli(0, "getblockcount"))}
    if path == "/mine":
        n = max(1, min(int(one("n", "1")), 200))
        return {"height": mine(n)}
    if path == "/price":
        STATE["price"] = str(float(one("usd")))
        return {"price": STATE["price"]}
    if path == "/yec":
        txid = cli(FUND_NODE, "sendtoaddress", one("to"), str(float(one("amount"))))
        wait_mempool(txid)
        return {"txid": txid, "height": mine(1)}
    if path == "/yed":
        r = json.loads(cli(0, "yed_send", one("to"), str(int(one("cents")))))
        wait_mempool(r["txid"])
        return {"txid": r["txid"], "height": mine(1)}
    raise KeyError(path)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        u = urlparse(self.path)
        try:
            with LOCK:
                body, code = dict(ok=True, **handle(u.path, parse_qs(u.query))), 200
        except KeyError as e:
            body, code = {"ok": False, "error": "unknown action %s" % e}, 404
        except Exception as e:   # the test shows the devnet's own error text
            body, code = {"ok": False, "error": str(e)}, 500
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        sys.stderr.write("operator: %s -> %s\n" % (self.path, body))

    def log_message(self, *a):
        pass


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=int(os.environ.get("YEW_OPERATOR_PORT", "2398")))
    a = ap.parse_args()
    if not os.path.isfile(TOOL):
        sys.exit("devnet-operator: no devnet tool at %s (YEW_DEVNET_TOOL)" % TOOL)
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), Handler)
    sys.stderr.write("devnet-operator: http://127.0.0.1:%d (tool %s, devnet %s)\n" % (a.port, TOOL, os.environ.get("YELLOWBACK_DEVNET_DIR", "?")))
    srv.serve_forever()


if __name__ == "__main__":
    main()
