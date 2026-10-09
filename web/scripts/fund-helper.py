#!/usr/bin/env python3
"""The funding helper of web/scripts/test-core-wasm.sh: a loopback HTTP server (with CORS) the
browser test calls to be paid from the devnet node's wallet.

  GET /fund?addr=<yregtestsapling1…>&zat=<n>   -> the txid of a z_sendmany to addr

The node's `ycash-cli` is $YEW_FUND_CLI (shell words; default: `kubectl exec` into the kind
cluster of ycash-infra; a local devnet: `yellowback-devnet cli --node 0 --`). Coinbase is
shielded to the node's own Sapling address first when its private balance is short
(z_shieldcoinbase, then wait for the miner), then z_sendmany from that address (1 confirmation).
A miner or heartbeat mines a block every few seconds, so nothing here mines.
"""
import http.server
import json
import os
import shlex
import subprocess
import sys
import time
import urllib.parse

NS = os.environ.get("YEW_KUBE_NS", "ycash")
POD = os.environ.get("YEW_YCASHD_POD", "ycash-ycashd-0")
CLI = shlex.split(os.environ.get("YEW_FUND_CLI", "")) or [
    "kubectl", "-n", NS, "exec", POD, "--", "ycash-cli", "-datadir=/var/lib/ycash",
]


def cli(*args):
    out = subprocess.run([*CLI, *args], capture_output=True, text=True, check=True).stdout.strip()
    try:
        return json.loads(out)
    except ValueError:
        return out


def wait_opid(opid, timeout=300):
    t0 = time.time()
    while time.time() - t0 < timeout:
        for st in cli("z_getoperationstatus", json.dumps([opid])):
            if st["status"] == "success":
                return st["result"]["txid"]
            if st["status"] == "failed":
                raise RuntimeError(st.get("error"))
        time.sleep(1)
    raise RuntimeError(f"operation {opid} timed out")


def node_zaddr():
    for a in cli("z_listaddresses"):
        if a.startswith("yregtestsapling1"):
            return a
    return cli("z_getnewaddress", "sapling")


def private_balance(zaddr, minconf=1):
    return float(cli("z_getbalance", zaddr, str(minconf)))


def ensure_private(zaddr, need_yec):
    if private_balance(zaddr) >= need_yec:
        return
    # fee null (the node's policy), the default limit (50), no memo; the coinbases sit on many of the
    # account's own t-addresses, which the default privacy policy refuses to link.
    r = cli("z_shieldcoinbase", "*", zaddr, "null", "50", "", "AllowLinkingAccountAddresses")
    txid = wait_opid(r["opid"])
    print(f"fund-helper: shielded {r['shieldingValue']} YEC in {txid}; waiting for a confirmation", flush=True)
    t0 = time.time()
    while private_balance(zaddr) < need_yec:
        if time.time() - t0 > 300:
            raise RuntimeError("shielded coinbase did not confirm")
        time.sleep(2)


def fund(addr, zat):
    yec = zat / 1e8
    zaddr = node_zaddr()
    ensure_private(zaddr, yec + 0.001)
    # fee null = ZIP-317 (6.22 refuses an explicit 0.0001); the node's account may hold the shielded
    # coinbase under several of its own addresses, which the default policy refuses to link.
    r = cli("z_sendmany", zaddr, json.dumps([{"address": addr, "amount": f"{yec:.8f}"}]), "1", "null", "AllowLinkingAccountAddresses")
    opid = r if isinstance(r, str) else r.get("opid")
    txid = wait_opid(opid)
    print(f"fund-helper: sent {yec} YEC to {addr} in {txid}", flush=True)
    return txid


class H(http.server.BaseHTTPRequestHandler):
    def _reply(self, code, text):
        body = text.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        if u.path != "/fund":
            return self._reply(404, "not found")
        q = urllib.parse.parse_qs(u.query)
        try:
            addr = q["addr"][0]
            zat = int(q.get("zat", ["150000000"])[0])
            if not addr.startswith("yregtestsapling1"):
                return self._reply(400, "a regtest Sapling address, please")
            self._reply(200, fund(addr, zat))
        except Exception as e:  # noqa: BLE001
            self._reply(500, f"{e}")

    def log_message(self, fmt, *a):
        print("fund-helper:", fmt % a, flush=True)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8766
    print(f"fund-helper: listening on 127.0.0.1:{port} (node: {' '.join(CLI)})", flush=True)
    http.server.HTTPServer(("127.0.0.1", port), H).serve_forever()
