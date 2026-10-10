#!/usr/bin/env python3
"""The funding helper of web/scripts/test-core-wasm.sh: a loopback HTTP server (with CORS) the
browser test calls to be paid from the devnet node's wallet.

  GET /fund?addr=<yregtestsapling1…>&zat=<n>   -> the txid of a z_sendmany to addr
                                                  (&memo=<text> carries a memo; W3)
  GET /fund_t?addr=<sm…>&zat=<n>               -> the txid of a sendtoaddress to the transparent addr
                                                  (W1a; z_sendmany from the node's z-address when
                                                  the node refuses to spend coinbase transparently)
  GET /address                                 -> a fresh transparent address of the node's wallet
                                                  (W2: the recipient of the shell's public send)
  GET /params/<file>                            -> the Sapling parameter file from $PARAMS_DIR
                                                  (default ~/.cache/yew-web/sapling-params; W1a's
                                                  fetch_params source, so the test never downloads)
  GET /reorg?depth=<d>  or  /reorg?height=<h>   -> a reorg (W3): invalidateblock at tip-d (or at h),
                                                  then `generate` so the new branch is longer by one;
                                                  JSON {oldTip, invalidated, newTip}. It disturbs
                                                  every client of the node: once per run, late.

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


def fund(addr, zat, memo=None):
    yec = zat / 1e8
    zaddr = node_zaddr()
    ensure_private(zaddr, yec + 0.001)
    out = {"address": addr, "amount": f"{yec:.8f}"}
    if memo:
        out["memo"] = memo.encode().hex()
    # fee null = ZIP-317 (6.22 refuses an explicit 0.0001); the node's account may hold the shielded
    # coinbase under several of its own addresses, which the default policy refuses to link.
    r = cli("z_sendmany", zaddr, json.dumps([out]), "1", "null", "AllowLinkingAccountAddresses")
    opid = r if isinstance(r, str) else r.get("opid")
    txid = wait_opid(opid)
    print(f"fund-helper: sent {yec} YEC to {addr} in {txid}", flush=True)
    return txid


def fund_t(addr, zat):
    yec = zat / 1e8
    try:
        txid = cli("sendtoaddress", addr, f"{yec:.8f}")
    except subprocess.CalledProcessError as e:
        print(f"fund-helper: sendtoaddress refused ({e.stderr.strip()}); z_sendmany instead", flush=True)
        zaddr = node_zaddr()
        ensure_private(zaddr, yec + 0.001)
        r = cli("z_sendmany", zaddr, json.dumps([{"address": addr, "amount": f"{yec:.8f}"}]), "1", "null", "NoPrivacy")
        txid = wait_opid(r if isinstance(r, str) else r.get("opid"))
    print(f"fund-helper: sent {yec} YEC to transparent {addr} in {txid}", flush=True)
    return txid


def reorg(depth=None, height=None):
    """Invalidate the block at `height` (or tip - depth) and mine until the new branch is one block
    longer than the old chain (the miner keeps mining on it). The disconnected transactions go
    back to the mempool, so a funding mined in the old branch is mined again in the new one."""
    old_tip = int(cli("getblockcount"))
    h = int(height) if height is not None else old_tip - int(depth)
    if h < 1 or h > old_tip:
        raise ValueError(f"height {h} not in 1..{old_tip}")
    cli("invalidateblock", cli("getblockhash", str(h)))
    want = old_tip + 1
    n = want - int(cli("getblockcount"))
    cli("generate", str(n))
    t0 = time.time()
    while int(cli("getblockcount")) < want:
        if time.time() - t0 > 120:
            raise RuntimeError("the new branch did not grow")
        time.sleep(1)
    new_tip = int(cli("getblockcount"))
    print(f"fund-helper: reorg: invalidated height {h} (old tip {old_tip}), new tip {new_tip}", flush=True)
    return json.dumps({"oldTip": old_tip, "invalidated": h, "newTip": new_tip})


PARAMS_DIR = os.environ.get("PARAMS_DIR") or os.path.join(
    os.environ.get("XDG_CACHE_HOME", os.path.expanduser("~/.cache")), "yew-web", "sapling-params")
PARAM_FILES = ("sapling-spend.params", "sapling-output.params")


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
        if u.path.startswith("/params/"):
            name = u.path[len("/params/"):]
            if name not in PARAM_FILES:
                return self._reply(404, "not found")
            path = os.path.join(PARAMS_DIR, name)
            if not os.path.isfile(path):
                return self._reply(404, f"{path} missing (web/scripts/test-spike-prover.sh fetches it)")
            size = os.path.getsize(path)
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", str(size))
            self.end_headers()
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(1 << 20)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
            return None
        if u.path == "/address":
            try:
                return self._reply(200, cli("getnewaddress"))
            except Exception as e:  # noqa: BLE001
                return self._reply(500, f"{e}")
        if u.path not in ("/fund", "/fund_t", "/reorg"):
            return self._reply(404, "not found")
        q = urllib.parse.parse_qs(u.query)
        try:
            if u.path == "/reorg":
                depth = q.get("depth", [None])[0]
                height = q.get("height", [None])[0]
                if depth is None and height is None:
                    return self._reply(400, "depth or height, please")
                return self._reply(200, reorg(depth=depth, height=height))
            addr = q["addr"][0]
            zat = int(q.get("zat", ["150000000"])[0])
            if u.path == "/fund_t":
                return self._reply(200, fund_t(addr, zat))
            if not addr.startswith("yregtestsapling1"):
                return self._reply(400, "a regtest Sapling address, please")
            self._reply(200, fund(addr, zat, q.get("memo", [None])[0]))
        except Exception as e:  # noqa: BLE001
            self._reply(500, f"{e}")

    def log_message(self, fmt, *a):
        print("fund-helper:", fmt % a, flush=True)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8766
    print(f"fund-helper: listening on 127.0.0.1:{port} (node: {' '.join(CLI)})", flush=True)
    http.server.ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
