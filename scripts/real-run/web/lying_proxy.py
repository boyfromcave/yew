#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or https://www.opensource.org/licenses/mit-license.php .
"""A hostile gRPC-web server for the browser wallet: forwards every request to the honest gRPC-web
front and rewrites the fee terms in GetYellowbackInfo's answer (YellowbackInfo.params.fees.network:
the plain and Yellowback zatPerKB, and the reported priceMicroUsd).

  lying_proxy.py <listen port> <upstream base URL> [--rate-x N] [--price-micro P]

--rate-x multiplies both zatPerKB (and maxTxFeeZat by the same factor); --price-micro replaces the
reported price. CORS is answered here (any origin). stdlib only.
"""
import http.server
import sys
import urllib.error
import urllib.request

PORT = int(sys.argv[1])
UP = sys.argv[2].rstrip('/')
RATE_X = int(sys.argv[sys.argv.index('--rate-x') + 1]) if '--rate-x' in sys.argv else 1
PRICE = int(sys.argv[sys.argv.index('--price-micro') + 1]) if '--price-micro' in sys.argv else None
TARGET = '/cash.z.wallet.sdk.rpc.YellowbackStreamer/GetYellowbackInfo'


def varint(b, i):
    v = s = 0
    while True:
        c = b[i]
        i += 1
        v |= (c & 0x7f) << s
        s += 7
        if c < 0x80:
            return v, i


def enc_varint(v):
    if v < 0:
        v += 1 << 64
    out = bytearray()
    while True:
        c = v & 0x7f
        v >>= 7
        if v:
            out.append(c | 0x80)
        else:
            out.append(c)
            return bytes(out)


def fields(b):
    i = 0
    out = []
    while i < len(b):
        key, i = varint(b, i)
        f, wt = key >> 3, key & 7
        if wt == 0:
            v, i = varint(b, i)
        elif wt == 2:
            n, i = varint(b, i)
            v = b[i:i + n]
            i += n
        elif wt == 1:
            v = b[i:i + 8]
            i += 8
        elif wt == 5:
            v = b[i:i + 4]
            i += 4
        else:
            raise ValueError('wire type %d' % wt)
        out.append((f, wt, v))
    return out


def build(fs):
    out = bytearray()
    for f, wt, v in fs:
        out += enc_varint(f << 3 | wt)
        if wt == 0:
            out += enc_varint(v)
        elif wt == 2:
            out += enc_varint(len(v)) + v
        else:
            out += v
    return bytes(out)


def edit(b, path, fn):
    """Apply fn(old int or None) -> new int at the varint field `path` (a list of field numbers)."""
    fs = fields(b)
    head, rest = path[0], path[1:]
    found = False
    for k, (f, wt, v) in enumerate(fs):
        if f == head:
            found = True
            fs[k] = (f, 2, edit(v, rest, fn)) if rest else (f, 0, fn(v))
    if not found:
        fs.append((head, 2, edit(b'', rest, fn)) if rest else (head, 0, fn(None)))
    return build(fs)


def lie(msg):
    net = [11, 24, 2]
    for rate in (5, 8):
        if RATE_X != 1:
            msg = edit(msg, net + [rate, 5], lambda v: (v or 0) * RATE_X)
            msg = edit(msg, net + [rate, 3], lambda v: (v or 0) * RATE_X)
    if RATE_X != 1:
        msg = edit(msg, [11, 23, 4], lambda v: (v or 0) * RATE_X)   # params.pq.feeRateZatPerKB, kept consistent
    if PRICE is not None:
        msg = edit(msg, net + [6], lambda v: PRICE)
    return msg


def rewrite(body):
    out = bytearray()
    i = 0
    while i + 5 <= len(body):
        flag = body[i]
        n = int.from_bytes(body[i + 1:i + 5], 'big')
        data = body[i + 5:i + 5 + n]
        i += 5 + n
        if flag == 0:
            data = lie(data)
        out += bytes([flag]) + len(data).to_bytes(4, 'big') + data
    return bytes(out)


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def cors(self):
        self.send_header('Access-Control-Allow-Origin', self.headers.get('Origin') or '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.send_header('Access-Control-Expose-Headers', 'grpc-status, grpc-message, grpc-status-details-bin')

    def do_OPTIONS(self):
        self.send_response(204)
        self.cors()
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
        hdrs = {k: v for k, v in self.headers.items() if k.lower() in ('content-type', 'x-grpc-web', 'x-user-agent', 'grpc-timeout', 'accept')}
        r = urllib.request.Request(UP + self.path, data=body, method='POST', headers=hdrs)
        try:
            with urllib.request.urlopen(r, timeout=180) as resp:
                data = resp.read()
                status, rh = resp.status, resp.headers
        except urllib.error.HTTPError as e:
            data, status, rh = e.read(), e.code, e.headers
        if self.path == TARGET and status == 200:
            data = rewrite(data)
            print('lied on', self.path, flush=True)
        self.send_response(status)
        for k, v in rh.items():
            if k.lower() in ('content-type', 'grpc-status', 'grpc-message'):
                self.send_header(k, v)
        self.cors()
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


if __name__ == '__main__':
    http.server.ThreadingHTTPServer(('127.0.0.1', PORT), H).serve_forever()
