#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or https://www.opensource.org/licenses/mit-license.php .
"""A loopback mirror of the Sapling proving files with CORS (any origin), for the browser's
fetch_params: params_mirror.py <port> <dir> [--corrupt] [--delay-ms N]. --corrupt flips one byte of
every file served (the pins must refuse it); --delay-ms sleeps before each answer (a slow source)."""
import http.server, os, sys, time
PORT, DIR = int(sys.argv[1]), sys.argv[2]
CORRUPT = '--corrupt' in sys.argv
DELAY = int(sys.argv[sys.argv.index('--delay-ms') + 1]) / 1000 if '--delay-ms' in sys.argv else 0
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        name = os.path.basename(self.path.split('?')[0])
        p = os.path.join(DIR, name)
        time.sleep(DELAY)
        if not name.endswith('.params') or not os.path.exists(p):
            self.send_response(404); self.send_header('Access-Control-Allow-Origin', '*'); self.send_header('Content-Length', '0'); self.end_headers(); return
        data = bytearray(open(p, 'rb').read())
        if CORRUPT: data[len(data) // 2] ^= 1
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers(); self.wfile.write(data)
        print('served', name, len(data), flush=True)
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(('127.0.0.1', PORT), H).serve_forever()
