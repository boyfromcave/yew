#!/usr/bin/env bash
# Runs web/spike-prover's browser tests (plan §2, W0.3) in headless Chrome, debug and release.
# Same toolchain recipe as test-spike-sqlite.sh (Homebrew LLVM clang for wasm32 C, a ChromeDriver
# matched to the installed Chrome, wasm-pack's wasm-bindgen-test-runner).
# The 52 MB of Sapling parameters are served from $PARAMS_DIR (default ~/.cache/yew-web/sapling-params,
# fetched once from download.z.cash and kept) by a tiny local HTTP server with CORS, so the test
# never re-downloads; the files are SHA-256 checked in the test anyway.
set -euo pipefail
cd "$(dirname "$0")/../spike-prover"
LLVM=${LLVM:-/opt/homebrew/opt/llvm/bin}
[ -x "$LLVM/clang" ] || { echo "brew install llvm (clang with the wasm32 backend)"; exit 1; }
CHROME_VER=$("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
CACHE=${XDG_CACHE_HOME:-$HOME/.cache}/yew-web/chromedriver-$CHROME_VER
if [ ! -x "$CACHE/chromedriver" ]; then
  URL=$(curl -s https://googlechromelabs.github.io/chrome-for-testing/known-good-versions-with-downloads.json | python3 -c "
import sys,json; d=json.load(sys.stdin); want='$CHROME_VER'
for v in reversed(d['versions']):
    if v['version'].startswith(want):
        for x in v.get('downloads',{}).get('chromedriver',[]):
            if x['platform']=='mac-arm64': print(x['url']); raise SystemExit
")
  [ -n "$URL" ] || { echo "no chromedriver for Chrome $CHROME_VER"; exit 1; }
  mkdir -p "$CACHE"; curl -sL "$URL" -o "$CACHE/cd.zip"; unzip -qo "$CACHE/cd.zip" -d "$CACHE"
  mv "$(find "$CACHE" -name chromedriver -type f | head -1)" "$CACHE/chromedriver"; chmod +x "$CACHE/chromedriver"
fi
RUNNER=$(ls -d ~/Library/Caches/.wasm-pack/wasm-bindgen-cargo-install-*/wasm-bindgen-test-runner 2>/dev/null | tail -1)
[ -n "$RUNNER" ] || { echo "run 'wasm-pack test --headless --chrome' once to install wasm-bindgen-test-runner"; exit 1; }

PARAMS_DIR=${PARAMS_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/yew-web/sapling-params}
mkdir -p "$PARAMS_DIR"
for f in sapling-spend.params sapling-output.params; do
  [ -s "$PARAMS_DIR/$f" ] || curl -L "https://download.z.cash/downloads/$f" -o "$PARAMS_DIR/$f"
done
PORT=${PARAMS_PORT:-8765}
python3 - "$PARAMS_DIR" "$PORT" <<'PY' &
import sys, http.server, functools
class H(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*"); super().end_headers()
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[2])), functools.partial(H, directory=sys.argv[1])).serve_forever()
PY
SERVER=$!
trap 'kill $SERVER 2>/dev/null' EXIT

export CC_wasm32_unknown_unknown="$LLVM/clang" AR_wasm32_unknown_unknown="$LLVM/llvm-ar"
export CHROMEDRIVER="$CACHE/chromedriver" CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER="$RUNNER" WASM_BINDGEN_TEST_ONLY_WEB=1
export SPIKE_PARAMS_URL="http://127.0.0.1:$PORT/"
# A proof takes seconds; the runner's default per-test timeout is 20 s.
export WASM_BINDGEN_TEST_TIMEOUT=${WASM_BINDGEN_TEST_TIMEOUT:-600}
cargo test --target wasm32-unknown-unknown --test web "$@" -- --nocapture
cargo test --release --target wasm32-unknown-unknown --test web "$@" -- --nocapture
