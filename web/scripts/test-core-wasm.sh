#!/usr/bin/env bash
# Runs web/core-wasm's end-to-end browser test (plan §5, W0.5) in headless Chrome, in a
# dedicated worker, debug and release: a fresh private wallet on OPFS syncs from its birthday to
# the tip of the lightwalletd behind $YEW_WEB_LWD (default http://localhost:9067, the kind
# cluster's plain gRPC-web listener; it must allow this origin: ycash-infra values-kind.yaml
# `gateway.plaintextGrpcCors`), then is paid from the node's wallet by the funding helper
# (web/scripts/fund-helper.py; its node CLI is $YEW_FUND_CLI, default kubectl into the kind
# cluster) and syncs until the note lands. FUND=0 skips the helper.
#
# Against a local devnet instead (the kind cluster's regtest activates only the vault upgrade,
# so it has no Sapling: GetTreeState fails there — see the plan's W0.5 findings):
#   export YELLOWBACK_DEVNET_DIR=$ws/wt/scratch/w05-web YELLOWBACK_DEVNET_PORTSEED=71 ZCASHD=$ws/ycash6/src/ycashd
#   (cd $ws/ycash6 && ../.venv/bin/python contrib/yellowback/devnet/yellowback-devnet up --force --no-attest --no-walk --no-sim --no-viz --heartbeat-rate 5 \
#      && ../.venv/bin/python contrib/yellowback/devnet/yellowback-devnet lightwalletd start --port 9138 --bin <lightwalletd-dd> --extra=--yellowback)
#   ~/go/bin/grpcwebproxy --backend_addr=127.0.0.1:9138 --backend_tls=false --run_tls_server=false \
#      --allow_all_origins --server_http_debug_port=9170 &        # go install github.com/improbable-eng/grpc-web/go/grpcwebproxy@latest
#   YEW_WEB_LWD=http://127.0.0.1:9170 \
#   YEW_FUND_CLI="$ws/.venv/bin/python $ws/ycash6/contrib/yellowback/devnet/yellowback-devnet cli --node 0 --" web/scripts/test-core-wasm.sh
# Same toolchain recipe as test-spike-sqlite.sh (Homebrew LLVM clang for wasm32 C, a ChromeDriver
# matched to the installed Chrome, wasm-pack's wasm-bindgen-test-runner).
set -euo pipefail
scripts="$(cd "$(dirname "$0")" && pwd)"
cd "$scripts/../core-wasm"
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

export YEW_WEB_LWD=${YEW_WEB_LWD:-http://localhost:9067}
if [ "${FUND:-1}" = 1 ]; then
  PORT=${FUND_PORT:-8766}
  python3 "$scripts/fund-helper.py" "$PORT" &
  HELPER=$!
  trap 'kill $HELPER 2>/dev/null' EXIT
  export YEW_WEB_FUND_URL="http://127.0.0.1:$PORT"
fi

export CC_wasm32_unknown_unknown="$LLVM/clang" AR_wasm32_unknown_unknown="$LLVM/llvm-ar"
export CHROMEDRIVER="$CACHE/chromedriver" CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER="$RUNNER" WASM_BINDGEN_TEST_ONLY_WEB=1
# Syncing, funding and waiting for blocks take minutes; the runner's default per-test timeout is 20 s.
export WASM_BINDGEN_TEST_TIMEOUT=${WASM_BINDGEN_TEST_TIMEOUT:-900}
cargo test --target wasm32-unknown-unknown --test web "$@" -- --nocapture
cargo test --release --target wasm32-unknown-unknown --test web "$@" -- --nocapture
