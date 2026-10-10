#!/usr/bin/env bash
# Runs web/core-wasm's end-to-end browser test (plan §5, W0.5) in headless Chrome, in a
# dedicated worker, debug and release: a fresh private wallet on OPFS syncs from its birthday to
# the tip of the lightwalletd behind $YEW_WEB_LWD (default http://localhost:9067, the kind
# cluster's plain gRPC-web listener; it must allow this origin: ycash-infra values-kind.yaml
# `gateway.plaintextGrpcCors`), then is paid from the node's wallet by the funding helper
# (web/scripts/fund-helper.py; its node CLI is $YEW_FUND_CLI, default kubectl into the kind
# cluster) and syncs until the note lands; W1a's test then pays the transparent address (the
# helper's /fund_t), sends t→t, shields, sends z→z (the proving parameters served by the helper
# from $PARAMS_DIR, default ~/.cache/yew-web/sapling-params — fetched once by
# test-spike-prover.sh), and exercises the YED / vault previews. FUND=0 skips the helper (and
# with it everything that needs money). TESTS (default "web harden") names the test targets:
# tests/harden.rs is W3's (restore from seed with a birthday, busy under concurrency, a reorg —
# the reorg test invalidates a block on the shared node through the helper's /reorg, ONCE per
# profile, so run it alone with TESTS=harden when others use the cluster, or set
# YEW_WEB_NO_REORG=1 to skip it). PROFILES (default "debug release") picks the cargo profiles.
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
  if lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "port $PORT is taken (a fund-helper.py from an earlier run? pkill -f fund-helper.py, or set FUND_PORT)"; exit 1
  fi
  python3 "$scripts/fund-helper.py" "$PORT" &
  HELPER=$!
  trap 'kill $HELPER 2>/dev/null' EXIT
  export YEW_WEB_FUND_URL="http://127.0.0.1:$PORT"
  export YEW_WEB_PARAMS_URL="http://127.0.0.1:$PORT/params/"
  PARAMS_DIR=${PARAMS_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/yew-web/sapling-params}
  for f in sapling-spend.params sapling-output.params; do
    [ -s "$PARAMS_DIR/$f" ] || { echo "$PARAMS_DIR/$f missing: run web/scripts/test-spike-prover.sh once"; exit 1; }
  done
fi

export CC_wasm32_unknown_unknown="$LLVM/clang" AR_wasm32_unknown_unknown="$LLVM/llvm-ar"
export CHROMEDRIVER="$CACHE/chromedriver" CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER="$RUNNER" WASM_BINDGEN_TEST_ONLY_WEB=1
# Syncing, funding and waiting for blocks take minutes; the runner's default per-test timeout is 20 s.
export WASM_BINDGEN_TEST_TIMEOUT=${WASM_BINDGEN_TEST_TIMEOUT:-900}
for profile in ${PROFILES:-debug release}; do
  flag=; [ "$profile" = release ] && flag=--release
  for t in ${TESTS:-web harden}; do
    cargo test $flag --target wasm32-unknown-unknown --test "$t" "$@" -- --nocapture
  done
done
