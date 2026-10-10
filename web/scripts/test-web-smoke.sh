#!/usr/bin/env bash
# Builds the shell and walks it in headless Chrome. Default: against MockCore (?mock=1):
# onboarding → home → send preview → confirm → unlock after a reload (W1b).
#
#   scripts/test-web-smoke.sh --kind [page-url]
#
# W2: the same bundle on the REAL core against the kind cluster (ycash-infra, `make kind-up`):
# the page from `vite preview` (http://localhost:4173) with the gRPC-web server typed as
# $YEW_WEB_LWD (default http://localhost:9067, the plain listener, CORS on), or, with a page URL,
# the bundle the gateway serves (https://localhost/, K4: the API on the same origin, so the server
# field keeps its default and the self-signed certificate is accepted). The funding helper
# (fund-helper.py, kubectl into the cluster by default: $YEW_FUND_CLI) pays the wallet and serves
# the proving files from $PARAMS_DIR (fetched once by test-spike-prover.sh). The walk is in
# smoke.py. Needs Google Chrome and a ChromeDriver of the same major version (cached as
# test-spike-sqlite.sh does). The wasm module must be built (scripts/build-core-wasm.sh).
set -euo pipefail
cd "$(dirname "$0")/.."
KIND=0; PAGE=""
for a in "$@"; do case "$a" in --kind) KIND=1 ;; *) PAGE=$a ;; esac; done
CHROME_VER=$("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
CACHE=${XDG_CACHE_HOME:-$HOME/.cache}/yew-web/chromedriver-$CHROME_VER
[ -x "$CACHE/chromedriver" ] || { echo "no chromedriver for Chrome $CHROME_VER in $CACHE (run scripts/test-spike-sqlite.sh once)"; exit 1; }
[ -n "$PAGE" ] || npm run build >/dev/null
PORT=${PORT:-4173}
PIDS=()
trap 'kill "${PIDS[@]}" 2>/dev/null' EXIT
if [ -z "$PAGE" ]; then
  npx vite preview --port "$PORT" --strictPort >/dev/null 2>&1 & PIDS+=($!)
  PAGE="http://localhost:$PORT/"
  [ "$KIND" = 1 ] || PAGE="$PAGE?mock=1"
fi
"$CACHE/chromedriver" --port=9515 >/dev/null 2>&1 & PIDS+=($!)
ARGS=()
if [ "$KIND" = 1 ]; then
  FUND_PORT=${FUND_PORT:-8766}
  PARAMS_DIR=${PARAMS_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/yew-web/sapling-params}
  for f in sapling-spend.params sapling-output.params; do
    [ -s "$PARAMS_DIR/$f" ] || { echo "$PARAMS_DIR/$f missing: run web/scripts/test-spike-prover.sh once"; exit 1; }
  done
  PARAMS_DIR=$PARAMS_DIR python3 scripts/fund-helper.py "$FUND_PORT" & PIDS+=($!)
  HELPER="http://127.0.0.1:$FUND_PORT"
  PAGE="$PAGE?params=$HELPER/params/"
  ARGS=(--kind "$HELPER")
  case "$PAGE" in https://*) ARGS+=(--insecure) ;; *) ARGS+=(--server "${YEW_WEB_LWD:-http://localhost:9067}") ;; esac
fi
for _ in $(seq 50); do curl -skf "$PAGE" >/dev/null && curl -sf http://localhost:9515/status >/dev/null && break; sleep 0.2; done
python3 -I scripts/smoke.py http://localhost:9515 "$PAGE" ${ARGS[@]+"${ARGS[@]}"}
