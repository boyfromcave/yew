#!/usr/bin/env bash
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or https://www.opensource.org/licenses/mit-license.php .
#
# The web wallet's real-stack run (regtest): ycash6 + lightwalletd-dd + an Envoy gRPC-web front
# (one container) + the built bundle under `vite preview` + headless Chrome through chromedriver.
#
#   run.sh up      the stack (nodes, YED live, lightwalletd), Envoy, vite preview, chromedriver
#   run.sh walk    the browser walk (web_real_walk.py; WALK_PHASES=addr,fund,sends,yed,persist,params)
#   run.sh down    stop everything this script started (by name / pid file)
#
# Environment (defaults in brackets):
#   W   the workspace                         [/Users/boy/projects/yellowback-workspace]
#   S   scratch/output directory              [$W/wt/scratch/web-real]
#   Y6  a built ycash6 tree                    [$W/wt/up6-b2-prefix]
#   LWD a lightwalletd-dd binary               [$S/bin/lightwalletd]
#   Y   this yew tree (web/ built: scripts/build-core-wasm.sh, npm ci, npm run build)
#   CHROMEDRIVER  a chromedriver of Chrome's major version (Chrome for Testing)
#   PORTSEED [5713] LWD_PORT [29767] WEB_PORT [29771] GRPCWEB_PORT [29769] WD_PORT [9615]
set -euo pipefail
W=${W:-/Users/boy/projects/yellowback-workspace}
S=${S:-$W/wt/scratch/web-real}
Y6=${Y6:-$W/wt/up6-b2-prefix}
LWD=${LWD:-$S/bin/lightwalletd}
Y=${Y:-$(cd "$(dirname "$0")/../../.." && pwd)}
HERE=$(cd "$(dirname "$0")" && pwd)
PORTSEED=${PORTSEED:-5713}; LWD_PORT=${LWD_PORT:-29767}; WEB_PORT=${WEB_PORT:-29771}
GRPCWEB_PORT=${GRPCWEB_PORT:-29769}; WD_PORT=${WD_PORT:-9615}
RUN=${RUN:-$S/run1}
PARAMS_DIR=${PARAMS_DIR:-$HOME/.cache/yew-web/sapling-params}   # sapling-{spend,output}.params (web/scripts/test-spike-prover.sh fetches them)
PY=${PY:-$W/.venv/bin/python}
ENVOY=web-real-envoy

case "${1:-}" in
up)
  mkdir -p "$RUN"
  YCASH6_QA=$Y6/qa/rpc-tests ZCASHD=$Y6/src/ycashd LWD_BIN=$LWD PYTHONUNBUFFERED=1 \
    nohup "$PY" "$HERE/web_real_stack.py" --tmpdir="$RUN/t" --portseed="$PORTSEED" --lwdport="$LWD_PORT" --nocleanup > "$RUN/log" 2>&1 &
  echo $! > "$RUN/stack.pid"
  sed -e 's/LWD_HOST/host.docker.internal/' -e "s/LWD_PORT/$LWD_PORT/" "$HERE/envoy.yaml" > "$RUN/envoy.yaml"
  docker rm -f "$ENVOY" >/dev/null 2>&1 || true
  docker run -d --name "$ENVOY" -p "127.0.0.1:$GRPCWEB_PORT:8080" -v "$RUN/envoy.yaml:/etc/envoy/envoy.yaml:ro" envoyproxy/envoy:v1.32.3 >/dev/null
  (cd "$Y/web" && nohup npx vite preview --port "$WEB_PORT" --strictPort > "$RUN/preview.log" 2>&1 & echo $! > "$RUN/preview.pid")
  nohup "$CHROMEDRIVER" --port="$WD_PORT" > "$RUN/chromedriver.log" 2>&1 & echo $! > "$RUN/chromedriver.pid"
  # the proving files from a loopback mirror with CORS, and a corrupt copy (the pins must refuse it)
  nohup "$PY" -I "$HERE/params_mirror.py" 29777 "$PARAMS_DIR" > "$RUN/mirror.log" 2>&1 & echo $! > "$RUN/mirror.pid"
  nohup "$PY" -I "$HERE/params_mirror.py" 29775 "$PARAMS_DIR" --corrupt > "$RUN/mirror-corrupt.log" 2>&1 & echo $! > "$RUN/mirror-corrupt.pid"
  echo "waiting for the stack (YED activation: several minutes)"
  until grep -q 'STACK READY' "$RUN/log"; do grep -q -E 'Traceback|Assertion|failed' "$RUN/log" && { tail -20 "$RUN/log"; exit 1; }; sleep 5; done
  echo "up: page http://localhost:$WEB_PORT/ server http://127.0.0.1:$GRPCWEB_PORT stack $(ls "$RUN"/t/*/stack.json)"
  ;;
walk)
  STACK_JSON=$(ls "$RUN"/t/*/stack.json) WEB_REAL_OUT=$RUN WD_URL=http://127.0.0.1:$WD_PORT WD_STATE=$RUN/wd-session \
    PAGE=http://localhost:$WEB_PORT/ SERVER=http://127.0.0.1:$GRPCWEB_PORT \
    "$PY" "$HERE/web_real_walk.py" "${WALK_PHASES:-addr,fund,sends,params,private,arm,yed,persist,restore}"
  ;;
down)
  touch "$RUN"/t/*/stop 2>/dev/null || true
  for p in preview chromedriver mirror mirror-corrupt; do [ -f "$RUN/$p.pid" ] && kill "$(cat "$RUN/$p.pid")" 2>/dev/null || true; done
  docker rm -f "$ENVOY" >/dev/null 2>&1 || true
  [ -f "$RUN/stack.pid" ] && while kill -0 "$(cat "$RUN/stack.pid")" 2>/dev/null; do sleep 1; done
  echo down
  ;;
*) sed -n 2,20p "$0"; exit 2 ;;
esac
