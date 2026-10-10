#!/usr/bin/env bash
# Builds the shell and walks it in headless Chrome against MockCore (?mock=1): onboarding →
# home → send preview → confirm → unlock after a reload. Needs Google Chrome and a ChromeDriver
# of the same major version (cached as test-spike-sqlite.sh does). The wasm module must be
# built (scripts/build-core-wasm.sh) for `vite build` to resolve the worker; the mock never
# calls it.
set -euo pipefail
cd "$(dirname "$0")/.."
CHROME_VER=$("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
CACHE=${XDG_CACHE_HOME:-$HOME/.cache}/yew-web/chromedriver-$CHROME_VER
[ -x "$CACHE/chromedriver" ] || { echo "no chromedriver for Chrome $CHROME_VER in $CACHE (run scripts/test-spike-sqlite.sh once)"; exit 1; }
npm run build >/dev/null
PORT=${PORT:-4173}
npx vite preview --port "$PORT" --strictPort >/dev/null 2>&1 & PREVIEW=$!
"$CACHE/chromedriver" --port=9515 >/dev/null 2>&1 & DRIVER=$!
trap 'kill $PREVIEW $DRIVER 2>/dev/null' EXIT
for _ in $(seq 50); do curl -sf "http://localhost:$PORT/" >/dev/null && curl -sf http://localhost:9515/status >/dev/null && break; sleep 0.2; done
python3 -I scripts/smoke.py http://localhost:9515 "http://localhost:$PORT/?mock=1"
