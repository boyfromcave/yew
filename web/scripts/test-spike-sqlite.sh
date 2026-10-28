#!/usr/bin/env bash
# Runs web/spike-sqlite's browser tests (plan §2, I-4) in headless Chrome.
# Needs: rustup target wasm32-unknown-unknown (for the pinned toolchain), Homebrew LLVM (Apple's
# clang has no wasm backend; secp256k1-sys compiles C), Google Chrome, and a ChromeDriver of the
# SAME major version as Chrome (wasm-pack's own download may be newer than the installed Chrome,
# and it ignores $CHROMEDRIVER, so this script drives cargo test directly).
set -euo pipefail
cd "$(dirname "$0")/../spike-sqlite"
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
export CC_wasm32_unknown_unknown="$LLVM/clang" AR_wasm32_unknown_unknown="$LLVM/llvm-ar"
export CHROMEDRIVER="$CACHE/chromedriver" CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER="$RUNNER" WASM_BINDGEN_TEST_ONLY_WEB=1
cargo test --target wasm32-unknown-unknown --test web "$@"
cargo test --release --target wasm32-unknown-unknown --test web "$@"
