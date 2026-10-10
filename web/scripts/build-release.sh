#!/usr/bin/env bash
# The reproducible release build of yew/web (plan §3, W3): the wasm module (wasm-pack, release,
# --no-opt: scripts/build-core-wasm.sh says why) and the Vite bundle are each built TWICE into
# clean temporary directories and every file compared by SHA-256; a difference fails the build.
# The second copies become web/src/wasm and web/dist, and dist/BUNDLE-SHA256SUMS lists the
# SHA-256 of every file in dist/ (sorted, relative paths; the file a release publishes and
# scripts/verify-bundle.sh checks against a served origin). Inputs: rust-toolchain.toml,
# core-wasm/Cargo.lock, package-lock.json (`npm ci`), the sources. Tool versions are printed so a
# second machine can match them; wasm-pack 0.15 is the one this was proved with.
#   WASM=0  reuse src/wasm as it is (the bundle alone is built twice)
#   CLEAN=0 let the second wasm build reuse the cargo cache (fast; the default compiles afresh)
set -euo pipefail
cd "$(dirname "$0")/.."
WEB=$PWD
TMP=$(mktemp -d "${TMPDIR:-/tmp}/yew-web-release.XXXXXX")
trap 'rm -rf "$TMP"' EXIT

sums() { (cd "$1" && find . -type f ! -name BUNDLE-SHA256SUMS | LC_ALL=C sort | xargs shasum -a 256 | sed 's#  \./#  #'); }
same() {  # same <dir1> <dir2> <what>
  if ! diff <(sums "$1") <(sums "$2") >/dev/null; then
    echo "build-release: $3 is NOT reproducible:" >&2
    diff <(sums "$1") <(sums "$2") >&2 || true
    exit 1
  fi
  echo "build-release: $3 identical across two builds ($(sums "$1" | wc -l | tr -d ' ') files)"
}

echo "build-release: node $(node --version), npm $(npm --version), rustc $(rustc --version | cut -d' ' -f2), wasm-pack $(wasm-pack --version | cut -d' ' -f2)"
[ -d node_modules ] || npm ci

if [ "${WASM:-1}" = 1 ]; then
  if [ -z "${CC_wasm32_unknown_unknown:-}" ] && [ -x /opt/homebrew/opt/llvm/bin/clang ]; then
    export CC_wasm32_unknown_unknown=/opt/homebrew/opt/llvm/bin/clang AR_wasm32_unknown_unknown=/opt/homebrew/opt/llvm/bin/llvm-ar
  fi
  # Paths are the one thing rustc embeds that differs by machine: panic locations and the
  # prost-generated file's `OUT_DIR` path (two strings) name the target directory, and ~500
  # source paths name the checkout and ~/.cargo. Remapped to fixed names, so the module is the
  # same from any checkout location, cargo home or target directory. This target-specific
  # variable REPLACES .cargo/config.toml's `target.wasm32-unknown-unknown.rustflags`, so the
  # getrandom cfg from there is repeated here (keep the two in step).
  REPO=$(cd .. && pwd); SIB=$(cd ../.. && pwd)
  # The target directory cargo will use (CARGO_TARGET_DIR, or a config.toml `build.target-dir`).
  TARGET1=$(cd core-wasm && cargo metadata --format-version 1 --no-deps 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')
  export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS="--cfg getrandom_backend=\"wasm_js\" --remap-path-prefix=$REPO=/src/yew --remap-path-prefix=$SIB/librustzcash6-web=/src/librustzcash6-web --remap-path-prefix=$SIB/x402-web=/src/x402-web --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo --remap-path-prefix=$(rustc --print sysroot)=/rustc --remap-path-prefix=$TARGET1=/target"
  # The second build compiles from scratch in its own target directory (a cached artifact would
  # prove nothing); CLEAN=0 skips that and reuses the cache (fast, a weaker check).
  for i in 1 2; do
    if [ "$i" = 2 ] && [ "${CLEAN:-1}" = 1 ]; then
      export CARGO_TARGET_DIR="$TMP/target"
      export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS="${CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS% --remap-path-prefix=*} --remap-path-prefix=$CARGO_TARGET_DIR=/target"
    fi
    wasm-pack build core-wasm --target web --release --no-opt --out-dir "$TMP/wasm$i" --out-name yew_web_core >/dev/null 2>&1 \
      || wasm-pack build core-wasm --target web --release --no-opt --out-dir "$TMP/wasm$i" --out-name yew_web_core
    rm -f "$TMP/wasm$i/.gitignore" "$TMP/wasm$i/package.json" "$TMP/wasm$i/README.md"
  done
  unset CARGO_TARGET_DIR
  same "$TMP/wasm1" "$TMP/wasm2" "the wasm module"
  rm -rf src/wasm && mkdir -p src/wasm && cp "$TMP/wasm2"/* src/wasm/
fi
[ -f src/wasm/yew_web_core.js ] || { echo "build-release: src/wasm missing (WASM=0 needs a previous build)"; exit 1; }

npx tsc --noEmit
for i in 1 2; do
  npx vite build --outDir "$TMP/dist$i" --emptyOutDir >/dev/null
  node scripts/sri.mjs "$TMP/dist$i" >/dev/null
done
same "$TMP/dist1" "$TMP/dist2" "the bundle"
rm -rf dist && mkdir dist && cp -R "$TMP/dist2"/. dist/
sums dist > dist/BUNDLE-SHA256SUMS
echo "build-release: dist/BUNDLE-SHA256SUMS:"
cat dist/BUNDLE-SHA256SUMS
echo "build-release: bundle hash (sha256 of BUNDLE-SHA256SUMS): $(shasum -a 256 dist/BUNDLE-SHA256SUMS | cut -d' ' -f1)"
