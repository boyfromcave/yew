#!/usr/bin/env bash
# wasm-pack build of web/core-wasm into web/src/wasm (what worker.ts imports).
set -euo pipefail
cd "$(dirname "$0")/.."
command -v wasm-pack >/dev/null || { echo "install wasm-pack: cargo install wasm-pack (and: rustup target add wasm32-unknown-unknown)"; exit 1; }
# C code in the graph (secp256k1-sys, …) needs a clang with the wasm32 backend: Homebrew LLVM's,
# not Apple's (plan W0.1 finding 5).
LLVM=${LLVM:-/opt/homebrew/opt/llvm/bin}
[ -x "$LLVM/clang" ] || { echo "brew install llvm (clang with the wasm32 backend), or LLVM=<bin dir>"; exit 1; }
export CC_wasm32_unknown_unknown="$LLVM/clang" AR_wasm32_unknown_unknown="$LLVM/llvm-ar"
wasm-pack build core-wasm --target web --release --out-dir ../src/wasm --out-name yew_web_core "$@"
rm -f src/wasm/.gitignore src/wasm/package.json
echo "built src/wasm/yew_web_core.js"
