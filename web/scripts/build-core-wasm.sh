#!/usr/bin/env bash
# wasm-pack build of web/core-wasm into web/src/wasm (what worker.ts imports).
set -euo pipefail
cd "$(dirname "$0")/.."
command -v wasm-pack >/dev/null || { echo "install wasm-pack: cargo install wasm-pack (and: rustup target add wasm32-unknown-unknown)"; exit 1; }
wasm-pack build core-wasm --target web --release --out-dir ../src/wasm --out-name yew_web_core "$@"
rm -f src/wasm/.gitignore src/wasm/package.json
echo "built src/wasm/yew_web_core.js"
