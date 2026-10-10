#!/usr/bin/env bash
# wasm-pack build of web/core-wasm into web/src/wasm (what worker.ts imports).
#
# `--no-opt` (W3, the reproducible build): without it wasm-pack runs a binaryen `wasm-opt` it
# downloads from GitHub unverified (version_117 for wasm-pack 0.15), one more input the bundle
# hash would depend on. Measured on this crate: wasm-opt -Os takes the module from 11.47 MB to
# 8.84 MB raw, 4.69 MB to 4.29 MB gzipped — 9 % on the wire — for a tool outside Cargo.lock. The
# module is now a function of rustc (rust-toolchain.toml), Cargo.lock and wasm-bindgen only
# (web/scripts/build-release.sh proves two builds identical). To take the 9 % back, pin a
# binaryen by checksum in build-release.sh and run it there, never through wasm-pack's download.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v wasm-pack >/dev/null || { echo "install wasm-pack: cargo install wasm-pack (and: rustup target add wasm32-unknown-unknown)"; exit 1; }
wasm-pack build core-wasm --target web --release --no-opt --out-dir ../src/wasm --out-name yew_web_core "$@"
rm -f src/wasm/.gitignore src/wasm/package.json
echo "built src/wasm/yew_web_core.js"
