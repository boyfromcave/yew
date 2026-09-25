#!/usr/bin/env bash
# Regenerates the flutter_rust_bridge bindings between core/src/api.rs and app/lib/ (Phase W3).
# Idempotent (codegen overwrites its own outputs). The codegen version must equal the
# flutter_rust_bridge crate version in core/Cargo.toml (plan §7 W0a); both are "to pin" in W0a.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$here"
need() { command -v "$1" >/dev/null 2>&1 || { echo "gen-bridge: missing '$1'. $2" >&2; exit 1; }; }
need flutter "Install Flutter: brew install --cask flutter (version in README.md)"
need cargo "Install Rust: https://rustup.rs"
command -v flutter_rust_bridge_codegen >/dev/null 2>&1 || {
  echo "gen-bridge: missing flutter_rust_bridge_codegen. Install the pinned version:" >&2
  echo "  cargo install flutter_rust_bridge_codegen --version <the flutter_rust_bridge version in core/Cargo.toml>" >&2
  exit 1; }
[[ -f flutter_rust_bridge.yaml ]] || { echo "gen-bridge: flutter_rust_bridge.yaml not present yet (added in Phase W3)" >&2; exit 1; }
flutter_rust_bridge_codegen generate
echo "gen-bridge: ok"
