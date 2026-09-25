#!/usr/bin/env bash
# Regenerates the flutter_rust_bridge bindings (flutter_rust_bridge.yaml): core/src/api.rs ->
# core/src/frb_generated.rs + app/lib/src/rust/*. Idempotent (codegen overwrites its outputs;
# both are committed). The codegen version must equal the flutter_rust_bridge crate version in
# core/Cargo.toml and the Dart package in app/pubspec.yaml (2.13.0, plan §7 W0a).
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
want="$(sed -n 's/^flutter_rust_bridge = "=\(.*\)"/\1/p' core/Cargo.toml)"
have="$(flutter_rust_bridge_codegen --version | awk '{print $2}')"
[[ "$want" == "$have" ]] || { echo "gen-bridge: codegen $have != crate $want (cargo install flutter_rust_bridge_codegen --version $want)" >&2; exit 1; }
[[ -f flutter_rust_bridge.yaml ]] || { echo "gen-bridge: flutter_rust_bridge.yaml missing" >&2; exit 1; }
# The Dart package version must match too (frb checks pubspec.lock); pub get needs the network.
(cd app && flutter pub get >/dev/null)
flutter_rust_bridge_codegen generate --config-file flutter_rust_bridge.yaml
echo "gen-bridge: ok"
