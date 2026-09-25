#!/usr/bin/env bash
# Plan §7 W3 acceptance: "no crypto or networking import under app/lib". The app is a view over
# the Rust core; the only networking is the core's gRPC, the only crypto is the core's, the only
# persistence of keys is flutter_secure_storage (D-W-6) and the core's SQLite. Fails when any
# file under app/lib imports a gRPC, crypto, SQLite or HTTP package, or dart:io sockets.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$here/app"
bad=0
banned_pkgs='package:(grpc|protobuf|crypto|pointycastle|cryptography|encrypt|bip39|bip32|web3dart|sqflite|sqlite3|drift|hive|isar|http|dio|web_socket_channel|socket_io_client|shelf)'
if grep -rnE "^import '($banned_pkgs)" lib; then bad=1; fi
if grep -rnE "^import 'dart:isolate'" lib; then bad=1; fi
# dart:io itself is allowed (Platform, Directory); sockets and HTTP clients are not.
if grep -rnE '\b(Socket|RawSocket|ServerSocket|SecureSocket|HttpClient|HttpServer|WebSocket)\b' lib --include='*.dart' | grep -v '^lib/src/rust/'; then bad=1; fi
# The bridge is called from one file only.
if grep -rln "src/rust/api.dart' as rust\|src/rust/frb_generated.dart" lib | grep -v '^lib/api/rust_wallet_api.dart$' | grep -v '^lib/src/rust/'; then
  echo "check-app-imports: the bridge functions are called from lib/api/rust_wallet_api.dart only" >&2
  bad=1
fi
if [[ $bad -ne 0 ]]; then
  echo "check-app-imports: forbidden import under app/lib (plan §7 W3: no crypto, networking or key persistence outside the core and the keystore)" >&2
  exit 1
fi
echo "check-app-imports: ok"
