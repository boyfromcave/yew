#!/usr/bin/env bash
# The shell cannot construct bytes: no crypto, SQLite, websocket or gRPC packages under web/src
# (the same rule app/lib has in scripts/check-app-imports.sh). The generated wasm glue is exempt.
set -euo pipefail
cd "$(dirname "$0")/.."
bad=$(grep -rEn "from ['\"](@noble|elliptic|secp256k1|bip39|bip32|tweetnacl|crypto-js|sql\.js|@sqlite\.org|better-sqlite3|ws|grpc|@grpc|@improbable-eng|@connectrpc|nice-grpc)" src --include='*.ts' --exclude-dir=wasm || true)
if [ -n "$bad" ]; then echo "forbidden imports under web/src:"; echo "$bad"; exit 1; fi
echo "web/src imports ok"
