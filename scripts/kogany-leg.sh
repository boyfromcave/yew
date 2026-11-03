#!/usr/bin/env bash
# The kogany leg (workspace kogany plan W9-c; report-only): YEW's W1 devnet acceptance
# (core/tests/devnet.rs w1_yec_round_trip_and_restore: fund, sync, send, restore from the seed)
# through lightwalletd-dd in front of a regtest kogany node, the third node line.
#
#   scripts/kogany-leg.sh
#
# scripts/kogany-rig.py starts kogany (zakurad --features ycash) and a ycash6 sidecar `connect=`
# kogany that holds the wallet and mines past the Vault activation (the YED module live on both
# with one attestor set id), and lightwalletd-dd on each. The test runs unchanged: the rig stands
# in for the devnet tool (YEW_DEVNET_TOOL; node 0 is the sidecar's wallet, every other node index
# reads kogany, `mine` mines on the sidecar and waits for kogany), and YEW talks only to the
# lightwalletd-dd that kogany serves.
#
# Environment: ZAKURAD (kogany's zakurad: kogany's zakurad-bin artifact), YCASHD (ycash6's ycashd:
# ycash6's node-bin), LWD_BIN (lightwalletd-dd, built at proto/PIN), KOGANY_RIG_DIR (default: a
# temporary directory), YEW_DEVNET_PYTHON (default: python3), KOGANY_LEG_SERVER (kogany, default;
# sidecar runs the same test through the sidecar's lightwalletd-dd, the reference column).
# Exit: cargo test's status.
set -euo pipefail
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or https://www.opensource.org/licenses/mit-license.php .
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${ZAKURAD:?ZAKURAD: kogany zakurad (--features ycash)}"
: "${YCASHD:?YCASHD: ycash6 ycashd}"
: "${LWD_BIN:?LWD_BIN: lightwalletd-dd}"
py="${YEW_DEVNET_PYTHON:-python3}"
dir="${KOGANY_RIG_DIR:-$(mktemp -d)/rig}"
rig() { "$py" "$here/scripts/kogany-rig.py" --dir "$dir" "$@"; }
trap 'rig down || true' EXIT
rig up --zakurad "$ZAKURAD" --ycashd "$YCASHD" --lightwalletd "$LWD_BIN" --lightwalletd-sidecar
case "${KOGANY_LEG_SERVER:-kogany}" in
  kogany) key=lightwalletd ;; sidecar) key=lightwalletd_sidecar ;;
  *) echo "kogany-leg: KOGANY_LEG_SERVER is kogany or sidecar" >&2; exit 2 ;;
esac
server=$("$py" -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$dir/rig.json" "$key")
echo "YEW W1 through lightwalletd-dd at $server ($key)"
cd "$here"
YEW_DEVNET=1 YEW_DEVNET_TOOL="$here/scripts/kogany-rig.py" YEW_DEVNET_PYTHON="$py" YELLOWBACK_DEVNET_DIR="$dir" \
  YEW_DEVNET_SERVER="$server" cargo test --locked -p yew-core --test devnet -- --ignored --nocapture w1_
