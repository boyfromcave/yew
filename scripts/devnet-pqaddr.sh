#!/usr/bin/env bash
# Post-quantum addresses end to end (quantum plan D-Q-20/D-Q-21; lightwalletd-dd q/pqaddr serves
# TX_PQPKH in GetTaddressTxids / GetTaddressBalance / GetAddressUtxos under the plain sq…/tq…/rq…
# form): an ARMED devnet of the quantum node in the mainnet regime (Falcon from the vault
# activation, the devnet tool's default), lightwalletd-dd q/pqaddr serving --yellowback, and
# core/tests/devnet.rs q_pqaddr_sq_receive_send_and_move against it.
#
#   scripts/devnet-pqaddr.sh up | lwd | test | status | down [--wipe]
#
# Point it at the quantum line: YEW_DEVNET_TOOL (default <workspace>/wt/q-dd/contrib/yellowback/
# devnet/yellowback-devnet), BITCOIND (its ycashd), YELLOWBACK_ATTEST_BIN, YELLOWBACK_LWD_BIN (a
# lightwalletd built from lightwalletd-dd q/pqaddr or later). Defaults: ~/yb-devnet-pqaddr,
# portseed 3370, lightwalletd on 3389 (YELLOWBACK_DEVNET_DIR, YELLOWBACK_DEVNET_PORTSEED,
# YEW_LWD_PORT).
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or https://www.opensource.org/licenses/mit-license.php .
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ws="$here"
while [[ ! -f "$ws/repos.yaml" && "$ws" != "/" ]]; do ws="$(dirname "$ws")"; done
[[ -f "$ws/repos.yaml" ]] || { echo "devnet-pqaddr: no workspace (repos.yaml) above $here" >&2; exit 2; }
export YELLOWBACK_DEVNET_DIR="${YELLOWBACK_DEVNET_DIR:-$HOME/yb-devnet-pqaddr}"
export YELLOWBACK_DEVNET_PORTSEED="${YELLOWBACK_DEVNET_PORTSEED:-3370}"
lwd_port="${YEW_LWD_PORT:-3389}"
export YEW_DEVNET_FUND_NODE="${YEW_DEVNET_FUND_NODE:-0}"
py="${YEW_DEVNET_PYTHON:-$ws/.venv/bin/python}"
tool="${YEW_DEVNET_TOOL:-$ws/wt/q-dd/contrib/yellowback/devnet/yellowback-devnet}"
[[ -x "$py" ]] || { echo "devnet-pqaddr: no venv python at $py (workspace: make bootstrap)" >&2; exit 2; }
[[ -f "$tool" ]] || { echo "devnet-pqaddr: no devnet tool at $tool" >&2; exit 2; }
node_repo="$(cd "$(dirname "$tool")/../../.." && pwd)"
dn() { (cd "$node_repo" && "$py" "$tool" "$@"); }

case "${1:-}" in
  up)
    dn up --force --no-viz --portseed "$YELLOWBACK_DEVNET_PORTSEED"
    dn lightwalletd start --port "$lwd_port" --extra=--yellowback
    ;;
  lwd)
    dn lightwalletd stop || true
    dn lightwalletd start --port "$lwd_port" --extra=--yellowback
    ;;
  test)
    cd "$here"
    YEW_DEVNET=1 YEW_DEVNET_SERVER="127.0.0.1:$lwd_port" YEW_DEVNET_PYTHON="$py" YEW_DEVNET_TOOL="$tool" \
      cargo test -p yew-core --test devnet -- --ignored --nocapture --test-threads=1 q_pqaddr_
    ;;
  status) dn status ;;
  down)
    dn lightwalletd stop || true
    shift; dn down "$@"
    ;;
  *) echo "usage: scripts/devnet-pqaddr.sh up | lwd | test | status | down [--wipe]" >&2; exit 2 ;;
esac
