#!/usr/bin/env bash
# In-term claims devnet acceptance (the workspace's docs/plans/yellowback-in-term-claims-plan.md,
# rpcversion 6): an ARMED devnet of the in-term node (ycash-dd branch upgrade/vault-in-term) and
# lightwalletd-dd of the same branch serving --yellowback. Runs core/tests/devnet.rs it_* (a YEW
# mint and its early redeem in term, the node's own quote for it, an in-term claim of node 0's
# vault after a -80 % shock, the owner's in-term redeem of a claimable vault) against the running
# devnet; `test w4` runs the W4 suites (mint, resume, lapse, redeem, claim, cancel), each on a
# devnet of its own that it brings up (`down --wipe` + `up`): it replaces the running devnet.
#
#   scripts/devnet-it.sh up | lwd | test [it|w4] | status | down [--wipe]
#
# The in-term line is not a main tree: point the script at it. YEW_DEVNET_TOOL (default
# <workspace>/ycash-dd/contrib/yellowback/devnet/yellowback-devnet; use the in-term checkout's),
# BITCOIND (its ycashd), YELLOWBACK_ATTEST_BIN (its yellowback-attest), YELLOWBACK_LWD_BIN (the
# in-term lightwalletd), optionally CHAINVIZ_BIN. Defaults: ~/yb-devnet-it, portseed 741,
# lightwalletd on 9741 (YELLOWBACK_DEVNET_DIR, YELLOWBACK_DEVNET_PORTSEED, YEW_LWD_PORT).
# Works from a git worktree too: the workspace is found by walking up to repos.yaml.
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or https://www.opensource.org/licenses/mit-license.php .
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ws="$here"
while [[ ! -f "$ws/repos.yaml" && "$ws" != "/" ]]; do ws="$(dirname "$ws")"; done
[[ -f "$ws/repos.yaml" ]] || { echo "devnet-it: no workspace (repos.yaml) above $here" >&2; exit 2; }
export YELLOWBACK_DEVNET_DIR="${YELLOWBACK_DEVNET_DIR:-$HOME/yb-devnet-it}"
export YELLOWBACK_DEVNET_PORTSEED="${YELLOWBACK_DEVNET_PORTSEED:-741}"
lwd_port="${YEW_LWD_PORT:-9741}"
# A fresh devnet's pools hold few mature coinbases; node 0 (funded by `up`) funds the test wallets.
export YEW_DEVNET_FUND_NODE="${YEW_DEVNET_FUND_NODE:-0}"
py="${YEW_DEVNET_PYTHON:-$ws/.venv/bin/python}"
tool="${YEW_DEVNET_TOOL:-$ws/ycash-dd/contrib/yellowback/devnet/yellowback-devnet}"
[[ -x "$py" ]] || { echo "devnet-it: no venv python at $py (workspace: make bootstrap)" >&2; exit 2; }
[[ -f "$tool" ]] || { echo "devnet-it: no devnet tool at $tool" >&2; exit 2; }
node_repo="$(cd "$(dirname "$tool")/../../.." && pwd)"
dn() { (cd "$node_repo" && "$py" "$tool" "$@"); }

case "${1:-}" in
  up)
    dn up --force --portseed "$YELLOWBACK_DEVNET_PORTSEED"
    dn lightwalletd start --port "$lwd_port" --extra=--yellowback
    ;;
  lwd)
    dn lightwalletd stop || true
    dn lightwalletd start --port "$lwd_port" --extra=--yellowback
    ;;
  test)
    cd "$here"
    run_filter() {
      YEW_DEVNET=1 YEW_DEVNET_SERVER="127.0.0.1:$lwd_port" YEW_DEVNET_PYTHON="$py" YEW_DEVNET_TOOL="$tool" \
        cargo test -p yew-core --test devnet -- --ignored --nocapture --test-threads=1 "$1"
    }
    fresh() {
      dn lightwalletd stop || true
      dn down --wipe || true
      dn up --force --portseed "$YELLOWBACK_DEVNET_PORTSEED"
      dn lightwalletd start --port "$lwd_port" --extra=--yellowback
    }
    case "${2:-it}" in
      it) run_filter it_ ;;
      w4)
        # Both W4 suites end in a -80 % shock that is never reversed (the main suite's liquidator
        # step, the cancel case's claim), which leaves the global ratio below HALT-2's 250 %: only
        # class C mints after it (IT-5), and the next suite's class-A mint is refused
        # mintpol-global-ratio. So each suite gets a fresh devnet, deterministically.
        fresh
        # The main suite claims a vault of node 0: give node 0 one (class A, 96 blocks) and mine
        # on the pools (blocks node 0 mines carry no quote tag) until it is ACTIVE.
        dn cli -- yed_mint 20000 96 "" "" false >/dev/null
        for i in $(seq 1 30); do
          dn mine 1 $((2 + i % 3)) >/dev/null
          sleep 2
          if dn cli -- yed_listvaults ACTIVE | grep -q '"txid"'; then break; fi
          [[ $i -lt 30 ]] || { echo "devnet-it: node 0's vault never confirmed" >&2; exit 1; }
        done
        run_filter w4_mint
        fresh
        run_filter w4_claim
        ;;
      *) echo "devnet-it: test [it|w4]" >&2; exit 2 ;;
    esac
    ;;
  status)
    dn status || true
    dn lightwalletd status || true
    ;;
  down)
    dn lightwalletd stop || true
    dn down "${2:-}"
    ;;
  *)
    sed -n '2,16p' "$0"
    exit 2
    ;;
esac
