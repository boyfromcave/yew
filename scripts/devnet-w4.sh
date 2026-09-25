#!/usr/bin/env bash
# Phase W4 devnet acceptance (plan §6.3, §7 W4): the ARMED devnet of W2 (~/yb-devnet-w0c,
# portseed 9), lightwalletd-dd `--yellowback` on 9267. Same conventions as devnet-w2.sh: every
# block is mined on a pool node after re-quoting (the armed devnet has no heartbeat); the test
# shocks the price to −80 % at its end (`price --shock=-80%`) to make node 0's vault claimable,
# so the devnet is left with a $10 price — `yellowback-devnet price 50` restores it.
#
#   scripts/devnet-w4.sh up | lwd | test | status | down [--wipe]
#
# Works from a git worktree too: the workspace is found by walking up to repos.yaml.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ws="$here"
while [[ ! -f "$ws/repos.yaml" && "$ws" != "/" ]]; do ws="$(dirname "$ws")"; done
[[ -f "$ws/repos.yaml" ]] || { echo "devnet-w4: no workspace (repos.yaml) above $here" >&2; exit 2; }
export YELLOWBACK_DEVNET_DIR="${YELLOWBACK_DEVNET_DIR:-$HOME/yb-devnet-w0c}"
export YELLOWBACK_DEVNET_PORTSEED="${YELLOWBACK_DEVNET_PORTSEED:-9}"
lwd_port="${YEW_LWD_PORT:-9267}"
py="${YEW_DEVNET_PYTHON:-$ws/.venv/bin/python}"
tool="${YEW_DEVNET_TOOL:-$ws/ycash-dd/contrib/yellowback/devnet/yellowback-devnet}"
[[ -x "$py" ]] || { echo "devnet-w4: no venv python at $py (workspace: make bootstrap)" >&2; exit 2; }
[[ -f "$tool" ]] || { echo "devnet-w4: no devnet tool at $tool" >&2; exit 2; }
dn() { (cd "$ws/ycash-dd" && "$py" "$tool" "$@"); }

case "${1:-}" in
  up)
    dn up --force
    dn lightwalletd start --port "$lwd_port" --extra=--yellowback
    ;;
  lwd)
    dn lightwalletd stop || true
    dn lightwalletd start --port "$lwd_port" --extra=--yellowback
    ;;
  test)
    cd "$here"
    YEW_DEVNET=1 YEW_DEVNET_SERVER="127.0.0.1:$lwd_port" YEW_DEVNET_PYTHON="$py" YEW_DEVNET_TOOL="$tool" \
      cargo test -p yew-core --test devnet -- --ignored --nocapture w4_
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
    sed -n '2,10p' "$0"
    exit 2
    ;;
esac
