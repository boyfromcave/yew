#!/usr/bin/env bash
# Phase W2 devnet acceptance (plan §6.3, §7 W2): the ARMED devnet the W0c vectors were taken
# from (~/yb-devnet-w0c, portseed 9), with lightwalletd-dd `--yellowback` on a plain port. The
# armed devnet has no heartbeat: blocks are mined on the pool nodes (2-4), never on node 0,
# whose untagged blocks empty the price windows (README, "Rules recorded in W2").
#
#   scripts/devnet-w2.sh up        bring up ~/yb-devnet-w0c (armed) + lightwalletd --yellowback on 9267
#   scripts/devnet-w2.sh lwd       (re)start only the lightwalletd on a devnet that is already up
#   scripts/devnet-w2.sh test      run core/tests/devnet.rs w2_* against it (YEW_DEVNET=1)
#   scripts/devnet-w2.sh status    devnet + lightwalletd status
#   scripts/devnet-w2.sh down      stop it (--wipe to delete the directory)
#
# The devnet is left up after `test`; `down` is deliberate. Overrides: YELLOWBACK_DEVNET_DIR,
# YELLOWBACK_DEVNET_PORTSEED, YEW_LWD_PORT. (devnet-w1.sh is the W1 counterpart on ~/yb-devnet-w1.)
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ws="$(cd "$here/.." && pwd)"
export YELLOWBACK_DEVNET_DIR="${YELLOWBACK_DEVNET_DIR:-$HOME/yb-devnet-w0c}"
export YELLOWBACK_DEVNET_PORTSEED="${YELLOWBACK_DEVNET_PORTSEED:-9}"
lwd_port="${YEW_LWD_PORT:-9267}"
py="${YEW_DEVNET_PYTHON:-$ws/.venv/bin/python}"
tool="${YEW_DEVNET_TOOL:-$ws/ycash-dd/contrib/yellowback/devnet/yellowback-devnet}"
[[ -x "$py" ]] || { echo "devnet-w2: no venv python at $py (workspace: make bootstrap)" >&2; exit 2; }
[[ -f "$tool" ]] || { echo "devnet-w2: no devnet tool at $tool" >&2; exit 2; }
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
      cargo test -p yew-core --test devnet -- --ignored --nocapture w2_
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
    sed -n '2,14p' "$0"
    exit 2
    ;;
esac
