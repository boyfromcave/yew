#!/usr/bin/env bash
# Phase W1 devnet acceptance (plan §6.3, §7 W1): a private regtest devnet for YEW, separate from
# the default one (~/yb-devnet, portseed 7), with lightwalletd-dd on a plain (no TLS) port.
#
#   scripts/devnet-w1.sh up        bring up ~/yb-devnet-w1 (portseed 57) + lightwalletd on 9167
#   scripts/devnet-w1.sh test      run core/tests/devnet.rs against it (YEW_DEVNET=1)
#   scripts/devnet-w1.sh status    devnet + lightwalletd status
#   scripts/devnet-w1.sh down      stop it (--wipe to delete the directory)
#
# The devnet is left up after `test`; `down` is deliberate. Everything under ~/yb-devnet-w1 is
# disposable. Overrides: YELLOWBACK_DEVNET_DIR, YELLOWBACK_DEVNET_PORTSEED, YEW_LWD_PORT.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ws="$(cd "$here/.." && pwd)"
export YELLOWBACK_DEVNET_DIR="${YELLOWBACK_DEVNET_DIR:-$HOME/yb-devnet-w1}"
export YELLOWBACK_DEVNET_PORTSEED="${YELLOWBACK_DEVNET_PORTSEED:-57}"
lwd_port="${YEW_LWD_PORT:-9167}"
py="${YEW_DEVNET_PYTHON:-$ws/.venv/bin/python}"
tool="${YEW_DEVNET_TOOL:-$ws/ycash-dd/contrib/yellowback/devnet/yellowback-devnet}"
[[ -x "$py" ]] || { echo "devnet-w1: no venv python at $py (workspace: make bootstrap)" >&2; exit 2; }
[[ -f "$tool" ]] || { echo "devnet-w1: no devnet tool at $tool" >&2; exit 2; }
dn() { (cd "$ws/ycash-dd" && "$py" "$tool" "$@"); }

case "${1:-}" in
  up)
    dn up --no-attest --lean --force
    dn lightwalletd start --port "$lwd_port"
    ;;
  test)
    cd "$here"
    YEW_DEVNET=1 YEW_DEVNET_SERVER="127.0.0.1:$lwd_port" YEW_DEVNET_PYTHON="$py" YEW_DEVNET_TOOL="$tool" \
      cargo test -p yew-core --test devnet -- --ignored --nocapture
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
    sed -n '2,12p' "$0"
    exit 2
    ;;
esac
