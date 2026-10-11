#!/usr/bin/env bash
# Falcon YED holders (TOK-PQ) devnet acceptance on the quantum line (the workspace's
# docs/plans/yellowback-quantum-spec.md F-7, R-A2; owner decision 2026-10-10: Falcon live from
# day one on mainnet): an ARMED devnet of the quantum node (ycash-dd upgrade/quantum-vaults) whose
# nodes ALL run -pqfalconheight=<F> (a consensus parameter, so every node, the stock one too),
# lightwalletd-dd of the same branch serving --yellowback, and core/tests/devnet.rs
# q_falcon_holders_receive_send_mint_and_restore against it.
#
#   scripts/devnet-falcon.sh up | lwd | test | status | down [--wipe]
#
# The devnet tool has no flag for the Falcon height, so `up` runs it through a small wrapper that
# appends -pqfalconheight=<F> to the framework's per-node upgrade arguments (YCASH_UPGRADE_ARGS,
# qa/rpc-tests/test_framework/yellowback_util.py) before the tool builds its node arguments;
# nothing in the node repository is changed. F defaults to 260 (`up` is ready at ~200; the test
# starts before F, crosses it, and continues after it): YEW_PQ_FALCON_HEIGHT.
#
# Point it at the quantum line: YEW_DEVNET_TOOL (default <workspace>/wt/q-dd/contrib/yellowback/
# devnet/yellowback-devnet), BITCOIND (its ycashd), YELLOWBACK_ATTEST_BIN, YELLOWBACK_LWD_BIN.
# Defaults: ~/yb-devnet-falcon, portseed 2200, lightwalletd on 2219 (YELLOWBACK_DEVNET_DIR,
# YELLOWBACK_DEVNET_PORTSEED, YEW_LWD_PORT).
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or https://www.opensource.org/licenses/mit-license.php .
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ws="$here"
while [[ ! -f "$ws/repos.yaml" && "$ws" != "/" ]]; do ws="$(dirname "$ws")"; done
[[ -f "$ws/repos.yaml" ]] || { echo "devnet-falcon: no workspace (repos.yaml) above $here" >&2; exit 2; }
export YELLOWBACK_DEVNET_DIR="${YELLOWBACK_DEVNET_DIR:-$HOME/yb-devnet-falcon}"
export YELLOWBACK_DEVNET_PORTSEED="${YELLOWBACK_DEVNET_PORTSEED:-2200}"
export YEW_PQ_FALCON_HEIGHT="${YEW_PQ_FALCON_HEIGHT:-260}"
lwd_port="${YEW_LWD_PORT:-2219}"
export YEW_DEVNET_FUND_NODE="${YEW_DEVNET_FUND_NODE:-0}"
py="${YEW_DEVNET_PYTHON:-$ws/.venv/bin/python}"
tool="${YEW_DEVNET_TOOL:-$ws/wt/q-dd/contrib/yellowback/devnet/yellowback-devnet}"
[[ -x "$py" ]] || { echo "devnet-falcon: no venv python at $py (workspace: make bootstrap)" >&2; exit 2; }
[[ -f "$tool" ]] || { echo "devnet-falcon: no devnet tool at $tool" >&2; exit 2; }
node_repo="$(cd "$(dirname "$tool")/../../.." && pwd)"
dn() { (cd "$node_repo" && "$py" "$tool" "$@"); }
# The tool with -pqfalconheight=<F> on every node it starts.
dn_falcon() {
  (cd "$node_repo" && "$py" - "$tool" "$@" <<'PY'
import os, runpy, sys
tool = sys.argv[1]
repo = os.path.abspath(os.path.join(os.path.dirname(tool), "..", "..", ".."))
sys.path.insert(0, os.path.join(repo, "qa", "rpc-tests"))
from test_framework import yellowback_util as yu
yu.YCASH_UPGRADE_ARGS.append("-pqfalconheight=%d" % int(os.environ["YEW_PQ_FALCON_HEIGHT"]))
sys.argv = [tool] + sys.argv[2:]
runpy.run_path(tool, run_name="__main__")
PY
  )
}

case "${1:-}" in
  up)
    dn_falcon up --force --no-viz --portseed "$YELLOWBACK_DEVNET_PORTSEED"
    dn lightwalletd start --port "$lwd_port" --extra=--yellowback
    dn cli -- yed_getinfo | grep -A3 '"pq"' || true
    ;;
  lwd)
    dn lightwalletd stop || true
    dn lightwalletd start --port "$lwd_port" --extra=--yellowback
    ;;
  test)
    cd "$here"
    YEW_DEVNET=1 YEW_DEVNET_SERVER="127.0.0.1:$lwd_port" YEW_DEVNET_PYTHON="$py" YEW_DEVNET_TOOL="$tool" \
      cargo test -p yew-core --test devnet -- --ignored --nocapture --test-threads=1 q_falcon_
    ;;
  status) dn status ;;
  down)
    dn lightwalletd stop || true
    shift; dn down "$@"
    ;;
  *) echo "usage: scripts/devnet-falcon.sh up | lwd | test | status | down [--wipe]" >&2; exit 2 ;;
esac
