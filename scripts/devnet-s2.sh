#!/usr/bin/env bash
# yew-shielded plan S2 devnet acceptance: Sapling restore / receive with memo / z→z with memo /
# z→t (revealsShielded) / transparent fallback / YED regression, and the S4 moves (s4_: shield,
# unshield, mint after an unshield) and the S5 hardening (s5_: restore with a birthday, reorgs
# under a synced wallet, interrupted sync), on EITHER node line. YEW_S2_TESTS picks the tests
# (default "s2_ s4_ s5_", run one at a time on the one devnet).
#
#   scripts/devnet-s2.sh {dd|6} <seed> [lwd-port]      (KEEP=1 leaves the devnet running)
#
# dd = the v4.5.0 line (ycash-dd, BITCOIND), 6 = the 6.21.0 line (ycash6, ZCASHD). Brings up the
# ARMED devnet of that line (no heartbeat, walk, personas or viz; every block is mined on a pool
# node by the test) in $YEW_S2_SCRATCH/<line>-<seed>, builds lightwalletd-dd (GetChainInfo needs
# 0b3448e+) into $YEW_S2_SCRATCH/lightwalletd and starts it with --yellowback on lwd-port
# (default 9067 + seed), runs `s2_` from core/tests/devnet.rs, writes the timings to
# $YEW_S2_SCRATCH/s2-<line>.json and tears everything down. Needs the Sapling proving parameters
# on this machine (a ycashd 4.5.0 fetch-params.sh copy, or YEW_SAPLING_PARAMS=<dir>).
# Works from a git worktree too: the workspace is found by walking up to repos.yaml.
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or https://www.opensource.org/licenses/mit-license.php .
set -euo pipefail
[ $# -ge 2 ] || { sed -n '2,15p' "$0"; exit 2; }
line=$1 seed=$2 port=${3:-$((9067 + seed))}
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ws="$here"
while [[ ! -f "$ws/repos.yaml" && "$ws" != "/" ]]; do ws="$(dirname "$ws")"; done
[[ -f "$ws/repos.yaml" ]] || { echo "devnet-s2: no workspace (repos.yaml) above $here" >&2; exit 2; }
case $line in dd) noderepo=$ws/ycash-dd; binvar=BITCOIND ;; 6) noderepo=$ws/ycash6; binvar=ZCASHD ;; *) exit 2 ;; esac
scratch=${YEW_S2_SCRATCH:-$ws/wt/scratch/yew-s2}
py="${YEW_DEVNET_PYTHON:-$ws/.venv/bin/python}"
tool=$noderepo/contrib/yellowback/devnet/yellowback-devnet
lwd_bin=${YEW_LWD_BIN:-$scratch/lightwalletd}
mkdir -p "$scratch"
if [ ! -x "$lwd_bin" ]; then
  echo "building lightwalletd-dd at $(git -C "$ws/lightwalletd-dd" rev-parse --short HEAD) into $lwd_bin"
  (cd "$ws/lightwalletd-dd" && CGO_ENABLED=0 go build -mod=vendor -o "$lwd_bin" .)
fi
export YELLOWBACK_DEVNET_DIR=$scratch/$line-$seed YELLOWBACK_DEVNET_PORTSEED=$seed
export "$binvar=$noderepo/src/ycashd"
dn() { (cd "$noderepo" && "$py" "$tool" "$@"); }
down() {
  [ "${KEEP:-0}" = 1 ] && { echo "KEEP=1: devnet left running in $YELLOWBACK_DEVNET_DIR (lightwalletd on $port)"; return; }
  dn lightwalletd stop || true
  dn down || true
}
trap down EXIT
if [ "${REUSE:-0}" != 1 ]; then
  dn up --force --no-heartbeat --no-walk --no-sim --no-viz
  dn lightwalletd start --port "$port" --bin "$lwd_bin" --extra=--yellowback
fi
cd "$here"
# s5_interrupted_sync_resumes kills a real `yew-cli sync` mid-scan.
cargo build -q -p yew-cli
target_dir=$(cargo metadata --no-deps --format-version 1 | "$py" -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')
export YEW_CLI_BIN=${YEW_CLI_BIN:-$target_dir/debug/yew-cli}
YEW_DEVNET=1 YEW_DEVNET_LINE=$line YEW_DEVNET_SERVER="127.0.0.1:$port" YEW_DEVNET_PYTHON="$py" \
  YEW_DEVNET_TOOL="$tool" YEW_DEVNET_TIMINGS="$scratch/s2-$line.json" \
  cargo test -p yew-core --test devnet -- --ignored --nocapture --test-threads=1 ${YEW_S2_TESTS:-s2_ s4_ s5_}
