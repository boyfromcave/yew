#!/usr/bin/env bash
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or https://www.opensource.org/licenses/mit-license.php .
#
# The kogany real run: yewd with koganyd as its node, beside ycashd peers (README.md here).
# Usage: repeat.sh <run-name> <portseed>
# Environment (all required unless defaulted):
#   W   the workspace root (its .venv and its zakura-common-ycash clone)
#   Y6  a built ycash6 tree (src/ycashd, qa/rpc-tests)
#   K   a kogany tree (koganyd is built here, --features ycash, dev profile)
#   Y   this yew tree (yewd is built here)
#   S   the output directory (default: $Y/target/kogany-real-run)
set -euo pipefail
: "${W:?workspace root}" "${Y6:?ycash6 tree}" "${K:?kogany tree}"
Y=${Y:-$(cd "$(dirname "$0")/../../.." && pwd)}
S=${S:-$Y/target/kogany-real-run}
RUN=${1:?run name}; SEED=${2:?portseed}
HERE=$(cd "$(dirname "$0")" && pwd)

# builds, each in its own tree's target dir (never a shared CARGO_TARGET_DIR)
( cd "$K" && CARGO_INCREMENTAL=0 CARGO_NET_GIT_FETCH_WITH_CLI=true CARGO_TARGET_DIR="$K/target" \
    GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0="url.file://$W/zakura-common-ycash.insteadOf" \
    GIT_CONFIG_VALUE_0=https://github.com/boyfromcave/zakura-common-ycash \
    cargo build --locked -j 4 -p kogany --bin koganyd --features ycash )        # dev profile, as kogany-bin.yml
( cd "$Y" && CARGO_TARGET_DIR="$Y/yewd/target" cargo build -j 4 --manifest-path yewd/Cargo.toml --bins )

mkdir -p "$S/$RUN"
export YCASH6_QA="$Y6/qa/rpc-tests" ZCASHD="$Y6/src/ycashd" PYTHONUNBUFFERED=1 \
       YEWD_BIN_PAIR="$Y/yewd/target/debug/yewd" KOGANYD="$K/target/debug/koganyd" YEW_REAL_OUT="$S/$RUN"
# phases: addr,matrix,restart,yed,facade,kparity,restore (default all); ~50 min; the framework stops every node
timeout 5400 "$W/.venv/bin/python" "$HERE/kg_yewd_real.py" --tmpdir="$S/$RUN/t" --portseed="$SEED" --nocleanup \
    > "$S/$RUN/log" 2>&1
grep -E '===|FINDING|balances|DIFFERS|paths only|Tests successful' "$S/$RUN/log" | cut -c1-300
# results: $S/$RUN/results.json (cells, balance_checks, statehashes, restart, yed, facade, kparity, restore, findings)
