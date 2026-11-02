#!/usr/bin/env bash
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or https://www.opensource.org/licenses/mit-license.php .
#
# The yewd unit leg (workspace plan docs/plans/kogany/kogany-yellowback-plan.md §5, "yewd's CI"):
# fmt, clippy (-D warnings), cargo test over the four crates, and the naming and attribution
# greps over yewd/ and its plan. Run from anywhere; CARGO_TARGET_DIR is honoured.
# The backend round trip (tests/regtest.rs) runs when YEWD_TEST_YCASHD names a ycashd.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$here"

# Naming (workspace AGENTS.md rule 6) and no AI attribution (rule 8). This file is excluded:
# it has to spell the patterns.
pattern='digidollar|ydollar|\byd_|co-authored-by|claude|anthropic|generated with'
if hits="$(grep -rniE "$pattern" --exclude=check-yewd.sh --exclude-dir=target . ../docs/plans/yewd-plan.md)"; then
  echo "check-yewd: forbidden naming or attribution:" >&2
  printf '%s\n' "$hits" >&2
  exit 1
fi

cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
echo "check-yewd: ok"
