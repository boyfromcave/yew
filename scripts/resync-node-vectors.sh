#!/usr/bin/env bash
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or https://www.opensource.org/licenses/mit-license.php .
#
# Re-copies the node's golden vectors (scripts/check-node-vectors.sh --files) into
# core/tests/vectors/ from the two node lines at the given revisions and rewrites
# core/tests/vectors/PIN. Refuses when the two lines' files differ (they must be byte-identical:
# reconcile the node lines first) or a revision does not resolve. Reads the sibling checkouts
# (YCASH_DD / YCASH6, default ../ycash-dd and ../ycash6); fetch them first.
#
#   scripts/resync-node-vectors.sh                                   # both at origin/upgrade/vault
#   scripts/resync-node-vectors.sh <ycash-dd rev> <ycash6 rev> [branch]
#
# Then run the core tests (cargo test --locked -p yew-core) and scripts/check-node-vectors.sh,
# and commit the copies with the PIN. The revisions must be pushed for CI to fetch them.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dd="${YCASH_DD:-$here/../ycash-dd}"
y6="${YCASH6:-$here/../ycash6}"
rev_dd="${1:-origin/upgrade/vault}"
rev_6="${2:-origin/upgrade/vault}"
branch="${3:-upgrade/vault}"
c_dd="$(git -C "$dd" rev-parse --verify "$rev_dd^{commit}")"
c_6="$(git -C "$y6" rev-parse --verify "$rev_6^{commit}")"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
while read -r path; do
  name="$(basename "$path")"
  git -C "$dd" show "$c_dd:$path" >"$tmp/dd-$name"
  git -C "$y6" show "$c_6:$path" >"$tmp/6-$name"
  if ! cmp -s "$tmp/dd-$name" "$tmp/6-$name"; then
    echo "resync-node-vectors: $path differs between ycash-dd $c_dd and ycash6 $c_6; reconcile the node lines first" >&2
    exit 1
  fi
done < <("$here/scripts/check-node-vectors.sh" --files)
while read -r path; do
  name="$(basename "$path")"
  cp "$tmp/dd-$name" "$here/core/tests/vectors/$name"
  echo "resync-node-vectors: core/tests/vectors/$name <- $path ($(shasum -a 256 "$tmp/dd-$name" | cut -c1-16)…)"
done < <("$here/scripts/check-node-vectors.sh" --files)
day="$(date -u +%Y-%m-%d)"
printf 'ycash-dd %s %s %s\nycash6 %s %s %s\n' "$c_dd" "$branch" "$day" "$c_6" "$branch" "$day" >"$here/core/tests/vectors/PIN"
echo "resync-node-vectors: core/tests/vectors/PIN = ycash-dd $c_dd, ycash6 $c_6"
