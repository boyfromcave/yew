#!/usr/bin/env bash
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or https://www.opensource.org/licenses/mit-license.php .
#
# Verifies that core/tests/vectors/testnet_profiles.json is what scripts/gen-testnet-profiles.py
# generates from ycash6's sources at the commit the fixture records (its "source.commit"): every
# network's upgrade heights and branch ids (mainnet, testnet-yb-fast, -slow, -legacy) and the YED
# lifecycle columns. core/tests/testnet_profiles.rs pins YEW's compiled-in tables to the fixture;
# this script pins the fixture to the node.
#
# Fails, never skips. Source of each file, in order: the sibling checkout (YCASH6, default
# ../ycash6) when it has the commit; otherwise raw.githubusercontent.com (CI).
#
#   scripts/check-testnet-profiles.sh                 # check
#   scripts/check-testnet-profiles.sh --regen <commit>   # rewrite the fixture from ycash6 at <commit>
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture="$here/core/tests/vectors/testnet_profiles.json"
sib="${YCASH6:-$here/../ycash6}"
FILES=(src/chainparams.cpp src/consensus/upgrades.cpp src/consensus/upgrades.h src/yellowback/params.cpp)
PY="${PYTHON:-python3}"

if [[ "${1:-}" == "--regen" ]]; then
  commit="${2:?--regen needs a full ycash6 commit}"
else
  commit="$("$PY" -c 'import json,sys; print(json.load(open(sys.argv[1]))["source"]["commit"])' "$fixture")"
fi
if [[ ! "$commit" =~ ^[0-9a-f]{40}$ ]]; then
  echo "check-testnet-profiles: the fixture must name a full ycash6 commit (got '$commit')" >&2
  exit 1
fi
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
args=()
for path in "${FILES[@]}"; do
  out="$tmp/$(echo "$path" | tr / _)"
  if git -C "$sib" cat-file -e "$commit^{commit}" 2>/dev/null; then
    git -C "$sib" show "$commit:$path" >"$out"
  else
    url="https://raw.githubusercontent.com/boyfromcave/ycash6/$commit/$path"
    if ! curl -fsSL --retry 3 --retry-delay 5 -o "$out" "$url"; then
      echo "check-testnet-profiles: cannot fetch $url (and $sib has no commit $commit)" >&2
      exit 1
    fi
  fi
  args+=("$out")
done
"$PY" -I "$here/scripts/gen-testnet-profiles.py" "$commit" "${args[@]}" >"$tmp/gen.json"
if [[ "${1:-}" == "--regen" ]]; then
  cp "$tmp/gen.json" "$fixture"
  echo "check-testnet-profiles: wrote $fixture from ycash6 $commit"
  exit
fi
if ! cmp -s "$tmp/gen.json" "$fixture"; then
  echo "check-testnet-profiles: core/tests/vectors/testnet_profiles.json differs from ycash6 at $commit:" >&2
  diff "$fixture" "$tmp/gen.json" >&2 || true
  exit 1
fi
echo "check-testnet-profiles: ok (ycash6 $commit)"
