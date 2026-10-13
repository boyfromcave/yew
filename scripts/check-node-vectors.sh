#!/usr/bin/env bash
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or https://www.opensource.org/licenses/mit-license.php .
#
# Verifies that YEW's copies of the node's golden vectors (core/tests/vectors/) are the node's
# files at the commits core/tests/vectors/PIN records, on BOTH node lines (ycash-dd v4.5.0 and
# ycash6 6.20.0, whose files are byte-identical by workspace rule). The vectors are declared once,
# in the node; YEW only replays them (vault.rs, pq.rs).
#
# Fails, never skips: a file that differs, a file missing at the pin, a fetch that fails, a PIN
# without both lines. Source of each pinned file, in order:
#   1. the sibling checkout (YCASH_DD / YCASH6, default ../ycash-dd and ../ycash6) when it has the
#      pinned commit: `git show <pin>:<path>` (offline, exact);
#   2. otherwise https://raw.githubusercontent.com/boyfromcave/<repo>/<pin>/<path> (CI).
# When a sibling checkout's HEAD has a different file than the pin, a note says so (the node has
# moved on: re-run scripts/resync-node-vectors.sh); that is not a failure.
#
#   scripts/check-node-vectors.sh            # check
#   scripts/check-node-vectors.sh --files    # print the node paths this script compares
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
pin_file="$here/core/tests/vectors/PIN"

# The node files YEW copies (node path; the copy is core/tests/vectors/<basename>).
FILES=(
  src/test/data/vault_vectors.json
  src/test/data/pq_vectors.json
  src/test/data/pq_wallet_vectors.json
)
if [[ "${1:-}" == "--files" ]]; then
  printf '%s\n' "${FILES[@]}"
  exit
fi

# PIN: "<line> <full commit> <branch> <date>" per node line. (No associative arrays: macOS bash 3.2.)
pin_of() { awk -v l="$1" '$1 == l { print $2 }' "$pin_file"; }
sibling_of() {
  case "$1" in
    ycash-dd) echo "${YCASH_DD:-$here/../ycash-dd}" ;;
    ycash6) echo "${YCASH6:-$here/../ycash6}" ;;
  esac
}
PIN_DD="$(pin_of ycash-dd)"
PIN_6="$(pin_of ycash6)"
for p in "$PIN_DD" "$PIN_6"; do
  if [[ ! "$p" =~ ^[0-9a-f]{40}$ ]]; then
    echo "check-node-vectors: $pin_file must name a full commit for ycash-dd and for ycash6" >&2
    exit 1
  fi
done
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# fetch <line> <path> <out>: the pinned file (prints where it came from), or return 1.
fetch() {
  local line="$1" path="$2" out="$3" commit sib url
  commit="$(pin_of "$line")"
  sib="$(sibling_of "$line")"
  if git -C "$sib" cat-file -e "$commit^{commit}" 2>/dev/null; then
    if git -C "$sib" show "$commit:$path" >"$out" 2>/dev/null; then
      echo "local $sib"
      return 0
    fi
    echo "check-node-vectors: $path is not in $line at $commit" >&2
    return 1
  fi
  url="https://raw.githubusercontent.com/boyfromcave/$line/$commit/$path"
  if curl -fsSL --retry 3 --retry-delay 5 -o "$out" "$url"; then
    echo "fetched $url"
    return 0
  fi
  echo "check-node-vectors: cannot fetch $url (and $sib has no commit $commit)" >&2
  return 1
}

rc=0
for path in "${FILES[@]}"; do
  name="$(basename "$path")"
  copy="$here/core/tests/vectors/$name"
  if [[ ! -f "$copy" ]]; then
    echo "check-node-vectors: core/tests/vectors/$name missing (scripts/resync-node-vectors.sh copies it)" >&2
    rc=1
    continue
  fi
  for line in ycash-dd ycash6; do
    got="$tmp/$line-$name"
    if ! from="$(fetch "$line" "$path" "$got")"; then
      rc=1
      continue
    fi
    if ! cmp -s "$got" "$copy"; then
      echo "check-node-vectors: core/tests/vectors/$name differs from $line $path at $(pin_of "$line") ($from)" >&2
      rc=1
      continue
    fi
    sib="$(sibling_of "$line")"
    if git -C "$sib" rev-parse --is-inside-work-tree >/dev/null 2>&1 && [[ -f "$sib/$path" ]] &&
      ! cmp -s "$sib/$path" "$copy"; then
      echo "check-node-vectors: note: $sib/$path (the checkout) differs from the pinned copy;" \
        "re-run scripts/resync-node-vectors.sh when the node change has landed" >&2
    fi
  done
done
if [[ $rc -ne 0 ]]; then
  echo "check-node-vectors: FAILED (pins: ycash-dd $PIN_DD, ycash6 $PIN_6)" >&2
  exit 1
fi
echo "check-node-vectors: ok (${#FILES[@]} files x 2 node lines; ycash-dd $PIN_DD, ycash6 $PIN_6)"
