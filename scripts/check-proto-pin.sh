#!/usr/bin/env bash
# Verifies proto/*.proto are byte-identical to lightwalletd-dd/walletrpc/ (the interface is
# declared once, in the server's repo; plan §1 budget table, §7 W0a). Skips when the sibling
# checkout is absent (CI), fails when it is present and differs; proto/PIN records the commit.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
src="${LIGHTWALLETD_DD:-$here/../lightwalletd-dd}/walletrpc"
if [[ ! -d "$src" ]]; then
  echo "check-proto-pin: $src not present, skipped (pin: $(cat "$here/proto/PIN"))"
  exit 0
fi
rc=0
for f in service.proto compact_formats.proto yellowback.proto; do
  if ! diff -u "$src/$f" "$here/proto/$f"; then
    echo "check-proto-pin: proto/$f differs from $src/$f" >&2
    rc=1
  fi
done
pinned="$(awk '{print $2}' "$here/proto/PIN")"
if command -v git >/dev/null && git -C "$src" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  head="$(git -C "$src" rev-parse HEAD)"
  if [[ "$head" != "$pinned" ]]; then
    echo "check-proto-pin: note: lightwalletd-dd is at $head, proto/PIN records $pinned" >&2
    [[ $rc -eq 0 ]] && echo "check-proto-pin: files identical; update proto/PIN when you re-copy"
  fi
fi
[[ $rc -eq 0 ]] && echo "check-proto-pin: ok ($pinned)"
exit $rc
