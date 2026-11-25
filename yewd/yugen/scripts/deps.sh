#!/bin/sh
# Checks out the Yugen repositories this workspace builds against, at pinned commits, into
# yewd/yugen/deps/ (git-ignored), from the URL in PINS, or from YUGEN_ROOT/<name> when set (a
# directory of clones or a git URL base). Re-run after a pin change; refuses a dirty checkout.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$here/deps"
while read -r name url commit; do
	case $name in ''|'#'*) continue ;; esac
	d=$here/deps/$name
	src=${YUGEN_ROOT:+$YUGEN_ROOT/$name}; src=${src:-$url}
	[ -d "$d/.git" ] || git clone -q --no-hardlinks --no-checkout "$src" "$d"
	if ! git -C "$d" cat-file -e "$commit^{commit}" 2>/dev/null; then git -C "$d" fetch -q "$src"; fi
	git -C "$d" -c advice.detachedHead=false checkout -q "$commit"
	[ -z "$(git -C "$d" status --porcelain)" ] || { echo "deps/$name is dirty" >&2; exit 1; }
	echo "$name $(git -C "$d" rev-parse --short HEAD)"
done < "$here/PINS"
