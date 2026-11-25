#!/bin/sh
# Checks out the Yugen repositories this workspace builds against, at pinned commits, into
# yewd/yugen/deps/ (git-ignored), from YUGEN_ROOT: a directory of clones or a git URL base
# (e.g. https://github.com/<org>). Re-run after a pin change; refuses a dirty checkout.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
src=${YUGEN_ROOT:?set YUGEN_ROOT to a directory of the Yugen repositories or a git URL base}
mkdir -p "$here/deps"
while read -r name commit; do
	case $name in ''|'#'*) continue ;; esac
	d=$here/deps/$name
	[ -d "$d/.git" ] || git clone -q --no-hardlinks --no-checkout "$src/$name" "$d"
	if ! git -C "$d" cat-file -e "$commit^{commit}" 2>/dev/null; then git -C "$d" fetch -q "$src/$name"; fi
	git -C "$d" -c advice.detachedHead=false checkout -q "$commit"
	[ -z "$(git -C "$d" status --porcelain)" ] || { echo "deps/$name is dirty" >&2; exit 1; }
	echo "$name $(git -C "$d" rev-parse --short HEAD)"
done < "$here/PINS"
