#!/usr/bin/env bash
# The Sapling proving files' pins, read from the one place they are written, core/src/sapling_params.rs
# (the constants the wallet itself checks a downloaded file against), for a deploy that puts the
# files on the wallet's own origin (.github/workflows/web-wallet-deploy.yml):
#   scripts/sapling-params-pins.sh sums    "<sha256>  <name>" per file (the format of sha256sum -c)
#   scripts/sapling-params-pins.sh sizes   "<bytes> <name>" per file
# Fails unless it finds exactly the two files, each with a 64-digit sum and a length.
set -euo pipefail
cd "$(dirname "$0")/../.."
mode=${1:?usage: sapling-params-pins.sh sums|sizes}
out=$(awk -v mode="$mode" '
  /^pub const [A-Z]+: ParamFile = ParamFile \{/ { inside = 1; name = ""; bytes = ""; sum = ""; next }
  inside && /^    name: "/   { split($0, q, "\""); name = q[2] }
  inside && /^    bytes: /   { bytes = $2; gsub(/[_,]/, "", bytes) }
  inside && /^    sha256: "/ { split($0, q, "\""); sum = q[2] }
  inside && /^\};/ {
    inside = 0
    if (name !~ /^sapling-(spend|output)\.params$/ || bytes !~ /^[0-9]+$/ || sum !~ /^[0-9a-f]{64}$/) { print "bad pin: " name > "/dev/stderr"; exit 1 }
    if (mode == "sums") print sum "  " name; else print bytes " " name
  }' core/src/sapling_params.rs)
case "$mode" in sums | sizes) ;; *) echo "usage: sapling-params-pins.sh sums|sizes" >&2; exit 1 ;; esac
[ "$(printf '%s\n' "$out" | wc -l | tr -d ' ')" = 2 ] || { echo "sapling-params-pins: expected two files in core/src/sapling_params.rs, got: $out" >&2; exit 1; }
printf '%s\n' "$out"
