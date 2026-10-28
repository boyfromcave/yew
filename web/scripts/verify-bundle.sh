#!/usr/bin/env bash
# Checks a served yew/web origin against a release's BUNDLE-SHA256SUMS (plan §3, W3):
#   scripts/verify-bundle.sh https://wallet.example.org [BUNDLE-SHA256SUMS]
# With no sums file, the origin's own /BUNDLE-SHA256SUMS is fetched and checked against the
# bundle hash published with the release (RELEASE_BUNDLE_HASH, the sha256 of the sums file) —
# without that hash a self-served sums file proves only that the origin is consistent with
# itself. Every listed file is fetched (curl, no cache) and its SHA-256 compared; index.html's
# integrity attributes are recomputed from the fetched assets; the isolation headers the wasm
# needs (COOP/COEP) are reported. Exit 1 on any mismatch.
set -euo pipefail
ORIGIN=${1:?origin, e.g. https://wallet.example.org}; ORIGIN=${ORIGIN%/}
SUMS=${2:-}
TMP=$(mktemp -d "${TMPDIR:-/tmp}/yew-web-verify.XXXXXX"); trap 'rm -rf "$TMP"' EXIT
fetch() { curl -fsS -H 'Cache-Control: no-cache' "$ORIGIN/$1" -o "$TMP/$(echo "$1" | tr / _)"; }

if [ -z "$SUMS" ]; then
  fetch BUNDLE-SHA256SUMS; SUMS="$TMP/BUNDLE-SHA256SUMS"
  got=$(shasum -a 256 "$SUMS" | cut -d' ' -f1)
  if [ -n "${RELEASE_BUNDLE_HASH:-}" ]; then
    [ "$got" = "$RELEASE_BUNDLE_HASH" ] || { echo "verify-bundle: the served BUNDLE-SHA256SUMS ($got) is not the release's ($RELEASE_BUNDLE_HASH)"; exit 1; }
    echo "verify-bundle: BUNDLE-SHA256SUMS matches the release hash"
  else
    echo "verify-bundle: WARNING: no RELEASE_BUNDLE_HASH; trusting the origin's own sums file ($got)"
  fi
fi

fail=0; n=0
while read -r sum path; do
  [ -n "$path" ] || continue
  fetch "$path" || { echo "verify-bundle: $path: not served"; fail=1; continue; }
  got=$(shasum -a 256 "$TMP/$(echo "$path" | tr / _)" | cut -d' ' -f1)
  if [ "$got" = "$sum" ]; then n=$((n+1)); else echo "verify-bundle: $path: served $got, expected $sum"; fail=1; fi
done < "$SUMS"
echo "verify-bundle: $n files match the sums"

# SRI: each integrity attribute of the served index.html against the served asset.
index="$TMP/index.html"
[ -f "$index" ] || fetch index.html
sri=0
while IFS= read -r line; do
  path=$(echo "$line" | sed -nE 's/.*(src|href)="\/([^"]*)".*/\2/p'); [ -n "$path" ] || continue
  want=$(echo "$line" | sed -nE 's/.*integrity="sha384-([^"]*)".*/\1/p')
  [ -n "$want" ] || { echo "verify-bundle: index.html: $path has no integrity attribute"; fail=1; continue; }
  f="$TMP/$(echo "$path" | tr / _)"; [ -f "$f" ] || fetch "$path"
  got=$(openssl dgst -sha384 -binary "$f" | openssl base64 -A)
  if [ "$got" = "$want" ]; then sri=$((sri+1)); else echo "verify-bundle: SRI mismatch for $path"; fail=1; fi
done < <(grep -oE '<(script|link)[^>]*>' "$index")
echo "verify-bundle: $sri SRI attributes verified"

# The headers the wasm worker needs; informational unless missing.
hdr=$(curl -fsSI "$ORIGIN/index.html" | tr -d '\r')
for h in cross-origin-opener-policy cross-origin-embedder-policy content-security-policy; do
  v=$(echo "$hdr" | grep -i "^$h:" | cut -d' ' -f2- || true)
  echo "verify-bundle: $h: ${v:-(not in headers)}"
done
exit $fail
