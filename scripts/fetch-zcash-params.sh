#!/usr/bin/env bash
# Fetch the Sapling and Sprout parameters into ~/.zcash-params and check them against the sums
# ycash6's zcutil/fetch-params.sh pins (the same steps as devnet-nightly.yml).
# Source: the project's release ycash-infra `zcash-params-v1` first (whole files), then
# download.z.cash (two parts each) for any file the release did not give with the pinned hash.
set -euo pipefail
RELEASE=${ZCASH_PARAMS_RELEASE:-https://github.com/boyfromcave/ycash-infra/releases/download/zcash-params-v1}
dir="$HOME/.zcash-params"; mkdir -p "$dir"; cd "$dir"
pinned() {
  case "$1" in
    sapling-spend.params) echo 8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13 ;;
    sapling-output.params) echo 2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4 ;;
    sprout-groth16.params) echo b685d700c60328498fbde589c8c7c484c722b788b265b72af448a5bf0ee55b50 ;;
  esac
}
# sha256sum (Linux, macOS 15), else shasum (older macOS)
if command -v sha256sum >/dev/null 2>&1; then sha=(sha256sum); else sha=(shasum -a 256); fi
for f in sapling-spend.params sapling-output.params sprout-groth16.params; do
  [ -f "$f" ] && continue
  if curl -fsSL --retry 3 -o "$f.release" "$RELEASE/$f" \
    && [ "$("${sha[@]}" "$f.release" | cut -d' ' -f1)" = "$(pinned "$f")" ]; then
    mv "$f.release" "$f"; echo "fetch-zcash-params: $f from the release"; continue
  fi
  rm -f "$f.release"
  echo "fetch-zcash-params: $f not verified from the release; falling back to download.z.cash" >&2
  for i in 1 2; do curl -fsSL --retry 3 -o "$f.part.$i" "https://download.z.cash/downloads/$f.part.$i"; done
  cat "$f.part.1" "$f.part.2" > "$f" && rm "$f.part.1" "$f.part.2"
done
# every file against the pinned sums; a mismatch or a missing file fails
sums="$(mktemp)"; trap 'rm -f "$sums"' EXIT
for f in sapling-spend.params sapling-output.params sprout-groth16.params; do
  echo "$(pinned "$f")  $f" >> "$sums"
done
"${sha[@]}" -c "$sums"
