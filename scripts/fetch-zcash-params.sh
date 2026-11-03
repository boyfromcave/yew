#!/usr/bin/env bash
# Fetch the Sapling and Sprout parameters into ~/.zcash-params and check them against the sums
# ycash6's zcutil/fetch-params.sh pins (the same steps as devnet-nightly.yml).
set -euo pipefail
dir="$HOME/.zcash-params"; mkdir -p "$dir"; cd "$dir"
for f in sapling-spend.params sapling-output.params sprout-groth16.params; do
  [ -f "$f" ] && continue
  for i in 1 2; do curl -fsSL --retry 3 -o "$f.part.$i" "https://download.z.cash/downloads/$f.part.$i"; done
  cat "$f.part.1" "$f.part.2" > "$f" && rm "$f.part.1" "$f.part.2"
done
sha256sum -c <<'EOF'
8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13  sapling-spend.params
2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4  sapling-output.params
b685d700c60328498fbde589c8c7c484c722b788b265b72af448a5bf0ee55b50  sprout-groth16.params
EOF
