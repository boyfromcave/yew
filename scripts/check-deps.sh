#!/usr/bin/env bash
# Dependency allow-list check (plan §3.3, §6.4): the direct normal dependencies of yew-core
# (from `cargo tree`) must all appear in scripts/allowed-deps.txt. Transitive deps are not
# checked; build-dependencies (tonic-prost-build, prost-build) are not checked.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$here"
actual="$(cargo tree -e normal --prefix none --no-dedupe -p yew-core --depth 1 \
  | awk '{print $1}' | grep -vx 'yew-core' | sort -u)"
allowed="$(grep -v '^#' scripts/allowed-deps.txt | sed '/^$/d' | sort -u)"
extra="$(comm -23 <(printf '%s\n' "$actual") <(printf '%s\n' "$allowed") || true)"
if [[ -n "$extra" ]]; then
  echo "check-deps: direct dependencies of yew-core not in scripts/allowed-deps.txt:" >&2
  printf '  %s\n' $extra >&2
  echo "check-deps: record the decision in the plan (§3.3) and add the crate to the list." >&2
  exit 1
fi
echo "check-deps: ok ($(printf '%s\n' "$actual" | wc -l | tr -d ' ') direct deps, all allowed)"
