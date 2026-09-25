#!/usr/bin/env bash
# Dependency audit (plan §7 W5, docs/release.md §2): `cargo audit` over Cargo.lock against the
# RustSec database. Blocking when an advisory has a patched version we could move to;
# non-blocking (printed, exit 0) when the advisory has no fix yet or is a warning
# (unmaintained, yanked, unsound) — those go into docs/security-review.md by hand.
# Needs: cargo install cargo-audit --locked; python3.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$here"
command -v cargo-audit >/dev/null 2>&1 || { echo "audit: cargo-audit missing (cargo install cargo-audit --locked)" >&2; exit 1; }
out="$(mktemp)"
trap 'rm -f "$out"' EXIT
# cargo-audit exits 1 on any vulnerability; the verdict is ours below.
cargo audit --json > "$out" || true
python3 - "$out" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
vulns = d.get("vulnerabilities", {}).get("list", [])
warnings = d.get("warnings", {})
blocking = 0
for v in vulns:
    a, p = v["advisory"], v["package"]
    patched = v.get("versions", {}).get("patched") or []
    tag = "BLOCKING (fix available)" if patched else "no fix yet (non-blocking)"
    print(f"audit: {a['id']} {p['name']} {p['version']}: {a['title']} — {tag}; patched: {patched or '-'}")
    if patched:
        blocking += 1
for kind, lst in warnings.items():
    for w in lst:
        a, p = w.get("advisory") or {}, w["package"]
        print(f"audit: warning [{kind}] {p['name']} {p['version']}: {a.get('id','-')} {a.get('title','')} (non-blocking)")
n = d.get("lockfile", {}).get("dependency-count", "?")
print(f"audit: {n} crates scanned, {len(vulns)} vulnerabilities, {sum(len(l) for l in warnings.values())} warnings, {blocking} blocking")
sys.exit(1 if blocking else 0)
PY
