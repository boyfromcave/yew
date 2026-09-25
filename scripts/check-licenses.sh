#!/usr/bin/env bash
# License listing and check (plan §7 W5, docs/licenses.md): every crate the shipped core links
# (normal + build dependencies of the workspace, dev dependencies excluded) must carry a license
# expression made only of the SPDX identifiers below — all permissive, all compatible with the
# MIT app. `--print` writes the Markdown table docs/licenses.md embeds. Needs python3.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$here"
meta="$(mktemp)"
trap 'rm -f "$meta"' EXIT
cargo metadata --format-version 1 --locked > "$meta"
python3 - "${1:-}" "$meta" <<'PY'
import json, re, sys
ALLOWED = {"MIT", "Apache-2.0", "Apache-2.0 WITH LLVM-exception", "BSD-2-Clause", "BSD-3-Clause",
           "ISC", "Zlib", "CC0-1.0", "MIT-0", "Unlicense", "0BSD", "Unicode-3.0", "Unicode-DFS-2016",
           "LGPL-2.1-or-later"}  # r-efi: "MIT OR Apache-2.0 OR LGPL-2.1-or-later" — MIT is taken
# A crate whose manifest gives license-file only (no SPDX expression): read by hand, recorded here.
FILE_ONLY = {"allo-isolate": "Apache-2.0"}   # LICENSE is the Apache 2.0 text
m = json.load(open(sys.argv[2]))
res = {n["id"]: n for n in m["resolve"]["nodes"]}
pk = {p["id"]: p for p in m["packages"]}
seen, stack = set(), list(m["workspace_members"])
while stack:
    i = stack.pop()
    if i in seen: continue
    seen.add(i)
    for d in res[i]["deps"]:
        if all(k.get("kind") == "dev" for k in d["dep_kinds"]): continue
        stack.append(d["pkg"])
rows, bad = [], []
for i in sorted(seen, key=lambda i: (pk[i]["name"], pk[i]["version"])):
    p = pk[i]
    if p["source"] is None: continue
    lic = p["license"] or FILE_ONLY.get(p["name"]) or "?"
    ids = {t.strip("() ") for t in re.split(r"\s+(?:OR|AND|/)\s+|/", lic)}
    ids = {re.sub(r"\s+WITH\s+.*", "", t) if t not in ALLOWED else t for t in ids}
    if lic == "?" or not ids or not any(t in ALLOWED for t in ids) or ("AND" in lic and not ids <= ALLOWED):
        bad.append((p["name"], p["version"], lic))
    rows.append((p["name"], p["version"], lic))
if sys.argv[1] == "--print":
    print("| Crate | Version | License (SPDX, from the manifest) |")
    print("|---|---|---|")
    for n, v, l in rows: print(f"| `{n}` | {v} | {l} |")
else:
    for n, v, l in bad: print(f"check-licenses: {n} {v}: {l!r} not in the allowed set", file=sys.stderr)
    print(f"check-licenses: {'FAIL' if bad else 'ok'} ({len(rows)} crates)")
    sys.exit(1 if bad else 0)
PY
