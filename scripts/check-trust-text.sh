#!/usr/bin/env bash
# The trust statement has one source, docs/trust.md; app/lib/trust_text.dart is its copy
# (client contract rule 7). Fails when the paragraphs differ.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$here"
want="$(python3 - <<'PY'
src=open('docs/trust.md').read()
body=src.split('\n\n',2)[2].strip()
print('\n'.join(p.replace('\n',' ') for p in body.split('\n\n')))
PY
)"
have="$(python3 - <<'PY'
import re
s=open('app/lib/trust_text.dart').read()
block=s[s.index('trustParagraphs = [')+len('trustParagraphs = ['):s.rindex('];')]
for m in re.finditer(r"'((?:[^'\\]|\\.)*)'", block, re.S):
    print(m.group(1).replace("\\'", "'").replace("\\\\", "\\"))
PY
)"
if [[ "$want" != "$have" ]]; then
  echo "check-trust-text: app/lib/trust_text.dart differs from docs/trust.md; regenerate the Dart copy" >&2
  diff <(printf '%s\n' "$want") <(printf '%s\n' "$have") >&2 || true
  exit 1
fi
echo "check-trust-text: ok"
