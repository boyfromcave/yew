#!/usr/bin/env bash
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or https://www.opensource.org/licenses/mit-license.php .
#
# The trust statement has one source, docs/trust.md; app/lib/trust_text.dart is its copy
# (client contract rule 7). Fails when the paragraphs differ.
#
# In-term claims (branch upgrade/vault-in-term; the workspace's in-term plan IT-8): the paragraph
# opening "Your YEC is locked" must also equal, whitespace-normalised, the collateral bullet of
# section 8.1 of the node's generated spec (ycash-dd doc/yellowback-spec.md, `make spec-in-term`).
# YELLOWBACK_SPEC names the spec; the default is the sibling ../ycash-dd checkout. Skipped when the
# file is absent (CI without the node) or when its section 8.1 is not the in-term line's (the
# sibling main tree is on upgrade/vault); fails when it is the in-term spec and the text differs.
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
spec="${YELLOWBACK_SPEC:-$here/../ycash-dd/doc/yellowback-spec.md}"
if [[ ! -f "$spec" ]]; then
  echo "check-trust-text: $spec not present, the in-term promise check skipped"
else
  verdict="$(SPEC="$spec" python3 - <<'PY'
import os, re
lines = open(os.environ['SPEC'], encoding='utf-8').read().splitlines()
heading, out, in81 = None, None, False
for line in lines:
    if line.startswith('### '):
        in81 = line.startswith('### 8.1')
        if in81:
            heading = line
        continue
    if not in81:
        continue
    if out is None:
        if line.startswith('- Your YEC is locked'):
            out = [line[2:]]
    elif line.startswith('  ') and line.strip():
        out.append(line.strip())
    else:
        break
if heading is None or 'in-term' not in heading:
    print('SKIP')
elif out is None:
    print('MISSING')
else:
    want = ' '.join(' '.join(out).split())
    src = open('docs/trust.md', encoding='utf-8').read().split('\n\n', 2)[2]
    have = [' '.join(p.split()) for p in src.split('\n\n') if p.startswith('Your YEC is locked')]
    print('OK' if have == [want] else 'DIFF\n  spec:   ' + want + '\n  wallet: ' + (have[0] if have else '(no paragraph opening "Your YEC is locked")'))
PY
)"
  case "$verdict" in
    OK) echo "check-trust-text: the promise is the in-term spec's section 8.1 ($spec)" ;;
    SKIP) echo "check-trust-text: $spec is not the in-term line's spec (section 8.1 heading), the promise check skipped" ;;
    MISSING) echo "check-trust-text: $spec section 8.1 has no bullet opening \"Your YEC is locked\"" >&2; exit 1 ;;
    *) echo "check-trust-text: docs/trust.md's promise differs from $spec section 8.1:" >&2; printf '%s\n' "${verdict#DIFF}" >&2; exit 1 ;;
  esac
fi
echo "check-trust-text: ok"
