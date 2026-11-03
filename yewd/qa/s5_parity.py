#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or https://www.opensource.org/licenses/mit-license.php .

"""
yewd S5, the parity gate (workspace plan docs/plans/kogany/kogany-yellowback-plan.md §3b S5, §6;
docs/plans/kogany/ci-design.md §7): the three-way W9 matrix over ycash6's wallet-needing scripts,
every script unchanged.

    column 1  ycash6       the scripts on plain ycashd nodes (the reference)
    column 2  rig          kogany + the ycash6 test rig (KOGANY_SIDECAR=1, W9-a): node i = kogany i and a
                           ycashd -connect'ed to it; the MixedLine compares each kogany with its ycashd
    column 3  pair         kogany + yewd (YEWD_BIN with YEWD_KOGANY): no ycashd behind any node; the
                           harness's YewdColumn compares the state hashes across the pairs at every sync point
    column 3m pair-mixed   column 3 with one ycash6 peer (YEWD_YCASH6_PEER=1): a ycashd -disablewallet
                           dialing pair 0, judging every block and transaction the pairs make (§4.3 rule 3),
                           compared at every sync point; the pairs' blocks are solved by the harness

The script list is the manifest's (ycash6 qa/kogany-mixed-shards.txt, group `pair`, the same 50 as
`sidecar`), or --scripts. Each script runs on its own (--srcdir, a distinct --portseed, its own
--tmpdir); a passing script's chain data is removed, its log kept. The table (script x column: pass,
or FAIL at the failure point, seconds; the state-hash points from the harness's KOGANY_STATS_FILE)
is written as Markdown and JSON. The failure point is the script's own frame of the traceback
(``<script>.py:<line> <function>``), the error (the first ``Assertion failed`` / ``JSONRPC error``
/ ``Unexpected exception`` line), the innermost helper frame and the step (the script's last
narration line before the error); a timeout names the last step. Below the table, "Failure points"
lists them in full. --rounds 2 runs the selection twice ("twice in a row").

CHAINVIZ_BIN (or --chainviz) names the chain-viz binary yellowback_chainviz runs: set it to a
current build (boyfromcave/chain-viz `cargo build --release`). Unset, the script falls back to
``$CARGO_TARGET_DIR/release/chain-viz`` then ``<workspace>/chain-viz/target/release/chain-viz``,
which may be stale (a chain-viz older than 78fe29a drops v4 PQ mint payloads, so the script fails
on yewd's mints); the runner warns when yellowback_chainviz is selected without it, and refuses a
CHAINVIZ_BIN that is not executable.

    YCASH6=<ycash6 checkout at vaults/kogany-compat (the YEWD_KOGANY harness)> \\
    ZCASHD=<ycashd> YEWD_BIN=<yewd> ZAKURAD=<zakurad --features ycash> \\
    CHAINVIZ_BIN=<chain-viz, current build> \\
        <venv>/bin/python yewd/qa/s5_parity.py --columns pair,pair-mixed,rig,ycash6 \\
        --out <dir> [--jobs 3] [--rounds 2] [--portseed 7000] [--scripts a,b] [--of vault]

Exit 0 when every selected script passed in every column and round, 1 otherwise.
"""

import argparse
import concurrent.futures
import json
import os
import re
import shutil
import subprocess
import sys
import time

COLUMNS = ('ycash6', 'rig', 'pair', 'pair-mixed')
ERR = re.compile(r'(JSONRPC error|Assertion failed|Unexpected exception|key not found)')
FRAME = re.compile(r'^\s+File "([^"]+)", line (\d+), in (\S+)')
NOT_A_STEP = re.compile(r'^(\s|Initializing test directory|yewd column|Stopping nodes|Failed|Cleaning up|'
                        r'Tests successful|Traceback|\S+Error\b|\S+Exception\b)')


def failure_point(lines, script, rc, secs):
    """The failure point of a failed run's log ``lines``: {'at': '<script>.py:<line> <function>',
    'code': that frame's source line, 'error': the first error line, 'helper': the innermost frame
    outside the script ('file:line function'), 'step': the script's last narration line before the
    error}.  Empty strings where the log has nothing (a crash before the framework, a timeout)."""
    out = {'at': '', 'code': '', 'error': '', 'helper': '', 'step': ''}
    first = next((n for n, l in enumerate(lines) if ERR.search(l)), None)
    narration = lines if first is None else lines[:first]
    for l in reversed(narration):
        if l.strip() and not NOT_A_STEP.match(l):
            out['step'] = l.strip()[:200]
            break
    if first is None:
        if rc == 124:
            out['error'] = 'timeout after %ds' % secs
        else:
            tail = [l.strip() for l in lines if l.strip() and not l.startswith(('Stopping', 'Failed', 'yewd column'))]
            out['error'] = (tail[-1] if tail else 'rc %d' % rc)[:240]
        return out
    out['error'] = lines[first].strip()[:240]
    frames = []
    for n in range(first + 1, len(lines)):
        m = FRAME.match(lines[n])
        if m:
            code = lines[n + 1].strip() if n + 1 < len(lines) and not FRAME.match(lines[n + 1]) else ''
            frames.append((m.group(1), int(m.group(2)), m.group(3), code))
        elif lines[n].startswith(('Stopping nodes', 'Failed')):
            break
    own = [f for f in frames if os.path.basename(f[0]) == script + '.py']
    if own:
        f = own[-1]
        out['at'] = '%s.py:%d %s' % (script, f[1], f[2])
        out['code'] = f[3][:200]
    if frames and (not own or frames[-1] is not own[-1]):
        f = frames[-1]
        out['helper'] = '%s:%d %s' % (os.path.basename(f[0]), f[1], f[2])
    return out


def column_env(col, base, ycash6, zakurad, yewd, script_flags):
    env = dict(base)
    for k in ('YEWD_BIN', 'YEWD_KOGANY', 'YEWD_YCASH6_PEER', 'KOGANY_BIN', 'KOGANY_SIDECAR',
              'KOGANY_MIRROR_INVALIDATE', 'KOGANY_MEMPOOL'):
        env.pop(k, None)
    env.setdefault('KOGANY_LIVE', 'W1-Y1,W2-b')
    if col == 'rig':
        env.update({'KOGANY_BIN': zakurad, 'KOGANY_SIDECAR': '1'})
        if 'mirror' in script_flags:
            env['KOGANY_MIRROR_INVALIDATE'] = '1'
        if 'mempool' in script_flags:
            env['KOGANY_MEMPOOL'] = '1'
    elif col in ('pair', 'pair-mixed'):
        env.update({'YEWD_BIN': yewd, 'YEWD_KOGANY': zakurad})
        if col == 'pair-mixed':
            env['YEWD_YCASH6_PEER'] = '1'
    return env


def manifest(ycash6, group='pair', of=None):
    """[(script, flags of its sidecar row)] from the manifest."""
    path = os.path.join(ycash6, 'qa', 'kogany-mixed-shards.txt')
    rows, groups = [], {}
    with open(path, encoding='utf-8') as fh:
        lines = [l.split('#', 1) for l in fh]
    for body, *rest in lines:
        f = body.split()
        if len(f) >= 4 and f[0] in ('node', 'vault', 'yed', 'fees', 'attest'):
            groups[f[1]] = f[0]
    flags = {}
    for body, *rest in lines:
        f = body.split()
        if len(f) >= 4 and f[0] == 'sidecar':
            flags[f[1]] = f[4:]
    for body, *rest in lines:
        f = body.split()
        if len(f) >= 4 and f[0] == group and (of is None or groups.get(f[1]) == of):
            rows.append((f[1], flags.get(f[1], [])))
    return rows


def run_one(col, script, flags, seed, out, args):
    qa = os.path.join(args.ycash6, 'qa', 'rpc-tests')
    d = os.path.join(out, col)
    os.makedirs(d, exist_ok=True)
    tmp = os.path.join(d, script + '.d')
    shutil.rmtree(tmp, ignore_errors=True)
    stats = os.path.join(d, script + '.stats.jsonl')
    if os.path.exists(stats):
        os.remove(stats)
    env = column_env(col, os.environ, args.ycash6, args.zakurad, args.yewd, flags)
    env['KOGANY_STATS_FILE'] = stats
    env['ZCASHD'] = args.zcashd
    srcdir = os.path.dirname(os.path.abspath(args.zcashd))
    cmd = [sys.executable, '-u', script + '.py', '--srcdir=' + srcdir, '--tmpdir=' + tmp,
           '--portseed=%d' % seed, '--nocleanup']
    t0 = time.time()
    with open(os.path.join(d, script + '.log'), 'w') as log:
        try:
            rc = subprocess.call(cmd, cwd=qa, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=args.timeout)
        except subprocess.TimeoutExpired:
            rc = 124
    secs = int(time.time() - t0)
    first = ''
    with open(os.path.join(d, script + '.log'), errors='replace') as log:
        lines = log.read().splitlines()
    for line in lines:
        if ERR.search(line):
            first = line.strip()[:240]
            break
    point = failure_point(lines, script, rc, secs) if rc != 0 else None
    points = {}
    if os.path.exists(stats):
        with open(stats) as fh:
            for line in fh:
                try:
                    st = json.loads(line)['stats']
                except (ValueError, KeyError):
                    continue
                for k, v in st.items():
                    points[k] = points.get(k, 0) + v
    if rc == 0:
        shutil.rmtree(tmp, ignore_errors=True)
    return {'column': col, 'script': script, 'rc': rc, 'seconds': secs, 'first_error': first, 'points': points,
            'failure_point': point}


def table(results, columns, scripts):
    by = {(r['column'], r['script']): r for r in results}
    lines = ['| script | ' + ' | '.join(columns) + ' |', '|---|' + '---|' * len(columns)]
    for s in scripts:
        cells = []
        for c in columns:
            r = by.get((c, s))
            if r is None:
                cells.append('-')
            elif r['rc'] == 0:
                p = r['points']
                hashes = p.get('statehash_vault', 0) + p.get('statehash_yed', 0)
                cells.append('pass (%ds%s)' % (r['seconds'], ', %d hash pts' % hashes if hashes else ''))
            else:
                fp = r.get('failure_point') or {}
                at = fp.get('at') or ('timeout' if r['rc'] == 124 else 'rc %d' % r['rc'])
                err = fp.get('error') or r['first_error']
                cells.append(('FAIL at %s: %s' % (at, err)).replace('|', '/')[:160])
        lines.append('| %s | %s |' % (s, ' | '.join(cells)))
    failed = [by[(c, s)] for s in scripts for c in columns if (c, s) in by and by[(c, s)]['rc'] != 0]
    if failed:
        lines += ['', '## Failure points', '']
        for r in failed:
            fp = r.get('failure_point') or {}
            lines.append('- **%s** (%s, rc %d, %ds): at `%s`%s' % (
                r['script'], r['column'], r['rc'], r['seconds'], fp.get('at') or '-',
                ' `%s`' % fp['code'] if fp.get('code') else ''))
            lines.append('  - error: %s' % (fp.get('error') or r['first_error'] or '-').replace('|', '/'))
            if fp.get('helper'):
                lines.append('  - innermost frame: `%s`' % fp['helper'])
            if fp.get('step'):
                lines.append('  - step: %s' % fp['step'].replace('|', '/'))
    return '\n'.join(lines) + '\n'


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--columns', default='pair')
    ap.add_argument('--out', required=True)
    ap.add_argument('--jobs', type=int, default=3)
    ap.add_argument('--rounds', type=int, default=1)
    ap.add_argument('--portseed', type=int, default=7000)
    ap.add_argument('--scripts')
    ap.add_argument('--of', choices=('node', 'vault', 'yed', 'fees', 'attest'))
    ap.add_argument('--timeout', type=int, default=2400)
    ap.add_argument('--ycash6', default=os.environ.get('YCASH6'))
    ap.add_argument('--zcashd', default=os.environ.get('ZCASHD'))
    ap.add_argument('--yewd', default=os.environ.get('YEWD_BIN'))
    ap.add_argument('--zakurad', default=os.environ.get('ZAKURAD') or os.environ.get('YEWD_KOGANY'))
    ap.add_argument('--chainviz', default=os.environ.get('CHAINVIZ_BIN'),
                    help='the chain-viz binary yellowback_chainviz runs (CHAINVIZ_BIN): a current build')
    args = ap.parse_args()
    columns = args.columns.split(',')
    for c in columns:
        if c not in COLUMNS:
            ap.error('unknown column %s (one of %s)' % (c, ', '.join(COLUMNS)))
    if not (args.ycash6 and args.zcashd):
        ap.error('YCASH6 and ZCASHD are required')
    if any(c != 'ycash6' for c in columns) and not args.zakurad:
        ap.error('ZAKURAD is required for the kogany columns')
    if any(c.startswith('pair') for c in columns) and not args.yewd:
        ap.error('YEWD_BIN is required for the pair columns')
    rows = manifest(args.ycash6, of=args.of)
    if args.scripts:
        want = args.scripts.split(',')
        rows = [r for r in rows if r[0] in want] or [(s, []) for s in want]
    scripts = [r[0] for r in rows]
    if args.chainviz:
        args.chainviz = os.path.abspath(args.chainviz)
        if not (os.path.isfile(args.chainviz) and os.access(args.chainviz, os.X_OK)):
            ap.error('CHAINVIZ_BIN %s is not an executable file' % args.chainviz)
        os.environ['CHAINVIZ_BIN'] = args.chainviz        # column_env copies the environment
    elif 'yellowback_chainviz' in scripts:
        print('s5_parity: warning: yellowback_chainviz without CHAINVIZ_BIN falls back to '
              '$CARGO_TARGET_DIR or <workspace>/chain-viz/target/release/chain-viz, which may be stale',
              file=sys.stderr)
    ok = True
    for rnd in range(1, args.rounds + 1):
        out = os.path.join(args.out, 'round%d' % rnd)
        jobs = []
        seed = args.portseed
        for c in columns:
            for s, flags in rows:
                seed += 1
                jobs.append((c, s, flags, seed))
        with concurrent.futures.ThreadPoolExecutor(args.jobs) as ex:
            results = list(ex.map(lambda j: run_one(*j, out, args), jobs))
        md = table(results, columns, scripts)
        os.makedirs(out, exist_ok=True)
        with open(os.path.join(out, 'matrix.md'), 'w') as fh:
            used = ['%s `%s`' % (k, v) for k, v in (('ZCASHD', args.zcashd), ('ZAKURAD', args.zakurad),
                                                    ('YEWD_BIN', args.yewd), ('CHAINVIZ_BIN', args.chainviz)) if v]
            fh.write('# S5 matrix, round %d\n\n' % rnd + ', '.join(used) + '\n\n' + md)
        with open(os.path.join(out, 'matrix.json'), 'w') as fh:
            json.dump(results, fh, indent=1, sort_keys=True)
        print('round %d\n%s' % (rnd, md))
        ok = ok and all(r['rc'] == 0 for r in results)
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
