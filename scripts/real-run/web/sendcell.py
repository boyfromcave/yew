#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or https://www.opensource.org/licenses/mit-license.php .
"""One send cell of the web walk: sendcell.py <label> <from: auto|pq_falcon|pq_slh> <to: a dst key or an own key> <amount>
Previews in the browser, confirms, checks the node's mempool, mines, summarizes the transaction,
compares every balance type with the node, appends a JSON line to $WEB_REAL_OUT/cells.jsonl."""
import json
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import drive as d  # noqa: E402
import wd  # noqa: E402

OUT = os.environ['WEB_REAL_OUT']


def own_ecc(A):
    p = os.path.join(OUT, 'own_ecc.json')
    return json.load(open(p)) if os.path.exists(p) else [A['ecc']]


def record_own(txid, to=''):
    """Add the transaction's own ECC outputs (its change; not `to`) to own_ecc.json: a Move or a
    mint also makes change on a fresh key, which the ECC comparison must count."""
    A = json.load(open(os.path.join(OUT, 'addrs.json')))
    own = own_ecc(A)
    for o in d.tx_summary(txid)['vout']:
        if o['addr'] and o['addr'] != to and o['addr'].startswith('sm') and o['addr'] not in own:
            own.append(o['addr'])
    json.dump(own, open(os.path.join(OUT, 'own_ecc.json'), 'w'))


def run(label, src, dst, amount, expect_refusal=False):
    A = json.load(open(os.path.join(OUT, 'addrs.json')))
    st = d.stack()
    to = st['dst'][dst] if dst in st['dst'] else A[dst[4:]] if dst.startswith('own_') else dst
    frm = A[src] if src != 'auto' else ''
    rec = {'cell': label, 'from': src, 'to': dst, 'amount': amount}
    t0 = time.time()
    page = d.send_yec(to, amount, frm, os.environ.get('MEMO', ''))
    rec['preview_s'] = round(time.time() - t0, 1)
    d.shot('cell-%s-preview' % label)
    lines = [x for x in page.splitlines() if x.strip()]
    rec['preview'] = ' | '.join(lines[lines.index('Send') if 'Send' in lines else 0:][:40])[:1500]
    if 'Slide to' not in page:
        rec['result'] = 'refused-at-preview'
        rec['message'] = [x for x in lines if re.search(r'(unsupported|Not available|refused|invalid|error|Fee)', x, re.I)][:4]
        print(json.dumps(rec, indent=1))
        open(os.path.join(OUT, 'cells.jsonl'), 'a').write(json.dumps(rec) + '\n')
        return rec
    txid, secs = d.confirm_and_txid()
    if not txid:
        rec['result'] = 'refused-at-confirm'
        rec['message'] = secs[:800]
        d.shot('cell-%s-confirm-fail' % label)
        print(json.dumps(rec, indent=1))
        open(os.path.join(OUT, 'cells.jsonl'), 'a').write(json.dumps(rec) + '\n')
        return rec
    rec['txid'], rec['confirm_s'] = txid, round(secs, 1)
    if txid.startswith('NOT-IN-MEMPOOL'):
        rec['result'] = 'NOT-IN-MEMPOOL'
        print(json.dumps(rec, indent=1))
        open(os.path.join(OUT, 'cells.jsonl'), 'a').write(json.dumps(rec) + '\n')
        return rec
    rec['mempool'] = d.in_mempool(txid)
    d.done()
    d.mine(1)
    rec['tx'] = d.tx_summary(txid)
    rec['mined'] = rec['tx']['height'] is not None
    own = own_ecc(A)
    for o in rec['tx']['vout']:
        if o['addr'] != to and o['addr'].startswith('sm') and o['addr'] not in own:
            own.append(o['addr'])
    json.dump(own, open(os.path.join(OUT, 'own_ecc.json'), 'w'))
    b = d.settle()
    node = {k: d.addr_balance(A[k]) for k in ('pq_falcon', 'pq_slh')}
    node['ecc'] = sum(d.addr_balance(a) for a in own)
    rec['browser'] = {k: b.get(k) for k in ('private', 'ecc', 'pq_falcon', 'pq_slh', 'yed_cents')}
    rec['node'] = node
    rec['agree'] = all(b.get(k) == node[k] for k in node)
    rec['result'] = 'ok' if rec['mempool'] and rec['mined'] and rec['agree'] else 'CHECK'
    print(json.dumps(rec, indent=1, default=str))
    open(os.path.join(OUT, 'cells.jsonl'), 'a').write(json.dumps(rec, default=str) + '\n')
    sev = d.console(label)
    if sev:
        print('SEVERE', sev)
    return rec


if __name__ == '__main__':
    run(*sys.argv[1:5])
