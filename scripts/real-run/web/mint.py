#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or https://www.opensource.org/licenses/mit-license.php .
"""The browser mint: mint.py <label> <dollars> <lock blocks> [from key: '' public | pq_falcon | pq_slh].
Estimate → Start (carrier) → slide (fund) → mine → sync until "Slide to mint" → slide → mine →
"Minted". Prints the estimate rows, the carrier and MINT transactions and the YED balance."""
import json
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import drive as d  # noqa: E402
import wd  # noqa: E402

OUT = os.environ['WEB_REAL_OUT']


def mempool_new(before):
    return [t for t in d.cli(0, 'getrawmempool') if t not in before]


def main(label, dollars, lock, src=''):
    A = json.load(open(os.path.join(OUT, 'addrs.json')))
    rec = {'mint': label, 'dollars': dollars, 'lock': lock, 'from': src or 'public'}
    d.nav('Yellowback')
    time.sleep(1.5)
    wd.click("//button[text()='Mint']")
    wd.wait('Minting is open', 60)
    wd.js("const s=document.querySelector('select[aria-label=\"Fund from\"]'); s.value=arguments[0]; s.dispatchEvent(new Event('change'));", A[src] if src else '')
    time.sleep(0.5)
    wd.type_into('input[inputmode=decimal]', dollars)
    wd.type_into('input[type=number]', lock)
    wd.click("//button[text()='Estimate']")
    est = wd.wait('Collateral to lock', 120)
    d.shot('mint-%s-estimate' % label)
    rec['estimate'] = [x for x in est.splitlines() if x.strip()][:60]
    if 'Pay this fee' in est:
        wd.click("//button[starts-with(text(),'Pay this fee')]")
    before = d.cli(0, 'getrawmempool')
    wd.click("//button[starts-with(text(),'Start')]")
    wd.wait('Step 1 of 2', 120)
    t0 = time.time()
    d.slide()
    wd.wait('Step 2 of 2', 180)
    rec['carrier_confirm_s'] = round(time.time() - t0, 1)
    time.sleep(1)
    new = mempool_new(before)
    rec['carrier_txids'] = new
    d.mine(1)
    for t in new:
        rec.setdefault('carrier', []).append(d.tx_summary(t))
    end = time.time() + 300
    while True:
        if time.time() > end:
            d.shot('mint-%s-stuck' % label)
            raise SystemExit('the MINT never became stageable:\n' + wd.body_text())
        d.sync_once()
        d.nav('Yellowback')
        time.sleep(1)
        wd.click("//button[text()='Mint']")
        wd.wait('Step 2 of 2', 30)
        if 'Slide to mint' in wd.body_text():
            break
        try:
            wd.click("//button[text()='Check the carrier']", 2)
        except SystemExit:
            pass
        time.sleep(2)
        if 'Slide to mint' in wd.body_text():
            break
    d.shot('mint-%s-step2' % label)
    before = d.cli(0, 'getrawmempool')
    d.slide()
    page = wd.wait('MAIN_SENT', 120)
    new = mempool_new(before)
    rec['mint_txids'] = new
    d.mine(1)
    for t in new:
        rec.setdefault('mint_tx', []).append(d.tx_summary(t))
    end = time.time() + 300
    while 'Minted' not in wd.body_text():
        if time.time() > end:
            raise SystemExit('never Minted:\n' + wd.body_text())
        d.sync_once()
        d.nav('Yellowback')
        time.sleep(1)
        wd.click("//button[text()='Mint']")
        time.sleep(1)
        try:
            wd.click("//button[text()='Check the carrier']", 2)
        except SystemExit:
            pass
        time.sleep(2)
    d.shot('mint-%s-minted' % label)
    rec['minted'] = [x for x in wd.body_text().splitlines() if x.startswith('Minted')]
    try:
        wd.click("//button[text()='Done']", 5)
    except SystemExit:
        pass
    rec['balances'] = d.settle()
    print(json.dumps(rec, indent=1, default=str))
    open(os.path.join(OUT, 'mints.jsonl'), 'a').write(json.dumps(rec, default=str) + '\n')


if __name__ == '__main__':
    main(*sys.argv[1:])
