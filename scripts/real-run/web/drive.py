#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or https://www.opensource.org/licenses/mit-license.php .
"""WEB-REAL driver helpers: the browser wallet (through wd.py's session) and the regtest nodes
(through stack.json's ycash-cli lines). Imported by the phase scripts; `python drive.py <fn> args`
calls one helper from the shell and prints its result as JSON.
"""
import json
import os
import re
import subprocess
import sys
import time
from decimal import Decimal

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wd  # noqa: E402

STACK = os.environ.get('STACK_JSON', '')
OUT = os.environ.get('WEB_REAL_OUT', '.')
PASS = 'correct horse battery'
COIN = Decimal(100_000_000)


def stack():
    return json.load(open(STACK))


def cli(node, *args):
    st = stack()
    out = subprocess.run(st['cli%d' % node] + [str(a) for a in args], capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError('cli%d %s: %s' % (node, ' '.join(map(str, args)), out.stderr.strip()))
    s = out.stdout.strip()
    try:
        return json.loads(s, parse_float=Decimal)
    except ValueError:
        return s


def mine(n=1):
    h = cli(0, 'generate', n)
    time.sleep(1)
    return h


def addr_balance(addr):
    """The node's view of a transparent or post-quantum address (insight index on node 0): zat."""
    r = cli(0, 'getaddressbalance', json.dumps({'addresses': [addr]}))
    return int(r['balance'])


def wait_mempool_empty(secs=60):
    end = time.time() + secs
    while time.time() < end:
        if not cli(0, 'getrawmempool'):
            return True
        time.sleep(1)
    return False


def in_mempool(txid, secs=30):
    end = time.time() + secs
    while time.time() < end:
        if txid in cli(0, 'getrawmempool'):
            return True
        time.sleep(0.5)
    return False


def shot(name):
    p = os.path.join(OUT, 'shots', name + '.png')
    os.makedirs(os.path.dirname(p), exist_ok=True)
    wd.shot(p)
    return p


def console(tag):
    """Append the browser console since the last call to console.log; return the SEVERE lines."""
    try:
        entries = wd.logs()
    except Exception as e:  # noqa: BLE001
        entries = [{'level': 'DRIVER', 'message': str(e)}]
    with open(os.path.join(OUT, 'console.log'), 'a') as f:
        for e in entries:
            f.write('[%s] %s %s\n' % (tag, e.get('level'), e.get('message', '')))
    return [e.get('message', '') for e in entries if e.get('level') == 'SEVERE']


# --- the page ------------------------------------------------------------------------------

def nav(name):
    wd.click("//nav/a[text()='%s']" % name)


def onboard(page, server, words=None, birthday=0):
    """New wallet (words None: returns the shown words) or restore (words given)."""
    wd.req('POST', wd.sess() + '/url', {'url': page})
    wd.wait('Create a new wallet', 60)
    if words is None:
        wd.click("//button[text()='Create a new wallet']")
        wd.wait('Your recovery phrase')
        els = wd.req('POST', wd.sess() + '/elements', {'using': 'css selector', 'value': 'ol.seed li'})
        words = [wd.req('GET', wd.sess() + '/element/%s/text' % e[wd.EL]) for e in els]
        wd.click("//button[text()='I have written it down']")
        wd.wait('Confirm your copy')
        inputs = wd.req('POST', wd.sess() + '/elements', {'using': 'css selector', 'value': 'input[type=text]'})
        for i, el in enumerate(inputs):
            n = int(wd.req('GET', wd.sess() + '/element/%s/attribute/placeholder' % el[wd.EL]).split()[-1])
            wd.type_into('input[type=text]', words[n - 1], i)
        wd.click("//button[text()='Continue']")
    else:
        wd.click("//button[text()='Restore from a recovery phrase']")
        wd.wait('Recovery phrase')
        wd.type_into('textarea', ' '.join(words))
        wd.type_into('input[type=number]', str(birthday))
        wd.click("//button[text()='Continue']")
    wd.wait('Server', 30)
    wd.type_into('input[type=url]', server)
    wd.click("//button[text()='Check server']")
    wd.wait('Server ok · tip', 60)
    wd.click("//button[text()='Continue']")
    wd.wait('What YEW trusts', 30)
    wd.click("//input[@type='checkbox']")
    wd.click("//button[text()='Continue']")
    wd.wait('Passphrase', 30)
    wd.type_into('input[type=password]', PASS, 0)
    wd.type_into('input[type=password]', PASS, 1)
    wd.click("//button[starts-with(text(),'Create wallet') or starts-with(text(),'Restore wallet')]")
    return words


def unlock():
    wd.wait('Unlock', 60)
    wd.type_into('input[type=password]', PASS, 0)
    wd.click("//button[text()='Unlock']")


def receive(kind_label):
    """The address the Receive screen shows for a segment label (Private, Public (ECC), PQ · …)."""
    nav('Receive')
    before = ''
    try:
        before = wd.req('GET', wd.sess() + '/element/%s/text' % wd.find('code.addr', 'css selector', 5))
    except SystemExit:
        pass
    wd.click("//div[@class='seg']/button[text()='%s']" % kind_label)
    end = time.time() + 20
    while time.time() < end:
        try:
            a = wd.req('GET', wd.sess() + '/element/%s/text' % wd.find('code.addr', 'css selector', 5))
        except Exception:  # noqa: BLE001
            a = ''
        if a and (a != before or kind_label == 'Private'):
            return a
        time.sleep(0.3)
    raise SystemExit('no address for %s; page:\n%s' % (kind_label, wd.body_text()))


def sync_once(timeout=180):
    nav('Home')
    wd.wait('Ycash', 30)
    end = time.time() + timeout
    # an automatic sync may be running: wait for it, then press Sync and wait again
    while 'Syncing…' in wd.body_text() and time.time() < end:
        time.sleep(0.5)
    wd.click("//button[text()='Sync']")
    time.sleep(0.5)
    while 'Syncing…' in wd.body_text() and time.time() < end:
        time.sleep(0.5)


ROWS = {'Private': 'private', 'Public (ECC)': 'ecc', 'PQ · SLH-DSA (sqs…)': 'pq_slh', 'PQ · FN-DSA-512 (sqf…)': 'pq_falcon'}


def balances():
    """The home screen's YEC rows (zat) and the YED line, read from innerText."""
    nav('Home')
    wd.wait('Public (ECC)', 30)
    t = wd.body_text()
    lines = [x.strip() for x in t.splitlines()]
    out = {}
    for i, line in enumerate(lines):
        for label, key in ROWS.items():
            if line.startswith(label):
                rest = line[len(label):].strip() or (lines[i + 1] if i + 1 < len(lines) else '')
                m = re.search(r'(\d+\.\d{8}) YEC', rest)
                if m:
                    out[key] = int(Decimal(m.group(1)) * COIN)
    m = re.search(r'Yellowback\s*\n\s*\$([\d,]+\.\d\d)', t)
    if m:
        out['yed_cents'] = int(Decimal(m.group(1).replace(',', '')) * 100)
    out['pending'] = [x for x in lines if 'pending' in x or 'spendable now' in x or 'held' in x or 'staged' in x]
    return out


def settle(pred=None, timeout=240):
    """Sync until nothing is pending (and pred(balances) holds); return the balances."""
    end = time.time() + timeout
    b = {}
    while time.time() < end:
        sync_once()
        b = balances()
        if not b['pending'] and (pred is None or pred(b)):
            return b
        time.sleep(2)
    raise SystemExit('never settled: %s\n%s' % (b, wd.body_text()))


def send_yec(to, amount, from_addr='', memo=''):
    """Fill the Send screen (YEC) and press Preview; return the page text after the preview (or the error)."""
    nav('Send')
    wd.wait('Preview', 30)
    wd.click("//div[@class='seg']/button[text()='YEC']")
    time.sleep(0.5)
    if True:
        wd.js("const s=document.querySelector('select[aria-label=From]'); s.value=arguments[0]; s.dispatchEvent(new Event('change'));", from_addr)
        time.sleep(0.5)
    wd.type_into('input[type=text]', to, 0)
    wd.click("//h2[text()='Send']")
    time.sleep(1.2)
    wd.type_into('input[inputmode=decimal]', amount, 0)
    if memo:
        wd.type_into('textarea', memo)
    wd.click("//button[text()='Preview']")
    end = time.time() + 300
    while time.time() < end:
        t = wd.body_text()
        if 'Slide to' in t or 'Asking the node' not in t and ('error' in t.lower() or 'refused' in t.lower() or 'unsupported' in t.lower() or 'not available' in t.lower() or 'invalid' in t.lower()):
            return t
        time.sleep(0.5)
    return wd.body_text()


def slide():
    wd.find('input.slide', 'css selector', 30)
    wd.js("const s=document.querySelector('input.slide'); s.value='100'; s.dispatchEvent(new Event('change'));")


def confirm_and_txid(timeout=600):
    """Slide, wait for the result card; return (txid, seconds)."""
    t0 = time.time()
    slide()
    end = time.time() + timeout
    while time.time() < end:
        t = wd.body_text()
        if 'Copy txid' in t:
            secs = time.time() - t0
            short = wd.js("const c=document.querySelector('code.txid'); return c ? c.textContent : ''")
            head = re.match(r'[0-9a-f]+', short).group(0)
            tail = re.search(r'([0-9a-f]+)$', short).group(1)
            for _ in range(60):
                for txid in cli(0, 'getrawmempool'):
                    if txid.startswith(head) and txid.endswith(tail):
                        return txid, secs
                time.sleep(0.5)
            return 'NOT-IN-MEMPOOL:' + short, secs
        if re.search(r'(refused|error|failed|unsupported|rejected)', t, re.I) and 'Slide to' not in t:
            return None, t
        time.sleep(0.5)
    return None, wd.body_text()


def done():
    try:
        wd.click("//button[text()='Done']", 5)
    except SystemExit:
        pass


def tx_summary(txid):
    """Inputs (scripts/addresses, values), outputs, shielded counts and fee of a mined or mempool tx."""
    tx = cli(0, 'getrawtransaction', txid, 1)
    vin = []
    total_in = 0
    for i in tx['vin']:
        p = cli(0, 'getrawtransaction', i['txid'], 1)['vout'][i['vout']]
        vin.append({'addr': (p['scriptPubKey'].get('addresses') or [p['scriptPubKey'].get('type')])[0], 'zat': int(p['valueZat'])})
        total_in += int(p['valueZat'])
    vout = [{'addr': (o['scriptPubKey'].get('addresses') or [o['scriptPubKey'].get('type')])[0], 'zat': int(o['valueZat'])} for o in tx['vout']]
    vb = int(tx.get('valueBalanceZat', 0))
    fee = total_in + vb - sum(o['zat'] for o in vout)
    return {'vin': vin, 'vout': vout, 'spends': len(tx.get('vShieldedSpend', [])), 'outputs': len(tx.get('vShieldedOutput', [])),
            'valueBalanceZat': vb, 'fee': fee, 'size': tx.get('size'), 'height': tx.get('height')}


if __name__ == '__main__':
    fn = globals()[sys.argv[1]]
    print(json.dumps(fn(*sys.argv[2:]), default=str, indent=1))


def move(direction_label, amount):
    """Home → Move… → direction → amount → Preview → slide; returns (txid or None, seconds or text, preview text)."""
    nav('Home')
    wd.click("//button[text()='Move…']")
    wd.wait('Move YEC')
    wd.click("//div[@class='seg']/button[text()='%s']" % direction_label)
    time.sleep(0.5)
    wd.type_into('input[inputmode=decimal]', amount)
    wd.click("//button[text()='Preview']")
    end = time.time() + 300
    while time.time() < end:
        t = wd.body_text()
        if 'Slide to' in t or re.search(r'^(build|invalid|unsupported|network|refused)', t, re.M):
            break
        time.sleep(0.5)
    pre = wd.body_text()
    if 'Slide to' not in pre:
        return None, pre, pre
    txid, secs = confirm_and_txid()
    return txid, secs, pre
