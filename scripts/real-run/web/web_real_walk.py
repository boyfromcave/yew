#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or https://www.opensource.org/licenses/mit-license.php .
"""The web wallet's real-stack walk (WEB-REAL), in phases, against the stack run.sh started.

  web_real_walk.py addr,fund,params,sends,private,arm,yed,persist,restore

addr     new seed in the browser; the address of every kind; the node's validateaddress on each
fund     3 YEC to the ECC address, 2 to each post-quantum address; balances per type = the node's
sends    the public cells: ECC -> ECC/Sapling/FN-DSA/SLH-DSA (Automatic, nothing private yet; the
         Sapling address is node 1's, so ECC -> Sapling is a payment to another wallet, WEB-FIX
         MEDIUM-4, and node 1's z_listreceivedbyaddress is printed),
         FN-DSA and SLH-DSA -> ECC/FN-DSA/SLH-DSA, and -> Sapling (refused: app only)
params   the proving files: a browser fetch of download.z.cash and of the zcash-params-v1 release
         (CORS, from a page without a CSP), a missing file on the page's own origin (404), an
         unreachable mirror, a corrupt one (the pins refuse it), then the default source: the
         page's own /sapling-params/ (WEB-FIX HIGH-2; with WEB_IMAGE the ycash-infra image serves
         them), else the loopback mirror (MIRROR, params_mirror.py)
private  Move 0.5 to private, 1.5 YEC to the Sapling address from the node, private -> Sapling
         with a memo, private -> ECC, private -> FN-DSA/SLH-DSA short of public YEC (refused),
         Move 0.3 to public
arm      three attestors on node 0 (yed_registerattestor), 20 blocks to ARMED; start attest_loop.py
yed      mint $100 from the public balance, 1 YED to node 1, plain YEC to the YED holder key spent
         from the browser (the token stays unspent), mint $100 from the FN-DSA address
fresh    a second, fresh browser profile with DEFAULT settings (WEB-FIX HIGH-2): restore the seed,
         fetch the proving files with Source empty (the page's own /sapling-params/), then a
         private send to node 1's Sapling address, mined; the renderer processes' peak RSS during it
persist  reload + unlock: balances equal
restore  wipe the site data (CDP Storage.clearDataForOrigin), restore with birthday 0: balances equal
Results: $WEB_REAL_OUT/cells.jsonl, mints.jsonl, console.log, shots/.
"""
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import drive as d  # noqa: E402
import wd  # noqa: E402
import sendcell  # noqa: E402

OUT = os.environ['WEB_REAL_OUT']
PAGE = os.environ.get('PAGE', 'http://localhost:29771/')
SERVER = os.environ.get('SERVER', 'http://127.0.0.1:29769')
MIRROR = os.environ.get('MIRROR', 'http://127.0.0.1:29777/')
CORRUPT = os.environ.get('MIRROR_CORRUPT', 'http://127.0.0.1:29775/')


def addrs():
    return json.load(open(os.path.join(OUT, 'addrs.json')))


def phase_addr():
    wd.new()
    words = d.onboard(PAGE, SERVER)
    json.dump(words, open(os.path.join(OUT, 'seed.json'), 'w'))
    wd.wait('Public (ECC)', 60)
    A = {}
    for label, k in [('Private', 'sapling'), ('Public (ECC)', 'ecc'), ('PQ · FN-DSA-512', 'pq_falcon'), ('PQ · SLH-DSA', 'pq_slh'), ('YED', 'yed')]:
        A[k] = d.receive(label)
        d.shot('receive-' + k)
    json.dump(A, open(os.path.join(OUT, 'addrs.json'), 'w'), indent=1)
    for k, a in A.items():
        v = d.cli(0, 'z_validateaddress' if k == 'sapling' else 'yed_validateaddress' if k == 'yed' else 'validateaddress', a)
        print('ADDR', k, a, {x: v.get(x) for x in ('isvalid', 'pqscheme', 'pqschemename', 'pqkeyhash', 'transparentAddress') if x in v}, flush=True)


def phase_fund():
    A = addrs()
    for k, amt in (('ecc', 3), ('pq_falcon', 2), ('pq_slh', 2)):
        d.cli(0, 'sendtoaddress', A[k], amt)
    d.mine(1)
    b = d.settle(lambda b: b.get('ecc', 0) and b.get('pq_slh', 0) and b.get('pq_falcon', 0))
    print('FUND browser', b, 'node', {k: d.addr_balance(A[k]) for k in ('ecc', 'pq_falcon', 'pq_slh')}, flush=True)


def phase_sends():
    for cell in (('ecc-ecc', 'auto', 'ecc'), ('ecc-sapling', 'auto', 'sapling'), ('ecc-pqf', 'auto', 'pq_falcon'), ('ecc-pqs', 'auto', 'pq_slh'),
                 ('pqf-ecc', 'pq_falcon', 'ecc'), ('pqf-pqf', 'pq_falcon', 'pq_falcon'), ('pqf-pqs', 'pq_falcon', 'pq_slh'), ('pqf-sapling', 'pq_falcon', 'sapling'),
                 ('pqs-ecc', 'pq_slh', 'ecc'), ('pqs-pqf', 'pq_slh', 'pq_falcon'), ('pqs-pqs', 'pq_slh', 'pq_slh'), ('pqs-sapling', 'pq_slh', 'sapling')):
        r = sendcell.run(*cell, '0.1')
        print('CELL', r['cell'], r['result'], r.get('tx', {}).get('fee'), r.get('message', ''), flush=True)
        if cell[0] == 'ecc-sapling' and r.get('txid'):
            got = [x for x in d.cli(1, 'z_listreceivedbyaddress', d.stack()['dst']['sapling'], 0) if x.get('txid') == r['txid']]
            print('THIRD-PARTY sapling received by node 1:', [(x.get('amount'), x.get('memoStr')) for x in got], flush=True)


def fetch_from(src, tag, secs=300):
    d.nav('Home')
    wd.click("//header//a[text()='Settings']")
    wd.wait('Private sending files')
    if 'Ready (' in wd.body_text():
        return 'already cached'
    wd.wait('Fetch (52 MB)', 20)
    # always typed: WebDriver's clear fires no input event, so an earlier mirror would stay in the
    # form's state; an empty source is a space and a backspace (two input events)
    wd.type_into('input[type=url]', src or ' \ue003')
    t0 = time.time()
    wd.click("//button[starts-with(text(),'Fetch')]")
    time.sleep(1)
    while time.time() - t0 < secs:
        t = wd.body_text()
        if 'Ready (' in t or ('Fetch (52 MB)' in t and ('network:' in t or 'params:' in t)):
            break
        time.sleep(0.5)
    d.shot('params-' + tag)
    msg = [x for x in wd.body_text().splitlines() if x.startswith(('network:', 'params:', 'Ready'))]
    print('PARAMS', tag, round(time.time() - t0, 1), 's', [m[:300] for m in msg], flush=True)
    return msg


RELEASE = 'https://github.com/boyfromcave/ycash-infra/releases/download/zcash-params-v1/'


def cors_probe():
    """Can a web page read the two public sources at all? A fetch from a page with no CSP (the
    loopback mirror's origin), so only CORS decides."""
    wd.req('POST', wd.sess() + '/url', {'url': MIRROR})
    script = ('const [u, done] = arguments; fetch(u).then(r => r.arrayBuffer().then(b => done("HTTP " + r.status + ", " + b.byteLength + " bytes")))'
              '.catch(e => done("refused: " + e.message));')
    for base in ('https://download.z.cash/downloads/', RELEASE):
        r = wd.req('POST', wd.sess() + '/execute/async', {'script': script, 'args': [base + 'sapling-output.params']})
        print('CORS', base, r, flush=True)
    wd.req('POST', wd.sess() + '/url', {'url': PAGE})
    d.unlock()
    wd.wait('Public (ECC)', 60)


def phase_params():
    cors_probe()
    fetch_from(PAGE.rstrip('/') + '/no-such-dir/', 'own-origin-404', 60)
    fetch_from('http://127.0.0.1:1/', 'unreachable', 60)
    fetch_from(CORRUPT, 'corrupt', 120)
    msg = fetch_from('', 'default')
    if not any(m.startswith('Ready') for m in msg or []) and msg != 'already cached':
        fetch_from(MIRROR, 'mirror')


def phase_private():
    A = addrs()
    txid, secs, _ = d.move('Public → private', '0.5')
    print('MOVE to private', txid, secs, flush=True)
    d.done()
    d.mine(1)
    sendcell.record_own(txid)
    z0 = d.cli(0, 'z_getnewaddress', 'sapling')
    try:
        d.cli(0, 'z_shieldcoinbase', '*', z0)
    except RuntimeError as e:  # nothing left to shield (a second walk): the ANY_TADDR path below
        print('PRIVATE shieldcoinbase', str(e)[:200], flush=True)
    time.sleep(5)
    d.mine(1)
    def z_send(frm, *extra):
        op = d.cli(0, 'z_sendmany', frm, json.dumps([{'address': A['sapling'], 'amount': 1.5}]), 1, *extra)
        for _ in range(60):
            st = d.cli(0, 'z_getoperationstatus', json.dumps([op]))[0]
            if st['status'] in ('success', 'failed'):
                return st
            time.sleep(1)
        return st
    st = z_send(z0)
    if st['status'] != 'success':
        # a second walk on the same stack: node 0's mature coinbase was shielded by the first, so
        # z0 is empty; pay from its transparent coins instead (repeatable walk)
        print('PRIVATE z0 send', st['status'], str(st.get('error', ''))[:200], '; from ANY_TADDR', flush=True)
        st = z_send('ANY_TADDR', 'null', 'AllowFullyTransparent')
        print('PRIVATE ANY_TADDR send', st['status'], str(st.get('error', ''))[:200], flush=True)
    d.mine(1)
    print('PRIVATE funded', d.settle(lambda b: b.get('private', 0) >= 200_000_000), flush=True)
    os.environ['MEMO'] = 'hello from the browser'
    sendcell.run('priv-sapling', 'auto', 'sapling', '0.3')
    os.environ['MEMO'] = ''
    for cell in (('priv-ecc', 'auto', 'ecc', '0.2'), ('priv-pqf-short', 'auto', 'pq_falcon', '9'), ('priv-pqs-short', 'auto', 'pq_slh', '9')):
        r = sendcell.run(*cell)
        print('CELL', r['cell'], r['result'], r.get('message', ''), flush=True)
    txid, secs, _ = d.move('Private → public', '0.3')
    print('MOVE to public', txid, secs, flush=True)
    d.done()
    d.mine(1)
    sendcell.record_own(txid)


def phase_arm():
    for _ in range(3):
        d.cli(0, 'yed_registerattestor', 10, 200)
        d.mine(1)
        time.sleep(2)
    d.mine(20)
    print('ARM', d.cli(0, 'yed_getinfo')['attest'].get('status'), flush=True)
    st = os.path.dirname(os.environ['STACK_JSON'])
    subprocess.Popen([sys.executable, os.path.join(HERE, 'attest_loop.py'), '50000000', '0,1,2'],
                     env=dict(os.environ, STOP_FILE=os.path.join(st, 'stop')),
                     stdout=open(os.path.join(OUT, 'attest.log'), 'w'), stderr=subprocess.STDOUT)
    time.sleep(4)
    d.mine(1)


def phase_yed():
    import mint
    A = addrs()
    # the pool's quote ages out (an hour or so into a run): quote again so the fast window fills
    d.cli(0, 'yed_setquote', 50000000, 1)
    d.mine(9)
    d.cli(0, 'sendtoaddress', A['ecc'], 10)
    d.cli(0, 'sendtoaddress', A['pq_falcon'], 10)
    d.mine(1)
    d.settle()
    # a page open since before the price came back keeps its "Waiting for a price" gate across
    # syncs (seen in the WEB-FIX re-run; reported, not fixed): reload so the Mint screen reads it
    wd.req('POST', wd.sess() + '/url', {'url': PAGE})
    d.unlock()
    wd.wait('Public (ECC)', 60)
    mint.main('pub', '100.00', '48')
    ye = d.cli(1, 'yed_getnewaddress')
    d.nav('Send')
    wd.wait('Preview', 30)
    wd.click("//div[@class='seg']/button[text()='YED']")
    wd.type_into('input[type=text]', ye, 0)
    wd.click("//h2[text()='Send']")
    time.sleep(1)
    wd.type_into('input[inputmode=decimal]', '1.00', 0)
    wd.click("//button[text()='Preview']")
    wd.wait('Node verdict', 120)
    txid, _ = d.confirm_and_txid()
    d.done()
    d.mine(1)
    info = d.cli(0, 'yed_gettxinfo', txid)
    print('YED send', txid, info['verdict'], info['assigned'], flush=True)
    holder = [a for a in info['assigned'] if a['cents'] != 100][0]
    hold_addr = d.cli(0, 'getrawtransaction', txid, 1)['vout'][holder['vout']]['scriptPubKey']['addresses'][0]
    d.cli(0, 'sendtoaddress', hold_addr, 0.5)
    d.mine(1)
    d.settle()
    A['holder'] = hold_addr
    json.dump(A, open(os.path.join(OUT, 'addrs.json'), 'w'), indent=1)
    wd.req('POST', wd.sess() + '/url', {'url': PAGE})
    d.unlock()
    wd.wait('Public (ECC)', 60)
    sendcell.run('holder-ecc', 'holder', 'ecc', '0.49')
    print('TOKEN still unspent:', d.cli(0, 'gettxout', txid, holder['vout']) is not None, flush=True)
    mint.main('pqf', '100.00', '48', 'pq_falcon')


def renderer_rss_kb():
    """RSS (KB) of every process under this run's chromedriver (Chrome, its renderers, GPU)."""
    root = open(os.path.join(OUT, 'chromedriver.pid')).read().strip()
    pids, todo = [], [root]
    while todo:
        p = todo.pop()
        kids = subprocess.run(['pgrep', '-P', p], capture_output=True, text=True).stdout.split()
        pids += kids
        todo += kids
    rows = subprocess.run(['ps', '-o', 'pid=,rss=,command=', '-p', ','.join(pids) or root], capture_output=True, text=True).stdout
    return [(int(r.split()[1]), ' '.join(r.split()[2:])) for r in rows.splitlines() if r.strip()]


def phase_fresh():
    import threading
    main = wd.STATE
    wd.STATE = main + '-fresh'
    wd.new()
    try:
        words = json.load(open(os.path.join(OUT, 'seed.json')))
        d.onboard(PAGE, SERVER, words=words, birthday=1)
        wd.wait('Public (ECC)', 120)
        d.settle(lambda b: b.get('private', 0) > 0, timeout=600)
        msg = fetch_from('', 'fresh-default')
        print('FRESH default source:', msg, flush=True)
        peak = {'renderer': 0, 'all': 0}
        stop = threading.Event()

        def sample():
            while not stop.is_set():
                rows = renderer_rss_kb()
                peak['renderer'] = max(peak['renderer'], max([kb for kb, c in rows if 'renderer' in c.lower()] or [0]))
                peak['all'] = max(peak['all'], sum(kb for kb, _ in rows))
                time.sleep(0.3)
        t = threading.Thread(target=sample, daemon=True)
        t.start()
        r = sendcell.run('fresh-priv-sapling', 'auto', 'sapling', '0.05')
        stop.set()
        t.join()
        print('CELL', r['cell'], r['result'], r.get('tx', {}).get('fee'), r.get('message', ''), flush=True)
        print('MEMORY peak renderer RSS %.0f MB, all Chrome processes %.0f MB' % (peak['renderer'] / 1024, peak['all'] / 1024), flush=True)
    finally:
        try:
            wd.req('DELETE', wd.sess())
        except RuntimeError:
            pass
        wd.STATE = main


def phase_persist():
    before = d.settle()
    wd.req('POST', wd.sess() + '/url', {'url': PAGE})
    d.unlock()
    wd.wait('Public (ECC)', 60)
    time.sleep(2)
    after = d.balances()
    print('PERSIST equal:', {k: before.get(k) == after.get(k) for k in ('private', 'ecc', 'pq_slh', 'pq_falcon', 'yed_cents')}, flush=True)


def phase_restore():
    before = d.settle()
    origin = PAGE.split('/#')[0].rstrip('/')
    wd.req('POST', wd.sess() + '/goog/cdp/execute', {'cmd': 'Storage.clearDataForOrigin', 'params': {'origin': origin, 'storageTypes': 'all'}})
    words = json.load(open(os.path.join(OUT, 'seed.json')))
    d.onboard(PAGE, SERVER, words=words, birthday=0)
    wd.wait('Public (ECC)', 120)
    after = d.settle(lambda b: b.get('private', 0) > 0 and b.get('yed_cents', 0) > 0, timeout=600)
    print('RESTORE equal:', {k: before.get(k) == after.get(k) for k in ('private', 'ecc', 'pq_slh', 'pq_falcon', 'yed_cents')}, flush=True)


if __name__ == '__main__':
    for p in sys.argv[1].split(','):
        print('== phase', p, flush=True)
        globals()['phase_' + p]()
