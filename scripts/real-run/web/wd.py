#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or https://www.opensource.org/licenses/mit-license.php .
"""A persistent WebDriver session over HTTP (stdlib only), for driving the browser wallet step by
step from the shell. The session id is kept in $WD_STATE (default ./wd-session).

  wd.py new [--headed]            start Chrome (headless unless --headed), print the session id
  wd.py url <url>                 navigate
  wd.py text                      the page's innerText
  wd.py click <xpath>             click (re-finds on a stale element)
  wd.py type <css> <text> [idx]   clear and type into the idx-th match
  wd.py js <script>               execute (return value printed as JSON)
  wd.py shot <file.png>           screenshot
  wd.py wait <needle> [secs]      wait until the page text contains needle
  wd.py logs                      the browser console log since the last call (chromedriver's)
  wd.py quit                      end the session
"""
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request

DRV = os.environ.get('WD_URL', 'http://127.0.0.1:9615')
STATE = os.environ.get('WD_STATE', 'wd-session')
EL = 'element-6066-11e4-a52e-4f735466cecf'


def req(method, path, body=None, timeout=900):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(DRV + path, data=data, method=method, headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return json.load(resp)['value']
    except urllib.error.HTTPError as e:
        raise RuntimeError(e.read().decode()[:600]) from None


def sess():
    return '/session/' + open(STATE).read().strip()


def body_text():
    return req('POST', sess() + '/execute/sync', {'script': 'return document.body.innerText', 'args': []})


def find(sel, using='xpath', timeout=15):
    end = time.time() + timeout
    while True:
        try:
            return req('POST', sess() + '/element', {'using': using, 'value': sel})[EL]
        except RuntimeError:
            if time.time() > end:
                raise SystemExit('no element %s; page:\n%s' % (sel, body_text()))
            time.sleep(0.3)


def click(xpath, timeout=15):
    for _ in range(4):
        try:
            return req('POST', sess() + '/element/%s/click' % find(xpath, timeout=timeout), {})
        except RuntimeError:
            time.sleep(0.4)
    raise SystemExit('could not click ' + xpath)


def type_into(css, text, idx=0):
    for _ in range(4):
        try:
            el = req('POST', sess() + '/elements', {'using': 'css selector', 'value': css})[idx][EL]
            req('POST', sess() + '/element/%s/clear' % el, {})
            req('POST', sess() + '/element/%s/value' % el, {'text': text})
            return
        except (RuntimeError, IndexError):
            time.sleep(0.4)
    raise SystemExit('could not type into %s[%d]' % (css, idx))


def js(script, *args):
    return req('POST', sess() + '/execute/sync', {'script': script, 'args': list(args)})


def wait(needle, secs=30, absent=False):
    end = time.time() + secs
    t = ''
    while time.time() < end:
        try:
            t = body_text()
            if (needle in t) != absent:
                return t
        except RuntimeError as e:
            t = str(e)
        time.sleep(0.3)
    raise SystemExit("'%s' %s after %ss; page:\n%s" % (needle, 'still there' if absent else 'not found', secs, t))


def shot(path):
    with open(path, 'wb') as f:
        f.write(base64.b64decode(req('GET', sess() + '/screenshot')))


def logs():
    return req('POST', sess() + '/se/log', {'type': 'browser'})


def new(headed=False):
    args = ['--window-size=520,1100']
    if not headed:
        args.insert(0, '--headless=new')
    caps = {'capabilities': {'alwaysMatch': {'goog:chromeOptions': {'args': args}, 'goog:loggingPrefs': {'browser': 'ALL'}}}}
    sid = req('POST', '/session', caps)['sessionId']
    with open(STATE, 'w') as f:
        f.write(sid)
    return sid


def main(a):
    cmd = a[0]
    if cmd == 'new':
        print(new('--headed' in a))
    elif cmd == 'url':
        req('POST', sess() + '/url', {'url': a[1]})
    elif cmd == 'text':
        print(body_text())
    elif cmd == 'click':
        click(a[1])
    elif cmd == 'type':
        type_into(a[1], a[2], int(a[3]) if len(a) > 3 else 0)
    elif cmd == 'js':
        print(json.dumps(js(a[1])))
    elif cmd == 'shot':
        shot(a[1])
    elif cmd == 'wait':
        wait(a[1], float(a[2]) if len(a) > 2 else 30)
    elif cmd == 'logs':
        for e in logs():
            print(e.get('level'), e.get('message', '')[:400])
    elif cmd == 'quit':
        req('DELETE', sess())
    else:
        raise SystemExit(__doc__)


if __name__ == '__main__':
    main(sys.argv[1:])
