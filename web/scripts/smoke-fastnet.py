#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or https://www.opensource.org/licenses/mit-license.php .
"""Headless-Chrome walk of the dev or preview page against a PUBLIC light-wallet server (the fast
testnet's gRPC-web endpoint), in steps, with a persistent browser profile so the wallet (OPFS,
IndexedDB) survives between them. Plain WebDriver over HTTP (stdlib only), as smoke.py.

  smoke-fastnet.py <chromedriver-url> <page-url> <profile-dir> restore <seed-file> <birthday> <server>
  smoke-fastnet.py <chromedriver-url> <page-url> <profile-dir> home
  smoke-fastnet.py <chromedriver-url> <page-url> <profile-dir> send <ytestsapling1…> <amount YEC>

The seed is read from a file and typed into the page; it is never printed. The passphrase is
$YEW_WEB_PASS (default a fixed test phrase). `send` fetches the proving files first if Settings
shows them missing (the page's ?params= names the source). Each step prints the home screen's
balance lines and its timings.
"""
import json, os, sys, time, urllib.error, urllib.request

DRV, PAGE, PROFILE, STEP = sys.argv[1:5]
REST = sys.argv[5:]
PASS = os.environ.get("YEW_WEB_PASS", "correct horse battery")

def req(method, path, body=None, timeout=120):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(DRV + path, data=data, method=method, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(r, timeout=timeout) as resp:
        return json.load(resp)["value"]

chrome_args = ["--headless=new", "--window-size=480,900", f"--user-data-dir={PROFILE}"]
sess = req("POST", "/session", {"capabilities": {"alwaysMatch": {"goog:chromeOptions": {"args": chrome_args}}}})["sessionId"]
S = f"/session/{sess}"
EL = "element-6066-11e4-a52e-4f735466cecf"

def body_text():
    return req("POST", S + "/execute/sync", {"script": "return document.body.innerText", "args": []})
def find(selector, using="css selector", timeout=10):
    end = time.time() + timeout
    while True:
        try:
            return req("POST", S + "/element", {"using": using, "value": selector})[EL]
        except Exception:
            if time.time() > end: raise SystemExit(f"no element {selector}; page:\n{body_text()}")
            time.sleep(0.2)
def click(xpath, timeout=10):
    for _ in range(3):
        try: return req("POST", S + f"/element/{find(xpath, 'xpath', timeout)}/click", {})
        except urllib.error.HTTPError: time.sleep(0.3)
    raise SystemExit(f"could not click {xpath}; page:\n{body_text()}")
def type_into(css, text, idx=0):
    for _ in range(3):
        try:
            el = req("POST", S + "/elements", {"using": "css selector", "value": css})[idx][EL]
            req("POST", S + f"/element/{el}/clear", {}); req("POST", S + f"/element/{el}/value", {"text": text}); return
        except (urllib.error.HTTPError, IndexError):
            time.sleep(0.3)
    raise SystemExit(f"could not type into {css}[{idx}]")
def wait_text(needle, timeout=10, absent=False, pred=None):
    end = time.time() + timeout; t = ""
    while time.time() < end:
        try:
            t = body_text()
            if pred(t) if pred else (needle in t) != absent: return t
        except Exception as e: t = f"(execute failed: {e})"
        time.sleep(0.3)
    raise SystemExit(f"'{needle}' {'still' if absent else 'not'} found after {timeout}s; page:\n{t}")
def slide():
    find("input.slide")
    req("POST", S + "/execute/sync", {"script": "const s=document.querySelector('input.slide'); s.value='100'; s.dispatchEvent(new Event('change'));", "args": []})
def lap(what, t0): print(f"  {what}: {time.time() - t0:.1f}s", flush=True)
def home(): click("//nav/a[text()='Home']")
def sync(timeout=600):
    """Press Sync once and wait until it is done."""
    t0 = time.time(); home()
    try: click("//button[text()='Sync']", 30)
    except SystemExit: pass
    time.sleep(1); wait_text("Syncing…", timeout, absent=True); lap("sync", t0)
def balances():
    t = body_text()
    lines = [l for l in t.splitlines() if l.endswith("YEC") or "pending" in l or "%" in l]
    print("  home: " + " | ".join(lines), flush=True)
    return t
def unlock():
    req("POST", S + "/url", {"url": PAGE})
    wait_text("Unlock", 60)
    type_into("input[type=password]", PASS, 0); click("//button[text()='Unlock']")
    wait_text("Sync", 60)

def restore(seed_file, birthday, server):
    words = " ".join(open(seed_file).read().split())
    t0 = time.time()
    req("POST", S + "/url", {"url": PAGE})
    wait_text("Restore from a recovery phrase", 60)
    click("//button[text()='Restore from a recovery phrase']")
    wait_text("Recovery phrase")
    type_into("textarea", words); type_into("input[type=number]", birthday)
    click("//button[text()='Continue']")
    wait_text("Check server")
    type_into("input[type=url]", server)
    click("//button[text()='Check server']")
    tip = wait_text("Server ok · tip", 60)
    print("  " + next(l for l in tip.splitlines() if "Server ok" in l), flush=True)
    click("//button[text()='Continue']")
    wait_text("What YEW trusts")
    click("//input[@type='checkbox']"); click("//button[text()='Continue']")
    wait_text("Passphrase")
    type_into("input[type=password]", PASS, 0); type_into("input[type=password]", PASS, 1)
    click("//button[text()='Restore wallet']")
    wait_text("Sync", 120); lap("restore → home", t0)
    sync(); balances()
    click("//nav/a[text()='Receive']"); wait_text("Private YEC")
    print("  private address " + req("GET", S + f"/element/{find('code.addr')}/text"), flush=True)

def send(to, amount):
    unlock(); sync(); balances()
    click("//header//a[text()='Settings']"); wait_text("Private sending files")
    if "Not fetched" in body_text():
        t0 = time.time(); click("//button[starts-with(text(),'Fetch')]"); wait_text("Ready (", 300); lap("fetch the proving files", t0)
    click("//nav/a[text()='Send']"); wait_text("Preview")
    click("//div[@class='seg']/button[text()='YEC']")
    type_into("input[type=text]", to, 0)
    click("//h2[text()='Send']"); wait_text("Message (", 30)
    type_into("input[inputmode=decimal]", amount, 0)
    type_into("textarea", "fastnet acceptance, web wallet")
    click("//button[text()='Preview']")
    pre = wait_text("your private balance", 120)
    print("  preview: " + " | ".join(l for l in pre.splitlines() if "fee" in l.lower() or "YEC" in l), flush=True)
    t0 = time.time(); slide(); wait_text("Copy txid", 300); lap("confirm (prove + broadcast) → Sent", t0)
    click("//button[text()='Done']")
    click("//nav/a[text()='History']"); wait_text("sent private YEC", 60)
    click("//ul[@class='list']/li[1]"); d = wait_text("txid", 30)
    print("  history row: " + " | ".join(d.splitlines()[:12]), flush=True)
    click("//button[text()='Back']")
    home(); balances()

try:
    if STEP == "restore": restore(*REST)
    elif STEP == "home": unlock(); sync(); balances()
    elif STEP == "send": send(*REST)
    else: raise SystemExit(f"unknown step {STEP}")
finally:
    req("DELETE", S)
