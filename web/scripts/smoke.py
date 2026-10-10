#!/usr/bin/env python3
"""Headless-Chrome smoke of the built shell with MockCore (?mock=1): onboarding → home → send
preview. Plain WebDriver over HTTP (stdlib only) against a running chromedriver.
Usage: smoke.py <chromedriver-url> <page-url>"""
import json, sys, time, urllib.request

DRV, PAGE = sys.argv[1], sys.argv[2]

def req(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(DRV + path, data=data, method=method, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(r, timeout=30) as resp:
        return json.load(resp)["value"]

sess = req("POST", "/session", {"capabilities": {"alwaysMatch": {"goog:chromeOptions": {"args": ["--headless=new", "--window-size=480,900"]}}}})["sessionId"]
S = f"/session/{sess}"

def find(selector, using="css selector", timeout=10):
    end = time.time() + timeout
    while True:
        try:
            return req("POST", S + "/element", {"using": using, "value": selector})["element-6066-11e4-a52e-4f735466cecf"]
        except Exception:
            if time.time() > end: raise
            time.sleep(0.2)
def click(xpath): req("POST", S + f"/element/{find(xpath, 'xpath')}/click", {})
def type_into(css, text, idx=0):
    for _ in range(3):  # a blur may re-render the screen between find and type: re-find
        try:
            els = req("POST", S + "/elements", {"using": "css selector", "value": css})
            el = els[idx]["element-6066-11e4-a52e-4f735466cecf"]
            req("POST", S + f"/element/{el}/clear", {}); req("POST", S + f"/element/{el}/value", {"text": text}); return
        except (urllib.error.HTTPError, IndexError):
            time.sleep(0.3)
    raise SystemExit(f"could not type into {css}[{idx}]; page:\n" + req("POST", S + "/execute/sync", {"script": "return document.body.innerText", "args": []}))
def text_of(css, timeout=10): return req("GET", S + f"/element/{find(css, timeout=timeout)}/text")
def wait_text(css, needle, timeout=10):
    end = time.time() + timeout; t = ""
    while time.time() < end:
        try:
            t = req("POST", S + "/execute/sync", {"script": "return document.body.innerText", "args": []})
            if needle in t: return
        except Exception as e: t = f"(execute failed: {e})"
        time.sleep(0.2)
    raise SystemExit(f"'{needle}' not found; page:\n{t}")

try:
    req("POST", S + "/url", {"url": PAGE})
    wait_text("body", "Create a new wallet")
    click("//button[text()='Create a new wallet']")
    wait_text("body", "Your recovery phrase")
    words = [req("GET", S + f"/element/{e['element-6066-11e4-a52e-4f735466cecf']}/text") for e in req("POST", S + "/elements", {"using": "css selector", "value": "ol.seed li"})]
    assert len(words) == 12, words
    click("//button[text()='I have written it down']")
    wait_text("body", "Confirm your copy")
    inputs = req("POST", S + "/elements", {"using": "css selector", "value": "input[type=text]"})
    for i, el in enumerate(inputs):
        label = req("GET", S + f"/element/{el['element-6066-11e4-a52e-4f735466cecf']}/attribute/placeholder")
        n = int(label.split()[-1]); type_into("input[type=text]", words[n - 1], i)
    click("//button[text()='Continue']")
    wait_text("body", "Server")
    click("//button[text()='Check server']")
    wait_text("body", "Server ok · tip 1200")
    click("//button[text()='Continue']")
    wait_text("body", "What YEW trusts")
    click("//input[@type='checkbox']"); click("//button[text()='Continue']")
    wait_text("body", "Passphrase")
    type_into("input[type=password]", "correct horse battery", 0); type_into("input[type=password]", "correct horse battery", 1)
    click("//button[text()='Create wallet']")
    wait_text("body", "$125.00"); wait_text("body", "1.50000000 YEC"); wait_text("body", "mint price 1.92 YEC")
    click("//button[text()='Send']")
    wait_text("body", "Preview")
    type_into("input[type=text]", "ye1Recipient000000000000000000000000", 0)
    type_into("input[inputmode=decimal]", "25.00", 0)
    click("//button[text()='Preview']")
    wait_text("body", "Node verdict"); wait_text("body", "ok: valid, burns nothing, would be accepted")
    # the slider, driven to the end by keyboard, is the only path to confirm()
    slider = find("input.slide"); req("POST", S + f"/element/{slider}/click", {})
    req("POST", S + "/execute/sync", {"script": "const s=document.querySelector('input.slide'); s.value='100'; s.dispatchEvent(new Event('change'));", "args": []})
    wait_text("body", "Sent"); wait_text("body", "Copy txid")
    # reload: the seed is at rest, the unlock screen asks for the passphrase
    req("POST", S + "/url", {"url": PAGE}); wait_text("body", "Unlock")
    type_into("input[type=password]", "correct horse battery", 0); click("//button[text()='Unlock']")
    wait_text("body", "$125.00")
    print("smoke ok: onboarding → home → send preview → confirm → unlock after reload")
finally:
    req("DELETE", S)
