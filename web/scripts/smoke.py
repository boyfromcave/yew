#!/usr/bin/env python3
"""Headless-Chrome smoke of the built shell. Plain WebDriver over HTTP (stdlib only) against a
running chromedriver.

  smoke.py <chromedriver-url> <page-url>                      the W1b walk on MockCore (?mock=1)
  smoke.py <chromedriver-url> <page-url> --kind <helper-url> [--server <grpc-web-url>] [--insecure]
      the W2 walk on the real core against a running cluster: onboarding (new seed) → home 0 →
      public funding (the helper's /fund_t) → a public send to the node (/address) → private
      funding (/fund) → history → the proving files from the helper (/params/, the page's
      ?params=) → move 0.4 YEC to private → a private send with a memo to the wallet's own new
      address → reload → unlock → the balances persist (OPFS) → the Yellowback screens (mint
      halted on kind, no vault, nothing claimable). --server is typed at the server step; without
      it the page's own default (its origin when served over https) is kept. --insecure accepts the
      gateway's self-signed certificate. Timings are printed at the end.
"""
import json, sys, time, urllib.request

args = sys.argv[1:]
DRV, PAGE = args[0], args[1]
KIND = "--kind" in args
HELPER = args[args.index("--kind") + 1] if KIND else ""
SERVER = args[args.index("--server") + 1] if "--server" in args else ""
INSECURE = "--insecure" in args
PASS = "correct horse battery"

def req(method, path, body=None, timeout=60):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(DRV + path, data=data, method=method, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(r, timeout=timeout) as resp:
        return json.load(resp)["value"]

chrome_args = ["--headless=new", "--window-size=480,900"] + (["--ignore-certificate-errors"] if INSECURE else [])
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
    for _ in range(3):  # a re-render between find and click makes the element stale: re-find
        try: return req("POST", S + f"/element/{find(xpath, 'xpath', timeout)}/click", {})
        except urllib.error.HTTPError: time.sleep(0.3)
    raise SystemExit(f"could not click {xpath}; page:\n{body_text()}")
def type_into(css, text, idx=0):
    for _ in range(3):  # a blur may re-render the screen between find and type: re-find
        try:
            els = req("POST", S + "/elements", {"using": "css selector", "value": css})
            el = els[idx][EL]
            req("POST", S + f"/element/{el}/clear", {}); req("POST", S + f"/element/{el}/value", {"text": text}); return
        except (urllib.error.HTTPError, IndexError):
            time.sleep(0.3)
    raise SystemExit(f"could not type into {css}[{idx}]; page:\n{body_text()}")
def text_of(css, timeout=10): return req("GET", S + f"/element/{find(css, timeout=timeout)}/text")
def wait_text(needle, timeout=10, absent=False):
    end = time.time() + timeout; t = ""
    while time.time() < end:
        try:
            t = body_text()
            if (needle in t) != absent: return t
        except Exception as e: t = f"(execute failed: {e})"
        time.sleep(0.2)
    raise SystemExit(f"'{needle}' {'still' if absent else 'not'} found after {timeout}s; page:\n{t}")
def slide(label):
    """The slider, driven to the end by script, is the only path to confirm()."""
    find("input.slide")
    req("POST", S + "/execute/sync", {"script": "const s=document.querySelector('input.slide'); s.value='100'; s.dispatchEvent(new Event('change'));", "args": []})
def helper(path):
    for i in range(5):  # the helper may still be binding its port when the walk starts
        try:
            with urllib.request.urlopen(HELPER + path, timeout=600) as r:
                return r.read().decode().strip()
        except urllib.error.URLError as e:
            if i == 4 or not isinstance(e.reason, ConnectionRefusedError): raise
            time.sleep(1)

def onboard(server):
    req("POST", S + "/url", {"url": PAGE})
    wait_text("Create a new wallet", 30)
    click("//button[text()='Create a new wallet']")
    wait_text("Your recovery phrase")
    words = [req("GET", S + f"/element/{e[EL]}/text") for e in req("POST", S + "/elements", {"using": "css selector", "value": "ol.seed li"})]
    assert len(words) in (12, 24), words
    click("//button[text()='I have written it down']")
    wait_text("Confirm your copy")
    inputs = req("POST", S + "/elements", {"using": "css selector", "value": "input[type=text]"})
    for i, el in enumerate(inputs):
        label = req("GET", S + f"/element/{el[EL]}/attribute/placeholder")
        n = int(label.split()[-1]); type_into("input[type=text]", words[n - 1], i)
    click("//button[text()='Continue']")
    wait_text("Server")
    if server: type_into("input[type=url]", server)
    click("//button[text()='Check server']")
    wait_text("Server ok · tip", 30)
    click("//button[text()='Continue']")
    wait_text("What YEW trusts")
    click("//input[@type='checkbox']"); click("//button[text()='Continue']")
    wait_text("Passphrase")
    type_into("input[type=password]", PASS, 0); type_into("input[type=password]", PASS, 1)
    click("//button[text()='Create wallet']")

def unlock():
    wait_text("Unlock", 30)
    type_into("input[type=password]", PASS, 0); click("//button[text()='Unlock']")

def walk_mock():
    onboard("")
    wait_text("$125.00"); wait_text("1.50000000 YEC"); wait_text("mint price 1.92 YEC")
    click("//button[text()='Send']")
    wait_text("Preview")
    type_into("input[type=text]", "ye1Recipient000000000000000000000000", 0)
    type_into("input[inputmode=decimal]", "25.00", 0)
    click("//button[text()='Preview']")
    wait_text("Node verdict"); wait_text("ok: valid, burns nothing, would be accepted")
    slide("send")
    wait_text("Sent"); wait_text("Copy txid")
    # reload: the seed is at rest, the unlock screen asks for the passphrase
    req("POST", S + "/url", {"url": PAGE}); unlock()
    wait_text("$125.00")
    print("smoke ok: onboarding → home → send preview → confirm → unlock after reload")

def walk_kind():
    timings = []
    t_all = time.time()
    def lap(what, t0): timings.append((what, time.time() - t0)); print(f"  {what}: {time.time() - t0:.1f}s", flush=True)
    def home(): click("//nav/a[text()='Home']")
    def sync_until(needle, timeout=180, absent=False, pred=None):
        """Press Sync until `needle` shows (or goes, with absent) — a block or more may be needed."""
        end = time.time() + timeout
        while time.time() < end:
            t = body_text()
            if pred(t) if pred else (needle in t) != absent: return
            if "Syncing…" not in t:
                try: click("//button[text()='Sync']", 2)
                except SystemExit: pass
            time.sleep(1.5)
        raise SystemExit(f"'{needle}' {'still' if absent else 'never'} on the home screen after {timeout}s; page:\n{body_text()}")
    def send_yec(to, amount, memo, paid_from):
        click("//nav/a[text()='Send']"); wait_text("Preview")
        click("//div[@class='seg']/button[text()='YEC']")
        type_into("input[type=text]", to, 0)
        click("//h2[text()='Send']")  # blur: the recipient is checked, a memo field appears for ys1…
        if memo: wait_text("Message (")
        else: time.sleep(1)
        type_into("input[inputmode=decimal]", amount, 0)
        if memo: type_into("textarea", memo)
        click("//button[text()='Preview']")
        wait_text(paid_from, 60)
        t0 = time.time(); slide("send"); wait_text("Copy txid", 120); return t0

    t0 = time.time(); onboard(SERVER)
    wait_text("$0.00", 60); wait_text("0.00000000 YEC"); lap("onboarding (new seed, open, first sync)", t0)
    # the addresses
    click("//nav/a[text()='Receive']"); wait_text("Private YEC")
    addr_z = text_of("code.addr"); assert addr_z.startswith("yregtestsapling1"), addr_z
    click("//div[@class='seg']/button[text()='Public']"); wait_text("Public YEC")
    addr_t = text_of("code.addr"); assert addr_t.startswith("sm") or addr_t.startswith("s1") or addr_t.startswith("t"), addr_t
    print(f"  private {addr_z}\n  public  {addr_t}", flush=True)
    # public funding: 2 YEC
    t0 = time.time(); txid = helper(f"/fund_t?addr={addr_t}&zat=200000000"); print(f"  funded 2 YEC public in {txid}", flush=True)
    home(); sync_until("2.00000000 YEC"); lap("2 YEC public seen (helper answered → balance)", t0)
    # a public send to the node
    node_t = helper("/address")
    t0 = send_yec(node_t, "0.5", "", "your public balance"); lap("public send 0.5 YEC: confirm → Sent", t0)
    click("//button[text()='Done']")
    # private funding: 1.5 YEC
    t0 = time.time(); txid = helper(f"/fund?addr={addr_z}&zat=150000000"); print(f"  funded 1.5 YEC private in {txid}", flush=True)
    home(); sync_until("1.50000000 YEC"); lap("1.5 YEC private seen (helper answered → balance)", t0)
    # history
    click("//nav/a[text()='History']"); wait_text("received private YEC", 30); wait_text("sent YEC"); wait_text("received YEC")
    rows = req("POST", S + "/elements", {"using": "css selector", "value": "ul.list li"}); assert len(rows) >= 3, len(rows)
    print(f"  history: {len(rows)} rows", flush=True)
    # the proving files from the helper (the page's ?params= prefilled the Settings field)
    click("//header//a[text()='Settings']"); wait_text("Private sending files")
    wait_text("Not fetched"); t0 = time.time(); click("//button[starts-with(text(),'Fetch')]")
    wait_text("Ready (", 120); lap("fetch params (52 MB from the helper, verified, loaded)", t0)
    # move 0.4 YEC to private (a shield, proved in the worker)
    home(); click("//button[text()='Move…']"); wait_text("Move YEC")
    type_into("input[inputmode=decimal]", "0.4"); click("//button[text()='Preview']"); wait_text("your public balance", 60)
    t0 = time.time(); slide("move"); wait_text("Copy txid", 120); lap("move 0.4 YEC to private: confirm (prove + broadcast) → Moved", t0)
    click("//button[text()='Done']")
    # a private send with a memo to the wallet's own new address
    click("//nav/a[text()='Receive']"); click("//div[@class='seg']/button[text()='Private']"); wait_text("Private YEC"); click("//button[text()='New private address']")
    time.sleep(1); addr_z2 = text_of("code.addr"); assert addr_z2 != addr_z and addr_z2.startswith("yregtestsapling1"), addr_z2
    t0 = send_yec(addr_z2, "0.3", "hello from the web", "your private balance"); lap("private send 0.3 YEC z→z with a memo: confirm (prove + broadcast) → Sent", t0)
    click("//button[text()='Done']")
    # the memo on the pending row (once scanned as received by the same account the store drops
    # it: plan W1a finding 5, so it is checked now, not after the block)
    click("//nav/a[text()='History']"); wait_text("sent private YEC ✉", 30)
    click("//ul[@class='list']/li[1]"); detail = wait_text("txid")
    print("  memo shown on the pending row: " + ("yes" if "hello from the web" in detail else "NO (already scanned as received: W1a finding 5)"), flush=True)
    click("//button[text()='Back']")
    # wait for everything to be mined and the self-send credited (W1a finding 5: the private
    # total is lower by the sent amount until the scan sees the note as received, one sync
    # later), then remember the balances: private = 1.5 + 0.4 − the z→z fee (0.0001)
    t0 = time.time(); home(); sync_until("", 180, pred=lambda t: "pending" not in t and "1.8999" in t)
    before = body_text(); lap("everything mined and credited (no pending line)", t0)
    priv = [l for l in before.splitlines() if l.endswith("YEC")]
    print(f"  balances: {priv}", flush=True)
    # reload → unlock → the same balances from OPFS
    t0 = time.time(); req("POST", S + "/url", {"url": PAGE}); unlock()
    for line in priv: wait_text(line, 60)
    lap("reload → unlock → balances back", t0)
    # Yellowback: minting halted on kind, no vault, nothing claimable
    click("//nav/a[text()='Yellowback']"); wait_text("No open vault"); wait_text("$0.00")
    click("//button[text()='Mint']"); halted = wait_text("halted", 30)
    print("  mint: " + next(l for l in halted.splitlines() if "halted" in l), flush=True)
    click("//nav/a[text()='Yellowback']"); wait_text("No open vault"); click("//button[text()='Claimable']"); wait_text("Nothing is claimable right now.", 30)
    print(f"smoke ok (kind, {PAGE}): {time.time() - t_all:.0f}s total")
    for what, secs in timings: print(f"  {secs:6.1f}s  {what}")

try:
    walk_kind() if KIND else walk_mock()
finally:
    req("DELETE", S)
