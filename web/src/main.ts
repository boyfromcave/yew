// YEW Web entry. The core (yew-web-core, WebAssembly) runs in a dedicated worker so proving and
// scanning never block the UI thread; this file wires the screens to the view-models and the
// view-models to the core, exactly as app/lib does for the Flutter shell. Nothing here
// constructs bytes. `?mock=1` (or VITE_MOCK=1) swaps in MockCore for development and tests.
import "./style.css";
import type { Core } from "./core";
import { CoreClient, messageOf, serialized } from "./core";
import { clear, currentRoute, go, h, onRoute } from "./dom";
import * as keystore from "./keystore";
import { renderOnboarding, renderUnlock } from "./screens/onboarding";
import { renderHome } from "./screens/home";
import { renderReceive } from "./screens/receive";
import { renderMove, renderSend } from "./screens/send";
import { renderHistory } from "./screens/history";
import { renderSettings } from "./screens/settings";
import { renderClaimable, renderMint, renderVault, renderYellowback } from "./screens/yellowback";
import { OnboardingVm } from "./vm/onboarding";
import { HomeVm } from "./vm/home";
import { ReceiveVm } from "./vm/receive";
import { SendVm } from "./vm/send";
import { HistoryVm } from "./vm/history";
import { SettingsVm } from "./vm/settings";
import { YellowbackVm } from "./vm/yellowback";

const app = document.getElementById("app")!;
const query = new URLSearchParams(location.search);
const useMock = query.get("mock") === "1" || import.meta.env.VITE_MOCK === "1";
/** The network the wallet is for (W2: regtest on the kind cluster; `VITE_NETWORK` for a build). */
const network = import.meta.env.VITE_NETWORK || "regtest";
/** Served by the gateway (https), the API is on this origin: the server field defaults to it.
 *  The dev loop (vite over http) keeps an explicit URL (the plain :9067 listener). */
const defaultServer = useMock ? "http://localhost:8080" : location.protocol === "https:" ? `https://${location.hostname}:${location.port || "443"}` : "";
/** `?params=<base URL>`: a mirror for the proving files (the test helper); the Settings field. */
const paramsSource = query.get("params") ?? "";

async function makeCore(): Promise<Core> {
  if (useMock) { const { MockCore } = await import("./mock"); return new MockCore({ delayMs: 50 }); }
  const c = new CoreClient(); await c.install_storage(); return c;
}

async function main() {
  app.textContent = "YEW — loading…";
  const core = serialized(await makeCore());
  const version = (await core.status()).version;
  let meta = await keystore.walletMeta();
  let method = await keystore.unlockMethod();
  let open = false;

  const home = new HomeVm(core), receive = new ReceiveVm(core), send = new SendVm(core), move = new SendVm(core, "yec");
  const history = new HistoryVm(core), settings = new SettingsVm(core, keystore, paramsSource), yb = new YellowbackVm(core);
  let unsub: (() => void) | undefined;

  const shell = (name: string, body: HTMLElement) => {
    clear(app);
    const link = (n: string, label: string) => h("a", { href: `#/${n}`, class: name === n ? "active" : "" }, label);
    app.append(h("header", { class: "top" }, h("h1", null, "YEW"), h("span", null, link("settings", "Settings"))), body,
      h("nav", null, link("home", "Home"), link("send", "Send"), link("receive", "Receive"), link("history", "History"), link("yellowback", "Yellowback")));
  };

  const opened = async () => { open = true; meta = await keystore.walletMeta(); method = await keystore.unlockMethod(); await home.attach(); await home.load(); home.sync(); go("home"); route(); };
  const unlockScreen = async (method: "prf" | "passphrase") => {
    clear(app); const body = h("div"); app.append(body);
    renderUnlock(body, method, async (u) => {
      const { seedWords, meta: m } = await keystore.unlockSeed(u);
      await core.open(seedWords, m.birthday, m.serverUrl, m.network || network);
      await opened();
    }, async () => { await keystore.forget(); location.reload(); });
  };
  const onboard = () => {
    clear(app); const body = h("div"); app.append(body);
    const vm = new OnboardingVm(core, keystore, defaultServer, network);
    renderOnboarding(body, vm);
    let done = false;
    vm.subscribe(() => { if (vm.state.step === "done" && !done) { done = true; opened(); } });
  };

  function route() {
    unsub?.(); unsub = undefined;
    if (!open) { if (useMock && currentRoute().name === "onboard") onboard(); else if (method) unlockScreen(method); else onboard(); return; }
    const r = currentRoute(); const body = h("div");
    shell(r.name, body);
    switch (r.name) {
      case "send": unsub = renderSend(body, send); break;
      case "move": unsub = renderMove(body, move); break;
      case "receive": unsub = renderReceive(body, receive); break;
      case "history": unsub = renderHistory(body, history); break;
      case "settings": unsub = renderSettings(body, settings, meta, version, () => { open = false; route(); }); break;
      case "yellowback": unsub = renderYellowback(body, yb, home.state.balances?.yedCents ?? "0"); break;
      case "mint": unsub = renderMint(body, yb); break;
      case "vault": unsub = renderVault(body, yb, r.arg); break;
      case "claimable": unsub = renderClaimable(body, yb); break;
      default: unsub = renderHome(body, home); home.load();
    }
  }
  onRoute(() => route());
}

main().catch((e) => { app.textContent = `failed: ${messageOf(e)}`; });
