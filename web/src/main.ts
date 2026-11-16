// YEW Web entry. The core (yew-web-core, WebAssembly) runs in a dedicated worker so proving and
// scanning never block the UI thread; this file wires the screens to the view-models and the
// view-models to the core, exactly as app/lib does for the Flutter shell. Nothing here
// constructs bytes. MockCore, for development and tests, runs only on the dev server (`?mock=1`)
// or in a build made with VITE_MOCK=1; every other build ignores `?mock` and does not contain it.
import "./style.css";
import type { Core } from "./core";
import { CoreClient, messageOf, serialized } from "./core";
import { clear, currentRoute, go, h, onRoute } from "./dom";
import * as keystore from "./keystore";
import { mockMode, networkBanner, setNetwork } from "./prefixes";
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
import { defaultServerFor } from "./servers";
import { OPEN_ELSEWHERE, openElsewhere } from "./plain";

const app = document.getElementById("app")!;
const query = new URLSearchParams(location.search);
/** A build that may run the mock at all (a constant after the build: false removes the mock chunk). */
const mockBuild: boolean = import.meta.env.DEV || import.meta.env.VITE_MOCK === "1";
const useMock = mockBuild && mockMode({ dev: import.meta.env.DEV, flag: import.meta.env.VITE_MOCK }, location.search);
// The mock never touches the wallet's keystore: its (public) seed goes to a database of its own.
if (useMock) keystore.useDatabase("yew-mock");
/** The network the wallet is for (W2: regtest on the kind cluster; `VITE_NETWORK` for a build). */
const network = import.meta.env.VITE_NETWORK || "regtest";
/** A build served apart from its light-client server (the hosted fast-testnet wallet) names the
 *  server: `VITE_DEFAULT_SERVER`; vite.config.ts puts the same origin in the page's connect-src. */
const hostedServer: string = import.meta.env.VITE_DEFAULT_SERVER || "";
/** The server field's default: the mock's in mock mode, else the hosted build's server, else
 *  `servers.ts` (the fast testnet's server for a testnet build, the gateway's own origin over
 *  https, none in the dev loop). */
const defaultServer = !useMock && hostedServer ? hostedServer : defaultServerFor(network, location, useMock);
/** The hosted build's one server, or "": the server cannot be changed and the proving files come from
 *  this site only (the page's policy allows nothing else). */
const fixedServer = !useMock && hostedServer ? hostedServer : "";
/** `?params=<base URL>`: a mirror for the proving files (the test helper); the Settings field. */
const paramsSource = query.get("params") ?? "";

async function makeCore(): Promise<Core> {
  if (mockBuild && useMock) { const { MockCore } = await import("./mock"); return new MockCore({ delayMs: 50 }); }
  const c = new CoreClient(); await c.install_storage(); return c;
}

async function main() {
  const note = networkBanner(network);
  if (note) document.body.prepend(h("div", { class: "netbanner", role: "note" }, note));
  app.textContent = "YEW — loading…";
  const core = serialized(await makeCore());
  const version = (await core.status()).version;
  let meta = await keystore.walletMeta();
  let method = await keystore.unlockMethod();
  let open = false;

  const home = new HomeVm(core), receive = new ReceiveVm(core), send = new SendVm(core), move = new SendVm(core, "yec");
  const history = new HistoryVm(core), settings = new SettingsVm(core, keystore, paramsSource, network, !!fixedServer), yb = new YellowbackVm(core);
  let unsub: (() => void) | undefined;

  const shell = (name: string, body: HTMLElement) => {
    clear(app);
    const link = (n: string, label: string) => h("a", { href: `#/${n}`, class: name === n ? "active" : "" }, label);
    app.append(h("header", { class: "top" }, h("h1", null, "YEW"), h("span", null, link("settings", "Settings"))), body,
      h("nav", null, link("home", "Home"), link("send", "Send"), link("receive", "Receive"), link("history", "History"), link("yellowback", "Yellowback")));
  };

  // Receive's addresses are asked for here, before the first sync takes the core: the core answers one
  // call at a time, and behind a sync an address took up to 15 s (beta3, the hosted acceptance run)
  const opened = async () => { open = true; meta = await keystore.walletMeta(); setNetwork(meta?.network || network); receive.clear(); void receive.prime(); method = await keystore.unlockMethod(); await home.attach(); await home.load(); home.sync(); home.autoSync(); go("home"); route(); };
  // a sync can use up the shown public / post-quantum / YED address (the core moves to the next unused one)
  home.onSynced(() => { yb.onSynced(); void receive.refreshRotating(); });
  const unlockScreen = async (method: "prf" | "passphrase") => {
    clear(app); const body = h("div"); app.append(body);
    renderUnlock(body, method, async (u) => {
      const { seedWords, meta: m } = await keystore.unlockSeed(u);
      setNetwork(m.network || network);
      if (m.storeDir) await core.open_at(seedWords, m.birthday, m.serverUrl, m.network || network, m.storeDir);
      else await core.open(seedWords, m.birthday, m.serverUrl, m.network || network);
      await opened();
    }, async () => {
      const m = await keystore.walletMeta(); await keystore.forget();
      await core.forget(keystore.storeDirOf(m, network)).catch(() => {});
      location.reload();
    }, keystore.cancelPasskey);
  };
  const onboard = () => {
    clear(app); const body = h("div"); app.append(body);
    setNetwork(network);
    const vm = new OnboardingVm(core, keystore, defaultServer, network, !!fixedServer);
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
      case "settings": unsub = renderSettings(body, settings, meta, version, () => { open = false; home.stopAutoSync(); receive.clear(); route(); }, fixedServer); break;
      case "yellowback": unsub = renderYellowback(body, yb, home.state.balances?.termsRefused ? "" : home.state.balances?.yedCents ?? "0"); break;
      case "mint": unsub = renderMint(body, yb, () => home.state.balances); break;
      case "vault": unsub = renderVault(body, yb, r.arg); break;
      case "claimable": unsub = renderClaimable(body, yb); break;
      default: unsub = renderHome(body, home); home.load();
    }
  }
  onRoute(() => route());
}

// A second tab or window on the same wallet: the first one holds the storage, and this one says so
// plainly (never the storage's internal error); the first tab is not touched.
main().catch((e) => { const m = messageOf(e); app.textContent = openElsewhere(m) ? OPEN_ELSEWHERE : `failed: ${m}`; });
