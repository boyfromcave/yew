// YEW Web entry. The core (yew-web-core, WebAssembly) runs in a dedicated worker so proving and
// scanning never block the UI thread; this file only renders models and sends intents, exactly
// as app/lib does for the Flutter shell. Nothing here constructs bytes.
import { CoreClient } from "./core";

const app = document.getElementById("app")!;
const core = new CoreClient();

async function main() {
  app.textContent = "YEW Web — core loading…";
  const status = await core.status();
  app.textContent = `YEW Web — core ${status.version} (wasm), server ${status.server ?? "not connected"}`;
}

main().catch((e) => { app.textContent = `failed: ${e}`; });
