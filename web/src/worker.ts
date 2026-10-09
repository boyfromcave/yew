// The core's worker: loads yew-web-core (wasm-bindgen output in ./wasm/) and dispatches calls.
// Until W0 produces the module, status() answers from a stub so the shell runs.
let core: { status(): Promise<unknown> } | null = null;

async function load() {
  try {
    const mod = await import("./wasm/yew_web_core.js");
    await mod.default();
    core = mod as unknown as { status(): Promise<unknown> };
  } catch {
    core = { async status() { return { version: "stub (core-wasm not built yet)" }; } };
  }
}

const ready = load();

self.onmessage = async (ev: MessageEvent) => {
  const { id, method, args } = ev.data;
  await ready;
  try {
    const fn = (core as unknown as Record<string, (...a: unknown[]) => Promise<unknown>>)[method];
    if (!fn) throw new Error(`no such core method: ${method}`);
    self.postMessage({ id, ok: true, value: await fn(...args) });
  } catch (e) {
    self.postMessage({ id, ok: false, error: String(e) });
  }
};
