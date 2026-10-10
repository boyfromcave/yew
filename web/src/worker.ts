// The core's worker: loads yew-web-core (wasm-bindgen output in ./wasm/) and dispatches calls by
// method name, so a new contract method needs no change here. The two callbacks cannot cross
// postMessage: `set_progress_callback` installs a worker-side function that posts
// `{event: "progress"}` messages, and `fetch_params` one that posts `{event: "params"}`.
type Fn = (...a: unknown[]) => Promise<unknown>;
let core: Record<string, Fn> | null = null;

async function load() {
  try {
    const mod = await import("./wasm/yew_web_core.js");
    await mod.default();
    core = mod as unknown as Record<string, Fn>;
  } catch {
    core = { async status() { return { version: "stub (core-wasm not built yet)" }; } };
  }
}

const ready = load();

self.onmessage = async (ev: MessageEvent) => {
  const { id, method, args } = ev.data as { id: number; method: string; args: unknown[] };
  await ready;
  try {
    const c = core!;
    let value: unknown;
    if (method === "set_progress_callback") {
      const on = args[0] as boolean;
      value = await c.set_progress_callback(on ? (e: unknown) => self.postMessage({ event: "progress", value: e }) : null);
    } else if (method === "fetch_params") {
      value = await c.fetch_params((p: unknown) => self.postMessage({ event: "params", value: p }));
    } else {
      const fn = c[method];
      if (!fn) throw new Error(`unsupported: no such core method ${method}`);
      value = await fn(...args);
    }
    self.postMessage({ id, ok: true, value });
  } catch (e) {
    self.postMessage({ id, ok: false, error: e instanceof Error ? e.message : String(e) });
  }
};
