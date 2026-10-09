// The one place the UI talks to the core: a typed RPC to the worker hosting the WebAssembly
// module. The method set mirrors core/src/api.rs (plan §3.4 of the wallet plan); every method
// returns the same DTOs the Dart side sees, so screens port one to one.
export interface Status { version: string; server?: string; tip?: number; syncHeight?: number }

export class CoreClient {
  private worker = new Worker(new URL("./worker.ts", import.meta.url), { type: "module" });
  private seq = 0;
  private pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: unknown) => void }>();

  constructor() {
    this.worker.onmessage = (ev: MessageEvent) => {
      const { id, ok, value, error } = ev.data;
      const p = this.pending.get(id);
      if (!p) return;
      this.pending.delete(id);
      ok ? p.resolve(value) : p.reject(new Error(error));
    };
  }

  private call<T>(method: string, ...args: unknown[]): Promise<T> {
    const id = ++this.seq;
    return new Promise<T>((resolve, reject) => {
      this.pending.set(id, { resolve: resolve as (v: unknown) => void, reject });
      this.worker.postMessage({ id, method, args });
    });
  }

  status() { return this.call<Status>("status"); }
}
