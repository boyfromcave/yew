// The one place the UI talks to the core: a typed RPC to the worker hosting the WebAssembly
// module (yew-web-core). The surface is the W1a contract (scratchpad API-yew-web-core.md):
// method names mirror core/src/api.rs, every call is async, every error is an Error whose
// message is "<kind>: <detail>" (kinds: busy, unsupported, network, store, gate, build, params,
// invalid). Amounts are strings (u64 zat / cents), heights are numbers. Nothing here constructs
// bytes; the screens render these DTOs and send intents, as app/lib does for Flutter.

export type AddressKind = "shielded" | "transparent" | "yed";
export type MoveDirection = "to_private" | "to_public";

export interface Status { version: string; server?: string; tip?: number; syncHeight?: number; open?: boolean }
export interface SyncResult { tip: number; scanned_height: number; blocks: number; received_notes: number; millis: number }
export interface Progress { pct: number; phase: string }
export interface ProgressEvent { phase: string; pct: number; height: number; tip: number }
export interface ShieldedBalance { total_zat: string; spendable_zat: string; pending_incoming_zat: string }
export interface Balances {
  yecZat: string; yecPendingZat: string; yedCents: string; yedPendingCents: string;
  /** Price in cents per YEC (the server's `GetPrice.pMint`); "0" when undefined. */
  priceCents: string; shieldedZat: string; shieldedSpendableZat: string;
}
export interface HistoryRow {
  txid: string; height: number; kind: string; yecDelta: string; yedDelta: string;
  verdict: string; pending: boolean; memo: string;
}
export interface ParamsStatus { present: boolean; bytes: number; needed: number }
export interface ParamsProgress { bytesDone: number; bytesTotal: number; name: string }
export interface YecPreview { previewId: string; fee: string; change: string; revealsShielded: boolean; funding: string }
export interface YedPreview { previewId: string; inputs: number; feeZat: string; verdict: string }
export interface MovePreview { previewId: string; fee: string }
export interface MintEstimate {
  cents: string; lockBlocks: number; termClass: string; refHeight: number; lockHeight: number;
  claimHeight: number; expiryHeight: number; collateralZat: string; feeZat: string; attestFeeZat: string; payee: string;
}
export interface MintStart { mintId: number; previewId: string }
export interface MintStatus {
  mintId: number; kind: string; state: string; cents: string; lockBlocks: number; termClass: string;
  collateralZat: string; vaultTxid: string; inProgress: boolean; canSweep: boolean;
}
export interface Vault {
  vaultTxid: string; status: string; ownerAddress: string; termClass: string; cents: string;
  collateralZat: string; lockHeight: number; claimHeight: number; mintHeight: number; tip: number;
  open: boolean; redeemable: boolean; blocksToLock: number;
}
export interface RedeemPreview { previewId: string; vaultTxid: string; returnedZat: string; burnCents: string; feeZat: string; payee: string }
export interface ClaimableItem {
  vaultTxid: string; ownerAddress: string; cents: string; collateralZat: string; claimHeight: number;
  claimPath: string; feeZat: string; residualZat: string; claimantZat: string; payee: string;
}
export interface ClaimPreview { previewId: string; vaultTxid: string; burnCents: string; claimantZat: string; feeZat: string }
export interface Confirmed { txid: string }
export interface AddressCheck { valid: boolean; kind: string }

/** The contract. `MockCore` (mock.ts) and `CoreClient` (the worker) both implement it. */
export interface Core {
  install_storage(): Promise<void>;
  new_seed_words(): Promise<string>;
  latest_height(serverUrl: string): Promise<number>;
  open(seedWords: string, birthday: number, serverUrl: string): Promise<void>;
  open_at(storeName: string, seedWords: string, birthday: number, serverUrl: string): Promise<void>;
  sync(): Promise<SyncResult>;
  progress(): Promise<Progress>;
  shielded_balance(): Promise<ShieldedBalance>;
  receive_address(kind: AddressKind): Promise<string>;
  new_shielded_address(): Promise<string>;
  network(): Promise<string>;
  close(): Promise<void>;
  status(): Promise<Status>;
  set_progress_callback(fn: ((e: ProgressEvent) => void) | null): Promise<void>;
  balances(): Promise<Balances>;
  history(page: number): Promise<HistoryRow[]>;
  params_status(): Promise<ParamsStatus>;
  fetch_params(fn: (p: ParamsProgress) => void): Promise<void>;
  send_yec_preview(to: string, zat: string, memo?: string): Promise<YecPreview>;
  send_yed_preview(to: string, cents: string): Promise<YedPreview>;
  move_preview(direction: MoveDirection, zat: string): Promise<MovePreview>;
  mint_estimate(cents: string, lockBlocks: number): Promise<MintEstimate>;
  mint_start(cents: string, lockBlocks: number): Promise<MintStart>;
  mint_finish(mintId: number): Promise<MintStatus>;
  mint_sweep(mintId: number): Promise<MintStatus>;
  vaults(): Promise<Vault[]>;
  redeem_preview(vaultTxid: string): Promise<RedeemPreview>;
  claimable(): Promise<ClaimableItem[]>;
  claim_preview(vaultTxid: string): Promise<ClaimPreview>;
  /** The ONLY path that signs and broadcasts; passes gate.rs. */
  confirm(previewId: string): Promise<Confirmed>;
  export_wif(address: string): Promise<string>;
  import_wif(wif: string, birthday: number): Promise<void>;
  validate_address(s: string): Promise<AddressCheck>;
}

/** The text to show for any core error: the message verbatim (a gate refusal is the node's verdict). */
export function messageOf(e: unknown): string { return e instanceof Error ? e.message : String(e); }
/** The kind prefix of a core error ("gate", "network", …) or "" for anything else. */
export function kindOf(e: unknown): string {
  const m = messageOf(e); const i = m.indexOf(":"); return i > 0 ? m.slice(0, i).trim() : "";
}

type Pending = { resolve: (v: unknown) => void; reject: (e: unknown) => void };

/** The worker bridge. Calls are dispatched by method name; the two callbacks (sync progress,
 *  params fetch) arrive as `{event}` messages from the worker (worker.ts). */
export class CoreClient implements Core {
  private worker: Worker;
  private seq = 0;
  private pending = new Map<number, Pending>();
  private onProgress: ((e: ProgressEvent) => void) | null = null;
  private onParams: ((p: ParamsProgress) => void) | null = null;

  constructor(worker?: Worker) {
    this.worker = worker ?? new Worker(new URL("./worker.ts", import.meta.url), { type: "module" });
    this.worker.onmessage = (ev: MessageEvent) => {
      const d = ev.data;
      if (d.event === "progress") { this.onProgress?.(d.value); return; }
      if (d.event === "params") { this.onParams?.(d.value); return; }
      const p = this.pending.get(d.id);
      if (!p) return;
      this.pending.delete(d.id);
      d.ok ? p.resolve(d.value) : p.reject(new Error(d.error));
    };
  }

  private call<T>(method: string, ...args: unknown[]): Promise<T> {
    const id = ++this.seq;
    return new Promise<T>((resolve, reject) => {
      this.pending.set(id, { resolve: resolve as (v: unknown) => void, reject });
      this.worker.postMessage({ id, method, args });
    });
  }

  install_storage() { return this.call<void>("install_storage"); }
  new_seed_words() { return this.call<string>("new_seed_words"); }
  latest_height(serverUrl: string) { return this.call<number>("latest_height", serverUrl); }
  open(seedWords: string, birthday: number, serverUrl: string) { return this.call<void>("open", seedWords, birthday, serverUrl); }
  open_at(storeName: string, seedWords: string, birthday: number, serverUrl: string) { return this.call<void>("open_at", storeName, seedWords, birthday, serverUrl); }
  sync() { return this.call<SyncResult>("sync"); }
  progress() { return this.call<Progress>("progress"); }
  shielded_balance() { return this.call<ShieldedBalance>("shielded_balance"); }
  receive_address(kind: AddressKind) { return this.call<string>("receive_address", kind); }
  new_shielded_address() { return this.call<string>("new_shielded_address"); }
  network() { return this.call<string>("network"); }
  close() { return this.call<void>("close"); }
  status() { return this.call<Status>("status"); }
  async set_progress_callback(fn: ((e: ProgressEvent) => void) | null) {
    this.onProgress = fn;
    await this.call<void>("set_progress_callback", fn !== null);
  }
  balances() { return this.call<Balances>("balances"); }
  history(page: number) { return this.call<HistoryRow[]>("history", page); }
  params_status() { return this.call<ParamsStatus>("params_status"); }
  async fetch_params(fn: (p: ParamsProgress) => void) {
    this.onParams = fn;
    try { await this.call<void>("fetch_params"); } finally { this.onParams = null; }
  }
  send_yec_preview(to: string, zat: string, memo?: string) { return this.call<YecPreview>("send_yec_preview", to, zat, memo); }
  send_yed_preview(to: string, cents: string) { return this.call<YedPreview>("send_yed_preview", to, cents); }
  move_preview(direction: MoveDirection, zat: string) { return this.call<MovePreview>("move_preview", direction, zat); }
  mint_estimate(cents: string, lockBlocks: number) { return this.call<MintEstimate>("mint_estimate", cents, lockBlocks); }
  mint_start(cents: string, lockBlocks: number) { return this.call<MintStart>("mint_start", cents, lockBlocks); }
  mint_finish(mintId: number) { return this.call<MintStatus>("mint_finish", mintId); }
  mint_sweep(mintId: number) { return this.call<MintStatus>("mint_sweep", mintId); }
  vaults() { return this.call<Vault[]>("vaults"); }
  redeem_preview(vaultTxid: string) { return this.call<RedeemPreview>("redeem_preview", vaultTxid); }
  claimable() { return this.call<ClaimableItem[]>("claimable"); }
  claim_preview(vaultTxid: string) { return this.call<ClaimPreview>("claim_preview", vaultTxid); }
  confirm(previewId: string) { return this.call<Confirmed>("confirm", previewId); }
  export_wif(address: string) { return this.call<string>("export_wif", address); }
  import_wif(wif: string, birthday: number) { return this.call<void>("import_wif", wif, birthday); }
  validate_address(s: string) { return this.call<AddressCheck>("validate_address", s); }
}

/** One call at a time: the core rejects a second call while one is in progress ("busy"), and
 *  two screens (a recipient check on blur, Preview on click) can race for it. The shell talks
 *  to the core through this queue, so a call waits instead of failing. */
export function serialized(core: Core): Core {
  let tail: Promise<unknown> = Promise.resolve();
  return new Proxy(core, {
    get(target, prop, receiver) {
      const v = Reflect.get(target, prop, receiver);
      if (typeof v !== "function") return v;
      return (...args: unknown[]) => {
        const run = tail.then(() => (v as (...a: unknown[]) => unknown).apply(target, args));
        tail = run.catch(() => {});
        return run;
      };
    },
  });
}
