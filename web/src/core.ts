// The one place the UI talks to the core: a typed RPC to the worker hosting the WebAssembly
// module (yew-web-core). The surface is what web/core-wasm exports (W1a; the DTOs are
// core-wasm/src/dto.rs, camelCase): method names mirror core/src/api.rs, every call is async,
// every error is an Error whose message is "<kind>: <detail>" (kinds: busy, unsupported,
// network, store, gate, build, params, invalid). Amounts are strings (u64 zat / cents), heights
// are numbers. Nothing here constructs bytes; the screens render these DTOs and send intents,
// as app/lib does for Flutter. W2 reconciled the names to the real core (plan §5 W2).

export type AddressKind = "shielded" | "transparent" | "yed";
export type MoveDirection = "to_private" | "to_public";

export interface Status { version: string; server: string | null; network: string | null; tip: number | null; yellowbackUsable: boolean | null; branchId: string | null }
export interface SyncResult { tip: number; scanned_height: number; blocks: number; received_notes: number; millis: number }
export interface Progress { scanned_height: number; tip_height: number; percent: number; enhancing: boolean }
export interface ProgressEvent { phase: string; pct: number; height: number; tip: number }
export interface ShieldedBalance { total_zat: string; spendable_zat: string; pending_incoming_zat: string }
export interface Balances {
  yecZat: string; yecReservedZat: string; yecPendingZat: string; yedCents: string; yedPendingCents: string;
  /** Price in cents per YEC (the server's `GetPrice.pMint`); null when undefined. */
  priceCents: string | null; priceMicroUsd: string | null; heldCount: number; syncHeight: number; yedSendMinZat: string;
  shieldedZat: string; shieldedSpendableZat: string; shieldedPendingZat: string; shieldedScannedHeight: number; shieldedSendable: boolean;
}
export interface HistoryRow {
  txid: string; height: number; pending: boolean; yecDelta: string; yedDelta: string;
  /** "received YEC", "sent private YEC", a Yellowback label, … (the text to show). */
  label: string; verdict: string; kind: string; hasPayload: boolean; shielded: boolean; memo: string;
}
export interface ParamsStatus { present: boolean; bytes: number; needed: number; loaded: boolean }
export interface ParamsProgress { bytesDone: number; bytesTotal: number; name: string }
/** A YEC send, a shield or an unshield (`build::yec_private::YecSendPlan`). */
export interface YecPreview {
  previewId: string; to: string; amountZat: string; amountBumped: boolean; fee: string; change: string; inputs: number;
  usesReserve: boolean; keepsReservedZat: string; expiryHeight: number; txid: string;
  /** "transparent" | "shielded": where the YEC comes from. */
  funding: string; revealsShielded: boolean; memo: string | null; paramsNeeded: boolean;
}
export interface DryRun { valid: boolean; verdict: string; burnedCents: string; wouldBeRejected: boolean; yedInCents: string; yedOutCents: string; accepted: boolean }
export interface YedPreview {
  previewId: string; to: string; cents: string; stage: string; inputs: number; changeCents: string; yecInputs: number;
  feeZat: string; yecChangeZat: string; expiryHeight: number; txid: string; verdict: string; dryRun: DryRun;
}
export type MovePreview = YecPreview;
export interface MintAvailability {
  allowed: boolean; reason: string; mintRequiresArmed: boolean; armed: boolean; attestStatus: string;
  mintableClasses: string[]; enabledClasses: string[]; halts: string[];
}
export interface MintEstimate {
  cents: string; lockBlocks: number; termClass: string; refHeight: number; lockHeight: number; claimHeight: number; expiryHeight: number;
  requiredZat: string; collateralZat: string; feeZat: string; attestFeeZat: string; payee: string; carrierZat: string; tokenZat: string;
  networkFeeZat: string; totalZat: string; availableZat: string; affordable: boolean; pMintMicroUsd: string | null; armed: boolean; bundleSeqs: number[];
}
/** `mint_start`: the carrier, staged; `confirm` funds and broadcasts it and answers the mintId. */
export interface MintStart { previewId: string; cents: string; lockBlocks: number }
export interface MintStatus {
  mintId: number; kind: string; state: string; createdHeight: number; cents: string; lockBlocks: number; termClass: string;
  refHeight: number; lockHeight: number; claimHeight: number; expiryHeight: number; collateralZat: string; feeZat: string;
  attestFeeZat: string; residualZat: string; payee: string; attestPayee: string; bundleSeqs: string; carrierTxid: string;
  mainTxid: string; sweepTxid: string; vaultTxid: string; tip: number; inProgress: boolean; windowOpen: boolean; blocksLeft: number;
  canFinish: boolean; canSweep: boolean; note: string;
}
/** `mint_finish` / `mint_sweep`: the step staged for `confirm`, with the mint's row. */
export interface MintStep { previewId: string; mintId: number; row: MintStatus }
export interface Vault {
  vaultTxid: string; status: string; ownerAddress: string; termClass: string; cents: string; collateralZat: string;
  lockHeight: number; claimHeight: number; mintHeight: number; tip: number; open: boolean; redeemable: boolean;
  blocksUntilRedeem: number; blocksUntilTermEnd: number; earlyRedeem: boolean; earlyRedeemFeeZat: string; earlyRedeemFeeBps: number;
  inTermClaims: boolean; claimThresholdBps: number; claimPriceMicroUsd: string; nearThreshold: boolean; releasable: boolean;
  claimable: boolean; underwaterAtMicroUsd: string; underwater: boolean; closeHeight: number; closingTxid: string; voidReason: string;
  lockTimeSecs: number; claimTimeSecs: number; blocksUntilClaim: number; renewable: boolean; renewLockBlocks: number;
  claimWarning: boolean; claimOpen: boolean; claiming: boolean; reopened: boolean;
}
export interface RedeemPreview {
  previewId: string; vaultTxid: string; kind: string; burnCents: string; extraBurnCents: string; changeCents: string; yedInputs: number;
  feeZat: string; enforcementFeeZat: string; earlyRedeemFeeZat: string; lockHeight: number; payee: string;
  /** The collateral returned to the owner. */
  collateralZat: string; collateralAddress: string; lockTime: number; expiryHeight: number; txid: string;
}
export interface ClaimableItem {
  vaultTxid: string; ownerAddress: string; cents: string; collateralZat: string; claimHeight: number; claimPath: string;
  pClaimMicroUsd: string; feeZat: string; attestFeeZat: string; residualZat: string; claimantZat: string; payee: string;
  claimable: boolean; underwaterAtMicroUsd: string; lockHeight: number; inTerm: boolean;
}
/** The bounds the confirm holds the server to (H-9.3): never more burned, never less paid. */
export interface ClaimPreview { previewId: string; item: ClaimableItem; maxBurnCents: string; minOutZat: string }
export interface Confirmed { txid: string; verdict: string; mintId: number | null }
export interface AddressCheck { valid: boolean; kind: string; yellowbackForm: boolean; message: string }
export interface AddressPair { ye: string; s: string; path: string; coveredBySeed: boolean; address: string; kind: string }

/** The contract. `MockCore` (mock.ts) and `CoreClient` (the worker) both implement it. */
export interface Core {
  install_storage(): Promise<void>;
  new_seed_words(): Promise<string>;
  latest_height(serverUrl: string, network: string): Promise<number>;
  /** `birthday` 0 = the current tip (a seed made here). Refuses a store holding another seed. */
  open(seedWords: string, birthday: number, serverUrl: string, network: string): Promise<void>;
  open_at(seedWords: string, birthday: number, serverUrl: string, network: string, storeDir: string): Promise<void>;
  /** The store directories on this origin (`yew/<network>`, `yew/<network>/<n>`), sorted. */
  stores(): Promise<string[]>;
  /** Close the wallet if open and delete the store's files (W0.6); the keystore is the shell's. Returns the files removed. */
  forget(storeDir: string): Promise<number>;
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
  /** `sources`: base URLs ending in `/`; empty = the standard source (download.z.cash). */
  fetch_params(fn: (p: ParamsProgress) => void, sources?: string[]): Promise<void>;
  send_yec_preview(to: string, zat: string, memo?: string): Promise<YecPreview>;
  send_yed_preview(to: string, cents: string): Promise<YedPreview>;
  move_preview(direction: MoveDirection, zat: string): Promise<MovePreview>;
  mint_availability(): Promise<MintAvailability>;
  mint_estimate(cents: string, lockBlocks: number): Promise<MintEstimate>;
  mint_start(cents: string, lockBlocks: number): Promise<MintStart>;
  mint_finish(mintId: number): Promise<MintStep>;
  mint_sweep(mintId: number): Promise<MintStep>;
  mints(): Promise<MintStatus[]>;
  vaults(): Promise<Vault[]>;
  redeem_preview(vaultTxid: string): Promise<RedeemPreview>;
  claimable(): Promise<ClaimableItem[]>;
  claim_preview(vaultTxid: string): Promise<ClaimPreview>;
  /** The ONLY path that signs and broadcasts; passes gate.rs. */
  confirm(previewId: string): Promise<Confirmed>;
  export_wif(address: string): Promise<string>;
  import_wif(wif: string, birthday?: number): Promise<AddressPair>;
  /** The open wallet's network, or `network` when none is open. */
  validate_address(s: string, network?: string): Promise<AddressCheck>;
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
  // wasm-bindgen crosses a bare u64 / i64 as a BigInt (the DTOs' fields, through serde, are numbers).
  async latest_height(serverUrl: string, network: string) { return Number(await this.call<bigint>("latest_height", serverUrl, network)); }
  async open(seedWords: string, birthday: number, serverUrl: string, network: string) { await this.call("open", seedWords, BigInt(birthday), serverUrl, network); }
  async open_at(seedWords: string, birthday: number, serverUrl: string, network: string, storeDir: string) { await this.call("open_at", seedWords, BigInt(birthday), serverUrl, network, storeDir); }
  stores() { return this.call<string[]>("stores"); }
  forget(storeDir: string) { return this.call<number>("forget", storeDir); }
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
  async fetch_params(fn: (p: ParamsProgress) => void, sources: string[] = []) {
    this.onParams = fn;
    try { await this.call<void>("fetch_params", sources); } finally { this.onParams = null; }
  }
  send_yec_preview(to: string, zat: string, memo?: string) { return this.call<YecPreview>("send_yec_preview", to, zat, memo); }
  send_yed_preview(to: string, cents: string) { return this.call<YedPreview>("send_yed_preview", to, cents); }
  move_preview(direction: MoveDirection, zat: string) { return this.call<MovePreview>("move_preview", direction, zat); }
  mint_availability() { return this.call<MintAvailability>("mint_availability"); }
  mint_estimate(cents: string, lockBlocks: number) { return this.call<MintEstimate>("mint_estimate", cents, lockBlocks); }
  mint_start(cents: string, lockBlocks: number) { return this.call<MintStart>("mint_start", cents, lockBlocks, null); }
  mint_finish(mintId: number) { return this.call<MintStep>("mint_finish", BigInt(mintId)); }
  mint_sweep(mintId: number) { return this.call<MintStep>("mint_sweep", BigInt(mintId)); }
  mints() { return this.call<MintStatus[]>("mints"); }
  vaults() { return this.call<Vault[]>("vaults"); }
  redeem_preview(vaultTxid: string) { return this.call<RedeemPreview>("redeem_preview", vaultTxid); }
  claimable() { return this.call<ClaimableItem[]>("claimable"); }
  claim_preview(vaultTxid: string) { return this.call<ClaimPreview>("claim_preview", vaultTxid); }
  confirm(previewId: string) { return this.call<Confirmed>("confirm", previewId); }
  export_wif(address: string) { return this.call<string>("export_wif", address); }
  import_wif(wif: string, birthday?: number) { return this.call<AddressPair>("import_wif", wif, birthday === undefined ? undefined : BigInt(birthday)); }
  validate_address(s: string, network?: string) { return this.call<AddressCheck>("validate_address", s, network); }
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
