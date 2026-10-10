// MockCore: the W1a contract with canned data, so every screen can be built and tested before
// the wasm binding lands. Dev only: main.ts selects it behind `?mock=1` or VITE_MOCK=1. The
// mock never leaves the browser's memory and constructs no bytes: previews are opaque ids.
import type {
  AddressCheck, AddressKind, Balances, ClaimPreview, ClaimableItem, Confirmed, Core, HistoryRow,
  MintEstimate, MintStart, MintStatus, MoveDirection, MovePreview, ParamsProgress, ParamsStatus,
  Progress, ProgressEvent, RedeemPreview, ShieldedBalance, Status, SyncResult, Vault, YecPreview, YedPreview,
} from "./core";

export const MOCK_SEED = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const SHIELDED = "ys1qmockshieldedaddress0000000000000000000000000000000000000000000000000000qq";
const TRANSPARENT = "s1MockTransparentAddress000000000000";
const YED = "ye1MockYedAddress0000000000000000000";
const FEE = "10000";

export interface MockOptions { delayMs?: number; tip?: number; failNetwork?: boolean }

export class MockCore implements Core {
  private isOpen = false;
  private previews = new Map<string, { kind: string; mintId?: number }>();
  private seq = 0;
  private onProgress: ((e: ProgressEvent) => void) | null = null;
  private tip: number;
  private delayMs: number;
  private failNetwork: boolean;
  private params: ParamsStatus = { present: false, bytes: 0, needed: 52_000_000 };
  private busy = false;
  readonly broadcasts: string[] = [];
  private bal: Balances = {
    yecZat: "250000000", yecPendingZat: "0", yedCents: "12500", yedPendingCents: "0",
    priceCents: "52", shieldedZat: "150000000", shieldedSpendableZat: "150000000",
  };
  private rows: HistoryRow[] = [
    { txid: "a1".repeat(32), height: 1180, kind: "received", yecDelta: "150000000", yedDelta: "0", verdict: "", pending: false, memo: "thanks for lunch" },
    { txid: "b2".repeat(32), height: 1175, kind: "sent", yecDelta: "-10000", yedDelta: "-2500", verdict: "ok", pending: false, memo: "" },
    { txid: "c3".repeat(32), height: 1170, kind: "mint", yecDelta: "-200010000", yedDelta: "10000", verdict: "ok", pending: false, memo: "" },
    { txid: "d4".repeat(32), height: 1100, kind: "received", yecDelta: "450000000", yedDelta: "0", verdict: "", pending: false, memo: "" },
  ];
  private mints: MintStatus[] = [];
  private vaultRows: Vault[] = [{
    vaultTxid: "c3".repeat(32), status: "ACTIVE", ownerAddress: YED, termClass: "A", cents: "10000",
    collateralZat: "200000000", lockHeight: 1230, claimHeight: 1290, mintHeight: 1170, tip: 1200,
    open: true, redeemable: false, blocksToLock: 30,
  }];
  private claimRows: ClaimableItem[] = [{
    vaultTxid: "e5".repeat(32), ownerAddress: "ye1OtherOwner00000000000000000000000", cents: "5000",
    collateralZat: "120000000", claimHeight: 1190, claimPath: "a", feeZat: "100000", residualZat: "0",
    claimantZat: "119900000", payee: "s1MinerPayee000000000000000000000000",
  }];

  constructor(o: MockOptions = {}) { this.tip = o.tip ?? 1200; this.delayMs = o.delayMs ?? 0; this.failNetwork = !!o.failNetwork; }

  private async step<T>(f: () => T): Promise<T> {
    if (this.busy) throw new Error("busy: a call is in progress");
    this.busy = true;
    try { if (this.delayMs) await new Promise((r) => setTimeout(r, this.delayMs)); return f(); } finally { this.busy = false; }
  }
  private need() { if (!this.isOpen) throw new Error("store: no wallet is open"); }
  private net() { if (this.failNetwork) throw new Error("network: the server did not answer"); }
  private preview(kind: string, extra: object = {}): string {
    const id = `p${++this.seq}`; this.previews.set(id, { kind, ...extra }); return id;
  }

  install_storage() { return this.step(() => {}); }
  new_seed_words() { return this.step(() => MOCK_SEED); }
  latest_height(_s: string) { return this.step(() => { this.net(); return this.tip; }); }
  open(seedWords: string, _b: number, _s: string) {
    return this.step(() => { if (seedWords.trim().split(/\s+/).length < 12) throw new Error("invalid: not a recovery phrase"); this.net(); this.isOpen = true; });
  }
  open_at(_n: string, s: string, b: number, u: string) { return this.open(s, b, u); }
  sync() {
    return this.step(() => {
      this.need(); this.net();
      for (let i = 1; i <= 4; i++) this.onProgress?.({ phase: "scan", pct: i * 25, height: this.tip - 4 + i, tip: this.tip });
      return { tip: this.tip, scanned_height: this.tip, blocks: 4, received_notes: 0, millis: 12 } as SyncResult;
    });
  }
  progress() { return this.step(() => ({ pct: 100, phase: "idle" } as Progress)); }
  shielded_balance() { return this.step(() => ({ total_zat: this.bal.shieldedZat, spendable_zat: this.bal.shieldedSpendableZat, pending_incoming_zat: "0" } as ShieldedBalance)); }
  receive_address(kind: AddressKind) { return this.step(() => { this.need(); return kind === "shielded" ? SHIELDED : kind === "yed" ? YED : TRANSPARENT; }); }
  new_shielded_address() { return this.step(() => { this.need(); return SHIELDED.replace("0000qq", `${++this.seq}`.padStart(4, "0") + "qq"); }); }
  network() { return this.step(() => "regtest"); }
  close() { return this.step(() => { this.isOpen = false; }); }
  status() { return this.step(() => ({ version: "mock", server: "mock://local", tip: this.tip, syncHeight: this.tip, open: this.isOpen } as Status)); }
  async set_progress_callback(fn: ((e: ProgressEvent) => void) | null) { this.onProgress = fn; }
  balances() { return this.step(() => { this.need(); return { ...this.bal }; }); }
  history(page: number) { return this.step(() => { this.need(); return page === 0 ? [...this.rows] : []; }); }
  params_status() { return this.step(() => ({ ...this.params })); }
  async fetch_params(fn: (p: ParamsProgress) => void) {
    return this.step(() => {
      this.net();
      for (const [name, total] of [["sapling-spend.params", 47_958_396], ["sapling-output.params", 3_592_860]] as const) {
        fn({ bytesDone: 0, bytesTotal: total, name }); fn({ bytesDone: total, bytesTotal: total, name });
      }
      this.params = { present: true, bytes: 51_551_256, needed: 51_551_256 };
    });
  }
  send_yec_preview(to: string, zat: string, memo?: string) {
    return this.step(() => {
      this.need();
      const check = checkAddress(to);
      if (!check.valid) throw new Error("invalid: not an address of this network");
      if (check.kind === "yed") throw new Error("invalid: YEC cannot be sent to a YED address");
      if (memo && check.kind !== "sapling") throw new Error("invalid: a message needs a private (ys1…) recipient");
      const amount = BigInt(zat);
      if (amount <= 0n) throw new Error("invalid: amount");
      const priv = BigInt(this.bal.shieldedSpendableZat);
      const fromPrivate = amount + BigInt(FEE) <= priv;
      if (!fromPrivate && amount + BigInt(FEE) > BigInt(this.bal.yecZat) + priv) throw new Error("build: insufficient YEC");
      if (fromPrivate && check.kind !== "sapling" && !this.params.present) throw new Error("params: the proving files are not fetched");
      return {
        previewId: this.preview("yec", { zat, fromPrivate }), fee: FEE,
        change: fromPrivate ? (priv - amount - BigInt(FEE)).toString() : (BigInt(this.bal.yecZat) - amount - BigInt(FEE)).toString(),
        revealsShielded: fromPrivate && check.kind !== "sapling", funding: fromPrivate ? "private" : "public",
      } as YecPreview;
    });
  }
  send_yed_preview(to: string, cents: string) {
    return this.step(() => {
      this.need();
      const check = checkAddress(to);
      if (!check.valid || check.kind === "sapling") throw new Error("invalid: YED can only be sent to a public address (ye… or s…)");
      if (BigInt(cents) <= 0n || BigInt(cents) > BigInt(this.bal.yedCents)) throw new Error("build: insufficient YED");
      return { previewId: this.preview("yed", { cents }), inputs: 1, feeZat: FEE, verdict: "ok: valid, burns nothing, would be accepted" } as YedPreview;
    });
  }
  move_preview(direction: MoveDirection, zat: string) {
    return this.step(() => {
      this.need();
      const from = direction === "to_private" ? BigInt(this.bal.yecZat) : BigInt(this.bal.shieldedSpendableZat);
      if (BigInt(zat) + BigInt(FEE) > from) throw new Error("build: insufficient YEC");
      if (!this.params.present) throw new Error("params: the proving files are not fetched");
      return { previewId: this.preview("move"), fee: FEE } as MovePreview;
    });
  }
  mint_estimate(cents: string, lockBlocks: number) {
    return this.step(() => {
      this.need(); this.net();
      if (BigInt(cents) <= 0n) throw new Error("invalid: amount");
      if (lockBlocks < 10) throw new Error("invalid: the lock must be inside one term class");
      const collateral = (BigInt(cents) * 100000000n * 3n) / BigInt(this.bal.priceCents);
      return {
        cents, lockBlocks, termClass: lockBlocks < 1000 ? "A" : lockBlocks < 10000 ? "B" : "C", refHeight: this.tip,
        lockHeight: this.tip + lockBlocks, claimHeight: this.tip + lockBlocks + 60, expiryHeight: this.tip + 40,
        collateralZat: collateral.toString(), feeZat: "100000", attestFeeZat: "0", payee: "s1MinerPayee000000000000000000000000",
      } as MintEstimate;
    });
  }
  mint_start(cents: string, lockBlocks: number) {
    return this.step(() => {
      this.need();
      const mintId = ++this.seq;
      this.mints.push({ mintId, kind: "mint", state: "CARRIER_BUILT", cents, lockBlocks, termClass: "A", collateralZat: "0", vaultTxid: "", inProgress: true, canSweep: false });
      return { mintId, previewId: this.preview("carrier", { mintId }) } as MintStart;
    });
  }
  mint_finish(mintId: number) {
    return this.step(() => {
      const m = this.mints.find((x) => x.mintId === mintId); if (!m) throw new Error("store: no such mint");
      if (m.state !== "CARRIER_SENT") throw new Error("build: the carrier is not confirmed yet");
      m.state = "DONE"; m.inProgress = false; m.vaultTxid = "f6".repeat(32);
      this.vaultRows.unshift({ vaultTxid: m.vaultTxid, status: "ACTIVE", ownerAddress: YED, termClass: m.termClass, cents: m.cents, collateralZat: m.collateralZat, lockHeight: this.tip + m.lockBlocks, claimHeight: this.tip + m.lockBlocks + 60, mintHeight: this.tip, tip: this.tip, open: true, redeemable: false, blocksToLock: m.lockBlocks });
      this.bal.yedCents = (BigInt(this.bal.yedCents) + BigInt(m.cents)).toString();
      return { ...m };
    });
  }
  mint_sweep(mintId: number) {
    return this.step(() => { const m = this.mints.find((x) => x.mintId === mintId); if (!m) throw new Error("store: no such mint"); m.state = "SWEEP_SENT"; m.inProgress = false; m.canSweep = false; return { ...m }; });
  }
  vaults() { return this.step(() => { this.need(); return this.vaultRows.map((v) => ({ ...v })); }); }
  redeem_preview(vaultTxid: string) {
    return this.step(() => {
      const v = this.vaultRows.find((x) => x.vaultTxid === vaultTxid); if (!v) throw new Error("store: no such vault");
      if (!v.open) throw new Error("build: the vault is closed");
      if (BigInt(this.bal.yedCents) < BigInt(v.cents)) throw new Error("build: not enough YED to burn");
      return { previewId: this.preview("redeem", { vaultTxid }), vaultTxid, returnedZat: v.collateralZat, burnCents: v.cents, feeZat: "100000", payee: "s1MinerPayee000000000000000000000000" } as RedeemPreview;
    });
  }
  claimable() { return this.step(() => { this.need(); this.net(); return this.claimRows.map((c) => ({ ...c })); }); }
  claim_preview(vaultTxid: string) {
    return this.step(() => {
      const c = this.claimRows.find((x) => x.vaultTxid === vaultTxid); if (!c) throw new Error("store: not claimable");
      if (BigInt(this.bal.yedCents) < BigInt(c.cents)) throw new Error("build: not enough YED to burn");
      return { previewId: this.preview("claim", { vaultTxid }), vaultTxid, burnCents: c.cents, claimantZat: c.claimantZat, feeZat: c.feeZat } as ClaimPreview;
    });
  }
  confirm(previewId: string) {
    return this.step(() => {
      const p = this.previews.get(previewId); if (!p) throw new Error("gate: unknown or expired preview");
      this.previews.delete(previewId);
      const txid = `${(this.seq++).toString(16).padStart(2, "0")}`.repeat(32);
      this.broadcasts.push(previewId);
      if (p.kind === "carrier") { const m = this.mints.find((x) => x.mintId === p.mintId)!; m.state = "CARRIER_SENT"; }
      if (p.kind === "redeem") { const v = this.vaultRows.find((x) => x.vaultTxid === (p as { vaultTxid?: string }).vaultTxid)!; v.open = false; v.status = "CLOSED"; }
      this.rows.unshift({ txid, height: 0, kind: p.kind, yecDelta: "-10000", yedDelta: "0", verdict: "ok", pending: true, memo: "" });
      return { txid } as Confirmed;
    });
  }
  export_wif(address: string) { return this.step(() => { if (address !== TRANSPARENT && address !== YED) throw new Error("invalid: not an own transparent address"); return "cMockWifKey0000000000000000000000000000000000000000"; }); }
  import_wif(wif: string, _b: number) { return this.step(() => { if (!wif.startsWith("c") && !wif.startsWith("L") && !wif.startsWith("K")) throw new Error("invalid: not a WIF"); }); }
  validate_address(s: string) { return this.step(() => checkAddress(s)); }
}

export function checkAddress(s: string): AddressCheck {
  const t = s.trim();
  if (/^ys1[a-z0-9]{20,}$/.test(t)) return { valid: true, kind: "sapling" };
  if (/^ye1?[A-Za-z0-9]{20,}$/.test(t)) return { valid: true, kind: "yed" };
  if (/^s1[A-Za-z0-9]{20,}$/.test(t)) return { valid: true, kind: "transparent" };
  return { valid: false, kind: "" };
}
