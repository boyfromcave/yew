// MockCore: the W1a contract with canned data, so every screen can be built and tested before
// the wasm binding lands. Dev only: main.ts selects it behind `?mock=1` or VITE_MOCK=1. The
// mock never leaves the browser's memory and constructs no bytes: previews are opaque ids.
import type {
  AddressCheck, AddressKind, AddressPair, Balances, ClaimPreview, ClaimableItem, Confirmed, Core, HistoryRow,
  MintAvailability, MintEstimate, MintStart, MintStatus, MintStep, MoveDirection, MovePreview, ParamsProgress, ParamsStatus,
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
  private params: ParamsStatus = { present: false, bytes: 0, needed: 52_000_000, loaded: false };
  private busy = false;
  readonly broadcasts: string[] = [];
  private bal: Balances = {
    yecZat: "250000000", yecReservedZat: "0", yecPendingZat: "0", yedCents: "12500", yedPendingCents: "0",
    priceCents: "52", priceMicroUsd: "520000", heldCount: 1, syncHeight: 1200, yedSendMinZat: "21000",
    shieldedZat: "150000000", shieldedSpendableZat: "150000000", shieldedPendingZat: "0", shieldedScannedHeight: 1200, shieldedSendable: true,
  };
  private rows: HistoryRow[] = [
    hist("a1", 1180, "received private YEC", "", "150000000", "0", "", "thanks for lunch", true),
    hist("b2", 1175, "sent YED", "transfer", "-10000", "-2500", "ok", ""),
    hist("c3", 1170, "minted YED", "mint", "-200010000", "10000", "ok", ""),
    hist("d4", 1100, "received YEC", "", "450000000", "0", "", ""),
  ];
  private mintRows: MintStatus[] = [];
  private vaultRows: Vault[] = [vault("c3".repeat(32), YED, "10000", "200000000", 1230, 1290, 1170, 1200)];
  private claimRows: ClaimableItem[] = [{
    vaultTxid: "e5".repeat(32), ownerAddress: "ye1OtherOwner00000000000000000000000", cents: "5000",
    collateralZat: "120000000", claimHeight: 1190, claimPath: "a", pClaimMicroUsd: "520000", feeZat: "100000", attestFeeZat: "0", residualZat: "0",
    claimantZat: "119900000", payee: "s1MinerPayee000000000000000000000000", claimable: true, underwaterAtMicroUsd: "400000", lockHeight: 1150, inTerm: false,
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
  latest_height(_s: string, _n: string) { return this.step(() => { this.net(); return this.tip; }); }
  open(seedWords: string, _b: number, _s: string, _n = "regtest") {
    return this.step(() => { if (seedWords.trim().split(/\s+/).length < 12) throw new Error("invalid: not a recovery phrase"); this.net(); this.isOpen = true; });
  }
  open_at(s: string, b: number, u: string, n: string, _dir: string) { return this.open(s, b, u, n); }
  sync() {
    return this.step(() => {
      this.need(); this.net();
      for (let i = 1; i <= 4; i++) this.onProgress?.({ phase: "scan", pct: i * 25, height: this.tip - 4 + i, tip: this.tip });
      return { tip: this.tip, scanned_height: this.tip, blocks: 4, received_notes: 0, millis: 12 } as SyncResult;
    });
  }
  progress() { return this.step(() => ({ scanned_height: this.tip, tip_height: this.tip, percent: 100, enhancing: false } as Progress)); }
  shielded_balance() { return this.step(() => ({ total_zat: this.bal.shieldedZat, spendable_zat: this.bal.shieldedSpendableZat, pending_incoming_zat: "0" } as ShieldedBalance)); }
  receive_address(kind: AddressKind) { return this.step(() => { this.need(); return kind === "shielded" ? SHIELDED : kind === "yed" ? YED : TRANSPARENT; }); }
  new_shielded_address() { return this.step(() => { this.need(); return SHIELDED.replace("0000qq", `${++this.seq}`.padStart(4, "0") + "qq"); }); }
  network() { return this.step(() => "regtest"); }
  close() { return this.step(() => { this.isOpen = false; }); }
  status() { return this.step(() => ({ version: "mock", server: this.isOpen ? "localhost:8080" : null, network: this.isOpen ? "regtest" : null, tip: this.tip, yellowbackUsable: true, branchId: "6d5b7a31" } as Status)); }
  async set_progress_callback(fn: ((e: ProgressEvent) => void) | null) { this.onProgress = fn; }
  balances() { return this.step(() => { this.need(); return { ...this.bal }; }); }
  history(page: number) { return this.step(() => { this.need(); return page === 0 ? [...this.rows] : []; }); }
  params_status() { return this.step(() => ({ ...this.params })); }
  async fetch_params(fn: (p: ParamsProgress) => void, _sources: string[] = []) {
    return this.step(() => {
      this.net();
      for (const [name, total] of [["sapling-spend.params", 47_958_396], ["sapling-output.params", 3_592_860]] as const) {
        fn({ bytesDone: 0, bytesTotal: total, name }); fn({ bytesDone: total, bytesTotal: total, name });
      }
      this.params = { present: true, bytes: 51_551_256, needed: 0, loaded: true };
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
      return yec(this.preview("yec", { zat, fromPrivate }), to, zat, fromPrivate ? (priv - amount - BigInt(FEE)).toString() : (BigInt(this.bal.yecZat) - amount - BigInt(FEE)).toString(),
        fromPrivate ? "shielded" : "transparent", fromPrivate && check.kind !== "sapling", memo ?? null, this.tip);
    });
  }
  send_yed_preview(to: string, cents: string) {
    return this.step(() => {
      this.need();
      const check = checkAddress(to);
      if (!check.valid || check.kind === "sapling") throw new Error("invalid: YED can only be sent to a public address (ye… or s…)");
      if (BigInt(cents) <= 0n || BigInt(cents) > BigInt(this.bal.yedCents)) throw new Error("build: insufficient YED");
      const verdict = "ok: valid, burns nothing, would be accepted";
      return { previewId: this.preview("yed", { cents }), to, cents, stage: "ready", inputs: 1, changeCents: (BigInt(this.bal.yedCents) - BigInt(cents)).toString(), yecInputs: 1, feeZat: FEE, yecChangeZat: "0", expiryHeight: this.tip + 40, txid: "", verdict,
        dryRun: { valid: true, verdict, burnedCents: "0", wouldBeRejected: false, yedInCents: this.bal.yedCents, yedOutCents: this.bal.yedCents, accepted: true } } as YedPreview;
    });
  }
  move_preview(direction: MoveDirection, zat: string) {
    return this.step(() => {
      this.need();
      const from = direction === "to_private" ? BigInt(this.bal.yecZat) : BigInt(this.bal.shieldedSpendableZat);
      if (BigInt(zat) + BigInt(FEE) > from) throw new Error("build: insufficient YEC");
      if (!this.params.present) throw new Error("params: the proving files are not fetched");
      return yec(this.preview("move"), direction === "to_private" ? SHIELDED : TRANSPARENT, zat, (from - BigInt(zat) - BigInt(FEE)).toString(), direction === "to_private" ? "transparent" : "shielded", false, null, this.tip) as MovePreview;
    });
  }
  mint_availability() {
    return this.step(() => { this.need(); this.net(); return { allowed: true, reason: "", mintRequiresArmed: false, armed: false, attestStatus: "UNARMED", mintableClasses: ["A", "B", "C"], enabledClasses: ["A", "B", "C"], halts: [] } as MintAvailability; });
  }
  mint_estimate(cents: string, lockBlocks: number) {
    return this.step(() => {
      this.need(); this.net();
      if (BigInt(cents) <= 0n) throw new Error("invalid: amount");
      if (lockBlocks < 10) throw new Error("invalid: the lock must be inside one term class");
      const collateral = (BigInt(cents) * 100000000n * 3n) / BigInt(this.bal.priceCents ?? "0");
      const total = collateral + 100000n + 2n * 10000n + 10000n;
      return {
        cents, lockBlocks, termClass: lockBlocks < 1000 ? "A" : lockBlocks < 10000 ? "B" : "C", refHeight: this.tip,
        lockHeight: this.tip + lockBlocks, claimHeight: this.tip + lockBlocks + 60, expiryHeight: this.tip + 40,
        requiredZat: collateral.toString(), collateralZat: collateral.toString(), feeZat: "100000", attestFeeZat: "0", payee: "s1MinerPayee000000000000000000000000",
        carrierZat: (collateral + 100000n).toString(), tokenZat: "10000", networkFeeZat: "10000", totalZat: total.toString(), availableZat: this.bal.yecZat,
        affordable: total <= BigInt(this.bal.yecZat), pMintMicroUsd: "520000", armed: false, bundleSeqs: [],
      } as MintEstimate;
    });
  }
  /** The carrier, staged: confirm funds it and answers the mintId (as the real core). */
  mint_start(cents: string, lockBlocks: number) {
    return this.step(() => { this.need(); return { previewId: this.preview("carrier", { cents, lockBlocks }), cents, lockBlocks } as MintStart; });
  }
  /** The MINT, staged for confirm; "build: …" until the carrier is confirmed. */
  mint_finish(mintId: number) {
    return this.step(() => {
      const m = this.mintRows.find((x) => x.mintId === mintId); if (!m) throw new Error(`invalid: no mint with id ${mintId}`);
      if (!m.canFinish) throw new Error("build: the carrier is not confirmed yet");
      return { previewId: this.preview("finish", { mintId }), mintId, row: { ...m } } as MintStep;
    });
  }
  mint_sweep(mintId: number) {
    return this.step(() => { const m = this.mintRows.find((x) => x.mintId === mintId); if (!m) throw new Error(`invalid: no mint with id ${mintId}`); return { previewId: this.preview("sweep", { mintId }), mintId, row: { ...m } } as MintStep; });
  }
  mints() { return this.step(() => this.mintRows.map((m) => ({ ...m }))); }
  vaults() { return this.step(() => { this.need(); return this.vaultRows.map((v) => ({ ...v })); }); }
  redeem_preview(vaultTxid: string) {
    return this.step(() => {
      const v = this.vaultRows.find((x) => x.vaultTxid === vaultTxid); if (!v) throw new Error("store: no such vault");
      if (!v.open) throw new Error("build: the vault is closed");
      if (BigInt(this.bal.yedCents) < BigInt(v.cents)) throw new Error("build: not enough YED to burn");
      return { previewId: this.preview("redeem", { vaultTxid }), vaultTxid, kind: v.redeemable ? "redeem" : "early", burnCents: v.cents, extraBurnCents: "0", changeCents: (BigInt(this.bal.yedCents) - BigInt(v.cents)).toString(), yedInputs: 1,
        feeZat: "100000", enforcementFeeZat: "100000", earlyRedeemFeeZat: v.redeemable ? "0" : "2000000", lockHeight: v.lockHeight, payee: "s1MinerPayee000000000000000000000000",
        collateralZat: v.collateralZat, collateralAddress: TRANSPARENT, lockTime: 0, expiryHeight: this.tip + 40, txid: "" } as RedeemPreview;
    });
  }
  claimable() { return this.step(() => { this.need(); this.net(); return this.claimRows.map((c) => ({ ...c })); }); }
  claim_preview(vaultTxid: string) {
    return this.step(() => {
      const c = this.claimRows.find((x) => x.vaultTxid === vaultTxid); if (!c) throw new Error("store: not claimable");
      if (BigInt(this.bal.yedCents) < BigInt(c.cents)) throw new Error("build: not enough YED to burn");
      return { previewId: this.preview("claim", { vaultTxid }), item: { ...c }, maxBurnCents: c.cents, minOutZat: c.claimantZat } as ClaimPreview;
    });
  }
  confirm(previewId: string) {
    return this.step(() => {
      const p = this.previews.get(previewId) as { kind: string; mintId?: number; vaultTxid?: string; cents?: string; lockBlocks?: number } | undefined;
      if (!p) throw new Error("gate: unknown or expired preview");
      this.previews.delete(previewId);
      const txid = `${(this.seq++).toString(16).padStart(2, "0")}`.repeat(32);
      this.broadcasts.push(previewId);
      let mintId: number | null = null;
      if (p.kind === "carrier") {
        mintId = ++this.seq;
        this.mintRows.push(mintRow(mintId, p.cents!, p.lockBlocks!, txid, this.tip));
      }
      if (p.kind === "finish") {
        const m = this.mintRows.find((x) => x.mintId === p.mintId)!; mintId = m.mintId;
        m.state = "DONE"; m.inProgress = false; m.canFinish = false; m.mainTxid = txid; m.vaultTxid = txid;
        this.vaultRows.unshift(vault(txid, YED, m.cents, m.collateralZat, this.tip + m.lockBlocks, this.tip + m.lockBlocks + 60, this.tip, this.tip));
        this.bal.yedCents = (BigInt(this.bal.yedCents) + BigInt(m.cents)).toString();
      }
      if (p.kind === "sweep") { const m = this.mintRows.find((x) => x.mintId === p.mintId)!; mintId = m.mintId; m.state = "SWEPT"; m.inProgress = false; m.canSweep = false; m.sweepTxid = txid; }
      if (p.kind === "redeem") { const v = this.vaultRows.find((x) => x.vaultTxid === p.vaultTxid)!; v.open = false; v.status = "CLOSED"; }
      this.rows.unshift(hist(txid.slice(0, 2), 0, p.kind, p.kind, "-10000", "0", "ok", "", false, true));
      return { txid, verdict: "ok", mintId } as Confirmed;
    });
  }
  export_wif(address: string) { return this.step(() => { if (address !== TRANSPARENT && address !== YED) throw new Error("invalid: not an own transparent address"); return "cMockWifKey0000000000000000000000000000000000000000"; }); }
  import_wif(wif: string, _b?: number) {
    return this.step(() => {
      if (!wif.startsWith("c") && !wif.startsWith("L") && !wif.startsWith("K")) throw new Error("invalid: not a WIF");
      return { ye: YED, s: TRANSPARENT, path: "imported", coveredBySeed: false, address: TRANSPARENT, kind: "transparent" } as AddressPair;
    });
  }
  validate_address(s: string, _n?: string) { return this.step(() => checkAddress(s)); }
}

/** The core's kinds: `sapling`, `p2pkh` (with `yellowbackForm` for the ye… form), `p2sh`. */
export function checkAddress(s: string): AddressCheck {
  const t = s.trim();
  if (/^ys1[a-z0-9]{20,}$/.test(t)) return { valid: true, kind: "sapling", yellowbackForm: false, message: "" };
  if (/^ye1?[A-Za-z0-9]{20,}$/.test(t)) return { valid: true, kind: "p2pkh", yellowbackForm: true, message: "" };
  if (/^s1[A-Za-z0-9]{20,}$/.test(t)) return { valid: true, kind: "p2pkh", yellowbackForm: false, message: "" };
  return { valid: false, kind: "", yellowbackForm: false, message: "not an address of this network" };
}

function hist(pair: string, height: number, label: string, kind: string, yecDelta: string, yedDelta: string, verdict: string, memo: string, shielded = false, pending = false): HistoryRow {
  return { txid: pair.repeat(32), height, pending, yecDelta, yedDelta, label, verdict, kind, hasPayload: kind !== "", shielded, memo };
}
function yec(previewId: string, to: string, zat: string, change: string, funding: string, revealsShielded: boolean, memo: string | null, tip: number): YecPreview {
  return { previewId, to, amountZat: zat, amountBumped: false, fee: FEE, change, inputs: 1, usesReserve: false, keepsReservedZat: "0", expiryHeight: tip + 40, txid: "", funding, revealsShielded, memo, paramsNeeded: funding === "shielded" };
}
function vault(vaultTxid: string, owner: string, cents: string, collateralZat: string, lockHeight: number, claimHeight: number, mintHeight: number, tip: number): Vault {
  return {
    vaultTxid, status: "ACTIVE", ownerAddress: owner, termClass: "A", cents, collateralZat, lockHeight, claimHeight, mintHeight, tip,
    open: true, redeemable: tip >= lockHeight, blocksUntilRedeem: lockHeight - tip, blocksUntilTermEnd: lockHeight - tip, earlyRedeem: true, earlyRedeemFeeZat: "2000000", earlyRedeemFeeBps: 100,
    inTermClaims: true, claimThresholdBps: 12500, claimPriceMicroUsd: "520000", nearThreshold: false, releasable: false, claimable: false, underwaterAtMicroUsd: "400000", underwater: false,
    closeHeight: 0, closingTxid: "", voidReason: "", lockTimeSecs: (lockHeight - tip) * 75, claimTimeSecs: (claimHeight - tip) * 75, blocksUntilClaim: claimHeight - tip, renewable: false, renewLockBlocks: 0,
    claimWarning: false, claimOpen: false, claiming: false, reopened: false,
  };
}
function mintRow(mintId: number, cents: string, lockBlocks: number, carrierTxid: string, tip: number): MintStatus {
  return {
    mintId, kind: "mint", state: "CARRIER_SENT", createdHeight: tip, cents, lockBlocks, termClass: "A", refHeight: tip, lockHeight: tip + lockBlocks, claimHeight: tip + lockBlocks + 60, expiryHeight: tip + 40,
    collateralZat: "57692307692", feeZat: "100000", attestFeeZat: "0", residualZat: "0", payee: "s1MinerPayee000000000000000000000000", attestPayee: "", bundleSeqs: "", carrierTxid, mainTxid: "", sweepTxid: "", vaultTxid: "",
    tip, inProgress: true, windowOpen: true, blocksLeft: 40, canFinish: true, canSweep: false, note: "",
  };
}
