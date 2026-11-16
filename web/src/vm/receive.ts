// Receive (receive.dart): Private / Public (ECC) / PQ · FN-DSA-512 (sqf…) / PQ · SLH-DSA (sqs…) / YED;
// the address, a QR, a new private address.
//
// beta3 (the hosted acceptance run): the core answers one call at a time behind the running sync,
// so an address could take 3 to 15 s, and the previous tab's address stayed on screen meanwhile,
// with Copy and the QR live. Now: the addresses are asked for once at unlock (before the first
// sync) and kept; a tab change shows its own address at once, or nothing and "loading" until it
// arrives; an answer is drawn only on its own tab and only if its prefix is that tab's.
import type { AddressKind, Core } from "../core";
import { messageOf } from "../core";
import { Vm } from "./base";
import type { Network } from "../prefixes";
import { addressMatchesKind, currentNetwork, expectedPrefixes } from "../prefixes";

export const RECEIVE_KINDS: AddressKind[] = ["shielded", "transparent", "pq_falcon", "pq_slh", "yed"];
/** The kinds whose address the core moves on by itself: the first unused external key (core/src/wallet.rs
 *  `receive_address`), which changes when a sync sees it used. The private address changes only with
 *  "New private address" (`new_shielded_address`), which this view-model asks for itself. */
export const ROTATING_KINDS: AddressKind[] = ["transparent", "pq_falcon", "pq_slh", "yed"];

export interface ReceiveState {
  kind: AddressKind;
  /** The address on screen, of `addressKind`; "" while loading or after an error. */
  address: string;
  /** The tab `address` was asked for and checked against; the screen shows it only when it is `kind`. */
  addressKind: AddressKind | null;
  loading: boolean;
  error: string;
}

export class ReceiveVm extends Vm<ReceiveState> {
  /** The wallet's address per tab, each checked against its tab's prefixes. */
  private cache = new Map<AddressKind, string>();
  private inflight = new Map<AddressKind, Promise<void>>();
  /** The latest request per tab: an older answer never lands (a fresh private address beats the unlock's default). */
  private latest = new Map<AddressKind, number>();
  private seq = 0;
  /** Bumped when the wallet closes: an answer for the previous wallet is dropped. */
  private epoch = 0;

  constructor(private core: Core, private network: () => Network = currentNetwork) {
    super({ kind: "shielded", address: "", addressKind: null, loading: false, error: "" });
  }

  /** The address the screen may show, copy and encode: "" unless it is the current tab's and carries its prefix. */
  get shown(): string {
    const s = this.state;
    return !s.loading && s.addressKind === s.kind && addressMatchesKind(s.kind, s.address, this.network()) ? s.address : "";
  }

  /** At unlock: every tab's address, asked for at once so the calls queue ahead of the first sync. */
  prime(): Promise<void> {
    return Promise.all(RECEIVE_KINDS.map((k) => this.cache.has(k) ? undefined : this.ask(k))).then(() => {});
  }

  /** After a sync: the rotating kinds again (the one shown stays until its successor arrives; both are the wallet's own). */
  refreshRotating(): Promise<void> {
    return Promise.all(ROTATING_KINDS.map((k) => this.ask(k))).then(() => {});
  }

  /** The wallet closed (lock, forget): nothing of it stays, and nothing it still had in flight lands. */
  clear() {
    this.epoch++; this.cache.clear(); this.inflight.clear(); this.latest.clear();
    this.set({ address: "", addressKind: null, loading: false, error: "" });
  }

  /** A tab: its address at once from the cache, else cleared and "loading" until its own answer. */
  show(kind: AddressKind): Promise<void> {
    const cached = this.cache.get(kind);
    if (cached !== undefined) { this.set({ kind, address: cached, addressKind: kind, loading: false, error: "" }); return Promise.resolve(); }
    this.set({ kind, address: "", addressKind: null, loading: true, error: "" });
    return this.inflight.get(kind) ?? this.ask(kind);
  }

  /** A new diversified private address: the old one leaves the screen at once. */
  fresh(): Promise<void> {
    this.cache.delete("shielded");
    this.set({ kind: "shielded", address: "", addressKind: null, loading: true, error: "" });
    return this.ask("shielded", () => this.core.new_shielded_address());
  }

  private ask(kind: AddressKind, call: () => Promise<string> = () => this.core.receive_address(kind)): Promise<void> {
    const epoch = this.epoch, n = ++this.seq;
    this.latest.set(kind, n);
    const stale = () => epoch !== this.epoch || this.latest.get(kind) !== n;
    const p = (async () => {
      try {
        const a = await call();
        if (stale()) return;
        const network = this.network();
        if (!addressMatchesKind(kind, a, network)) {
          // never shown: an address of another type under this tab is how money goes to the wrong place
          this.cache.delete(kind);
          if (this.state.kind === kind) this.set({ address: "", addressKind: null, loading: false, error: `invalid: the wallet answered an address that is not of this type (expected ${expectedPrefixes(kind, network)}); it is not shown` });
          return;
        }
        this.cache.set(kind, a);
        if (this.state.kind === kind) this.set({ address: a, addressKind: kind, loading: false, error: "" });
      } catch (e) {
        if (stale()) return;
        // a failed refresh keeps the address already shown (it is still the wallet's own, of this type)
        if (this.state.kind === kind && !this.cache.has(kind)) this.set({ address: "", addressKind: null, loading: false, error: messageOf(e) });
      }
    })();
    const done: Promise<void> = p.finally(() => { if (this.inflight.get(kind) === done) this.inflight.delete(kind); });
    this.inflight.set(kind, done);
    return done;
  }
}
