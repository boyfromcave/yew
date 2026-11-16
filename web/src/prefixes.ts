// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

// The address prefixes a label names, for the network in use (real-stack run WEB-REAL LOW-4: the
// labels said the mainnet `sqs…`/`sqf…` on regtest, where the wallet shows `rqs…`/`rqf…`). The
// texts are written with the mainnet prefixes; `localize` rewrites them for the open wallet's
// network. The prefixes are the node's (core/src/params.rs: p2pkh_prefix, pq_yec_version,
// pq_yellowback_version, yellowback_prefix, sapling_address_hrp); the core's test
// `params::tests::web_prefix_table_matches_the_core` derives each one from those parameters and
// fails when this table differs, so the table cannot drift from the core.
export type Network = "mainnet" | "testnet" | "regtest";

const PREFIXES: Record<Network, Record<string, string>> = {
  mainnet: { sqf: "sqf", sqs: "sqs", ybf: "ybf", ybs: "ybs", yb: "yb", ys1: "ys1", s1: "s1" },
  testnet: { sqf: "tqf", sqs: "tqs", ybf: "ytf", ybs: "yts", yb: "yt", ys1: "ytestsapling1", s1: "sm" },
  regtest: { sqf: "rqf", sqs: "rqs", ybf: "yrf", ybs: "yrs", yb: "yr", ys1: "yregtestsapling1", s1: "sm" },
};

let current: Network = "mainnet";

/** The network of the open wallet (main.ts sets it before any screen draws). */
export function setNetwork(n: string): void {
  current = n === "testnet" || n === "regtest" ? n : "mainnet";
}

export function currentNetwork(): Network { return current; }

/** `text` with every mainnet prefix (`sqf…`, `sqs…`, `ybf…`, `ybs…`, `yb…`, `ys1…`, and `s1…`, the
 *  wallet's own transparent form) replaced by the current network's. Only a prefix followed by "…" is
 *  touched; a bare `s…` (any transparent address, `s1…`/`s3…` on mainnet) is right on every network. */
export function localize(text: string, network: Network = current): string {
  const p = PREFIXES[network];
  return text.replace(/\b(sqf|sqs|ybf|ybs|yb|ys1|s1)…/g, (_, k: string) => `${p[k]}…`);
}

/** The line shown above every screen of a build for a network whose coins are worth nothing, or
 *  null. `testnet` is the fast testnet (core/src/params.rs: the one testnet profile this wallet
 *  signs for). A hosted wallet is a testnet build (web/README.md, "The hosted fast-testnet wallet"),
 *  and nobody should take it for a wallet that holds money. */
export function networkBanner(network: string): string | null {
  return network === "testnet" ? "Fast testnet: coins here have no value" : null;
}

/** Whether this page runs on MockCore (src/mock.ts: canned data, a public seed). Only a build made
 *  for it can: the dev server (`dev`), where `?mock=1` asks for it, or a build with `VITE_MOCK=1`
 *  (`flag`), which is always the mock. Any other build, the hosted wallet among them, ignores
 *  `?mock` whatever the address says: a link must never be able to swap the core of a real wallet.
 *  main.ts repeats the build half of the rule as a constant, so such a build does not even contain
 *  the mock. */
export function mockMode(build: { dev: boolean; flag: string | undefined }, search: string): boolean {
  if (build.flag === "1") return true;
  return build.dev && new URLSearchParams(search).get("mock") === "1";
}

/** Each receive tab's address prefixes, as keys of the table above (`yb` covers the YED forms with
 *  and without a scheme letter: `yb…`, `ybf…`, `ybs…`). */
const KIND_KEYS: Record<"shielded" | "transparent" | "pq_falcon" | "pq_slh" | "yed", string[]> = {
  shielded: ["ys1"], transparent: ["s1"], pq_falcon: ["sqf"], pq_slh: ["sqs"], yed: ["yb", "ybf", "ybs"],
};
export type ReceiveKind = keyof typeof KIND_KEYS;

/** The receive tab an address belongs to on `network`, by its longest matching prefix (so a testnet
 *  `ytestsapling1…` is private, never YED's `yt…`), or null when it is none of the wallet's forms. */
export function receiveKindOf(address: string, network: Network = current): ReceiveKind | null {
  const p = PREFIXES[network];
  let best: ReceiveKind | null = null, len = 0;
  for (const [kind, keys] of Object.entries(KIND_KEYS) as [ReceiveKind, string[]][]) {
    for (const k of keys) if (p[k].length > len && address.startsWith(p[k])) { best = kind; len = p[k].length; }
  }
  return best;
}

/** Whether `address` is of the type the `kind` tab names (beta3, the hosted acceptance run: the
 *  Public (ECC) tab showed the private address). The Receive screen shows nothing else. */
export function addressMatchesKind(kind: ReceiveKind, address: string, network: Network = current): boolean {
  return address.length > 0 && receiveKindOf(address, network) === kind;
}

/** The prefixes the `kind` tab expects, for an error message (`ytestsapling1…`, `sm…`, …). */
export function expectedPrefixes(kind: ReceiveKind, network: Network = current): string {
  return [...new Set(KIND_KEYS[kind].map((k) => PREFIXES[network][k]))].map((p) => `${p}…`).join(", ");
}
