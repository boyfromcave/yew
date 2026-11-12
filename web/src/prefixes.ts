// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

// The address prefixes a label names, for the network in use (real-stack run WEB-REAL LOW-4: the
// labels said the mainnet `sqs…`/`sqf…` on regtest, where the wallet shows `rqs…`/`rqf…`). The
// texts are written with the mainnet prefixes; `localize` rewrites them for the open wallet's
// network. The prefixes are the node's (core/src/params.rs: pq_yec_version, pq_yellowback_version,
// yellowback_prefix, sapling_address_hrp).
export type Network = "mainnet" | "testnet" | "regtest";

const PREFIXES: Record<Network, Record<string, string>> = {
  mainnet: { sqf: "sqf", sqs: "sqs", ybf: "ybf", ybs: "ybs", yb: "yb", ys1: "ys1" },
  testnet: { sqf: "tqf", sqs: "tqs", ybf: "ytf", ybs: "yts", yb: "yt", ys1: "ytestsapling1" },
  regtest: { sqf: "rqf", sqs: "rqs", ybf: "yrf", ybs: "yrs", yb: "yr", ys1: "yregtestsapling1" },
};

let current: Network = "mainnet";

/** The network of the open wallet (main.ts sets it before any screen draws). */
export function setNetwork(n: string): void {
  current = n === "testnet" || n === "regtest" ? n : "mainnet";
}

export function currentNetwork(): Network { return current; }

/** `text` with every mainnet prefix (`sqf…`, `sqs…`, `ybf…`, `ybs…`, `yb…`, `ys1…`) replaced by the
 *  current network's. Only a prefix followed by "…" is touched. */
export function localize(text: string, network: Network = current): string {
  const p = PREFIXES[network];
  return text.replace(/\b(sqf|sqs|ybf|ybs|yb|ys1)…/g, (_, k: string) => `${p[k]}…`);
}
