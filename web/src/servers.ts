// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

/** The fast testnet's lightwalletd, gRPC-web (beta3 item 17; the app's default is the native
 *  listener of the same host, yew-core `net::tls::default_servers`). It must stay in `connect-src`
 *  in index.html. */
export const TESTNET_DEFAULT_SERVER = "https://fastnet-lightwallet.ycash.team";

/** The server field's default: the mock's in mock mode; the fast testnet's server for a testnet
 *  build; otherwise the page's own origin when served by the gateway over https (the API is on
 *  this origin), and none in the dev loop over http (an explicit URL, the plain :9067 listener). */
export function defaultServerFor(network: string, loc: { protocol: string; hostname: string; port: string }, mock: boolean): string {
  if (mock) return "http://localhost:8080";
  if (network === "testnet") return TESTNET_DEFAULT_SERVER;
  return loc.protocol === "https:" ? `https://${loc.hostname}:${loc.port || "443"}` : "";
}
