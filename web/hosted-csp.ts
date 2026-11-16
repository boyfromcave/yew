// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

// The <meta> content security policy of a build that is served apart from its light-client server
// (VITE_DEFAULT_SERVER, the hosted fast-testnet wallet). index.html's policy says `connect-src
// 'self' https://download.z.cash`: right where the gateway serves the bundle and the API on one
// origin, but it would refuse the hosted wallet's only server (a browser enforces the <meta> policy
// and the response header's, each on its own). For such a build connect-src becomes exactly
// `'self'` and that server's origin: the proving files come from the page's own origin
// (/sapling-params/), and download.z.cash sends no CORS header, so it is dropped rather than kept.
// frame-ancestors is dropped from the <meta> of such a build: a browser ignores it there (and says so
// in the console on every load); the hosted wallet's response header carries it, where it works.
// A pure function so the rule has a test (tests/hosted-csp.test.ts); vite.config.ts applies it.
export function hostedCsp(html: string, server: string | undefined): string {
  if (!server) return html;
  const url = new URL(server);
  if (url.protocol !== "https:" || url.username || url.password || url.pathname !== "/" || url.search || url.hash) {
    throw new Error(`VITE_DEFAULT_SERVER: an https origin with nothing after it, not ${server}`);
  }
  const directive = /connect-src [^;"]*/g;
  if ((html.match(directive) ?? []).length !== 1) throw new Error("index.html: expected exactly one connect-src in the <meta> policy");
  return html.replace(directive, `connect-src 'self' ${url.origin}`).replace(/; frame-ancestors 'none'(?=[;"])/, "");
}
