// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

// Plain sentences for the few failures a first-time visitor of the page meets that the core can only
// describe in its own terms (the hosted fast-testnet acceptance run, beta3): another tab holding the
// wallet's storage, a server the page cannot reach, and the hosted build's fixed server and proving
// files. Pure functions, so each rule has a test (tests/plain.test.ts).

/** What the page shows when another tab or window holds this wallet's storage. */
export const OPEN_ELSEWHERE = "This wallet is open in another tab or window. Close it there, then reload.";

/** Whether a failure is the browser refusing the wallet's storage because another tab or window holds
 *  it: the storage keeps OPFS sync access handles open, and a browser gives each file to one holder. */
export function openElsewhere(message: string): boolean {
  return /NoModificationAllowedError|createSyncAccessHandle|Access Handles cannot be created/.test(message);
}

/** A server the browser could not reach at all (wrong address, server down, or one the page's policy
 *  does not let it connect to): one sentence instead of the transport's internal error text. Any
 *  other failure is returned as it is. */
export function unreachableServer(message: string, url: string): string {
  return /Failed to fetch|NetworkError when attempting to fetch|Load failed|fetch failed/.test(message)
    ? `Cannot reach the server at ${url}. Check the address.`
    : message;
}

/** A hosted build (VITE_DEFAULT_SERVER) talks to its one server: the page's policy allows no other. */
export function hostedServerText(server: string): string {
  return `This hosted wallet connects only to ${server}. To use another server, run the wallet yourself.`;
}

/** A hosted build fetches the proving files from its own site only, so the core's advice to set a
 *  mirror in Settings (a field such a build does not show) is replaced. */
export function hostedParamsText(message: string): string {
  return message
    .replace(/ Enter a mirror that does under Source, in Settings\./, " Check your connection, then try again.")
    .replace(/, or enter a mirror under Source, in Settings\./, ".");
}
