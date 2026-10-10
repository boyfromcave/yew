// The seed at rest (yew/web plan §3): encrypted in IndexedDB under AES-256-GCM. The wrapping
// key comes from WebAuthn PRF (a passkey; the PRF output is HKDF'd to the key) or, where PRF is
// unavailable, from a passphrase through PBKDF2-SHA-256 (Web Crypto). Argon2id would need a
// WASM package the import rule forbids (check-web-imports.sh), so PBKDF2 at 600 000 iterations
// is the fallback; a later W1a export of argon2 from the core's wasm can replace it here alone.
// Never localStorage, never a cookie, never sent. Unlock hands the plaintext seed straight to
// the core's open() and drops it.
const DB = "yew", STORE = "keystore", KEY = "wallet";
const PBKDF2_ITERS = 600_000;

export interface WalletMeta {
  birthday: number; serverUrl: string; network: string; createdAt: number;
  /** The core's store directory when it is not the network's default (a restore beside an older store; W0.6). */
  storeDir?: string;
}
/** The core's store directory for a wallet: `meta.storeDir`, else the network's default `yew/<network>`. */
export function storeDirOf(meta: WalletMeta | null, network: string): string { return meta?.storeDir ?? `yew/${meta?.network || network}`; }
interface Record_ {
  v: 1; method: "prf" | "passphrase"; salt: ArrayBuffer; iv: ArrayBuffer; ct: ArrayBuffer;
  credentialId?: ArrayBuffer; meta: WalletMeta;
}

function idb(): Promise<IDBDatabase> {
  return new Promise((res, rej) => {
    const r = indexedDB.open(DB, 1);
    r.onupgradeneeded = () => r.result.createObjectStore(STORE);
    r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error);
  });
}
async function get(): Promise<Record_ | undefined> {
  const db = await idb();
  return new Promise((res, rej) => { const q = db.transaction(STORE).objectStore(STORE).get(KEY); q.onsuccess = () => res(q.result); q.onerror = () => rej(q.error); });
}
async function put(r: Record_ | null): Promise<void> {
  const db = await idb();
  return new Promise((res, rej) => {
    const s = db.transaction(STORE, "readwrite").objectStore(STORE);
    const q = r ? s.put(r, KEY) : s.delete(KEY); q.onsuccess = () => res(); q.onerror = () => rej(q.error);
  });
}

const enc = new TextEncoder(), dec = new TextDecoder();
const rnd = (n: number) => crypto.getRandomValues(new Uint8Array(n));

async function aesFromPbkdf2(passphrase: string, salt: ArrayBuffer): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey("raw", enc.encode(passphrase.normalize("NFKD")), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt, iterations: PBKDF2_ITERS }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
async function aesFromPrf(prf: ArrayBuffer, salt: ArrayBuffer): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey("raw", prf, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt, info: enc.encode("yew-web seed v1") }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

type PrfCredential = { credentialId: ArrayBuffer; prf: ArrayBuffer };
/** Whether this browser can make a PRF passkey (feature-detected; the create() call is the real test). */
export function prfAvailable(): boolean {
  return typeof PublicKeyCredential !== "undefined" && !!navigator.credentials;
}
async function prfCreate(salt: ArrayBuffer): Promise<PrfCredential> {
  const cred = (await navigator.credentials.create({
    publicKey: {
      challenge: rnd(32), rp: { name: "YEW" },
      user: { id: rnd(16), name: "yew-wallet", displayName: "YEW wallet" },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
      authenticatorSelection: { residentKey: "required", userVerification: "required" },
      extensions: { prf: { eval: { first: salt } } } as AuthenticationExtensionsClientInputs,
    },
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error("passkey: cancelled");
  const ext = cred.getClientExtensionResults() as { prf?: { enabled?: boolean; results?: { first?: ArrayBuffer } } };
  if (!ext.prf?.results?.first) {
    // Some authenticators enable PRF at create but only evaluate at get: evaluate once now.
    return { credentialId: cred.rawId, prf: await prfGet(cred.rawId, salt) };
  }
  return { credentialId: cred.rawId, prf: ext.prf.results.first };
}
async function prfGet(credentialId: ArrayBuffer, salt: ArrayBuffer): Promise<ArrayBuffer> {
  const cred = (await navigator.credentials.get({
    publicKey: {
      challenge: rnd(32), allowCredentials: [{ type: "public-key", id: credentialId }], userVerification: "required",
      extensions: { prf: { eval: { first: salt } } } as AuthenticationExtensionsClientInputs,
    },
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error("passkey: cancelled");
  const ext = cred.getClientExtensionResults() as { prf?: { results?: { first?: ArrayBuffer } } };
  if (!ext.prf?.results?.first) throw new Error("passkey: this authenticator has no PRF; use a passphrase");
  return ext.prf.results.first;
}

export type Unlock = { method: "prf" } | { method: "passphrase"; passphrase: string };

export async function hasWallet(): Promise<boolean> { return !!(await get()); }
export async function walletMeta(): Promise<WalletMeta | null> { return (await get())?.meta ?? null; }
export async function unlockMethod(): Promise<"prf" | "passphrase" | null> { return (await get())?.method ?? null; }

/** Encrypt and store the seed; the plaintext is only ever in the caller's hands. */
export async function saveSeed(seedWords: string, unlock: Unlock, meta: WalletMeta): Promise<void> {
  const salt = rnd(32).buffer, iv = rnd(12).buffer;
  let key: CryptoKey, credentialId: ArrayBuffer | undefined;
  if (unlock.method === "prf") { const c = await prfCreate(salt); key = await aesFromPrf(c.prf, salt); credentialId = c.credentialId; }
  else {
    if (unlock.passphrase.length < 8) throw new Error("invalid: the passphrase needs at least 8 characters");
    key = await aesFromPbkdf2(unlock.passphrase, salt);
  }
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(seedWords));
  await put({ v: 1, method: unlock.method, salt, iv, ct, credentialId, meta });
}

/** Decrypt the seed. A wrong passphrase or a refused passkey throws. */
export async function unlockSeed(unlock: Unlock): Promise<{ seedWords: string; meta: WalletMeta }> {
  const r = await get(); if (!r) throw new Error("store: no wallet on this browser");
  if (r.method !== unlock.method) throw new Error(`invalid: this wallet unlocks with a ${r.method === "prf" ? "passkey" : "passphrase"}`);
  const key = unlock.method === "prf" ? await aesFromPrf(await prfGet(r.credentialId!, r.salt), r.salt) : await aesFromPbkdf2(unlock.passphrase, r.salt);
  try {
    return { seedWords: dec.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: r.iv }, key, r.ct)), meta: r.meta };
  } catch { throw new Error("invalid: wrong passphrase or passkey"); }
}

export async function updateMeta(patch: Partial<WalletMeta>): Promise<void> {
  const r = await get(); if (!r) return; await put({ ...r, meta: { ...r.meta, ...patch } });
}
/** Remove the seed from this browser. Only the written phrase restores it. */
export async function forget(): Promise<void> { await put(null); }
