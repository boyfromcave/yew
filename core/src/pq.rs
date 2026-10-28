// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! Post-quantum vault owners (workspace `docs/plans/yellowback-quantum-plan.md` Q7,
//! `docs/plans/yellowback-quantum-spec.md` §0–§2 and its header rulings): the scheme registry,
//! the key id `scheme ‖ SHA256(scheme ‖ pk)`, `TX_PQPKH` (`20 <keyHash> OP_1|OP_2 OP_CHECKPQSIG`,
//! 35 bytes), the chunked signature/key pushes `OP_CHECKPQSIG` reads, SLH-DSA-SHA2-128s key
//! generation and signing, and the node wallet's seed derivation (ruling A-12, "Q5 as
//! implemented").
//!
//! Translation source: `ycash-dd/src/crypto/pq/scheme.{h,cpp}` and `sign.{h,cpp}` (the library
//! contract of `wt/BRIEFING-quantum.md`), `src/pqkey.{h,cpp}` (`DerivePQSeed`, branch
//! `q/wallet`), `src/script/standard.cpp` (`TX_PQPKH`, `GetScriptForDestination(CPQKeyID)`) and
//! `src/script/sign.cpp` (the PQPKH `SignStep`). Byte identity is proved against the node's
//! golden vectors: `tests/vectors/pq_vectors.json` and `pq_wallet_vectors.json` (copies of the
//! node's `src/test/data/` files at the commits `tests/vectors/PIN` records, compared in CI by
//! `scripts/check-node-vectors.sh`), and the owner spends of `tests/vectors/vault_vectors.json`.
//!
//! **Scheme 1, SLH-DSA-SHA2-128s:** FIPS 205 *pure* SLH-DSA with an empty context string
//! (`M' = 0x00 ‖ 0x00 ‖ msg`), deterministic signing (`opt_rand = PK.seed`), key generation from
//! the 48-byte seed `SK.seed ‖ SK.prf ‖ PK.seed` (`slh_keygen_internal`). The implementation is
//! RustCrypto's `slh-dsa` =0.1.0 (FIPS 205 final; client survey §1). The message is the 32 bytes
//! of the ZIP-243 sighash in memory order, exactly what [`crate::tx::Transaction::sighash`]
//! returns and what the ECDSA signer hands secp256k1.
//!
//! **Scheme 2, FN-DSA-512 (PQClean `falcon-padded-512`):** the node's own C, vendored at
//! `core/pq-c/falcon/` (byte copies of ycash-dd `src/crypto/pq/falcon/`: PQClean
//! `falcon-padded-512/clean`, the inline-SHAKE patch P1 and the Ycash entry points
//! `ycash_falcon512_keygen_from_seed` / `ycash_falcon512_sign` / `ycash_falcon512_verify`),
//! compiled by `build.rs` with `cc`. Key generation from the 48-byte seed (SHAKE256 DRBG, spec
//! ruling C-8) and signing with explicit 88-byte entropy (`nonce(40) ‖ sampler seed(48)`)
//! therefore reproduce the node's golden vectors byte for byte; [`PqKey::sign`] draws that entropy
//! from the OS RNG, as the node's `pq::Sign` does from `GetRandBytes`. A pure-Rust Falcon was not
//! used: `fn-dsa` 0.4 hashes a different message representative and keygen (client survey C-7),
//! and no crate reproduces PQClean's seeded keygen. Signature: 666 bytes, key 897, secret 1,281.
//!
//! **Seed (A-12).** `DerivePQSeed`: HKDF-SHA256 (RFC 5869), IKM = the wallet seed, salt empty,
//! info = `"Ycash PQ key"` ‖ scheme u8 ‖ index u32 big-endian, L = 48. The node's IKM is its raw
//! HD seed (32 bytes); **YEW's is its 64-byte BIP39 seed** (`keys::seed_from_mnemonic`, with the
//! passphrase), the same seed both of its key trees come from. The two wallets' seeds differ
//! anyway, so what matters is that YEW's derivation is deterministic (restore) and the same
//! function as the node's — proved on the node's own vector (HD seed `0x00..0x1f`).
//! [`PqSeedRoot`] keeps only the HKDF pseudo-random key, never the seed.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use slh_dsa::signature::Keypair;
use thiserror::Error;

use crate::keys::{sha256, wipe};
use crate::script::{self, op, ScriptOp, MAX_SCRIPT_ELEMENT_SIZE};

/// `pq::SCHEME_SLH_DSA_SHA2_128S`.
pub const SCHEME_SLH_DSA_SHA2_128S: u8 = 0x01;
/// `pq::SCHEME_FN_DSA_512` (PQClean `falcon-padded-512`; gated by `pqFalconHeight` on the node).
pub const SCHEME_FN_DSA_512: u8 = 0x02;
/// `pq::KEYHASH_SIZE`.
pub const KEYHASH_SIZE: usize = 32;
/// `pq::MAX_CHUNK` (= `MAX_SCRIPT_ELEMENT_SIZE`): every chunk of a signature or key but the
/// last is exactly this long.
pub const MAX_CHUNK: usize = MAX_SCRIPT_ELEMENT_SIZE;
/// `OP_CHECKPQSIG` (quantum spec §0: after `OP_CHECKSETDORMANT = 0xc1`).
pub const OP_CHECKPQSIG: u8 = 0xc2;
/// `TX_PQPKH`'s length: `20 <32> OP_n c2` (spec F-1).
pub const PQPKH_SCRIPT_SIZE: usize = 35;
/// `MAX_STANDARD_PQ_SCRIPTSIG` (`src/policy/policy.h`): the relay limit on a PQ scriptSig
/// (`TX_PQPKH`, V and I inputs) once the vault upgrade is active.
pub const MAX_STANDARD_PQ_SCRIPTSIG: usize = 9_000;
/// The seed length of both schemes (`SK.seed ‖ SK.prf ‖ PK.seed`; PQClean's Falcon DRBG seed).
pub const SEED_SIZE: usize = 48;
/// The HKDF info prefix of `DerivePQSeed` (12 ASCII bytes).
pub const DERIVE_INFO: &[u8; 12] = b"Ycash PQ key";

type Slh = slh_dsa::Sha2_128s;

/// Falcon-512 secret key size (PQClean padded: `0x59 ‖ f ‖ g ‖ F`).
pub const FALCON_SECRET_KEY_SIZE: usize = 1_281;
/// Falcon signing entropy: the 40-byte nonce then the 48-byte sampler seed (`pq::SignWithEntropy`).
pub const FALCON_SIGN_ENTROPY_SIZE: usize = 88;

/// The vendored Falcon entry points (`core/pq-c/falcon/ycash_falcon.h`).
mod falcon_ffi {
    extern "C" {
        pub fn ycash_falcon512_verify(
            sig: *const u8,
            siglen: usize,
            m: *const u8,
            mlen: usize,
            pk: *const u8,
        ) -> i32;
        pub fn ycash_falcon512_keygen_from_seed(
            pk: *mut u8,
            sk: *mut u8,
            seed: *const u8,
            seedlen: usize,
        ) -> i32;
        pub fn ycash_falcon512_sign(
            sig: *mut u8,
            m: *const u8,
            mlen: usize,
            sk: *const u8,
            nonce: *const u8,
            seed: *const u8,
        ) -> i32;
    }
}

/// `ycash_falcon512_keygen_from_seed`: `(pk 897, sk 1,281)`.
fn falcon_keygen(seed: &[u8; SEED_SIZE]) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut pk = vec![0u8; 897];
    let mut sk = vec![0u8; FALCON_SECRET_KEY_SIZE];
    // SAFETY: the buffers have the sizes ycash_falcon.h names; the seed is SEED_SIZE bytes.
    let r = unsafe {
        falcon_ffi::ycash_falcon512_keygen_from_seed(
            pk.as_mut_ptr(),
            sk.as_mut_ptr(),
            seed.as_ptr(),
            seed.len(),
        )
    };
    if r != 0 {
        wipe(&mut sk);
        return None;
    }
    Some((pk, sk))
}

/// `ycash_falcon512_sign` over `msg` with explicit entropy: 666 bytes.
fn falcon_sign(sk: &[u8], msg: &[u8], entropy: &[u8; FALCON_SIGN_ENTROPY_SIZE]) -> Option<Vec<u8>> {
    if sk.len() != FALCON_SECRET_KEY_SIZE {
        return None;
    }
    let mut sig = vec![0u8; 666];
    // SAFETY: sig is YCASH_FALCON512_SIGBYTES, sk YCASH_FALCON512_SECRETKEYBYTES, nonce 40 and
    // the sampler seed 48 bytes inside `entropy`.
    let r = unsafe {
        falcon_ffi::ycash_falcon512_sign(
            sig.as_mut_ptr(),
            msg.as_ptr(),
            msg.len(),
            sk.as_ptr(),
            entropy.as_ptr(),
            entropy.as_ptr().add(40),
        )
    };
    (r == 0).then_some(sig)
}

/// PQ errors.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PqError {
    /// A scheme byte outside the registry, or one YEW cannot sign with (Falcon, for now).
    #[error("post-quantum scheme {0} is not supported here")]
    Scheme(u8),
    /// A seed, key or signature of the wrong length.
    #[error("post-quantum {what}: {got} bytes, expected {want}")]
    Size {
        /// Which field.
        what: &'static str,
        /// The length given.
        got: usize,
        /// The length the scheme needs.
        want: usize,
    },
    /// More than 16 chunks (no `OP_n` for the count).
    #[error("post-quantum element of {0} bytes needs more than 16 chunks")]
    TooManyChunks(usize),
}

/// `pq::IsKnownScheme`: `0x01` or `0x02` (whether scheme 2 is *active* is the caller's height).
pub fn is_known_scheme(scheme: u8) -> bool {
    scheme == SCHEME_SLH_DSA_SHA2_128S || scheme == SCHEME_FN_DSA_512
}

/// `pq::PubKeySize`: 32 | 897, 0 for an unknown scheme.
pub fn pub_key_size(scheme: u8) -> usize {
    match scheme {
        SCHEME_SLH_DSA_SHA2_128S => 32,
        SCHEME_FN_DSA_512 => 897,
        _ => 0,
    }
}

/// `pq::SigSize` without the hashtype byte: 7,856 | 666, 0 for an unknown scheme.
pub fn sig_size(scheme: u8) -> usize {
    match scheme {
        SCHEME_SLH_DSA_SHA2_128S => 7_856,
        SCHEME_FN_DSA_512 => 666,
        _ => 0,
    }
}

/// `pq::KeyHash`: `SHA256(scheme ‖ pk)`.
pub fn key_hash(scheme: u8, pk: &[u8]) -> [u8; 32] {
    let mut b = Vec::with_capacity(1 + pk.len());
    b.push(scheme);
    b.extend_from_slice(pk);
    sha256(&b)
}

/// `CPQKeyID`: the scheme and the key hash. Its 33-byte form `scheme ‖ hash` is the MINT
/// payload's owner field, the vault record's `ownerPubKey` bytes, and the PQ address payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PqKeyId {
    /// The scheme byte.
    pub scheme: u8,
    /// `SHA256(scheme ‖ pk)`, the bytes pushed in the script (uint256 memory order).
    pub hash: [u8; 32],
}

impl PqKeyId {
    /// The id of a public key.
    pub fn of(scheme: u8, pk: &[u8]) -> PqKeyId {
        PqKeyId {
            scheme,
            hash: key_hash(scheme, pk),
        }
    }

    /// `scheme ‖ hash`.
    pub fn to_bytes(&self) -> [u8; 33] {
        let mut b = [0u8; 33];
        b[0] = self.scheme;
        b[1..].copy_from_slice(&self.hash);
        b
    }

    /// From `scheme ‖ hash` (33 bytes). Any scheme byte decodes, as the node's payload codec
    /// does (the shape is fixed here; MINT-3 and [`PqKeyId::is_known`] judge the scheme).
    pub fn from_bytes(b: &[u8]) -> Option<PqKeyId> {
        if b.len() != 33 {
            return None;
        }
        Some(PqKeyId {
            scheme: b[0],
            hash: b[1..].try_into().ok()?,
        })
    }

    /// The scheme is registered.
    pub fn is_known(&self) -> bool {
        is_known_scheme(self.scheme)
    }
}

// ---------------------------------------------------------------------------------------------
// TX_PQPKH

/// `GetScriptForDestination(CPQKeyID)`: `20 <hash> OP_scheme OP_CHECKPQSIG` (35 bytes; spec
/// §2.1). The scheme is pushed as `OP_1`/`OP_2` (`CScript::EncodeOP_N`); `None` for a scheme
/// outside the registry.
pub fn pqpkh_script(id: &PqKeyId) -> Option<Vec<u8>> {
    if !id.is_known() {
        return None;
    }
    let mut s = Vec::with_capacity(PQPKH_SCRIPT_SIZE);
    script::push_data(&mut s, &id.hash);
    s.push(op::OP_1 + id.scheme - 1);
    s.push(OP_CHECKPQSIG);
    Some(s)
}

/// The `Solver` match for `TX_PQPKH` (spec §2.1, exact): `size == 35 && s[0] == 0x20 &&
/// s[33] ∈ {OP_1, OP_2} && s[34] == OP_CHECKPQSIG`. Any other scheme byte is non-standard.
pub fn pqpkh_of(spk: &[u8]) -> Option<PqKeyId> {
    if spk.len() == PQPKH_SCRIPT_SIZE
        && spk[0] == 0x20
        && (spk[33] == op::OP_1 || spk[33] == op::OP_1 + 1)
        && spk[34] == OP_CHECKPQSIG
    {
        Some(PqKeyId {
            scheme: spk[33] - op::OP_1 + 1,
            hash: spk[1..33].try_into().ok()?,
        })
    } else {
        None
    }
}

// ---------------------------------------------------------------------------------------------
// The chunked stack (plan §4.2, briefing "Chunked stack")

/// Split `data` into the chunks `OP_CHECKPQSIG` reassembles: every chunk but the last is
/// exactly 520 bytes, the last 1..=520. Empty input gives no chunk.
pub fn chunks(data: &[u8]) -> Vec<&[u8]> {
    data.chunks(MAX_CHUNK).collect()
}

/// Append `<c_1> … <c_n> OP_n` for one element (`n` = the chunk count, `OP_1..OP_16`).
fn push_chunked(s: &mut Vec<u8>, data: &[u8]) -> Result<(), PqError> {
    let c = chunks(data);
    if c.is_empty() || c.len() > 16 {
        return Err(PqError::TooManyChunks(data.len()));
    }
    for chunk in &c {
        script::push_data(s, chunk);
    }
    script::push_int(s, c.len() as i64);
    Ok(())
}

/// The PQ signature pushes: `<sig_1>…<sig_s> <s> <pk_1>…<pk_p> <p>`, `sig_with_hashtype`
/// carrying the hashtype as its last byte, minimal pushes (`OP_PUSHDATA2` for a 520-byte chunk,
/// `OP_n` for the counts). This is the whole `TX_PQPKH` scriptSig (spec §2.1), and the V/I
/// owner scriptSigs before their selector (§1.5).
pub fn pq_sig_pushes(sig_with_hashtype: &[u8], pk: &[u8]) -> Result<Vec<u8>, PqError> {
    let mut s = Vec::with_capacity(sig_with_hashtype.len() + pk.len() + 64);
    push_chunked(&mut s, sig_with_hashtype)?;
    push_chunked(&mut s, pk)?;
    Ok(s)
}

/// The `TX_PQPKH` scriptSig: [`pq_sig_pushes`].
pub fn pqpkh_script_sig(sig_with_hashtype: &[u8], pk: &[u8]) -> Result<Vec<u8>, PqError> {
    pq_sig_pushes(sig_with_hashtype, pk)
}

/// The size of [`pq_sig_pushes`] for a scheme, without building it: SLH-DSA 7,938, Falcon 1,577.
/// `None` for an unknown scheme.
pub fn pq_sig_pushes_size(scheme: u8) -> Option<usize> {
    if !is_known_scheme(scheme) {
        return None;
    }
    let push_len = |n: usize| -> usize {
        if n < op::OP_PUSHDATA1 as usize {
            1 + n
        } else if n <= 0xff {
            2 + n
        } else {
            3 + n
        }
    };
    let chunked = |n: usize| -> usize {
        let full = n / MAX_CHUNK;
        let rest = n % MAX_CHUNK;
        full * push_len(MAX_CHUNK) + if rest > 0 { push_len(rest) } else { 0 } + 1
    };
    Some(chunked(sig_size(scheme) + 1) + chunked(pub_key_size(scheme)))
}

/// Reassemble one chunked element ending at `ops[end - 1]` (the `OP_n` count). Returns the
/// element and the index of its first chunk. Each chunk must be a data push; every chunk but the
/// last exactly 520 bytes, the last 1..=520.
fn read_chunked(ops: &[ScriptOp], end: usize) -> Option<(Vec<u8>, usize)> {
    let count_op = ops.get(end.checked_sub(1)?)?;
    if !(op::OP_1..=op::OP_16).contains(&count_op.opcode) {
        return None;
    }
    let n = (count_op.opcode - op::OP_1 + 1) as usize;
    let first = end.checked_sub(1 + n)?;
    let mut out = Vec::with_capacity(n * MAX_CHUNK);
    for (i, c) in ops[first..end - 1].iter().enumerate() {
        if c.opcode > op::OP_PUSHDATA4 || c.data.is_empty() {
            return None;
        }
        let last = i + 1 == n;
        if (!last && c.data.len() != MAX_CHUNK) || c.data.len() > MAX_CHUNK {
            return None;
        }
        out.extend_from_slice(&c.data);
    }
    Some((out, first))
}

/// Parse [`pq_sig_pushes`] back: `(sig_with_hashtype, pk)` when `ops` is exactly
/// `<sig chunks> <s> <pk chunks> <p>` with the chunk rules above.
pub fn parse_pq_sig_ops(ops: &[ScriptOp]) -> Option<(Vec<u8>, Vec<u8>)> {
    let (pk, pk_first) = read_chunked(ops, ops.len())?;
    let (sig, sig_first) = read_chunked(ops, pk_first)?;
    (sig_first == 0).then_some((sig, pk))
}

/// True when `script_sig` is a post-quantum spend: the chunked `<sig…> <s> <pk…> <p>`, alone
/// (`TX_PQPKH`) or followed by one template selector (`OP_1`..`OP_16`: the V/I owner paths). Used
/// only to pick the relay size limit ([`MAX_STANDARD_PQ_SCRIPTSIG`]) before a broadcast.
pub fn is_pq_script_sig(script_sig: &[u8]) -> bool {
    let Ok(ops) = script::ops(script_sig) else {
        return false;
    };
    if parse_pq_sig_ops(&ops).is_some() {
        return true;
    }
    ops.split_last().is_some_and(|(last, rest)| {
        (op::OP_1..=op::OP_16).contains(&last.opcode) && parse_pq_sig_ops(rest).is_some()
    })
}

/// Parse a `TX_PQPKH` scriptSig into `(sig_with_hashtype, pk)`.
pub fn parse_pqpkh_script_sig(script_sig: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    parse_pq_sig_ops(&script::ops(script_sig).ok()?)
}

// ---------------------------------------------------------------------------------------------
// Seed derivation (A-12)

/// The HKDF-SHA256 pseudo-random key of a wallet seed (`HKDF-Extract(salt = "", IKM = seed)`),
/// from which every PQ seed is expanded. Holds no other secret; wiped on drop.
pub struct PqSeedRoot([u8; 32]);

impl Drop for PqSeedRoot {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

impl std::fmt::Debug for PqSeedRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PqSeedRoot(..)")
    }
}

fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("any key length");
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

/// RFC 5869 HKDF-SHA256 with an explicit salt and info (`L ≤ 255 · 32`).
pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) {
    let mut prk = hmac_sha256(salt, &[ikm]);
    hkdf_expand(&prk, info, out);
    wipe(&mut prk);
}

fn hkdf_expand(prk: &[u8; 32], info: &[u8], out: &mut [u8]) {
    assert!(out.len() <= 255 * 32, "HKDF output too long");
    let mut t: Vec<u8> = Vec::new();
    let mut done = 0;
    let mut counter = 1u8;
    while done < out.len() {
        let mut block = hmac_sha256(prk, &[&t, info, &[counter]]);
        let n = (out.len() - done).min(32);
        out[done..done + n].copy_from_slice(&block[..n]);
        wipe(&mut t);
        t = block.to_vec();
        wipe(&mut block);
        done += n;
        counter = counter.wrapping_add(1);
    }
    wipe(&mut t);
}

impl PqSeedRoot {
    /// `HKDF-Extract` with an empty salt over the wallet seed (YEW: the 64-byte BIP39 seed).
    pub fn from_seed(seed: &[u8]) -> PqSeedRoot {
        PqSeedRoot(hmac_sha256(&[], &[seed]))
    }

    /// `DerivePQSeed(seed, scheme, index)`: the 48-byte key seed of (`scheme`, `index`).
    pub fn derive(&self, scheme: u8, index: u32) -> [u8; SEED_SIZE] {
        let mut info = [0u8; 17];
        info[..12].copy_from_slice(DERIVE_INFO);
        info[12] = scheme;
        info[13..].copy_from_slice(&index.to_be_bytes());
        let mut out = [0u8; SEED_SIZE];
        hkdf_expand(&self.0, &info, &mut out);
        out
    }

    /// The SLH-DSA key at `index` (scheme 1), the owner key chain of YEW.
    pub fn slh_key(&self, index: u32) -> PqKey {
        let mut seed = self.derive(SCHEME_SLH_DSA_SHA2_128S, index);
        let k = PqKey::from_seed(SCHEME_SLH_DSA_SHA2_128S, &seed).expect("scheme 1, 48 bytes");
        wipe(&mut seed);
        k
    }

    /// The Falcon (scheme 2) key at `index`: `DerivePQSeed(seed, 2, index)` into PQClean's seeded
    /// keygen. YEW's YED holder keys (the index space is the wallet's; see
    /// `Wallet::falcon_holder_key`).
    pub fn falcon_key(&self, index: u32) -> PqKey {
        let mut seed = self.derive(SCHEME_FN_DSA_512, index);
        let k = PqKey::from_seed(SCHEME_FN_DSA_512, &seed).expect("scheme 2, 48 bytes");
        wipe(&mut seed);
        k
    }
}

// ---------------------------------------------------------------------------------------------
// Keys, signing, verification

/// A PQ key pair kept as its 48-byte seed (wiped on drop) and its public key; a Falcon key also
/// keeps its expanded secret key (wiped on drop), since Falcon signing does not re-derive it.
pub struct PqKey {
    scheme: u8,
    seed: [u8; SEED_SIZE],
    pk: Vec<u8>,
    falcon_sk: Vec<u8>,
}

impl std::fmt::Debug for PqKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PqKey({}, {:?})", self.scheme, self.id())
    }
}

impl Drop for PqKey {
    fn drop(&mut self) {
        wipe(&mut self.seed);
        wipe(&mut self.falcon_sk);
    }
}

fn slh_signing_key(seed: &[u8; SEED_SIZE]) -> slh_dsa::SigningKey<Slh> {
    slh_dsa::SigningKey::<Slh>::slh_keygen_internal(&seed[..16], &seed[16..32], &seed[32..])
}

impl PqKey {
    /// `pq::KeyGen` from the 48-byte seed: SLH-DSA from `SK.seed ‖ SK.prf ‖ PK.seed`, Falcon
    /// through PQClean's SHAKE256-seeded keygen (`ycash_falcon512_keygen_from_seed`).
    pub fn from_seed(scheme: u8, seed: &[u8]) -> Result<PqKey, PqError> {
        if !is_known_scheme(scheme) {
            return Err(PqError::Scheme(scheme));
        }
        let seed: [u8; SEED_SIZE] = seed.try_into().map_err(|_| PqError::Size {
            what: "seed",
            got: seed.len(),
            want: SEED_SIZE,
        })?;
        if scheme == SCHEME_FN_DSA_512 {
            let (pk, falcon_sk) = falcon_keygen(&seed).ok_or(PqError::Scheme(scheme))?;
            return Ok(PqKey {
                scheme,
                seed,
                pk,
                falcon_sk,
            });
        }
        let pk = slh_signing_key(&seed).verifying_key().to_bytes().to_vec();
        Ok(PqKey {
            scheme,
            seed,
            pk,
            falcon_sk: Vec::new(),
        })
    }

    /// The scheme byte.
    pub fn scheme(&self) -> u8 {
        self.scheme
    }

    /// The public key (32 bytes for SLH-DSA: `PK.seed ‖ PK.root`).
    pub fn public_key(&self) -> &[u8] {
        &self.pk
    }

    /// `CPQKeyID`.
    pub fn id(&self) -> PqKeyId {
        PqKeyId::of(self.scheme, &self.pk)
    }

    /// `pq::Sign`: the signature (no hashtype) over the 32-byte message (a ZIP-243 sighash in
    /// memory order). SLH-DSA: pure mode, empty context, deterministic (`opt_rand = PK.seed`).
    /// Falcon: randomized, the 88 bytes of entropy from the OS RNG (`pq::Sign`'s
    /// `GetRandBytes`), wiped after use; the signature is checked before it is returned.
    pub fn sign(&self, msg: &[u8; 32]) -> Vec<u8> {
        if self.scheme == SCHEME_FN_DSA_512 {
            use rand::RngCore;
            let mut entropy = [0u8; FALCON_SIGN_ENTROPY_SIZE];
            rand::rngs::OsRng.fill_bytes(&mut entropy);
            let sig = self.sign_with_entropy(msg, &entropy);
            wipe(&mut entropy);
            let sig = sig.expect("a Falcon key from keygen signs");
            assert!(
                verify(self.scheme, &self.pk, &sig, msg),
                "a fresh Falcon signature verifies"
            );
            return sig;
        }
        let sk = slh_signing_key(&self.seed);
        sk.try_sign_with_context(msg, &[], None)
            .expect("an empty context is at most 255 bytes")
            .to_vec()
    }

    /// `pq::SignWithEntropy` for Falcon (`nonce(40) ‖ sampler seed(48)`): the node's vector
    /// signatures are reproduced with it. `None` for an SLH-DSA key (deterministic: [`PqKey::sign`]).
    pub fn sign_with_entropy(
        &self,
        msg: &[u8; 32],
        entropy: &[u8; FALCON_SIGN_ENTROPY_SIZE],
    ) -> Option<Vec<u8>> {
        if self.scheme != SCHEME_FN_DSA_512 {
            return None;
        }
        falcon_sign(&self.falcon_sk, msg, entropy)
    }
}

/// `pq::Verify`; `false` for an unknown scheme, a wrong size (Falcon: exactly 666 bytes, the
/// padded form only), or a bad signature. A wallet-side self-check, never a verdict (the node
/// judges).
pub fn verify(scheme: u8, pk: &[u8], sig: &[u8], msg: &[u8; 32]) -> bool {
    if !is_known_scheme(scheme) || pk.len() != pub_key_size(scheme) || sig.len() != sig_size(scheme)
    {
        return false;
    }
    if scheme == SCHEME_FN_DSA_512 {
        // SAFETY: pk is 897 bytes (checked above); sig and msg are passed with their lengths.
        return unsafe {
            falcon_ffi::ycash_falcon512_verify(
                sig.as_ptr(),
                sig.len(),
                msg.as_ptr(),
                msg.len(),
                pk.as_ptr(),
            )
        } == 0;
    }
    let (Ok(vk), Ok(sig)) = (
        slh_dsa::VerifyingKey::<Slh>::try_from(pk),
        slh_dsa::Signature::<Slh>::try_from(sig),
    ) else {
        return false;
    };
    vk.try_verify_with_context(msg, &[], &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{hex, unhex};
    use serde_json::Value;

    fn vectors() -> Value {
        let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/vectors/pq_vectors.json");
        serde_json::from_str(&std::fs::read_to_string(p).expect("pq_vectors.json")).unwrap()
    }

    fn b(v: &Value) -> Vec<u8> {
        unhex(v.as_str().unwrap()).unwrap()
    }

    #[test]
    fn registry_matches_the_node() {
        assert_eq!((pub_key_size(1), sig_size(1)), (32, 7_856));
        assert_eq!((pub_key_size(2), sig_size(2)), (897, 666));
        assert_eq!((pub_key_size(3), sig_size(0)), (0, 0));
        assert!(is_known_scheme(1) && is_known_scheme(2));
        assert!(!is_known_scheme(0) && !is_known_scheme(3));
        assert_eq!(pq_sig_pushes_size(1), Some(7_938));
        assert_eq!(pq_sig_pushes_size(2), Some(1_577));
        assert_eq!(pq_sig_pushes_size(3), None);
    }

    /// Every entry of the node's golden vectors, both schemes: seed → pk, keyhash, and msg → sig
    /// byte for byte (SLH-DSA deterministic; Falcon with the recorded 88-byte entropy), the
    /// signature verifies, and a flipped message or signature does not.
    #[test]
    fn pq_reproduces_the_node_vectors() {
        let v = vectors();
        assert_eq!(v["format"], "ycash-pq-vectors-1");
        let (mut slh, mut falcon) = (0, 0);
        for k in v["keys"].as_array().unwrap() {
            let scheme = k["scheme"].as_u64().unwrap() as u8;
            let pk = b(&k["pk"]);
            let keyhash: [u8; 32] = b(&k["keyhash"]).try_into().unwrap();
            assert_eq!(key_hash(scheme, &pk), keyhash, "{}", k["label"]);
            assert_eq!(pk.len(), pub_key_size(scheme));
            assert_eq!(b(&k["sig"]).len(), sig_size(scheme));
            let key = PqKey::from_seed(scheme, &b(&k["seed"])).unwrap();
            assert_eq!(hex(key.public_key()), hex(&pk), "{}", k["label"]);
            assert_eq!(
                key.id(),
                PqKeyId {
                    scheme,
                    hash: keyhash
                }
            );
            let msg: [u8; 32] = b(&k["msg"]).try_into().unwrap();
            let entropy = b(&k["entropy"]);
            let sig = if scheme == SCHEME_SLH_DSA_SHA2_128S {
                slh += 1;
                assert_eq!(entropy, Vec::<u8>::new(), "SLH-DSA is deterministic");
                key.sign(&msg)
            } else {
                falcon += 1;
                let e: [u8; FALCON_SIGN_ENTROPY_SIZE] = entropy.try_into().unwrap();
                let s = key.sign_with_entropy(&msg, &e).unwrap();
                // a fresh randomized signature differs and verifies too
                let r = key.sign(&msg);
                assert_ne!(r, s);
                assert!(verify(scheme, &pk, &r, &msg));
                s
            };
            assert_eq!(hex(&sig), hex(&b(&k["sig"])), "{}", k["label"]);
            assert!(verify(scheme, &pk, &sig, &msg));
            assert!(verify(scheme, &pk, &b(&k["sig"]), &msg));
            let mut bad = msg;
            bad[0] ^= 1;
            assert!(!verify(scheme, &pk, &sig, &bad));
            let mut bad_sig = sig.clone();
            bad_sig[100] ^= 1;
            assert!(!verify(scheme, &pk, &bad_sig, &msg));
            assert!(!verify(scheme, &pk, &sig[..sig.len() - 1], &msg));
        }
        assert_eq!((slh, falcon), (2, 3));
    }

    /// Falcon accepts only the padded 666-byte form (`pq::Verify`): a non-zero padding byte, a
    /// wrong header, a wrong key header, or the signature under another scheme byte fail.
    #[test]
    fn falcon_padding_and_headers_are_exact() {
        let v = vectors();
        let k = v["keys"]
            .as_array()
            .unwrap()
            .iter()
            .find(|k| k["scheme"] == 2)
            .unwrap()
            .clone();
        let (pk, sig) = (b(&k["pk"]), b(&k["sig"]));
        let msg: [u8; 32] = b(&k["msg"]).try_into().unwrap();
        assert!(verify(2, &pk, &sig, &msg));
        let mut pad = sig.clone();
        *pad.last_mut().unwrap() ^= 1;
        assert!(!verify(2, &pk, &pad, &msg), "non-zero padding");
        let mut h = sig.clone();
        h[0] = 0x3a;
        assert!(!verify(2, &pk, &h, &msg), "signature header");
        let mut kh = pk.clone();
        kh[0] = 0x0a;
        assert!(!verify(2, &kh, &sig, &msg), "key header");
        assert!(!verify(1, &pk, &sig, &msg));
        assert!(!verify(3, &pk, &sig, &msg));
    }

    /// The NIST PQC KAT generator's AES-256 CTR DRBG (`rng.c` of the NIST package), as the
    /// node's `pq_crypto_tests.cpp` `NistDrbg`.
    struct NistDrbg {
        key: [u8; 32],
        v: [u8; 16],
    }

    impl NistDrbg {
        fn block(&mut self) -> [u8; 16] {
            use aes::cipher::{BlockEncrypt, KeyInit};
            for i in (0..16).rev() {
                self.v[i] = self.v[i].wrapping_add(1);
                if self.v[i] != 0 {
                    break;
                }
            }
            let c = aes::Aes256::new(&self.key.into());
            let mut blk = self.v.into();
            c.encrypt_block(&mut blk);
            blk.into()
        }

        fn update(&mut self, provided: Option<&[u8]>) {
            let mut t = [0u8; 48];
            for i in 0..3 {
                t[16 * i..16 * i + 16].copy_from_slice(&self.block());
            }
            if let Some(p) = provided {
                for (x, y) in t.iter_mut().zip(p) {
                    *x ^= y;
                }
            }
            self.key.copy_from_slice(&t[..32]);
            self.v.copy_from_slice(&t[32..]);
        }

        fn new(seed: &[u8]) -> NistDrbg {
            let mut d = NistDrbg {
                key: [0; 32],
                v: [0; 16],
            };
            d.update(Some(seed));
            d
        }

        fn get(&mut self, n: usize) -> Vec<u8> {
            let mut out = Vec::with_capacity(n);
            while out.len() < n {
                let blk = self.block();
                let k = (n - out.len()).min(16);
                out.extend_from_slice(&blk[..k]);
            }
            self.update(None);
            out
        }
    }

    /// The Falcon-512 KATs the node checks (`tests/vectors/pq_falcon_kat.json`, a byte copy of
    /// ycash-dd `src/test/data/pq_falcon_kat.json`), replayed through the NIST DRBG: the NIST
    /// round-3 entries (counts 0–4: keys equal, the signature equals the round-3 compressed
    /// signature in the padded layout) and PQClean's padded KAT (count 0) — an independent check
    /// of the vendored C against the Falcon reference and PQClean.
    #[test]
    fn falcon_reproduces_the_nist_kats() {
        let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/vectors/pq_falcon_kat.json");
        let v: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
        let replay = |e: &Value| {
            let mut d = NistDrbg::new(&b(&e["seed"]));
            let kseed = d.get(48);
            let key = PqKey::from_seed(2, &kseed).unwrap();
            assert_eq!(hex(key.public_key()), e["pk"].as_str().unwrap());
            assert_eq!(hex(&key.falcon_sk), e["sk"].as_str().unwrap());
            let msg = b(&e["msg"]);
            let entropy: [u8; 88] = [d.get(40), d.get(48)].concat().try_into().unwrap();
            let sig = falcon_sign(&key.falcon_sk, &msg, &entropy).unwrap();
            (key, msg, entropy, sig)
        };
        let mut n = 0;
        for e in v["r3"].as_array().unwrap() {
            let (key, msg, entropy, sig) = replay(e);
            let sm = b(&e["sm"]);
            let siglen = ((sm[0] as usize) << 8) | sm[1] as usize;
            assert_eq!(sm.len(), 2 + 40 + msg.len() + siglen);
            assert_eq!(&sm[2..42], &entropy[..40]);
            assert_eq!(sm[42 + msg.len()], 0x29);
            let mut padded = vec![0x39];
            padded.extend_from_slice(&entropy[..40]);
            padded.extend_from_slice(&sm[43 + msg.len()..]);
            padded.resize(666, 0);
            assert_eq!(hex(&sig), hex(&padded), "r3 count {}", e["count"]);
            if let Ok(m) = <[u8; 32]>::try_from(msg.as_slice()) {
                assert!(verify(2, key.public_key(), &sig, &m));
            }
            n += 1;
        }
        assert_eq!(n, 5);
        for e in v["padded"].as_array().unwrap() {
            let (_, msg, _, sig) = replay(e);
            assert_eq!(hex(&[sig, msg].concat()), e["sm"].as_str().unwrap());
            n += 1;
        }
        assert_eq!(n, 6);
    }

    /// The vendored Falcon C is exactly the files `core/pq-c/SHA256SUMS` pins (byte copies of
    /// the node's `src/crypto/pq/falcon/`, `core/pq-c/README.md`).
    #[test]
    fn vendored_falcon_matches_its_manifest() {
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("pq-c");
        let sums = std::fs::read_to_string(dir.join("SHA256SUMS")).unwrap();
        let mut n = 0;
        for line in sums.lines() {
            let (h, f) = line.split_once("  ").unwrap();
            let bytes = std::fs::read(dir.join("falcon").join(f)).unwrap();
            assert_eq!(hex(&sha256(&bytes)), h, "{f}");
            n += 1;
        }
        let files = std::fs::read_dir(dir.join("falcon")).unwrap().count();
        assert_eq!((n, files), (16, 16));
    }

    /// The Falcon holder chain: deterministic, distinct per index, and the node's scheme-2
    /// derivation seed (`pq_wallet_tests.cpp`, HD seed 0x00..0x1f) gives the same key here.
    #[test]
    fn falcon_keys_derive_deterministically() {
        let raw: Vec<u8> = (0u8..32).collect();
        let root = PqSeedRoot::from_seed(&raw);
        let a = root.falcon_key(0);
        let b2 = PqKey::from_seed(2, &root.derive(2, 0)).unwrap();
        assert_eq!(a.public_key(), b2.public_key());
        assert_eq!(a.scheme(), 2);
        assert_eq!(a.public_key().len(), 897);
        assert_ne!(root.falcon_key(1).id(), a.id());
        let msg = [9u8; 32];
        assert!(verify(2, a.public_key(), &a.sign(&msg), &msg));
    }

    /// The node's PQPKH spends: scriptPubKey from the key id, and the chunked scriptSig of the
    /// vector's signature ‖ hashtype and key, byte for byte (both schemes: chunking is
    /// scheme-agnostic), parsed back.
    #[test]
    fn pqpkh_scripts_and_chunked_script_sigs_match_the_node() {
        let v = vectors();
        let keys = v["keys"].as_array().unwrap();
        for s in v["spends"].as_array().unwrap() {
            let scheme = s["scheme"].as_u64().unwrap() as u8;
            // `key` indexes the whole `keys` array
            let k = &keys[s["key"].as_u64().unwrap() as usize];
            assert_eq!(k["scheme"].as_u64(), Some(scheme as u64));
            let pk = b(&k["pk"]);
            let id = PqKeyId::of(scheme, &pk);
            let spk = b(&s["scriptPubKey"]);
            assert_eq!(pqpkh_script(&id).unwrap(), spk);
            assert_eq!(pqpkh_of(&spk), Some(id));
            let mut sig = b(&k["sig"]);
            sig.push(s["hashtype"].as_u64().unwrap() as u8);
            let ss = pqpkh_script_sig(&sig, &pk).unwrap();
            assert_eq!(hex(&ss), hex(&b(&s["scriptSig"])), "scheme {scheme}");
            assert_eq!(ss.len() as u64, s["scriptSigSize"].as_u64().unwrap());
            assert_eq!(Some(ss.len()), pq_sig_pushes_size(scheme));
            let ops = script::ops(&ss).unwrap();
            assert_eq!(
                ops.len() as u64,
                s["sigChunks"].as_u64().unwrap() + s["pkChunks"].as_u64().unwrap() + 2
            );
            assert_eq!(parse_pqpkh_script_sig(&ss), Some((sig, pk)));
        }
    }

    #[test]
    fn pqpkh_shape_is_exact() {
        let id = PqKeyId {
            scheme: 1,
            hash: [7; 32],
        };
        let s = pqpkh_script(&id).unwrap();
        assert_eq!(s.len(), PQPKH_SCRIPT_SIZE);
        assert_eq!((s[0], s[33], s[34]), (0x20, 0x51, 0xc2));
        let falcon = PqKeyId { scheme: 2, ..id };
        assert_eq!(pqpkh_script(&falcon).unwrap()[33], 0x52);
        assert_eq!(pqpkh_script(&PqKeyId { scheme: 3, ..id }), None);
        // scheme 3 as OP_3, scheme pushed as data, a trailing byte, a short hash: not PQPKH
        let mut t = s.clone();
        t[33] = 0x53;
        assert_eq!(pqpkh_of(&t), None);
        let mut d = s[..33].to_vec();
        d.extend_from_slice(&[0x01, 0x01, 0xc2]);
        assert_eq!(pqpkh_of(&d), None);
        let mut long = s.clone();
        long.push(0x75);
        assert_eq!(pqpkh_of(&long), None);
        assert_eq!(pqpkh_of(&s[1..]), None);
        assert_eq!(PqKeyId::from_bytes(&id.to_bytes()), Some(id));
        assert_eq!(PqKeyId::from_bytes(&[1; 32]), None);
    }

    #[test]
    fn chunk_boundaries() {
        // SLH: 7,857 = 15 × 520 + 57 (OP_16), pk 32 (OP_1); Falcon: 667 = 520 + 147, 897 = 520 + 377.
        let sig = vec![0xab; 7_857];
        let pk = vec![0xcd; 32];
        let ss = pq_sig_pushes(&sig, &pk).unwrap();
        let ops = script::ops(&ss).unwrap();
        assert_eq!(ops.len(), 16 + 1 + 1 + 1);
        assert!(ops[..15]
            .iter()
            .all(|o| o.opcode == op::OP_PUSHDATA2 && o.data.len() == 520));
        assert_eq!((ops[15].opcode, ops[15].data.len()), (57, 57));
        assert_eq!(ops[16].opcode, op::OP_16);
        assert_eq!((ops[17].opcode, ops[18].opcode), (32, op::OP_1));
        let f = pq_sig_pushes(&vec![1; 667], &vec![2; 897]).unwrap();
        let o = script::ops(&f).unwrap();
        assert_eq!(o[1].data.len(), 147);
        assert_eq!(o[1].opcode, op::OP_PUSHDATA1);
        assert_eq!(o[4].data.len(), 377);
        assert_eq!(o[4].opcode, op::OP_PUSHDATA2);
        assert_eq!((o[2].opcode, o[5].opcode), (0x52, 0x52));
        // exactly 520: one full chunk
        assert_eq!(chunks(&[0; 520]).len(), 1);
        assert_eq!(chunks(&[0; 521]).len(), 2);
        assert!(pq_sig_pushes(&[], &pk).is_err());
        assert!(pq_sig_pushes(&vec![0; 16 * 520 + 1], &pk).is_err());
        // parse refuses a short middle chunk, a wrong count, an extra leading push
        let mut bad = Vec::new();
        script::push_data(&mut bad, &[1; 519]);
        script::push_data(&mut bad, &[1; 2]);
        script::push_int(&mut bad, 2);
        script::push_data(&mut bad, &pk);
        script::push_int(&mut bad, 1);
        assert_eq!(parse_pqpkh_script_sig(&bad), None);
        let mut lead = vec![0x51];
        lead.extend_from_slice(&ss);
        assert_eq!(parse_pqpkh_script_sig(&lead), None);
        let mut wrong_count = ss.clone();
        let at = wrong_count.len() - 1 - 33 - 1;
        wrong_count[at] = op::OP_16 - 1;
        assert_eq!(parse_pqpkh_script_sig(&wrong_count), None);
    }

    #[test]
    fn hkdf_rfc5869() {
        // A.1 (salt and info) and A.3 (empty salt and info), SHA-256 — the node's own checks.
        let ikm = [0x0b; 22];
        let salt: Vec<u8> = (0..=0x0c).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();
        let mut out = [0u8; 42];
        hkdf_sha256(&salt, &ikm, &info, &mut out);
        assert_eq!(
            hex(&out),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
        hkdf_sha256(&[], &ikm, &[], &mut out);
        assert_eq!(
            hex(&out),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        );
    }

    /// The node's A-12 derivation vector, `tests/vectors/pq_wallet_vectors.json` (a copy of the
    /// node's `src/test/data/pq_wallet_vectors.json` at `tests/vectors/PIN`, written by
    /// `gen_pq_wallet_vectors.py` and replayed by both lines' `pq_wallet_tests`): HKDF-SHA256 over
    /// the IKM, info `"Ycash PQ key" ‖ scheme ‖ index_be32`, 48 bytes, then KeyGen. `hdSeed` is the
    /// ycash-dd wallet's IKM (its 32-byte HD seed); `mnemonic` is ycash6's and YEW's (the 64-byte
    /// BIP39 seed of a 24-word English phrase, empty passphrase), so YEW's own path — phrase →
    /// [`crate::keys::seed_from_mnemonic`] → [`PqSeedRoot::from_seed`] — is checked against it.
    #[test]
    fn derivation_reproduces_the_node_wallet_vector() {
        let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/vectors/pq_wallet_vectors.json");
        let v: Value =
            serde_json::from_str(&std::fs::read_to_string(p).expect("pq_wallet_vectors.json"))
                .unwrap();
        assert_eq!(v["format"], "ycash-pq-wallet-vectors-1");
        assert_eq!(v["info"].as_str().unwrap().as_bytes(), DERIVE_INFO);
        let hd: Vec<u8> = (0u8..32).collect();
        assert_eq!(b(&v["hdSeed"]["ikm"]), hd);

        // YEW's path from the words: the phrase is the BIP39 encoding of the entropy, and its seed
        // (empty passphrase) is the mnemonic section's IKM.
        let m = &v["mnemonic"];
        let phrase = m["phrase"].as_str().unwrap();
        let words = bip39::Mnemonic::from_entropy(&b(&m["entropy"])).unwrap();
        assert_eq!(words.to_string(), phrase);
        assert_eq!(
            crate::keys::seed_from_mnemonic(phrase, "")
                .unwrap()
                .to_vec(),
            b(&m["ikm"])
        );

        let mut n = 0;
        for section in ["hdSeed", "mnemonic"] {
            let s = &v[section];
            let ikm = b(&s["ikm"]);
            let root = PqSeedRoot::from_seed(&ikm);
            for d in s["derive"].as_array().unwrap() {
                let scheme = d["scheme"].as_u64().unwrap() as u8;
                let index = d["index"].as_u64().unwrap() as u32;
                let seed = root.derive(scheme, index);
                assert_eq!(
                    hex(&seed),
                    d["seed"].as_str().unwrap(),
                    "{section} {scheme}/{index}"
                );
                // the RFC 5869 HKDF of the same inputs
                let mut info = DERIVE_INFO.to_vec();
                info.push(scheme);
                info.extend_from_slice(&index.to_be_bytes());
                let mut out = [0u8; SEED_SIZE];
                hkdf_sha256(&[], &ikm, &info, &mut out);
                assert_eq!(out, seed);
                let key = match scheme {
                    SCHEME_SLH_DSA_SHA2_128S => root.slh_key(index),
                    _ => root.falcon_key(index),
                };
                assert_eq!(key.id(), PqKey::from_seed(scheme, &seed).unwrap().id());
                n += 1;
            }
            let slh = &s["slh"];
            let k = root.slh_key(slh["index"].as_u64().unwrap() as u32);
            assert_eq!(
                hex(k.public_key()),
                slh["pk"].as_str().unwrap(),
                "{section}"
            );
            assert_eq!(
                hex(&k.id().hash),
                slh["keyhash"].as_str().unwrap(),
                "{section}"
            );
            assert_eq!(k.scheme(), 1);
            assert_ne!(root.slh_key(1).id(), k.id());
        }
        assert_eq!(n, 8, "a silently shrunk file fails");
    }
}
