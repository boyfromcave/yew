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
//! golden vectors: `tests/vectors/pq_vectors.json` (a byte copy of the node's
//! `src/test/data/pq_vectors.json`), and the owner spend of `tests/vectors/vault_vectors.json`.
//!
//! **Scheme 1, SLH-DSA-SHA2-128s:** FIPS 205 *pure* SLH-DSA with an empty context string
//! (`M' = 0x00 ‖ 0x00 ‖ msg`), deterministic signing (`opt_rand = PK.seed`), key generation from
//! the 48-byte seed `SK.seed ‖ SK.prf ‖ PK.seed` (`slh_keygen_internal`). The implementation is
//! RustCrypto's `slh-dsa` =0.1.0 (FIPS 205 final; client survey §1). The message is the 32 bytes
//! of the ZIP-243 sighash in memory order, exactly what [`crate::tx::Transaction::sighash`]
//! returns and what the ECDSA signer hands secp256k1.
//!
//! **Scheme 2, FN-DSA-512 (PQClean `falcon-padded-512`):** YEW neither signs nor verifies it
//! yet. Its sizes are registered (chunking, size estimates, the scheme byte of a script), and
//! the key id of a Falcon key is computed like any other, but [`PqKey::from_seed`] and
//! [`verify`] refuse scheme 2. A Falcon holder needs PQClean's keygen (48-byte seed into its
//! SHAKE256 DRBG, spec ruling C-8) and signer byte for byte — the node's vendored
//! `falcon-padded-512/clean` built with `cc`, or `fn-dsa =0.3.0` in original-Falcon mode proven
//! against PQClean both ways (client survey C-7; `fn-dsa` 0.4 is not compatible) — plus the
//! 88-byte signing entropy the node's vectors carry (`entropy`), since Falcon signing is
//! randomized.
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
}

// ---------------------------------------------------------------------------------------------
// Keys, signing, verification

/// A PQ key pair kept as its 48-byte seed (wiped on drop) and its public key.
pub struct PqKey {
    scheme: u8,
    seed: [u8; SEED_SIZE],
    pk: Vec<u8>,
}

impl std::fmt::Debug for PqKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PqKey({}, {:?})", self.scheme, self.id())
    }
}

impl Drop for PqKey {
    fn drop(&mut self) {
        wipe(&mut self.seed);
    }
}

fn slh_signing_key(seed: &[u8; SEED_SIZE]) -> slh_dsa::SigningKey<Slh> {
    slh_dsa::SigningKey::<Slh>::slh_keygen_internal(&seed[..16], &seed[16..32], &seed[32..])
}

impl PqKey {
    /// `pq::KeyGen`: SLH-DSA from `SK.seed ‖ SK.prf ‖ PK.seed`. Scheme 2 is refused (no Falcon
    /// signer in YEW yet; module docs).
    pub fn from_seed(scheme: u8, seed: &[u8]) -> Result<PqKey, PqError> {
        if scheme != SCHEME_SLH_DSA_SHA2_128S {
            return Err(PqError::Scheme(scheme));
        }
        let seed: [u8; SEED_SIZE] = seed.try_into().map_err(|_| PqError::Size {
            what: "seed",
            got: seed.len(),
            want: SEED_SIZE,
        })?;
        let pk = slh_signing_key(&seed).verifying_key().to_bytes().to_vec();
        Ok(PqKey { scheme, seed, pk })
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
    pub fn sign(&self, msg: &[u8; 32]) -> Vec<u8> {
        let sk = slh_signing_key(&self.seed);
        sk.try_sign_with_context(msg, &[], None)
            .expect("an empty context is at most 255 bytes")
            .to_vec()
    }
}

/// `pq::Verify` for the schemes YEW implements (SLH-DSA); `false` for anything else, a wrong
/// size, or a bad signature. A wallet-side self-check, never a verdict (the node judges).
pub fn verify(scheme: u8, pk: &[u8], sig: &[u8], msg: &[u8; 32]) -> bool {
    if scheme != SCHEME_SLH_DSA_SHA2_128S
        || pk.len() != pub_key_size(scheme)
        || sig.len() != sig_size(scheme)
    {
        return false;
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

    /// Every SLH-DSA entry of the node's golden vectors: seed → pk, keyhash, and msg → sig byte
    /// for byte (deterministic signing), and the signature verifies. Falcon entries: the key
    /// hash only (YEW has no Falcon implementation; module docs).
    #[test]
    fn slh_dsa_reproduces_the_node_vectors() {
        let v = vectors();
        assert_eq!(v["format"], "ycash-pq-vectors-1");
        let mut slh = 0;
        for k in v["keys"].as_array().unwrap() {
            let scheme = k["scheme"].as_u64().unwrap() as u8;
            let pk = b(&k["pk"]);
            let keyhash: [u8; 32] = b(&k["keyhash"]).try_into().unwrap();
            assert_eq!(key_hash(scheme, &pk), keyhash, "{}", k["label"]);
            assert_eq!(pk.len(), pub_key_size(scheme));
            assert_eq!(b(&k["sig"]).len(), sig_size(scheme));
            if scheme != SCHEME_SLH_DSA_SHA2_128S {
                assert_eq!(
                    PqKey::from_seed(scheme, &b(&k["seed"])).unwrap_err(),
                    PqError::Scheme(scheme)
                );
                continue;
            }
            slh += 1;
            assert_eq!(
                b(&k["entropy"]),
                Vec::<u8>::new(),
                "SLH-DSA is deterministic"
            );
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
            let sig = key.sign(&msg);
            assert_eq!(hex(&sig), hex(&b(&k["sig"])), "{}", k["label"]);
            assert!(verify(scheme, &pk, &sig, &msg));
            let mut bad = msg;
            bad[0] ^= 1;
            assert!(!verify(scheme, &pk, &sig, &bad));
            let mut bad_sig = sig.clone();
            bad_sig[100] ^= 1;
            assert!(!verify(scheme, &pk, &bad_sig, &msg));
        }
        assert_eq!(slh, 2);
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

    /// `pq_wallet_tests.cpp` `derivation_vector` (ycash-dd `q/wallet`): HD seed 0x00..0x1f.
    #[test]
    fn derivation_reproduces_the_node_wallet_vector() {
        let raw: Vec<u8> = (0u8..32).collect();
        let root = PqSeedRoot::from_seed(&raw);
        assert_eq!(
            hex(&root.derive(1, 0)),
            "335a7ef8fa0ab4fc9faeff290ce40ea4fce101b983c70cc23ac4893354fbda10d5fcce4ade352f727cfa37db588a9e1f"
        );
        assert_eq!(
            hex(&root.derive(1, 1)),
            "b4e9e97fedc3632dec77709ed522bab4fbc8d65f6ebf6359418d4d2f854b02c7d01ca11d6fdc81b91cddd1ada728fccf"
        );
        assert_eq!(
            hex(&root.derive(2, 0)),
            "16f91ba800e9d23d547e5e45f588464fa5102f3caa75fcb0dd3fd8cad5aa608f8368b05457b73d98aff51f5725c998b3"
        );
        let mut seed = [0u8; 48];
        hkdf_sha256(&[], &raw, b"Ycash PQ key\x01\x00\x00\x00\x00", &mut seed);
        assert_eq!(seed, root.derive(1, 0));
        let k = root.slh_key(0);
        assert_eq!(
            hex(k.public_key()),
            "d5fcce4ade352f727cfa37db588a9e1f3803cb0b132b60db35f26e8343f0500a"
        );
        assert_eq!(
            hex(&k.id().hash),
            "73efa99cd22fe553222b1db6a6a021b3cba29dafd4fb4dfb50be69abcfcf9364"
        );
        assert_eq!(k.scheme(), 1);
        assert_ne!(root.slh_key(1).id(), k.id());
    }
}
