//! Attestation bundles: the wire form, and compact-ECDSA verification of every attestation
//! against the seated attestor set returned by `YellowbackStreamer.ListAttestors` (plan §4
//! rule 6: "verify the bundle it is handed: every attestation's compact ECDSA signature against
//! the pubkey of its `seq` in `ListAttestors` — the server is a relay it cannot lie through,
//! only withhold").
//!
//! Translation source (plan §3.6): `ycash-dd/src/yellowback/bundle.cpp` (`EncodeBundle`
//! `:37-50`, `DecodeBundle` `:52-67`, `VerifyBundle` `:113-160`: shape → count → membership /
//! uniqueness → signatures; the freshness and price-range clauses need the node's parameter set
//! and are the node's to judge, so the client does not pretend to), `attest.cpp`
//! (`AttestMessage` `:38-49`, `VerifyCompactSig` `:51-63`, `EncodeAttestation` `:65-73`,
//! `DecodeAttestation` `:75-84`), and the Python reference
//! `qa/rpc-tests/test_framework/yellowback_attest.py:213-260`.
//!
//! Wire form (`bundle.h:24-25`): `"YA" ‖ version u8 (= 1) ‖ count u8 ‖ count × 74-byte
//! attestation`; an attestation (`attest.h:19-22`) is `seq u16 ‖ priceMicroUsd u32 ‖
//! citedHeight u32 ‖ sig 64 (compact r ‖ s)`, all little-endian. The signed message is
//! `SHA256("YBATTEST1" ‖ seq LE16 ‖ price LE32 ‖ citedHeight LE32 ‖ blockHash(citedHeight)
//! internal 32 bytes)`. A high-S signature is **rejected, never normalised** (R17): two
//! encodings of one signature would be two bundle hashes.

use std::collections::{HashMap, HashSet};

use secp256k1::ecdsa::Signature;
use secp256k1::{Message, PublicKey};
use thiserror::Error;

use crate::keys::sha256;

/// `BUNDLE_MAGIC` (`bundle.cpp:18`): `"YA"`.
pub const MAGIC: [u8; 2] = [0x59, 0x41];
/// `BUNDLE_VERSION` (`bundle.h:35`).
pub const VERSION: u8 = 1;
/// `BUNDLE_HEADER_SIZE` (`bundle.h:36`).
pub const HEADER_SIZE: usize = 4;
/// `ATTESTATION_SIZE` (`attest.h:29`).
pub const ATTESTATION_SIZE: usize = 74;
/// `BUNDLE_MAX` (`params.h:184`): six attestations, 448 bytes, inside the 520-byte push.
pub const BUNDLE_MAX: usize = 6;
/// `ATTEST_PREFIX` (`attest.cpp:17`): nine ASCII bytes, no length byte.
pub const ATTEST_PREFIX: &[u8; 9] = b"YBATTEST1";

/// Why a bundle was refused. The names are the node's `BundleVerdict.reason` values
/// (`bundle.h:106`) so a client refusal reads like a node refusal.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BundleError {
    /// Not `"YA" 0x01 count` followed by `count × 74` bytes.
    #[error("bundle-malformed: shape")]
    Shape,
    /// More than `BUNDLE_MAX` attestations, or none.
    #[error("bundle-refused: count {0} outside [1, {BUNDLE_MAX}]")]
    Count(usize),
    /// A `seq` that is not seated.
    #[error("bundle-refused: attestor seq {0} is not in the seated set")]
    Member(u16),
    /// The same `seq` twice.
    #[error("bundle-refused: attestor seq {0} appears twice")]
    Dup(u16),
    /// No block hash for a cited height (the server could not answer).
    #[error("bundle-refused: no block hash for cited height {0}")]
    NoBlock(u32),
    /// A signature that does not verify (or is high-S) under the seated key of its `seq`.
    #[error("bundle-refused: signature of attestor seq {0} over cited height {1} does not verify")]
    Sig(u16, u32),
}

/// One attestation (`attest.h:31-40`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attestation {
    /// The attestor's registration sequence number.
    pub seq: u16,
    /// The attested price, micro-USD per YEC.
    pub price_micro_usd: u32,
    /// The height whose block hash the signature commits to.
    pub cited_height: u32,
    /// The compact signature `r ‖ s`.
    pub sig: [u8; 64],
}

impl Attestation {
    /// `EncodeAttestation` (`attest.cpp:65-73`): 74 bytes.
    pub fn encode(&self) -> [u8; ATTESTATION_SIZE] {
        let mut out = [0u8; ATTESTATION_SIZE];
        out[0..2].copy_from_slice(&self.seq.to_le_bytes());
        out[2..6].copy_from_slice(&self.price_micro_usd.to_le_bytes());
        out[6..10].copy_from_slice(&self.cited_height.to_le_bytes());
        out[10..].copy_from_slice(&self.sig);
        out
    }

    /// `DecodeAttestation` (`attest.cpp:75-84`): exactly 74 bytes.
    pub fn decode(data: &[u8]) -> Option<Attestation> {
        if data.len() != ATTESTATION_SIZE {
            return None;
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&data[10..]);
        Some(Attestation {
            seq: u16::from_le_bytes([data[0], data[1]]),
            price_micro_usd: u32::from_le_bytes([data[2], data[3], data[4], data[5]]),
            cited_height: u32::from_le_bytes([data[6], data[7], data[8], data[9]]),
            sig,
        })
    }
}

/// `EncodeBundle` (`bundle.cpp:37-50`).
pub fn encode(atts: &[Attestation]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_SIZE + ATTESTATION_SIZE * atts.len());
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    out.push(atts.len().min(255) as u8);
    for a in atts.iter().take(255) {
        out.extend_from_slice(&a.encode());
    }
    out
}

/// `DecodeBundle` (`bundle.cpp:52-67`) with the encoding's own ceiling (255), as `VerifyBundle`
/// calls it (`:126`): the magic, version 1 and the exact length; the count bound is
/// [`verify`]'s.
pub fn decode(data: &[u8]) -> Result<Vec<Attestation>, BundleError> {
    if data.len() < HEADER_SIZE || data[0..2] != MAGIC || data[2] != VERSION {
        return Err(BundleError::Shape);
    }
    let count = data[3] as usize;
    if data.len() != HEADER_SIZE + ATTESTATION_SIZE * count {
        return Err(BundleError::Shape);
    }
    let mut atts = Vec::with_capacity(count);
    for i in 0..count {
        let start = HEADER_SIZE + ATTESTATION_SIZE * i;
        atts.push(
            Attestation::decode(&data[start..start + ATTESTATION_SIZE])
                .ok_or(BundleError::Shape)?,
        );
    }
    Ok(atts)
}

/// `SHA256(bundle)`: the commitment in the carrier script (`txbuilder.cpp:167-172`
/// `BundleHash`).
pub fn bundle_hash(bundle: &[u8]) -> [u8; 32] {
    sha256(bundle)
}

/// `AttestMessage` (`attest.cpp:38-49`): `block_hash` in internal byte order.
pub fn attest_message(
    seq: u16,
    price_micro_usd: u32,
    cited_height: u32,
    block_hash: &[u8; 32],
) -> [u8; 32] {
    let mut buf = [0u8; 9 + 2 + 4 + 4 + 32];
    buf[..9].copy_from_slice(ATTEST_PREFIX);
    buf[9..11].copy_from_slice(&seq.to_le_bytes());
    buf[11..15].copy_from_slice(&price_micro_usd.to_le_bytes());
    buf[15..19].copy_from_slice(&cited_height.to_le_bytes());
    buf[19..].copy_from_slice(block_hash);
    sha256(&buf)
}

/// `VerifyCompactSig` (`attest.cpp:51-63`): compact parse, **high-S rejected** (a signature
/// that `normalize_s` would change is refused, not repaired), verify under a compressed key.
pub fn verify_compact_sig(pk: &[u8; 33], msg: &[u8; 32], sig: &[u8; 64]) -> bool {
    let pk = match PublicKey::from_slice(pk) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let s = match Signature::from_compact(sig) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let mut low = s;
    low.normalize_s();
    if low.serialize_compact() != s.serialize_compact() {
        return false;
    }
    secp256k1::ecdsa::verify(&s, Message::from_digest(*msg), &pk).is_ok()
}

/// The seated set as `ListAttestors` gives it: `seq → attestorPubKey`.
pub type Seated = HashMap<u16, [u8; 33]>;

/// `VerifyBundle` (`bundle.cpp:113-160`) as far as a client can take it: shape → count (1 ..
/// `BUNDLE_MAX`) → every `seq` seated and unique → every signature under its seated key over
/// `attest_message(…, block_hash_at(citedHeight))`. Freshness (`stale`) and the price range
/// are the node's rules over its parameter set; the node's dry run judges them (D-W-5).
/// Returns the attestations in bundle order.
pub fn verify(
    bundle: &[u8],
    seated: &Seated,
    block_hash_at: impl Fn(u32) -> Option<[u8; 32]>,
) -> Result<Vec<Attestation>, BundleError> {
    let atts = decode(bundle)?;
    if atts.is_empty() || atts.len() > BUNDLE_MAX {
        return Err(BundleError::Count(atts.len()));
    }
    let mut seen = HashSet::new();
    for a in &atts {
        if !seated.contains_key(&a.seq) {
            return Err(BundleError::Member(a.seq));
        }
        if !seen.insert(a.seq) {
            return Err(BundleError::Dup(a.seq));
        }
    }
    for a in &atts {
        let hash = block_hash_at(a.cited_height).ok_or(BundleError::NoBlock(a.cited_height))?;
        let msg = attest_message(a.seq, a.price_micro_usd, a.cited_height, &hash);
        if !verify_compact_sig(&seated[&a.seq], &msg, &a.sig) {
            return Err(BundleError::Sig(a.seq, a.cited_height));
        }
    }
    Ok(atts)
}

/// `DefaultAttestPayee` (`ycash-dd/src/yellowback/state.cpp:1488-1509`, AFEE-W): the attestor
/// the node's wallet pays by default — of the bundle's `seq`s (sorted, unique) the one at
/// `SHA256(blockHash(R) ‖ selector ‖ "A") mod |A|`, the digest read as the node's
/// `arith_uint256` (little-endian). AFEE-1 accepts any `seq` of the bundle; this is the
/// wallet-policy pick, translated so the two wallets choose alike. The client has no
/// `-yellowbackpreferredattestor`.
pub fn default_attest_payee(block_hash_r: &[u8; 32], selector: &[u8], seqs: &[u16]) -> Option<u16> {
    let mut a: Vec<u16> = seqs.to_vec();
    a.sort_unstable();
    a.dedup();
    if a.is_empty() {
        return None;
    }
    let mut pre = Vec::with_capacity(32 + selector.len() + 1);
    pre.extend_from_slice(block_hash_r);
    pre.extend_from_slice(selector);
    pre.push(b'A');
    let digest = sha256(&pre);
    // digest as a little-endian integer, mod |A|.
    let n = a.len() as u64;
    let mut acc: u64 = 0;
    for b in digest.iter().rev() {
        acc = (acc * 256 + *b as u64) % n;
    }
    Some(a[acc as usize])
}

/// `OutPointSelector` (`yellowback_attest.py:420-422`, R13): the 36-byte serialised outpoint,
/// txid internal bytes then `vout` LE32 — the selector of a claim's bundle and fee payee.
pub fn outpoint_selector(txid: &[u8; 32], vout: u32) -> Vec<u8> {
    let mut s = Vec::with_capacity(36);
    s.extend_from_slice(txid);
    s.extend_from_slice(&vout.to_le_bytes());
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::SecretKey;

    /// `sign_attestation` (`yellowback_attest.py:226-234`): a low-S compact signature.
    pub(crate) fn sign(
        secret: &SecretKey,
        seq: u16,
        price: u32,
        cited: u32,
        hash: &[u8; 32],
    ) -> Attestation {
        let msg = attest_message(seq, price, cited, hash);
        let s = secp256k1::ecdsa::sign(Message::from_digest(msg), secret);
        Attestation {
            seq,
            price_micro_usd: price,
            cited_height: cited,
            sig: s.serialize_compact(),
        }
    }

    fn key(i: u8) -> (SecretKey, [u8; 33]) {
        let sk = SecretKey::from_secret_bytes([i; 32]).unwrap();
        (sk, PublicKey::from_secret_key(&sk).serialize())
    }

    #[test]
    fn encode_decode_and_message_shape() {
        let (sk, pk) = key(3);
        let hash = [7u8; 32];
        let a = sign(&sk, 5, 50_000_000, 480, &hash);
        let bytes = a.encode();
        assert_eq!(bytes.len(), ATTESTATION_SIZE);
        assert_eq!(&bytes[..2], &[5, 0]);
        assert_eq!(Attestation::decode(&bytes), Some(a.clone()));
        assert_eq!(Attestation::decode(&bytes[..73]), None);
        let b = encode(std::slice::from_ref(&a));
        assert_eq!(&b[..4], &[0x59, 0x41, 1, 1]);
        assert_eq!(decode(&b).unwrap(), vec![a.clone()]);
        assert_eq!(decode(&b[..b.len() - 1]), Err(BundleError::Shape));
        assert_eq!(decode(b"YB\x01\x00"), Err(BundleError::Shape));
        assert_eq!(decode(b"YA\x02\x00"), Err(BundleError::Shape));
        assert_eq!(decode(b"YA\x01\x00").unwrap(), Vec::<Attestation>::new());
        let msg = attest_message(5, 50_000_000, 480, &hash);
        assert!(verify_compact_sig(&pk, &msg, &a.sig));
        assert!(!verify_compact_sig(&key(4).1, &msg, &a.sig));
        // High-S is refused, not normalised (R17).
        let sig = Signature::from_compact(&a.sig).unwrap();
        let mut compact = sig.serialize_compact();
        // s' = n - s.
        let n = [
            0xffu8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x41,
        ];
        let mut borrow = 0i32;
        for i in (0..32).rev() {
            let d = n[i] as i32 - compact[32 + i] as i32 - borrow;
            compact[32 + i] = d.rem_euclid(256) as u8;
            borrow = i32::from(d < 0);
        }
        assert!(!verify_compact_sig(&pk, &msg, &compact));
    }

    #[test]
    fn verify_refuses_one_mutated_signature_and_bad_members() {
        let hash = |h: u32| -> Option<[u8; 32]> {
            if h >= 470 {
                Some([h as u8; 32])
            } else {
                None
            }
        };
        let mut seated = Seated::new();
        let mut atts = Vec::new();
        for seq in 0u16..3 {
            let (sk, pk) = key(seq as u8 + 10);
            seated.insert(seq, pk);
            atts.push(sign(
                &sk,
                seq,
                50_000_000 + seq as u32,
                480 + seq as u32,
                &hash(480 + seq as u32).unwrap(),
            ));
        }
        let good = encode(&atts);
        assert_eq!(verify(&good, &seated, hash).unwrap(), atts);
        // One mutated signature byte: refused, naming the attestor.
        let mut bad = good.clone();
        let off = HEADER_SIZE + ATTESTATION_SIZE + 10 + 40;
        bad[off] ^= 0x01;
        assert_eq!(verify(&bad, &seated, hash), Err(BundleError::Sig(1, 481)));
        // A mutated price: the message changes, the signature no longer verifies.
        let mut price = good.clone();
        price[HEADER_SIZE + 2] ^= 0x01;
        assert_eq!(verify(&price, &seated, hash), Err(BundleError::Sig(0, 480)));
        // Not seated, duplicated, empty, over the cap, no block hash.
        let mut unseated = seated.clone();
        unseated.remove(&2);
        assert_eq!(verify(&good, &unseated, hash), Err(BundleError::Member(2)));
        let dup = encode(&[atts[0].clone(), atts[0].clone()]);
        assert_eq!(verify(&dup, &seated, hash), Err(BundleError::Dup(0)));
        assert_eq!(
            verify(&encode(&[]), &seated, hash),
            Err(BundleError::Count(0))
        );
        let many: Vec<Attestation> = (0..7).map(|_| atts[0].clone()).collect();
        assert_eq!(
            verify(&encode(&many), &seated, hash),
            Err(BundleError::Count(7))
        );
        let (sk, pk) = key(30);
        seated.insert(9, pk);
        let old = encode(&[sign(&sk, 9, 1, 100, &[1; 32])]);
        assert_eq!(verify(&old, &seated, hash), Err(BundleError::NoBlock(100)));
        assert_eq!(bundle_hash(&good), sha256(&good));
        let sel = outpoint_selector(&[0xaa; 32], 3);
        assert_eq!(sel.len(), 36);
        assert_eq!(&sel[32..], &[3, 0, 0, 0]);
        // DefaultAttestPayee: deterministic, in A, order-insensitive; None for an empty A.
        let pick = default_attest_payee(&[1; 32], &sel, &[2, 0, 1]).unwrap();
        assert!(pick < 3);
        assert_eq!(
            default_attest_payee(&[1; 32], &sel, &[0, 1, 2, 2]),
            Some(pick)
        );
        assert_eq!(default_attest_payee(&[1; 32], &sel, &[7]), Some(7));
        assert_eq!(default_attest_payee(&[1; 32], &sel, &[]), None);
    }
}
