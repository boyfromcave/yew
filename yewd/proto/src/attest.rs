// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The attestor role's messages (S3), re-derived from ycash6 at the revision `yewd/PIN` names
//! (plan §4.3 rule 1) and checked against `yellowback_attest_vectors.json` and the C++ unit tests'
//! layouts:
//!
//! - the 74-byte attestation and its message are yew-core's (`bundle.rs`: `AttestMessage`,
//!   `EncodeAttestation`, `VerifyCompactSig`);
//! - the cancel co-signature message `SHA256d("YedCancelCosign" ‖ attestorSetId ‖ intentTxid ‖
//!   n ‖ citedHeight ‖ price ‖ blockHash(R))` (ycash6 `src/yellowback/attest.cpp`
//!   `CancelCosignMessage`) and the `"YC"` list a cancel's carrier holds (`bundle.cpp`
//!   `EncodeCancelCosigns` / `DecodeCancelCosigns`);
//! - `signmessage`'s digest: `SHA256d(ser("Zcash Signed Message:\n") ‖ ser(message))`
//!   (`src/wallet/rpcwallet.cpp` `signmessage`, `src/main.cpp` `strMessageMagic`);
//! - RED-4's claimable test (`src/yellowback/math.h` `IsUnderwater`), which a cancel
//!   co-signature's price statement must not meet.

use yew_core::keys::sha256d;

/// `CANCEL_COSIGN_PREFIX` (`attest.h`): 15 bytes.
pub const CANCEL_COSIGN_PREFIX: &[u8; 15] = b"YedCancelCosign";
/// The `"YC"` list's magic, version, ceiling and entry size (`bundle.h`).
pub const COSIGN_MAGIC: [u8; 2] = *b"YC";
pub const CANCEL_COSIGN_VERSION: u8 = 1;
pub const CANCEL_COSIGN_MAX: usize = 7;
pub const CANCEL_COSIGN_ENTRY_SIZE: usize = 69;
/// `PRICE_MIN` / `PRICE_MAX` (`params.h`), micro-USD per YEC.
pub const PRICE_MIN: i64 = 100;
pub const PRICE_MAX: i64 = 4_294_967_295;
/// `strMessageMagic` (`src/main.cpp`).
pub const MESSAGE_MAGIC: &str = "Zcash Signed Message:\n";
const COIN: u128 = 100_000_000;

/// `CancelCosignMessage`: every hash argument in internal byte order.
pub fn cancel_cosign_message(
    attestor_set_id: &[u8; 32],
    intent_txid: &[u8; 32],
    intent_n: u32,
    cited_height: u32,
    price_micro_usd: u32,
    block_hash: &[u8; 32],
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(123);
    buf.extend_from_slice(CANCEL_COSIGN_PREFIX);
    buf.extend_from_slice(attestor_set_id);
    buf.extend_from_slice(intent_txid);
    buf.extend_from_slice(&intent_n.to_le_bytes());
    buf.extend_from_slice(&cited_height.to_le_bytes());
    buf.extend_from_slice(&price_micro_usd.to_le_bytes());
    buf.extend_from_slice(block_hash);
    sha256d(&buf)
}

/// One co-signature entry: the stated price and a 65-byte recoverable signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CosignEntry {
    pub price_micro_usd: u32,
    pub sig: [u8; 65],
}

impl CosignEntry {
    /// The 69 bytes `price_le32 ‖ sig65` (`yed_signcancelcosign`'s `cosig`).
    pub fn bytes(&self) -> [u8; CANCEL_COSIGN_ENTRY_SIZE] {
        let mut b = [0u8; CANCEL_COSIGN_ENTRY_SIZE];
        b[..4].copy_from_slice(&self.price_micro_usd.to_le_bytes());
        b[4..].copy_from_slice(&self.sig);
        b
    }

    pub fn from_bytes(b: &[u8]) -> Option<CosignEntry> {
        if b.len() != CANCEL_COSIGN_ENTRY_SIZE {
            return None;
        }
        Some(CosignEntry {
            price_micro_usd: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            sig: b[4..].try_into().ok()?,
        })
    }
}

/// `EncodeCancelCosigns`: `None` for an empty list or more than [`CANCEL_COSIGN_MAX`].
pub fn encode_cosigns(entries: &[CosignEntry]) -> Option<Vec<u8>> {
    if entries.is_empty() || entries.len() > CANCEL_COSIGN_MAX {
        return None;
    }
    let mut out = vec![
        COSIGN_MAGIC[0],
        COSIGN_MAGIC[1],
        CANCEL_COSIGN_VERSION,
        entries.len() as u8,
    ];
    for e in entries {
        out.extend_from_slice(&e.bytes());
    }
    Some(out)
}

/// `DecodeCancelCosigns`: magic, version 1, `1 ≤ count ≤ 7`, the exact length.
pub fn decode_cosigns(data: &[u8]) -> Option<Vec<CosignEntry>> {
    if data.len() < 4 || data[..2] != COSIGN_MAGIC || data[2] != CANCEL_COSIGN_VERSION {
        return None;
    }
    let count = data[3] as usize;
    if !(1..=CANCEL_COSIGN_MAX).contains(&count)
        || data.len() != 4 + CANCEL_COSIGN_ENTRY_SIZE * count
    {
        return None;
    }
    data[4..]
        .chunks(CANCEL_COSIGN_ENTRY_SIZE)
        .map(CosignEntry::from_bytes)
        .collect()
}

/// Bitcoin's `CompactSize` length prefix, then the bytes (`ser(std::string)`).
fn ser_string(out: &mut Vec<u8>, s: &[u8]) {
    let n = s.len() as u64;
    if n < 253 {
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(253);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        out.push(254);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        out.push(255);
        out.extend_from_slice(&n.to_le_bytes());
    }
    out.extend_from_slice(s);
}

/// `signmessage`'s digest (`CHashWriter << strMessageMagic << strMessage`, SHA256d).
pub fn message_hash(message: &str) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 + message.len());
    ser_string(&mut buf, MESSAGE_MAGIC.as_bytes());
    ser_string(&mut buf, message.as_bytes());
    sha256d(&buf)
}

/// `IsUnderwater` (RED-4): `collateralZat × price < mintedCents × thresholdBps × COIN`; never for
/// a non-positive price, debt or threshold.
pub fn is_underwater(
    collateral_zat: i64,
    price_micro_usd: i64,
    minted_cents: i64,
    threshold_bps: i64,
) -> bool {
    if price_micro_usd <= 0 || minted_cents <= 0 || threshold_bps <= 0 {
        return false;
    }
    let c = collateral_zat.max(0) as u128;
    c * (price_micro_usd as u128) < (minted_cents as u128) * (threshold_bps as u128) * COIN
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `yellowback_bundle_tests.cpp` `cancel_cosign_codecs`: the preimage layout (123 bytes).
    #[test]
    fn cosign_message_layout() {
        let set = [0x11u8; 32];
        let txid = [0x22u8; 32];
        let bh = [0x33u8; 32];
        let mut pre = b"YedCancelCosign".to_vec();
        pre.extend_from_slice(&set);
        pre.extend_from_slice(&txid);
        for v in [2u32, 950, 50000] {
            pre.extend_from_slice(&v.to_le_bytes());
        }
        pre.extend_from_slice(&bh);
        assert_eq!(pre.len(), 123);
        assert_eq!(
            cancel_cosign_message(&set, &txid, 2, 950, 50000, &bh),
            sha256d(&pre)
        );
    }

    #[test]
    fn cosign_list_round_trips_and_refuses_bad_shapes() {
        let e = CosignEntry {
            price_micro_usd: 50_000,
            sig: [7u8; 65],
        };
        let blob = encode_cosigns(&vec![e.clone(); 7]).unwrap();
        assert_eq!(blob.len(), 4 + 69 * 7);
        assert!(blob.len() <= 520);
        assert_eq!(decode_cosigns(&blob).unwrap(), vec![e.clone(); 7]);
        assert!(encode_cosigns(&[]).is_none());
        assert!(encode_cosigns(&vec![e.clone(); 8]).is_none());
        let mut bad = blob.clone();
        bad.pop();
        assert!(decode_cosigns(&bad).is_none());
        let mut bad = blob.clone();
        bad[3] = 0;
        assert!(decode_cosigns(&bad).is_none());
        let mut bad = blob.clone();
        bad[2] = 2;
        assert!(decode_cosigns(&bad).is_none());
        let mut bad = blob;
        bad[1] = b'A';
        assert!(decode_cosigns(&bad).is_none());
        assert_eq!(CosignEntry::from_bytes(&e.bytes()).unwrap(), e);
    }

    #[test]
    fn message_hash_is_the_magic_and_the_text() {
        let mut pre = vec![22u8];
        pre.extend_from_slice(b"Zcash Signed Message:\n");
        pre.push(5);
        pre.extend_from_slice(b"hello");
        assert_eq!(message_hash("hello"), sha256d(&pre));
        let long = "x".repeat(300);
        let mut pre = vec![22u8];
        pre.extend_from_slice(b"Zcash Signed Message:\n");
        pre.extend_from_slice(&[253, 0x2c, 0x01]);
        pre.extend_from_slice(long.as_bytes());
        assert_eq!(message_hash(&long), sha256d(&pre));
    }

    #[test]
    fn underwater_is_red4() {
        // 1 YEC at $1 against $1 of debt at θ 125 %: underwater
        assert!(is_underwater(100_000_000, 1_000_000, 100, 12_500));
        // at $1.25 exactly: not (strictly less)
        assert!(!is_underwater(100_000_000, 1_250_000, 100, 12_500));
        assert!(!is_underwater(100_000_000, 0, 100, 12_500));
        assert!(!is_underwater(100_000_000, 1, 0, 12_500));
        assert!(is_underwater(-5, 1, 1, 1));
    }
}
