// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The façade↔signer protocol (workspace plan `docs/plans/kogany/kogany-yellowback-plan.md` §3b S2,
//! decision K-24). S0 fixes the envelope only; S2 fills the key references, the act payloads and
//! the refusal reasons, and adds the vectors that pin the encoding.
//!
//! The rule the types encode: the signer is shown the **unsigned transaction bytes and every
//! spent prevout**, and recomputes every digest itself. No field carries a digest for the signer
//! to sign blindly.
//!
//! **S1: the public bundle.** The façade holds public material only (K-24, plan §4.3 rule 2):
//! the BIP32 account public key of the transparent tree, the Sapling full viewing key of the one
//! account, and the post-quantum public keys of a lookahead pool. The signer derives them from
//! the seed and hands them over as a [`PublicBundle`] ([`PublicRequest`] asks for more PQ keys
//! when the pool runs low, as ycashd's `TopUpPQKeys` does).

use serde::{Deserialize, Serialize};

/// The protocol version a request names; a signer refuses any other.
pub const PROTO_VERSION: u32 = 0;

/// One spent output, as the signer needs it to recompute the ZIP-243 digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Prevout {
    /// `txid:n`.
    pub outpoint: String,
    /// The spent output's `scriptPubKey`, hex.
    pub script: String,
    /// Its value in zatoshi.
    pub amount_zat: u64,
}

/// A request to sign one transaction (S2 completes the key references and act payloads).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignRequest {
    pub version: u32,
    /// The unsigned v4 transaction, hex.
    pub tx: String,
    /// The consensus branch ID of the next block (ZIP-243 binds it).
    pub branch_id: u32,
    /// One per transparent input, in input order.
    pub prevouts: Vec<Prevout>,
    /// The broadcast-gate path the signer checks the inputs against (yew-core `gate.rs`).
    pub gate_path: String,
    /// The largest value that may leave the wallet, in zatoshi; `None` for no cap.
    pub outflow_cap_zat: Option<u64>,
    /// A `HandoffPreview`-shaped summary (ycash6 `doc/vault-rpc.md` "Shapes") for a human or a
    /// device to compare with the bytes; the signer refuses a preview that disagrees with them.
    pub preview: serde_json::Value,
}

/// The signer's answer: the whole transaction signed, or a refusal. Never half-signed (H10).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "lowercase")]
pub enum SignResponse {
    Signed { tx: String },
    Refused { reason: String },
}

/// The format tag a [`PublicBundle`] carries.
pub const PUBLIC_FORMAT: &str = "yewd-public-1";

/// A BIP32 extended public key without depth, fingerprint or child number (yew-core never
/// serializes xpubs): the account node `m/44'/347'/0'`; the façade derives `/chain/index` itself
/// (CKDpub, non-hardened).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountXpub {
    /// The compressed public key, hex (33 bytes).
    pub pubkey: String,
    /// The chain code, hex (32 bytes).
    pub chain_code: String,
}

/// One post-quantum public key of the seed (quantum spec A-12: `DerivePQSeed(seed, scheme, index)`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqPublic {
    /// 1 = SLH-DSA-SHA2-128s, 2 = FN-DSA-512.
    pub scheme: u8,
    /// The derivation index within the scheme.
    pub index: u32,
    /// The public key, hex (32 bytes for scheme 1, 897 for scheme 2).
    pub pk: String,
}

/// What the façade asks the signer for: the post-quantum keys `[from, from + count)` of each
/// listed scheme (the transparent and Sapling material always comes with it).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicRequest {
    /// `(scheme, from, count)`.
    pub pq: Vec<(u8, u32, u32)>,
}

/// The public material of one seed: everything the façade needs to recognise the wallet's
/// coins, notes and vaults, and nothing that can spend them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicBundle {
    /// [`PUBLIC_FORMAT`].
    pub format: String,
    /// `main`, `test` or `regtest` (yew-core `Network::chain_name`).
    pub network: String,
    /// The ZIP-32 seed fingerprint (`BLAKE2b-256("Zcash_HD_Seed_FP", len ‖ seed)`), hex: what
    /// ycashd's `getwalletinfo` reports as `mnemonic_seedfp`; it identifies the seed, it does not
    /// reveal it.
    pub seed_fp: String,
    /// The transparent account node `m/44'/347'/0'`.
    pub account: AccountXpub,
    /// The Sapling diversifiable full viewing key of the account `m/32'/347'/0'`
    /// (`ak ‖ nk ‖ ovk ‖ dk`, 128 bytes), hex.
    pub sapling_dfvk: String,
    /// The post-quantum public keys asked for.
    pub pq: Vec<PqPublic>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_round_trips() {
        let r = SignResponse::Refused {
            reason: "preview disagrees with the bytes".into(),
        };
        let s = serde_json::to_string(&r).unwrap();
        assert_eq!(
            s,
            r#"{"result":"refused","reason":"preview disagrees with the bytes"}"#
        );
        assert_eq!(serde_json::from_str::<SignResponse>(&s).unwrap(), r);
    }

    #[test]
    fn public_request_round_trips() {
        let r = PublicRequest {
            pq: vec![(1, 0, 20), (2, 5, 1)],
        };
        let s = serde_json::to_string(&r).unwrap();
        assert_eq!(s, r#"{"pq":[[1,0,20],[2,5,1]]}"#);
        assert_eq!(serde_json::from_str::<PublicRequest>(&s).unwrap(), r);
    }
}
