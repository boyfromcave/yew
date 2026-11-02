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
}
