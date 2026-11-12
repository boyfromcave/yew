// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The Sapling part of a hybrid transaction and its wire types (moved from `yewd_proto`, review
//! YEW-PORT-5 R1; `yewd_proto` re-exports them, the wire format unchanged).

use serde::{Deserialize, Serialize};

/// The Sapling part of a yewd `SignRequest`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaplingPart {
    pub target_height: u32,
    pub vault_height: Option<u32>,
    pub spends: Vec<SaplingSpend>,
    /// Shielded outputs only ([`SaplingOut::Shielded`] / [`SaplingOut::Change`]).
    pub outputs: Vec<SaplingOut>,
    /// The anchor of the spends (empty: none).
    pub anchor: String,
    pub params_dir: String,
}

impl SaplingPart {
    /// `(spent, paid, paid to the wallet)`: the values the preview adds.
    pub fn values(&self) -> (i64, i64, i64) {
        let spent: i64 = self.spends.iter().map(|s| s.value as i64).sum();
        let mut paid = 0;
        let mut own = 0;
        for o in &self.outputs {
            let (v, mine) = match o {
                SaplingOut::Shielded { value, own, .. } => (*value, *own),
                SaplingOut::Change { value } => (*value, true),
                SaplingOut::Transparent { .. } => (0, false),
            };
            paid += v;
            if mine {
                own += v;
            }
        }
        (spent, paid, own)
    }
}

/// A Sapling note to spend (`z_sendmany`, S4; F-S2-8): the note the façade decrypted and its
/// Merkle path at the anchor, computed by the façade from the node's tree state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaplingSpend {
    /// The recipient address, 43 bytes hex (diversifier ‖ pk_d).
    pub recipient: String,
    pub value: u64,
    /// `rseed`: 32 bytes hex; `after_zip212` picks the variant.
    pub rseed: String,
    pub after_zip212: bool,
    /// The note was received on the account's internal (change) scope.
    pub internal: bool,
    /// The note's position in the commitment tree.
    pub position: u64,
    /// The authentication path, 32 nodes hex (leaf to root).
    pub path: Vec<String>,
}

/// An output of a Sapling-capable build.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SaplingOut {
    /// A transparent output (P2PKH or P2SH script).
    Transparent {
        script: String,
        value: i64,
        own: bool,
    },
    /// A Sapling output: the encoded address, the memo (512 bytes hex; empty = no memo).
    Shielded {
        address: String,
        value: i64,
        memo: String,
        own: bool,
    },
    /// A Sapling output to the account's internal (change) address.
    Change { value: i64 },
}
