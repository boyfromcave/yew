// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The preview of a transaction (ycash6 `HandoffSend`'s `HandoffPreview`), computed from the bytes
//! and the prevouts. The façade computes it to show it (`vault_send … {"dryrun": true}`) and to put
//! it in a [`crate::SignRequest`]; the signer computes it again from the same bytes and refuses a
//! request whose preview differs (`preview-mismatch`). Both sides run this one function over the
//! bytes, so the preview is a statement about the bytes, never the façade's word.

use std::collections::BTreeSet;

use yew_core::params::Network;
use yew_core::tx::Transaction;

use crate::{Preview, PreviewCoin, PreviewOutput, Prevout};

/// The address ycashd prints for a script (`ScriptAddress`): P2PKH, P2SH, `TX_PQPKH`.
pub fn script_address(network: Network, script: &[u8]) -> Option<String> {
    if let Some(h) = yew_core::script::p2pkh_hash(script) {
        return Some(yew_core::keys::encode_p2pkh(network, &h));
    }
    if let Some(h) = yew_core::script::p2sh_hash(script) {
        return Some(yew_core::keys::encode_p2sh(network, &h));
    }
    let id = yew_core::pq::pqpkh_of(script)?;
    yew_core::keys::encode_pq_yec(network, &id)
}

/// `OutputKind`: `act`, `vault`, `intent`, `bond` (a bare bond redeem script), else `payment`.
pub fn output_kind(spk: &[u8]) -> &'static str {
    if crate::act::is_act_output(spk) {
        "act"
    } else if yew_core::vault::parse_vault(spk).is_some() {
        "vault"
    } else if yew_core::vault::parse_intent(spk).is_some() {
        "intent"
    } else if is_bond_redeem(spk) {
        "bond"
    } else {
        "payment"
    }
}

/// `ParseBondRedeem`: `<locktime> CLTV DROP <33-byte key> CHECKSIG`.
pub fn is_bond_redeem(spk: &[u8]) -> bool {
    let Ok(o) = yew_core::script::ops(spk) else {
        return false;
    };
    o.len() == 5
        && o[1].opcode == yew_core::script::op::OP_CHECKLOCKTIMEVERIFY
        && o[2].opcode == yew_core::script::op::OP_DROP
        && o[3].data.len() == 33
        && o[4].opcode == yew_core::script::op::OP_CHECKSIG
}

/// The preview of `tx` spending `prevouts` (one per input, in order), signing the inputs `signed`
/// names, with the outputs `own` names as the wallet's.
pub fn compute(
    network: Network,
    tx: &Transaction,
    prevouts: &[Prevout],
    signed: &BTreeSet<u32>,
    own: &BTreeSet<u32>,
) -> Preview {
    let mut sign = Vec::new();
    let mut signed_in = 0i64;
    let mut total_in = 0i64;
    for (i, p) in prevouts.iter().enumerate() {
        total_in += p.amount_zat;
        if signed.contains(&(i as u32)) {
            signed_in += p.amount_zat;
            sign.push(PreviewCoin {
                vin: i as u32,
                outpoint: p.outpoint.clone(),
                amount_zat: p.amount_zat,
            });
        }
    }
    let mut outputs = Vec::new();
    let mut own_out = 0i64;
    for (n, o) in tx.vout.iter().enumerate() {
        let mine = own.contains(&(n as u32));
        if mine {
            own_out += o.value;
        }
        let address = script_address(network, &o.script_pubkey);
        outputs.push(PreviewOutput {
            n: n as u32,
            amount_zat: o.value,
            script: address.is_none().then(|| hex::encode(&o.script_pubkey)),
            address,
            mine,
            kind: output_kind(&o.script_pubkey).to_string(),
        });
    }
    Preview {
        sign,
        outputs,
        fee_zat: total_in - tx.output_total(),
        outflow_zat: signed_in - own_out,
    }
}

/// [`compute`] for a transaction with a Sapling part: its spends fund it, its outputs are paid
/// (S4, [`crate::SaplingPart`]).
pub fn with_sapling(mut p: Preview, part: Option<&crate::SaplingPart>) -> Preview {
    if let Some(part) = part {
        let (spent, paid, own) = part.values();
        p.fee_zat += spent - paid;
        p.outflow_zat += spent - own;
    }
    p
}

/// The first difference between two previews, for the refusal's reason.
pub fn difference(want: &Preview, got: &Preview) -> Option<String> {
    if want.sign != got.sign {
        return Some(format!(
            "the inputs to sign are {:?}, the preview lists {:?}",
            want.sign
                .iter()
                .map(|c| (c.vin, c.outpoint.as_str(), c.amount_zat))
                .collect::<Vec<_>>(),
            got.sign
                .iter()
                .map(|c| (c.vin, c.outpoint.as_str(), c.amount_zat))
                .collect::<Vec<_>>()
        ));
    }
    if want.outputs.len() != got.outputs.len() {
        return Some(format!(
            "the transaction has {} outputs, the preview {}",
            want.outputs.len(),
            got.outputs.len()
        ));
    }
    for (a, b) in want.outputs.iter().zip(&got.outputs) {
        if a != b {
            return Some(format!(
                "output {}: the bytes pay {} zat to {}, the preview {} zat to {}",
                a.n,
                a.amount_zat,
                a.address.as_deref().or(a.script.as_deref()).unwrap_or("?"),
                b.amount_zat,
                b.address.as_deref().or(b.script.as_deref()).unwrap_or("?")
            ));
        }
    }
    if want.fee_zat != got.fee_zat {
        return Some(format!(
            "the fee is {} zat, the preview says {}",
            want.fee_zat, got.fee_zat
        ));
    }
    if want.outflow_zat != got.outflow_zat {
        return Some(format!(
            "the outflow is {} zat, the preview says {}",
            want.outflow_zat, got.outflow_zat
        ));
    }
    None
}
