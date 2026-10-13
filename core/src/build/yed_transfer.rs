// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! A YED transfer (TRANSFER, spec §3.5): YED inputs from the floor-aware selector, one
//! `TOKEN_VALUE` P2PKH output per recipient, one for YED change (next change address), the
//! `OP_RETURN` TRANSFER payload, YEC fee inputs from `FEE_RESERVE` then `YEC` (plan §3.7 item
//! 3 — never any other class), YEC change to the same change address, `nExpiryHeight = tip +
//! TX_EXPIRY_DELTA`, signed with ZIP-243. The preview is the transaction that will be sent.
//!
//! Translation source (plan §3.6): `ycash-dd/src/yellowback/txbuilder.cpp:1213-1290`
//! (`BuildTransfer`), `:529-556` (`SelectYed` and its refusals), `:501-510` (`RankedCoins`).
//! Differences from the node: the YEC side selects from the wallet's classes (the node has the
//! whole keypool), the YED and the YEC change share one change address (§3.7 "Change"), and
//! the node's `refHeight`-based expiry is the same `tip + 40` the YEC send uses.
//!
//! [`assemble`] is the low-level step (inputs and assignments in, signed bytes out) that
//! [`build_yed_transfer`] calls with the selector's answer; the devnet suite calls it with a
//! deliberately wrong assignment to prove the gate refuses it. It is not a gate bypass: nothing
//! reaches the network without [`broadcast`], which runs both layers of [`crate::gate`].

use thiserror::Error;

use crate::coins::{self, Utxo, UtxoClass};
use crate::coinselect::{self, Alternatives, SelectStage};
use crate::gate::{self, Validator};
use crate::keys::{self, YedDestination};
use crate::net::{CompactClient, Validation};
use crate::params::Network;
use crate::params::{MAX_INPUTS, MIN_OUTPUT_CENTS, TOKEN_VALUE, TX_EXPIRY_DELTA};
use crate::payload::{self, Assignment, Payload, MAX_ASSIGNMENTS};
use crate::script;
use crate::store::HistoryRow;
use crate::tx::{txid_hex, OutPoint, Transaction, TxIn, TxOut};
use crate::wallet::{dollars, Wallet, WalletError};

use super::yec_send::MIN_CHANGE;

/// `MAX_ASSIGNMENTS - 1` recipients: one assignment is kept for the change
/// (`txbuilder.cpp:1218`).
pub const MAX_RECIPIENTS: usize = MAX_ASSIGNMENTS - 1;

/// `maxOutput` (XFER-1; `ycash-dd/src/yellowback/params.cpp:19`): $100,000 per output.
pub const MAX_OUTPUT_CENTS: u64 = 10_000_000;

/// Why a transfer could not be built (the node's identifiers, `doc/yellowback-rpc.md`).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TransferError {
    /// No recipients.
    #[error("no recipients")]
    NoRecipients,
    /// More than [`MAX_RECIPIENTS`].
    #[error("at most {MAX_RECIPIENTS} recipients per transaction")]
    TooManyRecipients,
    /// `bad-xfer-amount`.
    #[error("bad-xfer-amount: {0} cents is outside [{MIN_OUTPUT_CENTS}, {MAX_OUTPUT_CENTS}]")]
    BadAmount(u64),
    /// `insufficient-yed`.
    #[error("insufficient-yed: need {need} cents, have {have} confirmed and spendable")]
    InsufficientYed {
        /// Needed.
        need: u64,
        /// Spendable.
        have: u64,
    },
    /// `too-many-inputs` (H11).
    #[error(
        "too-many-inputs: more than {MAX_INPUTS} YED inputs would be needed; consolidate first"
    )]
    TooManyInputs,
    /// `change-floor` (H2), with `NearestWorkable`'s alternatives.
    #[error("change-floor: {needed} cents cannot be sent from these coins without change below the $1.00 minimum output; nearest workable amounts: below {}, above {}", .below.map(|c| c.to_string()).unwrap_or_else(|| "none".into()), .above.map(|c| c.to_string()).unwrap_or_else(|| "none".into()))]
    ChangeFloor {
        /// The request.
        needed: u64,
        /// The largest workable amount below it.
        below: Option<i64>,
        /// The smallest workable amount above it.
        above: Option<i64>,
    },
    /// The payload could not be encoded.
    #[error("cannot encode the transfer payload")]
    Payload,
    /// `TOK-PQ` (quantum spec F-7): Falcon is active, so every output that receives YED must be a
    /// Falcon (scheme 2) post-quantum key: a P2PKH or SLH-DSA recipient is refused (YEW's own
    /// change goes to its Falcon holder keys).
    #[error("falcon-holder-required: Falcon is active, so YED can only go to a Falcon post-quantum address: {0}")]
    FalconHolderRequired(String),
}

/// What the screen renders and what will be broadcast, unchanged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct YedTransferPreview {
    /// The recipients as given, with their cents.
    pub recipients: Vec<(String, u64)>,
    /// The YED inputs spent.
    pub yed_inputs: Vec<Utxo>,
    /// The selector stage that chose them.
    pub stage: SelectStage,
    /// The YED change in cents (0 = none).
    pub change_cents: u64,
    /// The YEC inputs spent for the fee and the new token outputs.
    pub yec_inputs: Vec<Utxo>,
    /// The YEC fee actually paid (`FEE_ZAT`, plus folded change).
    pub fee: i64,
    /// The YEC change (0 = none).
    pub yec_change: i64,
    /// The change address (`s…` form) when either change exists.
    pub change_address: Option<String>,
    /// The payload bytes.
    pub payload: Vec<u8>,
    /// `nExpiryHeight`.
    pub expiry_height: u32,
    /// The signed transaction.
    pub raw: Vec<u8>,
    /// Its txid (internal order).
    pub txid: [u8; 32],
}

/// The output of [`assemble`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assembled {
    /// The signed transaction.
    pub raw: Vec<u8>,
    /// Its txid.
    pub txid: [u8; 32],
    /// The YEC inputs chosen.
    pub yec_inputs: Vec<Utxo>,
    /// The YEC fee paid.
    pub fee: i64,
    /// The YEC change.
    pub yec_change: i64,
    /// The payload bytes.
    pub payload: Vec<u8>,
    /// `nExpiryHeight`.
    pub expiry_height: u32,
}

/// Assemble and sign a TRANSFER from chosen YED inputs and token outputs
/// (`txbuilder.cpp:1229-1276`): `vin` = `yed_inputs` then the YEC inputs; `vout[i]` =
/// `TOKEN_VALUE` to `token_outputs[i].0`, assigned `token_outputs[i].1` cents; then the
/// `OP_RETURN` payload; then YEC change to `yec_change_hash`. The YEC needed is
/// `tokenOut + fee − tokenIn` (`:1253`), from `FEE_RESERVE` then `YEC`.
pub fn assemble(
    wallet: &Wallet,
    yed_inputs: &[Utxo],
    token_outputs: &[(Vec<u8>, u32)],
    yec_change_hash: &[u8; 20],
    tip: u64,
    branch_id: u32,
) -> Result<Assembled, WalletError> {
    let assignments: Vec<Assignment> = token_outputs
        .iter()
        .enumerate()
        .map(|(i, (_, cents))| Assignment {
            vout: i as u8,
            cents: *cents,
        })
        .collect();
    let payload_bytes = payload::encode(&Payload::Transfer { assignments })
        .ok_or(WalletError::Transfer(TransferError::Payload))?;

    let mut tx = Transaction::new_v4();
    tx.expiry_height = (tip as u32).saturating_add(TX_EXPIRY_DELTA);
    for u in yed_inputs {
        tx.vin.push(TxIn::new(u.outpoint));
    }
    for (script_pubkey, _) in token_outputs {
        tx.vout.push(TxOut {
            value: TOKEN_VALUE,
            script_pubkey: script_pubkey.clone(),
        });
    }
    tx.vout.push(TxOut {
        value: 0,
        script_pubkey: payload::payload_script(&payload_bytes),
    });

    // YEC accounting: token inputs carry TOKEN_VALUE each; outputs need TOKEN_VALUE each plus
    // the fee (txbuilder.cpp:1250-1253).
    let token_in = yed_inputs.len() as i64 * TOKEN_VALUE;
    let token_out = token_outputs.len() as i64 * TOKEN_VALUE;
    let spendable = wallet.spendable_utxos()?;
    // rpcversion 8 (D-Q-23 (b)): a YED transfer is a Yellowback transaction, priced by size at the
    // Yellowback rate (dollars per KB at the attested price) whether or not it has a post-quantum
    // input — the node's `YedNetworkFee` over the YED inputs, raised as YEC inputs are selected
    // (`PQFeeFollower`): 1,000 bytes, 150 per P2PKH input, a Falcon holder input at its spend size.
    let priced_for = |inputs: &[Utxo]| -> i64 {
        let mut pq = Vec::new();
        let mut other = 0;
        for u in yed_inputs.iter().chain(inputs) {
            match crate::pq::pqpkh_of(&u.script) {
                Some(id) => pq.push(id.scheme),
                None => other += 1,
            }
        }
        wallet.pq_terms().yed_network_fee(other, &pq)
    };
    let mut base_fee = priced_for(&[]);
    let (yec_inputs, mut fee, mut yec_change) = loop {
        let yec_needed = token_out + base_fee - token_in;
        let yec_inputs = coins::select_yec(&spendable, yec_needed, true)?;
        let priced = priced_for(&yec_inputs);
        if priced > base_fee {
            base_fee = priced;
            continue;
        }
        let selected_yec: i64 = yec_inputs.iter().map(|u| u.value).sum();
        break (yec_inputs, base_fee, selected_yec - yec_needed);
    };
    if yec_change == TOKEN_VALUE {
        yec_change -= 1;
        fee += 1;
    }
    if yec_change > 0 && yec_change < MIN_CHANGE {
        fee += yec_change;
        yec_change = 0;
    }
    for u in &yec_inputs {
        tx.vin.push(TxIn::new(u.outpoint));
    }
    if yec_change > 0 {
        tx.vout.push(TxOut {
            value: yec_change,
            script_pubkey: script::p2pkh_script(yec_change_hash),
        });
    }

    // Sign YED inputs (P2PKH or Falcon PQPKH, own) then YEC inputs (txbuilder.cpp:1265-1271).
    super::mint::sign_p2pkh_inputs(wallet, &mut tx, yed_inputs, 0, branch_id)?;
    super::mint::sign_p2pkh_inputs(wallet, &mut tx, &yec_inputs, yed_inputs.len(), branch_id)?;
    let raw = tx.serialize()?;
    let txid = tx.txid()?;
    Ok(Assembled {
        raw,
        txid,
        yec_inputs,
        fee,
        yec_change,
        payload: payload_bytes,
        expiry_height: tx.expiry_height,
    })
}

/// The YED selection for `needed` cents over the wallet's spendable tokens (`SelectYed`,
/// `txbuilder.cpp:529-549`): the ranked coins, the selector, the node's three refusals.
pub fn select_yed(
    wallet: &Wallet,
    needed: u64,
) -> Result<(Vec<Utxo>, SelectStage, u64), WalletError> {
    let coins = coins::ranked_tokens(&wallet.spendable_utxos()?);
    let cents: Vec<i64> = coins.iter().map(|c| c.cents as i64).collect();
    let have: u64 = coins.iter().map(|c| c.cents).sum();
    let s = coinselect::select_floor_aware(
        &cents,
        needed as i64,
        MIN_OUTPUT_CENTS as i64,
        MAX_INPUTS,
        false,
    );
    if !s.ok {
        if s.insufficient {
            return Err(TransferError::InsufficientYed { need: needed, have }.into());
        }
        if s.too_many_inputs {
            return Err(TransferError::TooManyInputs.into());
        }
        let Alternatives { below, above } = coinselect::nearest_workable(
            &cents,
            needed as i64,
            MIN_OUTPUT_CENTS as i64,
            MAX_INPUTS,
        );
        return Err(TransferError::ChangeFloor {
            needed,
            below,
            above,
        }
        .into());
    }
    let sel: Vec<Utxo> = s.inputs.iter().map(|&i| coins[i].clone()).collect();
    Ok((sel, s.stage, s.change as u64))
}

/// The token output for a YED recipient `to` (rpcversion 7 `yed_send`: either address form),
/// under the holder rule of the next block (`falcon`: TOK-PQ is in force):
/// - before Falcon: a P2PKH key (`yb…`/`yt…`/`yr…` 35 characters or its `s…` form). A
///   53-character SLH-DSA address is a vault owner, never a YED receive address (C-10), and a
///   Falcon address is non-standard until Falcon activates (spec §2.3 A-6): both refused;
/// - from Falcon: only a Falcon (scheme 2) post-quantum address; a P2PKH or SLH-DSA one would
///   make the transaction invalid (TOK-PQ), so it is refused here with the reason.
///
/// A P2SH address or a post-quantum YEC address (`sq…`) is never a YED destination.
pub fn yed_holder_script(network: Network, to: &str, falcon: bool) -> Result<Vec<u8>, WalletError> {
    let dest = keys::parse_yed_destination(network, to).map_err(|e| match e {
        keys::KeyError::WrongNetwork(..) if keys::parse_address(network, to).is_ok() => {
            WalletError::Other(format!(
                "not-a-yellowback-address: {to} is a script address; YED goes to a key"
            ))
        }
        e => e.into(),
    })?;
    match dest {
        YedDestination::P2pkh(_) if falcon => Err(TransferError::FalconHolderRequired(format!(
            "{to} is a P2PKH address"
        ))
        .into()),
        YedDestination::P2pkh(h) => Ok(script::p2pkh_script(&h)),
        YedDestination::Pq(id) if id.scheme == crate::pq::SCHEME_FN_DSA_512 && falcon => {
            crate::pq::pqpkh_script(&id).ok_or_else(|| keys::KeyError::PqOwnerAddress(to.into()).into())
        }
        YedDestination::Pq(id) if id.scheme == crate::pq::SCHEME_FN_DSA_512 => {
            Err(WalletError::Other(format!(
                "falcon-not-active: {to} is a Falcon address; it can receive YED only after Falcon activates"
            )))
        }
        YedDestination::Pq(_) if falcon => Err(TransferError::FalconHolderRequired(format!(
            "{to} is a vault-owner (SLH-DSA) address"
        ))
        .into()),
        YedDestination::Pq(_) => Err(keys::KeyError::PqOwnerAddress(to.into()).into()),
    }
}

/// Build and sign a transfer of `recipients` (`address`, `cents`) — `yb…`, `yr…`, `yt…` or the
/// `s…` form, the same key hash — from this wallet (`BuildTransfer`).
pub fn build_yed_transfer(
    wallet: &Wallet,
    recipients: &[(String, u64)],
    tip: u64,
    branch_id: u32,
) -> Result<YedTransferPreview, WalletError> {
    if recipients.is_empty() {
        return Err(TransferError::NoRecipients.into());
    }
    if recipients.len() > MAX_RECIPIENTS {
        return Err(TransferError::TooManyRecipients.into());
    }
    // TOK-PQ (quantum spec F-7; Q4 as implemented): from the Falcon height every output that
    // receives YED must be a Falcon (scheme 2) TX_PQPKH, or the transaction is invalid.
    let falcon = wallet.pq_terms().falcon_at(tip + 1);
    let mut needed = 0u64;
    let mut token_outputs: Vec<(Vec<u8>, u32)> = Vec::with_capacity(recipients.len() + 1);
    for (to, cents) in recipients {
        if *cents < MIN_OUTPUT_CENTS || *cents > MAX_OUTPUT_CENTS {
            return Err(TransferError::BadAmount(*cents).into());
        }
        let script_pubkey = yed_holder_script(wallet.network, to, falcon)?;
        needed += cents;
        token_outputs.push((script_pubkey, *cents as u32));
    }
    let (yed_inputs, stage, change_cents) = select_yed(wallet, needed)?;
    let change_row = wallet.change_address()?;
    if change_cents > 0 {
        // From the Falcon height the YED change goes to the change key's Falcon holder.
        token_outputs.push((
            wallet.yed_holder_script(&change_row, falcon)?,
            change_cents as u32,
        ));
    }
    let a = assemble(
        wallet,
        &yed_inputs,
        &token_outputs,
        &change_row.hash160,
        tip,
        branch_id,
    )?;
    // The local gate layer sees the bytes that will be sent (D-W-5); `broadcast` runs both.
    gate::check(gate::Path::YedTransfer, &a.raw, |op| {
        wallet.store.utxo_class(op).ok().flatten()
    })?;
    Ok(YedTransferPreview {
        recipients: recipients.to_vec(),
        yed_inputs,
        stage,
        change_cents,
        yec_inputs: a.yec_inputs,
        fee: a.fee,
        yec_change: a.yec_change,
        change_address: if change_cents > 0 || a.yec_change > 0 {
            Some(change_row.address_s)
        } else {
            None
        },
        payload: a.payload,
        expiry_height: a.expiry_height,
        raw: a.raw,
        txid: a.txid,
    })
}

/// `confirm`: both gate layers, then `SendTransaction`, then the locks, the pending record,
/// the pending history row (labelled locally until `GetTxInfo` answers) and the change
/// bookkeeping. Returns the txid in display form and the node's validation.
pub async fn broadcast(
    wallet: &Wallet,
    client: &mut CompactClient,
    validator: &mut Validator,
    preview: &YedTransferPreview,
) -> Result<(String, Validation), WalletError> {
    let (_, validation) = gate::confirm(validator, gate::Path::YedTransfer, &preview.raw, |op| {
        wallet.store.utxo_class(op).ok().flatten()
    })
    .await?;
    let validation = validation.ok_or(gate::GateError::YellowbackAbsent)?;
    let reply = client.send_transaction(preview.raw.clone()).await?;
    let txid_str = txid_hex(&preview.txid);
    if !reply.is_empty() && reply != txid_str {
        return Err(WalletError::Other(format!(
            "server replied {reply} for txid {txid_str}"
        )));
    }
    let reason = format!("spent-by:{txid_str}");
    for u in preview.yed_inputs.iter().chain(preview.yec_inputs.iter()) {
        wallet
            .store
            .lock(&u.outpoint, &reason, preview.expiry_height as u64)?;
    }
    for u in &preview.yed_inputs {
        wallet
            .store
            .insert_spent_token(&preview.txid, &u.outpoint, u.cents)?;
    }
    wallet
        .store
        .insert_pending_tx(&preview.txid, &preview.raw, preview.expiry_height as u64)?;
    // PreLock (wallet.cpp:410-427): the payload's own assignments become PENDING_TOKEN rows
    // now, so the balance shows them as pending before the next sync.
    let (tx, _) = Transaction::parse(&preview.raw)?;
    let own = wallet.own_hashes()?;
    let own_falcon = wallet.own_falcon_holders_for(&tx)?;
    for (n, cents) in
        coins::pre_lock_scripts(&tx, |s| Wallet::is_own_holder_script(s, &own, &own_falcon))
    {
        let script_pubkey = tx.vout[n as usize].script_pubkey.clone();
        let address = holder_address(wallet.network, &script_pubkey);
        wallet.store.upsert_utxo(&Utxo {
            outpoint: OutPoint {
                txid: preview.txid,
                n,
            },
            address,
            script: script_pubkey,
            value: TOKEN_VALUE,
            height: 0,
            class: UtxoClass::PendingToken,
            cents,
        })?;
    }
    let sent: u64 = preview.recipients.iter().map(|r| r.1).sum();
    let yec_spent: i64 = preview.yec_inputs.iter().map(|u| u.value).sum::<i64>()
        + preview.yed_inputs.iter().map(|u| u.value).sum::<i64>();
    let own_token_out = if preview.change_cents > 0 {
        TOKEN_VALUE
    } else {
        0
    };
    wallet.store.upsert_history(&HistoryRow {
        txid: preview.txid,
        height: 0,
        yec_delta: preview.yec_change + own_token_out - yec_spent,
        has_payload: true,
        pending: true,
        shielded: false,
        yed_delta: -(sent as i64),
        kind: "transfer".into(),
        verdict: String::new(),
        label: format!("sending {}", dollars(sent as i64)),
        labelled: false,
    })?;
    if let Some(a) = &preview.change_address {
        if let Some(row) = wallet.row_for_address(a)? {
            wallet.store.mark_used(&row.hash160)?;
            let n_recipients = preview.recipients.len() as u32;
            if preview.change_cents > 0 {
                wallet.store.insert_own_output(
                    &OutPoint {
                        txid: preview.txid,
                        n: n_recipients,
                    },
                    TOKEN_VALUE,
                    &row.hash160,
                )?;
            }
            if preview.yec_change > 0 {
                // vout: recipients, [YED change], OP_RETURN, YEC change.
                let n = n_recipients + u32::from(preview.change_cents > 0) + 1;
                wallet.store.insert_own_output(
                    &OutPoint {
                        txid: preview.txid,
                        n,
                    },
                    preview.yec_change,
                    &row.hash160,
                )?;
            }
        }
    }
    Ok((txid_str, validation))
}

/// The address a holder output is listed under: the `s…` form of a P2PKH, the 53-character
/// post-quantum YED form of a `TX_PQPKH` (as `GetAddressTokens` names it), else empty.
pub fn holder_address(network: Network, script_pubkey: &[u8]) -> String {
    if let Some(h) = script::p2pkh_hash(script_pubkey) {
        return keys::encode_p2pkh(network, &h);
    }
    crate::pq::pqpkh_of(script_pubkey)
        .and_then(|id| keys::encode_pq_yellowback(network, &id))
        .unwrap_or_default()
}

/// The classes a transfer may spend, for the CLI's explanation of a refusal.
pub fn spendable_classes() -> [UtxoClass; 3] {
    [UtxoClass::Token, UtxoClass::FeeReserve, UtxoClass::Yec]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::Network;
    use crate::params::FEE_ZAT;
    use crate::store::Store;

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    /// A wallet whose store holds `coins` = `(value, class, cents)` on its own addresses.
    pub(crate) fn wallet_with(coins: &[(i64, UtxoClass, u64)]) -> Wallet {
        let seed = keys::seed_from_mnemonic(PHRASE, "").unwrap();
        let mut w = Wallet::from_parts(
            Store::open_in_memory().unwrap(),
            Network::Regtest,
            &seed,
            None,
        )
        .unwrap();
        let rows = w.addresses().unwrap();
        let utxos: Vec<Utxo> = coins
            .iter()
            .enumerate()
            .map(|(i, (v, c, cents))| {
                let row = &rows[i % rows.len()];
                Utxo {
                    outpoint: OutPoint {
                        txid: [i as u8 + 1; 32],
                        n: 0,
                    },
                    address: row.address_s.clone(),
                    script: script::p2pkh_script(&row.hash160),
                    value: *v,
                    height: 10,
                    class: *c,
                    cents: *cents,
                }
            })
            .collect();
        w.store.replace_utxos(&utxos).unwrap();
        w
    }

    fn dest() -> String {
        keys::encode_yellowback(Network::Regtest, &[0x42; 20])
    }

    /// The server's post-quantum terms with Falcon from `height` (`None`: no activation).
    fn note_falcon(w: &Wallet, height: Option<i64>) {
        let p = crate::net::rpc::YellowbackParams {
            pq: Some(crate::net::rpc::YellowbackPqParams {
                schemes: vec![1],
                falcon_active: false,
                falcon_height: height.unwrap_or(-1),
                fee_rate_zat_per_kb: 100,
            }),
            fees: Some(crate::build::terms::fallback_fee_params(100)),
            ..Default::default()
        };
        w.note_server_params(Some(&p)).unwrap();
    }

    /// The holder rule per destination form (rpcversion 7 `yed_send` takes either form; C-10;
    /// TOK-PQ after Falcon), and the change rule after Falcon.
    #[test]
    fn yed_destinations_follow_the_holder_rule() {
        let r = Network::Regtest;
        let slh = keys::encode_pq_yellowback(
            r,
            &crate::pq::PqKeyId {
                scheme: 1,
                hash: [5; 32],
            },
        )
        .unwrap();
        let falcon_id = crate::pq::PqKeyId {
            scheme: 2,
            hash: [6; 32],
        };
        let falcon_addr = keys::encode_pq_yellowback(r, &falcon_id).unwrap();
        let sq = keys::encode_pq_yec(r, &falcon_id).unwrap();
        // Before Falcon: P2PKH only.
        assert_eq!(
            yed_holder_script(r, &dest(), false).unwrap(),
            script::p2pkh_script(&[0x42; 20])
        );
        let e = yed_holder_script(r, &slh, false).unwrap_err().to_string();
        assert!(e.contains("vault-owner address"), "{e}");
        let e = yed_holder_script(r, &falcon_addr, false)
            .unwrap_err()
            .to_string();
        assert!(e.starts_with("falcon-not-active"), "{e}");
        let e = yed_holder_script(r, &sq, false).unwrap_err().to_string();
        assert!(e.contains("post-quantum YEC address"), "{e}");
        let e = yed_holder_script(r, &keys::encode_p2sh(r, &[1; 20]), false)
            .unwrap_err()
            .to_string();
        assert!(e.starts_with("not-a-yellowback-address"), "{e}");
        // From Falcon: a Falcon address only.
        assert_eq!(
            yed_holder_script(r, &falcon_addr, true).unwrap(),
            crate::pq::pqpkh_script(&falcon_id).unwrap()
        );
        for to in [dest(), slh.clone()] {
            assert!(matches!(
                yed_holder_script(r, &to, true).unwrap_err(),
                WalletError::Transfer(TransferError::FalconHolderRequired(_))
            ));
        }

        let w = wallet_with(&[
            (TOKEN_VALUE, UtxoClass::Token, 10_000),
            (50_000, UtxoClass::Yec, 0),
        ]);
        // Falcon from height 102: built at tip 100 the next block (101) is before it.
        note_falcon(&w, Some(102));
        assert!(build_yed_transfer(&w, &[(dest(), 4_000)], 100, 1).is_ok());
        // At tip 101 the next block is 102: P2PKH refused; a Falcon recipient with change builds,
        // the change going to the change key's own Falcon holder; the exact amount builds too.
        let e = build_yed_transfer(&w, &[(dest(), 4_000)], 101, 1).unwrap_err();
        assert!(e.to_string().starts_with("falcon-holder-required"), "{e}");
        let p = build_yed_transfer(&w, &[(falcon_addr.clone(), 4_000)], 101, 1).unwrap();
        assert_eq!(p.change_cents, 6_000);
        let (tx, _) = Transaction::parse(&p.raw).unwrap();
        let change_row = w.change_address().unwrap();
        let own_falcon = w.falcon_holder_id(&change_row).unwrap();
        assert_eq!(own_falcon.scheme, 2);
        assert_eq!(
            tx.vout[1].script_pubkey,
            crate::pq::pqpkh_script(&own_falcon).unwrap()
        );
        let p = build_yed_transfer(&w, &[(falcon_addr.clone(), 10_000)], 101, 1).unwrap();
        assert_eq!(p.change_cents, 0);
        let (tx, _) = Transaction::parse(&p.raw).unwrap();
        assert_eq!(
            tx.vout[0].script_pubkey,
            crate::pq::pqpkh_script(&falcon_id).unwrap()
        );
        note_falcon(&w, None);
        assert!(build_yed_transfer(&w, &[(dest(), 4_000)], 101, 1).is_ok());
    }

    /// A Falcon holder token (TOK-PQ) is spent with the wallet's Falcon key: the chunked
    /// scriptSig (`s = 2`, `p = 2`, 1,577 bytes) carries a signature that verifies over the
    /// input's ZIP-243 sighash, the change goes back to a Falcon holder, the fee is size-priced
    /// (`max(FEE_ZAT, rate × size)`), and the gate's class rules accept the input.
    #[test]
    fn falcon_holder_tokens_are_spent_with_falcon_keys() {
        let mut w = wallet_with(&[(50_000, UtxoClass::Yec, 0)]);
        note_falcon(&w, Some(0));
        let row = w.addresses().unwrap()[1].clone();
        let id = w.falcon_holder_id(&row).unwrap();
        let spk = crate::pq::pqpkh_script(&id).unwrap();
        let mut utxos = w.store.utxos().unwrap();
        utxos.push(Utxo {
            outpoint: OutPoint {
                txid: [0xf1; 32],
                n: 1,
            },
            address: keys::encode_pq_yellowback(Network::Regtest, &id).unwrap(),
            script: spk.clone(),
            value: TOKEN_VALUE,
            height: 10,
            class: UtxoClass::Token,
            cents: 10_000,
        });
        w.store.replace_utxos(&utxos).unwrap();
        let to = crate::pq::PqKeyId {
            scheme: 2,
            hash: [6; 32],
        };
        let to_addr = keys::encode_pq_yellowback(Network::Regtest, &to).unwrap();
        let branch = 0x6d5b_7a31;
        let p = build_yed_transfer(&w, &[(to_addr, 2_500)], 100, branch).unwrap();
        assert_eq!(p.change_cents, 7_500);
        let (tx, _) = Transaction::parse(&p.raw).unwrap();
        assert_eq!(tx.vin[0].prevout.txid, [0xf1; 32]);
        let ss = &tx.vin[0].script_sig;
        assert_eq!(ss.len(), 1_577);
        let ops = script::ops(ss).unwrap();
        assert_eq!(ops.len(), 6);
        assert_eq!((ops[2].opcode, ops[5].opcode), (0x52, 0x52));
        let (sig, pk) = crate::pq::parse_pqpkh_script_sig(ss).unwrap();
        assert_eq!((sig.len(), *sig.last().unwrap()), (667, 1));
        assert_eq!(crate::pq::PqKeyId::of(2, &pk), id);
        let digest = tx
            .sighash(0, &spk, TOKEN_VALUE, crate::params::SIGHASH_ALL, branch)
            .unwrap();
        assert!(crate::pq::verify(2, &pk, &sig[..666], &digest));
        assert!(!crate::pq::verify(2, &pk, &sig[..666], &[0; 32]));
        // YED change: an own Falcon holder; YEC input signed with ECDSA.
        let change = crate::pq::pqpkh_of(&tx.vout[1].script_pubkey).unwrap();
        assert!(w.own_falcon_holders().unwrap().contains_key(&change));
        assert!(tx.vin[1].script_sig.len() <= crate::tx::MAX_P2PKH_SCRIPT_SIG);
        tx.check_script_sig_sizes().unwrap();
        // rpcversion 8: the Yellowback size fee at the node's estimated size (1,000 bytes, 150 per
        // P2PKH input, the Falcon input at its spend size): at 1× (100 zat/kB) under FEE_ZAT; the
        // Falcon input raises it to the 6.20.0 conventional-fee estimate (04/N-1,
        // `YedConventionalFeeEstimate`: 600 vout bytes are 18 actions), 9,000 zat.
        assert_eq!(
            p.fee,
            crate::params::yed_conventional_fee_estimate(p.yec_inputs.len(), &[2])
        );
        assert_eq!(p.fee, 9_000);
        let rich = crate::net::rpc::YellowbackParams {
            pq: Some(crate::net::rpc::YellowbackPqParams {
                schemes: vec![1],
                falcon_active: false,
                falcon_height: 0,
                fee_rate_zat_per_kb: 10_000,
            }),
            fees: Some(crate::build::terms::fallback_fee_params(10_000)),
            ..Default::default()
        };
        w.note_server_params(Some(&rich)).unwrap();
        let q = build_yed_transfer(
            &w,
            &[(
                keys::encode_pq_yellowback(Network::Regtest, &to).unwrap(),
                2_500,
            )],
            100,
            branch,
        )
        .unwrap();
        let size = crate::params::yed_estimated_size(q.yec_inputs.len(), &[2]);
        assert_eq!(crate::params::pq_spend_input_size(2), 1_620);
        // folded change may add a little on top of the priced fee
        assert!(
            q.fee >= 10_000 * size as i64 / 1000,
            "{} for {size} bytes",
            q.fee
        );
        assert!(q.fee < 10_000 * size as i64 / 1000 + crate::build::yec_send::MIN_CHANGE);
    }

    #[test]
    fn transfer_with_yed_change_and_yec_change_reproduces_the_template_shape() {
        let w = wallet_with(&[
            (TOKEN_VALUE, UtxoClass::Token, 10_000),
            (50_000, UtxoClass::Yec, 0),
            (3_000, UtxoClass::FeeReserve, 0),
            (TOKEN_VALUE, UtxoClass::PendingToken, 700),
            (TOKEN_VALUE, UtxoClass::Held, 0),
        ]);
        let p = build_yed_transfer(&w, &[(dest(), 4_000)], 100, 0x19bd_2d2f).unwrap();
        assert_eq!(p.stage, SelectStage::Single);
        assert_eq!(p.change_cents, 6_000);
        assert_eq!(p.yed_inputs.len(), 1);
        // YEC needed = 2 × TOKEN_VALUE + fee − 1 × TOKEN_VALUE = 11_000: the reserve (3_000)
        // first, then the 50_000.
        assert_eq!(
            p.yec_inputs.iter().map(|u| u.value).collect::<Vec<_>>(),
            vec![3_000, 50_000]
        );
        assert_eq!(p.fee, FEE_ZAT);
        assert_eq!(p.yec_change, 53_000 - 11_000);
        let (tx, txid) = Transaction::parse(&p.raw).unwrap();
        assert_eq!(txid, p.txid);
        assert_eq!(tx.vin.len(), 3);
        assert_eq!(tx.vout.len(), 4);
        assert_eq!(tx.vout[0].value, TOKEN_VALUE);
        assert_eq!(tx.vout[0].script_pubkey, script::p2pkh_script(&[0x42; 20]));
        assert_eq!(tx.vout[1].value, TOKEN_VALUE);
        let fp = payload::find_payload(&tx).unwrap();
        assert_eq!(fp.op_return_index, 2);
        assert_eq!(
            fp.payload,
            Payload::Transfer {
                assignments: vec![
                    Assignment {
                        vout: 0,
                        cents: 4_000
                    },
                    Assignment {
                        vout: 1,
                        cents: 6_000
                    }
                ]
            }
        );
        assert_eq!(tx.vout[3].value, p.yec_change);
        assert_eq!(tx.expiry_height, 140);
        assert!(p.change_address.is_some());
        // The same key hash in the `s…` form is accepted.
        let s_form = keys::encode_p2pkh(Network::Regtest, &[0x42; 20]);
        let q = build_yed_transfer(&w, &[(s_form, 4_000)], 100, 1).unwrap();
        let (tq, _) = Transaction::parse(&q.raw).unwrap();
        assert_eq!(tq.vout[0].script_pubkey, tx.vout[0].script_pubkey);
    }

    #[test]
    fn refusals_carry_the_node_identifiers() {
        let w = wallet_with(&[
            (TOKEN_VALUE, UtxoClass::Token, 10_000),
            (50_000, UtxoClass::Yec, 0),
        ]);
        let e = build_yed_transfer(&w, &[(dest(), 9_950)], 100, 1).unwrap_err();
        match e {
            WalletError::Transfer(TransferError::ChangeFloor {
                needed,
                below,
                above,
            }) => {
                assert_eq!((needed, below, above), (9_950, Some(9_900), Some(10_000)));
            }
            other => panic!("{other}"),
        }
        assert!(e.to_string().starts_with("change-floor: 9950 cents"));
        assert!(matches!(
            build_yed_transfer(&w, &[(dest(), 20_000)], 100, 1).unwrap_err(),
            WalletError::Transfer(TransferError::InsufficientYed {
                need: 20_000,
                have: 10_000
            })
        ));
        assert!(matches!(
            build_yed_transfer(&w, &[(dest(), 50)], 100, 1).unwrap_err(),
            WalletError::Transfer(TransferError::BadAmount(50))
        ));
        assert!(matches!(
            build_yed_transfer(&w, &[], 100, 1).unwrap_err(),
            WalletError::Transfer(TransferError::NoRecipients)
        ));
        let many: Vec<(String, u64)> = (0..15).map(|_| (dest(), 100)).collect();
        assert!(matches!(
            build_yed_transfer(&w, &many, 100, 1).unwrap_err(),
            WalletError::Transfer(TransferError::TooManyRecipients)
        ));
        // A P2SH destination is refused; a mainnet address on regtest is refused.
        assert!(build_yed_transfer(
            &w,
            &[(keys::encode_p2sh(Network::Regtest, &[1; 20]), 100)],
            100,
            1
        )
        .is_err());
        assert!(build_yed_transfer(
            &w,
            &[(keys::encode_yellowback(Network::Mainnet, &[1; 20]), 100)],
            100,
            1
        )
        .is_err());
        // Without YEC for the fee: insufficient-yec.
        let poor = wallet_with(&[(TOKEN_VALUE, UtxoClass::Token, 10_000)]);
        assert!(matches!(
            build_yed_transfer(&poor, &[(dest(), 10_000)], 100, 1).unwrap_err(),
            WalletError::Coins(_)
        ));
    }

    #[test]
    fn exact_spend_needs_no_yed_change_and_surplus_token_value_is_yec_change() {
        // Two tokens in, one out: tokenIn = 20_000 > tokenOut + fee = 11_000, so no YEC input
        // is needed and 9_000 zat come back as YEC change (txbuilder.cpp:1253-1258).
        let w = wallet_with(&[
            (TOKEN_VALUE, UtxoClass::Token, 300),
            (TOKEN_VALUE, UtxoClass::Token, 200),
        ]);
        let p = build_yed_transfer(&w, &[(dest(), 500)], 100, 1).unwrap();
        assert_eq!(p.stage, SelectStage::Exact);
        assert_eq!(p.change_cents, 0);
        assert!(p.yec_inputs.is_empty());
        assert_eq!(p.yec_change, 9_000);
        let (tx, _) = Transaction::parse(&p.raw).unwrap();
        assert_eq!(tx.vout.len(), 3);
        assert_eq!(tx.vout[2].value, 9_000);
    }

    /// Plan §6.1 item 3 at the builder level: 1,000 random wallets holding tokens, pending
    /// tokens, held and reserve outputs; every YEC send that builds spends only YEC /
    /// FEE_RESERVE inputs (asserted on the raw bytes), and every transfer that builds spends
    /// tokens plus YEC / FEE_RESERVE only.
    #[test]
    fn property_builders_never_touch_a_forbidden_class() {
        use crate::build::yec_send;
        use std::collections::HashMap;
        let mut x = 0x2545_f491_4f6c_dd1du64;
        let mut rng = move |n: u64| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x % n
        };
        const CLASSES: [UtxoClass; 6] = [
            UtxoClass::Yec,
            UtxoClass::FeeReserve,
            UtxoClass::Token,
            UtxoClass::PendingToken,
            UtxoClass::Held,
            UtxoClass::UnknownP2sh,
        ];
        for _ in 0..1000 {
            let n = 1 + rng(8) as usize;
            let coins: Vec<(i64, UtxoClass, u64)> = (0..n)
                .map(|_| {
                    let c = CLASSES[rng(CLASSES.len() as u64) as usize];
                    match c {
                        UtxoClass::Token | UtxoClass::PendingToken | UtxoClass::Held => {
                            (TOKEN_VALUE, c, 100 + rng(20_000))
                        }
                        _ => (1_000 + rng(200_000) as i64, c, 0),
                    }
                })
                .collect();
            let w = wallet_with(&coins);
            let classes: HashMap<OutPoint, UtxoClass> = w
                .store
                .utxos()
                .unwrap()
                .into_iter()
                .map(|u| (u.outpoint, u.class))
                .collect();
            let amount = 1 + rng(100_000) as i64;
            if let Ok(p) = yec_send::build_yec_send(&w, &dest(), amount, rng(2) == 0, 100, 1) {
                let (tx, _) = Transaction::parse(&p.raw).unwrap();
                for i in &tx.vin {
                    assert!(
                        classes[&i.prevout].yec_spendable(),
                        "{:?}",
                        classes[&i.prevout]
                    );
                }
            }
            let cents = 100 + rng(30_000);
            if let Ok(p) = build_yed_transfer(&w, &[(dest(), cents)], 100, 1) {
                let (tx, _) = Transaction::parse(&p.raw).unwrap();
                let mut tokens = 0;
                for i in &tx.vin {
                    let c = classes[&i.prevout];
                    assert!(c.transfer_spendable(), "{c:?}");
                    tokens += usize::from(c == UtxoClass::Token);
                }
                assert!(tokens > 0);
                assert_eq!(
                    payload::find_payload(&tx).unwrap().payload.assigned_cents(),
                    p.yed_inputs.iter().map(|u| u.cents as i64).sum::<i64>()
                );
            }
        }
    }
}
