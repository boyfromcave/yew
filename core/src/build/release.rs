// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The RELEASE of a claim intent paying this wallet (the vault upgrade: upgrade plan §15.3
//! intent I selector 1, U-15, U-23): after `CLAIM_DELAY` the claimant's intent (or the owner's
//! RED-5 residual intent) is spent to the recipient it commits to. No signature is needed on
//! the intent (`OP_1`; anyone may release once it matured); its input carries `nSequence =
//! delay` (BIP68, U-11), it is `vin[0]` and the only template input (S-1); `vout[0]` pays the
//! intent's whole value to the recipient (I-1); the network fee comes from the wallet's own
//! `YEC` / `FEE_RESERVE` inputs, with change to a fresh change key.
//!
//! Translation source: `ycash-dd/src/rpc/vault.cpp` `vault_release` (branch `upgrade/vault`)
//! and the Python reference `build_release_tx` (`qa/rpc-tests/test_framework/vault.py`).

use crate::coins::{self, Utxo};
use crate::gate::{self, Validator};
use crate::net::{CompactClient, Validation};
use crate::params::{FEE_ZAT, TOKEN_VALUE, TX_EXPIRY_DELTA};
use crate::script;
use crate::store::{HistoryRow, IntentRow, IntentState};
use crate::tx::{txid_hex, OutPoint, Transaction, TxIn, TxOut};
use crate::vault;
use crate::wallet::{Wallet, WalletError};

use super::mint;
use super::yec_send::MIN_CHANGE;

/// What the release screen shows and what is broadcast.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseBuild {
    /// The intent released.
    pub intent: OutPoint,
    /// Its value, paid to the recipient.
    pub value: i64,
    /// The recipient (`s…`).
    pub recipient_address: String,
    /// The fee inputs.
    pub inputs: Vec<Utxo>,
    /// The fee inputs' change, zat (0 = none).
    pub change: i64,
    /// `nExpiryHeight`.
    pub expiry_height: u32,
    /// The signed transaction.
    pub raw: Vec<u8>,
    /// Its txid.
    pub txid: [u8; 32],
}

/// Why an intent cannot be released yet.
pub fn not_releasable(row: &IntentRow, tip: u64) -> Option<String> {
    if !row.state.open() || row.state == IntentState::Releasing {
        return Some(format!(
            "intent-not-open: the intent is {}",
            row.state.as_str()
        ));
    }
    match row.release_height() {
        None => Some("intent-unconfirmed: the claim has not confirmed yet".into()),
        Some(h) if h > tip + 1 => Some(format!(
            "intent-not-mature: the intent can be released from height {h} (tip {tip})"
        )),
        Some(_) => None,
    }
}

/// Build and sign the release of `row` for the next block (`branch_id` is the next block's, the
/// Vault id after activation). Nothing is broadcast; [`broadcast`] sends the same bytes.
pub fn build_release(
    wallet: &Wallet,
    row: &IntentRow,
    tip: u64,
    branch_id: u32,
) -> Result<ReleaseBuild, WalletError> {
    if let Some(why) = not_releasable(row, tip) {
        return Err(WalletError::Other(why));
    }
    let ip = vault::parse_intent(&row.intent_script).ok_or_else(|| {
        WalletError::Other("intent-malformed: the stored intent does not parse".into())
    })?;
    if vault::script_hash256(&row.recipient_script) != ip.recipient_hash {
        return Err(WalletError::Other(
            "intent-recipient: the stored recipient is not the intent's".into(),
        ));
    }
    let recipient_hash = script::p2pkh_hash(&row.recipient_script)
        .filter(|h| wallet.own_hashes().map(|o| o.contains(h)).unwrap_or(false))
        .ok_or_else(|| {
            WalletError::Other("intent-not-ours: the intent does not pay this wallet".into())
        })?;
    let inputs = coins::select_yec(&wallet.spendable_utxos()?, FEE_ZAT, true)?;
    let selected: i64 = inputs.iter().map(|u| u.value).sum();
    let mut change = selected - FEE_ZAT;
    if change == TOKEN_VALUE {
        change -= 1;
    }
    if change > 0 && change < MIN_CHANGE {
        change = 0;
    }
    let mut tx = Transaction::new_v4();
    tx.expiry_height = (tip as u32).saturating_add(TX_EXPIRY_DELTA);
    tx.vin.push(TxIn {
        prevout: row.outpoint,
        script_sig: vault::intent_release_script_sig(),
        sequence: ip.delay as u32,
    });
    for u in &inputs {
        tx.vin.push(TxIn::new(u.outpoint));
    }
    tx.vout.push(TxOut {
        value: row.value,
        script_pubkey: row.recipient_script.clone(),
    });
    // Peeked, not taken: marked used only when broadcast.
    let change_row = wallet.change_address()?;
    if change > 0 {
        tx.vout.push(TxOut {
            value: change,
            script_pubkey: script::p2pkh_script(&change_row.hash160),
        });
    }
    // Every signature commits to vin[0]'s nSequence (ZIP-243 hashSequence): set before signing.
    mint::sign_p2pkh_inputs(wallet, &mut tx, &inputs, 1, branch_id)?;
    let raw = tx.serialize()?;
    let txid = tx.txid()?;
    gate::check(gate::Path::IntentRelease(row.outpoint), &raw, |op| {
        wallet.store.utxo_class(op).ok().flatten()
    })?;
    Ok(ReleaseBuild {
        intent: row.outpoint,
        value: row.value,
        recipient_address: crate::keys::encode_p2pkh(wallet.network, &recipient_hash),
        inputs,
        change,
        expiry_height: tx.expiry_height,
        raw,
        txid,
    })
}

/// Both gate layers, broadcast, locks, the history row; the intent row to `Releasing`.
pub async fn broadcast(
    wallet: &Wallet,
    client: &mut CompactClient,
    validator: &mut Validator,
    p: &ReleaseBuild,
) -> Result<(String, Validation), WalletError> {
    let row = wallet
        .store
        .intent(&p.intent)?
        .ok_or_else(|| WalletError::Other("intent-unknown: not an intent of this wallet".into()))?;
    let (tx, validation) = gate::confirm(
        validator,
        gate::Path::IntentRelease(p.intent),
        &p.raw,
        |op| wallet.store.utxo_class(op).ok().flatten(),
    )
    .await?;
    let validation = validation.ok_or(gate::GateError::YellowbackAbsent)?;
    mint::send(client, &p.raw, &p.txid).await?;
    mint::record_broadcast(wallet, &p.txid, &p.raw, p.expiry_height, &p.inputs)?;
    // vout[0] pays the intent's own recipient; vout[1] (if any) is the change key peeked at build.
    for (n, o) in tx.vout.iter().enumerate() {
        if let Some(h) = script::p2pkh_hash(&o.script_pubkey) {
            if n == 1 {
                wallet.store.mark_used(&h)?;
                wallet.ensure_gap()?;
            }
            wallet.store.insert_own_output(
                &OutPoint {
                    txid: p.txid,
                    n: n as u32,
                },
                o.value,
                &h,
            )?;
        }
    }
    let spent: i64 = p.inputs.iter().map(|u| u.value).sum();
    wallet.store.upsert_history(&HistoryRow {
        txid: p.txid,
        height: 0,
        yec_delta: p.value + p.change - spent,
        has_payload: false,
        pending: true,
        shielded: false,
        yed_delta: 0,
        kind: "claim_release".into(),
        verdict: String::new(),
        label: format!(
            "releasing {} from {} intent",
            crate::wallet::yec(p.value),
            if row.role == super::claim::ROLE_RESIDUAL {
                "the residual"
            } else {
                "the claim"
            }
        ),
        labelled: false,
    })?;
    wallet.store.upsert_intent(&IntentRow {
        state: IntentState::Releasing,
        spend_txid: p.txid,
        note: format!("release {} broadcast", &txid_hex(&p.txid)[..8]),
        ..row
    })?;
    Ok((txid_hex(&p.txid), validation))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(height: u64, state: IntentState) -> IntentRow {
        IntentRow {
            outpoint: OutPoint {
                txid: [1; 32],
                n: 0,
            },
            vault_txid: [2; 32],
            role: "claimant".into(),
            value: 1_000_000,
            recipient_script: script::p2pkh_script(&[3; 20]),
            intent_script: Vec::new(),
            delay: 10,
            height,
            state,
            spend_txid: [0; 32],
            note: String::new(),
        }
    }

    #[test]
    fn releasable_from_coin_height_plus_delay() {
        assert!(not_releasable(&row(0, IntentState::Pending), 500).is_some());
        // Mined at 100, delay 10: the release may be in block 110, i.e. built at tip 109.
        assert!(not_releasable(&row(100, IntentState::Pending), 108).is_some());
        assert!(not_releasable(&row(100, IntentState::Pending), 109).is_none());
        assert!(not_releasable(&row(100, IntentState::Releasing), 200).is_some());
        assert!(not_releasable(&row(100, IntentState::Cancelled), 200).is_some());
        assert!(vault::bip68_ok(100, 10, 110) && !vault::bip68_ok(100, 10, 109));
    }
}
