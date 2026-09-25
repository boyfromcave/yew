//! A YEC send: `SelectYec` inputs, one P2PKH/P2SH output to the destination, change to the
//! next change address, fee = `FEE_ZAT`, `nExpiryHeight = tip + TX_EXPIRY_DELTA`, signed with
//! ZIP-243 under the server's branch id. The preview is the transaction that will be sent.
//!
//! Translation source (plan §3.6): `ycash-dd/src/yellowback/txbuilder.cpp` (`SelectYec`
//! `:399-420`, `SetFee` `:338`); `nExpiryHeight` as the node's `CreateTransaction`.
//!
//! Two rules recorded in plan §3.7 "Change": an amount of exactly `TOKEN_VALUE` is bumped by
//! one zat so a plain YEC output never looks like a token; a change of exactly `TOKEN_VALUE`
//! is lowered by one zat (the zat goes to the fee) for the same reason.

use crate::coins::{self, Utxo};
use crate::gate::{self, Validator};
use crate::keys::{self, AddressKind};
use crate::net::CompactClient;
use crate::params::{FEE_ZAT, TOKEN_VALUE, TX_EXPIRY_DELTA};
use crate::script;
use crate::store::HistoryRow;
use crate::tx::{txid_hex, OutPoint, Transaction, TxIn, TxOut};
use crate::wallet::{Wallet, WalletError};

/// Change below this folds into the fee (a few relay-dust thresholds at 100 zat/kB).
pub const MIN_CHANGE: i64 = 100;

/// What the screen renders and what will be broadcast, unchanged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct YecSendPreview {
    /// The destination as given.
    pub to: String,
    /// The amount paid to it (after the `TOKEN_VALUE` bump, if any).
    pub amount: i64,
    /// True when the amount was bumped from exactly `TOKEN_VALUE`.
    pub amount_bumped: bool,
    /// The fee actually paid (`FEE_ZAT`, plus folded change).
    pub fee: i64,
    /// The change output value (0 = none).
    pub change: i64,
    /// The change address (`s…` form) when `change > 0`.
    pub change_address: Option<String>,
    /// The inputs spent.
    pub inputs: Vec<Utxo>,
    /// True when FEE_RESERVE outputs were used ("send everything anyway").
    pub uses_reserve: bool,
    /// `nExpiryHeight`.
    pub expiry_height: u32,
    /// The signed transaction.
    pub raw: Vec<u8>,
    /// Its txid (internal order).
    pub txid: [u8; 32],
}

/// Build and sign a YEC send of `amount` zat to `to`.
pub fn build_yec_send(
    wallet: &Wallet,
    to: &str,
    amount: i64,
    send_everything: bool,
    tip: u64,
    branch_id: u32,
) -> Result<YecSendPreview, WalletError> {
    if amount <= 0 {
        return Err(WalletError::Other("amount must be positive".into()));
    }
    let dest = keys::parse_address(wallet.network, to)?;
    let dest_script = match dest.kind {
        AddressKind::P2pkh(h) => script::p2pkh_script(&h),
        AddressKind::P2sh(h) => script::p2sh_script(&h),
    };
    let (amount, amount_bumped) = if amount == TOKEN_VALUE {
        (amount + 1, true)
    } else {
        (amount, false)
    };

    let spendable = wallet.spendable_utxos()?;
    let inputs = coins::select_yec(&spendable, amount + FEE_ZAT, send_everything)?;
    let total: i64 = inputs.iter().map(|u| u.value).sum();
    let mut fee = FEE_ZAT;
    let mut change = total - amount - fee;
    if change == TOKEN_VALUE {
        change -= 1;
        fee += 1;
    }
    if change > 0 && change < MIN_CHANGE {
        fee += change;
        change = 0;
    }

    let mut tx = Transaction::new_v4();
    tx.expiry_height = (tip as u32).saturating_add(TX_EXPIRY_DELTA);
    for u in &inputs {
        tx.vin.push(TxIn::new(u.outpoint));
    }
    tx.vout.push(TxOut {
        value: amount,
        script_pubkey: dest_script,
    });
    let mut change_address = None;
    if change > 0 {
        let row = wallet.change_address()?;
        tx.vout.push(TxOut {
            value: change,
            script_pubkey: script::p2pkh_script(&row.hash160),
        });
        change_address = Some(row.address_s);
    }
    for (i, u) in inputs.iter().enumerate() {
        let h = script::p2pkh_hash(&u.script).ok_or_else(|| {
            WalletError::Other(format!("input {} is not P2PKH", u.outpoint.display()))
        })?;
        let key = wallet.key_for_hash(&h)?.ok_or_else(|| {
            WalletError::Other(format!("no key for input {}", u.outpoint.display()))
        })?;
        tx.sign_p2pkh_input(i, &key.secret, &u.script, u.value, branch_id)?;
    }
    let raw = tx.serialize()?;
    let txid = tx.txid()?;
    // The gate sees the bytes that will be sent (D-W-5); `broadcast` runs it again.
    gate::check(gate::Path::Yec, &raw, |op| {
        wallet.store.utxo_class(op).ok().flatten()
    })?;
    Ok(YecSendPreview {
        to: to.to_string(),
        amount,
        amount_bumped,
        fee,
        change,
        change_address,
        uses_reserve: inputs
            .iter()
            .any(|u| u.class == coins::UtxoClass::FeeReserve),
        inputs,
        expiry_height: tx.expiry_height,
        raw,
        txid,
    })
}

/// `confirm`: both gate layers (the node's `ValidateRawTransaction` too, D-W-5; on a server
/// without Yellowback the local layer alone, see `gate`), then `SendTransaction`, then the
/// locks, the pending record and the history row. Returns the txid in display form.
pub async fn broadcast(
    wallet: &Wallet,
    client: &mut CompactClient,
    validator: &mut Validator,
    preview: &YecSendPreview,
) -> Result<String, WalletError> {
    gate::confirm(validator, gate::Path::Yec, &preview.raw, |op| {
        wallet.store.utxo_class(op).ok().flatten()
    })
    .await?;
    let reply = client.send_transaction(preview.raw.clone()).await?;
    let txid_str = txid_hex(&preview.txid);
    if !reply.is_empty() && reply != txid_str {
        return Err(WalletError::Other(format!(
            "server replied {reply} for txid {txid_str}"
        )));
    }
    let reason = format!("spent-by:{txid_str}");
    for u in &preview.inputs {
        wallet
            .store
            .lock(&u.outpoint, &reason, preview.expiry_height as u64)?;
    }
    wallet
        .store
        .insert_pending_tx(&preview.txid, &preview.raw, preview.expiry_height as u64)?;
    let spent: i64 = preview.inputs.iter().map(|u| u.value).sum();
    wallet.store.upsert_history(&HistoryRow {
        txid: preview.txid,
        height: 0,
        yec_delta: preview.change - spent,
        has_payload: false,
        pending: true,
        shielded: false,
        yed_delta: 0,
        kind: String::new(),
        verdict: String::new(),
        label: String::new(),
        labelled: true,
    })?;
    if let Some(a) = &preview.change_address {
        if let Some(row) = wallet.row_for_address(a)? {
            wallet.store.mark_used(&row.hash160)?;
            wallet.store.insert_own_output(
                &OutPoint {
                    txid: preview.txid,
                    n: 1,
                },
                preview.change,
                &row.hash160,
            )?;
        }
    }
    Ok(txid_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coins::UtxoClass;
    use crate::params::Network;
    use crate::store::Store;

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn wallet_with(values: &[(i64, UtxoClass)]) -> Wallet {
        let seed = keys::seed_from_mnemonic(PHRASE, "").unwrap();
        let mut w = Wallet::from_parts(
            Store::open_in_memory().unwrap(),
            Network::Regtest,
            &seed,
            None,
        )
        .unwrap();
        let rows = w.addresses().unwrap();
        let utxos: Vec<Utxo> = values
            .iter()
            .enumerate()
            .map(|(i, (v, c))| {
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
                    cents: 0,
                }
            })
            .collect();
        w.store.replace_utxos(&utxos).unwrap();
        w
    }

    #[test]
    fn builds_signed_send_with_change_and_bumps_token_value() {
        let w = wallet_with(&[
            (50_000, UtxoClass::Yec),
            (30_000, UtxoClass::FeeReserve),
            (10_000, UtxoClass::Held),
        ]);
        let to = keys::encode_p2pkh(Network::Regtest, &[0x42; 20]);
        let p = build_yec_send(&w, &to, TOKEN_VALUE, false, 100, 0x2bb4_0e60).unwrap();
        assert_eq!(p.amount, TOKEN_VALUE + 1);
        assert!(p.amount_bumped);
        assert_eq!(p.fee, FEE_ZAT);
        assert_eq!(p.change, 50_000 - 10_001 - FEE_ZAT);
        assert_eq!(p.inputs.len(), 1);
        assert_eq!(p.expiry_height, 140);
        let (tx, txid) = Transaction::parse(&p.raw).unwrap();
        assert_eq!(txid, p.txid);
        assert_eq!(tx.vout.len(), 2);
        assert_eq!(tx.vout[0].script_pubkey, script::p2pkh_script(&[0x42; 20]));
        assert!(script::pushes(&tx.vin[0].script_sig).unwrap().len() == 2);
        assert!(!p.uses_reserve);
        // Change of exactly TOKEN_VALUE is lowered by one zat.
        let q = build_yec_send(&w, &to, 50_000 - FEE_ZAT - TOKEN_VALUE, false, 100, 1).unwrap();
        assert_eq!(q.change, TOKEN_VALUE - 1);
        assert_eq!(q.fee, FEE_ZAT + 1);
        // Too much without the reserve; fine with it.
        assert!(build_yec_send(&w, &to, 60_000, false, 100, 1).is_err());
        let r = build_yec_send(&w, &to, 60_000, true, 100, 1).unwrap();
        assert!(r.uses_reserve);
        assert_eq!(r.inputs.len(), 2);
        // Dust change folds into the fee.
        let s = build_yec_send(&w, &to, 50_000 - FEE_ZAT - 50, false, 100, 1).unwrap();
        assert_eq!(s.change, 0);
        assert_eq!(s.fee, FEE_ZAT + 50);
        assert!(build_yec_send(&w, &to, 0, false, 100, 1).is_err());
        assert!(build_yec_send(
            &w,
            &keys::encode_p2pkh(Network::Mainnet, &[1; 20]),
            5,
            false,
            100,
            1
        )
        .is_err());
    }

    #[test]
    fn locked_inputs_are_not_selected() {
        let w = wallet_with(&[(50_000, UtxoClass::Yec)]);
        let to = keys::encode_p2sh(Network::Regtest, &[0x42; 20]);
        w.store
            .lock(
                &OutPoint {
                    txid: [1; 32],
                    n: 0,
                },
                "spent-by:x",
                0,
            )
            .unwrap();
        assert!(build_yec_send(&w, &to, 1_000, false, 100, 1).is_err());
        w.store
            .unlock(&OutPoint {
                txid: [1; 32],
                n: 0,
            })
            .unwrap();
        let p = build_yec_send(&w, &to, 1_000, false, 100, 1).unwrap();
        let (tx, _) = Transaction::parse(&p.raw).unwrap();
        assert_eq!(tx.vout[0].script_pubkey, script::p2sh_script(&[0x42; 20]));
    }
}
