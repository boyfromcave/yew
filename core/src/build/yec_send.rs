// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! A YEC send: `SelectYec` inputs, one P2PKH/P2SH/`TX_PQPKH` output to the destination (an
//! `s1…`/`s3…`/`yb…` address, or a post-quantum `sq…`, D-Q-20), change to the
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
use crate::keys;
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

/// The gate path of a YEC send to `to` (beta2 item 3): [`gate::Path::YecToPq`] for a decoded
/// plain-YEC post-quantum address of this network, [`gate::Path::Yec`] for a P2PKH / P2SH one.
/// A post-quantum YED (`ybf…`) or vault-owner address is refused with the reason
/// (`keys::parse_yec_destination`).
pub fn send_path(network: crate::params::Network, to: &str) -> Result<gate::Path, WalletError> {
    Ok(match keys::parse_yec_destination(network, to)? {
        keys::YecDestination::Pq(id) => gate::Path::YecToPq(id),
        _ => gate::Path::Yec,
    })
}

/// Build and sign a YEC send of `amount` zat to `to`. The coins come from one of the wallet's
/// public addresses unless `allow_linking` (the user's go-ahead after
/// [`coins::CoinError::LinkingNeeded`], beta2 D-5: ycashd's `z_sendmany` asks for `NoPrivacy`
/// before it combines coins of several addresses for a transparent recipient).
pub fn build_yec_send(
    wallet: &Wallet,
    to: &str,
    amount: i64,
    send_everything: bool,
    allow_linking: bool,
    tip: u64,
    branch_id: u32,
) -> Result<YecSendPreview, WalletError> {
    if amount <= 0 {
        return Err(WalletError::Other("amount must be positive".into()));
    }
    // A post-quantum `sq…`/`tq…`/`rq…` is paid a `TX_PQPKH` (D-Q-20): the inputs stay the
    // wallet's P2PKH keys, so the transaction's size and fee are those of any YEC send.
    let dest_script = keys::parse_yec_destination(wallet.network, to)?.script();
    let path = send_path(wallet.network, to)?;
    let (amount, amount_bumped) = if amount == TOKEN_VALUE {
        (amount + 1, true)
    } else {
        (amount, false)
    };

    let spendable = wallet.spendable_utxos()?;
    let inputs =
        coins::select_yec_linking(&spendable, amount + FEE_ZAT, send_everything, allow_linking)?;
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
    gate::check(path, &raw, |op| wallet.store.utxo_class(op).ok().flatten())?;
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
    // the has-held-YED guard (beta2 item 32): a wallet that held YED spends transparent YEC
    // only where Yellowback tells its YED outputs apart
    // beta2 item 3: a post-quantum recipient is its own path, whose dry run is mandatory
    let path = send_path(wallet.network, &preview.to)?;
    gate::refuse_held_absent(validator, path, wallet.has_held_yed()?)?;
    gate::confirm(validator, path, &preview.raw, |op| {
        wallet.store.utxo_class(op).ok().flatten()
    })
    .await?;
    // layer 3: no input carries YED by its creating transaction (review YEW-REVIEW-3)
    gate::confirm_provenance(
        client,
        path,
        &preview.raw,
        |op| wallet.store.utxo_class(op).ok().flatten(),
        |op| wallet.store.utxo_txout(op).ok().flatten(),
    )
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

    /// beta2 D-5 (lane KG-YEWD-FIX): a send takes one public address's coins whenever one
    /// address covers it; combining addresses (which links them on the chain, as ycashd's
    /// `z_sendmany` refuses without `NoPrivacy`) needs the go-ahead, and the transaction then
    /// spends both addresses' coins.
    #[test]
    fn a_send_links_public_addresses_only_with_the_go_ahead() {
        // address 0: 40,000; address 1: 30,000 (wallet_with puts coin i at address row i)
        let w = wallet_with(&[(40_000, UtxoClass::Yec), (30_000, UtxoClass::Yec)]);
        let rows = w.addresses().unwrap();
        assert!(rows.len() >= 2);
        let to = keys::encode_p2pkh(Network::Regtest, &[0x42; 20]);
        // 25,000: smallest-first would take the 30,000 coin alone: one address either way
        let p = build_yec_send(&w, &to, 25_000, false, false, 100, 1).unwrap();
        assert_eq!(coins::distinct_addresses(&p.inputs), 1);
        assert_eq!(p.inputs[0].value, 30_000);
        // 35,000: the 40,000 coin alone (one address), where the plain selector links both
        let plain =
            coins::select_yec(&w.spendable_utxos().unwrap(), 35_000 + FEE_ZAT, false).unwrap();
        assert_eq!(coins::distinct_addresses(&plain), 2);
        let p = build_yec_send(&w, &to, 35_000, false, false, 100, 1).unwrap();
        assert_eq!(coins::distinct_addresses(&p.inputs), 1);
        assert_eq!(p.inputs[0].value, 40_000);
        // 60,000: no single address holds it; refused with the reason, nothing signed
        let e = build_yec_send(&w, &to, 60_000, false, false, 100, 1).unwrap_err();
        assert!(
            matches!(
                e,
                WalletError::Coins(coins::CoinError::LinkingNeeded {
                    need: 61_000,
                    best_one: 40_000
                })
            ),
            "{e}"
        );
        assert!(
            e.to_string().contains("several of your public addresses"),
            "{e}"
        );
        // the app sees its own kind, the go-ahead question (the dialog shows the text)
        let y = crate::api::YewError::from(e);
        assert_eq!(y.kind, crate::api::ErrorKind::AddressLinkingNeeded);
        // with the go-ahead: both addresses, one transaction
        let p = build_yec_send(&w, &to, 60_000, false, true, 100, 1).unwrap();
        assert_eq!(coins::distinct_addresses(&p.inputs), 2);
        let (tx, _) = Transaction::parse(&p.raw).unwrap();
        assert_eq!(tx.vin.len(), 2);
        // more than everything: insufficient, never the linking question
        assert!(matches!(
            build_yec_send(&w, &to, 100_000, false, false, 100, 1),
            Err(WalletError::Coins(coins::CoinError::Insufficient { .. }))
        ));
    }

    #[test]
    fn builds_signed_send_with_change_and_bumps_token_value() {
        let w = wallet_with(&[
            (50_000, UtxoClass::Yec),
            (30_000, UtxoClass::FeeReserve),
            (10_000, UtxoClass::Held),
        ]);
        let to = keys::encode_p2pkh(Network::Regtest, &[0x42; 20]);
        let p = build_yec_send(&w, &to, TOKEN_VALUE, false, false, 100, 0x2bb4_0e60).unwrap();
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
        let q = build_yec_send(
            &w,
            &to,
            50_000 - FEE_ZAT - TOKEN_VALUE,
            false,
            false,
            100,
            1,
        )
        .unwrap();
        assert_eq!(q.change, TOKEN_VALUE - 1);
        assert_eq!(q.fee, FEE_ZAT + 1);
        // Too much without the reserve; fine with it.
        assert!(build_yec_send(&w, &to, 60_000, false, false, 100, 1).is_err());
        // The reserve sits at another address than the coin (beta2 D-5): only with the go-ahead.
        assert!(matches!(
            build_yec_send(&w, &to, 60_000, true, false, 100, 1),
            Err(WalletError::Coins(coins::CoinError::LinkingNeeded { .. }))
        ));
        let r = build_yec_send(&w, &to, 60_000, true, true, 100, 1).unwrap();
        assert!(r.uses_reserve);
        assert_eq!(r.inputs.len(), 2);
        // Dust change folds into the fee.
        let s = build_yec_send(&w, &to, 50_000 - FEE_ZAT - 50, false, false, 100, 1).unwrap();
        assert_eq!(s.change, 0);
        assert_eq!(s.fee, FEE_ZAT + 50);
        assert!(build_yec_send(&w, &to, 0, false, false, 100, 1).is_err());
        assert!(build_yec_send(
            &w,
            &keys::encode_p2pkh(Network::Mainnet, &[1; 20]),
            5,
            false,
            false,
            100,
            1
        )
        .is_err());
    }

    /// D-Q-20: YEC to a post-quantum `sq…`/`rq…` pays a `TX_PQPKH` (the regtest pair from a
    /// q/attest node, lightwalletd-dd q/pqaddr `pqPlainVectors`); the inputs and fee are those of
    /// any YEC send. A 53-character `yr…` is refused (Falcon: its sq… form receives YEC; SLH-DSA:
    /// a vault owner).
    #[test]
    fn pays_a_post_quantum_yec_address() {
        let w = wallet_with(&[(50_000, UtxoClass::Yec)]);
        let to = "rqf37MAujTiHQadywBQeNWk42bweehqf1UdcCrXg4oAqhqZQhCebM";
        let p = build_yec_send(&w, to, 20_000, false, false, 100, 0x6d5b_7a31).unwrap();
        let (tx, _) = Transaction::parse(&p.raw).unwrap();
        let id = keys::parse_pq_yec_address(Network::Regtest, to).unwrap();
        assert_eq!(id.scheme, 2);
        assert_eq!(
            tx.vout[0].script_pubkey,
            crate::pq::pqpkh_script(&id).unwrap()
        );
        assert_eq!(tx.vout[0].value, 20_000);
        assert_eq!((p.fee, p.change), (FEE_ZAT, 50_000 - 20_000 - FEE_ZAT));
        assert_eq!(p.to, to);
        // beta2 item 3: its own gate path; the plain YEC path refuses the same bytes
        assert_eq!(
            send_path(Network::Regtest, to).unwrap(),
            gate::Path::YecToPq(id)
        );
        let class = |op: &OutPoint| w.store.utxo_class(op).ok().flatten();
        assert!(gate::check(gate::Path::YecToPq(id), &p.raw, class).is_ok());
        assert_eq!(
            gate::check(gate::Path::Yec, &p.raw, class).unwrap_err(),
            gate::GateError::PqOutputOnYecPath(0)
        );
        let ecc = keys::encode_p2pkh(Network::Regtest, &[0x42; 20]);
        assert_eq!(send_path(Network::Regtest, &ecc).unwrap(), gate::Path::Yec);
        let q = build_yec_send(&w, &ecc, 20_000, false, false, 100, 1).unwrap();
        assert!(gate::check(gate::Path::Yec, &q.raw, class).is_ok());
        assert!(send_path(
            Network::Regtest,
            "yrf1yW8ubn3p8Wf9XWuksXcZs562YHJTTjqdnLuWym3qJQ8SeGH2b"
        )
        .is_err());
        for refused in [
            "yrf1yW8ubn3p8Wf9XWuksXcZs562YHJTTjqdnLuWym3qJQ8SeGH2b",
            "yrs2wCox3ZNcy8vFFh8wejMoNVDfSRKfdjwrp3q4fipDxaJRZPzW3",
            "sq4ekeYR7pAE7ByLpq428jfiHrrsVyMnSTs58MNJeFMXDFL63vTbT",
        ] {
            assert!(
                build_yec_send(&w, refused, 20_000, false, false, 100, 1).is_err(),
                "{refused}"
            );
        }
        let e = build_yec_send(
            &w,
            "yrf1yW8ubn3p8Wf9XWuksXcZs562YHJTTjqdnLuWym3qJQ8SeGH2b",
            20_000,
            false,
            false,
            100,
            1,
        )
        .unwrap_err();
        assert!(e.to_string().contains("ask for its sq… address"), "{e}");
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
        assert!(build_yec_send(&w, &to, 1_000, false, false, 100, 1).is_err());
        w.store
            .unlock(&OutPoint {
                txid: [1; 32],
                n: 0,
            })
            .unwrap();
        let p = build_yec_send(&w, &to, 1_000, false, false, 100, 1).unwrap();
        let (tx, _) = Transaction::parse(&p.raw).unwrap();
        assert_eq!(tx.vout[0].script_pubkey, script::p2sh_script(&[0x42; 20]));
    }
}
