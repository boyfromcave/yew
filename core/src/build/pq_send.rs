// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! A plain YEC send **from** one of the wallet's own post-quantum addresses (`sqf…`/`sqs…`, a
//! Falcon holder's or a vault owner's `TX_PQPKH` coins; beta2 D-2, D-4, D-8) to a transparent
//! recipient of either kind: an ECC `s1…`/`s3…` or another post-quantum address. The shape is
//! planned by [`super::any_to_any::plan_pq_source`], the planner yewd's `z_sendmany` uses (the
//! fee priced on the size, change back to the source address, ycash6's error texts), and signed
//! with the wallet's post-quantum key through the existing [`Transaction::sign_pqpkh_input`], one
//! input at a time (no new signing code). The transaction carries no Sapling part.
//!
//! Burn safety (the gate's [`gate::Path::PqSpend`]): only `PQ_OWNED` rows are candidates, so never
//! a token (the sync's `GetAddressTokens` answers mark every listed PQ outpoint `HELD`, and so is
//! every output of exactly `TOKEN_VALUE`), never a P2PKH coin, never the fee reserve; the local
//! layer refuses any other input class, any payload and any output of exactly `TOKEN_VALUE`; the
//! remote layer (the node's `ValidateRawTransaction`, `ok, burned 0`) is mandatory, so a server
//! without Yellowback refuses the send outright.
//!
//! Not here (reported to the lead, beta2 D-8): a Sapling recipient from a post-quantum source,
//! and a post-quantum recipient paid from Sapling notes. Both need the hybrid builder (Sapling
//! bundle plus transparent post-quantum part, `v4_signature_hash`) that lives in yewd's signer,
//! not in this crate; moving it is a change to signing code.

use crate::build::any_to_any::{self as plan, PlanRecipient, PqCoin};
use crate::coins::{Utxo, UtxoClass};
use crate::gate::{self, Validator};
use crate::keys::{self, YecDestination};
use crate::net::{CompactClient, Validation};
use crate::params::{self, TOKEN_VALUE, TX_EXPIRY_DELTA, VAULT_BRANCH_ID};
use crate::store::HistoryRow;
use crate::tx::{txid_hex, Transaction, TxIn, TxOut};
use crate::wallet::{Wallet, WalletError};

use super::mint;
use super::release::own_pq_key;
use super::terms;

/// The privacy policy the app sends under: the transparent sender is revealed by any spend from
/// a post-quantum address, and the recipient is transparent too (6.x `AllowFullyTransparent`,
/// `z_sendmany`'s default).
pub const APP_POLICY: &str = "AllowFullyTransparent";

/// A planned and signed post-quantum send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqSendPreview {
    /// The source address as given.
    pub from: String,
    /// Its scheme (1 SLH-DSA-SHA2-128s, 2 FN-DSA-512).
    pub scheme: u8,
    /// The recipient as given.
    pub to: String,
    /// The amount paid to it (after the `TOKEN_VALUE` bump, if any).
    pub amount: i64,
    /// True when the amount was bumped from exactly `TOKEN_VALUE`.
    pub amount_bumped: bool,
    /// The fee, zat (folded dust change included).
    pub fee: i64,
    /// The change back to the source address, zat (0 = none).
    pub change: i64,
    /// The coins spent.
    pub inputs: Vec<Utxo>,
    /// `nExpiryHeight`.
    pub expiry_height: u32,
    /// The signed transaction.
    pub raw: Vec<u8>,
    /// Its txid (internal order).
    pub txid: [u8; 32],
    /// Milliseconds spent signing (an SLH-DSA signature takes noticeably longer than ECDSA);
    /// `None` where the platform has no clock to measure it (the browser).
    pub sign_millis: Option<u64>,
    /// Set when the fee is unusual ([`terms::guard_fee`]): why, for the preview to show next to
    /// the fee and the separate confirmation (review YEW-REVIEW-3 M1, YEW-REVIEW-4 M2).
    pub fee_note: Option<String>,
    /// The fee guard: [`broadcast`] refuses a flagged fee without its acknowledgement.
    pub fee_guard: terms::FeeGuard,
}

fn other(m: impl Into<String>) -> WalletError {
    WalletError::Other(m.into())
}

/// Plan and sign a send of `amount` zat from the own post-quantum address `from` to the
/// transparent address `to`, at `tip` under the next block's `branch_id`. Nothing is broadcast.
pub fn build_pq_send(
    wallet: &Wallet,
    from: &str,
    to: &str,
    amount: i64,
    tip: u64,
    branch_id: u32,
) -> Result<PqSendPreview, WalletError> {
    if amount <= 0 {
        return Err(other("amount must be positive"));
    }
    let from = from.trim();
    let to = to.trim();
    let id = keys::parse_pq_yec_address(wallet.network, from).map_err(|_| {
        other("Invalid from address: should be a post-quantum address of this wallet.")
    })?;
    // ycash6 EnsurePQSourceSpendable
    if branch_id != VAULT_BRANCH_ID {
        return Err(other(
            "post-quantum addresses can be spent from only once the vault upgrade is active at the next block",
        ));
    }
    // review YEW-REVIEW-3 M1: never price a send on older terms when the server's were refused
    if let Some(why) = wallet.terms_refused() {
        return Err(other(format!(
            "The server's fee terms were refused, so nothing is sent: {why}"
        )));
    }
    let terms = wallet.pq_terms();
    let falcon_next = terms.falcon_at(tip + 1);
    if id.scheme == crate::pq::SCHEME_FN_DSA_512 && !falcon_next {
        return Err(other(
            "an FN-DSA-512 (scheme 2) post-quantum address can be spent from only once Falcon is active at the next block",
        ));
    }
    let key = own_pq_key(wallet, &id)?.ok_or_else(|| {
        other("From address does not belong to this node, post-quantum key not found.")
    })?;
    if crate::shielded_keys::is_sapling_address(wallet.network, to) {
        return Err(other(
            "Sending from a post-quantum address to a private (ys1…) address is not available in this app yet.",
        ));
    }
    let dest = keys::parse_yec_destination(wallet.network, to)?;
    // ycash6 EnsurePQRecipientPayable
    if let YecDestination::Pq(r) = &dest {
        if r.scheme == crate::pq::SCHEME_FN_DSA_512 && !falcon_next {
            return Err(other(
                "an FN-DSA-512 (scheme 2) post-quantum address can be paid only once Falcon is active at the next block",
            ));
        }
    }
    let dest_script = dest.script();
    // never a YEC output that looks like a token (as `yec_send`)
    let (amount, amount_bumped) = if amount == TOKEN_VALUE {
        (amount + 1, true)
    } else {
        (amount, false)
    };
    let source = crate::pq::pqpkh_script(&id)
        .ok_or_else(|| other("the address's scheme is not registered"))?;
    // the candidates: this address's confirmed PQ_OWNED rows, unlocked (spendable_utxos leaves
    // out the inputs of the wallet's own unconfirmed transactions)
    let spendable = wallet.spendable_utxos()?;
    let coins: Vec<PqCoin<Utxo>> = spendable
        .iter()
        .filter(|u| u.class == UtxoClass::PqOwned && u.script == source && u.height > 0)
        .map(|u| PqCoin {
            outpoint: u.outpoint,
            value: u.value,
            script: u.script.clone(),
            key: u.clone(),
        })
        .collect();
    let recipients = [PlanRecipient {
        script: Some(dest_script),
        amount,
    }];
    let (rate, cap) = (terms.fee_rate_zat_per_kb, terms.max_fee_zat);
    let mut p = plan::plan_pq_source(&coins, &source, &recipients, None, APP_POLICY, rate, cap)
        .map_err(|e| other(e.to_string()))?;
    // never a change output of exactly TOKEN_VALUE: one zat more to the fee
    if p.change == TOKEN_VALUE {
        p.change -= 1;
        p.fee += 1;
        if let Some(o) = p.transparent_outputs.last_mut() {
            o.1 -= 1;
        }
        if p.fee > cap {
            return Err(other(
                plan::PlanError::FeeAboveCap { fee: p.fee, cap }.to_string(),
            ));
        }
    }
    let mut tx = Transaction::new_v4();
    tx.expiry_height = (tip as u32).saturating_add(TX_EXPIRY_DELTA);
    for c in &p.selected {
        tx.vin.push(TxIn::new(c.outpoint));
    }
    for (script, value) in &p.transparent_outputs {
        tx.vout.push(TxOut {
            value: *value,
            script_pubkey: script.clone(),
        });
    }
    // no monotonic clock on wasm32-unknown-unknown (`Instant::now` panics there): 0 in the browser
    #[cfg(not(target_arch = "wasm32"))]
    let started = std::time::Instant::now();
    for (i, c) in p.selected.iter().enumerate() {
        let digest = tx.sign_pqpkh_input(i, &key, &c.script, c.value, branch_id)?;
        // the signature is checked before it leaves (as `release::pq_move`)
        let ok =
            crate::pq::parse_pqpkh_script_sig(&tx.vin[i].script_sig).is_some_and(|(sig, pk)| {
                crate::pq::verify(id.scheme, &pk, &sig[..sig.len() - 1], &digest)
            });
        if !ok {
            return Err(other("the post-quantum signature does not verify"));
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    let sign_millis = Some(started.elapsed().as_millis() as u64);
    #[cfg(target_arch = "wasm32")]
    let sign_millis = None;
    tx.check_script_sig_sizes()?;
    let raw = tx.serialize()?;
    // the signed transaction re-priced: the estimate must cover it
    let sizes: Vec<usize> = tx.vin.iter().map(|i| i.script_sig.len()).collect();
    let conventional = tx.zip317_conventional_fee(&sizes)?;
    plan::check_signed_fee(p.fee, raw.len(), conventional, rate, cap)
        .map_err(|e| other(e.to_string()))?;
    // review YEW-REVIEW-3 M1: the fee is bounded by this build, whatever the server's terms say
    let limit = params::pq_send_fee_limit(raw.len(), conventional);
    if p.fee > limit {
        return Err(other(fee_limit_refusal(p.fee, limit, rate, raw.len())));
    }
    // review YEW-REVIEW-3 L6: the signed bytes are what the preview shows
    check_signed_locally(&tx, &p.selected, p.fee)?;
    let txid = tx.txid()?;
    // review YEW-REVIEW-4 M2: unusual relative to the highest price this wallet has seen
    let fee_guard = wallet.guard_fee(
        terms::FeeKind::Plain,
        p.fee,
        raw.len(),
        conventional,
        &txid_hex(&txid),
    )?;
    let fee_note = fee_guard.note.clone();
    gate::check(gate::Path::PqSpend, &raw, |op| {
        wallet.store.utxo_class(op).ok().flatten()
    })?;
    Ok(PqSendPreview {
        from: from.to_string(),
        scheme: id.scheme,
        to: to.to_string(),
        amount,
        amount_bumped,
        fee: p.fee,
        change: p.change,
        inputs: p.selected.into_iter().map(|c| c.key).collect(),
        expiry_height: tx.expiry_height,
        raw,
        txid,
        sign_millis,
        fee_note,
        fee_guard,
    })
}

/// The refusal of a fee above [`params::pq_send_fee_limit`], naming the quoted rate and the limit.
fn fee_limit_refusal(fee: i64, limit: i64, rate: i64, size: usize) -> String {
    format!(
        "Fee {} YEC is above this app's limit of {} YEC for a {size}-byte post-quantum send (at most {} zat/KB, $0.02/KB at $0.01 per YEC); the server quotes {rate} zat/KB from a YEC price it reports and this app cannot verify. Nothing was sent; try another server.",
        plan::format_money(fee),
        plan::format_money(limit),
        params::MAX_PLAIN_FEE_RATE_ZAT_PER_KB
    )
}

/// Review YEW-REVIEW-3 L6, before a signed send leaves the builder: the inputs are exactly the
/// selected coins, in order, and their total less the outputs is the fee the preview shows; each
/// input's public key hashes to its coin's `TX_PQPKH` key hash. The node's dry run checks both
/// again; this does not rest on it.
fn check_signed_locally(
    tx: &Transaction,
    selected: &[PqCoin<Utxo>],
    fee: i64,
) -> Result<(), WalletError> {
    if tx.vin.len() != selected.len() {
        return Err(other(
            "the signed transaction's inputs are not the selected coins",
        ));
    }
    let mut total_in: i64 = 0;
    for (i, c) in selected.iter().enumerate() {
        if tx.vin[i].prevout != c.outpoint {
            return Err(other(
                "the signed transaction's inputs are not the selected coins",
            ));
        }
        let id = crate::pq::pqpkh_of(&c.script)
            .ok_or_else(|| other("a selected coin is not a post-quantum (TX_PQPKH) output"))?;
        let (_, pk) = crate::pq::parse_pqpkh_script_sig(&tx.vin[i].script_sig)
            .ok_or_else(|| other("a post-quantum input carries no signature"))?;
        if crate::pq::PqKeyId::of(id.scheme, &pk) != id {
            return Err(other(
                "a post-quantum input's public key does not hash to its coin's key hash",
            ));
        }
        total_in = total_in
            .checked_add(c.value)
            .ok_or_else(|| other("input total out of range"))?;
    }
    let total_out = tx
        .vout
        .iter()
        .try_fold(0i64, |a, o| a.checked_add(o.value))
        .ok_or_else(|| other("output total out of range"))?;
    if total_in - total_out != fee {
        return Err(other(format!(
            "the signed transaction pays a fee of {} zat, not the {fee} zat the preview shows",
            total_in - total_out
        )));
    }
    Ok(())
}

/// Both gate layers on the preview ([`gate::Path::PqSpend`]: the node must say `ok, burned 0`;
/// no server without Yellowback), then record (inputs locked until it confirms or expires, the
/// pending transaction, the history row) and `SendTransaction`. A send the server certainly
/// refused is undone and its error returned; any other failure leaves the record for the sync
/// to settle and says so: `…; status unknown, txid <txid>: check before sending again` (yewd's
/// wording, review M1).
pub async fn broadcast(
    wallet: &Wallet,
    client: &mut CompactClient,
    validator: &mut Validator,
    p: &PqSendPreview,
    accept_unusual_fee: Option<&str>,
) -> Result<(String, Validation), WalletError> {
    // YEW-PORT-6 item 2: a flagged fee is never confirmed by the normal button
    terms::require_ack(&p.fee_guard, accept_unusual_fee)?;
    let (_, validation) = gate::confirm(validator, gate::Path::PqSpend, &p.raw, |op| {
        wallet.store.utxo_class(op).ok().flatten()
    })
    .await?;
    let validation = validation.ok_or(gate::GateError::YellowbackAbsent)?;
    // layer 3: no input carries YED by its creating transaction (review YEW-REVIEW-3)
    gate::confirm_provenance(client, gate::Path::PqSpend, &p.raw, |op| {
        wallet.store.utxo_class(op).ok().flatten()
    })
    .await?;
    // review YEW-REVIEW-3 L6: the dry run's `feeZat` is the Yellowback enforcement fee, which a
    // plain YEC send never pays (its network fee is not in the answer: the local check covers it)
    if validation.fee_zat != 0 {
        return Err(other(format!(
            "the node's dry run reports a Yellowback fee of {} zat on a plain YEC send; nothing was sent",
            validation.fee_zat
        )));
    }
    let txid = txid_hex(&p.txid);
    let spent: i64 = p.inputs.iter().map(|u| u.value).sum();
    let persist = || -> Result<(), WalletError> {
        wallet.store.upsert_history(&HistoryRow {
            txid: p.txid,
            height: 0,
            yec_delta: p.change - spent,
            has_payload: false,
            pending: true,
            shielded: false,
            yed_delta: 0,
            kind: String::new(),
            verdict: String::new(),
            label: format!(
                "sent {} from your post-quantum address",
                crate::wallet::yec(p.amount)
            ),
            labelled: false,
        })?;
        Ok(())
    };
    match mint::send_recorded(
        wallet,
        &p.txid,
        &p.raw,
        p.expiry_height,
        &p.inputs,
        persist,
        || Ok(()),
        mint::send(client, &p.raw, &p.txid),
    )
    .await
    {
        Ok(()) => Ok((txid, validation)),
        Err(e) if mint::send_refused(&e) => Err(e),
        Err(e) => Err(other(format!(
            "{e}; status unknown, txid {txid}: check before sending again"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::Network;
    use crate::store::Store;
    use crate::tx::OutPoint;

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    /// A regtest wallet with Falcon active and its first Falcon holder's coins `values` (class
    /// PQ_OWNED unless given), plus other rows to show the selection skips them.
    fn wallet_with(rows: &[(i64, UtxoClass)]) -> (Wallet, String, Vec<u8>) {
        let seed = keys::seed_from_mnemonic(PHRASE, "").unwrap();
        let mut w = Wallet::from_parts(
            Store::open_in_memory().unwrap(),
            Network::Regtest,
            &seed,
            None,
        )
        .unwrap();
        let mut t = w.pq_terms();
        t.falcon_active = true;
        w.set_pq_terms_for_test(t);
        let holders = w.own_falcon_holders().unwrap();
        let (id, _) = holders.iter().next().expect("a Falcon holder");
        let script = crate::pq::pqpkh_script(id).unwrap();
        let from = keys::encode_pq_yec(Network::Regtest, id).unwrap();
        let utxos: Vec<Utxo> = rows
            .iter()
            .enumerate()
            .map(|(i, (v, c))| Utxo {
                outpoint: OutPoint {
                    txid: [i as u8 + 1; 32],
                    n: 0,
                },
                address: from.clone(),
                script: script.clone(),
                value: *v,
                height: 10,
                class: *c,
                cents: 0,
            })
            .collect();
        w.store.replace_utxos(&utxos).unwrap();
        (w, from, script)
    }

    fn ecc_to() -> String {
        keys::encode_p2pkh(Network::Regtest, &[0x42; 20])
    }

    /// PQ source → ECC: only PQ_OWNED coins of the address, the change back to the source (D-4),
    /// the fee on the size, signatures that verify, the gate's PQ path passes.
    #[test]
    fn pq_to_ecc_change_to_source() {
        let (w, from, script) = wallet_with(&[
            (3_000_000, UtxoClass::PqOwned),
            (90_000_000, UtxoClass::Held),
            (80_000_000, UtxoClass::Token),
        ]);
        let p = build_pq_send(&w, &from, &ecc_to(), 1_000_000, 100, VAULT_BRANCH_ID).unwrap();
        assert_eq!(p.inputs.len(), 1);
        assert_eq!(p.inputs[0].class, UtxoClass::PqOwned);
        let (tx, _) = Transaction::parse(&p.raw).unwrap();
        assert_eq!(tx.vout.len(), 2);
        assert_eq!(
            tx.vout[1].script_pubkey, script,
            "D-4: change to the source"
        );
        assert_eq!(p.amount + p.fee + p.change, 3_000_000);
        assert!(p.fee >= 1000);
        assert_eq!(p.scheme, crate::pq::SCHEME_FN_DSA_512);
    }

    /// The HELD and TOKEN rows of the same address are never selected: with only those, the
    /// send has no coins.
    #[test]
    fn never_selects_held_or_token() {
        let (w, from, _) = wallet_with(&[
            (TOKEN_VALUE, UtxoClass::Held),
            (80_000_000, UtxoClass::Token),
            (5_000_000, UtxoClass::PendingToken),
        ]);
        let e = build_pq_send(&w, &from, &ecc_to(), 1_000_000, 100, VAULT_BRANCH_ID).unwrap_err();
        assert_eq!(
            e.to_string(),
            "Insufficient transparent funds, no UTXOs found for taddr from address."
        );
    }

    /// PQ source → PQ recipient, and the vault-branch / Sapling refusals.
    #[test]
    fn pq_to_pq_and_refusals() {
        let (w, from, _) = wallet_with(&[(3_000_000, UtxoClass::PqOwned)]);
        let other = keys::encode_pq_yec(
            Network::Regtest,
            &crate::pq::PqKeyId {
                scheme: crate::pq::SCHEME_SLH_DSA_SHA2_128S,
                hash: [9; 32],
            },
        )
        .unwrap();
        assert!(other.starts_with("rqs"));
        let p = build_pq_send(&w, &from, &other, 1_000_000, 100, VAULT_BRANCH_ID).unwrap();
        let (tx, _) = Transaction::parse(&p.raw).unwrap();
        assert!(crate::pq::pqpkh_of(&tx.vout[0].script_pubkey).is_some());
        let e = build_pq_send(&w, &from, &other, 1_000_000, 100, 0x2bb4_0e60).unwrap_err();
        assert!(
            e.to_string()
                .contains("only once the vault upgrade is active"),
            "{e}"
        );
        let e = build_pq_send(&w, &from, &ecc_to(), 50_000_000, 100, VAULT_BRANCH_ID).unwrap_err();
        assert!(
            e.to_string()
                .starts_with("Insufficient transparent funds, have 0.03, need"),
            "{e}"
        );
    }

    /// Review YEW-REVIEW-3 M1: terms that would make the fee exceed this build's limit (as a
    /// server reporting a tiny price would, had its terms got through) are refused, naming the
    /// quoted rate and the limit; at exactly the limit rate the send passes with the unusual-fee
    /// note; honest terms keep their fee and carry no note.
    #[test]
    fn fee_limit_and_unusual_note() {
        let (w, from, _) = wallet_with(&[(30 * params::COIN, UtxoClass::PqOwned)]);
        // honest default terms: the fee is unchanged by the limit, no note
        let honest = build_pq_send(&w, &from, &ecc_to(), 1_000_000, 100, VAULT_BRANCH_ID).unwrap();
        assert!(honest.fee_note.is_none());
        assert!(honest.fee < params::DEFAULT_TRANSACTION_MAXFEE_ZAT);
        let base = w.pq_terms();
        let mut t = w.pq_terms();
        // hostile: 10 YEC/KB with the 10 YEC cap
        t.fee_rate_zat_per_kb = 10 * params::COIN;
        t.max_fee_zat = params::MAX_YED_TX_FEE_ZAT;
        w.set_pq_terms_for_test(t);
        let e = build_pq_send(&w, &from, &ecc_to(), 1_000_000, 100, VAULT_BRANCH_ID).unwrap_err();
        let e = e.to_string();
        assert!(
            e.starts_with("Fee 10.00 YEC is above this app's limit of")
                && e.contains("the server quotes 1000000000 zat/KB"),
            "{e}"
        );
        // the boundary: exactly the limit rate passes, marked unusual
        t.fee_rate_zat_per_kb = params::MAX_PLAIN_FEE_RATE_ZAT_PER_KB;
        w.set_pq_terms_for_test(t);
        let p = build_pq_send(&w, &from, &ecc_to(), 1_000_000, 100, VAULT_BRANCH_ID).unwrap();
        let conventional = {
            let (tx, _) = Transaction::parse(&p.raw).unwrap();
            let sizes: Vec<usize> = tx.vin.iter().map(|i| i.script_sig.len()).collect();
            tx.zip317_conventional_fee(&sizes).unwrap()
        };
        assert_eq!(p.fee, params::pq_send_fee_limit(p.raw.len(), conventional));
        // review YEW-REVIEW-4 M2: on first use (no price seen) nothing below the limit is flagged
        assert!(p.fee_note.is_none() && p.fee_guard.ack.is_none());
        // once a price was seen ($0.05), the same terms are flagged, with an acknowledgement
        w.store.set_meta("fee_price_high_water", "50000").unwrap();
        let p = build_pq_send(&w, &from, &ecc_to(), 1_000_000, 100, VAULT_BRANCH_ID).unwrap();
        let note = p.fee_note.clone().expect("an unusual fee is marked");
        assert!(
            note.starts_with("Unusual fee:")
                && note.contains("× the usual")
                && note.contains("came from the server"),
            "{note}"
        );
        let ack = p
            .fee_guard
            .ack
            .clone()
            .expect("flagged: an acknowledgement");
        assert!(ack.ends_with(&txid_hex(&p.txid)), "{ack}");
        // YEW-PORT-6 item 2: the confirm refuses without it, with another, and passes with it
        assert!(terms::require_ack(&p.fee_guard, None)
            .unwrap_err()
            .to_string()
            .starts_with("unusual-fee:"));
        assert!(terms::require_ack(&p.fee_guard, Some("accept-unusual-fee:1:x")).is_err());
        assert!(terms::require_ack(&p.fee_guard, Some(&ack)).is_ok());
        // honest terms at that price: not flagged, and a stray acknowledgement is refused
        w.set_pq_terms_for_test(base);
        let honest = build_pq_send(&w, &from, &ecc_to(), 1_000_000, 100, VAULT_BRANCH_ID).unwrap();
        assert!(honest.fee_note.is_none());
        assert!(terms::require_ack(&honest.fee_guard, None).is_ok());
        assert!(terms::require_ack(&honest.fee_guard, Some(&ack)).is_err());
    }

    /// Review YEW-REVIEW-3 M1: when the server's terms were refused, the send refuses with the
    /// reason instead of pricing itself on older terms.
    #[test]
    fn refused_terms_refuse_the_send() {
        let (w, from, _) = wallet_with(&[(3_000_000, UtxoClass::PqOwned)]);
        assert!(w.note_server_params(None).is_err());
        let e = build_pq_send(&w, &from, &ecc_to(), 1_000_000, 100, VAULT_BRANCH_ID).unwrap_err();
        assert!(
            e.to_string()
                .starts_with("The server's fee terms were refused"),
            "{e}"
        );
    }

    /// Review YEW-REVIEW-3 L6: the local checks of the signed bytes refuse a fee other than the
    /// preview's, an input other than the selected coin, and a key that is not the coin's.
    #[test]
    fn signed_bytes_are_checked_locally() {
        let (w, from, _) = wallet_with(&[(3_000_000, UtxoClass::PqOwned)]);
        let p = build_pq_send(&w, &from, &ecc_to(), 1_000_000, 100, VAULT_BRANCH_ID).unwrap();
        let (tx, _) = Transaction::parse(&p.raw).unwrap();
        let sel: Vec<PqCoin<Utxo>> = p
            .inputs
            .iter()
            .map(|u| PqCoin {
                outpoint: u.outpoint,
                value: u.value,
                script: u.script.clone(),
                key: u.clone(),
            })
            .collect();
        check_signed_locally(&tx, &sel, p.fee).unwrap();
        let e = check_signed_locally(&tx, &sel, p.fee + 1).unwrap_err();
        assert!(e.to_string().contains("not the"), "{e}");
        let mut moved = sel.clone();
        moved[0].outpoint.n = 7;
        assert!(check_signed_locally(&tx, &moved, p.fee).is_err());
        let mut foreign = sel.clone();
        foreign[0].script = crate::pq::pqpkh_script(&crate::pq::PqKeyId {
            scheme: crate::pq::SCHEME_FN_DSA_512,
            hash: [3; 32],
        })
        .unwrap();
        let e = check_signed_locally(&tx, &foreign, p.fee).unwrap_err();
        assert!(e.to_string().contains("does not hash"), "{e}");
    }
}
