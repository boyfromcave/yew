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
//!
//! **The post-quantum residual (quantum spec F-3, §3.3).** The owner's RED-5 residual intent pays
//! `PQPKH(owner)` (35 bytes), not a P2PKH key. Its release is built as above; the coin it makes is
//! then moved to an own P2PKH key by a second transaction ([`ReleaseKind::PqSweep`], one ~8 KB
//! SLH-DSA spend signed with `Wallet::pq_key_for_owner`), offered on the same intent row once the
//! release has confirmed: the coin is `spend_txid:0` of a release this wallet broadcast.
//!
//! **Any own post-quantum coin.** Since lightwalletd-dd q/pqaddr indexes `TX_PQPKH` under the
//! plain `sq…` address, the sync lists the YEC at the wallet's own post-quantum keys (a residual
//! released by someone else — allowed, the release needs no signature, U-15 — or a payment to a
//! Falcon holder's `sq…` form) as `PQ_OWNED` UTXO rows. [`build_pq_coin_move`] moves one such
//! coin to an own P2PKH key the same way (one input, signed by the owner's SLH-DSA key or the
//! holder's Falcon key, the fee out of the coin); the remote gate layer must say `ok, burned 0`,
//! so a coin that is in fact a YED token is never moved as YEC.

use crate::coins::{self, Utxo};
use crate::gate::{self, Validator};
use crate::net::{CompactClient, Validation};
use crate::params::{TOKEN_VALUE, TX_EXPIRY_DELTA};
use crate::pq::PqKeyId;
use crate::script;
use crate::store::{HistoryRow, IntentRow, IntentState, VaultRow};
use crate::tx::{txid_hex, OutPoint, Transaction, TxIn, TxOut};
use crate::vault;
use crate::wallet::{Wallet, WalletError};

use super::mint;
use super::yec_send::MIN_CHANGE;

/// What a [`ReleaseBuild`] does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReleaseKind {
    /// The release of a matured intent to the recipient it commits to.
    Release,
    /// The move of a released residual's post-quantum coin to an own P2PKH key.
    PqSweep,
}

/// What the release screen shows and what is broadcast.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseBuild {
    /// Release or post-quantum move.
    pub kind: ReleaseKind,
    /// The intent released.
    pub intent: OutPoint,
    /// What the recipient receives: the intent's whole value (a release), or the coin's value
    /// less the size-priced fee (a move).
    pub value: i64,
    /// The recipient: `s…` (a P2PKH key; a move's own key), or the vault owner's 53-character
    /// post-quantum address (a residual's release).
    pub recipient_address: String,
    /// The network fee, zat: `FEE_ZAT` from the wallet's YEC (a release), or `max(FEE_ZAT,
    /// pqfeerate × size)` out of the coin (a move).
    pub fee: i64,
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

/// The post-quantum coin of a released residual that still waits to be moved: `spend_txid:0`
/// paying `PQPKH(owner)`, released by this wallet (its txid known), not yet moved.
pub fn pq_coin(row: &IntentRow) -> Option<(OutPoint, PqKeyId)> {
    let owner = crate::pq::pqpkh_of(&row.recipient_script)?;
    (row.role == super::claim::ROLE_RESIDUAL
        && row.state == IntentState::Released
        && row.spend_txid != [0; 32]
        && row.pq_spend_txid == [0; 32])
        .then_some((
            OutPoint {
                txid: row.spend_txid,
                n: 0,
            },
            owner,
        ))
}

/// Why an intent cannot be released (or its post-quantum coin moved) now.
pub fn not_releasable(row: &IntentRow, tip: u64) -> Option<String> {
    if pq_coin(row).is_some() {
        return None;
    }
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

/// The held residual (the per-vault cancel limit, CAN-3): when an attestor-set cancel re-created
/// the owner's vault, the residual intent of that cancelled claim is held by the position (the
/// vault's `heldResiduals`, as the last sync read it). The node releases it only once the position
/// is CLOSED or CLAIMED, or ACTIVE from `cancelQuietUntil` while no claim on it could pass. Returns
/// why `row` is held now (the text to show), or `None` when it is not held or the release may
/// pass. The wallet judges "could not be claimed" by the node's `claimable` at the last sync; the
/// node's own test reads every reference height a claim may cite, so its refusal
/// (`intent-residual-held`) still stands where the two differ.
pub fn residual_held(row: &IntentRow, vaults: &[VaultRow], tip: u64) -> Option<String> {
    if pq_coin(row).is_some() || !row.state.open() {
        return None;
    }
    let v = vaults
        .iter()
        .find(|v| v.cancel.held_residuals.contains(&row.outpoint))?;
    held_reason(v, tip)
}

/// Why a residual held by vault `v` cannot be released in the next block (`None`: it may be).
pub fn held_reason(v: &VaultRow, tip: u64) -> Option<String> {
    let next = tip + 1;
    match v.status.as_str() {
        "CLOSED" | "CLAIMED" => None,
        "ACTIVE" if next < v.cancel.quiet_until => Some(format!(
            "intent-residual-held: held after a cancelled claim until height {} (the quiet period), \
             and after that only while the vault cannot be claimed; redeeming the vault releases it",
            v.cancel.quiet_until
        )),
        "ACTIVE" if v.claimable => Some(
            "intent-residual-held: held while the vault can be claimed; it is released once the \
             vault cannot be claimed, or once the vault is closed (redeem it)"
                .into(),
        ),
        "ACTIVE" => None,
        _ => Some(
            "intent-residual-held: held while a claim of the vault is in progress; it is released \
             once the vault is closed, or active again and past its quiet period while it cannot \
             be claimed"
                .into(),
        ),
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
    if let Some(why) = residual_held(row, &wallet.store.vaults()?, tip) {
        return Err(WalletError::Other(why));
    }
    if let Some((coin, owner)) = pq_coin(row) {
        return build_pq_sweep(wallet, row, coin, &owner, tip, branch_id);
    }
    let ip = vault::parse_intent(&row.intent_script).ok_or_else(|| {
        WalletError::Other("intent-malformed: the stored intent does not parse".into())
    })?;
    if vault::script_hash256(&row.recipient_script) != ip.recipient_hash {
        return Err(WalletError::Other(
            "intent-recipient: the stored recipient is not the intent's".into(),
        ));
    }
    // The recipient: an own P2PKH key (a claimant intent), or an own vault owner's PQPKH (the
    // residual, quantum spec F-3): released the same way, its coin moved afterwards.
    let recipient_address = if let Some(h) = script::p2pkh_hash(&row.recipient_script)
        .filter(|h| wallet.own_hashes().map(|o| o.contains(h)).unwrap_or(false))
    {
        crate::keys::encode_p2pkh(wallet.network, &h)
    } else if let Some(id) = crate::pq::pqpkh_of(&row.recipient_script).filter(|id| {
        wallet
            .own_pq_owners()
            .map(|o| o.contains_key(id))
            .unwrap_or(false)
    }) {
        crate::keys::encode_pq_yellowback(wallet.network, &id).unwrap_or_default()
    } else {
        return Err(WalletError::Other(
            "intent-not-ours: the intent does not pay this wallet".into(),
        ));
    };
    // rpcversion 8: `vault_release` prices the release at the Yellowback rate by its size
    // (`YedSizeFee(VAULT_RPC_FEE, size)` capped by `YedMaxTxFee()`): the intent input (an empty-ish
    // scriptSig), the fee coins at their P2PKH bound, the recipient and a change output.
    let spendable = wallet.spendable_utxos()?;
    let sized = |n_inputs: usize| -> i64 {
        // version/header/expiry ~ 30, the intent input ~ 45, each P2PKH input ≤ 41 + 107 + 3,
        // two outputs ≤ 2 × 45 (Transaction::size_with_script_sigs is exact once built)
        wallet
            .pq_terms()
            .yed_fee(30 + 45 + n_inputs * 151 + 90 + row.recipient_script.len())
    };
    let mut fee = sized(1);
    let inputs = loop {
        let sel = coins::select_yec(&spendable, fee, true)?;
        let next = sized(sel.len());
        if next <= fee {
            break sel;
        }
        fee = next;
    };
    let selected: i64 = inputs.iter().map(|u| u.value).sum();
    let mut change = selected - fee;
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
        kind: ReleaseKind::Release,
        intent: row.outpoint,
        value: row.value,
        recipient_address,
        fee,
        inputs,
        change,
        expiry_height: tx.expiry_height,
        raw,
        txid,
    })
}

/// Move a released residual's post-quantum coin (`coin`, paying `PQPKH(owner)`) to an own fresh
/// P2PKH change key: one input, signed by the owner's SLH-DSA key (7,938-byte scriptSig), one
/// output of the coin's value less `max(FEE_ZAT, pqfeerate × size)` (the size is exact: one
/// post-quantum input of a fixed size). The signature is checked before it leaves, and the
/// scriptSig against the 9,000-byte relay limit.
fn build_pq_sweep(
    wallet: &Wallet,
    row: &IntentRow,
    coin: OutPoint,
    owner: &PqKeyId,
    tip: u64,
    branch_id: u32,
) -> Result<ReleaseBuild, WalletError> {
    let paired = wallet.own_pq_owners()?.get(owner).copied().ok_or_else(|| {
        WalletError::Other(
            "intent-not-ours: the residual's owner is not a key of this wallet".into(),
        )
    })?;
    let key = wallet
        .pq_key_for_owner(owner, &paired)?
        .ok_or_else(|| WalletError::Other("vault-not-owned: owner key missing".into()))?;
    pq_move(
        wallet,
        row.outpoint,
        coin,
        row.value,
        &row.recipient_script,
        &key,
        tip,
        branch_id,
    )
}

/// The key of an own post-quantum id: a vault owner (SLH-DSA, through its paired external key)
/// or a Falcon YED holder.
fn own_pq_key(wallet: &Wallet, id: &PqKeyId) -> Result<Option<crate::pq::PqKey>, WalletError> {
    if let Some(paired) = wallet.own_pq_owners()?.get(id).copied() {
        return wallet.pq_key_for_owner(id, &paired);
    }
    wallet.falcon_key_for_id(id)
}

/// The move of an own post-quantum coin the sync found (class `PQ_OWNED`: plain YEC at a vault
/// owner's or a Falcon holder's `TX_PQPKH`, never a listed token, never exactly `TOKEN_VALUE`)
/// to a fresh own P2PKH change key, its fee out of the coin. `intent` of the result is the coin.
pub fn build_pq_coin_move(
    wallet: &Wallet,
    coin: &OutPoint,
    tip: u64,
    branch_id: u32,
) -> Result<ReleaseBuild, WalletError> {
    let u = wallet
        .spendable_utxos()?
        .into_iter()
        .find(|u| u.outpoint == *coin)
        .ok_or_else(|| {
            WalletError::Other(format!(
                "pq-coin-unknown: {} is not an unspent coin of this wallet",
                coin.display()
            ))
        })?;
    if u.class != coins::UtxoClass::PqOwned {
        return Err(WalletError::Other(format!(
            "pq-coin-class: {} is {}, not post-quantum YEC",
            coin.display(),
            u.class.as_str()
        )));
    }
    let id = crate::pq::pqpkh_of(&u.script).ok_or_else(|| {
        WalletError::Other(format!(
            "pq-coin-script: {} is not a TX_PQPKH",
            coin.display()
        ))
    })?;
    let key = own_pq_key(wallet, &id)?.ok_or_else(|| {
        WalletError::Other(format!(
            "pq-coin-not-ours: no key of this wallet signs for {}",
            coin.display()
        ))
    })?;
    pq_move(
        wallet, *coin, *coin, u.value, &u.script, &key, tip, branch_id,
    )
}

/// One post-quantum input `coin` (`value` zat, `script` its `TX_PQPKH`) to a fresh own P2PKH
/// change key, signed by `key`; `intent` names what the result is recorded under.
#[allow(clippy::too_many_arguments)]
fn pq_move(
    wallet: &Wallet,
    intent: OutPoint,
    coin: OutPoint,
    value_in: i64,
    script_pubkey: &[u8],
    key: &crate::pq::PqKey,
    tip: u64,
    branch_id: u32,
) -> Result<ReleaseBuild, WalletError> {
    let owner = &key.id();
    if crate::pq::pqpkh_of(script_pubkey) != Some(*owner) {
        return Err(WalletError::Other(
            "the post-quantum key does not match the coin's script".into(),
        ));
    }
    let dest = wallet.change_address()?;
    let mut tx = Transaction::new_v4();
    tx.expiry_height = (tip as u32).saturating_add(TX_EXPIRY_DELTA);
    tx.vin.push(TxIn::new(coin));
    tx.vout.push(TxOut {
        value: value_in,
        script_pubkey: script::p2pkh_script(&dest.hash160),
    });
    let ss = crate::pq::pq_sig_pushes_size(owner.scheme)
        .ok_or_else(|| WalletError::Other("the key's scheme is not registered".into()))?;
    // At least the 6.20.0 line's ZIP-317 conventional fee (audit 04/N-1; as `CreateTransaction`
    // on both node lines, outside the cap).
    let fee = wallet
        .pq_terms()
        .fee(tx.size_with_script_sigs(&[ss])?)
        .max(tx.zip317_conventional_fee(&[ss])?);
    let mut value = value_in - fee;
    if value == TOKEN_VALUE {
        value -= 1; // never a YEC output that looks like a token
    }
    if value < MIN_CHANGE {
        return Err(WalletError::Other(format!(
            "pq-coin-too-small: the coin ({value_in} zat) does not cover the {fee} zat fee of a post-quantum spend"
        )));
    }
    tx.vout[0].value = value;
    let digest = tx.sign_pqpkh_input(0, key, script_pubkey, value_in, branch_id)?;
    let ok = crate::pq::parse_pqpkh_script_sig(&tx.vin[0].script_sig).is_some_and(|(sig, pk)| {
        crate::pq::verify(owner.scheme, &pk, &sig[..sig.len() - 1], &digest)
    });
    if !ok {
        return Err(WalletError::Other(
            "the post-quantum signature does not verify".into(),
        ));
    }
    tx.check_script_sig_sizes()?;
    let raw = tx.serialize()?;
    let txid = tx.txid()?;
    gate::check(gate::Path::PqSweep(coin), &raw, |op| {
        wallet.store.utxo_class(op).ok().flatten()
    })?;
    Ok(ReleaseBuild {
        kind: ReleaseKind::PqSweep,
        intent,
        value,
        recipient_address: dest.address_s.clone(),
        fee: value_in - value,
        inputs: Vec::new(),
        change: 0,
        expiry_height: tx.expiry_height,
        raw,
        txid,
    })
}

/// The move's broadcast: both gate layers on the named coin, the own output, the history row,
/// the intent row's `pq_spend_txid`.
async fn broadcast_pq_sweep(
    wallet: &Wallet,
    client: &mut CompactClient,
    validator: &mut Validator,
    p: &ReleaseBuild,
    row: IntentRow,
) -> Result<(String, Validation), WalletError> {
    let coin = OutPoint {
        txid: row.spend_txid,
        n: 0,
    };
    let (tx, validation) = gate::confirm(validator, gate::Path::PqSweep(coin), &p.raw, |op| {
        wallet.store.utxo_class(op).ok().flatten()
    })
    .await?;
    let validation = validation.ok_or(gate::GateError::YellowbackAbsent)?;
    let original = row.clone();
    let persist = || -> Result<(), WalletError> {
        if let Some(h) = tx
            .vout
            .first()
            .and_then(|o| script::p2pkh_hash(&o.script_pubkey))
        {
            wallet.store.mark_used(&h)?;
            wallet.ensure_gap()?;
            wallet
                .store
                .insert_own_output(&OutPoint { txid: p.txid, n: 0 }, p.value, &h)?;
        }
        wallet.store.upsert_history(&HistoryRow {
            txid: p.txid,
            height: 0,
            yec_delta: p.value,
            has_payload: false,
            pending: true,
            shielded: false,
            yed_delta: 0,
            kind: "pq_sweep".into(),
            verdict: String::new(),
            label: format!(
                "moving {} from your vault-owner key",
                crate::wallet::yec(p.value)
            ),
            labelled: false,
        })?;
        wallet.store.upsert_intent(&IntentRow {
            pq_spend_txid: p.txid,
            note: format!(
                "moving the residual to your wallet ({} broadcast)",
                &txid_hex(&p.txid)[..8]
            ),
            ..row
        })?;
        Ok(())
    };
    mint::send_recorded(
        wallet,
        &p.txid,
        &p.raw,
        p.expiry_height,
        &[],
        persist,
        || Ok(wallet.store.upsert_intent(&original)?),
        mint::send(client, &p.raw, &p.txid),
    )
    .await?;
    Ok((txid_hex(&p.txid), validation))
}

/// The broadcast of a [`build_pq_coin_move`]: the coin still `PQ_OWNED` and unlocked, both gate
/// layers on the named coin (the remote one must say `ok, burned 0`), then the coin locked
/// until the move confirms or expires, the own output and the history row.
async fn broadcast_pq_coin_move(
    wallet: &Wallet,
    client: &mut CompactClient,
    validator: &mut Validator,
    p: &ReleaseBuild,
) -> Result<(String, Validation), WalletError> {
    let coin = p.intent;
    let u = wallet
        .spendable_utxos()?
        .into_iter()
        .find(|u| u.outpoint == coin && u.class == coins::UtxoClass::PqOwned)
        .ok_or_else(|| {
            WalletError::Other(format!(
                "pq-coin-unknown: {} is no longer an unspent post-quantum coin of this wallet",
                coin.display()
            ))
        })?;
    let (tx, validation) = gate::confirm(validator, gate::Path::PqSweep(coin), &p.raw, |op| {
        wallet.store.utxo_class(op).ok().flatten()
    })
    .await?;
    let validation = validation.ok_or(gate::GateError::YellowbackAbsent)?;
    let persist = || -> Result<(), WalletError> {
        if let Some(h) = tx
            .vout
            .first()
            .and_then(|o| script::p2pkh_hash(&o.script_pubkey))
        {
            wallet.store.mark_used(&h)?;
            wallet.ensure_gap()?;
            wallet
                .store
                .insert_own_output(&OutPoint { txid: p.txid, n: 0 }, p.value, &h)?;
        }
        wallet.store.upsert_history(&HistoryRow {
            txid: p.txid,
            height: 0,
            yec_delta: -p.fee,
            has_payload: false,
            pending: true,
            shielded: false,
            yed_delta: 0,
            kind: "pq_sweep".into(),
            verdict: String::new(),
            label: format!(
                "moving {} from your post-quantum address",
                crate::wallet::yec(p.value)
            ),
            labelled: false,
        })?;
        Ok(())
    };
    mint::send_recorded(
        wallet,
        &p.txid,
        &p.raw,
        p.expiry_height,
        std::slice::from_ref(&u),
        persist,
        || Ok(()),
        mint::send(client, &p.raw, &p.txid),
    )
    .await?;
    Ok((txid_hex(&p.txid), validation))
}

/// Both gate layers, broadcast, locks, the history row; the intent row to `Releasing`.
pub async fn broadcast(
    wallet: &Wallet,
    client: &mut CompactClient,
    validator: &mut Validator,
    p: &ReleaseBuild,
) -> Result<(String, Validation), WalletError> {
    let row = match wallet.store.intent(&p.intent)? {
        Some(r) => r,
        None if p.kind == ReleaseKind::PqSweep => {
            return broadcast_pq_coin_move(wallet, client, validator, p).await
        }
        None => {
            return Err(WalletError::Other(
                "intent-unknown: not an intent of this wallet".into(),
            ))
        }
    };
    if p.kind == ReleaseKind::PqSweep {
        return broadcast_pq_sweep(wallet, client, validator, p, row).await;
    }
    let to_pq = crate::pq::pqpkh_of(&row.recipient_script).is_some();
    let (tx, validation) = gate::confirm(
        validator,
        gate::Path::IntentRelease(p.intent),
        &p.raw,
        |op| wallet.store.utxo_class(op).ok().flatten(),
    )
    .await?;
    let validation = validation.ok_or(gate::GateError::YellowbackAbsent)?;
    let original = row.clone();
    let persist = || -> Result<(), WalletError> {
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
            // A residual paid to the owner's PQPKH is not spendable YEC until it is moved.
            yec_delta: if to_pq { 0 } else { p.value } + p.change - spent,
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
            pq_spend_txid: [0; 32],
            note: format!("release {} broadcast", &txid_hex(&p.txid)[..8]),
            ..row
        })?;
        Ok(())
    };
    mint::send_recorded(
        wallet,
        &p.txid,
        &p.raw,
        p.expiry_height,
        &p.inputs,
        persist,
        || Ok(wallet.store.upsert_intent(&original)?),
        mint::send(client, &p.raw, &p.txid),
    )
    .await?;
    Ok((txid_hex(&p.txid), validation))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::FEE_ZAT;

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
            pq_spend_txid: [0; 32],
            note: String::new(),
            refund: Default::default(),
        }
    }

    fn holder(status: &str, quiet_until: u64, claimable: bool, held: Vec<OutPoint>) -> VaultRow {
        VaultRow {
            txid: [9; 32],
            vout: 0,
            status: status.into(),
            owner_hash160: [2; 20],
            owner: PqKeyId {
                scheme: 1,
                hash: [2; 32],
            },
            term_class: "A".into(),
            lock_height: 900,
            claim_height: 900,
            collateral_zat: 1_000_000_000,
            minted_cents: 10_000,
            mint_height: 90,
            claimable,
            underwater_at: 0,
            sweep_before: 0,
            close_height: 0,
            closing_txid: String::new(),
            void_reason: String::new(),
            updated_height: 0,
            owner_height: 91,
            app_height: 91,
            p_mint: 520_000,
            cancel: crate::store::VaultCancel {
                count: 1,
                required: 2,
                quiet_until,
                held_residuals: held,
            },
        }
    }

    /// CAN-3: a residual its position holds is not released before the quiet period ends, nor
    /// while the vault is claimable or a claim of it is in progress; it is once the vault is
    /// closed or claimed, or active, past the quiet period and not claimable.
    #[test]
    fn held_residual_waits_for_quiet_or_close() {
        let mut r = row(100, IntentState::Pending);
        r.role = crate::build::claim::ROLE_RESIDUAL.into();
        let held = vec![r.outpoint];
        // Not held by any vault: only the claim delay applies.
        assert!(residual_held(&r, &[holder("ACTIVE", 200, false, vec![])], 150).is_none());
        // Held, inside the quiet period (the release would be in block 199 < 200).
        let why = residual_held(&r, &[holder("ACTIVE", 200, false, held.clone())], 198).unwrap();
        assert!(
            why.starts_with("intent-residual-held") && why.contains("200"),
            "{why}"
        );
        // From the quiet period's end (block 200) while not claimable: may pass.
        assert!(residual_held(&r, &[holder("ACTIVE", 200, false, held.clone())], 199).is_none());
        // Past the quiet period but claimable: held.
        assert!(residual_held(&r, &[holder("ACTIVE", 200, true, held.clone())], 300).is_some());
        // A claim of the position in progress: held.
        assert!(residual_held(&r, &[holder("CLAIMING", 200, false, held.clone())], 300).is_some());
        // The position closed or claimed: released at once, inside the quiet period too.
        for status in ["CLOSED", "CLAIMED"] {
            assert!(residual_held(&r, &[holder(status, 200, true, held.clone())], 150).is_none());
        }
        // A released (or cancelled) row is not judged here.
        r.state = IntentState::Released;
        assert!(residual_held(&r, &[holder("ACTIVE", 200, true, held)], 150).is_none());
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

    /// Quantum spec F-3: the residual pays `PQPKH(owner)`; once released by this wallet, the
    /// same row builds the move of that coin into the wallet, signed with the owner's SLH-DSA key
    /// (verified), priced by its exact size, gated by name; a non-owned or unreleased row cannot.
    #[test]
    fn residual_pq_coin_moves_into_the_wallet() {
        const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let seed = crate::keys::seed_from_mnemonic(PHRASE, "").unwrap();
        let w = Wallet::from_parts(
            crate::store::Store::open_in_memory().unwrap(),
            crate::params::Network::Regtest,
            &seed,
            None,
        )
        .unwrap();
        let owner = w.pq_owner_id(0);
        let pqpkh = crate::pq::pqpkh_script(&owner).unwrap();
        let mut r = IntentRow {
            role: super::super::claim::ROLE_RESIDUAL.into(),
            recipient_script: pqpkh.clone(),
            value: 5_000_000,
            ..row(100, IntentState::Pending)
        };
        // Pending: a release (the intent itself), not a move.
        assert!(pq_coin(&r).is_none());
        // Released by this wallet: the coin is spend_txid:0, and the row is actionable again.
        r.state = IntentState::Released;
        r.spend_txid = [0xab; 32];
        assert_eq!(
            pq_coin(&r),
            Some((
                OutPoint {
                    txid: [0xab; 32],
                    n: 0
                },
                owner
            ))
        );
        assert!(not_releasable(&r, 500).is_none());
        let b = build_release(&w, &r, 500, 0x6d5b_7a31).unwrap();
        assert_eq!(b.kind, ReleaseKind::PqSweep);
        assert!(b.inputs.is_empty());
        let (tx, _) = Transaction::parse(&b.raw).unwrap();
        assert_eq!(tx.vin.len(), 1);
        assert_eq!(tx.vin[0].prevout.txid, [0xab; 32]);
        assert_eq!(tx.vin[0].script_sig.len(), 7_938);
        assert_eq!(b.fee, 5_000_000 - tx.vout[0].value);
        // 1x the relay floor: the size fee is under the flat 1,000 (C-5), but the 7,981 vin bytes
        // are 54 ZIP-317 actions, so the 6.20.0 conventional fee, 27,000, is paid (04/N-1).
        assert_eq!(b.fee, 27_000);
        assert_eq!(b.fee, tx.zip317_conventional_fee(&[7_938]).unwrap());
        assert!(b.raw.len() > 8_000);
        assert!(b.recipient_address.starts_with("sm"));
        // In flight, released by another party (no txid), or another wallet's owner: no move.
        let mut moving = r.clone();
        moving.pq_spend_txid = [1; 32];
        assert!(pq_coin(&moving).is_none() && not_releasable(&moving, 500).is_some());
        let mut by_other = r.clone();
        by_other.spend_txid = [0; 32];
        assert!(pq_coin(&by_other).is_none());
        let mut foreign = r.clone();
        foreign.recipient_script = crate::pq::pqpkh_script(&crate::pq::PqKeyId {
            scheme: 1,
            hash: [9; 32],
        })
        .unwrap();
        assert!(build_release(&w, &foreign, 500, 0x6d5b_7a31)
            .unwrap_err()
            .to_string()
            .starts_with("intent-not-ours"));
        // A coin too small for the fee is refused.
        let mut tiny = r.clone();
        tiny.value = FEE_ZAT + MIN_CHANGE - 1;
        assert!(build_release(&w, &tiny, 500, 0x6d5b_7a31)
            .unwrap_err()
            .to_string()
            .starts_with("pq-coin-too-small"));
        // The gate takes the named coin only, alone.
        assert!(gate::check(
            gate::Path::PqSweep(OutPoint {
                txid: [0xab; 32],
                n: 0
            }),
            &b.raw,
            |_| None
        )
        .is_ok());
        assert!(gate::check(
            gate::Path::PqSweep(OutPoint {
                txid: [0xac; 32],
                n: 0
            }),
            &b.raw,
            |_| None
        )
        .is_err());
    }

    /// The sync's `PQ_OWNED` rows (lightwalletd-dd q/pqaddr): plain YEC at a Falcon holder's
    /// `sq…` form or at a vault owner's key, moved one coin at a time through `release_preview`;
    /// a HELD (token-marked) or locked coin, or one no own key signs, is never moved.
    #[test]
    fn own_pq_coins_move_into_the_wallet() {
        use crate::coins::{Utxo, UtxoClass};
        const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let seed = crate::keys::seed_from_mnemonic(PHRASE, "").unwrap();
        let mut w = Wallet::from_parts(
            crate::store::Store::open_in_memory().unwrap(),
            crate::params::Network::Regtest,
            &seed,
            None,
        )
        .unwrap();
        let first = w.addresses().unwrap()[0].clone();
        let falcon = w.falcon_holder_id(&first).unwrap();
        let owner = w.pq_owner_id(0);
        let stranger = crate::pq::PqKeyId {
            scheme: 2,
            hash: [9; 32],
        };
        let op = |n| OutPoint {
            txid: [0xc0; 32],
            n,
        };
        let pq_row = |n, id: &crate::pq::PqKeyId, value, class| Utxo {
            outpoint: op(n),
            address: crate::keys::encode_pq_yec(w.network, id).unwrap(),
            script: crate::pq::pqpkh_script(id).unwrap(),
            value,
            height: 300 + n as u64,
            class,
            cents: 0,
        };
        w.store
            .replace_utxos(&[
                pq_row(0, &falcon, 150_000_000, UtxoClass::PqOwned),
                pq_row(1, &owner, 4_000_000, UtxoClass::PqOwned),
                pq_row(2, &falcon, 77_777, UtxoClass::Held),
                pq_row(3, &stranger, 9_000_000, UtxoClass::PqOwned),
            ])
            .unwrap();
        let b = w.balances().unwrap();
        assert_eq!(b.yec_pq_zat, 163_000_000);
        assert_eq!((b.yec_zat, b.yec_reserved_zat), (0, 0));
        assert_eq!(b.pq_coins, vec![op(0), op(1), op(3)]);

        // The Falcon holder's coin: one 1,577-byte Falcon scriptSig, the fee out of the coin.
        let f = w.release_preview(&op(0), 500, 0x6d5b_7a31).unwrap();
        assert_eq!((f.kind, f.intent), (ReleaseKind::PqSweep, op(0)));
        let (tx, _) = Transaction::parse(&f.raw).unwrap();
        assert_eq!(tx.vin.len(), 1);
        assert_eq!(tx.vin[0].prevout, op(0));
        assert_eq!(tx.vin[0].script_sig.len(), 1_577);
        assert_eq!(tx.vout.len(), 1);
        assert_eq!(f.value + f.fee, 150_000_000);
        // audit 04/N-1: a Falcon input is 1,620 vin bytes, 11 ZIP-317 actions, so the
        // conventional 5,500 zat is the fee (above the 1,000 flat and the relay-rate size fee).
        assert_eq!(tx.zip317_conventional_fee(&[1_577]).unwrap(), 5_500);
        assert!(w.pq_terms().fee(f.raw.len()) < 5_500);
        assert_eq!(f.fee, 5_500);
        let to = script::p2pkh_hash(&tx.vout[0].script_pubkey).unwrap();
        assert!(w.own_hashes().unwrap().contains(&to));
        assert!(gate::check(gate::Path::PqSweep(op(0)), &f.raw, |_| None).is_ok());
        // The vault owner's coin: one 7,938-byte SLH-DSA scriptSig.
        let o = w.release_preview(&op(1), 500, 0x6d5b_7a31).unwrap();
        let (tx, _) = Transaction::parse(&o.raw).unwrap();
        assert_eq!(tx.vin[0].script_sig.len(), 7_938);
        assert_eq!(o.value + o.fee, 4_000_000);
        // A token-marked (HELD) coin is not post-quantum YEC; a stranger's key signs nothing here.
        let held = build_pq_coin_move(&w, &op(2), 500, 0x6d5b_7a31).unwrap_err();
        assert!(held.to_string().starts_with("pq-coin-class"), "{held}");
        assert!(w
            .release_preview(&op(2), 500, 0x6d5b_7a31)
            .unwrap_err()
            .to_string()
            .starts_with("intent-unknown"));
        let foreign = build_pq_coin_move(&w, &op(3), 500, 0x6d5b_7a31).unwrap_err();
        assert!(
            foreign.to_string().starts_with("pq-coin-not-ours"),
            "{foreign}"
        );
        // A coin being moved (locked) is not offered again.
        w.store.lock(&op(0), "spent-by:x", 524).unwrap();
        assert!(build_pq_coin_move(&w, &op(0), 500, 0x6d5b_7a31)
            .unwrap_err()
            .to_string()
            .starts_with("pq-coin-unknown"));
        assert_eq!(w.balances().unwrap().pq_coins, vec![op(1), op(3)]);
    }
}
