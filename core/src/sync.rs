//! Sync (plan §3.2, YEC only in Phase W1): gap-limit address derivation, `GetTaddressTxids`
//! per address for history (the yodl baseline streams the raw transactions with heights),
//! `GetAddressUtxos` for the confirmed UTXO set, classification (`coins`), the fee reserve,
//! lock release. W2 adds `GetAddressTokens` and `GetTxInfo` labels.
//!
//! Translation source (plan §3.6): `yecwallet-dd/src/yellowbackmodels.cpp`,
//! `yellowbackcontroller.cpp` for labels and the `PreLock` pending rule (W2).
//!
//! Locks are released **only** here: when the spending transaction is seen confirmed, or when
//! its `nExpiryHeight` has passed (plan §3.7 "Locks").

use std::collections::HashSet;

use crate::coins::{self, Utxo};
use crate::net::CompactClient;
use crate::params::GAP_LIMIT;
use crate::script;
use crate::store::HistoryRow;
use crate::tx::{txid_hex, OutPoint, Transaction};
use crate::wallet::{Wallet, WalletError};

/// What one sync did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncReport {
    /// The tip the sync ran to.
    pub tip: u64,
    /// The `consensusBranchId` the server reports (stored for signing).
    pub branch_id: u32,
    /// Addresses scanned.
    pub addresses: usize,
    /// Transactions parsed into history this run.
    pub transactions: usize,
    /// UTXOs after classification.
    pub utxos: usize,
    /// Locks released.
    pub locks_released: usize,
    /// `(available, reserved)` YEC in zat.
    pub yec: (i64, i64),
}

/// Run one sync of `wallet` against `client`.
pub async fn sync(
    wallet: &mut Wallet,
    client: &mut CompactClient,
) -> Result<SyncReport, WalletError> {
    let info = client.lightd_info_for(wallet.network).await?;
    let tip = client.latest_height().await?.max(info.block_height);
    wallet
        .store
        .set_meta("branch_id", &format!("{:08x}", info.branch_id))?;
    let birthday = wallet.birthday()?;
    let scanned = wallet.store.meta_u64("scanned_height")?;
    let mut report = SyncReport {
        tip,
        branch_id: info.branch_id,
        ..Default::default()
    };

    // 1-3. Addresses and history, extending the gap until no address in the last GAP_LIMIT
    // of either chain turns out used.
    let mut pending: Vec<(String, u64)> = wallet
        .addresses()?
        .into_iter()
        .map(|a| {
            (
                a.address_s,
                if scanned == 0 { birthday } else { scanned + 1 },
            )
        })
        .collect();
    let mut seen_txids: HashSet<[u8; 32]> = HashSet::new();
    while !pending.is_empty() {
        let own = wallet.own_hashes()?;
        let mut any_new_use = false;
        for (address, from) in pending.drain(..) {
            report.addresses += 1;
            // lightwalletd refuses a range starting at 0 ("Start and end are expected to be
            // greater than zero"); a birthday of 0 means "from the first block".
            let from = from.max(1);
            if from > tip {
                continue;
            }
            for raw in client.taddress_txs(&address, from, tip).await? {
                let (tx, txid) = Transaction::parse(&raw.data)?;
                if !seen_txids.insert(txid) {
                    continue;
                }
                any_new_use |= record_transaction(wallet, &tx, &txid, raw.height, &own)?;
                report.transactions += 1;
            }
        }
        if any_new_use {
            let created = wallet.ensure_gap()?;
            pending = created
                .into_iter()
                .map(|a| (a.address_s, birthday))
                .collect();
        }
    }
    let _ = GAP_LIMIT; // the gap rule lives in Wallet::ensure_gap

    // 2. The confirmed UTXO set, classified for the YEC-only phase, then the fee reserve.
    let own = wallet.own_hashes()?;
    let addresses: Vec<String> = wallet
        .addresses()?
        .into_iter()
        .map(|a| a.address_s)
        .collect();
    let mut utxos: Vec<Utxo> = client
        .address_utxos(&addresses, birthday)
        .await?
        .into_iter()
        .map(|u| Utxo {
            class: coins::classify_yec_phase(&u.script, u.value_zat, |h| own.contains(h)),
            outpoint: OutPoint {
                txid: u.txid,
                n: u.index,
            },
            address: u.address,
            script: u.script,
            value: u.value_zat,
            height: u.height,
        })
        .collect();
    coins::apply_fee_reserve(&mut utxos);
    for u in &utxos {
        if let Some(h) = script::p2pkh_hash(&u.script) {
            if own.contains(&h) {
                wallet.store.insert_own_output(&u.outpoint, u.value, &h)?;
                wallet.store.mark_used(&h)?;
            }
        }
    }
    wallet.store.replace_utxos(&utxos)?;
    report.utxos = utxos.len();
    report.yec = coins::yec_balances(&utxos);

    // Locks: a spending transaction seen confirmed released its inputs in record_transaction;
    // here the expired ones lapse (nExpiryHeight passed and the spend never confirmed).
    for (txid, _raw, expiry) in wallet.store.pending_txs()? {
        if expiry != 0 && tip > expiry {
            release_spent_by(wallet, &txid)?;
            wallet.store.remove_pending_tx(&txid)?;
            if let Some(mut row) = wallet.store.history()?.into_iter().find(|h| h.txid == txid) {
                row.pending = false;
                row.height = 0;
                row.yec_delta = 0;
                wallet.store.upsert_history(&row)?;
            }
            report.locks_released += 1;
        }
    }
    let present: HashSet<OutPoint> = utxos.iter().map(|u| u.outpoint).collect();
    for l in wallet.store.locks()? {
        if !present.contains(&l.outpoint) && l.reason.starts_with("spent-by:") {
            // The output is gone from the confirmed set: the spend confirmed (or a reorg took
            // the output); either way the lock has nothing left to protect.
            wallet.store.unlock(&l.outpoint)?;
            report.locks_released += 1;
        }
    }

    wallet.store.set_meta("scanned_height", &tip.to_string())?;
    wallet
        .store
        .set_meta("last_synced_height", &tip.to_string())?;
    Ok(report)
}

/// Record one transaction touching an own address: history row, own outputs, used marks,
/// pending-transaction confirmation. Returns whether an address was newly marked used.
fn record_transaction(
    wallet: &Wallet,
    tx: &Transaction,
    txid: &[u8; 32],
    height: u64,
    own: &HashSet<[u8; 20]>,
) -> Result<bool, WalletError> {
    let mut newly_used = false;
    let mut delta = 0i64;
    let mut has_payload = false;
    for (n, o) in tx.vout.iter().enumerate() {
        if script::is_op_return(&o.script_pubkey) {
            has_payload = true;
        }
        if let Some(h) = script::p2pkh_hash(&o.script_pubkey) {
            if own.contains(&h) {
                delta += o.value;
                let op = OutPoint {
                    txid: *txid,
                    n: n as u32,
                };
                wallet.store.insert_own_output(&op, o.value, &h)?;
                newly_used |= wallet.store.mark_used(&h)?;
            }
        }
    }
    for i in &tx.vin {
        if let Some(v) = wallet.store.own_output_value(&i.prevout)? {
            delta -= v;
        }
        // A P2PKH scriptSig's second push is the pubkey: an own key spending marks it used.
        if let Some(p) = script::pushes(&i.script_sig) {
            if p.len() == 2 && p[1].len() == 33 {
                let h = crate::keys::hash160(&p[1]);
                if own.contains(&h) {
                    newly_used |= wallet.store.mark_used(&h)?;
                }
            }
        }
    }
    let confirmed = height != 0 && height != u64::MAX;
    if confirmed
        && wallet
            .store
            .pending_txs()?
            .iter()
            .any(|(t, _, _)| t == txid)
    {
        release_spent_by(wallet, txid)?;
        wallet.store.remove_pending_tx(txid)?;
    }
    wallet.store.upsert_history(&HistoryRow {
        txid: *txid,
        height: if confirmed { height } else { 0 },
        yec_delta: delta,
        has_payload,
        pending: !confirmed,
        shielded: tx.shielded.any(),
    })?;
    Ok(newly_used)
}

fn release_spent_by(wallet: &Wallet, txid: &[u8; 32]) -> Result<(), WalletError> {
    let reason = format!("spent-by:{}", txid_hex(txid));
    for l in wallet.store.locks()? {
        if l.reason == reason {
            wallet.store.unlock(&l.outpoint)?;
        }
    }
    Ok(())
}
