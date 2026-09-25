//! Sync (plan §3.2): gap-limit address derivation, `GetTaddressTxids` per address for history
//! (the yodl baseline streams the raw transactions with heights), `GetAddressUtxos` for the
//! confirmed UTXO set, **`GetAddressTokens` for the YED token set** (the only source of the
//! TOKEN class, D-W-8), classification (`coins`), the `PreLock` pending rule for the wallet's
//! own unconfirmed transactions, the fee reserve, lock release, `GetTxInfo` labels for every
//! own transaction that carries a `"YB"` payload or spends an own token, and `GetPrice.pMint`.
//!
//! Translation source (plan §3.6): `yecwallet-dd/src/yellowbackmodels.cpp:202-216`
//! (`typeLabel`), `:743-810` (`YellowbackTxModel::data`: the self-transfer, expired and burn
//! rules) for the verdict-to-label mapping; `ycash-dd/src/yellowback/wallet.cpp:410-427`
//! (`PreLock`). The verdict is the server's, the label is derived from it, never from the
//! payload alone (contract rule 3); the payload is read locally only for the *pending* label of
//! a transaction this wallet itself broadcast.
//!
//! Locks are released **only** here: when the spending transaction is seen confirmed, or when
//! its `nExpiryHeight` has passed (plan §3.7 "Locks").
//!
//! **W4.** Each sync also advances every in-flight two-step row (`mints`, plan §5.3): the
//! carrier seen confirmed ⇒ `CarrierConfirmed`; the main transaction seen confirmed ⇒ `Done`;
//! the window (`refHeight + REF_WINDOW`) closed without it ⇒ `Lapsed` (the sweep is the
//! wallet's explicit `mint_sweep`; `yew-cli sync` runs it for every lapsed row); the sweep
//! seen confirmed ⇒ `Swept`. It refreshes every own vault from `GetVault` (the mint rows'
//! and every history row the server labelled `mint`, so a restore from seed finds them) and
//! synthesises the `VAULT` (open own vaults) and `CARRIER` (rows holding a carrier) UTXO rows,
//! which `GetAddressUtxos` never lists: they are P2SH, not an own address.

use std::collections::{HashMap, HashSet};

use crate::build::mint::window_open;
use crate::bundle;
use crate::coins::{self, Utxo, UtxoClass};
use crate::keys;
use crate::net::rpc::YedTxInfo;
use crate::net::{CompactClient, NetError, YellowbackClient};
use crate::params::{CARRIER_VALUE, GAP_LIMIT};
use crate::script;
use crate::store::{HistoryRow, MintState, VaultRow};
use crate::tx::{txid_from_hex, txid_hex, OutPoint, Transaction};
use crate::wallet::{dollars, Wallet, WalletError};

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
    /// UTXOs after classification (pending tokens included).
    pub utxos: usize,
    /// Locks released.
    pub locks_released: usize,
    /// `(available, reserved)` YEC in zat.
    pub yec: (i64, i64),
    /// `(cents, pending cents)` YED.
    pub yed: (u64, u64),
    /// Tokens `GetAddressTokens` listed.
    pub tokens: usize,
    /// History rows labelled from `GetTxInfo` this run.
    pub labelled: usize,
    /// A Yellowback client was given (the YED steps ran).
    pub yellowback: bool,
    /// `GetPrice.pMint` at the tip, when defined.
    pub price_micro_usd: Option<i64>,
    /// Two-step rows advanced this run, as `(id, new state)`.
    pub mints_advanced: Vec<(i64, MintState)>,
    /// Own vaults refreshed from `GetVault`.
    pub vaults: usize,
}

/// Run one sync of `wallet` against `client`, and against `yellowback` for the YED steps when
/// the server offers the service (`None` = contract rule 1 said absent: every own
/// `TOKEN_VALUE` output stays `HELD`, no labels, no price).
pub async fn sync(
    wallet: &mut Wallet,
    client: &mut CompactClient,
    mut yellowback: Option<&mut YellowbackClient>,
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
        yellowback: yellowback.is_some(),
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

    // 4a. The token set (D-W-8): the only source of class TOKEN.
    let own = wallet.own_hashes()?;
    let addresses: Vec<String> = wallet
        .addresses()?
        .into_iter()
        .map(|a| a.address_s)
        .collect();
    let mut tokens: HashMap<OutPoint, u64> = HashMap::new();
    if let Some(yb) = yellowback.as_mut() {
        for t in yb.address_tokens(&addresses, 0).await? {
            wallet.store.insert_own_token(&t.outpoint, t.cents)?;
            tokens.insert(t.outpoint, t.cents);
        }
        report.tokens = tokens.len();
    }

    // 2. The confirmed UTXO set, classified, then the fee reserve.
    let mut utxos: Vec<Utxo> = client
        .address_utxos(&addresses, birthday)
        .await?
        .into_iter()
        .map(|u| {
            let outpoint = OutPoint {
                txid: u.txid,
                n: u.index,
            };
            let (class, cents) = coins::classify(
                &outpoint,
                &u.script,
                u.value_zat,
                |h| own.contains(h),
                &tokens,
            );
            Utxo {
                outpoint,
                address: u.address,
                script: u.script,
                value: u.value_zat,
                height: u.height,
                class,
                cents,
            }
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

    // Locks: a spending transaction seen confirmed released its inputs in record_transaction;
    // here the expired ones lapse (nExpiryHeight passed and the spend never confirmed).
    for (txid, _raw, expiry) in wallet.store.pending_txs()? {
        if expiry != 0 && tip > expiry {
            release_spent_by(wallet, &txid)?;
            wallet.store.remove_pending_tx(&txid)?;
            if let Some(row) = wallet.store.history_row(&txid)? {
                wallet.store.upsert_history(&HistoryRow {
                    pending: false,
                    height: 0,
                    yec_delta: 0,
                    yed_delta: 0,
                    verdict: "expired".into(),
                    label: "expired".into(),
                    labelled: true,
                    ..row
                })?;
            }
            report.locks_released += 1;
        }
    }

    // 4b. PENDING_TOKEN (`PreLock`): the outputs of the wallet's own still-unconfirmed
    // transactions that their payload marks as YED for own keys. In neither balance.
    let present: HashSet<OutPoint> = utxos.iter().map(|u| u.outpoint).collect();
    for (txid, raw, _expiry) in wallet.store.pending_txs()? {
        let (tx, _) = match Transaction::parse(&raw) {
            Ok(t) => t,
            Err(_) => continue,
        };
        for (n, cents) in coins::pre_lock(&tx, |h| own.contains(h)) {
            let outpoint = OutPoint { txid, n };
            if present.contains(&outpoint) {
                continue;
            }
            let script = tx.vout[n as usize].script_pubkey.clone();
            let address = script::p2pkh_hash(&script)
                .map(|h| keys::encode_p2pkh(wallet.network, &h))
                .unwrap_or_default();
            utxos.push(Utxo {
                outpoint,
                address,
                script,
                value: tx.vout[n as usize].value,
                height: 0,
                class: UtxoClass::PendingToken,
                cents,
            });
        }
    }
    // 4c. Labels from GetTxInfo, and the price.
    if let Some(yb) = yellowback.as_mut() {
        report.labelled = label_history(wallet, yb).await?;
        let p = yb.price(0).await?;
        report.price_micro_usd = if p.p_mint > 0 { Some(p.p_mint) } else { None };
        wallet.store.set_meta(
            "price_micro_usd",
            &report.price_micro_usd.unwrap_or(0).to_string(),
        )?;
    }

    // 5. W4: the two-step rows, the own vaults, and the VAULT / CARRIER rows.
    report.mints_advanced = advance_mints(wallet, tip)?;
    if let Some(yb) = yellowback.as_mut() {
        report.vaults = refresh_vaults(wallet, yb, tip).await?;
    }
    let present: HashSet<OutPoint> = utxos.iter().map(|u| u.outpoint).collect();
    for v in wallet.store.vaults()? {
        let op = OutPoint {
            txid: v.txid,
            n: v.vout,
        };
        if !v.is_open() || present.contains(&op) {
            continue;
        }
        let vs = script::vault_script(v.lock_height, &v.owner_pubkey, v.claim_height)
            .map_err(|e| WalletError::Other(e.to_string()))?;
        let hash = keys::hash160(&vs);
        utxos.push(Utxo {
            outpoint: op,
            address: keys::encode_p2sh(wallet.network, &hash),
            script: script::p2sh_script(&hash),
            value: v.collateral_zat,
            height: v.mint_height,
            class: UtxoClass::Vault,
            cents: 0,
        });
    }
    for m in wallet.store.mints()? {
        if !m.state.holds_carrier() {
            continue;
        }
        let op = OutPoint {
            txid: m.carrier_txid,
            n: m.carrier_vout,
        };
        if present.contains(&op) {
            continue;
        }
        let key = match wallet.key_for_hash(&m.carrier_hash160)? {
            Some(k) => k,
            None => continue,
        };
        let redeem = script::carrier_script(&key.pubkey, &bundle::bundle_hash(&m.bundle))
            .map_err(|e| WalletError::Other(e.to_string()))?;
        let hash = keys::hash160(&redeem);
        utxos.push(Utxo {
            outpoint: op,
            address: keys::encode_p2sh(wallet.network, &hash),
            script: script::p2sh_script(&hash),
            value: CARRIER_VALUE,
            height: m.created_height,
            class: UtxoClass::Carrier,
            cents: 0,
        });
    }

    wallet.store.replace_utxos(&utxos)?;
    report.utxos = utxos.len();
    report.yec = coins::yec_balances(&utxos);
    report.yed = coins::yed_balances(&utxos);

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

/// The height a transaction was seen confirmed at, if the history scan saw it.
fn confirmed_height(wallet: &Wallet, txid: &[u8; 32]) -> Result<Option<u64>, WalletError> {
    Ok(wallet
        .store
        .history_row(txid)?
        .filter(|r| !r.pending && r.height > 0)
        .map(|r| r.height))
}

/// Advance every in-flight two-step row (plan §5.3) from what the history scan saw at `tip`.
/// Returns `(id, new state)` for the rows that moved.
pub fn advance_mints(wallet: &Wallet, tip: u64) -> Result<Vec<(i64, MintState)>, WalletError> {
    let mut moved = Vec::new();
    for m in wallet.store.mints()? {
        if !m.state.in_flight() {
            continue;
        }
        let next: Option<(MintState, String)> = match m.state {
            MintState::CarrierSent => {
                if confirmed_height(wallet, &m.carrier_txid)?.is_some() {
                    Some((MintState::CarrierConfirmed, String::new()))
                } else if tip > m.expiry_height as u64 {
                    Some((
                        MintState::Failed,
                        format!("carrier {} expired unconfirmed", txid_hex(&m.carrier_txid)),
                    ))
                } else {
                    None
                }
            }
            MintState::CarrierConfirmed => {
                if window_open(tip, m.expiry_height) {
                    None
                } else {
                    Some((
                        MintState::Lapsed,
                        format!(
                            "window closed at {} without the main transaction",
                            m.expiry_height
                        ),
                    ))
                }
            }
            MintState::MainSent => {
                if let Some(h) = confirmed_height(wallet, &m.main_txid)? {
                    let verdict = wallet
                        .store
                        .history_row(&m.main_txid)?
                        .map(|r| r.verdict)
                        .unwrap_or_default();
                    Some((
                        MintState::Done,
                        format!(
                            "confirmed at {h}{}",
                            if verdict.is_empty() {
                                String::new()
                            } else {
                                format!(", verdict {verdict}")
                            }
                        ),
                    ))
                } else if tip > m.expiry_height as u64 {
                    Some((
                        MintState::Lapsed,
                        format!(
                            "main transaction {} expired unconfirmed",
                            txid_hex(&m.main_txid)
                        ),
                    ))
                } else {
                    None
                }
            }
            MintState::SweepSent => {
                if confirmed_height(wallet, &m.sweep_txid)?.is_some() {
                    Some((MintState::Swept, String::new()))
                } else if wallet
                    .store
                    .pending_txs()?
                    .iter()
                    .all(|(t, _, _)| *t != m.sweep_txid)
                {
                    // The sweep expired (its pending record lapsed): the carrier is back.
                    Some((MintState::Lapsed, "sweep expired unconfirmed".into()))
                } else {
                    None
                }
            }
            MintState::Lapsed | MintState::Done | MintState::Swept | MintState::Failed => None,
        };
        if let Some((state, note)) = next {
            let note = if note.is_empty() {
                m.note.clone()
            } else {
                note
            };
            wallet
                .store
                .set_mint_state(m.id, state, None, None, &note)?;
            moved.push((m.id, state));
        }
    }
    Ok(moved)
}

/// Refresh the own vaults from `GetVault`: every mint row's main transaction and every
/// history row labelled `mint`, kept when the owner key is ours. Returns the rows written.
pub async fn refresh_vaults(
    wallet: &Wallet,
    yb: &mut YellowbackClient,
    tip: u64,
) -> Result<usize, WalletError> {
    let own = wallet.own_hashes()?;
    let mut candidates: HashSet<[u8; 32]> = HashSet::new();
    for m in wallet.store.mints()? {
        if m.kind == crate::store::MintKind::Mint
            && matches!(m.state, MintState::Done | MintState::MainSent)
            && m.main_txid != [0; 32]
        {
            candidates.insert(m.main_txid);
        }
    }
    for h in wallet.store.history()? {
        if h.kind == "mint" && !h.pending {
            candidates.insert(h.txid);
        }
    }
    for v in wallet.store.vaults()? {
        if v.is_open() {
            candidates.insert(v.txid);
        }
    }
    let mut n = 0;
    for txid in candidates {
        let v = match yb.vault(&txid_hex(&txid)).await {
            Ok(v) => v,
            Err(NetError::Node { identifier, .. }) if identifier == "vault-not-found" => continue,
            Err(e) => return Err(e.into()),
        };
        let pk: [u8; 33] = match keys::unhex(&v.owner_pub_key)
            .ok()
            .and_then(|b| b.as_slice().try_into().ok())
        {
            Some(p) => p,
            None => continue,
        };
        let owner_hash160 = keys::hash160(&pk);
        if !own.contains(&owner_hash160) {
            continue;
        }
        let vault_txid = txid_from_hex(&v.txid).unwrap_or(txid);
        wallet.store.upsert_vault(&VaultRow {
            txid: vault_txid,
            vout: v.vout,
            status: v.status,
            owner_hash160,
            owner_pubkey: pk,
            term_class: v.term_class,
            lock_height: v.lock_height as u32,
            claim_height: v.claim_height as u32,
            collateral_zat: v.collateral_zat,
            minted_cents: v.minted_cents.max(0) as u64,
            mint_height: v.mint_height.max(0) as u64,
            claimable: v.claimable,
            underwater_at: v.underwater_at,
            sweep_before: v.sweep_before.max(0) as u64,
            close_height: v.close_height.max(0) as u64,
            closing_txid: v.closing_txid,
            void_reason: v.void_reason,
            updated_height: tip,
        })?;
        n += 1;
    }
    Ok(n)
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
        if let Some(cents) = wallet.store.own_token_cents(&i.prevout)? {
            wallet.store.insert_spent_token(txid, &i.prevout, cents)?;
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
    let prior = wallet.store.history_row(txid)?;
    let mut row = HistoryRow {
        txid: *txid,
        height: if confirmed { height } else { 0 },
        yec_delta: delta,
        has_payload,
        pending: !confirmed,
        shielded: tx.shielded.any(),
        yed_delta: 0,
        kind: String::new(),
        verdict: String::new(),
        label: String::new(),
        labelled: false,
    };
    if let Some(p) = prior {
        // A row this wallet broadcast keeps its pending label until GetTxInfo labels it; once
        // confirmed, the local label is dropped so nothing "pending" survives confirmation.
        if confirmed && p.pending && (p.kind == "carrier" || p.kind == "sweep") {
            // The wallet's own carrier and sweep rows carry no payload: nothing to relabel.
            row.kind = p.kind;
            row.label = p.label;
            row.labelled = true;
        } else if confirmed && p.pending {
            row.labelled = false;
        } else {
            row.yed_delta = p.yed_delta;
            row.kind = p.kind;
            row.verdict = p.verdict;
            row.label = p.label;
            row.labelled = p.labelled;
        }
    }
    wallet.store.upsert_history(&row)?;
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

/// Label every confirmed, unlabelled history row that carries a payload or spends a token the
/// wallet ever held, from `GetTxInfo` (contract rule 3). A `tx-not-found` (an `OP_RETURN`
/// that is not a Yellowback payload) marks the row labelled with an empty label. Returns the
/// number of rows labelled.
pub async fn label_history(
    wallet: &Wallet,
    yb: &mut YellowbackClient,
) -> Result<usize, WalletError> {
    let mut n = 0;
    for row in wallet.store.history()? {
        if row.labelled || row.pending {
            continue;
        }
        let spends_token = spent_own_token_cents(wallet, &row.txid)?.is_some();
        if !row.has_payload && !spends_token {
            continue;
        }
        let txid = txid_hex(&row.txid);
        match yb.tx_info(&txid).await {
            Ok(info) => {
                let own_out = own_assigned_cents(wallet, &row.txid, &info)?;
                let own_in = spent_own_token_cents(wallet, &row.txid)?.unwrap_or(0);
                let (label, yed_delta) = label_for(&info, own_in, own_out);
                wallet.store.set_history_label(
                    &row.txid,
                    yed_delta,
                    &info.r#type,
                    &info.verdict,
                    &label,
                    true,
                )?;
                n += 1;
            }
            Err(NetError::Node { identifier, .. }) if identifier == "tx-not-found" => {
                wallet
                    .store
                    .set_history_label(&row.txid, 0, "", "", "", true)?;
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(n)
}

/// The cents `info.assigned` gives to outputs of `txid` paid to own keys.
fn own_assigned_cents(
    wallet: &Wallet,
    txid: &[u8; 32],
    info: &YedTxInfo,
) -> Result<u64, WalletError> {
    let own_vouts: HashSet<u32> = wallet
        .store
        .own_outputs_of(txid)?
        .into_iter()
        .map(|(n, _, _)| n)
        .collect();
    Ok(info
        .assigned
        .iter()
        .filter(|a| own_vouts.contains(&a.vout))
        .map(|a| a.cents)
        .sum())
}

/// The cents of tokens the wallet ever held that `txid` spent, or `None` when it spent none
/// (`spent_tokens`, written by `record_transaction` and by the transfer builder's broadcast;
/// IN-1 erases spent tokens server-side, so the wallet keeps its own record). A token
/// created and spent between two syncs was never listed and is not counted — the row then
/// reads as "received" for its own change; the verdict and cents are still the server's.
fn spent_own_token_cents(wallet: &Wallet, txid: &[u8; 32]) -> Result<Option<u64>, WalletError> {
    let spent = wallet.store.spent_tokens_by(txid)?;
    if spent.is_empty() {
        return Ok(None);
    }
    Ok(Some(spent.iter().map(|(_, c)| *c).sum()))
}

/// The verdict-to-label mapping (translated from `yellowbackmodels.cpp`, W2). Returns the
/// label and the wallet's net YED change in cents.
pub fn label_for(info: &YedTxInfo, own_in: u64, own_out: u64) -> (String, i64) {
    let delta = own_out as i64 - own_in as i64;
    let burned = if info.burned > 0 {
        format!(", burned {}", dollars(info.burned))
    } else {
        String::new()
    };
    if info.expired || info.verdict == "expired" {
        return ("expired".into(), 0);
    }
    let ok = info.verdict == "ok";
    let label = match info.r#type.as_str() {
        "mint" => {
            if ok {
                format!("minted {}", dollars(own_out as i64))
            } else {
                format!("VOID mint ({})", info.verdict)
            }
        }
        "transfer" => {
            if !ok {
                format!("transfer refused ({}){burned}", info.verdict)
            } else if own_in > 0 && own_out > 0 && delta == 0 {
                format!("self-transfer{burned}")
            } else if delta < 0 {
                format!("sent {}{burned}", dollars(-delta))
            } else {
                format!("received {}{burned}", dollars(delta))
            }
        }
        "redeem" if info.path == "claim" => {
            if ok {
                format!("claimed vault{burned}")
            } else {
                format!("claim ({}){burned}", info.verdict)
            }
        }
        "redeem" => {
            if ok {
                format!("redeemed{burned}")
            } else {
                format!("redeem ({}){burned}", info.verdict)
            }
        }
        "" if info.burned > 0 => format!("burned {}", dollars(info.burned)),
        other => {
            if ok {
                format!("{other}{burned}")
            } else {
                format!("{other} ({}){burned}", info.verdict)
            }
        }
    };
    (label, delta)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(t: &str, verdict: &str, burned: i64) -> YedTxInfo {
        YedTxInfo {
            r#type: t.into(),
            verdict: verdict.into(),
            burned,
            ..Default::default()
        }
    }

    #[test]
    fn labels_follow_the_verdict() {
        assert_eq!(
            label_for(&info("mint", "ok", 0), 0, 10_000),
            ("minted $100.00".into(), 10_000)
        );
        assert_eq!(
            label_for(&info("mint", "mintpol-no-price", 0), 0, 0),
            ("VOID mint (mintpol-no-price)".into(), 0)
        );
        assert_eq!(
            label_for(&info("transfer", "ok", 0), 500, 250),
            ("sent $2.50".into(), -250)
        );
        assert_eq!(
            label_for(&info("transfer", "ok", 0), 0, 250),
            ("received $2.50".into(), 250)
        );
        assert_eq!(
            label_for(&info("transfer", "ok", 0), 500, 500),
            ("self-transfer".into(), 0)
        );
        assert_eq!(
            label_for(&info("transfer", "xfer-conservation", 500), 500, 0),
            (
                "transfer refused (xfer-conservation), burned $5.00".into(),
                -500
            )
        );
        assert_eq!(
            label_for(&info("redeem", "ok", 10_000), 10_000, 0),
            ("redeemed, burned $100.00".into(), -10_000)
        );
        assert_eq!(
            label_for(&info("", "ok", 700), 700, 0),
            ("burned $7.00".into(), -700)
        );
        assert_eq!(
            label_for(&info("notice", "ok", 0), 0, 0),
            ("notice".into(), 0)
        );
        let mut e = info("transfer", "expired", 0);
        e.expired = true;
        assert_eq!(label_for(&e, 500, 0), ("expired".into(), 0));
    }

    #[test]
    fn advance_mints_follows_the_history() {
        use crate::keys;
        use crate::params::Network;
        use crate::store::{MintKind, MintRow, Store};
        let seed = keys::seed_from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "",
        )
        .unwrap();
        let w = Wallet::from_parts(
            Store::open_in_memory().unwrap(),
            Network::Regtest,
            &seed,
            None,
        )
        .unwrap();
        let row = MintRow {
            id: 0,
            kind: MintKind::Mint,
            state: MintState::CarrierSent,
            created_height: 480,
            cents: 10_000,
            lock_blocks: 48,
            term_class: "A".into(),
            ref_height: 478,
            lock_height: 526,
            claim_height: 550,
            collateral_zat: 1_000_000_000,
            fee_zat: 0,
            payee: String::new(),
            attest_fee_zat: 0,
            attest_payee: String::new(),
            residual_zat: 0,
            bundle: vec![],
            bundle_seqs: String::new(),
            carrier_hash160: [1; 20],
            owner_hash160: [2; 20],
            carrier_txid: [3; 32],
            carrier_vout: 0,
            main_txid: [0; 32],
            sweep_txid: [0; 32],
            expiry_height: 518,
            vault_txid: [0; 32],
            owner_pubkey: vec![],
            note: String::new(),
        };
        let id = w.store.insert_mint(&row).unwrap();
        let seen = |txid: [u8; 32], height: u64| HistoryRow {
            txid,
            height,
            yec_delta: 0,
            has_payload: false,
            pending: false,
            shielded: false,
            yed_delta: 0,
            kind: String::new(),
            verdict: String::new(),
            label: String::new(),
            labelled: true,
        };
        // Nothing seen yet: still CarrierSent.
        assert!(advance_mints(&w, 481).unwrap().is_empty());
        w.store.upsert_history(&seen([3; 32], 481)).unwrap();
        assert_eq!(
            advance_mints(&w, 481).unwrap(),
            vec![(id, MintState::CarrierConfirmed)]
        );
        // The window closes at 518: tip 514 is the last open tip (514 + 4 <= 518).
        assert!(advance_mints(&w, 514).unwrap().is_empty());
        assert_eq!(
            advance_mints(&w, 515).unwrap(),
            vec![(id, MintState::Lapsed)]
        );
        // A second row that finishes: MainSent → Done with the verdict.
        let id2 = w
            .store
            .insert_mint(&MintRow {
                carrier_txid: [4; 32],
                ..row.clone()
            })
            .unwrap();
        w.store.upsert_history(&seen([4; 32], 482)).unwrap();
        assert_eq!(
            advance_mints(&w, 482).unwrap(),
            vec![(id2, MintState::CarrierConfirmed)]
        );
        w.store
            .set_mint_state(id2, MintState::MainSent, Some(&[5; 32]), None, "")
            .unwrap();
        assert!(advance_mints(&w, 483).unwrap().is_empty());
        w.store
            .upsert_history(&HistoryRow {
                verdict: "ok".into(),
                ..seen([5; 32], 484)
            })
            .unwrap();
        assert_eq!(
            advance_mints(&w, 484).unwrap(),
            vec![(id2, MintState::Done)]
        );
        assert!(w
            .store
            .mint(id2)
            .unwrap()
            .unwrap()
            .note
            .contains("verdict ok"));
        // A third whose carrier never confirms: Failed once the expiry passed.
        let id3 = w
            .store
            .insert_mint(&MintRow {
                carrier_txid: [6; 32],
                ..row
            })
            .unwrap();
        assert!(advance_mints(&w, 518).unwrap().is_empty());
        assert_eq!(
            advance_mints(&w, 519).unwrap(),
            vec![(id3, MintState::Failed)]
        );
        assert!(w.store.mint(id).unwrap().unwrap().state.in_flight());
        let mut c = info("redeem", "ok", 10_000);
        c.path = "claim".into();
        assert_eq!(
            label_for(&c, 10_000, 0),
            ("claimed vault, burned $100.00".into(), -10_000)
        );
    }
}
