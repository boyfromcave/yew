// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! Sync (plan §3.2): gap-limit address derivation, `GetTaddressTxids` per address for history
//! (the yodl baseline streams the raw transactions with heights), `GetAddressUtxos` for the
//! confirmed UTXO set — both also on the `sq…`/`tq…`/`rq…` form of every own post-quantum key
//! (Falcon holders, vault owners; lightwalletd-dd q/pqaddr), whose YEC is `PQ_OWNED` —,
//! **`GetAddressTokens` for the YED token set** (the only source of the TOKEN class, D-W-8), classification (`coins`), the `PreLock` pending rule for the wallet's
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
use crate::build::terms;
use crate::bundle;
use crate::coins::{self, Utxo, UtxoClass};
use crate::keys;
use crate::net::rpc::YedTxInfo;
use crate::net::{CompactClient, NetError, YellowbackClient};
use crate::params::{self, CARRIER_VALUE, GAP_LIMIT, TOKEN_VALUE};
use crate::script;
use crate::store::{HistoryRow, IntentRow, IntentState, MintState, VaultCancel, VaultRow};
use crate::tx::{txid_from_hex, txid_hex, OutPoint, Transaction};
use crate::wallet::{dollars, Wallet, WalletError};

/// Blocks of history read again on every sync, so a reorg that drops or moves a transaction
/// inside them corrects its row (the private side's light library rewinds the same ten).
pub const REORG_WINDOW: u64 = 10;

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
    /// Claim intents paying this wallet whose state moved this run (the vault upgrade).
    pub intents: usize,
    /// Own post-quantum plain-YEC addresses (`sq…`/`tq…`/`rq…`) asked about this run.
    pub pq_addresses: usize,
    /// The server refused a post-quantum address in the taddr methods (`INVALID_ARGUMENT`: a
    /// lightwalletd before q/pqaddr): its `TX_PQPKH` outputs were not looked up this run.
    pub pq_unindexed: bool,
    /// The server's Yellowback service was refused for this run, and why: on mainnet and testnet
    /// its Falcon activation is not this build's (`terms::check_falcon_activation`). The YED steps
    /// did not run (`yellowback` is false) and the wallet kept its own terms.
    pub yellowback_refused: Option<String>,
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
    // The branch id every transparent signature commits to is the NEXT block's (ZIP-243): the
    // Vault id from the vault upgrade's activation height on (upgrade plan §8, §15.1).
    // `GetLightdInfo` carries the chaintip's; `GetChainInfo` the next block's and the upgrade
    // heights, which the height rule must agree with (`params::signing_branch_id`).
    let mut branch_id = info.branch_id;
    let mut next_height = tip + 1;
    let mut activation = None;
    let mut next_server = None;
    if let Some(yb) = yellowback.as_mut() {
        if let Some(ci) = yb.chain_info_full().await? {
            next_height = ci.block_height + 1;
            next_server = Some(
                u32::from_str_radix(ci.next_block_branch_id.trim_start_matches("0x"), 16).map_err(
                    |_| {
                        NetError::Mismatch(format!(
                            "bad nextBlockBranchId {:?}",
                            ci.next_block_branch_id
                        ))
                    },
                )?,
            );
            if u32::from_str_radix(ci.consensus_branch_id.trim_start_matches("0x"), 16)
                .is_ok_and(|b| b == params::VAULT_BRANCH_ID)
            {
                branch_id = params::VAULT_BRANCH_ID;
            }
            activation = crate::net::yellowback::vault_activation(&ci);
        }
    }
    let branch_id = params::signing_branch_id(
        wallet.network,
        branch_id,
        next_height,
        activation,
        next_server,
    )
    .map_err(|e| WalletError::Other(e.to_string()))?;
    wallet
        .store
        .set_meta("branch_id", &format!("{:08x}", branch_id))?;
    wallet.set_vault_activation(activation)?;
    let birthday = wallet.birthday()?;
    let scanned = wallet.store.meta_u64("scanned_height")?;
    let mut report = SyncReport {
        tip,
        branch_id,
        yellowback: yellowback.is_some(),
        ..Default::default()
    };

    // rpcversion 7: the post-quantum terms (fee rate, Falcon activation) for this sync and the
    // builders after it. A bad `params.pq` is not fatal here (the builders re-read and refuse),
    // except a Falcon activation that is not this build's (mainnet, testnet): then the server's
    // YED is not believed at all — the YED steps are skipped, as for a server without the
    // service, and the report says why (the wallet keeps its compiled terms).
    if let Some(yb) = yellowback.as_mut() {
        if let Ok(info) = yb.info().await {
            let refused = info
                .params
                .as_ref()
                .and_then(|p| p.pq.as_ref())
                .and_then(|pq| {
                    crate::build::terms::check_falcon_activation(wallet.network, pq).err()
                });
            match refused {
                Some(e) => {
                    report.yellowback = false;
                    report.yellowback_refused = Some(e.to_string());
                    yellowback = None;
                }
                None => {
                    let _ = wallet.note_server_params(info.params.as_ref());
                }
            }
        }
    }
    // TOK-PQ: once the server announces a Falcon height (mainnet and testnet: the vault
    // upgrade's first block), every HD key also has a Falcon YED holder; their tokens are found
    // through `GetAddressTokens` on the 53-character addresses (the only source of YED), their
    // plain YEC and history through the taddr methods on the `sq…` form (below).
    let falcon_on = yellowback.is_some() && {
        let t = wallet.pq_terms();
        t.falcon_active || t.falcon_height.is_some()
    };
    let mut falcon_tokens: HashMap<OutPoint, crate::net::Token> = HashMap::new();
    // The wallet's own post-quantum keys as plain-YEC addresses (D-Q-20; lightwalletd-dd
    // q/pqaddr serves `TX_PQPKH` in the taddr methods): the Falcon holders once TOK-PQ is
    // announced, and the vault owners whenever the server offers Yellowback (a claim residual
    // released by another party pays `PQPKH(owner)`). Payments to them are found here like any
    // own address's; YED at them only ever through `GetAddressTokens` (4a).
    let vaults_on = yellowback.is_some();
    let mut pq_indexed = true;

    // 1-3. Addresses and history, extending the gap until no address in the last GAP_LIMIT
    // of either chain turns out used. The last REORG_WINDOW blocks already scanned are read
    // again, so a reorg there corrects the history (yew-shielded plan S5).
    let window_from = if scanned == 0 {
        birthday
    } else {
        (scanned + 1).saturating_sub(REORG_WINDOW).max(birthday)
    };
    let mut pending: Vec<(String, u64)> = wallet
        .addresses()?
        .into_iter()
        .map(|a| (a.address_s, window_from))
        .collect();
    let mut seen_txids: HashSet<[u8; 32]> = HashSet::new();
    while !pending.is_empty() {
        let own = wallet.own_hashes()?;
        let own_falcon = if falcon_on {
            wallet.own_falcon_holders()?
        } else {
            HashMap::new()
        };
        let own_pq = own_pq_keys(wallet, &own_falcon, vaults_on)?;
        let mut any_new_use = false;
        if falcon_on {
            // The Falcon holders paired with this pass's addresses: a listed token marks the
            // pair used (the gap rule), and its transaction goes into history.
            let batch: HashSet<&str> = pending.iter().map(|(a, _)| a.as_str()).collect();
            let falcon_addrs: Vec<String> = own_falcon
                .iter()
                .filter(|(_, r)| batch.contains(r.address_s.as_str()))
                .filter_map(|(id, _)| keys::encode_pq_yellowback(wallet.network, id))
                .collect();
            if let Some(yb) = yellowback.as_mut() {
                for t in yb.address_tokens(&falcon_addrs, 0).await? {
                    let Ok(id) = keys::parse_pq_address(wallet.network, &t.address) else {
                        continue;
                    };
                    if let Some(row) = own_falcon.get(&id) {
                        any_new_use |= wallet.store.mark_used(&row.hash160)?;
                    }
                    falcon_tokens.insert(t.outpoint, t);
                }
            }
        }
        // This pass's post-quantum addresses: the sq… forms paired with its P2PKH addresses.
        let pq_pending: Vec<(String, u64)> = if pq_indexed {
            let by_hash: HashMap<[u8; 20], u64> = wallet
                .addresses()?
                .into_iter()
                .filter_map(|r| {
                    let from = pending.iter().find(|(a, _)| *a == r.address_s)?.1;
                    Some((r.hash160, from))
                })
                .collect();
            let mut v: Vec<(String, u64)> = own_pq
                .iter()
                .filter_map(|(id, h)| {
                    Some((keys::encode_pq_yec(wallet.network, id)?, *by_hash.get(h)?))
                })
                .collect();
            v.sort();
            v
        } else {
            Vec::new()
        };
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
                any_new_use |= record_transaction(wallet, &tx, &txid, raw.height, &own, &own_pq)?;
                report.transactions += 1;
            }
        }
        for (address, from) in pq_pending {
            let from = from.max(1);
            if from > tip {
                continue;
            }
            report.pq_addresses += 1;
            let txs = match client.taddress_txs(&address, from, tip).await {
                Ok(t) => t,
                Err(e) if pq_refused(&e) => {
                    pq_indexed = false;
                    report.pq_unindexed = true;
                    break;
                }
                Err(e) => return Err(e.into()),
            };
            for raw in txs {
                let (tx, txid) = Transaction::parse(&raw.data)?;
                if !seen_txids.insert(txid) {
                    continue;
                }
                any_new_use |= record_transaction(wallet, &tx, &txid, raw.height, &own, &own_pq)?;
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

    // A row recorded confirmed inside the re-read window that no address listed again left the
    // chain in a reorg: it is unconfirmed again (back in the mempool, or gone), so it shows as
    // pending until a later sync sees it mined, rather than confirmed at a height it is not at.
    // Its locks and own outputs are untouched: the UTXO set below is re-read in full anyway.
    if scanned > 0 {
        for row in wallet.store.history()? {
            if !row.pending
                && row.height >= window_from
                && row.height <= scanned
                && !seen_txids.contains(&row.txid)
            {
                wallet.store.upsert_history(&HistoryRow {
                    height: 0,
                    pending: true,
                    ..row
                })?;
            }
        }
    }

    // 4a. The token set (D-W-8): the only source of class TOKEN.
    let own = wallet.own_hashes()?;
    let addresses: Vec<String> = wallet
        .addresses()?
        .into_iter()
        .map(|a| a.address_s)
        .collect();
    let mut tokens: HashMap<OutPoint, u64> = HashMap::new();
    let own_falcon = if falcon_on {
        wallet.own_falcon_holders()?
    } else {
        HashMap::new()
    };
    let own_pq = own_pq_keys(wallet, &own_falcon, vaults_on)?;
    // Every token at an own post-quantum key, Falcon holder or not (a vault owner holds none
    // by design, C-10, but its outputs must still never pass for YEC): the PQ classifier's
    // token marker, beside the Falcon rows below.
    let mut pq_tokens: HashMap<OutPoint, u64> =
        falcon_tokens.iter().map(|(op, t)| (*op, t.cents)).collect();
    if let Some(yb) = yellowback.as_mut() {
        for t in yb.address_tokens(&addresses, 0).await? {
            wallet.store.insert_own_token(&t.outpoint, t.cents)?;
            tokens.insert(t.outpoint, t.cents);
        }
        let owner_addrs: Vec<String> = own_pq
            .keys()
            .filter(|id| !own_falcon.contains_key(id))
            .filter_map(|id| keys::encode_pq_yellowback(wallet.network, id))
            .collect();
        if !owner_addrs.is_empty() {
            for t in yb.address_tokens(&owner_addrs, 0).await? {
                pq_tokens.insert(t.outpoint, t.cents);
            }
        }
    }
    // The Falcon holder tokens (TOK-PQ), as UTXO rows of class TOKEN: built from the token and
    // the output's own script (`GetAddressUtxos` lists a `TX_PQPKH` only from lightwalletd-dd
    // q/pqaddr on, and never says it is YED; step 2b skips these outpoints), read
    // from the transaction (a `TX_PQCHANNEL` client output is listed under the same address but
    // is not a wallet coin, D-Q-19: it is skipped).
    let falcon_rows = falcon_token_utxos(wallet, client, &falcon_tokens, tip).await?;
    for u in &falcon_rows {
        wallet.store.insert_own_token(&u.outpoint, u.cents)?;
        tokens.insert(u.outpoint, u.cents);
    }
    if yellowback.is_some() {
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
    // 2b. The own post-quantum addresses' UTXOs (lightwalletd-dd q/pqaddr). A Falcon token
    // is already a TOKEN row (`falcon_rows`); any other listed token, or an output of exactly
    // `TOKEN_VALUE`, is HELD; plain YEC is PQ_OWNED: shown, never in a P2PKH path's selection.
    let falcon_ops: HashSet<OutPoint> = falcon_rows.iter().map(|u| u.outpoint).collect();
    let mut pq_rows: Vec<Utxo> = Vec::new();
    if pq_indexed && !own_pq.is_empty() {
        let mut pq_addrs: Vec<String> = own_pq
            .keys()
            .filter_map(|id| keys::encode_pq_yec(wallet.network, id))
            .collect();
        pq_addrs.sort();
        match client.address_utxos(&pq_addrs, birthday).await {
            Ok(list) => {
                for u in list {
                    let outpoint = OutPoint {
                        txid: u.txid,
                        n: u.index,
                    };
                    if falcon_ops.contains(&outpoint) {
                        continue;
                    }
                    let (class, cents) = coins::classify_pq_listed(
                        &outpoint,
                        &u.script,
                        u.value_zat,
                        |id| own_pq.contains_key(id),
                        &pq_tokens,
                    );
                    pq_rows.push(Utxo {
                        outpoint,
                        address: u.address,
                        script: u.script,
                        value: u.value_zat,
                        height: u.height,
                        class,
                        cents,
                    });
                }
            }
            Err(e) if pq_refused(&e) => report.pq_unindexed = true,
            Err(e) => return Err(e.into()),
        }
    }
    utxos.extend(falcon_rows);
    coins::apply_fee_reserve(&mut utxos);
    for u in &utxos {
        if let Some(h) = script::p2pkh_hash(&u.script) {
            if own.contains(&h) {
                wallet.store.insert_own_output(&u.outpoint, u.value, &h)?;
                wallet.store.mark_used(&h)?;
            }
        }
    }
    for u in &pq_rows {
        if let Some(h) = crate::pq::pqpkh_of(&u.script).and_then(|id| own_pq.get(&id)) {
            wallet.store.insert_own_output(&u.outpoint, u.value, h)?;
            wallet.store.mark_used(h)?;
        }
    }
    utxos.extend(pq_rows);

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
    let own_falcon = if falcon_on {
        wallet.own_falcon_holders()?
    } else {
        HashMap::new()
    };
    let present: HashSet<OutPoint> = utxos.iter().map(|u| u.outpoint).collect();
    for (txid, raw, _expiry) in wallet.store.pending_txs()? {
        let (tx, _) = match Transaction::parse(&raw) {
            Ok(t) => t,
            Err(_) => continue,
        };
        for (n, cents) in
            coins::pre_lock_scripts(&tx, |s| Wallet::is_own_holder_script(s, &own, &own_falcon))
        {
            let outpoint = OutPoint { txid, n };
            if present.contains(&outpoint) {
                continue;
            }
            let script = tx.vout[n as usize].script_pubkey.clone();
            let address = crate::build::yed_transfer::holder_address(wallet.network, &script);
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
        // In-term IT-8: the claim price the vault warnings compare against `underwaterAt`.
        wallet
            .store
            .set_meta("claim_price_micro_usd", &p.p_claim.max(0).to_string())?;
    }

    // 5. W4: the two-step rows, the own vaults, and the VAULT / CARRIER rows.
    report.mints_advanced = advance_mints(wallet, tip)?;
    let mut vt = None;
    if let Some(yb) = yellowback.as_mut() {
        let (n, terms) = refresh_vaults(wallet, yb, tip).await?;
        report.vaults = n;
        vt = terms;
        if let Some(t) = vt.as_ref() {
            report.intents = refresh_intents(wallet, yb, t, tip).await?;
        }
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
        // The vault upgrade (U-23): the vault is the bare V template, which no address lists.
        let Some(t) = vt.as_ref() else { continue };
        // In-term IT-1: the V's own branch heights, as the last refresh checked them (0 = a store
        // migrated from schema v3 before its first refresh: the in-term mint's V is not
        // derivable without refHeight, so the row waits for GetVault).
        if v.owner_height == 0 || v.app_height == 0 {
            continue;
        }
        let vs = t.vault_script_at(&v.owner, v.owner_height, v.app_height)?;
        utxos.push(Utxo {
            outpoint: op,
            address: String::new(),
            script: vs,
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

/// The wallet's own post-quantum key ids with the key hash each is paired with: the Falcon
/// holders given (`falcon`, empty before TOK-PQ is announced) and, with `owners`, the SLH-DSA
/// vault owners of the external keys (`Wallet::own_pq_owners`).
fn own_pq_keys(
    wallet: &Wallet,
    falcon: &HashMap<crate::pq::PqKeyId, crate::store::AddressRow>,
    owners: bool,
) -> Result<HashMap<crate::pq::PqKeyId, [u8; 20]>, WalletError> {
    let mut m: HashMap<crate::pq::PqKeyId, [u8; 20]> =
        falcon.iter().map(|(id, r)| (*id, r.hash160)).collect();
    if owners {
        m.extend(wallet.own_pq_owners()?);
    }
    Ok(m)
}

/// The server refused a post-quantum address in a taddr method: a lightwalletd before q/pqaddr
/// answers `INVALID_ARGUMENT` ("invalid address"). The sync goes on without the PQ lookups.
fn pq_refused(e: &NetError) -> bool {
    matches!(e, NetError::Status(s) if s.code() == tonic::Code::InvalidArgument)
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
/// history row labelled `mint`, kept when the owner key is ours and its script terms follow
/// the network's rules (`terms::check_vault`, and since the vault upgrade the V script the node
/// reports, `terms::check_vault_script`). A vault an attestor cancel re-created at a new
/// outpoint (U-24: the node keys it there and forgets the old one) is found again through
/// `ListVaultOutputs` by its owner key. The owner's RED-5 residual intent of a `CLAIMING` vault
/// is recorded for release ([`refresh_intents`]). Returns the rows written and the vault terms
/// (`None` when the server reports no usable YED attestor set and the wallet has no vault).
pub async fn refresh_vaults(
    wallet: &Wallet,
    yb: &mut YellowbackClient,
    tip: u64,
) -> Result<(usize, Option<terms::VaultTerms>), WalletError> {
    let vt = match crate::build::mint::vault_terms_now(wallet, yb).await {
        Ok(t) => t,
        Err(e) => {
            if wallet
                .store
                .vaults()?
                .iter()
                .any(|v| v.is_open() || v.status == "CLAIMING")
                || wallet.store.intents()?.iter().any(|i| i.state.open())
            {
                return Err(e);
            }
            return Ok((0, None));
        }
    };
    // Own vaults are recognised by their post-quantum owner (quantum spec §1): the owner paired
    // with each own external key (`Wallet::pq_owner_key`), mapped to that key's hash.
    let own = wallet.own_pq_owners()?;
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
    let mut lost: Vec<VaultRow> = Vec::new();
    for v in wallet.store.vaults()? {
        if v.is_open() || v.status == "CLAIMING" {
            candidates.insert(v.txid);
        }
    }
    let mut n = 0;
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    let mut queue: Vec<[u8; 32]> = candidates.into_iter().collect();
    while let Some(txid) = queue.pop() {
        if !seen.insert(txid) {
            continue;
        }
        let v = match yb.vault(&txid_hex(&txid)).await {
            Ok(v) => v,
            Err(NetError::Node { identifier, .. }) if identifier == "vault-not-found" => {
                if let Some(row) = wallet.store.vault(&txid)? {
                    if row.is_open() || row.status == "CLAIMING" {
                        lost.push(row);
                    }
                }
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        let Ok(owner) = terms::vault_owner(&v) else {
            continue;
        };
        let Some(&owner_hash160) = own.get(&owner) else {
            continue;
        };
        // The script terms the wallet would sign against, checked before the vault is shown
        // as redeemable (audit G-1); an inconsistent answer fails the sync with that error.
        terms::check_vault(wallet.network, &v)?;
        let yv = terms::check_vault_script(&vt, &v)?;
        let vault_txid = txid_from_hex(&v.txid).unwrap_or(txid);
        wallet.store.upsert_vault(&VaultRow {
            txid: vault_txid,
            vout: v.vout,
            status: v.status.clone(),
            owner_hash160,
            owner,
            term_class: v.term_class.clone(),
            lock_height: v.lock_height as u32,
            claim_height: v.claim_height as u32,
            collateral_zat: v.collateral_zat,
            minted_cents: v.minted_cents.max(0) as u64,
            mint_height: v.mint_height.max(0) as u64,
            claimable: v.claimable,
            underwater_at: v.underwater_at,
            sweep_before: 0,
            close_height: v.close_height.max(0) as u64,
            closing_txid: v.closing_txid.clone(),
            void_reason: v.void_reason.clone(),
            updated_height: tip,
            owner_height: yv.owner_height(),
            app_height: yv.app_height(),
            p_mint: v.p_mint,
            cancel: cancel_of(&v),
        })?;
        n += 1;
        if v.status == "CLAIMING" {
            record_residual_intents(wallet, yb, &v, &owner, &yv, vault_txid).await?;
        }
    }
    // U-24: a vault the node no longer knows under its old outpoint was either re-created by an
    // attestor cancel (ACTIVE again at the cancel's output 0) or reorganised away. Look for the
    // owner's live YED vaults and adopt the new outpoint.
    for row in lost {
        let mut found = None;
        for o in yb
            .list_vault_outputs("", "", &keys::hex(&row.owner.to_bytes()), "vault")
            .await?
        {
            let Ok(t) = txid_from_hex(&o.txid) else {
                continue;
            };
            if seen.contains(&t) || wallet.store.vault(&t)?.is_some() {
                continue;
            }
            let Ok(v) = yb.vault(&o.txid).await else {
                continue;
            };
            if v.lock_height as u32 != row.lock_height
                || v.minted_cents.max(0) as u64 != row.minted_cents
            {
                continue;
            }
            terms::check_vault(wallet.network, &v)?;
            let yv = terms::check_vault_script(&vt, &v)?;
            wallet.store.upsert_vault(&VaultRow {
                txid: t,
                vout: v.vout,
                status: v.status.clone(),
                owner_height: yv.owner_height(),
                app_height: yv.app_height(),
                collateral_zat: v.collateral_zat,
                claimable: v.claimable,
                underwater_at: v.underwater_at,
                close_height: 0,
                closing_txid: String::new(),
                updated_height: tip,
                p_mint: v.p_mint,
                cancel: cancel_of(&v),
                ..row.clone()
            })?;
            found = Some(t);
            n += 1;
            break;
        }
        wallet.store.upsert_vault(&VaultRow {
            status: if found.is_some() {
                "REOPENED".into()
            } else {
                "GONE".into()
            },
            closing_txid: found.map(|t| txid_hex(&t)).unwrap_or_default(),
            updated_height: tip,
            ..row
        })?;
    }
    Ok((n, Some(vt)))
}

/// The per-vault cancel limit of a `GetVault` answer (CAN-2, CAN-3), as the store keeps it: the
/// node's `null` `cancelQuietUntil` arrives as 0; a held residual whose txid does not parse is
/// skipped (it cannot match an intent of this wallet).
fn cancel_of(v: &crate::net::rpc::YedVault) -> VaultCancel {
    VaultCancel {
        count: v.cancel_count,
        required: v.cancels_required,
        quiet_until: v.cancel_quiet_until.max(0) as u64,
        held_residuals: v
            .held_residuals
            .iter()
            .filter_map(|o| {
                txid_from_hex(&o.txid)
                    .ok()
                    .map(|txid| OutPoint { txid, n: o.vout })
            })
            .collect(),
    }
}

/// The owner's RED-5 residual intent of an own `CLAIMING` vault (`yed_getvault.intents`, role
/// `"residual"`): its value and script from `ListVaultOutputs`, the script checked to be the
/// intent this wallet derives (paying `PQPKH(owner)`, quantum spec F-3), recorded for release.
async fn record_residual_intents(
    wallet: &Wallet,
    yb: &mut YellowbackClient,
    v: &crate::net::rpc::YedVault,
    owner: &crate::pq::PqKeyId,
    yv: &terms::YedV,
    vault_txid: [u8; 32],
) -> Result<(), WalletError> {
    let residual: Vec<_> = v
        .intents
        .iter()
        .filter(|i| i.role == crate::build::claim::ROLE_RESIDUAL)
        .collect();
    if residual.is_empty() {
        return Ok(());
    }
    let recipient = crate::pq::pqpkh_script(owner)
        .ok_or_else(|| WalletError::Other("the vault owner's scheme is not registered".into()))?;
    let want = crate::vault::build_intent(&crate::vault::intent_for(
        &yv.params, &yv.script, &recipient,
    ))
    .ok_or_else(|| WalletError::Other("cannot build the residual intent".into()))?;
    let live = yb
        .list_vault_outputs("", "", &keys::hex(&owner.to_bytes()), "intent")
        .await?;
    for i in residual {
        let Ok(txid) = txid_from_hex(&i.txid) else {
            continue;
        };
        let op = OutPoint { txid, n: i.vout };
        if wallet.store.intent(&op)?.is_some() {
            continue;
        }
        let Some(o) = live.iter().find(|o| o.txid == i.txid && o.vout == i.vout) else {
            continue;
        };
        if keys::unhex(&o.script).ok().as_deref() != Some(&want[..]) {
            return Err(terms_inconsistent(format!(
                "the residual intent {}:{} is not the one paying this vault's owner",
                i.txid, i.vout
            )));
        }
        wallet.store.upsert_intent(&IntentRow {
            outpoint: op,
            vault_txid,
            role: crate::build::claim::ROLE_RESIDUAL.into(),
            value: o.valuezat,
            recipient_script: recipient.clone(),
            intent_script: want.clone(),
            delay: yv.params.delay,
            height: i.height.max(0) as u64,
            state: IntentState::Pending,
            spend_txid: [0; 32],
            pq_spend_txid: [0; 32],
            note: format!(
                "your vault {} was claimed: the RED-5 residual is yours after the claim delay. If the claim is cancelled, it stays held until the vault closes. After the quiet period it can be released only once the position is no longer claimable",
                &txid_hex(&vault_txid)[..8]
            ),
            refund: Default::default(),
        })?;
    }
    Ok(())
}

fn terms_inconsistent(what: String) -> WalletError {
    crate::build::mint::MintError::Inconsistent { what }.into()
}

/// Advance every open claim intent paying this wallet (the vault upgrade, U-15, U-23, U-24):
/// its confirmation height from the history scan (the claim spends own coins, so the scan sees
/// it); a release seen confirmed ⇒ `Released`, a release that expired ⇒ back to `Pending`; a
/// confirmed intent no longer among the live template outputs ⇒ `Released` when the vault is
/// `CLAIMED` (or it is the owner's residual), `Cancelled` when the attestor set re-created the
/// vault (CAN-1: the claim's burn came back as a YED token to the refund holder, which the token
/// sync finds like any own token; the YEC fees did not). While the vault is CLAIMING a claimant
/// row takes the node's `refundHolder` / `burnedCents` (what a cancel would re-issue, to whom).
/// Returns the rows that moved.
pub async fn refresh_intents(
    wallet: &Wallet,
    yb: &mut YellowbackClient,
    vt: &terms::VaultTerms,
    _tip: u64,
) -> Result<usize, WalletError> {
    let mut moved = 0;
    let set_hex = txid_hex(&vt.attestor_set_id);
    let mut live: Option<HashSet<OutPoint>> = None;
    for i in wallet.store.intents()? {
        // A released residual's post-quantum coin being moved (quantum spec F-3): confirmed ⇒
        // `Swept`; dropped unconfirmed ⇒ offered again.
        if i.state == IntentState::Released && i.pq_spend_txid != [0; 32] {
            let mut row = i.clone();
            if confirmed_height(wallet, &i.pq_spend_txid)?.is_some() {
                row.state = IntentState::Swept;
                row.note = "the residual is in your wallet".into();
            } else if wallet
                .store
                .pending_txs()?
                .iter()
                .all(|(t, _, _)| *t != i.pq_spend_txid)
            {
                row.pq_spend_txid = [0; 32];
                row.note = "the move expired unconfirmed; move it again".into();
            }
            if row != i {
                wallet.store.upsert_intent(&row)?;
                moved += 1;
            }
            continue;
        }
        if !i.state.open() {
            continue;
        }
        let mut row = i.clone();
        if row.height == 0 {
            if let Some(h) = confirmed_height(wallet, &row.outpoint.txid)? {
                row.height = h;
            }
        }
        if row.state == IntentState::Releasing {
            if confirmed_height(wallet, &row.spend_txid)?.is_some() {
                row.state = IntentState::Released;
                row.note = if crate::build::release::pq_coin(&row).is_some() {
                    "released to your vault-owner (post-quantum) key: move it to your wallet".into()
                } else {
                    "released".into()
                };
            } else if wallet
                .store
                .pending_txs()?
                .iter()
                .all(|(t, _, _)| *t != row.spend_txid)
            {
                row.state = IntentState::Pending;
                row.note = "the release expired unconfirmed; release again".into();
            }
        }
        if row.state == IntentState::Pending && row.height > 0 {
            // GetVault is a light call: while the vault is CLAIMING its live intents are listed.
            // Only an intent it no longer lists needs the (heavy) template-output scan.
            let (status, listed) = match yb.vault(&txid_hex(&row.vault_txid)).await {
                Ok(v) => {
                    if row.role == crate::build::claim::ROLE_CLAIMANT
                        && v.status == "CLAIMING"
                        && !v.refund_holder.is_empty()
                    {
                        if let Ok(script) = keys::unhex(&v.refund_holder) {
                            row.refund = crate::store::IntentRefund {
                                script,
                                cents: v.burned_cents.max(0) as u64,
                            };
                        }
                    }
                    let listed = v.intents.iter().any(|x| {
                        x.vout == row.outpoint.n
                            && txid_from_hex(&x.txid).ok() == Some(row.outpoint.txid)
                    });
                    (v.status, listed)
                }
                Err(NetError::Node { identifier, .. }) if identifier == "vault-not-found" => {
                    (String::new(), false)
                }
                Err(e) => return Err(e.into()),
            };
            let alive = if listed {
                true
            } else if row.role == crate::build::claim::ROLE_RESIDUAL {
                // A residual outlives its vault's CLAIMING state (and a cancel of the claimant
                // intent, which re-keys the vault): ask the template-output index.
                if live.is_none() {
                    let mut s = HashSet::new();
                    for o in yb.list_vault_outputs("", &set_hex, "", "intent").await? {
                        if let Ok(t) = txid_from_hex(&o.txid) {
                            s.insert(OutPoint { txid: t, n: o.vout });
                        }
                    }
                    live = Some(s);
                }
                live.as_ref().is_some_and(|s| s.contains(&row.outpoint))
            } else {
                false
            };
            if !alive {
                if row.role == crate::build::claim::ROLE_RESIDUAL || status == "CLAIMED" {
                    row.state = IntentState::Released;
                    row.note = if crate::pq::pqpkh_of(&row.recipient_script).is_some() {
                        // The coin is `PQPKH(owner)` in a transaction this wallet did not make:
                        // the sync finds it on the owner's sq… form (lightwalletd-dd q/pqaddr) as
                        // a PQ_OWNED row, moved from Home like any own post-quantum coin.
                        "released by another party to your vault-owner (post-quantum) key; it shows on Home as YEC at your post-quantum addresses, to move into your wallet".into()
                    } else {
                        "released (by another party: a release needs no signature, U-15)".into()
                    };
                } else {
                    row.state = IntentState::Cancelled;
                    row.note = "cancelled by the attestor set: the collateral went back into the vault and the YED you burned came back to you as a token (CAN-1); the claim's YEC fees did not".into();
                }
            }
        }
        if row != i {
            wallet.store.upsert_intent(&row)?;
            moved += 1;
        }
    }
    Ok(moved)
}

/// Record one transaction touching an own address: history row, own outputs, used marks,
/// pending-transaction confirmation. Returns whether an address was newly marked used.
fn record_transaction(
    wallet: &Wallet,
    tx: &Transaction,
    txid: &[u8; 32],
    height: u64,
    own: &HashSet<[u8; 20]>,
    own_pq: &HashMap<crate::pq::PqKeyId, [u8; 20]>,
) -> Result<bool, WalletError> {
    let mut newly_used = false;
    let mut delta = 0i64;
    let mut has_payload = false;
    for (n, o) in tx.vout.iter().enumerate() {
        if script::is_op_return(&o.script_pubkey) {
            has_payload = true;
        }
        // An own post-quantum output (a Falcon holder, TOK-PQ, or a vault owner's residual)
        // counts like its paired key's.
        let h = script::p2pkh_hash(&o.script_pubkey)
            .filter(|h| own.contains(h))
            .or_else(|| {
                crate::pq::pqpkh_of(&o.script_pubkey)
                    .and_then(|id| own_pq.get(&id))
                    .copied()
            });
        if let Some(h) = h {
            delta += o.value;
            let op = OutPoint {
                txid: *txid,
                n: n as u32,
            };
            wallet.store.insert_own_output(&op, o.value, &h)?;
            newly_used |= wallet.store.mark_used(&h)?;
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

/// The UTXO rows of the wallet's Falcon holder tokens (`tokens`, from `GetAddressTokens` on the
/// 53-character addresses): each output's script is checked to be the own `TX_PQPKH` (a row the
/// last sync stored is trusted; otherwise the transaction is fetched once, recorded in history,
/// and read). Class TOKEN, the address the token was listed under.
async fn falcon_token_utxos(
    wallet: &Wallet,
    client: &mut CompactClient,
    tokens: &HashMap<OutPoint, crate::net::Token>,
    tip: u64,
) -> Result<Vec<Utxo>, WalletError> {
    if tokens.is_empty() {
        return Ok(Vec::new());
    }
    let own = wallet.own_hashes()?;
    let own_falcon = wallet.own_falcon_holders()?;
    let own_pq = own_pq_keys(wallet, &own_falcon, false)?;
    let known: HashMap<OutPoint, (Vec<u8>, i64)> = wallet
        .store
        .utxos()?
        .into_iter()
        .filter(|u| crate::pq::pqpkh_of(&u.script).is_some())
        .map(|u| (u.outpoint, (u.script, u.value)))
        .collect();
    let mut fetched: HashMap<[u8; 32], Option<Transaction>> = HashMap::new();
    let mut out = Vec::new();
    for (op, t) in tokens {
        let Ok(id) = keys::parse_pq_address(wallet.network, &t.address) else {
            continue;
        };
        if !own_falcon.contains_key(&id) {
            continue;
        }
        let want = crate::pq::pqpkh_script(&id).unwrap_or_default();
        if t.value_zat != TOKEN_VALUE {
            continue;
        }
        // A stored row is trusted for its script, and its value (a `GetAddressUtxos` row's, or
        // TOKEN_VALUE checked when the row was built) must be the carrier's too.
        let script = if let Some((s, v)) = known.get(op).filter(|(s, _)| *s == want) {
            if *v != TOKEN_VALUE {
                continue;
            }
            s.clone()
        } else {
            if let std::collections::hash_map::Entry::Vacant(slot) = fetched.entry(op.txid) {
                let tx = match client.get_transaction(&op.txid).await? {
                    Some((raw, height)) => {
                        let (tx, txid) = Transaction::parse(&raw)?;
                        let height = if height == 0 && t.height > 0 {
                            t.height as u64
                        } else {
                            height
                        };
                        if height <= tip {
                            record_transaction(wallet, &tx, &txid, height, &own, &own_pq)?;
                        }
                        Some(tx)
                    }
                    None => None,
                };
                slot.insert(tx);
            }
            match fetched
                .get(&op.txid)
                .and_then(|t| t.as_ref())
                .and_then(|tx| tx.vout.get(op.n as usize))
            {
                Some(o) if o.script_pubkey == want && o.value == TOKEN_VALUE => want.clone(),
                _ => continue, // a channel output, or a transaction the server cannot serve
            }
        };
        out.push(Utxo {
            outpoint: *op,
            address: t.address.clone(),
            script,
            value: TOKEN_VALUE,
            height: t.height.max(0) as u64,
            class: UtxoClass::Token,
            cents: t.cents,
        });
    }
    out.sort_by_key(|u| (u.height, u.outpoint.txid, u.outpoint.n));
    Ok(out)
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
            owner: None,
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
