//! The data the shell sees (yew/web plan W1a; the contract in the briefing's
//! API-yew-web-core.md): plain `serde` structs rendered to JS objects, camelCase, amounts as
//! decimal strings (zatoshi, cents: u64/i64 do not fit a JS number), heights and counts as
//! numbers. Each mapping below is translated from the same-named one in `core/src/api.rs`
//! (the Dart surface), which cannot compile for wasm32 (flutter_rust_bridge, tokio); the DTO
//! fields are the Dart ones, so screens port one to one. No wallet logic lives here.

use serde::Serialize;
use yew_core::build::claim::Claimable;
use yew_core::build::mint::MintEstimate as CoreMintEstimate;
use yew_core::build::redeem::RedeemBuild;
use yew_core::build::release::ReleaseBuild;
use yew_core::build::terms::MintGate;
use yew_core::build::yec_private::{Funding, YecSendPlan};
use yew_core::build::yed_transfer::YedTransferPreview;
use yew_core::coins::UtxoClass;
use yew_core::keys;
use yew_core::net::Validation;
use yew_core::params::{self, Network};
use yew_core::shielded::{ShieldedBalance, ShieldedTx};
use yew_core::store::{HistoryRow, IntentRow, IntentState, MintKind, MintRow, MintState, VaultRow};
use yew_core::tx::txid_hex;
use yew_core::wallet::Balances as CoreBalances;

/// An amount as the contract wants it: a decimal string.
pub fn amt(v: i64) -> String {
    v.to_string()
}

fn hex_or_empty(txid: &[u8; 32]) -> String {
    if *txid == [0; 32] {
        String::new()
    } else {
        txid_hex(txid)
    }
}

/// `balances()`: transparent YEC, YED, the price and the private balance in one call
/// (`api::Balances`).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Balances {
    pub yec_zat: String,
    pub yec_reserved_zat: String,
    pub yec_pending_zat: String,
    pub yed_cents: String,
    pub yed_pending_cents: String,
    /// `GetPrice.pMint` at the last sync as cents per YEC; `null` when undefined.
    pub price_cents: Option<String>,
    /// The same, micro-USD per YEC.
    pub price_micro_usd: Option<String>,
    pub held_count: u64,
    pub sync_height: u64,
    pub yed_send_min_zat: String,
    pub shielded_zat: String,
    pub shielded_spendable_zat: String,
    pub shielded_pending_zat: String,
    pub shielded_scanned_height: u64,
    pub shielded_sendable: bool,
}

pub fn balances(b: &CoreBalances, z: &ShieldedBalance, held: u64, sync_height: u64) -> Balances {
    Balances {
        yec_zat: amt(b.yec_zat),
        yec_reserved_zat: amt(b.yec_reserved_zat),
        yec_pending_zat: amt(b.yec_pending_zat),
        yed_cents: amt(b.yed_cents as i64),
        yed_pending_cents: amt(b.yed_pending_cents as i64),
        price_cents: b.price_micro_usd.map(|p| amt(p / 10_000)),
        price_micro_usd: b.price_micro_usd.map(amt),
        held_count: held,
        sync_height,
        yed_send_min_zat: amt(params::FEE_ZAT + 2 * params::TOKEN_VALUE),
        shielded_zat: amt(z.total_zat as i64),
        shielded_spendable_zat: amt(z.spendable_zat as i64),
        shielded_pending_zat: amt((z.pending_change_zat + z.pending_incoming_zat) as i64),
        shielded_scanned_height: z.scanned_height,
        shielded_sendable: z.sendable,
    }
}

/// A receive address (`api::AddressPair`): `address` is the one of `kind`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddressPair {
    pub ye: String,
    pub s: String,
    pub path: String,
    pub covered_by_seed: bool,
    pub address: String,
    pub kind: String,
}

/// One history row (`api::HistoryItem`).
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct HistoryItem {
    pub txid: String,
    pub height: u64,
    pub pending: bool,
    pub yec_delta: String,
    pub yed_delta: String,
    pub label: String,
    pub verdict: String,
    pub kind: String,
    pub has_payload: bool,
    pub shielded: bool,
    pub memo: String,
    #[serde(skip)]
    yec_delta_zat: i64,
}

fn history_item(h: &HistoryRow) -> HistoryItem {
    let label = if h.label.is_empty() {
        if h.has_payload {
            if h.labelled {
                "payload, not yellowback"
            } else {
                "payload, unlabelled"
            }
        } else if h.yec_delta < 0 {
            "sent YEC"
        } else if h.yec_delta > 0 {
            "received YEC"
        } else {
            ""
        }
        .to_string()
    } else {
        h.label.clone()
    };
    HistoryItem {
        txid: txid_hex(&h.txid),
        height: h.height,
        pending: h.pending,
        yec_delta: amt(h.yec_delta),
        yed_delta: amt(h.yed_delta),
        label,
        verdict: h.verdict.clone(),
        kind: h.kind.clone(),
        has_payload: h.has_payload,
        shielded: h.shielded,
        memo: String::new(),
        yec_delta_zat: h.yec_delta,
    }
}

/// The row of a private transaction, merged into its transparent row when the same transaction
/// also moved transparent funds (`api::merge_shielded`).
fn merge_shielded(rows: &mut Vec<HistoryItem>, z: &ShieldedTx) {
    let txid = txid_hex(&z.txid);
    if let Some(r) = rows.iter_mut().find(|r| r.txid == txid) {
        r.yec_delta_zat += z.delta_zat;
        r.yec_delta = amt(r.yec_delta_zat);
        r.shielded = true;
        if r.memo.is_empty() {
            r.memo = z.memo.clone();
        }
        if z.height > 0 && r.height == 0 {
            r.height = z.height;
            r.pending = false;
        }
        return;
    }
    rows.push(HistoryItem {
        txid,
        height: z.height,
        pending: z.height == 0,
        yec_delta: amt(z.delta_zat),
        yed_delta: amt(0),
        label: if z.delta_zat < 0 {
            "sent private YEC"
        } else {
            "received private YEC"
        }
        .into(),
        verdict: String::new(),
        kind: String::new(),
        has_payload: false,
        shielded: true,
        memo: z.memo.clone(),
        yec_delta_zat: z.delta_zat,
    });
}

/// One page (50 rows) of the merged history, pending first then newest first (`api::history`).
pub fn history_page(all: &[HistoryRow], shielded: &[ShieldedTx], page: u32) -> Vec<HistoryItem> {
    const SIZE: usize = 50;
    let mut merged: Vec<HistoryItem> = all.iter().map(history_item).collect();
    for z in shielded.iter().filter(|z| !z.expired) {
        merge_shielded(&mut merged, z);
    }
    merged.sort_by_key(|r| (!r.pending, std::cmp::Reverse(r.height)));
    merged
        .into_iter()
        .skip(page as usize * SIZE)
        .take(SIZE)
        .collect()
}

/// A YEC send or move before confirmation (`api::YecPreview`).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct YecPreview {
    pub preview_id: String,
    pub to: String,
    pub amount_zat: String,
    pub amount_bumped: bool,
    pub fee: String,
    pub change: String,
    pub inputs: u32,
    pub uses_reserve: bool,
    pub keeps_reserved_zat: String,
    pub expiry_height: u32,
    pub txid: String,
    /// `transparent` or `shielded` (where the money comes from).
    pub funding: String,
    pub reveals_shielded: bool,
    pub memo: Option<String>,
    /// Proving parameters are needed at confirm and no prover is loaded: `fetch_params` first.
    pub params_needed: bool,
}

pub fn yec_preview(
    preview_id: String,
    plan: &YecSendPlan,
    reserved: i64,
    has_prover: bool,
) -> YecPreview {
    match &plan.funding {
        Funding::Transparent(p) => {
            let reserved_spent: i64 = p
                .inputs
                .iter()
                .filter(|u| u.class == UtxoClass::FeeReserve)
                .map(|u| u.value)
                .sum();
            YecPreview {
                preview_id,
                to: p.to.clone(),
                amount_zat: amt(p.amount),
                amount_bumped: p.amount_bumped,
                fee: amt(p.fee),
                change: amt(p.change),
                inputs: p.inputs.len() as u32,
                uses_reserve: p.uses_reserve,
                keeps_reserved_zat: amt(reserved - reserved_spent),
                expiry_height: p.expiry_height,
                txid: txid_hex(&p.txid),
                funding: "transparent".into(),
                reveals_shielded: false,
                memo: None,
                params_needed: false,
            }
        }
        Funding::Shielded(p) => YecPreview {
            preview_id,
            to: p.to.clone(),
            amount_zat: amt(p.amount_zat as i64),
            amount_bumped: p.amount_bumped,
            fee: amt(p.fee_zat as i64),
            change: amt(p.change_zat as i64),
            inputs: p.notes,
            uses_reserve: false,
            keeps_reserved_zat: amt(reserved),
            expiry_height: p.expiry_height,
            txid: String::new(),
            funding: "shielded".into(),
            reveals_shielded: plan.reveals_shielded,
            memo: p.memo.clone(),
            params_needed: !has_prover,
        },
        Funding::Shield(p) => YecPreview {
            preview_id,
            to: p.to.clone(),
            amount_zat: amt(p.amount),
            amount_bumped: p.amount_bumped,
            fee: amt(p.fee),
            change: amt(p.change),
            inputs: p.inputs.len() as u32,
            uses_reserve: false,
            keeps_reserved_zat: amt(reserved),
            expiry_height: p.expiry_height,
            txid: String::new(),
            funding: "transparent".into(),
            reveals_shielded: false,
            memo: None,
            params_needed: !has_prover,
        },
    }
}

/// The node's dry run of a preview (`api::DryRun`).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DryRun {
    pub valid: bool,
    pub verdict: String,
    pub burned_cents: String,
    pub would_be_rejected: bool,
    pub yed_in_cents: String,
    pub yed_out_cents: String,
    pub accepted: bool,
}

pub fn dry_run(v: &Validation) -> DryRun {
    DryRun {
        valid: v.valid,
        verdict: v.verdict.clone(),
        burned_cents: amt(v.burned),
        would_be_rejected: v.would_be_rejected,
        yed_in_cents: amt(v.yed_in),
        yed_out_cents: amt(v.yed_out),
        accepted: yew_core::gate::accept(v, 0).is_ok(),
    }
}

/// A YED send before confirmation (`api::YedPreview`).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct YedPreview {
    pub preview_id: String,
    pub to: String,
    pub cents: String,
    pub stage: String,
    pub inputs: u32,
    pub change_cents: String,
    pub yec_inputs: u32,
    pub fee_zat: String,
    pub yec_change_zat: String,
    pub expiry_height: u32,
    pub txid: String,
    pub verdict: String,
    pub dry_run: DryRun,
}

pub fn yed_preview(id: String, p: &YedTransferPreview, v: &Validation) -> YedPreview {
    YedPreview {
        preview_id: id.clone(),
        to: p
            .recipients
            .first()
            .map(|r| r.0.clone())
            .unwrap_or_default(),
        cents: amt(p.recipients.iter().map(|r| r.1 as i64).sum()),
        stage: p.stage.name().into(),
        inputs: p.yed_inputs.len() as u32,
        change_cents: amt(p.change_cents as i64),
        yec_inputs: p.yec_inputs.len() as u32,
        fee_zat: amt(p.fee),
        yec_change_zat: amt(p.yec_change),
        expiry_height: p.expiry_height,
        txid: id,
        verdict: v.verdict.clone(),
        dry_run: dry_run(v),
    }
}

/// The result of `confirm` (`api::SendResult`, plus the row id of a mint step).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SendResult {
    pub txid: String,
    pub verdict: String,
    pub mint_id: Option<i64>,
}

/// `mint_estimate` (`api::MintEstimate`).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MintEstimate {
    pub cents: String,
    pub lock_blocks: u32,
    pub term_class: String,
    pub ref_height: u64,
    pub lock_height: u64,
    pub claim_height: u64,
    pub expiry_height: u64,
    pub required_zat: String,
    pub collateral_zat: String,
    pub fee_zat: String,
    pub attest_fee_zat: String,
    pub payee: String,
    pub carrier_zat: String,
    pub token_zat: String,
    pub network_fee_zat: String,
    pub total_zat: String,
    pub available_zat: String,
    pub affordable: bool,
    pub p_mint_micro_usd: Option<String>,
    pub armed: bool,
    pub bundle_seqs: Vec<u32>,
}

pub fn mint_estimate(e: &CoreMintEstimate) -> MintEstimate {
    MintEstimate {
        cents: amt(e.cents as i64),
        lock_blocks: e.lock_blocks,
        term_class: e.term_class.clone(),
        ref_height: e.ref_height as u64,
        lock_height: e.lock_height as u64,
        claim_height: e.claim_height as u64,
        expiry_height: e.ref_height as u64 + params::REF_WINDOW as u64,
        required_zat: amt(e.required_zat),
        collateral_zat: amt(e.collateral_zat),
        fee_zat: amt(e.fee_zat),
        attest_fee_zat: amt(e.attest_fee_zat),
        payee: e.payee.clone(),
        carrier_zat: amt(params::CARRIER_VALUE),
        token_zat: amt(params::TOKEN_VALUE),
        network_fee_zat: amt(2 * params::FEE_ZAT),
        total_zat: amt(e.total_zat),
        available_zat: amt(e.available_zat),
        affordable: e.affordable(),
        p_mint_micro_usd: (e.p_mint > 0).then(|| amt(e.p_mint)),
        armed: e.armed,
        bundle_seqs: e.bundle_seqs.iter().map(|s| *s as u32).collect(),
    }
}

/// One `mints` row (`api::MintStatus`).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MintStatus {
    pub mint_id: i64,
    pub kind: String,
    pub state: String,
    pub created_height: u64,
    pub cents: String,
    pub lock_blocks: u32,
    pub term_class: String,
    pub ref_height: u64,
    pub lock_height: u64,
    pub claim_height: u64,
    pub expiry_height: u64,
    pub collateral_zat: String,
    pub fee_zat: String,
    pub attest_fee_zat: String,
    pub residual_zat: String,
    pub payee: String,
    pub attest_payee: String,
    pub bundle_seqs: String,
    pub carrier_txid: String,
    pub main_txid: String,
    pub sweep_txid: String,
    pub vault_txid: String,
    pub tip: u64,
    pub in_progress: bool,
    pub window_open: bool,
    pub blocks_left: i64,
    pub can_finish: bool,
    pub can_sweep: bool,
    pub note: String,
}

pub fn mint_status(m: &MintRow, tip: u64) -> MintStatus {
    let open = yew_core::build::mint::window_open(tip, m.expiry_height);
    let blocks_left = (m.expiry_height as i64)
        .saturating_sub(tip as i64 + 1 + params::TX_EXPIRING_SOON_THRESHOLD as i64)
        .max(0);
    MintStatus {
        mint_id: m.id,
        kind: m.kind.as_str().into(),
        state: m.state.as_str().into(),
        created_height: m.created_height,
        cents: amt(m.cents as i64),
        lock_blocks: m.lock_blocks,
        term_class: m.term_class.clone(),
        ref_height: m.ref_height as u64,
        lock_height: m.lock_height as u64,
        claim_height: m.claim_height as u64,
        expiry_height: m.expiry_height as u64,
        collateral_zat: amt(m.collateral_zat),
        fee_zat: amt(m.fee_zat),
        attest_fee_zat: amt(m.attest_fee_zat),
        residual_zat: amt(m.residual_zat),
        payee: m.payee.clone(),
        attest_payee: m.attest_payee.clone(),
        bundle_seqs: m.bundle_seqs.clone(),
        carrier_txid: hex_or_empty(&m.carrier_txid),
        main_txid: hex_or_empty(&m.main_txid),
        sweep_txid: hex_or_empty(&m.sweep_txid),
        vault_txid: hex_or_empty(&m.vault_txid),
        tip,
        in_progress: matches!(
            m.state,
            MintState::CarrierSent | MintState::CarrierConfirmed | MintState::MainSent
        ),
        window_open: open,
        blocks_left,
        can_finish: m.state == MintState::CarrierConfirmed && open,
        can_sweep: m.state == MintState::Lapsed,
        note: m.note.clone(),
    }
}

/// One own vault (`api::VaultSummary`).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultSummary {
    pub vault_txid: String,
    pub status: String,
    pub owner_address: String,
    pub term_class: String,
    pub cents: String,
    pub collateral_zat: String,
    pub lock_height: u64,
    pub claim_height: u64,
    pub mint_height: u64,
    pub tip: u64,
    pub open: bool,
    pub redeemable: bool,
    pub blocks_until_redeem: i64,
    pub releasable: bool,
    pub claimable: bool,
    pub underwater_at_micro_usd: String,
    pub underwater: bool,
    pub close_height: u64,
    pub closing_txid: String,
    pub void_reason: String,
    pub lock_time_secs: i64,
    pub claim_time_secs: i64,
    pub blocks_until_claim: i64,
    pub renewable: bool,
    pub renew_lock_blocks: u32,
    pub claim_warning: bool,
    pub claim_open: bool,
    pub claiming: bool,
    pub reopened: bool,
}

fn renew_lock_blocks(v: &VaultRow, mints: &[MintRow], network: Network) -> u32 {
    if let Some(m) = mints
        .iter()
        .find(|m| m.kind == MintKind::Mint && m.vault_txid == v.txid && m.lock_blocks > 0)
    {
        return m.lock_blocks;
    }
    let class = network
        .enabled_classes()
        .find(|c| c.letter == v.term_class)
        .or_else(|| network.enabled_classes().next());
    let guess = (v.lock_height as i64 - v.mint_height as i64).max(0) as u32;
    match class {
        Some(c) => guess.clamp(c.min_blocks, c.max_blocks),
        None => guess,
    }
}

fn height_time(network: Network, height: u64, tip: u64, now_secs: i64) -> i64 {
    now_secs + (height as i64 - tip as i64) * network.target_spacing_secs()
}

pub fn vault_summary(
    v: &VaultRow,
    tip: u64,
    price: Option<i64>,
    network: Network,
    mints: &[MintRow],
    now_secs: i64,
) -> VaultSummary {
    let active = v.status == "ACTIVE";
    let void = v.status == "VOID";
    let claim_warn_from = (v.claim_height as u64).saturating_sub(network.day_blocks() as u64);
    VaultSummary {
        vault_txid: txid_hex(&v.txid),
        status: v.status.clone(),
        owner_address: keys::encode_yellowback(network, &v.owner_hash160),
        term_class: v.term_class.clone(),
        cents: amt(v.minted_cents as i64),
        collateral_zat: amt(v.collateral_zat),
        lock_height: v.lock_height as u64,
        claim_height: v.claim_height as u64,
        mint_height: v.mint_height,
        tip,
        open: v.is_open(),
        redeemable: active && tip >= v.lock_height as u64,
        blocks_until_redeem: (v.lock_height as i64 - tip as i64).max(0),
        releasable: void,
        claimable: v.claimable,
        underwater_at_micro_usd: amt(v.underwater_at),
        underwater: v.is_open()
            && v.underwater_at > 0
            && price.is_some_and(|p| p > 0 && p <= v.underwater_at),
        close_height: v.close_height,
        closing_txid: v.closing_txid.clone(),
        void_reason: v.void_reason.clone(),
        lock_time_secs: height_time(network, v.lock_height as u64, tip, now_secs),
        claim_time_secs: height_time(network, v.claim_height as u64, tip, now_secs),
        blocks_until_claim: (v.claim_height as i64 - tip as i64).max(0),
        renewable: active && tip >= v.lock_height as u64,
        renew_lock_blocks: renew_lock_blocks(v, mints, network),
        claim_warning: active && tip >= claim_warn_from,
        claim_open: active && tip >= v.claim_height as u64,
        claiming: v.status == "CLAIMING",
        reopened: v.status == "REOPENED",
    }
}

/// A claim intent paying this wallet (`api::ClaimIntent`).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimIntent {
    pub intent: String,
    pub vault_txid: String,
    pub role: String,
    pub value_zat: String,
    pub state: String,
    pub height: u64,
    pub release_height: u64,
    pub blocks_until_release: i64,
    pub releasable: bool,
    pub cancelled: bool,
    pub release_time_secs: i64,
    pub spend_txid: String,
    pub note: String,
}

pub fn claim_intent(i: &IntentRow, tip: u64, network: Network, now: i64) -> ClaimIntent {
    let rh = i.release_height().unwrap_or(0);
    ClaimIntent {
        intent: format!("{}:{}", txid_hex(&i.outpoint.txid), i.outpoint.n),
        vault_txid: txid_hex(&i.vault_txid),
        role: i.role.clone(),
        value_zat: amt(i.value),
        state: i.state.as_str().into(),
        height: i.height,
        release_height: rh,
        blocks_until_release: if rh == 0 {
            0
        } else {
            (rh as i64 - (tip as i64 + 1)).max(0)
        },
        releasable: yew_core::build::release::not_releasable(i, tip).is_none(),
        cancelled: i.state == IntentState::Cancelled,
        release_time_secs: if rh == 0 {
            0
        } else {
            height_time(network, rh, tip, now)
        },
        spend_txid: hex_or_empty(&i.spend_txid),
        note: i.note.clone(),
    }
}

/// One `ListClaimable` row (`api::ClaimableItem`).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimableItem {
    pub vault_txid: String,
    pub owner_address: String,
    pub cents: String,
    pub collateral_zat: String,
    pub claim_height: u64,
    pub claim_path: String,
    pub p_claim_micro_usd: String,
    pub fee_zat: String,
    pub attest_fee_zat: String,
    pub residual_zat: String,
    pub claimant_zat: String,
    pub payee: String,
}

pub fn claimable_item(c: &Claimable) -> ClaimableItem {
    ClaimableItem {
        vault_txid: c.vault_txid.clone(),
        owner_address: c.owner_address.clone(),
        cents: amt(c.minted_cents as i64),
        collateral_zat: amt(c.collateral_zat),
        claim_height: c.claim_height as u64,
        claim_path: c.claim_path.clone(),
        p_claim_micro_usd: amt(c.p_claim),
        fee_zat: amt(c.fee_zat),
        attest_fee_zat: amt(c.attest_fee_zat),
        residual_zat: amt(c.residual_zat),
        claimant_zat: amt(c.claimant_zat),
        payee: c.payee.clone(),
    }
}

/// `claim_preview`: the row the user confirms, with the bounds the confirm will hold the
/// server to (H-9.3).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimPreview {
    pub preview_id: String,
    pub item: ClaimableItem,
    pub max_burn_cents: String,
    pub min_out_zat: String,
}

/// `redeem_preview` (`api::RedeemPreview`).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedeemPreview {
    pub preview_id: String,
    pub vault_txid: String,
    pub kind: String,
    pub burn_cents: String,
    pub extra_burn_cents: String,
    pub change_cents: String,
    pub yed_inputs: u32,
    pub fee_zat: String,
    pub payee: String,
    pub collateral_zat: String,
    pub collateral_address: String,
    pub lock_time: u64,
    pub expiry_height: u64,
    pub txid: String,
}

pub fn redeem_preview(id: String, p: &RedeemBuild) -> RedeemPreview {
    RedeemPreview {
        preview_id: id.clone(),
        vault_txid: p.vault_txid.clone(),
        kind: p.kind.into(),
        burn_cents: amt(p.burn_cents as i64),
        extra_burn_cents: amt(p.extra_burn_cents as i64),
        change_cents: amt(p.change_cents as i64),
        yed_inputs: p.yed_inputs.len() as u32,
        fee_zat: amt(p.fee_zat),
        payee: p.payee.clone(),
        collateral_zat: amt(p.collateral_out),
        collateral_address: p.collateral_address.clone(),
        lock_time: p.lock_time as u64,
        expiry_height: p.expiry_height as u64,
        txid: id,
    }
}

/// `release_preview` (`api::ReleasePreview`).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleasePreview {
    pub preview_id: String,
    pub intent: String,
    pub value_zat: String,
    pub recipient_address: String,
    pub fee_zat: String,
    pub txid: String,
}

pub fn release_preview(id: String, p: &ReleaseBuild) -> ReleasePreview {
    ReleasePreview {
        preview_id: id.clone(),
        intent: format!("{}:{}", txid_hex(&p.intent.txid), p.intent.n),
        value_zat: amt(p.value),
        recipient_address: p.recipient_address.clone(),
        fee_zat: amt(params::FEE_ZAT),
        txid: id,
    }
}

/// `mint_availability` (`api::MintAvailability`).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MintAvailability {
    pub allowed: bool,
    pub reason: String,
    pub mint_requires_armed: bool,
    pub armed: bool,
    pub attest_status: String,
    pub mintable_classes: Vec<String>,
    pub enabled_classes: Vec<String>,
    pub halts: Vec<String>,
}

pub fn mint_availability(g: &MintGate, network: Network) -> MintAvailability {
    MintAvailability {
        allowed: g.blocked.is_none(),
        reason: g.blocked.clone().unwrap_or_default(),
        mint_requires_armed: g.requires_armed,
        armed: g.armed,
        attest_status: g.attest_status.clone(),
        mintable_classes: g.mintable_classes.iter().map(|c| c.to_string()).collect(),
        enabled_classes: network
            .enabled_classes()
            .map(|c| c.letter.to_string())
            .collect(),
        halts: g.halts.clone(),
    }
}

/// `validate_address` (`api::AddressCheck`).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddressCheck {
    pub valid: bool,
    pub kind: String,
    pub yellowback_form: bool,
    pub message: String,
}

pub fn validate_address(network: Network, address: &str) -> AddressCheck {
    let address = address.trim();
    if yew_core::shielded_keys::is_sapling_address(network, address) {
        return AddressCheck {
            valid: true,
            kind: "sapling".into(),
            yellowback_form: false,
            message: String::new(),
        };
    }
    match keys::parse_address(network, address) {
        Ok(a) => AddressCheck {
            valid: true,
            kind: match a.kind {
                keys::AddressKind::P2pkh(_) => "p2pkh".into(),
                keys::AddressKind::P2sh(_) => "p2sh".into(),
            },
            yellowback_form: a.yellowback_form,
            message: String::new(),
        },
        Err(e) => AddressCheck {
            valid: false,
            kind: String::new(),
            yellowback_form: false,
            message: e.to_string(),
        },
    }
}
