// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! Local checks of the economic terms a server supplies (audit G-1, G-2, G-9). The relay
//! computes `EstimateCollateral`, `GetFeePayee`, `ListClaimable` and `GetVault` from its own
//! index; the node then judges the transaction by the spec's rules. A lying server can make the
//! wallet build a MINT that fails MINT-2/5/8 — a VOID vault whose collateral stays locked until
//! a `lockHeight` the server chose — or a REDEEM / CLAIM that pays most of the collateral to a
//! "fee" payee. Everything the spec fixes per parameter set (`crate::params`) is therefore
//! recomputed here and compared before anything is signed; what cannot be checked locally
//! (the payee's eligibility `E(R)`, the price snapshot `xMint`) is documented in
//! `docs/trust.md`.
//!
//! Spec: `ycash-dd/doc/yellowback-spec.md` MINT-2 (`:422-423`), MINT-5 (`:428-429`), MINT-8
//! (`:433`), FEE-1 (`:350`), AFEE-1 (`:907`), "Required collateral" (`:330-331`), PRICE-2
//! (`:901-903`, `pMint = min(xMint, aMint)`), the vault script (`:153-160`).

use crate::bundle::Attestation;
use crate::net::rpc;
use crate::params::{
    self, Network, TermClass, LOCKTIME_THRESHOLD, REF_WINDOW, SIGMA_MULT_MAX_BPS,
    SIGMA_MULT_MIN_BPS,
};

use super::mint::MintError;

/// The node reports `requiredZat` rounded up to this granularity (`RequiredCollateralRounded`,
/// `ycash-dd/src/yellowback/math.h:127-135`): the server's figure must lie between the exact
/// ceiling and that rounding — less makes the mint VOID (MINT-5), more is not the rule.
pub const REQUIRED_GRANULARITY_ZAT: i64 = 1_000;

fn inconsistent(what: impl Into<String>) -> MintError {
    MintError::Inconsistent { what: what.into() }
}

/// The mint amount bounds of MINT-2 (`MIN_MINT ≤ cents ≤ MAX_MINT`, the network's `MAX_MINT`),
/// which also keeps `cents` inside the payload's `u32` (audit G-9).
pub fn check_cents(network: Network, cents: u64) -> Result<(), MintError> {
    let max = network.max_mint_cents();
    if !(params::MIN_MINT_CENTS..=max).contains(&cents) {
        return Err(MintError::BadAmount {
            cents,
            min: params::MIN_MINT_CENTS,
            max,
        });
    }
    debug_assert!(cents <= u32::MAX as u64);
    Ok(())
}

/// What the wallet says while the network has no mint price (`pMint` undefined, HALT-1).
pub const WAITING_FOR_PRICE: &str = "Waiting for a price: the attestors have not published a YEC price the network can mint at yet. Try again in a few blocks; redeeming is not affected.";

/// A `haltMask` name (`GetStats.haltMask`, the node's `HaltMaskNames`) in plain words, for the
/// mint screen; an unknown name is shown as it is.
pub fn halt_sentence(name: &str) -> String {
    match name {
        "NO_PRICE" => "there is no YEC price yet".into(),
        "GLOBAL_RATIO" => "the system's collateral ratio is below its safety floor, so only the most collateralised term classes can mint".into(),
        "DIVERGENCE" => "the short- and long-term YEC prices disagree too much to price a mint safely".into(),
        "NOT_ACTIVE" => "Yellowback is not active yet".into(),
        "PARTICIPATION" => "too few attestors are taking part".into(),
        "ENFORCEMENT" => "the network's enforcement check is not satisfied".into(),
        other => format!("an unrecognised halt ({other})"),
    }
}

/// A mint refusal identifier (`yed_mint`'s `mintpol-*`, as `mintBlockedReason` carries it) in
/// plain words; an unknown identifier is shown as it is.
pub fn mint_blocked_sentence(identifier: &str) -> String {
    let id = identifier.split(':').next().unwrap_or("").trim();
    match id {
        "mintpol-no-price" => WAITING_FOR_PRICE.into(),
        "mintpol-unarmed" => "Minting is paused: the price feed is not armed yet. Redeeming and claiming are not affected.".into(),
        "mintpol-global-ratio" => "Minting is paused for this term: the system's collateral ratio is below its safety floor, so only the most collateralised term classes can mint.".into(),
        "mintpol-divergence" => "Minting is paused: the short- and long-term YEC prices disagree too much to price a mint safely. Try again later.".into(),
        "mintpol-cap" => "Minting is paused: the YED supply cap is reached.".into(),
        "mintpol-not-active" => "Minting is not possible: Yellowback is not active on the network now.".into(),
        "" => "Minting is not possible now (the server gave no reason).".into(),
        _ => format!("Minting is not possible now ({identifier})."),
    }
}

/// The class `lock_blocks` falls in, or `bad-lock`.
pub fn class_for(network: Network, lock_blocks: u32) -> Result<&'static TermClass, MintError> {
    network
        .class_for_lock_blocks(lock_blocks)
        .ok_or(MintError::BadLock {
            lock_blocks,
            network,
        })
}

/// Check an `EstimateCollateral` answer for `(cents, lock_blocks)` at the wallet's `tip`
/// (audit G-1). Returns the term class the mint is in.
pub fn check_estimate(
    network: Network,
    tip: u64,
    cents: u64,
    lock_blocks: u32,
    e: &rpc::YedCollateralEstimate,
) -> Result<&'static TermClass, MintError> {
    check_cents(network, cents)?;
    let class = class_for(network, lock_blocks)?;
    // The node's own verdict on this mint (`mintBlocked`, cf. DigiByte v9.26.7 e18654a3): the
    // mint would be refused at the next block, so nothing else in the estimate is relied on.
    if e.mint_blocked {
        return Err(MintError::Blocked {
            reason: mint_blocked_sentence(&e.mint_blocked_reason),
        });
    }
    if e.term_class != class.letter {
        return Err(inconsistent(format!(
            "termClass {:?} for a lock of {lock_blocks} blocks (class {})",
            e.term_class, class.letter
        )));
    }
    // MINT-2's window: H − REF_WINDOW ≤ R ≤ H − 1 for the confirmation height H > tip.
    let r = e.ref_height;
    if r < 1 || r as u64 >= tip || (r as u64) + (REF_WINDOW as u64) < tip {
        return Err(inconsistent(format!(
            "refHeight {r} outside [tip − {REF_WINDOW}, tip − 1] at tip {tip}"
        )));
    }
    let r = r as u32;
    let lock_height = e.lock_height;
    if lock_height != r as i64 + lock_blocks as i64 {
        return Err(inconsistent(format!(
            "lockHeight {lock_height} is not refHeight {r} + {lock_blocks}"
        )));
    }
    let claim_height = e.claim_height;
    if claim_height != lock_height + network.grace() as i64 {
        return Err(inconsistent(format!(
            "claimHeight {claim_height} is not lockHeight {lock_height} + GRACE {}",
            network.grace()
        )));
    }
    if claim_height >= LOCKTIME_THRESHOLD as i64 {
        return Err(inconsistent(format!(
            "claimHeight {claim_height} at or above LOCKTIME_THRESHOLD"
        )));
    }
    if e.p_mint <= 0 {
        // No mint price yet (HALT-1): an honest state of the network, not a server fault.
        return Err(MintError::Blocked {
            reason: WAITING_FOR_PRICE.into(),
        });
    }
    if e.armed {
        // PRICE-2 (revised): pMint = min(xMint, aMint).
        let expected = e.x_mint.min(e.a_mint);
        if e.x_mint <= 0 || e.a_mint <= 0 || e.p_mint != expected {
            return Err(inconsistent(format!(
                "pMint {} is not min(xMint {}, aMint {})",
                e.p_mint, e.x_mint, e.a_mint
            )));
        }
    }
    if e.base_ratio_bps != class.base_ratio_bps {
        return Err(inconsistent(format!(
            "baseRatioBps {} for class {} (spec {})",
            e.base_ratio_bps, class.letter, class.base_ratio_bps
        )));
    }
    if e.sigma_mult_bps < SIGMA_MULT_MIN_BPS || e.sigma_mult_bps > SIGMA_MULT_MAX_BPS {
        return Err(inconsistent(format!(
            "sigmaMultBps {} outside [{SIGMA_MULT_MIN_BPS}, {SIGMA_MULT_MAX_BPS}]",
            e.sigma_mult_bps
        )));
    }
    let min_ratio = class.base_ratio_bps * e.sigma_mult_bps / params::BPS;
    if e.min_ratio_bps != min_ratio {
        return Err(inconsistent(format!(
            "minRatioBps {} is not baseRatioBps · sigmaMultBps / 10⁴ = {min_ratio}",
            e.min_ratio_bps
        )));
    }
    let local = params::required_zat(cents, min_ratio, e.p_mint)
        .ok_or_else(|| inconsistent("requiredZat unsatisfiable at this price (K14)"))?;
    if e.required_zat < local {
        return Err(inconsistent(format!(
            "requiredZat {} below the rule's {local} (the mint would be VOID)",
            e.required_zat
        )));
    }
    let rounded = local
        .checked_add(
            (REQUIRED_GRANULARITY_ZAT - local % REQUIRED_GRANULARITY_ZAT)
                % REQUIRED_GRANULARITY_ZAT,
        )
        .ok_or_else(|| inconsistent("requiredZat unsatisfiable at this price (K14)"))?;
    if e.required_zat > rounded {
        return Err(inconsistent(format!(
            "requiredZat {} above the rule's {local} (rounded {rounded})",
            e.required_zat
        )));
    }
    // rpcversion 8: the estimate's protocol fee (FEE-1′ of the debt at its pMint), when reported.
    check_protocol_fee(
        "EstimateCollateral",
        cents,
        e.p_mint,
        e.protocol_fee_cents,
        e.protocol_fee_zat,
    )?;
    Ok(class)
}

/// `pMint` against the bundle the wallet verified itself (audit G-1): `pMint ≤ aMint`, and
/// `aMint` is a quantile of the attested prices, so `pMint` can never exceed the highest
/// price in the bundle. A `pMint` above it means the server's `requiredZat` is below what the
/// node will compute from the same bundle (MINT-5 ⇒ VOID).
pub fn check_bundle_price(p_mint: i64, bundle: &[Attestation]) -> Result<(), MintError> {
    let max = bundle
        .iter()
        .map(|a| a.price_micro_usd as i64)
        .max()
        .ok_or_else(|| inconsistent("empty bundle"))?;
    if p_mint > max {
        return Err(inconsistent(format!(
            "pMint {p_mint} above every attested price in the bundle (max {max})"
        )));
    }
    Ok(())
}

/// FEE-1′ (rpcversion 8, D-Q-23) computed locally (audit G-2): the protocol fee of a debt of
/// `debt_cents` at the vault's mint price `p_mint`, 0 under FEE-0 (no payee). The server is never
/// asked for the figure; a server-reported one (`protocolFeeZat`, `feeZat`) is compared with
/// [`check_protocol_fee`].
pub fn protocol_fee(debt_cents: u64, p_mint: i64, payee: &str) -> Result<i64, MintError> {
    if payee.is_empty() {
        return Ok(0);
    }
    params::protocol_fee_zat(debt_cents, p_mint).ok_or_else(|| {
        inconsistent(format!(
            "pMint {p_mint} undefined: no protocol fee can be priced"
        ))
    })
}

/// A server's protocol-fee figure against FEE-1′ (audit G-2). `reported` 0 is "not reported".
pub fn check_protocol_fee(
    what: &str,
    debt_cents: u64,
    p_mint: i64,
    reported_cents: i64,
    reported_zat: i64,
) -> Result<(), MintError> {
    let cents = params::protocol_fee_cents(debt_cents);
    if reported_cents != 0 && reported_cents != cents {
        return Err(inconsistent(format!(
            "{what}: protocolFeeCents {reported_cents} for a debt of {debt_cents} cents (FEE-1′ gives {cents})"
        )));
    }
    if reported_zat != 0 {
        let local = params::protocol_fee_zat(debt_cents, p_mint).unwrap_or(-1);
        if reported_zat != local {
            return Err(inconsistent(format!(
                "{what}: protocolFeeZat {reported_zat} for a debt of {debt_cents} cents at pMint {p_mint} (FEE-1′ gives {local})"
            )));
        }
    }
    Ok(())
}

/// The attestor fee for a protocol fee (AFEE-1′), computed locally.
pub fn attest_fee(network: Network, fee_zat: i64, seqs: &[u16]) -> i64 {
    if seqs.is_empty() {
        0
    } else {
        params::attest_fee_zat_for(network, fee_zat)
    }
}

/// The vault upgrade's terms every YED script is built from (upgrade plan U-22, U-23): the
/// network's attestor set (both sets of every YED vault), `CLAIM_DELAY` and `GRACE`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VaultTerms {
    /// The YED attestor set id, internal byte order (as the V pushes it).
    pub attestor_set_id: [u8; 32],
    /// `CLAIM_DELAY`.
    pub claim_delay: i64,
    /// `GRACE`.
    pub grace: u32,
}

impl VaultTerms {
    /// The V of a new mint by `owner` at reference height `ref_height` (`YedVaultScript(P, owner,
    /// R)`, in-term plan IT-1, D-IT-15): `ownerHeight = appHeight = R + 1`.
    pub fn mint_vault_params(
        &self,
        owner: &crate::pq::PqKeyId,
        ref_height: u32,
    ) -> crate::vault::VaultParams {
        crate::vault::yed_mint_vault_params(
            &self.attestor_set_id,
            self.claim_delay,
            owner,
            ref_height,
        )
    }

    /// The V scriptPubKey of a new mint by `owner` at reference height `ref_height`.
    pub fn mint_vault_script(
        &self,
        owner: &crate::pq::PqKeyId,
        ref_height: u32,
    ) -> Result<Vec<u8>, MintError> {
        build_or_refuse(&self.mint_vault_params(owner, ref_height))
    }

    /// The V of an existing vault with the given branch heights (`YedVaultScriptAt`).
    pub fn vault_params_at(
        &self,
        owner: &crate::pq::PqKeyId,
        owner_height: u32,
        app_height: u32,
    ) -> crate::vault::VaultParams {
        crate::vault::yed_vault_params_at(
            &self.attestor_set_id,
            self.claim_delay,
            owner,
            owner_height as i64,
            app_height as i64,
        )
    }

    /// The V scriptPubKey of an existing vault with the given branch heights.
    pub fn vault_script_at(
        &self,
        owner: &crate::pq::PqKeyId,
        owner_height: u32,
        app_height: u32,
    ) -> Result<Vec<u8>, MintError> {
        build_or_refuse(&self.vault_params_at(owner, owner_height, app_height))
    }

    /// The pre-plan V of a vault locked until `lock_height` (`ownerHeight = lockHeight`,
    /// `appHeight = lockHeight + GRACE`): minted before the in-term rule, still spendable.
    pub fn pre_plan_vault_params(
        &self,
        owner: &crate::pq::PqKeyId,
        lock_height: u32,
    ) -> crate::vault::VaultParams {
        crate::vault::yed_vault_params(
            &self.attestor_set_id,
            self.claim_delay,
            self.grace,
            owner,
            lock_height,
        )
    }
}

fn build_or_refuse(p: &crate::vault::VaultParams) -> Result<Vec<u8>, MintError> {
    crate::vault::build_vault(p).ok_or_else(|| {
        inconsistent(format!(
            "the vault of ownerHeight {} / appHeight {} is outside the template's ranges",
            p.owner_height, p.app_height
        ))
    })
}

/// A YED vault's V as this wallet rebuilds it: its parameters (the branch heights) and its
/// scriptPubKey.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct YedV {
    /// The V parameters.
    pub params: crate::vault::VaultParams,
    /// `BuildVault(params)`.
    pub script: Vec<u8>,
}

impl YedV {
    /// `ownerHeight`: the owner's redeem is valid from here (the redeem's `nLockTime`).
    pub fn owner_height(&self) -> u32 {
        self.params.owner_height as u32
    }
    /// `appHeight`: the claim branch is open from here (the claim's `nLockTime`).
    pub fn app_height(&self) -> u32 {
        self.params.app_height as u32
    }
}

/// The [`VaultTerms`] of a server (`GetYellowbackInfo`, rpcversion 5), checked: the upgrade is
/// reported with `CLAIM_DELAY` equal to the network's, the attestor set is a 32-byte id equal in
/// `params` and `upgrade`, and on a network that compiles its set in (none yet: mainnet and
/// testnet are unset, P8) equal to that. Regtest takes the server's set (`-yellowbackattestorset`).
pub fn vault_terms(network: Network, info: &rpc::YellowbackInfo) -> Result<VaultTerms, MintError> {
    let p = info
        .params
        .as_ref()
        .ok_or_else(|| inconsistent("GetYellowbackInfo carries no params"))?;
    if p.claim_delay != network.claim_delay() {
        return Err(inconsistent(format!(
            "params.claimDelay {} (this network's CLAIM_DELAY is {})",
            p.claim_delay,
            network.claim_delay()
        )));
    }
    let set = crate::tx::txid_from_hex(&p.attestor_set_id).map_err(|_| {
        inconsistent(format!(
            "params.attestorSetId {:?} is not a set id (Yellowback is off without one)",
            p.attestor_set_id
        ))
    })?;
    if set == [0; 32] {
        return Err(inconsistent(
            "params.attestorSetId is null: Yellowback is off",
        ));
    }
    if let Some(u) = info.upgrade.as_ref() {
        if !u.attestor_set_id.is_empty() && u.attestor_set_id != p.attestor_set_id {
            return Err(inconsistent(format!(
                "upgrade.attestorSetId {} differs from params.attestorSetId {}",
                u.attestor_set_id, p.attestor_set_id
            )));
        }
        if u.claim_delay != 0 && u.claim_delay != p.claim_delay {
            return Err(inconsistent(format!(
                "upgrade.claimDelay {} differs from params.claimDelay {}",
                u.claim_delay, p.claim_delay
            )));
        }
        if !u.branch_id.is_empty()
            && u32::from_str_radix(&u.branch_id, 16).ok() != Some(params::VAULT_BRANCH_ID)
        {
            return Err(inconsistent(format!(
                "upgrade.branchId {} is not the vault upgrade's {:08x}",
                u.branch_id,
                params::VAULT_BRANCH_ID
            )));
        }
    }
    if let Some(compiled) = network.attestor_set_id() {
        if compiled != set {
            return Err(inconsistent(format!(
                "params.attestorSetId {} is not {}'s attestor set",
                p.attestor_set_id,
                network.chain_name()
            )));
        }
    }
    Ok(VaultTerms {
        attestor_set_id: set,
        claim_delay: network.claim_delay(),
        grace: network.grace(),
    })
}

/// A `GetVault` record's post-quantum owner (quantum spec §1, §3.4, §6.2): `ownerScheme` (a
/// registered scheme) and `ownerHash` (32 bytes, hex). **The one place the record's owner field
/// is read.** rpcversion 7 removed `ownerPubKey`/`ownerKeyId`: no public key is on chain.
pub fn vault_owner(v: &rpc::YedVault) -> Result<crate::pq::PqKeyId, MintError> {
    let bad = || inconsistent(format!("vault {}: owner", v.txid));
    let scheme = u8::try_from(v.owner_scheme).map_err(|_| bad())?;
    let hash: [u8; 32] = crate::keys::unhex(&v.owner_hash)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(bad)?;
    Some(crate::pq::PqKeyId { scheme, hash })
        .filter(|o| o.is_known())
        .ok_or_else(bad)
}

/// A `GetVault` record's V script (rpcversion 5, U-23; rpcversion 6, in-term IT-1): the node's
/// `scriptPubKey` must be the YED vault this wallet rebuilds from the owner key and the
/// [`VaultTerms`] — the in-term mint's V (`ownerHeight = appHeight = refHeight + 1`) or, for a
/// vault minted before the in-term rule, the pre-plan V of its `lockHeight` — the script it
/// will sign against (owner) or name in its claim intents (claimant). Returns it with its
/// branch heights.
pub fn check_vault_script(t: &VaultTerms, v: &rpc::YedVault) -> Result<YedV, MintError> {
    let owner = vault_owner(v)?;
    let theirs = v.script_pub_key.to_ascii_lowercase();
    let mut candidates = Vec::new();
    if let Ok(r) = u32::try_from(v.ref_height) {
        candidates.push(t.mint_vault_params(&owner, r));
    }
    if let Ok(l) = u32::try_from(v.lock_height) {
        candidates.push(t.pre_plan_vault_params(&owner, l));
    }
    for params in candidates {
        if let Some(script) = crate::vault::build_vault(&params) {
            if crate::keys::hex(&script) == theirs {
                return Ok(YedV { params, script });
            }
        }
    }
    Err(inconsistent(format!(
        "vault {}: scriptPubKey is not the YED vault of its owner, refHeight and lockHeight",
        v.txid
    )))
}

/// A `GetVault` record's script terms (audit G-1, `sync::refresh_vaults`): `claimHeight =
/// lockHeight + GRACE`, and for a vault the node holds ACTIVE, `lockHeight − refHeight` inside
/// the class it reports.
pub fn check_vault(network: Network, v: &rpc::YedVault) -> Result<(), MintError> {
    if v.claim_height != v.lock_height + network.grace() as i64 {
        return Err(inconsistent(format!(
            "vault {}: claimHeight {} is not lockHeight {} + GRACE {}",
            v.txid,
            v.claim_height,
            v.lock_height,
            network.grace()
        )));
    }
    if v.claim_height >= LOCKTIME_THRESHOLD as i64 || v.lock_height <= 0 {
        return Err(inconsistent(format!(
            "vault {}: lockHeight {} / claimHeight {} out of range",
            v.txid, v.lock_height, v.claim_height
        )));
    }
    // rpcversion 8: the stored mint price every fee of the vault is struck at. MINT-5 put at least
    // `mintedCents · baseRatio · COIN / pMint` in the vault, so pMint ≥ that over the collateral: a
    // server reporting a lower price (a higher fee in YEC) is refused; a higher one only makes the
    // fee short, which the node's own check refuses before anything is sent.
    if v.status == "ACTIVE" || v.status == "CLAIMING" {
        if v.p_mint <= 0 || v.p_mint > params::PRICE_MAX_MICRO_USD {
            return Err(inconsistent(format!(
                "vault {}: pMint {} out of range (rpcversion 8)",
                v.txid, v.p_mint
            )));
        }
        if let Some(c) = network
            .term_classes()
            .iter()
            .find(|c| c.letter == v.term_class)
        {
            let floor = (v.minted_cents.max(0) as u128)
                * (c.base_ratio_bps as u128)
                * (params::COIN as u128)
                / (v.collateral_zat.max(1) as u128);
            if (v.p_mint as u128) < floor {
                return Err(inconsistent(format!(
                    "vault {}: pMint {} below what its collateral {} backs {} cents at in class {} ({floor})",
                    v.txid, v.p_mint, v.collateral_zat, v.minted_cents, c.letter
                )));
            }
        }
    }
    if v.status == "ACTIVE" {
        let lock_blocks = v.lock_height - v.ref_height;
        let class = u32::try_from(lock_blocks)
            .ok()
            .and_then(|b| network.class_for_lock_blocks(b));
        match class {
            Some(c) if c.letter == v.term_class => {}
            _ => {
                return Err(inconsistent(format!(
                    "vault {}: a lock of {lock_blocks} blocks is not class {:?}",
                    v.txid, v.term_class
                )))
            }
        }
    }
    Ok(())
}

/// The post-quantum and network-fee terms a server reports (`GetYellowbackInfo.params.pq`,
/// `params.fees.network` and `attest.mintPayloadVersion`; rpcversion 7, 8; quantum spec §6.2, fees
/// spec §3.1, client survey C-5): the size fee rates, the flat floor, the cap and the Falcon
/// activation. Unlike the rest of the parameter set these are the node's *operator* settings
/// (`-pqfeeusdperkb`, `-yellowbackfeeusdperkb`, `-pqfeerate`, `-yellowbackmaxtxfee`) at the attested
/// tip price, and a height, so they are read, bounded and recomputed from their own inputs, not
/// compared with a compiled value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PqTerms {
    /// The plain post-quantum rate, zat/KB (`fees.network.plain.zatPerKB` = `pq.feeRateZatPerKB`):
    /// a move of a post-quantum YEC coin.
    pub fee_rate_zat_per_kb: i64,
    /// The vault / Yellowback rate, zat/KB (`fees.network.yellowback.zatPerKB`): every transaction
    /// the node's YED builder or a `vault_*` RPC would price (mint, redeem, claim, transfer, release).
    pub yed_rate_zat_per_kb: i64,
    /// The floor rate the owner path falls back to when the dollar-priced fee would take what the
    /// vault has left (`YedFloorSizeFee`, review L-1): `max(floorZatPerKB, -pqfeerate)` with a price,
    /// `-pqfeerate` without one.
    pub floor_rate_zat_per_kb: i64,
    /// The flat floor of one transaction (`fees.network.flatZat`, = `params.feeZat`).
    pub flat_zat: i64,
    /// The cap of a size-priced fee (`fees.network.yellowback.maxTxFeeZat`), never above
    /// [`params::MAX_YED_TX_FEE_ZAT`].
    pub max_fee_zat: i64,
    /// `pq.falconHeight` (`None` = no activation height). Mainnet and testnet must report the
    /// height compiled into this build ([`Network::pq_falcon_height`], `0` by the owner's decision
    /// of 2026-10-10); [`pq_terms`] refuses a server that reports another.
    pub falcon_height: Option<u64>,
    /// `pq.falconActive` as the node judged it (at its next block).
    pub falcon_active: bool,
}

impl Default for PqTerms {
    /// Before a server has answered: the relay floor, the flat fee, the absolute cap, Falcon
    /// unknown (treated as inactive; the node's dry run judges `TOK-PQ` before anything is sent).
    fn default() -> PqTerms {
        PqTerms {
            fee_rate_zat_per_kb: params::RELAY_FLOOR_ZAT_PER_KB,
            yed_rate_zat_per_kb: params::RELAY_FLOOR_ZAT_PER_KB,
            floor_rate_zat_per_kb: params::RELAY_FLOOR_ZAT_PER_KB,
            flat_zat: params::FEE_ZAT,
            max_fee_zat: params::MAX_YED_TX_FEE_ZAT,
            falcon_height: None,
            falcon_active: false,
        }
    }
}

impl PqTerms {
    /// The terms before any server has answered on `network`: [`PqTerms::default`] with the
    /// network's compiled Falcon activation ([`Network::pq_falcon_height`]; mainnet and testnet
    /// active from height 0, so an offline wallet's YED holder is a Falcon key from the start).
    /// Regtest: Falcon unknown (inactive) until the server says otherwise.
    pub fn default_for(network: Network) -> PqTerms {
        let mut t = PqTerms::default();
        if let Some(h) = network.pq_falcon_height() {
            t.falcon_height = Some(h);
            t.falcon_active = h == 0;
        }
        t
    }

    /// Falcon (scheme 2) and `TOK-PQ` apply to a transaction mined at `height`
    /// (`IsPQFalconActive(params, nHeight)`: `nHeight >= pqFalconHeight`; R-A2), or the node
    /// already said so.
    pub fn falcon_at(&self, height: u64) -> bool {
        self.falcon_active || self.falcon_height.is_some_and(|h| height >= h)
    }

    /// The network fee of a transaction of `size` bytes with a post-quantum input, at the plain
    /// rate (`CWallet::CreateTransaction`: `min(max(DEFAULT_FEE, PQSizeFee), PQMaxTxFee())`).
    pub fn fee(&self, size: usize) -> i64 {
        params::pq_size_fee(self.flat_zat, self.fee_rate_zat_per_kb, size)
            .min(self.max_fee_zat)
            .max(self.flat_zat)
    }

    /// The network fee of a Yellowback transaction of `size` bytes (`YedNetworkFee`:
    /// `max(flat, min(YedSizeFee(flat, size), YedMaxTxFee()))`), `size` as the node estimates it
    /// ([`params::yed_estimated_size`]).
    pub fn yed_fee(&self, size: usize) -> i64 {
        params::rate_fee(self.yed_rate_zat_per_kb, size)
            .max(self.flat_zat)
            .min(self.max_fee_zat)
            .max(self.flat_zat)
    }

    /// The network fee of a Yellowback transaction with `other_inputs` non-PQ inputs and the
    /// post-quantum inputs `pq_schemes` (`YedNetworkFee`): [`PqTerms::yed_fee`] at
    /// [`params::yed_estimated_size`], never below [`params::yed_conventional_fee_estimate`] (the
    /// 6.20.0 line's ZIP-317 conventional fee, audit 04/N-1; 0 without a PQ input), which, as on
    /// the node, stands outside the cap.
    pub fn yed_network_fee(&self, other_inputs: usize, pq_schemes: &[u8]) -> i64 {
        self.yed_fee(params::yed_estimated_size(other_inputs, pq_schemes))
            .max(params::yed_conventional_fee_estimate(
                other_inputs,
                pq_schemes,
            ))
    }

    /// The owner path's clamp (`YedFloorSizeFee`, review L-1): `max(flat, floor rate × size)`.
    pub fn yed_floor_fee(&self, size: usize) -> i64 {
        params::rate_fee(self.floor_rate_zat_per_kb, size).max(self.flat_zat)
    }
}

/// Read and bound `params.pq` (rpcversion 7) and `params.fees.network` (rpcversion 8). Refused: no
/// `pq` or no `fees.network` block; a scheme list without SLH-DSA (1), or with Falcon (2) while
/// Falcon is inactive, or naming an unknown scheme; a MINT payload version other than this build's
/// ([`crate::payload::MINT_VERSION`]); a dollar target above [`params::MAX_USD_PER_KB_MICRO`], a
/// floor above [`params::MAX_FEE_FLOOR_ZAT_PER_KB`], a fallback rate outside
/// `0..=`[`params::MAX_PQ_FEE_RATE_ZAT_PER_KB`], a price outside `PRICE_MAX`, a flat fee below
/// `FEE_ZAT`; **a rate that is not its own inputs' `AttestedRateZatPerKB`** — so a server can
/// report a high price target only in the open, never a padded zat figure; and on mainnet and
/// testnet **a Falcon activation other than this build's** ([`check_falcon_activation`]).
pub fn pq_terms(p: &rpc::YellowbackParams, network: Network) -> Result<PqTerms, MintError> {
    let pq =
        p.pq.as_ref()
            .ok_or_else(|| inconsistent("params.pq missing (rpcversion 7)"))?;
    check_falcon_activation(network, pq)?;
    if !pq
        .schemes
        .contains(&(crate::pq::SCHEME_SLH_DSA_SHA2_128S as i64))
        || pq
            .schemes
            .iter()
            .any(|&s| !u8::try_from(s).is_ok_and(crate::pq::is_known_scheme))
        || (pq.schemes.contains(&(crate::pq::SCHEME_FN_DSA_512 as i64)) && !pq.falcon_active)
    {
        return Err(inconsistent(format!(
            "params.pq.schemes {:?} (falconActive {})",
            pq.schemes, pq.falcon_active
        )));
    }
    if let Some(a) = p.attest.as_ref() {
        if a.mint_payload_version != crate::payload::MINT_VERSION as i64 {
            return Err(inconsistent(format!(
                "params.attest.mintPayloadVersion {} (this build writes {})",
                a.mint_payload_version,
                crate::payload::MINT_VERSION
            )));
        }
    }
    let n = p
        .fees
        .as_ref()
        .and_then(|f| f.network.as_ref())
        .ok_or_else(|| inconsistent("params.fees.network missing (rpcversion 8)"))?;
    let bad = |what: String| Err(inconsistent(format!("params.fees.network.{what}")));
    if n.fallback_zat_per_kb < 0 || n.fallback_zat_per_kb > params::MAX_PQ_FEE_RATE_ZAT_PER_KB {
        return bad(format!(
            "fallbackZatPerKB {} (YEW accepts 0..={})",
            n.fallback_zat_per_kb,
            params::MAX_PQ_FEE_RATE_ZAT_PER_KB
        ));
    }
    if n.floor_zat_per_kb < 0 || n.floor_zat_per_kb > params::MAX_FEE_FLOOR_ZAT_PER_KB {
        return bad(format!(
            "floorZatPerKB {} (YEW accepts 0..={})",
            n.floor_zat_per_kb,
            params::MAX_FEE_FLOOR_ZAT_PER_KB
        ));
    }
    if n.price_micro_usd < 0 || n.price_micro_usd > params::PRICE_MAX_MICRO_USD {
        return bad(format!("priceMicroUsd {}", n.price_micro_usd));
    }
    if n.flat_zat < params::FEE_ZAT || n.flat_zat > params::MAX_YED_TX_FEE_ZAT {
        return bad(format!(
            "flatZat {} (at least {})",
            n.flat_zat,
            params::FEE_ZAT
        ));
    }
    let floor_eff = n.floor_zat_per_kb.max(n.fallback_zat_per_kb);
    // AttestedRateZatPerKB, or the -pqfeerate fallback without a price or a target (policy.cpp
    // PlainPQFeeRate / YedFeeRate)
    let rate_of = |what: &str, r: Option<&rpc::YellowbackNetworkRate>| -> Result<i64, MintError> {
        let r = r.ok_or_else(|| inconsistent(format!("params.fees.network.{what} missing")))?;
        if r.usd_per_kb_micro < 0 || r.usd_per_kb_micro > params::MAX_USD_PER_KB_MICRO {
            return Err(inconsistent(format!(
                "params.fees.network.{what}.usdPerKBMicro {} (YEW accepts 0..={})",
                r.usd_per_kb_micro,
                params::MAX_USD_PER_KB_MICRO
            )));
        }
        let want = if n.price_micro_usd > 0 && r.usd_per_kb_micro > 0 {
            params::attested_rate_zat_per_kb(r.usd_per_kb_micro, n.price_micro_usd, floor_eff)
        } else {
            n.fallback_zat_per_kb
        };
        if r.zat_per_kb != want {
            return Err(inconsistent(format!(
                "params.fees.network.{what}.zatPerKB {} (${}.{:06}/KB at {} µUSD gives {want})",
                r.zat_per_kb,
                r.usd_per_kb_micro / 1_000_000,
                r.usd_per_kb_micro % 1_000_000,
                n.price_micro_usd
            )));
        }
        Ok(want.max(params::RELAY_FLOOR_ZAT_PER_KB))
    };
    let plain = rate_of("plain", n.plain.as_ref())?;
    let yed = rate_of("yellowback", n.yellowback.as_ref())?;
    // rpcversion 8: pq.feeRateZatPerKB is the plain rate, so rpcversion-7 readers keep working
    if pq.fee_rate_zat_per_kb.max(params::RELAY_FLOOR_ZAT_PER_KB) != plain {
        return Err(inconsistent(format!(
            "params.pq.feeRateZatPerKB {} is not params.fees.network.plain.zatPerKB {plain}",
            pq.fee_rate_zat_per_kb
        )));
    }
    let cap = n.yellowback.as_ref().map(|y| y.max_tx_fee_zat).unwrap_or(0);
    if cap < n.flat_zat {
        return bad(format!(
            "yellowback.maxTxFeeZat {cap} (below flatZat {})",
            n.flat_zat
        ));
    }
    Ok(PqTerms {
        fee_rate_zat_per_kb: plain,
        yed_rate_zat_per_kb: yed,
        floor_rate_zat_per_kb: if n.price_micro_usd > 0 {
            floor_eff
        } else {
            n.fallback_zat_per_kb
        }
        .max(params::RELAY_FLOOR_ZAT_PER_KB),
        flat_zat: n.flat_zat,
        max_fee_zat: cap.min(params::MAX_YED_TX_FEE_ZAT),
        falcon_height: u64::try_from(pq.falcon_height).ok(),
        falcon_active: pq.falcon_active,
    })
}

/// The server's Falcon activation (`params.pq.falconHeight` / `falconActive`) against the height
/// compiled into this build ([`Network::pq_falcon_height`]; ycash-dd and ycash6
/// `chainparams.cpp` `pqFalconHeight`). Mainnet and testnet: the height must be the compiled one,
/// and at height 0 Falcon must be active; anything else is [`MintError::Inconsistent`] — the
/// wallet refuses the server's YED terms rather than override them (a server whose node does not
/// enforce `TOK-PQ` would otherwise be handed Falcon holder shapes it does not accept, or the
/// reverse). Regtest follows the server (`-pqfalconheight`).
pub fn check_falcon_activation(
    network: Network,
    pq: &rpc::YellowbackPqParams,
) -> Result<(), MintError> {
    let Some(expected) = network.pq_falcon_height() else {
        return Ok(());
    };
    let height = u64::try_from(pq.falcon_height).ok();
    if height != Some(expected) || (expected == 0 && !pq.falcon_active) {
        return Err(inconsistent(format!(
            "params.pq.falconHeight {} / falconActive {} (this build expects {expected} / active on {})",
            pq.falcon_height,
            pq.falcon_active,
            network.chain_name()
        )));
    }
    Ok(())
}

/// A `params.fees` block before any attested price (both size rates `-pqfeerate` = `rate`), for
/// tests that feed `Wallet::note_server_params`.
#[cfg(test)]
pub(crate) fn fallback_fee_params(rate: i64) -> rpc::YellowbackFeeParams {
    rpc::YellowbackFeeParams {
        network: Some(rpc::YellowbackNetworkFee {
            price_source: "fallback".into(),
            plain: Some(rpc::YellowbackNetworkRate {
                usd_per_kb_micro: 20_000,
                zat_per_kb: rate,
                ..Default::default()
            }),
            yellowback: Some(rpc::YellowbackNetworkRate {
                usd_per_kb_micro: 50_000,
                zat_per_kb: rate,
                max_tx_fee_zat: 10_000_000,
                ..Default::default()
            }),
            floor_zat_per_kb: params::ATTESTED_FEE_FLOOR_ZAT_PER_KB,
            fallback_zat_per_kb: rate,
            flat_zat: params::FEE_ZAT,
            max_tx_fee_zat: 10_000_000,
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// The parameter set a server reports (`GetYellowbackInfo.params`) against the one this build
/// compiles for the network (audit G-1, G-2; hardening H-9.3 "recompute the fee floor and the
/// height identities locally"). The wallet never prices a mint, a fee or a deadline from the
/// server's figures; this check only refuses a server whose node runs another parameter set
/// (a stale release, a hand-edited one, a lie), because every local check below would then
/// disagree with the node that judges the transaction. Compared: the protocol fee's bands and
/// floor (rpcversion 8, FEE-1′), `MAX_MINT`, `GRACE`, `REF_WINDOW`, `TOKEN_VALUE`, `ATTEST_FEE_BPS`,
/// `RESIDUAL_MIN_ZAT`, the per-vault share (MINT-6b) and each term
/// class's range and base ratio (a disabled class is reported with its empty range, H-5).
/// Values a regtest flag sets (`startHeight`, `enforceUntilHeight`, `sigmaRefBps`,
/// `supplyCapBps`) are not compared.
pub fn check_server_params(
    network: Network,
    p: Option<&rpc::YellowbackParams>,
) -> Result<(), MintError> {
    let p = p.ok_or_else(|| inconsistent("GetYellowbackInfo carries no params"))?;
    let want = |what: &str, got: i64, local: i64| -> Result<(), MintError> {
        if got != local {
            return Err(inconsistent(format!(
                "params.{what} {got} (this network's rule is {local})"
            )));
        }
        Ok(())
    };
    // rpcversion 8 (D-Q-23, D-Q-24, D-Q-23a): FEE-1′'s bands and floor, maxMint, the vault share
    want(
        "maxMintCents",
        p.max_mint_cents,
        network.max_mint_cents() as i64,
    )?;
    let fees = p
        .fees
        .as_ref()
        .ok_or_else(|| inconsistent("params.fees missing (rpcversion 8)"))?;
    let protocol = fees
        .protocol
        .as_ref()
        .ok_or_else(|| inconsistent("params.fees.protocol missing"))?;
    let bands: Vec<(i64, i64)> = protocol
        .bands
        .iter()
        .map(|b| (b.upto_cents, b.bps))
        .collect();
    let local_bands: Vec<(i64, i64)> = params::PROTOCOL_FEE_BANDS
        .iter()
        .map(|(u, b)| (*u as i64, *b))
        .collect();
    if bands != local_bands {
        return Err(inconsistent(format!(
            "params.fees.protocol.bands {bands:?} (this network's rule is {local_bands:?})"
        )));
    }
    want(
        "fees.protocol.floorCents",
        protocol.floor_cents,
        params::PROTOCOL_FEE_FLOOR_CENTS,
    )?;
    want(
        "fees.protocol.attestFeeBps",
        protocol.attest_fee_bps,
        network.attest_fee_bps(),
    )?;
    if let Some(sc) = p.supply_cap.as_ref() {
        want(
            "supplyCap.maxVaultShareBps",
            sc.max_vault_share_bps,
            params::MAX_VAULT_SHARE_BPS,
        )?;
        want(
            "supplyCap.vaultShareFloorCents",
            sc.vault_share_floor_cents,
            params::VAULT_SHARE_FLOOR_CENTS,
        )?;
    }
    want("grace", p.grace, network.grace() as i64)?;
    want("refWindow", p.ref_window, REF_WINDOW as i64)?;
    want("tokenValueZat", p.token_value_zat, params::TOKEN_VALUE)?;
    // rpcversion 5 (U-23): CLAIM_DELAY is the YED vault's delay, part of every vault script.
    want("claimDelay", p.claim_delay, network.claim_delay())?;
    // rpcversion 6 (in-term plan IT-7, IT-9): this build implements the in-term rule set — a claim
    // is judged by θ at every height, the owner redeems at any height with the early-redeem fee
    // before lockHeight. A server whose node runs another rule set is refused.
    if !p.in_term_claims {
        return Err(inconsistent(
            "params.inTermClaims is false: the node does not run the in-term claims rules this wallet implements",
        ));
    }
    want(
        "claimThresholdBps",
        p.claim_threshold_bps,
        params::CLAIM_THRESHOLD_BPS,
    )?;
    want("sigmaMultMaxBps", p.sigma_mult_max_bps, SIGMA_MULT_MAX_BPS)?;
    let local: Vec<i64> = network
        .term_classes()
        .iter()
        .map(|c| c.early_redeem_fee_bps)
        .collect();
    if p.early_redeem_fee_bps != local {
        return Err(inconsistent(format!(
            "params.earlyRedeemFeeBps {:?} (this network's rule is {local:?})",
            p.early_redeem_fee_bps
        )));
    }
    if fees.early_redeem_fee_bps != local {
        return Err(inconsistent(format!(
            "params.fees.earlyRedeemFeeBps {:?} (this network's rule is {local:?})",
            fees.early_redeem_fee_bps
        )));
    }
    let a = p
        .attest
        .as_ref()
        .ok_or_else(|| inconsistent("params.attest missing"))?;
    want(
        "attest.attestFeeBps",
        a.attest_fee_bps,
        network.attest_fee_bps(),
    )?;
    want(
        "attest.residualMinZat",
        a.residual_min_zat,
        params::RESIDUAL_MIN_ZAT,
    )?;
    // rpcversion 7, 8: the post-quantum and network-fee blocks must be present and sane (read and
    // recomputed from their own inputs, not compared).
    pq_terms(p, network)?;
    for c in network.term_classes() {
        let s = p
            .classes
            .iter()
            .find(|s| s.class == c.letter)
            .ok_or_else(|| inconsistent(format!("params.classes has no class {}", c.letter)))?;
        want(
            &format!("classes.{}.minBlocks", c.letter),
            s.min_blocks,
            c.min_blocks as i64,
        )?;
        want(
            &format!("classes.{}.maxBlocks", c.letter),
            s.max_blocks,
            c.max_blocks as i64,
        )?;
        want(
            &format!("classes.{}.baseRatioBps", c.letter),
            s.base_ratio_bps,
            c.base_ratio_bps,
        )?;
        want(
            &format!("classes.{}.earlyRedeemFeeBps", c.letter),
            s.early_redeem_fee_bps,
            c.early_redeem_fee_bps,
        )?;
    }
    Ok(())
}

/// Whether a mint can be made now, and why not (hardening H-1, H-5, H-9.2; the Mint screen's
/// gate). Built from `GetYellowbackInfo`, `GetPrice` (tip) and `GetStats` by [`mint_gate`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MintGate {
    /// `MINT_REQUIRES_ARMED`: the network's fixed value (mainnet, testnet: true), or on regtest
    /// the server's `mintRequiresArmed`.
    pub requires_armed: bool,
    /// `GetPrice.armed` at the index tip.
    pub armed: bool,
    /// `GetPrice.attestStatus` (`"ARMED"`, `"PENDING"`, `"DISARMED"`, ...).
    pub attest_status: String,
    /// The classes a mint can use now: `GetStats.mintableClasses`, each one a class this build
    /// has enabled for the network. Empty = no class mintable.
    pub mintable_classes: Vec<&'static str>,
    /// `GetStats.haltMask` names.
    pub halts: Vec<String>,
    /// `None` when a mint may be made; otherwise the reason, as the screen shows it.
    pub blocked: Option<String>,
}

/// The mint gate (pure; the network calls are the caller's). A server listing a class this
/// build has disabled for the network (H-5: B or C on mainnet) is refused as inconsistent.
pub fn mint_gate(
    network: Network,
    info: &rpc::YellowbackInfo,
    price: &rpc::YedPrice,
    stats: &rpc::YellowbackStats,
) -> Result<MintGate, MintError> {
    let requires_armed = network
        .mint_requires_armed()
        .unwrap_or(info.mint_requires_armed)
        || info.mint_requires_armed;
    let mut mintable_classes = Vec::new();
    for letter in &stats.mintable_classes {
        let class = network
            .enabled_classes()
            .find(|c| c.letter == letter)
            .ok_or_else(|| {
                inconsistent(format!(
                    "mintableClasses lists class {letter:?}, which {} does not enable",
                    network.chain_name()
                ))
            })?;
        if !mintable_classes.contains(&class.letter) {
            mintable_classes.push(class.letter);
        }
    }
    let active = info
        .upgrade
        .as_ref()
        .is_some_and(|a| a.status == crate::net::yellowback::STATUS_ACTIVE);
    // TOK-PQ (quantum spec §3.6, F-7): from the Falcon height a MINT's token goes to the
    // wallet's Falcon holder key (`build::mint::mint_token_script`); nothing blocks here.
    let blocked = if !info.enabled || !active {
        Some("Yellowback is not active on this server's node: nothing can be minted.".to_string())
    } else if requires_armed && !price.armed {
        Some(format!(
            "Minting is paused: the price feed is not armed (attestation {}). The node refuses every mint until enough attestors arm it. Redeeming and claiming are not affected.",
            if price.attest_status.is_empty() { "status unknown" } else { price.attest_status.as_str() }
        ))
    } else if mintable_classes.is_empty() {
        Some(if stats.halt_mask.iter().any(|h| h == "NO_PRICE") {
            WAITING_FOR_PRICE.to_string()
        } else if !stats.halt_mask.is_empty() {
            let why: Vec<String> = stats.halt_mask.iter().map(|h| halt_sentence(h)).collect();
            format!(
                "Minting is paused: {}. No term class can mint now; redeeming is not affected.",
                why.join("; ")
            )
        } else {
            // The cap (W20, H-10) or the recapitalisation floor (W16) leaves no class.
            "No term class is mintable now (the supply cap or the recapitalisation floor excludes every class).".to_string()
        })
    } else {
        None
    };
    Ok(MintGate {
        requires_armed,
        armed: price.armed,
        attest_status: price.attest_status.clone(),
        mintable_classes,
        halts: stats.halt_mask.clone(),
        blocked,
    })
}

/// A `ListClaimable` row's RED-5 residual against the vault's terms (audit G-2; `ClaimAt`): a
/// server inflating the residual moves the claimant's YEC to the owner. Returns the residual the
/// CLAIM pays: the node builder's (`ClaimAt` drops a residual below `RESIDUAL_MIN_ZAT`;
/// `yed_listclaimable` reports it unfloored, so both are accepted).
///
/// Clause `"a"` sizes the claimant cap at the row's `pClaim` with `claimThresholdBps`, and the
/// vault must also be underwater at that `pClaim` (`IsUnderwater`). Clause `"b"` sizes it at
/// `p_emerg` (`min(xClaim, aClaim)`, RED-5b A1) with margin `10⁴` and does **not** cross-check
/// the residual at `pClaim` — that figure rejects every honest path-(b) claim. `p_emerg` is
/// `None` when the row carries neither `pEmerg` nor both inputs; the path-(b) build is then
/// refused.
pub fn check_claimable(c: &rpc::YedClaimable, p_emerg: Option<i64>) -> Result<i64, MintError> {
    // rpcversion 6 (in-term IT-7): a row above θ is listed with `claimable: false`, no claim path
    // and no residual; it is shown, never claimed, so nothing in it is relied on.
    if !c.claimable {
        return Ok(0);
    }
    if c.claim_path != "a" && c.claim_path != "b" {
        return Err(inconsistent(format!(
            "claimPath {:?} for vault {}",
            c.claim_path, c.vault
        )));
    }
    if c.minted_cents <= 0 || c.collateral_zat <= 0 {
        return Err(inconsistent(format!(
            "vault {} has no debt or no collateral",
            c.vault
        )));
    }
    let cents = c.minted_cents as u64;
    // RED-5b (A1): path (b) at pEmerg. The ListClaimable row does not carry pEmerg, xClaim or
    // aClaim; the caller passes pEmerg computed as min(xClaim, aClaim) when those exist.
    let price = if c.claim_path == "b" {
        p_emerg.filter(|p| *p > 0).ok_or_else(|| {
            inconsistent(format!(
                "pEmerg unknown for vault {}: path (b) sizes the claimant cap at the emergency price min(xClaim, aClaim), not at pClaim, and that price cannot be known",
                c.vault
            ))
        })?
    } else {
        c.p_claim
    };
    let floored = params::residual_zat_for(c.collateral_zat, cents, price, &c.claim_path)
        .ok_or_else(|| {
            inconsistent(format!(
                "{} undefined for vault {}",
                if c.claim_path == "b" {
                    "pEmerg"
                } else {
                    "pClaim"
                },
                c.vault
            ))
        })?;
    let raw = if floored > 0 {
        floored
    } else {
        // The unfloored figure the RPC reports (`EstimateClaim` has no RESIDUAL_MIN_ZAT).
        let margin = if c.claim_path == "a" {
            params::CLAIM_THRESHOLD_BPS
        } else {
            params::BPS
        };
        let num = (cents as u128) * (margin as u128) * (params::COIN as u128);
        let max = num.div_ceil(price as u128);
        i64::try_from(max)
            .ok()
            .filter(|m| c.collateral_zat > *m)
            .map(|m| c.collateral_zat - m)
            .unwrap_or(0)
    };
    let price_name = if c.claim_path == "b" {
        "pEmerg"
    } else {
        "pClaim"
    };
    if c.residual_zat != floored && c.residual_zat != raw {
        return Err(inconsistent(format!(
            "residualZat {} for vault {} (RED-5 at {price_name} {price} gives {floored})",
            c.residual_zat, c.vault
        )));
    }
    if c.claim_path == "a" {
        let lhs = (c.collateral_zat as u128) * (c.p_claim as u128);
        let rhs = (cents as u128) * (params::CLAIM_THRESHOLD_BPS as u128) * (params::COIN as u128);
        if lhs >= rhs {
            return Err(inconsistent(format!(
                "vault {} is not underwater at pClaim {} (clause a)",
                c.vault, c.p_claim
            )));
        }
    }
    Ok(floored)
}

/// The bounds the user saw on the Claimable screen (the light-client form of `yed_claim`'s
/// `maxBurnCents` / `minOutZat`, audit C/F-1, hardening H-9.3): the claim is refused before
/// anything is signed when the server's numbers would burn more YED or pay less YEC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClaimBounds {
    /// The most debt the claim may burn, cents (the row's `mintedCents` as shown).
    pub max_burn_cents: u64,
    /// The least YEC the claimant takes from the vault, zat: collateral − fees − residual −
    /// the network fee, as shown.
    pub min_out_zat: i64,
}

/// What the claimant takes from the vault (the carrier and YED inputs aside):
/// `collateral − fee − attestFee − residual − FEE_ZAT`.
pub fn claimant_take(
    collateral_zat: i64,
    fee_zat: i64,
    attest_fee_zat: i64,
    residual_zat: i64,
) -> i64 {
    collateral_zat - fee_zat - attest_fee_zat - residual_zat - params::FEE_ZAT
}

/// [`ClaimBounds`] against the claim about to be built.
pub fn check_claim_bounds(
    b: &ClaimBounds,
    burn_cents: u64,
    take_zat: i64,
) -> Result<(), MintError> {
    if burn_cents > b.max_burn_cents {
        return Err(MintError::BoundExceeded {
            what: "claim-burn-above-max",
            detail: format!(
                "the claim would burn {burn_cents} cents of YED, above the {} you confirmed",
                b.max_burn_cents
            ),
        });
    }
    if take_zat < b.min_out_zat {
        return Err(MintError::BoundExceeded {
            what: "claim-out-below-min",
            detail: format!(
                "the claim would pay you {take_zat} zat, below the {} you confirmed",
                b.min_out_zat
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    type Bend<T> = Box<dyn Fn(&mut T)>;

    /// An honest regtest answer for $100 over 48 blocks at tip 484, $0.52/YEC, 300 % (class A
    /// since the in-term plan's D-IT-4).
    fn honest() -> rpc::YedCollateralEstimate {
        rpc::YedCollateralEstimate {
            a_mint: 520_000,
            armed: true,
            attest_fee_zat: 12_500_000,
            base_ratio_bps: 30_000,
            bundle_seqs: vec![0, 1, 2],
            claim_height: 480 + 48 + 24,
            divergence_bps: 0,
            lock_height: 480 + 48,
            min_ratio_bps: 30_000,
            p_mint: 520_000,
            ref_height: 480,
            required_zat: params::required_zat(10_000, 30_000, 520_000).unwrap(),
            sigma_mult_bps: 10_000,
            source: "attest".into(),
            term_class: "A".into(),
            protocol_fee_cents: params::protocol_fee_cents(10_000),
            protocol_fee_zat: params::protocol_fee_zat(10_000, 520_000).unwrap(),
            x_mint: 530_000,
            mint_blocked: false,
            mint_blocked_reason: String::new(),
        }
    }

    fn check(e: &rpc::YedCollateralEstimate) -> Result<&'static TermClass, MintError> {
        check_estimate(Network::Regtest, 484, 10_000, 48, e)
    }

    #[test]
    fn honest_estimate_passes() {
        assert_eq!(check(&honest()).unwrap().letter, "A");
        // $100 at 300 % and $0.52/YEC ≈ 576.92 YEC.
        assert_eq!(honest().required_zat, 57_692_307_693);
        // Mainnet class A at tip 1_200_000.
        let mut e = honest();
        e.ref_height = 1_199_990;
        e.lock_height = 1_199_990 + 50_000;
        e.claim_height = e.lock_height + 34_560;
        assert_eq!(
            check_estimate(Network::Mainnet, 1_200_000, 10_000, 50_000, &e)
                .unwrap()
                .letter,
            "A"
        );
        // Mainnet class B is enabled again (in-term D-IT-9): 91–180 days at 400 %.
        let mut b = e.clone();
        b.lock_height = 1_199_990 + 200_000;
        b.claim_height = b.lock_height + 34_560;
        b.term_class = "B".into();
        b.base_ratio_bps = 40_000;
        b.min_ratio_bps = 40_000;
        b.required_zat = params::required_zat(10_000, 40_000, 520_000).unwrap();
        assert_eq!(
            check_estimate(Network::Mainnet, 1_200_000, 10_000, 200_000, &b)
                .unwrap()
                .letter,
            "B"
        );
        // Beyond class C's 365 days: outside every class.
        let mut c = b.clone();
        c.lock_height = 1_199_990 + 420_481;
        c.claim_height = c.lock_height + 34_560;
        assert!(matches!(
            check_estimate(Network::Mainnet, 1_200_000, 10_000, 420_481, &c),
            Err(MintError::BadLock { .. })
        ));
        // Regtest class B stays enabled.
        let mut rb = honest();
        rb.lock_height = 480 + 100;
        rb.claim_height = rb.lock_height + 24;
        rb.term_class = "B".into();
        rb.base_ratio_bps = 40_000;
        rb.min_ratio_bps = 40_000;
        rb.required_zat = params::required_zat(10_000, 40_000, 520_000).unwrap();
        assert_eq!(
            check_estimate(Network::Regtest, 484, 10_000, 100, &rb)
                .unwrap()
                .letter,
            "B"
        );
    }

    /// Every field a hostile server could bend, one at a time (audit G-1).
    #[test]
    fn hostile_estimates_are_refused() {
        let hostile: Vec<(&str, Bend<rpc::YedCollateralEstimate>)> = vec![
            (
                "lock far in the future",
                Box::new(|e| e.lock_height = 400_000_000),
            ),
            ("lock one block short", Box::new(|e| e.lock_height -= 1)),
            (
                "claim opens one block after the lock",
                Box::new(|e| e.claim_height = e.lock_height + 1),
            ),
            (
                "claim past LOCKTIME_THRESHOLD",
                Box::new(|e| {
                    e.lock_height = LOCKTIME_THRESHOLD as i64 - 10;
                    e.claim_height = e.lock_height + 24;
                    e.ref_height = e.lock_height - 48;
                }),
            ),
            (
                "ref height at the tip",
                Box::new(|e| {
                    e.ref_height = 484;
                    e.lock_height = 484 + 48;
                    e.claim_height = e.lock_height + 24;
                }),
            ),
            (
                "ref height too old",
                Box::new(|e| {
                    e.ref_height = 484 - 41;
                    e.lock_height = e.ref_height + 48;
                    e.claim_height = e.lock_height + 24;
                }),
            ),
            (
                "ref height zero",
                Box::new(|e| {
                    e.ref_height = 0;
                    e.lock_height = 48;
                    e.claim_height = 72;
                }),
            ),
            (
                "wrong class letter",
                Box::new(|e| e.term_class = "B".into()),
            ),
            (
                "required far below the rule",
                Box::new(|e| e.required_zat = 1_000),
            ),
            (
                "required one zat below the rule",
                Box::new(|e| e.required_zat -= 1),
            ),
            (
                "required 2 % above the rule",
                Box::new(|e| e.required_zat += e.required_zat / 50),
            ),
            (
                "pMint above min(xMint, aMint)",
                Box::new(|e| e.p_mint = 600_000),
            ),
            (
                "base ratio of another class",
                Box::new(|e| {
                    e.base_ratio_bps = 50_000;
                    e.min_ratio_bps = 50_000;
                    e.required_zat = params::required_zat(10_000, 50_000, 520_000).unwrap();
                }),
            ),
            (
                "sigma below 1x",
                Box::new(|e| {
                    e.sigma_mult_bps = 5_000;
                    e.min_ratio_bps = 25_000;
                    e.required_zat = params::required_zat(10_000, 25_000, 520_000).unwrap();
                }),
            ),
            (
                "sigma above the cap",
                Box::new(|e| {
                    e.sigma_mult_bps = 40_000;
                    e.min_ratio_bps = 200_000;
                    e.required_zat = params::required_zat(10_000, 200_000, 520_000).unwrap();
                }),
            ),
            (
                "min ratio not base · sigma",
                Box::new(|e| e.min_ratio_bps = 45_000),
            ),
        ];
        for (what, bend) in hostile {
            let mut e = honest();
            bend(&mut e);
            match check(&e) {
                Err(MintError::Inconsistent { .. }) => {}
                other => panic!("{what}: {other:?}"),
            }
        }
        // Y3: an undefined pMint is the network waiting for a price, not an inconsistent server.
        let mut e = honest();
        e.p_mint = 0;
        match check(&e) {
            Err(MintError::Blocked { reason }) => assert_eq!(reason, WAITING_FOR_PRICE),
            other => panic!("pMint undefined: {other:?}"),
        }
        // The node's mintBlocked verdict (lightwalletd L1) is the refusal, in plain words.
        let mut e = honest();
        e.mint_blocked = true;
        e.mint_blocked_reason = "mintpol-global-ratio".into();
        match check(&e) {
            Err(MintError::Blocked { reason }) => {
                assert!(reason.contains("collateral ratio is below"), "{reason}")
            }
            other => panic!("mintBlocked: {other:?}"),
        }
        let mut e = honest();
        e.mint_blocked = true;
        e.mint_blocked_reason = "mintpol-no-price: no pMint at refHeight".into();
        assert!(
            matches!(check(&e), Err(MintError::Blocked { reason }) if reason == WAITING_FOR_PRICE)
        );
        // The node's own rounding (up to 1,000 zat) is accepted.
        let mut e = honest();
        e.required_zat = 57_692_308_000;
        assert!(check(&e).is_ok());
        // In-term D-IT-5: the sigma multiplier is pinned at 1; a server reporting 2x — even with
        // the ratio and the collateral following it — runs another rule set and is refused.
        let mut e = honest();
        e.sigma_mult_bps = 20_000;
        e.min_ratio_bps = 60_000;
        e.required_zat = params::required_zat(10_000, 60_000, 520_000).unwrap();
        assert!(matches!(check(&e), Err(MintError::Inconsistent { .. })));
        // Not armed: the min(x, a) rule is not applied (the node refuses the mint anyway).
        let mut e = honest();
        e.armed = false;
        e.x_mint = 0;
        e.a_mint = 0;
        assert!(check(&e).is_ok());
    }

    #[test]
    fn amount_and_lock_bounds() {
        let r = Network::Regtest;
        assert!(matches!(
            check_cents(r, 9_999),
            Err(MintError::BadAmount { .. })
        ));
        assert!(check_cents(r, 10_000).is_ok());
        assert!(check_cents(r, 10_000_000).is_ok());
        assert!(matches!(
            check_cents(r, 10_000_001),
            Err(MintError::BadAmount { .. })
        ));
        assert!(matches!(
            check_cents(r, u32::MAX as u64 + 1),
            Err(MintError::BadAmount { .. })
        ));
        // D-Q-24: $100,000 on every network (H-12's $2,500 guard reversed).
        for n in [Network::Mainnet, Network::Testnet] {
            assert!(check_cents(n, 10_000_000).is_ok());
            assert!(matches!(
                check_cents(n, 10_000_001),
                Err(MintError::BadAmount {
                    max: 10_000_000,
                    ..
                })
            ));
        }
        // In-term D-IT-9: classes B and C are enabled on mainnet and testnet again (H-5 reversed).
        assert_eq!(class_for(Network::Mainnet, 200_000).unwrap().letter, "B");
        assert_eq!(class_for(Network::Testnet, 103_681).unwrap().letter, "B");
        assert_eq!(class_for(Network::Mainnet, 420_480).unwrap().letter, "C");
        assert!(matches!(
            class_for(Network::Mainnet, 420_481),
            Err(MintError::BadLock { .. })
        ));
        assert!(matches!(
            class_for(Network::Regtest, 47),
            Err(MintError::BadLock { .. })
        ));
        assert!(matches!(
            class_for(Network::Mainnet, 48),
            Err(MintError::BadLock { .. })
        ));
        assert_eq!(class_for(Network::Mainnet, 34_560).unwrap().letter, "A");
        let e = check_estimate(Network::Regtest, 484, 5_000, 48, &honest());
        assert!(matches!(e, Err(MintError::BadAmount { .. })));
        let e = check_estimate(Network::Regtest, 484, 10_000, 47, &honest());
        assert!(matches!(e, Err(MintError::BadLock { .. })));
    }

    #[test]
    fn bundle_price_bounds_p_mint() {
        let att = |p: u32| Attestation {
            seq: 0,
            price_micro_usd: p,
            cited_height: 480,
            sig: [0; 64],
        };
        let bundle = [att(500_000), att(520_000), att(510_000)];
        assert!(check_bundle_price(520_000, &bundle).is_ok());
        assert!(check_bundle_price(400_000, &bundle).is_ok());
        assert!(matches!(
            check_bundle_price(520_001, &bundle),
            Err(MintError::Inconsistent { .. })
        ));
        assert!(check_bundle_price(1, &[]).is_err());
    }

    /// FEE-1′ computed locally, FEE-0 only with no payee, a server's figure compared (audit G-2).
    #[test]
    fn hostile_fees_are_refused() {
        let payee = "s1payee";
        // $1,000 at $1.99: 1 % = $10.00 = ⌈10⁷ · 10⁸ / 1,990,000⌉ zat.
        assert_eq!(
            protocol_fee(100_000, 1_990_000, payee).unwrap(),
            502_512_563
        );
        // FEE-0: no payee, no fee.
        assert_eq!(protocol_fee(100_000, 1_990_000, "").unwrap(), 0);
        // an undefined price prices nothing
        assert!(protocol_fee(100_000, 0, payee).is_err());
        // a server's figure: right, or not reported (0), or refused
        assert!(check_protocol_fee("t", 100_000, 1_990_000, 1_000, 502_512_563).is_ok());
        assert!(check_protocol_fee("t", 100_000, 1_990_000, 0, 0).is_ok());
        assert!(check_protocol_fee("t", 100_000, 1_990_000, 1_001, 502_512_563).is_err());
        assert!(check_protocol_fee("t", 100_000, 1_990_000, 1_000, 502_512_564).is_err());
        // the audit's scenario: most of the collateral as the fee
        assert!(check_protocol_fee("t", 100_000, 1_990_000, 0, 250_000_000_000).is_err());
        let r = Network::Regtest;
        assert_eq!(attest_fee(r, 50_000_000, &[0, 1]), 12_500_000);
        assert_eq!(attest_fee(r, 50_000_000, &[]), 0);
        let m = Network::Mainnet;
        assert_eq!(attest_fee(m, 600_000_000, &[0]), 300_000_000);
        // an estimate whose protocol fee is not FEE-1′ at its own pMint is refused
        let mut e = honest();
        e.protocol_fee_zat += 1;
        assert!(check_estimate(r, 484, 10_000, 48, &e).is_err());
    }

    /// `GetVault` with bent script terms (audit G-1, the sync side).
    #[test]
    fn hostile_vaults_are_refused() {
        let honest = rpc::YedVault {
            txid: "ab".repeat(32),
            status: "ACTIVE".into(),
            term_class: "A".into(),
            ref_height: 480,
            lock_height: 528,
            claim_height: 552,
            minted_cents: 10_000,
            collateral_zat: 600_000_000_000,
            p_mint: 50_000, // $100 at 300 % = 6,000 YEC at $0.05
            ..Default::default()
        };
        assert!(check_vault(Network::Regtest, &honest).is_ok());
        // rpcversion 8: a stored mint price below what the collateral backs, or none, is refused
        for p_mint in [0, 49_999] {
            let v = rpc::YedVault {
                p_mint,
                ..honest.clone()
            };
            assert!(check_vault(Network::Regtest, &v).is_err(), "pMint {p_mint}");
        }
        let void = rpc::YedVault {
            status: "VOID".into(),
            term_class: String::new(),
            ..honest.clone()
        };
        assert!(check_vault(Network::Regtest, &void).is_ok());
        let bent: Vec<Bend<rpc::YedVault>> = vec![
            Box::new(|v| v.claim_height = v.lock_height + 1),
            Box::new(|v| v.claim_height = v.lock_height + 34_560),
            Box::new(|v| v.lock_height = 0),
            Box::new(|v| v.term_class = "C".into()),
            Box::new(|v| {
                v.ref_height = 0;
                v.lock_height = 528;
                v.claim_height = 552;
            }),
            Box::new(|v| {
                v.lock_height = LOCKTIME_THRESHOLD as i64;
                v.claim_height = v.lock_height + 24;
                v.ref_height = v.lock_height - 48;
            }),
        ];
        for (i, bend) in bent.iter().enumerate() {
            let mut v = honest.clone();
            bend(&mut v);
            assert!(
                matches!(
                    check_vault(Network::Regtest, &v),
                    Err(MintError::Inconsistent { .. })
                ),
                "case {i}"
            );
        }
        // A VOID vault's class is not judged (its payload may have been the fault).
        let mut v = void;
        v.term_class = "C".into();
        assert!(check_vault(Network::Regtest, &v).is_ok());
    }

    /// The regtest parameter set as the node reports it (`yed_getinfo.params`).
    fn server_params(network: Network) -> rpc::YellowbackParams {
        rpc::YellowbackParams {
            grace: network.grace() as i64,
            ref_window: REF_WINDOW as i64,
            token_value_zat: params::TOKEN_VALUE,
            claim_delay: network.claim_delay(),
            attest: Some(rpc::YellowbackAttestParams {
                attest_fee_bps: network.attest_fee_bps(),
                residual_min_zat: params::RESIDUAL_MIN_ZAT,
                mint_payload_version: 4,
                ..Default::default()
            }),
            // rpcversion 7 (quantum spec §6.2)
            // (mainnet and testnet: Falcon from height 0, as both node lines' chainparams)
            pq: Some(match network.pq_falcon_height() {
                Some(h) => rpc::YellowbackPqParams {
                    schemes: vec![1, 2],
                    falcon_active: true,
                    falcon_height: h as i64,
                    fee_rate_zat_per_kb: 100,
                },
                None => rpc::YellowbackPqParams {
                    schemes: vec![1],
                    falcon_active: false,
                    falcon_height: -1,
                    fee_rate_zat_per_kb: 100,
                },
            }),
            // rpcversion 8 (fees spec §3.4): the bands, the floor, the early fee; no attested price
            // yet (priceSource "fallback"), so both size rates are -pqfeerate
            max_mint_cents: network.max_mint_cents() as i64,
            fees: Some(rpc::YellowbackFeeParams {
                early_redeem_fee_bps: network
                    .term_classes()
                    .iter()
                    .map(|c| c.early_redeem_fee_bps)
                    .collect(),
                protocol: Some(rpc::YellowbackProtocolFee {
                    attest_fee_bps: network.attest_fee_bps(),
                    bands: params::PROTOCOL_FEE_BANDS
                        .iter()
                        .map(|(u, b)| rpc::YellowbackFeeBand {
                            upto_cents: *u as i64,
                            bps: *b,
                        })
                        .collect(),
                    floor_cents: params::PROTOCOL_FEE_FLOOR_CENTS,
                    price_source: "pMint".into(),
                }),
                network: Some(fallback_network()),
            }),
            supply_cap: Some(rpc::YellowbackSupplyCap {
                max_vault_share_bps: params::MAX_VAULT_SHARE_BPS,
                vault_share_floor_cents: params::VAULT_SHARE_FLOOR_CENTS,
                ..Default::default()
            }),
            classes: network
                .term_classes()
                .iter()
                .map(|c| rpc::YellowbackClassParams {
                    base_ratio_bps: c.base_ratio_bps,
                    class: c.letter.into(),
                    max_blocks: c.max_blocks as i64,
                    min_blocks: c.min_blocks as i64,
                    early_redeem_fee_bps: c.early_redeem_fee_bps,
                })
                .collect(),
            // rpcversion 6 (in-term IT-7, IT-9)
            claim_threshold_bps: params::CLAIM_THRESHOLD_BPS,
            early_redeem_fee_bps: network
                .term_classes()
                .iter()
                .map(|c| c.early_redeem_fee_bps)
                .collect(),
            sigma_mult_max_bps: SIGMA_MULT_MAX_BPS,
            in_term_claims: true,
            ..Default::default()
        }
    }

    /// `params.fees.network` before any attested price: both rates are `-pqfeerate` (100).
    fn fallback_network() -> rpc::YellowbackNetworkFee {
        rpc::YellowbackNetworkFee {
            price_micro_usd: 0,
            price_source: "fallback".into(),
            plain: Some(rpc::YellowbackNetworkRate {
                usd_per_kb_micro: 20_000,
                zat_per_kb: 100,
                ..Default::default()
            }),
            yellowback: Some(rpc::YellowbackNetworkRate {
                usd_per_kb_micro: 50_000,
                zat_per_kb: 100,
                max_tx_fee_usd_micro: 2_000_000,
                max_tx_fee_ceiling_zat: 1_000_000_000,
                max_tx_fee_zat: 10_000_000,
            }),
            floor_zat_per_kb: 5_000,
            fallback_zat_per_kb: 100,
            flat_zat: 1_000,
            max_tx_fee_zat: 10_000_000,
        }
    }

    /// `params.fees.network` at an attested $0.40 (the delta's example): $0.02/KB plain =
    /// 5,000,000 zat/KB, $0.05/KB Yellowback = 12,500,000 zat/KB, the cap $2 = 5 YEC.
    fn priced_network() -> rpc::YellowbackNetworkFee {
        let mut n = fallback_network();
        n.price_micro_usd = 400_000;
        n.price_source = "tip".into();
        n.plain.as_mut().unwrap().zat_per_kb = 5_000_000;
        let y = n.yellowback.as_mut().unwrap();
        y.zat_per_kb = 12_500_000;
        y.max_tx_fee_zat = 500_000_000;
        n
    }

    /// rpcversion 8: `params.fees.network` is read and recomputed from its own inputs; the size fees.
    #[test]
    fn network_fee_terms_are_recomputed() {
        let mut p = server_params(Network::Regtest);
        p.fees.as_mut().unwrap().network = Some(priced_network());
        p.pq.as_mut().unwrap().fee_rate_zat_per_kb = 5_000_000;
        let t = pq_terms(&p, Network::Regtest).unwrap();
        assert_eq!(t.fee_rate_zat_per_kb, 5_000_000);
        assert_eq!(t.yed_rate_zat_per_kb, 12_500_000);
        assert_eq!(t.floor_rate_zat_per_kb, 5_000);
        assert_eq!((t.flat_zat, t.max_fee_zat), (1_000, 500_000_000));
        // a redeem: the SLH-DSA owner input (7,981 bytes) on the 1,000-byte base, $0.05/KB
        let size = params::yed_estimated_size(0, &[1]);
        assert_eq!(size, 8_981);
        assert_eq!(t.yed_fee(size), 12_500_000 * 8_981 / 1000);
        assert_eq!(t.yed_floor_fee(size), 5_000 * 8_981 / 1000);
        // the cap, and the flat floor
        assert_eq!(t.yed_fee(100_000), 500_000_000);
        assert_eq!(t.yed_fee(0), 12_500_000, "CFeeRate: a 0 fee is the rate");
        // a padded rate, a target out of bounds, a pq rate that is not the plain one: refused
        let bent = |f: &dyn Fn(&mut rpc::YellowbackParams)| {
            let mut q = p.clone();
            f(&mut q);
            pq_terms(&q, Network::Regtest).is_err()
        };
        fn net(q: &mut rpc::YellowbackParams) -> &mut rpc::YellowbackNetworkFee {
            q.fees.as_mut().unwrap().network.as_mut().unwrap()
        }
        assert!(bent(
            &|q| net(q).yellowback.as_mut().unwrap().zat_per_kb += 1
        ));
        assert!(bent(&|q| net(q).plain.as_mut().unwrap().zat_per_kb *= 2));
        assert!(bent(&|q| net(q)
            .yellowback
            .as_mut()
            .unwrap()
            .usd_per_kb_micro = 2_000_000));
        assert!(bent(&|q| net(q).floor_zat_per_kb = 1_000_000));
        assert!(bent(&|q| net(q).flat_zat = 999));
        assert!(bent(&|q| q.pq.as_mut().unwrap().fee_rate_zat_per_kb = 100));
        assert!(bent(&|q| q.fees = None));
        // the absolute ceiling: a server cap above 10 YEC is held at 10 YEC
        let mut big = p.clone();
        net(&mut big).yellowback.as_mut().unwrap().max_tx_fee_zat = 100 * params::COIN;
        assert_eq!(
            pq_terms(&big, Network::Regtest).unwrap().max_fee_zat,
            params::MAX_YED_TX_FEE_ZAT
        );
    }

    /// rpcversion 7: `params.pq` is read and bounded; Falcon by height.
    #[test]
    fn pq_terms_are_read_and_bounded() {
        let base = server_params(Network::Regtest);
        let t = pq_terms(&base, Network::Regtest).unwrap();
        assert_eq!(
            t,
            PqTerms {
                max_fee_zat: 10_000_000, // the fallback block's cap
                ..PqTerms::default()
            }
        );
        assert!(!t.falcon_at(1_000_000));
        let with = |f: &dyn Fn(&mut rpc::YellowbackPqParams)| {
            let mut p = base.clone();
            f(p.pq.as_mut().unwrap());
            p
        };
        // schemes: SLH required, Falcon only when active, nothing unknown
        assert!(pq_terms(&with(&|q| q.schemes = vec![]), Network::Regtest).is_err());
        assert!(pq_terms(&with(&|q| q.schemes = vec![1, 2]), Network::Regtest).is_err());
        assert!(pq_terms(&with(&|q| q.schemes = vec![1, 3]), Network::Regtest).is_err());
        let f = pq_terms(
            &with(&|q| {
                q.schemes = vec![1, 2];
                q.falcon_active = true;
                q.falcon_height = 200;
            }),
            Network::Regtest,
        )
        .unwrap();
        assert!(f.falcon_active && f.falcon_at(0));
        let h = pq_terms(&with(&|q| q.falcon_height = 300), Network::Regtest).unwrap();
        assert_eq!(h.falcon_height, Some(300));
        assert!(!h.falcon_at(299) && h.falcon_at(300));
        // no pq block, or another MINT payload version: refused (and so is the parameter set)
        let mut p = base.clone();
        p.pq = None;
        assert!(pq_terms(&p, Network::Regtest).is_err());
        assert!(check_server_params(Network::Regtest, Some(&p)).is_err());
        let mut p = base.clone();
        p.attest.as_mut().unwrap().mint_payload_version = 3;
        assert!(pq_terms(&p, Network::Regtest).is_err());
        // the fee: max(1,000, rate × size), CFeeRate rounding, under the cap
        let t = PqTerms {
            fee_rate_zat_per_kb: 100,
            ..PqTerms::default()
        };
        assert_eq!(t.fee(8_200), 1_000, "1x at the default: unchanged (C-5)");
        let t5 = PqTerms {
            fee_rate_zat_per_kb: 500,
            ..t
        };
        assert_eq!(t5.fee(8_200), 4_100);
        assert_eq!(
            t5.fee(8_201),
            4_100,
            "integer division, as CFeeRate::GetFee"
        );
        assert_eq!(params::pq_size_fee(0, 100, 0), 100, "a 0 fee is the rate");
    }

    /// LOW-06-Y-4: mainnet and testnet compile Falcon from height 0 (`pqFalconHeight = 0` on both
    /// node lines) and refuse a server that says otherwise; regtest follows the server.
    #[test]
    fn falcon_activation_is_checked_not_overridden() {
        for n in [Network::Mainnet, Network::Testnet] {
            let base = server_params(n);
            let t = pq_terms(&base, n).unwrap();
            assert_eq!((t.falcon_height, t.falcon_active), (Some(0), true));
            let with = |f: &dyn Fn(&mut rpc::YellowbackPqParams)| {
                let mut p = base.clone();
                f(p.pq.as_mut().unwrap());
                p
            };
            // another height
            let moved = with(&|q| {
                q.falcon_height = 300;
                q.falcon_active = false;
                q.schemes = vec![1];
            });
            assert!(matches!(
                pq_terms(&moved, n),
                Err(MintError::Inconsistent { .. })
            ));
            assert!(check_server_params(n, Some(&moved)).is_err());
            // the case the old override masked: Falcon inactive, scheme 2 absent, height kept
            let inactive = with(&|q| {
                q.falcon_active = false;
                q.schemes = vec![1];
            });
            let e = pq_terms(&inactive, n).unwrap_err().to_string();
            assert!(e.contains("falconActive false"), "{e}");
            // no activation height at all
            assert!(pq_terms(&with(&|q| q.falcon_height = -1), n).is_err());
            assert!(check_falcon_activation(n, base.pq.as_ref().unwrap()).is_ok());
        }
        // regtest: the server's height, whatever it is
        let mut p = server_params(Network::Regtest);
        p.pq.as_mut().unwrap().falcon_height = 300;
        let t = pq_terms(&p, Network::Regtest).unwrap();
        assert!(!t.falcon_at(299) && t.falcon_at(300));
        // the offline defaults
        for n in [Network::Mainnet, Network::Testnet] {
            let d = PqTerms::default_for(n);
            assert!(d.falcon_at(0) && d.falcon_active);
            assert_eq!(
                d.fee_rate_zat_per_kb,
                PqTerms::default().fee_rate_zat_per_kb
            );
        }
        assert_eq!(PqTerms::default_for(Network::Regtest), PqTerms::default());
        assert_eq!(params::PQ_FALCON_HEIGHT_MAINNET, 0);
        assert_eq!(params::PQ_FALCON_HEIGHT_TESTNET, 0);
    }

    /// H-9.3: the server's parameter set must be the network's.
    #[test]
    fn server_params_are_the_networks() {
        for n in [Network::Mainnet, Network::Testnet, Network::Regtest] {
            assert!(check_server_params(n, Some(&server_params(n))).is_ok());
        }
        assert!(check_server_params(Network::Regtest, None).is_err());
        // A mainnet server still on the v3 set (fee 25 bps, attestor 25 %, B and C enabled).
        assert!(
            check_server_params(Network::Mainnet, Some(&server_params(Network::Regtest))).is_err()
        );
        let bends: Vec<Bend<rpc::YellowbackParams>> = vec![
            // rpcversion 8: FEE-1′'s bands and floor, maxMint, the early fee, the vault share
            Box::new(|p| p.max_mint_cents = 250_000),
            Box::new(|p| p.fees = None),
            Box::new(|p| p.fees.as_mut().unwrap().protocol.as_mut().unwrap().bands[0].bps = 150),
            Box::new(|p| {
                p.fees
                    .as_mut()
                    .unwrap()
                    .protocol
                    .as_mut()
                    .unwrap()
                    .bands
                    .truncate(2)
            }),
            Box::new(|p| {
                p.fees
                    .as_mut()
                    .unwrap()
                    .protocol
                    .as_mut()
                    .unwrap()
                    .floor_cents = 500
            }),
            Box::new(|p| {
                p.fees
                    .as_mut()
                    .unwrap()
                    .protocol
                    .as_mut()
                    .unwrap()
                    .attest_fee_bps = 2_500
            }),
            Box::new(|p| p.fees.as_mut().unwrap().early_redeem_fee_bps = vec![500, 250, 50]),
            Box::new(|p| p.supply_cap.as_mut().unwrap().max_vault_share_bps = 5_000),
            Box::new(|p| p.grace = 1),
            Box::new(|p| p.ref_window = 400),
            Box::new(|p| p.token_value_zat = 20_000),
            Box::new(|p| p.claim_delay = 10),
            Box::new(|p| p.attest = None),
            Box::new(|p| p.attest.as_mut().unwrap().attest_fee_bps = 9_000),
            Box::new(|p| p.attest.as_mut().unwrap().residual_min_zat = 0),
            Box::new(|p| p.classes.retain(|c| c.class != "B")),
            Box::new(|p| p.classes[1].max_blocks = 420_480),
            Box::new(|p| p.classes[0].base_ratio_bps = 10_000),
            Box::new(|p| p.classes[0].min_blocks = 1),
            // rpcversion 6 (in-term): the rule set the wallet implements
            Box::new(|p| p.in_term_claims = false),
            Box::new(|p| p.claim_threshold_bps = 11_000),
            Box::new(|p| p.sigma_mult_max_bps = 30_000),
            Box::new(|p| p.early_redeem_fee_bps = vec![500, 250]),
            Box::new(|p| p.early_redeem_fee_bps[0] = 0),
            Box::new(|p| p.classes[2].early_redeem_fee_bps = 500),
        ];
        for (i, bend) in bends.iter().enumerate() {
            let mut p = server_params(Network::Mainnet);
            bend(&mut p);
            assert!(
                matches!(
                    check_server_params(Network::Mainnet, Some(&p)),
                    Err(MintError::Inconsistent { .. })
                ),
                "case {i}"
            );
        }
    }

    fn info(requires_armed: bool) -> rpc::YellowbackInfo {
        rpc::YellowbackInfo {
            enabled: true,
            upgrade: Some(rpc::YellowbackActivation {
                status: "active".into(),
                ..Default::default()
            }),
            mint_requires_armed: requires_armed,
            ..Default::default()
        }
    }

    fn price(armed: bool) -> rpc::YedPrice {
        rpc::YedPrice {
            armed,
            attest_status: if armed { "ARMED" } else { "PENDING" }.into(),
            ..Default::default()
        }
    }

    fn stats(classes: &[&str], halts: &[&str]) -> rpc::YellowbackStats {
        rpc::YellowbackStats {
            mintable_classes: classes.iter().map(|c| c.to_string()).collect(),
            halt_mask: halts.iter().map(|c| c.to_string()).collect(),
            ..Default::default()
        }
    }

    /// H-1, H-5: the mint gate's states.
    #[test]
    fn mint_gate_states() {
        let r = Network::Regtest;
        let m = Network::Mainnet;
        // Armed, every class: open.
        let g = mint_gate(r, &info(false), &price(true), &stats(&["A", "B", "C"], &[])).unwrap();
        assert!(g.blocked.is_none() && g.mintable_classes == ["A", "B", "C"]);
        // Regtest without the flag: an unarmed price does not block (the node does not either).
        let g = mint_gate(r, &info(false), &price(false), &stats(&["A"], &[])).unwrap();
        assert!(g.blocked.is_none() && !g.requires_armed);
        // Regtest with the flag: blocked, with the attestation status in the reason.
        let g = mint_gate(r, &info(true), &price(false), &stats(&[], &[])).unwrap();
        assert!(g.requires_armed);
        assert!(g
            .blocked
            .as_deref()
            .unwrap()
            .contains("not armed (attestation PENDING)"));
        // Mainnet requires ARMED whatever the server says.
        let g = mint_gate(m, &info(false), &price(false), &stats(&["A"], &[])).unwrap();
        assert!(g.requires_armed && g.blocked.is_some());
        let g = mint_gate(m, &info(true), &price(true), &stats(&["A"], &[])).unwrap();
        assert!(g.blocked.is_none() && g.mintable_classes == ["A"]);
        // Empty mintableClasses: no class mintable, with the halts named.
        let g = mint_gate(
            m,
            &info(true),
            &price(true),
            &stats(&[], &["GLOBAL_RATIO", "PARTICIPATION"]),
        )
        .unwrap();
        assert!(g.mintable_classes.is_empty());
        // Y3: plain words, not the raw halt names.
        let why = g.blocked.as_deref().unwrap();
        assert!(
            why.starts_with("Minting is paused: the system's collateral ratio"),
            "{why}"
        );
        assert!(why.contains("too few attestors"), "{why}");
        assert!(
            !why.contains("GLOBAL_RATIO") && !why.contains("PARTICIPATION"),
            "{why}"
        );
        // A missing price reads as waiting for one.
        let g = mint_gate(m, &info(true), &price(true), &stats(&[], &["NO_PRICE"])).unwrap();
        assert_eq!(g.blocked.as_deref(), Some(WAITING_FOR_PRICE));
        assert_eq!(halt_sentence("NEW_BIT"), "an unrecognised halt (NEW_BIT)");
        let g = mint_gate(m, &info(true), &price(true), &stats(&[], &[])).unwrap();
        assert!(g
            .blocked
            .as_deref()
            .unwrap()
            .starts_with("No term class is mintable now"));
        // A mainnet server listing a class this build does not enable is inconsistent (H-5).
        assert!(mint_gate(m, &info(true), &price(true), &stats(&["A", "B", "C"], &[])).is_ok());
        assert!(matches!(
            mint_gate(m, &info(true), &price(true), &stats(&["A", "D"], &[])),
            Err(MintError::Inconsistent { .. })
        ));
        // Not active.
        let mut i = info(true);
        i.upgrade.as_mut().unwrap().status = "pending".into();
        let g = mint_gate(r, &i, &price(true), &stats(&["A"], &[])).unwrap();
        assert!(g.blocked.as_deref().unwrap().contains("not active"));
        // TOK-PQ: from the Falcon height the token goes to a Falcon holder; the gate stays open.
        let mut i = info(false);
        i.height = 299;
        let mut p = server_params(Network::Regtest);
        p.pq.as_mut().unwrap().falcon_height = 301;
        i.params = Some(p.clone());
        let g = mint_gate(r, &i, &price(true), &stats(&["A"], &[])).unwrap();
        assert!(g.blocked.is_none(), "the next block (300) is before Falcon");
        i.height = 300;
        let g = mint_gate(r, &i, &price(true), &stats(&["A"], &[])).unwrap();
        assert!(g.blocked.is_none(), "Falcon holders are built, not refused");
    }

    /// RED-5 recomputed from `pClaim` on path (a) and from `pEmerg` on path (b), and the claim
    /// bounds (H-9.3, RED-5b A1).
    #[test]
    fn claimable_residual_and_bounds() {
        // $100 debt at $0.10/YEC: claimantMax = ⌈10⁴ · margin · 10⁸ / 10⁵⌉ — 1.25·10¹¹
        // under clause (a) (θ 125 %, in-term D-IT-2), 10¹¹ under (b) at the same price.
        let (cm_a, cm_b) = (125_000_000_000i64, 100_000_000_000i64);
        let row = |path: &str, collateral: i64, residual: i64| rpc::YedClaimable {
            vault: format!("{}:0", "ab".repeat(32)),
            claimable: true,
            claim_path: path.into(),
            collateral_zat: collateral,
            minted_cents: 10_000,
            p_claim: 100_000,
            residual_zat: residual,
            ..Default::default()
        };
        // Clause (a): underwater means collateral < claimantMax, so the residual is 0.
        assert_eq!(
            check_claimable(&row("a", cm_a - 1_000, 0), None).unwrap(),
            0
        );
        // An invented residual under (a): refused.
        assert!(check_claimable(&row("a", cm_a - 1_000, 50_000_000), None).is_err());
        // Not underwater at the row's own pClaim: refused even with a matching residual.
        assert!(check_claimable(&row("a", cm_a + 50_000_000, 50_000_000), None).is_err());
        // Clause (b) at a known pEmerg (equal to the row's pClaim here): margin 10⁴, not θ.
        let emerg = Some(100_000);
        assert_eq!(
            check_claimable(&row("b", cm_b + 70_000_000, 70_000_000), emerg).unwrap(),
            70_000_000
        );
        assert!(check_claimable(&row("b", cm_b + 70_000_000, 80_000_000), emerg).is_err());
        assert!(check_claimable(&row("b", cm_b + 70_000_000, 60_000_000), emerg).is_err());
        // A dust residual: the RPC's unfloored figure and 0 are both accepted; 0 is paid.
        assert_eq!(
            check_claimable(&row("b", cm_b + 5_000, 5_000), emerg).unwrap(),
            0
        );
        assert_eq!(
            check_claimable(&row("b", cm_b + 5_000, 0), emerg).unwrap(),
            0
        );
        assert!(check_claimable(&row("c", cm_a - 1, 0), None).is_err());
        let mut undefined = row("a", cm_a - 1, 0);
        undefined.p_claim = 0;
        assert!(check_claimable(&undefined, None).is_err());
        // rpcversion 6: a row listed above θ (claimable false, no path, pClaim maybe null) is
        // shown, not claimed: nothing in it is checked or relied on.
        let listed = rpc::YedClaimable {
            claimable: false,
            claim_path: String::new(),
            p_claim: 0,
            ..row("a", cm_a * 2, 0)
        };
        assert_eq!(check_claimable(&listed, None).unwrap(), 0);

        // RED-5b (A1): path (b) at pEmerg 0.349, not at pClaim 0.42. $100,000 over 300,000 YEC.
        let collateral = 300_000 * params::COIN;
        let at_emerg = 1_346_704_871_060i64;
        let at_claim = 6_190_476_190_476i64;
        let mut a1 = row("b", collateral, at_emerg);
        a1.minted_cents = 10_000_000;
        a1.p_claim = 420_000;
        assert_eq!(check_claimable(&a1, Some(349_000)).unwrap(), at_emerg);
        // The pre-A1 residual (sized at pClaim) is inconsistent once path (b) uses pEmerg.
        let mut sized_at_claim = a1.clone();
        sized_at_claim.residual_zat = at_claim;
        assert!(check_claimable(&sized_at_claim, Some(349_000)).is_err());
        // No fallback to pClaim when pEmerg cannot be known.
        match check_claimable(&a1, None) {
            Err(MintError::Inconsistent { what }) => {
                assert!(what.contains("pEmerg unknown"), "{what}")
            }
            other => panic!("expected pEmerg unknown, got {other:?}"),
        }
        assert!(check_claimable(&a1, Some(0)).is_err());
        // pClaim on the row is not the sizing price: an undefined pClaim still passes at pEmerg.
        a1.p_claim = 0;
        assert_eq!(check_claimable(&a1, Some(349_000)).unwrap(), at_emerg);

        let take = claimant_take(10_000_000_000, 50_000_000, 12_500_000, 0);
        assert_eq!(
            take,
            10_000_000_000 - 50_000_000 - 12_500_000 - params::FEE_ZAT
        );
        let bounds = ClaimBounds {
            max_burn_cents: 10_000,
            min_out_zat: take,
        };
        assert!(check_claim_bounds(&bounds, 10_000, take).is_ok());
        assert!(check_claim_bounds(&bounds, 9_000, take + 1).is_ok());
        assert!(matches!(
            check_claim_bounds(&bounds, 10_001, take),
            Err(MintError::BoundExceeded {
                what: "claim-burn-above-max",
                ..
            })
        ));
        assert!(matches!(
            check_claim_bounds(&bounds, 10_000, take - 1),
            Err(MintError::BoundExceeded {
                what: "claim-out-below-min",
                ..
            })
        ));
    }

    /// rpcversion 5 (U-22, U-23): the attestor set and CLAIM_DELAY a server reports, and the V
    /// script of a vault it reports, rebuilt locally.
    #[test]
    fn vault_terms_and_the_vault_script() {
        let r = Network::Regtest;
        let set_display = "75".repeat(32);
        let mut i = rpc::YellowbackInfo {
            params: Some(rpc::YellowbackParams {
                claim_delay: 10,
                attestor_set_id: set_display.clone(),
                ..server_params(r)
            }),
            upgrade: Some(rpc::YellowbackActivation {
                status: "active".into(),
                attestor_set_id: set_display.clone(),
                claim_delay: 10,
                branch_id: "6d5b7a31".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let t = vault_terms(r, &i).unwrap();
        assert_eq!(t.attestor_set_id, [0x75; 32]);
        assert_eq!((t.claim_delay, t.grace), (10, 24));
        // Mainnet's CLAIM_DELAY is 1,152: a regtest-shaped server is refused there.
        assert!(vault_terms(Network::Mainnet, &i).is_err());
        let mut bad = i.clone();
        bad.params.as_mut().unwrap().attestor_set_id = String::new();
        assert!(vault_terms(r, &bad).is_err());
        bad = i.clone();
        bad.params.as_mut().unwrap().attestor_set_id = "00".repeat(32);
        assert!(vault_terms(r, &bad).is_err());
        bad = i.clone();
        bad.upgrade.as_mut().unwrap().attestor_set_id = "76".repeat(32);
        assert!(vault_terms(r, &bad).is_err());
        bad = i.clone();
        bad.upgrade.as_mut().unwrap().branch_id = "19bd2d2f".into();
        assert!(vault_terms(r, &bad).is_err());
        i.upgrade = None;
        assert!(vault_terms(r, &i).is_ok());

        // The vault script a server reports must be the one rebuilt from owner and refHeight
        // (in-term IT-1: ownerHeight = appHeight = R + 1) — or, for a vault minted before the
        // rule, from owner and lockHeight (ownerHeight = L, appHeight = L + GRACE).
        let owner = crate::pq::PqKeyId {
            scheme: 1,
            hash: [7; 32],
        };
        let spk = t.mint_vault_script(&owner, 329).unwrap();
        let p = crate::vault::parse_vault(&spk).unwrap();
        assert_eq!(p.tag, crate::vault::YED_TAG);
        assert_eq!((p.owner_height, p.app_height, p.delay), (330, 330, 10));
        let mut v = rpc::YedVault {
            txid: "ab".repeat(32),
            owner_scheme: owner.scheme.into(),
            owner_hash: crate::keys::hex(&owner.hash),
            ref_height: 329,
            lock_height: 377,
            claim_height: 401,
            script_pub_key: crate::keys::hex(&spk).to_uppercase(),
            ..Default::default()
        };
        let yv = check_vault_script(&t, &v).unwrap();
        assert_eq!(
            (yv.script.clone(), yv.owner_height(), yv.app_height()),
            (spk.clone(), 330, 330)
        );
        v.ref_height = 330;
        assert!(check_vault_script(&t, &v).is_err());
        v.ref_height = 329;
        let other = crate::pq::PqKeyId {
            hash: [2; 32],
            ..owner
        };
        v.script_pub_key = crate::keys::hex(&t.mint_vault_script(&other, 329).unwrap());
        assert!(check_vault_script(&t, &v).is_err());
        // an unregistered scheme or a short owner field is not a vault owner
        let mut w = v.clone();
        w.owner_scheme = 3;
        assert!(vault_owner(&w).is_err());
        w.owner_scheme = 256 + 1;
        assert!(vault_owner(&w).is_err());
        w.owner_scheme = 1;
        assert!(vault_owner(&w).is_ok());
        w.owner_hash = "01".repeat(31);
        assert!(vault_owner(&w).is_err());
        // A pre-plan vault (the upgrade line's V) is still recognised, with its own heights.
        let old = crate::vault::build_vault(&t.pre_plan_vault_params(&owner, 377)).unwrap();
        v.script_pub_key = crate::keys::hex(&old);
        let yv = check_vault_script(&t, &v).unwrap();
        assert_eq!((yv.owner_height(), yv.app_height()), (377, 401));
        v.lock_height = 378;
        assert!(check_vault_script(&t, &v).is_err());
    }
}
