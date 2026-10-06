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
        return Err(inconsistent("pMint undefined"));
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

/// The enforcement fee a server quotes for `collateral_zat` (audit G-2): FEE-0 (no payee) ⇒
/// 0; otherwise exactly `feeZat(collateralZat)` — less and the node refuses the transaction
/// (MINT-8 ⇒ VOID), more and the surplus is the server's to direct.
pub fn check_fee(
    network: Network,
    collateral_zat: i64,
    payee: &str,
    fee_zat: i64,
) -> Result<i64, MintError> {
    if payee.is_empty() {
        return Ok(0);
    }
    let local = params::fee_zat_for(network, collateral_zat);
    if fee_zat != local {
        return Err(inconsistent(format!(
            "feeZat {fee_zat} for collateral {collateral_zat} (FEE-1 gives {local})"
        )));
    }
    Ok(fee_zat)
}

/// The attestor fee for an enforcement fee (AFEE-1), computed locally.
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
    /// The V of a mint by `owner` locked until `lock_height` (`YedVaultScript`).
    pub fn vault_params(&self, owner: &[u8; 33], lock_height: u32) -> crate::vault::VaultParams {
        crate::vault::yed_vault_params(
            &self.attestor_set_id,
            self.claim_delay,
            self.grace,
            owner,
            lock_height,
        )
    }

    /// The V scriptPubKey of a mint by `owner` locked until `lock_height`.
    pub fn vault_script(&self, owner: &[u8; 33], lock_height: u32) -> Result<Vec<u8>, MintError> {
        crate::vault::build_vault(&self.vault_params(owner, lock_height)).ok_or_else(|| {
            inconsistent(format!(
                "the vault of lockHeight {lock_height} is outside the template's ranges"
            ))
        })
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

/// A `GetVault` record's V script (rpcversion 5, U-23): the node's `scriptPubKey` must be the
/// YED vault this wallet rebuilds from the owner key, `lockHeight` and the [`VaultTerms`], the
/// script it will sign against (owner) or name in its claim intents (claimant). Returns it.
pub fn check_vault_script(t: &VaultTerms, v: &rpc::YedVault) -> Result<Vec<u8>, MintError> {
    let owner: [u8; 33] = crate::keys::unhex(&v.owner_pub_key)
        .ok()
        .and_then(|b| b.as_slice().try_into().ok())
        .ok_or_else(|| inconsistent(format!("vault {}: ownerPubKey", v.txid)))?;
    let ours = t.vault_script(&owner, v.lock_height as u32)?;
    if crate::keys::hex(&ours) != v.script_pub_key.to_ascii_lowercase() {
        return Err(inconsistent(format!(
            "vault {}: scriptPubKey is not the YED vault of its owner and lockHeight",
            v.txid
        )));
    }
    Ok(ours)
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

/// The parameter set a server reports (`GetYellowbackInfo.params`) against the one this build
/// compiles for the network (audit G-1, G-2; hardening H-9.3 "recompute the fee floor and the
/// height identities locally"). The wallet never prices a mint, a fee or a deadline from the
/// server's figures; this check only refuses a server whose node runs another parameter set
/// (a stale release, a hand-edited one, a lie), because every local check below would then
/// disagree with the node that judges the transaction. Compared: `FEE_MIN`, `FEE_BPS`,
/// `GRACE`, `REF_WINDOW`, `TOKEN_VALUE`, `ATTEST_FEE_BPS`, `RESIDUAL_MIN_ZAT` and each term
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
    want("feeMinZat", p.fee_min_zat, params::FEE_MIN_ZAT)?;
    want("feeBps", p.fee_bps, network.fee_bps())?;
    want("grace", p.grace, network.grace() as i64)?;
    want("refWindow", p.ref_window, REF_WINDOW as i64)?;
    want("tokenValueZat", p.token_value_zat, params::TOKEN_VALUE)?;
    // rpcversion 5 (U-23): CLAIM_DELAY is the YED vault's delay, part of every vault script.
    want("claimDelay", p.claim_delay, network.claim_delay())?;
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
    let blocked = if !info.enabled || !active {
        Some("Yellowback is not active on this server's node: nothing can be minted.".to_string())
    } else if requires_armed && !price.armed {
        Some(format!(
            "Minting is paused: the price feed is not armed (attestation {}). The node refuses every mint until enough attestors arm it. Redeeming and claiming are not affected.",
            if price.attest_status.is_empty() { "status unknown" } else { price.attest_status.as_str() }
        ))
    } else if mintable_classes.is_empty() {
        Some(if !stats.halt_mask.is_empty() {
            format!(
                "Minting is halted ({}): no term class is mintable now.",
                stats.halt_mask.join(", ")
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

/// A `ListClaimable` row's RED-5 residual against the vault's terms and the row's own `pClaim`
/// (audit G-2; `ClaimAt`): a server inflating the residual moves the claimant's YEC to the
/// owner. Returns the residual the CLAIM pays: the node builder's (`ClaimAt` drops a residual
/// below `RESIDUAL_MIN_ZAT`; `yed_listclaimable` reports it unfloored, so both are accepted).
/// Under clause (a) the vault must also be underwater at that `pClaim` (`IsUnderwater`).
pub fn check_claimable(c: &rpc::YedClaimable) -> Result<i64, MintError> {
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
    let floored = params::residual_zat_for(c.collateral_zat, cents, c.p_claim, &c.claim_path)
        .ok_or_else(|| inconsistent(format!("pClaim undefined for vault {}", c.vault)))?;
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
        let max = num.div_ceil(c.p_claim as u128);
        i64::try_from(max)
            .ok()
            .filter(|m| c.collateral_zat > *m)
            .map(|m| c.collateral_zat - m)
            .unwrap_or(0)
    };
    if c.residual_zat != floored && c.residual_zat != raw {
        return Err(inconsistent(format!(
            "residualZat {} for vault {} (RED-5 at pClaim {} gives {floored})",
            c.residual_zat, c.vault, c.p_claim
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

    /// An honest regtest answer for $100 over 48 blocks at tip 484, $0.52/YEC, 500 %.
    fn honest() -> rpc::YedCollateralEstimate {
        rpc::YedCollateralEstimate {
            a_mint: 520_000,
            armed: true,
            attest_fee_zat: 12_500_000,
            base_ratio_bps: 50_000,
            bundle_seqs: vec![0, 1, 2],
            claim_height: 480 + 48 + 24,
            divergence_bps: 0,
            lock_height: 480 + 48,
            min_ratio_bps: 50_000,
            p_mint: 520_000,
            ref_height: 480,
            required_zat: params::required_zat(10_000, 50_000, 520_000).unwrap(),
            sigma_mult_bps: 10_000,
            source: "attest".into(),
            term_class: "A".into(),
            x_mint: 530_000,
        }
    }

    fn check(e: &rpc::YedCollateralEstimate) -> Result<&'static TermClass, MintError> {
        check_estimate(Network::Regtest, 484, 10_000, 48, e)
    }

    #[test]
    fn honest_estimate_passes() {
        assert_eq!(check(&honest()).unwrap().letter, "A");
        // The spec's worked numbers: $100 at 500 % and $0.52/YEC ≈ 961.54 YEC.
        assert_eq!(honest().required_zat, 96_153_846_154);
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
        // Mainnet class B is disabled (H-5): refused as a lock outside every class.
        let mut b = e.clone();
        b.lock_height = 1_199_990 + 200_000;
        b.claim_height = b.lock_height + 34_560;
        b.term_class = "B".into();
        b.base_ratio_bps = 40_000;
        b.min_ratio_bps = 40_000;
        b.required_zat = params::required_zat(10_000, 40_000, 520_000).unwrap();
        assert!(matches!(
            check_estimate(Network::Mainnet, 1_200_000, 10_000, 200_000, &b),
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
            ("pMint undefined", Box::new(|e| e.p_mint = 0)),
            (
                "base ratio of another class",
                Box::new(|e| {
                    e.base_ratio_bps = 30_000;
                    e.min_ratio_bps = 30_000;
                    e.required_zat = params::required_zat(10_000, 30_000, 520_000).unwrap();
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
        // The node's own rounding (up to 1,000 zat) is accepted.
        let mut e = honest();
        e.required_zat = 96_153_847_000;
        assert!(check(&e).is_ok());
        // A higher sigma multiplier is legitimate when the ratio and the collateral follow it.
        let mut e = honest();
        e.sigma_mult_bps = 20_000;
        e.min_ratio_bps = 100_000;
        e.required_zat = params::required_zat(10_000, 100_000, 520_000).unwrap();
        assert!(check(&e).is_ok());
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
        assert!(check_cents(r, 1_000_000).is_ok());
        assert!(matches!(
            check_cents(r, 1_000_001),
            Err(MintError::BadAmount { .. })
        ));
        assert!(matches!(
            check_cents(r, u32::MAX as u64 + 1),
            Err(MintError::BadAmount { .. })
        ));
        // H-12: $2,500 on mainnet and testnet.
        for n in [Network::Mainnet, Network::Testnet] {
            assert!(check_cents(n, 250_000).is_ok());
            assert!(matches!(
                check_cents(n, 250_001),
                Err(MintError::BadAmount { max: 250_000, .. })
            ));
        }
        // H-5: classes B and C are disabled on mainnet.
        assert!(matches!(
            class_for(Network::Mainnet, 200_000),
            Err(MintError::BadLock { .. })
        ));
        assert!(matches!(
            class_for(Network::Testnet, 103_681),
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

    /// FEE-1 exactly, FEE-0 only with no payee (audit G-2).
    #[test]
    fn hostile_fees_are_refused() {
        let payee = "s1payee";
        let r = Network::Regtest;
        assert_eq!(
            check_fee(r, 1_000_000_000, payee, 50_000_000).unwrap(),
            50_000_000
        );
        assert_eq!(
            check_fee(r, 400_000_000_000, payee, 1_000_000_000).unwrap(),
            1_000_000_000
        );
        // The audit's scenario: fee = collateral − 2,000 to the operator's pool.
        assert!(check_fee(r, 1_000_000_000, payee, 999_998_000).is_err());
        assert!(check_fee(r, 1_000_000_000, payee, 50_000_001).is_err());
        assert!(check_fee(r, 1_000_000_000, payee, 49_999_999).is_err());
        assert!(check_fee(r, 1_000_000_000, payee, 0).is_err());
        // FEE-0: no payee, no fee, whatever number the server attached.
        assert_eq!(check_fee(r, 1_000_000_000, "", 999_998_000).unwrap(), 0);
        assert_eq!(attest_fee(r, 50_000_000, &[0, 1]), 12_500_000);
        assert_eq!(attest_fee(r, 50_000_000, &[]), 0);
        // H-4 on mainnet: 0.15 %, the attestor half. A server still quoting the v3 rate
        // (0.25 %) is refused.
        let m = Network::Mainnet;
        assert_eq!(
            check_fee(m, 400_000_000_000, payee, 600_000_000).unwrap(),
            600_000_000
        );
        assert!(check_fee(m, 400_000_000_000, payee, 1_000_000_000).is_err());
        assert_eq!(attest_fee(m, 600_000_000, &[0]), 300_000_000);
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
            ..Default::default()
        };
        assert!(check_vault(Network::Regtest, &honest).is_ok());
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
            fee_min_zat: params::FEE_MIN_ZAT,
            fee_bps: network.fee_bps(),
            grace: network.grace() as i64,
            ref_window: REF_WINDOW as i64,
            token_value_zat: params::TOKEN_VALUE,
            claim_delay: network.claim_delay(),
            attest: Some(rpc::YellowbackAttestParams {
                attest_fee_bps: network.attest_fee_bps(),
                residual_min_zat: params::RESIDUAL_MIN_ZAT,
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
                })
                .collect(),
            ..Default::default()
        }
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
            Box::new(|p| p.fee_min_zat = 1),
            Box::new(|p| p.fee_bps = 100),
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
        assert!(g
            .blocked
            .as_deref()
            .unwrap()
            .contains("GLOBAL_RATIO, PARTICIPATION"));
        let g = mint_gate(m, &info(true), &price(true), &stats(&[], &[])).unwrap();
        assert!(g
            .blocked
            .as_deref()
            .unwrap()
            .starts_with("No term class is mintable now"));
        // A mainnet server listing a disabled class is inconsistent (H-5).
        assert!(matches!(
            mint_gate(m, &info(true), &price(true), &stats(&["A", "B"], &[])),
            Err(MintError::Inconsistent { .. })
        ));
        // Not active.
        let mut i = info(true);
        i.upgrade.as_mut().unwrap().status = "pending".into();
        let g = mint_gate(r, &i, &price(true), &stats(&["A"], &[])).unwrap();
        assert!(g.blocked.as_deref().unwrap().contains("not active"));
    }

    /// RED-5 recomputed from `pClaim`, and the claim bounds (H-9.3).
    #[test]
    fn claimable_residual_and_bounds() {
        // $100 debt at pClaim $0.10/YEC: claimantMax = ⌈10⁴ · margin · 10⁸ / 10⁵⌉ — 1.1·10¹¹
        // under clause (a), 10¹¹ under (b).
        let (cm_a, cm_b) = (110_000_000_000i64, 100_000_000_000i64);
        let row = |path: &str, collateral: i64, residual: i64| rpc::YedClaimable {
            vault: format!("{}:0", "ab".repeat(32)),
            claim_path: path.into(),
            collateral_zat: collateral,
            minted_cents: 10_000,
            p_claim: 100_000,
            residual_zat: residual,
            ..Default::default()
        };
        // Clause (a): underwater means collateral < claimantMax, so the residual is 0.
        assert_eq!(check_claimable(&row("a", cm_a - 1_000, 0)).unwrap(), 0);
        // An invented residual under (a): refused.
        assert!(check_claimable(&row("a", cm_a - 1_000, 50_000_000)).is_err());
        // Not underwater at the row's own pClaim: refused even with a matching residual.
        assert!(check_claimable(&row("a", cm_a + 50_000_000, 50_000_000)).is_err());
        // Clause (b): no margin; the residual is RED-5's.
        assert_eq!(
            check_claimable(&row("b", cm_b + 70_000_000, 70_000_000)).unwrap(),
            70_000_000
        );
        assert!(check_claimable(&row("b", cm_b + 70_000_000, 80_000_000)).is_err());
        assert!(check_claimable(&row("b", cm_b + 70_000_000, 60_000_000)).is_err());
        // A dust residual: the RPC's unfloored figure and 0 are both accepted; 0 is paid.
        assert_eq!(check_claimable(&row("b", cm_b + 5_000, 5_000)).unwrap(), 0);
        assert_eq!(check_claimable(&row("b", cm_b + 5_000, 0)).unwrap(), 0);
        assert!(check_claimable(&row("c", cm_a - 1, 0)).is_err());
        let mut undefined = row("a", cm_a - 1, 0);
        undefined.p_claim = 0;
        assert!(check_claimable(&undefined).is_err());

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

        // The vault script a server reports must be the one rebuilt from owner and lockHeight.
        let owner = secp256k1::PublicKey::from_secret_key(
            &secp256k1::SecretKey::from_secret_bytes([7; 32]).unwrap(),
        )
        .serialize();
        let spk = t.vault_script(&owner, 377).unwrap();
        let p = crate::vault::parse_vault(&spk).unwrap();
        assert_eq!(p.tag, crate::vault::YED_TAG);
        assert_eq!((p.owner_height, p.app_height, p.delay), (377, 401, 10));
        let mut v = rpc::YedVault {
            txid: "ab".repeat(32),
            owner_pub_key: crate::keys::hex(&owner),
            lock_height: 377,
            claim_height: 401,
            script_pub_key: crate::keys::hex(&spk).to_uppercase(),
            ..Default::default()
        };
        assert_eq!(check_vault_script(&t, &v).unwrap(), spk);
        v.lock_height = 378;
        assert!(check_vault_script(&t, &v).is_err());
        v.lock_height = 377;
        v.script_pub_key = crate::keys::hex(&t.vault_script(&[2; 33], 377).unwrap());
        assert!(check_vault_script(&t, &v).is_err());
    }
}
