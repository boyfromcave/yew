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

/// The mint amount bounds of MINT-2 (`MIN_MINT ≤ cents ≤ MAX_MINT`), which also keeps `cents`
/// inside the payload's `u32` (audit G-9).
pub fn check_cents(cents: u64) -> Result<(), MintError> {
    if !(params::MIN_MINT_CENTS..=params::MAX_MINT_CENTS).contains(&cents) {
        return Err(MintError::BadAmount {
            cents,
            min: params::MIN_MINT_CENTS,
            max: params::MAX_MINT_CENTS,
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
    check_cents(cents)?;
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
pub fn check_fee(collateral_zat: i64, payee: &str, fee_zat: i64) -> Result<i64, MintError> {
    if payee.is_empty() {
        return Ok(0);
    }
    let local = params::fee_zat_for(collateral_zat);
    if fee_zat != local {
        return Err(inconsistent(format!(
            "feeZat {fee_zat} for collateral {collateral_zat} (FEE-1 gives {local})"
        )));
    }
    Ok(fee_zat)
}

/// The attestor fee for an enforcement fee (AFEE-1), computed locally.
pub fn attest_fee(fee_zat: i64, seqs: &[u16]) -> i64 {
    if seqs.is_empty() {
        0
    } else {
        params::attest_fee_zat_for(fee_zat)
    }
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
        // Mainnet class B at tip 1_200_000.
        let mut e = honest();
        e.ref_height = 1_199_990;
        e.lock_height = 1_199_990 + 200_000;
        e.claim_height = e.lock_height + 34_560;
        e.term_class = "B".into();
        e.base_ratio_bps = 40_000;
        e.min_ratio_bps = 40_000;
        e.required_zat = params::required_zat(10_000, 40_000, 520_000).unwrap();
        assert_eq!(
            check_estimate(Network::Mainnet, 1_200_000, 10_000, 200_000, &e)
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
        assert!(matches!(
            check_cents(9_999),
            Err(MintError::BadAmount { .. })
        ));
        assert!(check_cents(10_000).is_ok());
        assert!(check_cents(1_000_000).is_ok());
        assert!(matches!(
            check_cents(1_000_001),
            Err(MintError::BadAmount { .. })
        ));
        assert!(matches!(
            check_cents(u32::MAX as u64 + 1),
            Err(MintError::BadAmount { .. })
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
        assert_eq!(
            check_fee(1_000_000_000, payee, 50_000_000).unwrap(),
            50_000_000
        );
        assert_eq!(
            check_fee(400_000_000_000, payee, 1_000_000_000).unwrap(),
            1_000_000_000
        );
        // The audit's scenario: fee = collateral − 2,000 to the operator's pool.
        assert!(check_fee(1_000_000_000, payee, 999_998_000).is_err());
        assert!(check_fee(1_000_000_000, payee, 50_000_001).is_err());
        assert!(check_fee(1_000_000_000, payee, 49_999_999).is_err());
        assert!(check_fee(1_000_000_000, payee, 0).is_err());
        // FEE-0: no payee, no fee, whatever number the server attached.
        assert_eq!(check_fee(1_000_000_000, "", 999_998_000).unwrap(), 0);
        assert_eq!(attest_fee(50_000_000, &[0, 1]), 12_500_000);
        assert_eq!(attest_fee(50_000_000, &[]), 0);
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
}
