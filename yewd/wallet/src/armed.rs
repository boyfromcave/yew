// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The armed attestation layer's wallet facts (finding F-S2-4, resolved in S4): ycash6
//! `src/yellowback/txbuilder.cpp` `BundleAt`, `AttestFeeFor`, `ClaimAt`, `NoticeAt`, and
//! `src/rpc/yellowback.cpp` `EstimateClaim`'s `canNotice`, re-derived from node reads.
//!
//! - **The bundle at `(R, selector)`** (`BundleAt`): unarmed, none; armed, the pool's
//!   (`yed_buildbundle`, its `seqs`, `aMint`, `aClaim`) or the caller's `bundleHex`, whose
//!   statistics are `BundleStat` over the attestors' weights at `R` (`yed_listattestors R`).
//! - **The attestor payee** (`AttestFeeFor`, AFEE-W): `DefaultAttestPayee` (yew-core
//!   `bundle::default_attest_payee` over the block hash at `R`, the selector and the bundle's
//!   seqs; the node's `params.policy.preferredAttestor` first when it is one of them), paid to the
//!   seq's `bondKeyAddress` (`yed_listattestors`); the fee AFEE-1′ =
//!   `protocolFee · params.attest.attestFeeBps / 10⁴` (floor).
//! - **The prices** (`PriceCombine`): `pMint = min(xMint, aMint)`, `pClaim = max(xClaim,
//!   aClaim)`, `pEmerg = min(xClaim, aClaim)`, the cross-section `x…` from `yed_getprice R`.

use serde_json::Value;

use crate::json::J;
use crate::node::{self, Node, NodeError};
use crate::{code, RpcError, Wallet};

const BPS: u128 = 10_000;
const COIN: u128 = 100_000_000;

/// What the bundle at `(R, selector)` decided (`BundleFactsW`).
#[derive(Clone, Debug, Default)]
pub struct BundleFacts {
    pub armed: bool,
    pub bundle: Vec<u8>,
    /// A: the counted attestations' seqs.
    pub seqs: Vec<u16>,
    pub a_mint: Option<i64>,
    pub a_claim: Option<i64>,
}

impl BundleFacts {
    pub fn seqs_json(&self) -> J {
        if !self.armed {
            return J::Arr(vec![]);
        }
        J::Arr(self.seqs.iter().map(|s| J::Int(*s as i64)).collect())
    }
}

/// The attestor fee output of a transaction (`AttestFeeFor`).
#[derive(Clone, Debug)]
pub struct AttestPayee {
    pub seq: u16,
    pub address: String,
    pub script: Vec<u8>,
    pub fee_zat: i64,
}

/// The node's rule identifiers come back as `-4`/`-26` build errors.
fn node_err(e: NodeError) -> RpcError {
    match e {
        NodeError::Rpc { message, .. } => crate::mint::build_error(message),
        other => other.into(),
    }
}

/// `ArmedAt(R)`: `yed_getprice R`'s `armed`.
pub(crate) async fn armed_at(node: &dyn Node, r: i64) -> Result<bool, RpcError> {
    let p = node::call(node, "yed_getprice", serde_json::json!([r]))
        .await
        .map_err(node_err)?;
    Ok(p["armed"].as_bool().unwrap_or(false))
}

/// The cross-section at `R`: `(xMint, xClaim)`.
pub(crate) async fn cross_section(
    node: &dyn Node,
    r: i64,
) -> Result<(Option<i64>, Option<i64>), RpcError> {
    let p = node::call(node, "yed_getprice", serde_json::json!([r]))
        .await
        .map_err(node_err)?;
    Ok((p["xMint"].as_i64(), p["xClaim"].as_i64()))
}

/// `WeightedQuantile` (`math.h`): the first price whose cumulative weight reaches
/// `⌈total · q / 10⁴⌉`, over entries sorted by price (stable on `(price, seq)`).
fn weighted_quantile(entries: &[(i64, u128)], q_bps: i64) -> Option<i64> {
    if entries.is_empty() {
        return None;
    }
    let q = q_bps.max(0) as u128;
    let total: u128 = entries.iter().map(|e| e.1).sum();
    let threshold = (total * q).div_ceil(BPS);
    let mut cum = 0u128;
    for (price, w) in entries {
        cum += w;
        if cum >= threshold {
            return Some(*price);
        }
    }
    None
}

/// `BundleStat` (`bundle.cpp`): `(Q(qLow), Q(qHigh))` = `(aMint, aClaim)` over the bundle's
/// attestations weighted by their attestors' weights at `R`.
fn bundle_stat(
    atts: &[(u16, i64, u128)],
    m_select: usize,
    q_low: i64,
    q_high: i64,
) -> (Option<i64>, Option<i64>) {
    if atts.is_empty() || atts.len() < m_select {
        return (None, None);
    }
    if !(0..=10_000).contains(&q_low) || !(0..=10_000).contains(&q_high) {
        return (None, None);
    }
    let mut sorted: Vec<(u16, i64, u128)> = atts.to_vec();
    sorted.sort_by_key(|a| (a.1, a.0));
    let e: Vec<(i64, u128)> = sorted.iter().map(|a| (a.1, a.2)).collect();
    (weighted_quantile(&e, q_low), weighted_quantile(&e, q_high))
}

fn weight_of(v: &Value) -> Option<u128> {
    match v {
        Value::Number(n) => n.as_u64().map(|x| x as u128),
        Value::String(s) => s.parse::<u128>().ok(),
        _ => None,
    }
}

/// `IsUnderwater` (`math.h`): `collateral · price < cents · threshold · COIN`.
pub fn is_underwater(
    collateral_zat: i64,
    price: Option<i64>,
    minted_cents: i64,
    threshold_bps: i64,
) -> bool {
    let Some(p) = price.filter(|p| *p > 0) else {
        return false;
    };
    if minted_cents <= 0 || threshold_bps <= 0 {
        return false;
    }
    let c = collateral_zat.max(0) as u128;
    c * (p as u128) < (minted_cents as u128) * (threshold_bps as u128) * COIN
}

/// `AttestFeeZat`: `floor(fee · bps / 10⁴)`.
pub fn attest_fee_zat(fee_zat: i64, bps: i64) -> i64 {
    if fee_zat <= 0 || bps <= 0 {
        return 0;
    }
    ((fee_zat as u128) * (bps as u128) / BPS).min(i64::MAX as u128) as i64
}

impl Wallet {
    /// `BundleAt(R, selector, bundleHex)`.
    pub(crate) async fn bundle_at(
        &self,
        node: &dyn Node,
        r: i64,
        selector_hex: &str,
        bundle_arg: &[u8],
    ) -> Result<BundleFacts, RpcError> {
        let armed = armed_at(node, r).await?;
        if !armed {
            // an explicit bundle while unarmed is still carried; the node's dry run judges it
            return Ok(BundleFacts {
                armed: false,
                bundle: bundle_arg.to_vec(),
                ..Default::default()
            });
        }
        if bundle_arg.is_empty() {
            let b = node::call(
                node,
                "yed_buildbundle",
                serde_json::json!([r, selector_hex]),
            )
            .await
            .map_err(node_err)?;
            let bundle = hex::decode(b["hex"].as_str().unwrap_or("")).unwrap_or_default();
            let seqs = b["seqs"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_u64())
                        .map(|x| x as u16)
                        .collect()
                })
                .unwrap_or_default();
            return Ok(BundleFacts {
                armed: true,
                bundle,
                seqs,
                a_mint: b["aMint"].as_i64(),
                a_claim: b["aClaim"].as_i64(),
            });
        }
        let atts = yew_core::bundle::decode(bundle_arg).map_err(|_| {
            crate::mint::build_error("bundle-malformed: bundleHex is not \"YA\" 0x01 count followed by count x 74-byte attestations".into())
        })?;
        let info = node::call(node, "yed_getinfo", serde_json::json!([])).await?;
        let at = &info["params"]["attest"];
        let rows = node::call(node, "yed_listattestors", serde_json::json!([r]))
            .await
            .map_err(node_err)?;
        let rows = rows.as_array().cloned().unwrap_or_default();
        let mut weighted = Vec::new();
        for a in &atts {
            let w = rows
                .iter()
                .find(|x| {
                    x["seq"]
                        .as_u64()
                        .or_else(|| x["seq"].as_str().and_then(|s| s.parse().ok()))
                        == Some(a.seq as u64)
                })
                .and_then(|x| weight_of(&x["weight"]))
                .unwrap_or(0);
            weighted.push((a.seq, a.price_micro_usd as i64, w));
        }
        let (a_mint, a_claim) = bundle_stat(
            &weighted,
            at["mSelect"].as_u64().unwrap_or(0) as usize,
            at["qLowBps"].as_i64().unwrap_or(3333),
            at["qHighBps"].as_i64().unwrap_or(6667),
        );
        if a_mint.is_none() || a_claim.is_none() {
            return Err(crate::mint::build_error(format!(
                "bundle-insufficient: the bundle's statistics are undefined at {r} (BUNDLE-1)"
            )));
        }
        Ok(BundleFacts {
            armed: true,
            bundle: bundle_arg.to_vec(),
            seqs: atts.iter().map(|a| a.seq).collect(),
            a_mint,
            a_claim,
        })
    }

    /// `AttestFeeFor(R, selector, f, protocolFee)`: `None` unarmed or with an empty bundle.
    pub(crate) async fn attest_payee(
        &self,
        node: &dyn Node,
        r: i64,
        selector: &[u8],
        f: &BundleFacts,
        protocol_fee_zat: i64,
    ) -> Result<Option<AttestPayee>, RpcError> {
        if !f.armed || f.seqs.is_empty() {
            return Ok(None);
        }
        let info = node::call(node, "yed_getinfo", serde_json::json!([])).await?;
        let prm = &info["params"];
        let mut a = f.seqs.clone();
        a.sort_unstable();
        a.dedup();
        let preferred = prm["policy"]["preferredAttestor"]
            .as_u64()
            .map(|x| x as u16)
            .filter(|p| a.contains(p));
        let seq = match preferred {
            Some(p) => p,
            None => {
                let h = node::call(node, "getblockhash", serde_json::json!([r])).await?;
                let mut hash: [u8; 32] = hex::decode(h.as_str().unwrap_or(""))
                    .ok()
                    .and_then(|b| b.try_into().ok())
                    .ok_or_else(|| RpcError::new(code::MISC_ERROR, "yewd: getblockhash"))?;
                hash.reverse();
                yew_core::bundle::default_attest_payee(&hash, selector, &a)
                    .ok_or_else(|| RpcError::new(code::MISC_ERROR, "yewd: an empty bundle"))?
            }
        };
        let rows = node::call(node, "yed_listattestors", serde_json::json!([]))
            .await
            .map_err(node_err)?;
        let address = rows
            .as_array()
            .and_then(|rows| {
                rows.iter().find(|x| {
                    x["seq"]
                        .as_u64()
                        .or_else(|| x["seq"].as_str().and_then(|s| s.parse().ok()))
                        == Some(seq as u64)
                })
            })
            .and_then(|x| x["bondKeyAddress"].as_str().map(str::to_string))
            .ok_or_else(|| {
                crate::mint::build_error(format!(
                    "attest-unknown-seq: attestor {seq} has no bond key"
                ))
            })?;
        let script = crate::rpc::parse_taddr_script(self.network, &address).ok_or_else(|| {
            RpcError::new(
                code::MISC_ERROR,
                format!("yewd: the bond key address {address} is not an address"),
            )
        })?;
        let bps = prm["attest"]["attestFeeBps"].as_i64().unwrap_or(0);
        Ok(Some(AttestPayee {
            seq,
            address,
            script,
            fee_zat: attest_fee_zat(protocol_fee_zat, bps),
        }))
    }
}

/// `PriceCombine`'s claim half: `(pClaim, pEmerg)` from the cross-section and the bundle.
pub fn claim_prices(x_claim: Option<i64>, f: &BundleFacts) -> (Option<i64>, Option<i64>) {
    if !f.armed {
        return (x_claim, None);
    }
    match (x_claim, f.a_claim) {
        (Some(x), Some(a)) => (Some(x.max(a)), Some(x.min(a))),
        _ => (None, None),
    }
}

/// `PriceCombine`'s mint half: `min(xMint, aMint)`.
pub fn mint_price(x_mint: Option<i64>, f: &BundleFacts) -> Option<i64> {
    if !f.armed {
        return x_mint;
    }
    match (x_mint, f.a_mint) {
        (Some(x), Some(a)) => Some(x.min(a)),
        _ => None,
    }
}

pub fn opt(v: Option<i64>) -> J {
    v.map(J::Int).unwrap_or(J::Null)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantile_and_stat() {
        // equal weights, three prices: ⌈3 · 0.3333⌉ = 1 (the first), ⌈3 · 0.6667⌉ = 3 (the third)
        let atts = [(1u16, 300i64, 1u128), (2, 100, 1), (3, 200, 1)];
        assert_eq!(bundle_stat(&atts, 2, 3333, 6667), (Some(100), Some(300)));
        assert_eq!(bundle_stat(&atts, 4, 3333, 6667), (None, None));
        // a heavy attestor moves the quantile
        let atts = [(1u16, 100i64, 1u128), (2, 200, 10)];
        assert_eq!(bundle_stat(&atts, 2, 3333, 6667), (Some(200), Some(200)));
    }

    #[test]
    fn underwater_and_fee() {
        // $100 at 125 % needs 125 USD of collateral: at $1 that is 125 YEC
        assert!(is_underwater(
            124 * 100_000_000,
            Some(1_000_000),
            10_000,
            12_500
        ));
        assert!(!is_underwater(
            126 * 100_000_000,
            Some(1_000_000),
            10_000,
            12_500
        ));
        assert!(!is_underwater(1, None, 10_000, 12_500));
        assert_eq!(attest_fee_zat(1_000_001, 2_500), 250_000);
        assert_eq!(attest_fee_zat(0, 2_500), 0);
    }
}
