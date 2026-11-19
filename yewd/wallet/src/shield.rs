// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! `z_shieldcoinbase` from a post-quantum address (beta4 item 7): **a yewd extension**. ycashd
//! (both C++ lines, beta3) refuses a post-quantum `fromaddress` ("z_shieldcoinbase cannot spend
//! from a post-quantum address; use z_sendmany"), and yewd answers that refusal too for every
//! other source it does not serve. Here yewd serves the one source a miner paid at a post-quantum
//! address needs: the address's mature coinbase coins, shielded in one transaction to one Sapling
//! address, the amount computed by the wallet (the coins less the fee, so no change), within the
//! `limit`.
//!
//! The transaction is the one an exact-amount `z_sendmany` from the address to the same Sapling
//! address builds when it selects the same coins: the post-quantum inputs, no transparent output,
//! one Sapling output padded to two, the fee of a post-quantum spend on its real size
//! (`PQBuilderFee`, base `LEGACY_DEFAULT_FEE`; an explicit fee below it is refused, above the
//! post-quantum cap refused). Built and committed by `z_mergetoaddress`'s operation
//! ([`Wallet::run_merge`]).
//!
//! Arguments, defaults and result are ycashd's `z_shieldcoinbase`'s: `"fromaddress" "toaddress"
//! ( fee ) ( limit ) ( memo ) ( privacyPolicy )`, `limit` 50 (0: as many as one transaction
//! carries, at most `MAX_PQ_INPUTS_PER_TX`), policy `AllowRevealedSenders`; the result's
//! `remainingUTXOs` / `remainingValue` count the mature coinbase coins left for a next call.

use serde_json::Value;
use yewd_proto::KeyRef;

use crate::build::{amount_param, next_block};
use crate::json::J;
use crate::keys::Owner;
use crate::merge::{int_param, plan_error, Cand};
use crate::node::Node;
use crate::rpc::invalid;
use crate::zsend::{now, opid, Op, MAX_PQ_INPUTS_PER_TX};
use crate::{code, RpcError, Wallet};
use yew_core::build::any_to_any::{
    self as plan, PlanError, MAX_STANDARD_TX_SIGOPS, PQ_SIGOP_COST, PRIVACY_POLICIES,
};

/// ycashd `SHIELD_COINBASE_DEFAULT_LIMIT` (`asyncrpcoperation_shieldcoinbase.h`).
pub const SHIELD_COINBASE_DEFAULT_LIMIT: i64 = 50;

/// The arguments ycashd's `z_shieldcoinbase` takes (`rpcwallet.cpp`: at least 2, at most 6).
pub const ARITY: (usize, usize) = (2, 6);

/// Whether the call is the one yewd serves: `z_shieldcoinbase` with a post-quantum `fromaddress`.
/// Any other source (an ECC address, `"*"`) stays outside the façade's scope (`-32601`).
pub fn serves_pq_source(network: yew_core::params::Network, p: &[Value]) -> bool {
    p.first()
        .and_then(|v| v.as_str())
        .is_some_and(|a| yew_core::keys::parse_pq_yec_address(network, a).is_ok())
}

/// The tail of a refusal that found no mature coinbase: what the address holds immature and how
/// many blocks the first of it still needs (`COINBASE_MATURITY + 1` confirmations).
pub(crate) fn immature_tail(immature: i64, blocks_to_go: i64) -> String {
    if immature <= 0 {
        return String::new();
    }
    format!(
        " The address holds {} YEC of immature mining rewards (coinbase); a mining reward can be shielded after {} confirmations, the first of these in {} more block{}.",
        crate::rpc::format_money(immature),
        crate::COINBASE_MATURITY + 1,
        blocks_to_go,
        if blocks_to_go == 1 { "" } else { "s" }
    )
}

impl Wallet {
    /// `z_shieldcoinbase "fromaddress" "toaddress" ( fee ) ( limit ) ( memo ) ( privacyPolicy )`
    /// with a post-quantum `fromaddress` ([`serves_pq_source`]).
    pub(crate) async fn z_shieldcoinbase_pq(
        &mut self,
        node: &dyn Node,
        p: &[Value],
    ) -> Result<J, RpcError> {
        let next = next_block(node).await?;
        let from = p.first().and_then(|v| v.as_str()).ok_or_else(|| {
            RpcError::new(code::MISC_ERROR, "JSON value is not a string as expected")
        })?;
        let id = yew_core::keys::parse_pq_yec_address(self.network, from).map_err(|_| {
            RpcError::new(
                code::INVALID_ADDRESS_OR_KEY,
                "Invalid from address: should be a taddr, zaddr, UA, or the string 'ANY_TADDR'.",
            )
        })?;
        self.ensure_pq_spendable(&id)?;
        let source = yew_core::pq::pqpkh_script(&id).ok_or_else(|| {
            RpcError::new(
                code::INVALID_ADDRESS_OR_KEY,
                "Invalid from address: should be a taddr, zaddr, UA, or the string 'ANY_TADDR'.",
            )
        })?;
        let dest = p.get(1).and_then(|v| v.as_str()).ok_or_else(|| {
            RpcError::new(code::MISC_ERROR, "JSON value is not a string as expected")
        })?;
        if !yew_core::shielded_keys::is_sapling_address(self.network, dest) {
            // ycashd's AsyncRPCOperation_shieldcoinbase: a transparent destination is refused
            // (a coinbase is spent only into the shielded pool)
            let what = if yew_core::keys::parse_pq_yec_address(self.network, dest).is_ok() {
                "a post-quantum"
            } else {
                match crate::rpc::parse_taddr_script(self.network, dest) {
                    Some(s) if yew_core::script::p2sh_hash(&s).is_some() => "a p2sh",
                    Some(_) => "a p2pkh",
                    None => {
                        return Err(invalid(format!(
                            "Invalid parameter, unknown address format: {dest}"
                        )))
                    }
                }
            };
            return Err(RpcError::new(
                code::TRANSACTION_ERROR,
                format!("Cannot shield coinbase output to {what} address."),
            ));
        }
        let fee = match p.get(2) {
            None | Some(Value::Null) => None,
            Some(v) => Some(amount_param(v)?),
        };
        let limit = int_param(p, 3)?.unwrap_or(SHIELD_COINBASE_DEFAULT_LIMIT);
        if limit < 0 {
            return Err(invalid(
                "Limit on maximum number of utxos cannot be negative",
            ));
        }
        let memo = match p.get(4) {
            None | Some(Value::Null) => String::new(),
            Some(Value::String(m)) => {
                let b = hex::decode(m).map_err(|_| {
                    invalid("Invalid parameter, expected memo data in hexadecimal format.")
                })?;
                if b.len() > 512 {
                    return Err(invalid(
                        "Invalid parameter, memo is longer than the maximum allowed 512 bytes.",
                    ));
                }
                hex::encode(b)
            }
            Some(_) => {
                return Err(RpcError::new(
                    code::MISC_ERROR,
                    "JSON value is not a string as expected",
                ))
            }
        };
        let policy = match p.get(5) {
            None | Some(Value::Null) => "AllowRevealedSenders".to_string(),
            Some(Value::String(s)) if s == "LegacyCompat" => "AllowFullyTransparent".to_string(),
            Some(Value::String(s)) if PRIVACY_POLICIES.contains(&s.as_str()) => s.clone(),
            Some(Value::String(s)) => {
                return Err(invalid(format!("Unknown privacy policy name '{s}'")))
            }
            Some(_) => {
                return Err(RpcError::new(
                    code::MISC_ERROR,
                    "JSON value is not a string as expected",
                ))
            }
        };

        // the coins: the source's mature coinbase, unlocked, not spent by a mempool transaction,
        // never an output YED holds; largest first (z_sendmany's order)
        let (rate, cap) = crate::send::pq_fee_params(node).await;
        let spent = self.mempool_spent();
        let reserved = self.yed_reserved(node).await?;
        let mut cands: Vec<Cand> = Vec::new();
        for (c, _) in self.available_coins(None) {
            let k = (c.txid.clone(), c.vout);
            if !c.coinbase || c.script != source || spent.contains(&k) || reserved.contains(&k) {
                continue;
            }
            let Owner::Pq(scheme, index) = c.owner else {
                continue;
            };
            cands.push(Cand {
                op: yew_core::tx::OutPoint {
                    txid: yew_core::tx::txid_from_hex(&c.txid)
                        .map_err(|e| RpcError::new(code::MISC_ERROR, e))?,
                    n: c.vout,
                },
                value: c.value,
                script: c.script.clone(),
                key: KeyRef::Pq { scheme, index },
                pq: Some(scheme),
            });
        }
        cands.sort_by(|a, b| {
            b.value
                .cmp(&a.value)
                .then((a.op.txid, a.op.n).cmp(&(b.op.txid, b.op.n)))
        });
        let max = if limit == 0 {
            MAX_PQ_INPUTS_PER_TX
        } else {
            (limit as usize).min(MAX_PQ_INPUTS_PER_TX)
        };
        let max = max.min((MAX_STANDARD_TX_SIGOPS - 1) / PQ_SIGOP_COST);
        let counter = cands.len();
        let remaining: i64 = cands.iter().skip(max).map(|c| c.value).sum();
        cands.truncate(max);
        let sel = cands;
        if sel.is_empty() {
            return Err(RpcError::new(
                code::WALLET_INSUFFICIENT_FUNDS,
                format!(
                    "Could not find any coinbase funds to shield.{}",
                    immature_tail(
                        self.pq_immature_coinbase(&source),
                        self.pq_coinbase_blocks_to_go(&source)
                    )
                ),
            ));
        }
        let shielding: i64 = sel.iter().map(|c| c.value).sum();
        // ycash6 PQBuilderFee(fee or LEGACY_DEFAULT_FEE, the shape), as z_sendmany and
        // z_mergetoaddress settle a post-quantum source's fee: no transparent output, one Sapling
        // output padded to two
        if let Some(f) = fee {
            if f > cap {
                return Err(plan_error(PlanError::FeeAboveCap { fee: f, cap }));
            }
        }
        let z_outs = plan::padded(1);
        let (bytes, conventional) = plan::shape_size(
            sel.iter().map(|c| c.script.as_slice()),
            &Vec::<(Vec<u8>, i64)>::new(),
            0,
            z_outs,
        );
        let needed = plan::pq_builder_fee(
            fee.unwrap_or(plan::LEGACY_DEFAULT_FEE),
            bytes,
            conventional,
            rate,
            cap,
        );
        if let Some(f) = fee {
            if needed > f {
                return Err(plan_error(PlanError::FeeBelowNeeded { fee: f, needed }));
            }
        }
        if needed > cap {
            return Err(plan_error(PlanError::FeeAboveCap { fee: needed, cap }));
        }
        let fee_zat = fee.unwrap_or(needed);
        let net = shielding - fee_zat;
        if net <= 0 {
            return Err(RpcError::new(
                code::WALLET_INSUFFICIENT_FUNDS,
                format!(
                    "Insufficient coinbase funds, have {}, which is less than miners fee {}",
                    plan::format_money(shielding),
                    plan::format_money(fee_zat)
                ),
            ));
        }
        // a transparent sender, a shielded recipient
        let build_refusal = (!plan::policy_allows(&policy, "AllowRevealedSenders")).then(|| {
            format!(
                "Failed to build transaction: The specified privacy policy, {policy}, does not permit the creation of the requested transaction. Select AllowRevealedSenders or weaker to allow this transaction to be constructed."
            )
        });

        let mut ctx = serde_json::Map::new();
        ctx.insert("fromaddress".into(), p[0].clone());
        ctx.insert("toaddress".into(), p[1].clone());
        ctx.insert(
            "fee".into(),
            serde_json::from_str(&crate::zsend::money8(fee_zat)).unwrap_or(Value::Null),
        );
        let opid = opid();
        let started = std::time::Instant::now();
        let created = now();
        let outcome = match build_refusal {
            Some(m) => Err(RpcError::new(code::WALLET_ERROR, m)),
            None => {
                self.run_merge(
                    node,
                    &next,
                    &sel,
                    &[],
                    &Err(dest.to_string()),
                    Some(memo),
                    net,
                    fee_zat,
                    true,
                    rate,
                    cap,
                )
                .await
            }
        };
        let (status, error, txid) = match outcome {
            Ok(t) => ("success", None, Some(t)),
            Err(e) => ("failed", Some((e.code, e.message)), None),
        };
        self.ops.ops.push(Op {
            id: opid.clone(),
            method: "z_shieldcoinbase",
            status,
            creation_time: created,
            error,
            txid,
            secs: started.elapsed().as_secs_f64(),
            params: Value::Object(ctx),
        });
        Ok(J::obj()
            .with("remainingUTXOs", (counter - sel.len()) as i64)
            .with("remainingValue", J::Amount(remaining))
            .with("shieldingUTXOs", sel.len() as i64)
            .with("shieldingValue", J::Amount(shielding))
            .with("opid", opid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_a_post_quantum_source_is_served() {
        let net = yew_core::params::Network::Regtest;
        let pq = "rqf3MNYNywmb2xNZ7jTKQ6YCjBxVp9Da9Uay7v4sSox2eUhPBkvfh";
        assert!(serves_pq_source(net, &[json!(pq), json!("z")]));
        assert!(!serves_pq_source(net, &[json!("*"), json!("z")]));
        assert!(!serves_pq_source(
            net,
            &[json!("smPoyeG3G6u6utA4ePAJrKoY9e2shPE3Zd3"), json!("z")]
        ));
        assert!(!serves_pq_source(net, &[]));
    }

    #[test]
    fn the_immature_tail_names_the_blocks_to_go() {
        assert_eq!(immature_tail(0, 5), "");
        assert_eq!(
            immature_tail(625_000_000, 95),
            " The address holds 6.25 YEC of immature mining rewards (coinbase); a mining reward can be shielded after 101 confirmations, the first of these in 95 more blocks."
        );
        assert!(immature_tail(625_000_000, 1).ends_with("in 1 more block."));
    }
}
