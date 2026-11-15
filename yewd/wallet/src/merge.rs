// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! `z_mergetoaddress` (beta3 item 14): ycash6 `src/wallet/rpcwallet.cpp` `z_mergetoaddress`
//! (beta2 D-6: a post-quantum address merges its own `TX_PQPKH` coins), by its arguments,
//! limits, fee rule, errors and result. yewd used to answer only its refusals.
//!
//! The sources: `ANY_TADDR` (the wallet's ECC P2PKH coins, never a post-quantum one), an ECC
//! address, a post-quantum address of this wallet (its own coins), `ANY_SAPLING` or a Sapling
//! address (its notes at `DEFAULT_ANCHOR_CONFIRMATIONS` deep). Coinbase, unconfirmed and locked
//! coins and the outputs YED holds are never merged. The destination: an ECC or P2SH address, a
//! post-quantum address (one `TX_PQPKH` output) or a Sapling address. The limits are ycashd's:
//! `transparent_limit` coins (50; 0: as many as fit), `shielded_limit` notes (200), at most
//! `MAX_PQ_INPUTS_PER_TX` post-quantum inputs and the standard signature-operation limit; the
//! coins past a limit are reported as remaining. A merge with a post-quantum input pays the fee of
//! a post-quantum spend on its real size (`PQBuilderFee`: the default is raised to it, an explicit
//! fee below it is refused); any other merge pays ycashd's `-feepolicy=peroutput` default.
//!
//! Not merged by yewd: P2SH coins (the signer holds no multisig signing path), which ycashd's
//! `ANY_TADDR` and a named P2SH address also take.

use std::collections::BTreeSet;

use serde_json::Value;
use yewd_proto::{KeyRef, SaplingOut};

use crate::build::{amount_param, next_block};
use crate::json::J;
use crate::keys::Owner;
use crate::node::Node;
use crate::rpc::invalid;
use crate::zsend::{
    now, op_error, opid, sapling_spends, Op, MAX_PQ_INPUTS_PER_TX, WEIGHT_RATIO_CAP,
};
use crate::{code, RpcError, Wallet};
use yew_core::build::any_to_any::{
    self as plan, PlanError, MAX_STANDARD_TX_SIGOPS, PQ_SIGOP_COST, PRIVACY_POLICIES,
};

pub const SERVED: &[&str] = &["z_mergetoaddress"];

const DEFAULT_TRANSPARENT_LIMIT: i64 = 50;
const DEFAULT_SAPLING_LIMIT: i64 = 200;
/// ycash6 `src/wallet/wallet.h` `DEFAULT_ANCHOR_CONFIRMATIONS`: the depth a merged note needs.
const ANCHOR_CONFIRMATIONS: i64 = 3;
/// `MAX_TX_SIZE_AFTER_SAPLING` (`MAX_BLOCK_SIZE`).
const MAX_TX_SIZE: usize = 2_000_000;
const CTXIN_SPEND_P2PKH_SIZE: usize = 148;
const SPENDDESCRIPTION_SIZE: usize = 384;
const OUTPUTDESCRIPTION_SIZE: usize = 948;
/// ycash6 `MARGINAL_FEE` and `P2PKH_STANDARD_INPUT_SIZE` (ZIP-317).
const MARGINAL_FEE: i64 = 5_000 / 10;
const P2PKH_STANDARD_INPUT_SIZE: usize = 150;

/// A coin a merge may take.
struct Cand {
    op: yew_core::tx::OutPoint,
    value: i64,
    script: Vec<u8>,
    key: KeyRef,
    pq: Option<u8>,
}

/// ycash6 `PQInputMarginalFee` (asyncrpcoperation_common.cpp): the fee one post-quantum input adds,
/// at the plain rate or ZIP-317's marginal fee, whichever is more (audit A-M2: a coin worth no
/// more is not merged).
fn pq_input_marginal_fee(scheme: u8, rate: i64) -> i64 {
    let n = plan::pq_input_size(scheme);
    (rate * n as i64 / 1000).max(MARGINAL_FEE * n.div_ceil(P2PKH_STANDARD_INPUT_SIZE) as i64)
}

fn int_param(p: &[Value], i: usize) -> Result<Option<i64>, RpcError> {
    match p.get(i) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v.as_i64().map(Some).ok_or_else(|| {
            RpcError::new(code::MISC_ERROR, "JSON value is not an integer as expected")
        }),
    }
}

impl Wallet {
    pub(crate) async fn merge_call(
        &mut self,
        node: &dyn Node,
        method: &str,
        p: &[Value],
    ) -> Result<J, RpcError> {
        match method {
            "z_mergetoaddress" => self.z_mergetoaddress(node, p).await,
            _ => Err(RpcError::new(code::METHOD_NOT_FOUND, "Method not found")),
        }
    }

    /// `z_mergetoaddress ["fromaddress", ...] "toaddress" ( fee ) ( transparent_limit )
    /// ( shielded_limit ) ( memo ) ( privacyPolicy )`.
    async fn z_mergetoaddress(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        let next = next_block(node).await?;
        let froms = p.first().and_then(|v| v.as_array()).ok_or_else(|| {
            RpcError::new(code::MISC_ERROR, "JSON value is not an array as expected")
        })?;
        if froms.is_empty() {
            return Err(invalid("Invalid parameter, fromaddresses array is empty."));
        }
        let (mut any_t, mut any_z) = (false, false);
        let mut taddrs: BTreeSet<Vec<u8>> = BTreeSet::new();
        let mut zaddrs: BTreeSet<String> = BTreeSet::new();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        for o in froms {
            let a = o
                .as_str()
                .ok_or_else(|| invalid("Invalid parameter, expected string"))?;
            if a == "ANY_TADDR" {
                any_t = true;
            } else if a == "ANY_SPROUT" {
                // no Sprout notes in a yewd wallet: nothing to add
            } else if a == "ANY_SAPLING" {
                any_z = true;
            } else if let Ok(id) = yew_core::keys::parse_pq_yec_address(self.network, a) {
                self.ensure_pq_spendable(&id)?;
                let s = yew_core::pq::pqpkh_script(&id)
                    .ok_or_else(|| invalid(format!("Unknown address format: {a}")))?;
                taddrs.insert(s);
            } else if let Some(s) = crate::rpc::parse_taddr_script(self.network, a) {
                taddrs.insert(s);
            } else if yew_core::shielded_keys::is_sapling_address(self.network, a) {
                zaddrs.insert(a.to_string());
            } else {
                return Err(invalid(format!("Unknown address format: {a}")));
            }
            if !seen.insert(a.to_string()) {
                return Err(invalid(format!(
                    "Invalid parameter, duplicated address: {a}"
                )));
            }
        }
        if any_t && !taddrs.is_empty() {
            return Err(invalid(
                "Cannot specify specific taddrs when using \"ANY_TADDR\"",
            ));
        }
        if any_z && !zaddrs.is_empty() {
            return Err(invalid(
                "Cannot specify specific zaddrs when using \"ANY_SPROUT\" or \"ANY_SAPLING\"",
            ));
        }
        let dest_str = p.get(1).and_then(|v| v.as_str()).ok_or_else(|| {
            RpcError::new(code::MISC_ERROR, "JSON value is not a string as expected")
        })?;
        let mut estimated = 200usize;
        // the destination: (transparent script | Sapling address)
        let dest: Result<Vec<u8>, String> =
            if let Ok(id) = yew_core::keys::parse_pq_yec_address(self.network, dest_str) {
                let s = yew_core::pq::pqpkh_script(&id).ok_or_else(|| {
                    invalid(format!(
                        "Invalid parameter, unknown address format: {dest_str}"
                    ))
                })?;
                self.ensure_pq_payable(&s)?;
                Ok(s)
            } else if let Some(s) = crate::rpc::parse_taddr_script(self.network, dest_str) {
                Ok(s)
            } else if yew_core::shielded_keys::is_sapling_address(self.network, dest_str) {
                estimated += OUTPUTDESCRIPTION_SIZE * 2;
                Err(dest_str.to_string())
            } else {
                return Err(invalid(format!(
                    "Invalid parameter, unknown address format: {dest_str}"
                )));
            };
        let pq_dest = dest
            .as_ref()
            .ok()
            .is_some_and(|s| yew_core::pq::pqpkh_of(s).is_some());
        let fee = match p.get(2) {
            None | Some(Value::Null) => None,
            Some(v) => Some(amount_param(v)?),
        };
        let utxo_limit = int_param(p, 3)?.unwrap_or(DEFAULT_TRANSPARENT_LIMIT);
        if utxo_limit < 0 {
            return Err(invalid(
                "Limit on maximum number of UTXOs cannot be negative",
            ));
        }
        let note_limit = int_param(p, 4)?.unwrap_or(DEFAULT_SAPLING_LIMIT);
        if note_limit < 0 {
            return Err(invalid(
                "Limit on maximum number of notes cannot be negative",
            ));
        }
        let memo = match p.get(5) {
            None | Some(Value::Null) => None,
            Some(Value::String(m)) => {
                let b = hex::decode(m).map_err(|_| {
                    invalid("Invalid parameter, expected memo data in hexadecimal format.")
                })?;
                if b.len() > 512 {
                    return Err(invalid(
                        "Invalid parameter, memo is longer than the maximum allowed 512 bytes.",
                    ));
                }
                Some(hex::encode(b))
            }
            Some(_) => {
                return Err(RpcError::new(
                    code::MISC_ERROR,
                    "JSON value is not a string as expected",
                ))
            }
        };
        if memo.is_some() && dest.is_ok() {
            return Err(invalid("Memos cannot be sent to transparent addresses."));
        }
        let policy = match p.get(6) {
            None | Some(Value::Null) => "AllowFullyTransparent".to_string(),
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

        // the coins: confirmed, mature, not coinbase, not locked, not spent by a mempool
        // transaction, never an output YED holds
        let (rate, cap) = crate::send::pq_fee_params(node).await;
        let mut cands: Vec<Cand> = Vec::new();
        if any_t || !taddrs.is_empty() {
            let spent = self.mempool_spent();
            let reserved = self.yed_reserved(node).await?;
            for (c, d) in self.available_coins(None) {
                let k = (c.txid.clone(), c.vout);
                if d < 1 || c.coinbase || spent.contains(&k) || reserved.contains(&k) {
                    continue;
                }
                let (key, pq) = match c.owner {
                    Owner::T(chain, index) => {
                        if !any_t && !taddrs.contains(&c.script) {
                            continue;
                        }
                        (KeyRef::Bip32 { chain, index }, None)
                    }
                    Owner::Pq(scheme, index) => {
                        // a post-quantum coin only from its named address, and only one worth
                        // more than the fee its own input adds (audit A-M2)
                        if !taddrs.contains(&c.script)
                            || c.value <= pq_input_marginal_fee(scheme, rate)
                        {
                            continue;
                        }
                        (KeyRef::Pq { scheme, index }, Some(scheme))
                    }
                };
                cands.push(Cand {
                    op: yew_core::tx::OutPoint {
                        txid: yew_core::tx::txid_from_hex(&c.txid)
                            .map_err(|e| RpcError::new(code::MISC_ERROR, e))?,
                        n: c.vout,
                    },
                    value: c.value,
                    script: c.script.clone(),
                    key,
                    pq,
                });
            }
            cands.sort_by(|a, b| (a.op.txid, a.op.n).cmp(&(b.op.txid, b.op.n)));
        }
        let (mut merged_t, mut remaining_t) = (0i64, 0i64);
        let (mut counter_t, mut n_pq) = (0usize, 0usize);
        let mut sigops = 1usize;
        let mut maxed = false;
        let mut sel: Vec<Cand> = Vec::new();
        for c in cands {
            counter_t += 1;
            if !maxed {
                let increase = c.pq.map_or(CTXIN_SPEND_P2PKH_SIZE, plan::pq_input_size);
                let ops = if c.pq.is_some() { PQ_SIGOP_COST } else { 0 };
                if estimated + increase >= MAX_TX_SIZE
                    || (utxo_limit > 0 && counter_t as i64 > utxo_limit)
                    || (c.pq.is_some() && n_pq >= MAX_PQ_INPUTS_PER_TX)
                    || sigops + ops > MAX_STANDARD_TX_SIGOPS
                {
                    maxed = true;
                } else {
                    estimated += increase;
                    merged_t += c.value;
                    sigops += ops;
                    n_pq += usize::from(c.pq.is_some());
                    sel.push(c);
                    continue;
                }
            }
            remaining_t += c.value;
        }
        // the notes, at the anchor depth
        let (mut merged_z, mut remaining_z) = (0i64, 0i64);
        let mut counter_z = 0usize;
        let mut sel_z: Vec<crate::NoteRow> = Vec::new();
        if any_z || !zaddrs.is_empty() {
            let mut maxed = false;
            let mut notes: Vec<crate::NoteRow> = self
                .notes
                .iter()
                .filter(|n| {
                    !n.spent
                        && n.position.is_some()
                        && self.depth(n.height) >= ANCHOR_CONFIRMATIONS
                        && (any_z || zaddrs.contains(&n.address))
                })
                .cloned()
                .collect();
            notes.sort_by(|a, b| (&a.txid, a.outindex).cmp(&(&b.txid, b.outindex)));
            for n in notes {
                counter_z += 1;
                if !maxed {
                    if estimated + SPENDDESCRIPTION_SIZE >= MAX_TX_SIZE
                        || (note_limit > 0 && counter_z as i64 > note_limit)
                    {
                        maxed = true;
                    } else {
                        estimated += SPENDDESCRIPTION_SIZE;
                        merged_z += n.value as i64;
                        sel_z.push(n);
                        continue;
                    }
                }
                remaining_z += n.value as i64;
            }
        }
        if sel.is_empty() && sel_z.is_empty() {
            return Err(RpcError::new(
                code::WALLET_INSUFFICIENT_FUNDS,
                "Could not find any funds to merge.",
            ));
        }
        if seen.len() == 1 && seen.contains(dest_str) && sel.len() + sel_z.len() == 1 {
            return Err(invalid("Destination address is also the only source address, and all its funds are already merged."));
        }
        let merged = merged_t + merged_z;
        let z_outs = if dest.is_err() || !sel_z.is_empty() {
            2
        } else {
            0
        };
        let t_outs: Vec<(Vec<u8>, i64)> = match &dest {
            Ok(s) => vec![(s.clone(), merged)],
            Err(_) => Vec::new(),
        };
        let fee_zat = if n_pq > 0 {
            // ycash6 PQBuilderFee(fee or LEGACY_DEFAULT_FEE, the shape): the default raised to it,
            // an explicit fee below it refused; never above the post-quantum cap
            let (bytes, conventional) = plan::shape_size(
                sel.iter().map(|c| c.script.as_slice()),
                &t_outs,
                sel_z.len(),
                z_outs,
            );
            if let Some(f) = fee {
                if f > cap {
                    return Err(plan_error(PlanError::FeeAboveCap { fee: f, cap }));
                }
            }
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
            needed
        } else {
            let conventional = plan::conventional_fee_bytes(
                sel.len(),
                t_outs.len(),
                if pq_dest { 10 } else { 0 },
                sel_z.len(),
                if dest.is_err() { 1 } else { 0 },
            );
            match fee {
                Some(f) if f > WEIGHT_RATIO_CAP * conventional => {
                    return Err(invalid(format!("Fee {} is greater than {WEIGHT_RATIO_CAP} times the conventional fee for this tx (which is {}). There is no prioritisation benefit to a fee this large (see https://zips.z.cash/zip-0317#recommended-algorithm-for-block-template-construction), and it likely indicates a mistake in setting the fee.", plan::format_money(f), plan::format_money(conventional))));
                }
                Some(f) => f,
                // ycashd's default -feepolicy=peroutput for a merge's one output
                None => plan::peroutput_fee(plan::padded(usize::from(dest.is_err()))),
            }
        };
        let net = merged - fee_zat;
        if net <= 0 {
            return Err(RpcError::new(
                code::WALLET_INSUFFICIENT_FUNDS,
                format!(
                    "Insufficient funds: have {}, need {}.",
                    plan::format_money(merged),
                    plan::format_money(fee_zat)
                ),
            ));
        }
        if let Ok(s) = &dest {
            if pq_dest {
                let dust = crate::send::dust_threshold(s);
                if net < dust {
                    return Err(invalid(format!(
                        "Invalid parameter, amount {} is below the dust threshold {} of a post-quantum output",
                        plan::format_money(net),
                        plan::format_money(dust)
                    )));
                }
            }
        }
        // the privacy policy (ycashd's GetRequiredPrivacyPolicy, as z_sendmany's)
        let t_in = !sel.is_empty();
        let t_out = dest.is_ok();
        let addresses: BTreeSet<&Vec<u8>> = sel.iter().map(|c| &c.script).collect();
        let required = match (t_in, t_out) {
            (true, _) if addresses.len() > 1 && t_out => "NoPrivacy",
            (true, _) if addresses.len() > 1 => "AllowLinkingAccountAddresses",
            (true, true) => "AllowFullyTransparent",
            (true, false) => "AllowRevealedSenders",
            (false, true) => "AllowRevealedRecipients",
            (false, false) => "FullPrivacy",
        };
        if !plan::policy_allows(&policy, required) {
            return Err(plan_error(PlanError::Policy {
                policy: policy.clone(),
                required,
            }));
        }

        let mut ctx = serde_json::Map::new();
        ctx.insert("fromaddresses".into(), p[0].clone());
        ctx.insert("toaddress".into(), p[1].clone());
        if n_pq > 0 || fee.is_some() {
            ctx.insert(
                "fee".into(),
                serde_json::from_str(&crate::zsend::money8(fee_zat)).unwrap_or(Value::Null),
            );
        }
        let id = opid();
        let started = std::time::Instant::now();
        let created = now();
        let outcome = self
            .run_merge(
                node,
                &next,
                &sel,
                &sel_z,
                &dest,
                memo,
                net,
                fee_zat,
                n_pq > 0,
                rate,
                cap,
            )
            .await;
        let (status, error, txid) = match outcome {
            Ok(t) => ("success", None, Some(t)),
            Err(e) => ("failed", Some((e.code, e.message)), None),
        };
        self.ops.ops.push(Op {
            id: id.clone(),
            status,
            creation_time: created,
            error,
            txid,
            secs: started.elapsed().as_secs_f64(),
            params: Value::Object(ctx),
        });
        Ok(J::obj()
            .with("remainingUTXOs", (counter_t - sel.len()) as i64)
            .with("remainingTransparentValue", J::Amount(remaining_t))
            .with("remainingNotes", (counter_z - sel_z.len()) as i64)
            .with("remainingShieldedValue", J::Amount(remaining_z))
            .with("mergingUTXOs", sel.len() as i64)
            .with("mergingTransparentValue", J::Amount(merged_t))
            .with("mergingNotes", sel_z.len() as i64)
            .with("mergingShieldedValue", J::Amount(merged_z))
            .with("opid", id))
    }

    /// The merge's operation: the transaction built and signed in the signer (the transparent
    /// part with the Sapling part beside it), a post-quantum one re-priced on its signed size,
    /// then committed.
    #[allow(clippy::too_many_arguments)]
    async fn run_merge(
        &mut self,
        node: &dyn Node,
        next: &crate::build::Next,
        sel: &[Cand],
        sel_z: &[crate::NoteRow],
        dest: &Result<Vec<u8>, String>,
        memo: Option<String>,
        net: i64,
        fee_zat: i64,
        pq: bool,
        rate: i64,
        cap: i64,
    ) -> Result<String, RpcError> {
        let (anchor, paths) = if sel_z.is_empty() {
            (String::new(), Vec::new())
        } else {
            self.sapling_paths(node, sel_z, self.tip_height()).await?
        };
        let spends = sapling_spends(sel_z, paths);
        let output = match dest {
            Ok(s) => SaplingOut::Transparent {
                script: hex::encode(s),
                value: net,
                own: self.book.owns_script(s).is_some(),
            },
            Err(a) => SaplingOut::Shielded {
                address: a.clone(),
                value: net,
                memo: memo.unwrap_or_default(),
                own: self.view.owns_address(a).is_some(),
            },
        };
        let inputs: Vec<(yew_core::tx::OutPoint, i64, Vec<u8>, KeyRef)> = sel
            .iter()
            .map(|c| (c.op, c.value, c.script.clone(), c.key))
            .collect();
        let hexs = self
            .sign_hybrid(next, &inputs, spends, anchor, vec![output], net + fee_zat)
            .await?;
        if pq {
            let raw = hex::decode(&hexs)
                .map_err(|e| RpcError::new(code::INTERNAL_ERROR, e.to_string()))?;
            let (signed, _) = yew_core::tx::Transaction::parse(&raw).map_err(|e| {
                RpcError::new(
                    code::INTERNAL_ERROR,
                    format!("yewd: the signer's transaction: {e}"),
                )
            })?;
            let sizes: Vec<usize> = signed.vin.iter().map(|i| i.script_sig.len()).collect();
            let conventional = signed
                .zip317_conventional_fee(&sizes)
                .map_err(|e| RpcError::new(code::INTERNAL_ERROR, e.to_string()))?;
            plan::check_signed_fee(fee_zat, raw.len(), conventional, rate, cap)
                .map_err(|e| op_error(e.rpc_code(), e.to_string()))?;
        }
        self.commit_z(node, &hexs, pq && fee_zat <= cap).await
    }
}

fn plan_error(e: PlanError) -> RpcError {
    RpcError::new(e.rpc_code(), e.to_string())
}
