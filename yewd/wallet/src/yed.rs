// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The YED transfer builders (R6; ycash6 `src/rpc/yellowbackwallet.cpp` `yed_send`,
//! `yed_sendmany`, `yed_estimatesend`, `yed_lockcoins`, `yed_unlockcoin`;
//! `src/yellowback/txbuilder.cpp` `BuildTransfer`, `EstimateTransfer`, `SelectYed`,
//! `PickYecCoins`, `YedNetworkFee`). The pure parts are yew-core's: the floor-aware selector
//! (`coinselect.rs`, the node's verbatim), the TRANSFER payload codec (`payload.rs`), the
//! holder rule (`build::yed_transfer::yed_holder_script`). The coins are the node index's tokens at
//! this wallet's scripts (`yed_listtokens`), the fee rates the node's (`yed_getinfo`), and the
//! signatures the signer's.

use std::collections::BTreeSet;

use serde_json::Value;
use yew_core::coinselect;
use yew_core::params::{MAX_INPUTS, MIN_OUTPUT_CENTS, TOKEN_VALUE};
use yew_core::payload::{self, Assignment, Payload, MAX_ASSIGNMENTS};
use yew_core::tx::{OutPoint, Transaction, TxIn, TxOut};
use yewd_proto::{GatePath, KeyRef};

use crate::build::{next_block, NodeCoin};
use crate::json::J;
use crate::keys::Owner;
use crate::node::{self, Node};
use crate::rpc::invalid;
use crate::{code, txid_hex, RpcError, Wallet};

/// The R6 builders S2 serves.
pub const SERVED: &[&str] = &[
    "yed_send",
    "yed_sendmany",
    "yed_estimatesend",
    "yed_lockcoins",
    "yed_unlockcoin",
    "yed_redeem",
    "yed_estimateredeem",
];

/// `maxOutput` (XFER-1): $100,000 per output.
pub const MAX_OUTPUT_CENTS: i64 = 10_000_000;
/// `MAX_YEC_INPUTS`, `MAX_YEC_INPUT_BYTES` (`PickYecCoins`'s caps).
pub const MAX_YEC_INPUTS: usize = 200;
pub const MAX_YEC_INPUT_BYTES: usize = 90_000;
/// `TX_EXPIRING_SOON_THRESHOLD`.
const EXPIRING_SOON: u32 = 3;
const UNLOCK_ACKNOWLEDGEMENT: &str = "I understand this burns YED";

/// A YED coin of the wallet: a confirmed token at one of its holder scripts.
#[derive(Clone, Debug)]
pub(crate) struct YedCoin {
    pub(crate) outpoint: OutPoint,
    pub(crate) cents: i64,
    pub(crate) script: Vec<u8>,
    pub(crate) value: i64,
}

/// What the builders need of the node's Yellowback parameters (`yed_getinfo`).
#[derive(Clone, Debug)]
pub(crate) struct YedInfo {
    pub(crate) index_height: i64,
    pub(crate) ref_lag: i64,
    pub(crate) ref_window: i64,
    pub(crate) flat_fee: i64,
    pub(crate) rate_per_kb: i64,
    pub(crate) max_fee: i64,
}

/// `PQSpendInputSize`: a post-quantum input's serialized size.
fn pq_input_size(scheme: u8) -> usize {
    let ss = yew_core::pq::pq_sig_pushes_size(scheme).unwrap_or(0);
    40 + if ss > 252 { 3 } else { 1 } + ss
}

/// The bytes `YedEstimatedSize` counts for one input.
pub(crate) fn input_bytes(script: &[u8]) -> usize {
    match yew_core::pq::pqpkh_of(script) {
        Some(id) => pq_input_size(id.scheme),
        None => 150,
    }
}

impl YedInfo {
    /// `YedNetworkFee`: max(flat, min(max(flat, rate × size), cap)) over the estimated size.
    pub(crate) fn network_fee(&self, scripts: &[&[u8]]) -> i64 {
        let bytes = 1000 + scripts.iter().map(|s| input_bytes(s)).sum::<usize>() as i64;
        let sized = self.flat_fee.max(self.rate_per_kb * bytes / 1000);
        self.flat_fee.max(sized.min(self.max_fee))
    }
}

pub(crate) async fn yed_info(node: &dyn Node) -> Result<YedInfo, RpcError> {
    let v = node::call(node, "yed_getinfo", serde_json::json!([])).await?;
    let p = &v["params"];
    let net = &p["fees"]["network"];
    Ok(YedInfo {
        index_height: v["height"].as_i64().unwrap_or(0),
        ref_lag: p["refLag"].as_i64().unwrap_or(2),
        ref_window: p["refWindow"].as_i64().unwrap_or(40),
        flat_fee: p["feeZat"].as_i64().or_else(|| net["flatZat"].as_i64()).unwrap_or(10_000),
        rate_per_kb: net["yellowback"]["zatPerKB"].as_i64().unwrap_or(0),
        max_fee: net["yellowback"]["maxTxFeeZat"].as_i64().unwrap_or(crate::build::DEFAULT_MAX_TX_FEE),
    })
}

/// A build failure with ycashd's code (`ThrowBuildError`): the rule identifiers `-26`... as the
/// node maps them; the parameter identifiers `-8`; the rest `-4`.
fn build_error(msg: String) -> RpcError {
    const PARAM: &[&str] = &["bad-xfer-amount", "not-a-yellowback-address", "bad-address", "vault-not-found", "vault-not-active", "vault-not-owned"];
    if PARAM.iter().any(|p| msg.starts_with(p)) {
        RpcError::new(code::INVALID_PARAMETER, msg)
    } else if msg.starts_with("mempool-check-failed") || msg.starts_with("vault-spend-") {
        RpcError::new(-26, msg)
    } else {
        RpcError::new(code::WALLET_ERROR, msg)
    }
}

impl Wallet {
    pub async fn yed_call(&mut self, node: &dyn Node, method: &str, p: &[Value]) -> Result<J, RpcError> {
        match method {
            "yed_send" => {
                if p.len() != 2 {
                    return Err(RpcError::new(code::MISC_ERROR, "yed_send \"yedaddress\" cents"));
                }
                let dest = self.parse_yed_address(&p[0])?;
                let cents = p[1].as_i64().ok_or_else(|| RpcError::new(code::TYPE_ERROR, "Expected type number"))?;
                self.do_send(node, vec![(dest, cents)]).await
            }
            "yed_sendmany" => {
                if p.len() != 1 {
                    return Err(RpcError::new(code::MISC_ERROR, "yed_sendmany {\"yedaddress\":cents,...}"));
                }
                let o = p[0].as_object().ok_or_else(|| RpcError::new(code::TYPE_ERROR, "Expected type object"))?;
                let mut r = Vec::new();
                for (k, v) in o {
                    let dest = self.parse_yed_address(&Value::String(k.clone()))?;
                    r.push((dest, v.as_i64().ok_or_else(|| RpcError::new(code::TYPE_ERROR, "Expected type number"))?));
                }
                self.do_send(node, r).await
            }
            "yed_estimatesend" => self.yed_estimatesend(node, p).await,
            "yed_lockcoins" => self.yed_lockcoins(node, p).await,
            "yed_unlockcoin" => self.yed_unlockcoin(node, p).await,
            "yed_redeem" => self.yed_redeem(node, p).await,
            "yed_estimateredeem" => self.yed_estimateredeem(node, p).await,
            _ => Err(RpcError::new(code::METHOD_NOT_FOUND, "Method not found")),
        }
    }

    /// `ParseYedAddress`: a Yellowback address of this network, either form.
    fn parse_yed_address(&self, v: &Value) -> Result<Vec<u8>, RpcError> {
        let s = v.as_str().unwrap_or("");
        if let Ok(id) = yew_core::keys::parse_pq_address(self.network, s) {
            if let Some(sc) = yew_core::pq::pqpkh_script(&id) {
                return Ok(sc);
            }
        }
        if let Ok(a) = yew_core::keys::parse_address(self.network, s) {
            if let yew_core::keys::AddressKind::P2pkh(h) = a.kind {
                if yew_core::keys::encode_yellowback(self.network, &h) == s {
                    return Ok(yew_core::script::p2pkh_script(&h));
                }
            }
        }
        let prefix: String = yew_core::keys::encode_yellowback(self.network, &[0u8; 20]).chars().take(2).collect();
        Err(invalid(format!("not-a-yellowback-address: expected a Yellowback address of this network (prefix '{prefix}')")))
    }

    /// The spendable YED coins in the selector's canonical order (`RankedCoins`): confirmed tokens at
    /// this wallet's scripts not spent by a mempool transaction.
    pub(crate) async fn ranked_coins(&self, node: &dyn Node) -> Result<Vec<YedCoin>, RpcError> {
        let spent = self.mempool_spent();
        let mut v = Vec::new();
        for t in self.tokens(node).await? {
            let txid = t["txid"].as_str().unwrap_or("").to_string();
            let vout = t["vout"].as_u64().unwrap_or(0) as u32;
            if spent.contains(&(txid.clone(), vout)) {
                continue;
            }
            let Some(c) = self.coins.iter().find(|c| c.txid == txid && c.vout == vout) else { continue };
            v.push(YedCoin {
                outpoint: OutPoint { txid: yew_core::tx::txid_from_hex(&txid).map_err(|e| RpcError::new(code::MISC_ERROR, e))?, n: vout },
                cents: t["cents"].as_i64().unwrap_or(0),
                script: c.script.clone(),
                value: c.value,
            });
        }
        v.sort_by(|a, b| {
            (a.cents, txid_hex(&a.outpoint.txid), a.outpoint.n).cmp(&(b.cents, txid_hex(&b.outpoint.txid), b.outpoint.n))
        });
        Ok(v)
    }

    /// `SelectYed` (a transfer never burns).
    fn select_yed(coins: &[YedCoin], needed: i64) -> Result<(Vec<YedCoin>, i64, &'static str), RpcError> {
        let cents: Vec<i64> = coins.iter().map(|c| c.cents).collect();
        let have: i64 = cents.iter().sum();
        let s = coinselect::select_floor_aware(&cents, needed, MIN_OUTPUT_CENTS as i64, MAX_INPUTS, false);
        if !s.ok {
            if s.insufficient {
                return Err(build_error(format!("insufficient-yed: need {needed} cents, have {have} confirmed and spendable")));
            }
            if s.too_many_inputs {
                return Err(build_error(format!("too-many-inputs: more than {MAX_INPUTS} YED inputs would be needed; consolidate first")));
            }
            let alt = coinselect::nearest_workable(&cents, needed, MIN_OUTPUT_CENTS as i64, MAX_INPUTS);
            let show = |o: Option<i64>| o.map(|v| v.to_string()).unwrap_or_else(|| "none".into());
            return Err(build_error(format!(
                "change-floor: {needed} cents cannot be sent from these coins without change below the ${}.{:02} minimum output; nearest workable amounts: below {}, above {}",
                MIN_OUTPUT_CENTS / 100,
                MIN_OUTPUT_CENTS % 100,
                show(alt.below),
                show(alt.above)
            )));
        }
        Ok((s.inputs.iter().map(|&i| coins[i].clone()).collect(), s.change, s.stage.name()))
    }

    /// `SelectYec` / `PickYecCoins`: confirmed plain YEC coins (never a token, a vault or P2SH),
    /// smallest first, largest first when that would cross a cap; the fee follows a PQ coin.
    pub(crate) async fn pick_yec(&self, node: &dyn Node, needed: i64, info: &YedInfo, prior: &[Vec<u8>], fee0: i64) -> Result<(Vec<(OutPoint, i64, Vec<u8>)>, i64), RpcError> {
        if needed <= 0 {
            return Ok((vec![], fee0));
        }
        let mut cand = Vec::new();
        for c in self.eligible(node, &Default::default()).await? {
            cand.push((c.outpoint, c.value, c.script));
        }
        // eligible() is P2PKH only; the wallet's own PQ coins (TX_PQPKH) are YEC too
        let spent = self.mempool_spent();
        let reserved = self.yed_reserved(node).await?;
        for (c, d) in self.available_coins(None) {
            if d < 1 || !matches!(c.owner, Owner::Pq(..)) || spent.contains(&(c.txid.clone(), c.vout)) || reserved.contains(&(c.txid.clone(), c.vout)) {
                continue;
            }
            let op = OutPoint { txid: yew_core::tx::txid_from_hex(&c.txid).map_err(|e| RpcError::new(code::MISC_ERROR, e))?, n: c.vout };
            cand.push((op, c.value, c.script.clone()));
        }
        let attempt = |order: &[usize]| -> (Vec<usize>, i64, i64, bool, bool) {
            let mut picked = Vec::new();
            let mut sel = 0i64;
            let mut need = needed;
            let mut fee = fee0;
            let mut bytes = 0usize;
            let mut scripts: Vec<&[u8]> = prior.iter().map(|s| s.as_slice()).collect();
            for &i in order {
                picked.push(i);
                sel += cand[i].1;
                bytes += input_bytes(&cand[i].2);
                if picked.len() > MAX_YEC_INPUTS || bytes > MAX_YEC_INPUT_BYTES {
                    return (picked, sel, need, false, true);
                }
                scripts.push(&cand[i].2);
                let next = info.network_fee(&scripts);
                if next > fee {
                    need += next - fee;
                    fee = next;
                }
                if sel >= need {
                    return (picked, sel, fee, true, false);
                }
            }
            (picked, sel, need, false, false)
        };
        let mut order: Vec<usize> = (0..cand.len()).collect();
        order.sort_by_key(|&i| cand[i].1);
        let mut r = attempt(&order);
        if !r.3 && r.4 {
            order.reverse();
            r = attempt(&order);
        }
        let (picked, sel, fee_or_need, ok, too_many) = r;
        if too_many {
            return Err(build_error(format!(
                "too-many-coins: covering {} YEC would take more than {MAX_YEC_INPUTS} coins (or {MAX_YEC_INPUT_BYTES} bytes of inputs); combine small coins first by sending them to yourself, then retry",
                crate::rpc::format_money(needed)
            )));
        }
        if !ok {
            return Err(build_error(format!(
                "insufficient-yec: need {}, have {} confirmed and unlocked",
                crate::rpc::format_money(fee_or_need),
                crate::rpc::format_money(sel)
            )));
        }
        Ok((picked.into_iter().map(|i| cand[i].clone()).collect(), fee_or_need))
    }

    /// A fresh YED holder script for change (`FreshHolderScript`): a Falcon key from the Falcon
    /// height, else a new P2PKH key (in the book with purpose `yellowback-change`).
    pub(crate) fn fresh_holder(&mut self) -> Result<Vec<u8>, RpcError> {
        if self.falcon_next() {
            let id = self.new_pq(2)?;
            return yew_core::pq::pqpkh_script(&id).ok_or_else(|| RpcError::new(code::WALLET_ERROR, "keypool-empty: cannot draw a post-quantum holder key"));
        }
        let pk = self.new_wallet_key()?;
        let h = yew_core::keys::hash160(&pk);
        self.st.book.insert(
            yew_core::keys::encode_p2pkh(self.network, &h),
            crate::state::BookEntry { label: String::new(), purpose: "yellowback-change".into() },
        );
        Ok(yew_core::script::p2pkh_script(&h))
    }

    /// `DoSend` / `BuildTransfer`.
    async fn do_send(&mut self, node: &dyn Node, recipients: Vec<(Vec<u8>, i64)>) -> Result<J, RpcError> {
        let info = yed_info(node).await?;
        let next = next_block(node).await?;
        if recipients.is_empty() {
            return Err(build_error("no recipients".into()));
        }
        if recipients.len() > MAX_ASSIGNMENTS - 1 {
            return Err(build_error(format!("at most {} recipients per transaction", MAX_ASSIGNMENTS - 1)));
        }
        let falcon = self.falcon_next();
        for (s, _) in &recipients {
            let pq2 = yew_core::pq::pqpkh_of(s).is_some_and(|id| id.scheme == 2);
            if falcon && !pq2 {
                return Err(build_error("bad-yed-holder: from the Falcon height YED is held by post-quantum (Falcon) addresses only; pass a 53-character yb…/yt…/yr… address".into()));
            }
        }
        let mut needed = 0i64;
        for (_, c) in &recipients {
            if *c < MIN_OUTPUT_CENTS as i64 || *c > MAX_OUTPUT_CENTS {
                return Err(build_error(format!("bad-xfer-amount: each amount must be between {MIN_OUTPUT_CENTS} and {MAX_OUTPUT_CENTS} cents")));
            }
            needed += c;
        }
        let coins = self.ranked_coins(node).await?;
        let (sel, change, _) = Self::select_yed(&coins, needed)?;
        let ref_height = info.index_height - info.ref_lag;
        let expiry = (ref_height + info.ref_window) as u32;
        if expiry < next.height + EXPIRING_SOON {
            return Err(build_error("expiring-too-soon: the transaction would expire too soon; the index is too far behind the chain".into()));
        }
        let mut base = Transaction::new_v4();
        base.expiry_height = expiry;
        for c in &sel {
            base.vin.push(TxIn::new(c.outpoint));
        }
        let mut assignments = Vec::new();
        for (i, (s, c)) in recipients.iter().enumerate() {
            base.vout.push(TxOut { value: TOKEN_VALUE, script_pubkey: s.clone() });
            assignments.push(Assignment { vout: i as u8, cents: *c as u32 });
        }
        if change > 0 {
            let s = self.fresh_holder()?;
            base.vout.push(TxOut { value: TOKEN_VALUE, script_pubkey: s });
            assignments.push(Assignment { vout: recipients.len() as u8, cents: change as u32 });
        }
        let pl = payload::encode(&Payload::Transfer { assignments }).ok_or_else(|| build_error("cannot encode the transfer payload".into()))?;
        base.vout.push(TxOut { value: 0, script_pubkey: payload::payload_script(&pl) });
        let token_in: i64 = sel.iter().map(|c| c.value).sum();
        let token_out = (recipients.len() as i64 + (change > 0) as i64) * TOKEN_VALUE;
        let yed_scripts: Vec<Vec<u8>> = sel.iter().map(|c| c.script.clone()).collect();
        let mut fee_floor = info.flat_fee;
        let change_script = self.new_change()?;
        let (tx, prevs, fee) = loop {
            let mut tx = base.clone();
            let scripts: Vec<&[u8]> = yed_scripts.iter().map(|s| s.as_slice()).collect();
            let fee0 = fee_floor.max(info.network_fee(&scripts));
            let yec_needed = token_out + fee0 - token_in;
            let (yec, fee) = self.pick_yec(node, yec_needed, &info, &yed_scripts, fee0).await?;
            let selected: i64 = yec.iter().map(|c| c.1).sum();
            let yec_change = selected - yec_needed - (fee - fee0);
            for c in &yec {
                tx.vin.push(TxIn::new(c.0));
            }
            if yec_change > 0 {
                tx.vout.push(TxOut { value: yec_change, script_pubkey: change_script.clone() });
            }
            // P-2: the ZIP-317 conventional fee of the signed shape
            let sizes: Vec<usize> = sel
                .iter()
                .map(|c| c.script.as_slice())
                .chain(yec.iter().map(|c| c.2.as_slice()))
                .map(yew_core::tx::script_sig_size_bound)
                .collect();
            let conventional = tx.zip317_conventional_fee(&sizes).unwrap_or(0);
            let paid = fee + if yec_change < 0 { yec_change } else { 0 };
            if conventional > paid.max(fee) && conventional > fee_floor {
                fee_floor = conventional;
                continue;
            }
            let mut prevs: Vec<NodeCoin> = sel.iter().map(|c| NodeCoin { value: c.value, script: c.script.clone(), height: None, coinbase: false }).collect();
            prevs.extend(yec.iter().map(|c| NodeCoin { value: c.1, script: c.2.clone(), height: None, coinbase: false }));
            break (tx, prevs, fee);
        };
        let keys: Vec<KeyRef> = prevs.iter().map(|p| self.key_of_script(&p.script).unwrap_or(KeyRef::None)).collect();
        // the outflow the request implies: the recipients' token outputs and the fee
        let cap = recipients.len() as i64 * TOKEN_VALUE + fee + 1;
        let signed = self.sign_inputs(&tx, &prevs, &keys, &[], GatePath::Yed, cap, next.branch).await?;
        let txid = self.broadcast(node, &signed, Some(info.max_fee)).await?;
        Ok(J::obj().with("txid", txid).with("changeCents", change).with("expiryHeight", expiry as i64))
    }

    /// `yed_estimatesend {"yedaddress":cents,...}|cents`.
    async fn yed_estimatesend(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        if p.len() != 1 {
            return Err(RpcError::new(code::MISC_ERROR, "yed_estimatesend {\"yedaddress\":cents,...}|cents"));
        }
        let bad = || invalid(format!("bad-xfer-amount: each amount must be between {MIN_OUTPUT_CENTS} and {MAX_OUTPUT_CENTS} cents"));
        let (amount, recipients) = if let Some(o) = p[0].as_object() {
            if o.is_empty() {
                return Err(invalid("no recipients"));
            }
            if o.len() > MAX_ASSIGNMENTS - 1 {
                return Err(invalid(format!("at most {} recipients per transaction", MAX_ASSIGNMENTS - 1)));
            }
            let mut a = 0i64;
            for (k, v) in o {
                self.parse_yed_address(&Value::String(k.clone()))?;
                let one = v.as_i64().ok_or_else(|| RpcError::new(code::TYPE_ERROR, "Expected type number"))?;
                if one < MIN_OUTPUT_CENTS as i64 || one > MAX_OUTPUT_CENTS {
                    return Err(bad());
                }
                a += one;
            }
            (a, o.len())
        } else {
            (p[0].as_i64().ok_or_else(|| RpcError::new(code::TYPE_ERROR, "Expected type number"))?, 1)
        };
        if amount < MIN_OUTPUT_CENTS as i64 || amount > MAX_OUTPUT_CENTS {
            return Err(bad());
        }
        let info = yed_info(node).await?;
        let coins = self.ranked_coins(node).await?;
        let cents: Vec<i64> = coins.iter().map(|c| c.cents).collect();
        let spendable: i64 = cents.iter().sum();
        let s = coinselect::select_floor_aware(&cents, amount, MIN_OUTPUT_CENTS as i64, MAX_INPUTS, false);
        let mut o = J::obj()
            .with("amountCents", amount)
            .with("recipients", recipients as i64)
            .with("workable", s.ok)
            .with("stage", s.stage.name());
        if s.ok {
            let sel: Vec<&YedCoin> = s.inputs.iter().map(|&i| &coins[i]).collect();
            let scripts: Vec<&[u8]> = sel.iter().map(|c| c.script.as_slice()).collect();
            o.push(
                "inputs",
                J::Arr(sel.iter().map(|c| J::obj().with("txid", txid_hex(&c.outpoint.txid)).with("vout", c.outpoint.n as i64).with("cents", c.cents)).collect()),
            );
            o.push("selectedCents", J::Int(s.selected));
            o.push("changeCents", J::Int(s.change));
            o.push("spendableCents", J::Int(spendable));
            o.push("networkFeeZat", J::Int(info.network_fee(&scripts)));
            o.push("error", J::Str(String::new()));
            o.push("alternatives", J::Null);
        } else {
            let alt = coinselect::nearest_workable(&cents, amount, MIN_OUTPUT_CENTS as i64, MAX_INPUTS);
            let err = if s.insufficient { "insufficient-yed" } else if s.too_many_inputs { "too-many-inputs" } else { "change-floor" };
            o.push("inputs", J::Arr(vec![]));
            o.push("selectedCents", J::Int(0));
            o.push("changeCents", J::Int(0));
            o.push("spendableCents", J::Int(spendable));
            o.push("networkFeeZat", J::Null);
            o.push("error", J::Str(err.into()));
            o.push(
                "alternatives",
                J::obj().with("below", alt.below.map(J::Int).unwrap_or(J::Null)).with("above", alt.above.map(J::Int).unwrap_or(J::Null)),
            );
        }
        Ok(o)
    }

    /// `yed_lockcoins`: the outputs YED holds (tokens and the wallet's vaults), locked against plain
    /// YEC selection (H5); returns them.
    async fn yed_lockcoins(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        if !p.is_empty() {
            return Err(RpcError::new(code::MISC_ERROR, "yed_lockcoins"));
        }
        let reserved: BTreeSet<(String, u32)> = self.yed_reserved(node).await?;
        let mut out = Vec::new();
        for (t, n) in &reserved {
            if self.coins.iter().any(|c| c.txid == *t && c.vout == *n && !c.spent) {
                self.st.locks.insert(format!("{t}:{n}"));
                out.push(J::obj().with("txid", t.clone()).with("vout", *n as i64));
            }
        }
        self.persist_state()?;
        Ok(J::Arr(out))
    }

    /// `yed_unlockcoin "txid" n "acknowledgement"`.
    async fn yed_unlockcoin(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        if p.len() != 3 {
            return Err(RpcError::new(code::MISC_ERROR, "yed_unlockcoin \"txid\" n \"acknowledgement\""));
        }
        let txid = p[0].as_str().unwrap_or("").to_lowercase();
        if txid.len() != 64 || !txid.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(invalid("txid must be of length 64"));
        }
        let n = p[1].as_i64().ok_or_else(|| RpcError::new(code::TYPE_ERROR, "Expected type number"))?;
        if n < 0 {
            return Err(invalid("vout must not be negative"));
        }
        if p[2].as_str() != Some(UNLOCK_ACKNOWLEDGEMENT) {
            return Err(invalid(format!("unlock-acknowledgement-missing: the third argument must be exactly \"{UNLOCK_ACKNOWLEDGEMENT}\"")));
        }
        let key = format!("{txid}:{n}");
        let was = self.st.locks.remove(&key);
        self.persist_state()?;
        let cents = self
            .tokens(node)
            .await
            .unwrap_or_default()
            .iter()
            .find(|t| t["txid"].as_str() == Some(txid.as_str()) && t["vout"].as_i64() == Some(n))
            .and_then(|t| t["cents"].as_i64())
            .unwrap_or(0);
        Ok(J::obj()
            .with("txid", txid)
            .with("vout", n)
            .with("unlocked", true)
            .with("wasYellowbackLocked", was)
            .with("cents", cents))
    }

    // ------------------------------------------------------------------ redeem

    /// The vault record (`yed_getvault`), `vault-not-found` as ycashd.
    pub(crate) async fn yed_vault(node: &dyn Node, txid: &str) -> Result<Value, RpcError> {
        match node::call(node, "yed_getvault", serde_json::json!([txid])).await {
            Ok(v) => Ok(v),
            Err(crate::node::NodeError::Rpc { message, .. }) if message.contains("vault-not-found") => {
                Err(invalid(format!("vault-not-found: no vault at {txid}:0")))
            }
            Err(e) => Err(e.into()),
        }
    }

    /// The txid of a mempool transaction spending `op`, if any (`MempoolSpenderOf`).
    pub(crate) async fn mempool_spender(node: &dyn Node, op: &OutPoint) -> Result<Option<String>, RpcError> {
        if crate::build::node_coin(node, op).await?.is_some() {
            return Ok(None);
        }
        let ids = node::mempool(node).await?;
        for t in ids {
            if let Some(raw) = node::raw_tx(node, &t).await? {
                if let Ok((tx, _)) = Transaction::parse(&raw) {
                    if tx.vin.iter().any(|i| i.prevout == *op) {
                        return Ok(Some(t));
                    }
                }
            }
        }
        Ok(None)
    }

    /// FEE-W's payee for a vault spend at `r` (`yed_getfeepayee r <outpoint selector>`); `None`
    /// under FEE-0 (no eligible payee).
    pub(crate) async fn spend_payee(node: &dyn Node, r: i64, op: &OutPoint) -> Result<Option<String>, RpcError> {
        let mut sel = op.txid.to_vec();
        sel.extend_from_slice(&op.n.to_le_bytes());
        match node::call(node, "yed_getfeepayee", serde_json::json!([r, hex::encode(sel)])).await {
            Ok(v) => Ok(v["preferred"].as_str().or_else(|| v["default"]["payoutAddress"].as_str()).map(str::to_string)),
            Err(crate::node::NodeError::Rpc { message, .. }) if message.contains("fee-no-eligible-payee") => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// IT-9': the early-redeem fee of an ACTIVE vault redeemed at `r + 1` (0 at or past lockHeight,
    /// under FEE-0, for an unknown class).
    async fn early_fee(node: &dyn Node, v: &Value, r: i64, payee: bool) -> Result<(i64, i64, i64), RpcError> {
        let info = node::call(node, "yed_getinfo", serde_json::json!([])).await?;
        let class = v["termClass"].as_str().unwrap_or("");
        let idx = match class {
            "A" => 0,
            "B" => 1,
            "C" => 2,
            _ => usize::MAX,
        };
        let bps = info["params"]["earlyRedeemFeeBps"].get(idx).and_then(|b| b.as_i64()).unwrap_or(0);
        let minted = v["mintedCents"].as_i64().unwrap_or(0);
        let p_mint = v["pMint"].as_i64().unwrap_or(0);
        let active = v["status"].as_str() == Some("ACTIVE");
        if !active || !payee || r + 1 >= v["lockHeight"].as_i64().unwrap_or(0) || idx == usize::MAX {
            return Ok((0, 0, bps));
        }
        let zat = yew_core::params::early_redeem_fee_zat(minted as u64, bps, p_mint);
        let cents = (minted * bps + 9_999) / 10_000;
        Ok((zat, cents, bps))
    }

    /// `yed_redeem "vaultTxid" ( "to" )` (`BuildRedeem` → `BuildVaultSpend`, owner path).
    async fn yed_redeem(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        if p.is_empty() || p.len() > 2 {
            return Err(RpcError::new(code::MISC_ERROR, "yed_redeem \"vaultTxid\" ( \"to\" )"));
        }
        let txid_s = p[0].as_str().unwrap_or("").to_lowercase();
        let txid = yew_core::tx::txid_from_hex(&txid_s).map_err(|_| invalid("vaultTxid must be hexadecimal string of length 64"))?;
        let op = OutPoint { txid, n: 0 };
        let to = p.get(1).and_then(|v| v.as_str()).unwrap_or("").to_string();
        // N1: a pending spend is refused before coin selection
        if let Some(sp) = Self::mempool_spender(node, &op).await? {
            return Err(RpcError::new(code::WALLET_ERROR, format!("vault-spend-pending: the vault {txid_s}:0 already has a spend in the mempool ({sp}); wait for it to confirm or expire")));
        }
        let v = Self::yed_vault(node, &txid_s).await?;
        let info = yed_info(node).await?;
        let next = next_block(node).await?;
        let status = v["status"].as_str().unwrap_or("").to_string();
        if status != "ACTIVE" && status != "VOID" {
            return Err(build_error(format!("vault-not-active: the vault is {status}")));
        }
        let owner = yew_core::pq::PqKeyId {
            scheme: v["ownerScheme"].as_u64().unwrap_or(0) as u8,
            hash: hex::decode(v["ownerHash"].as_str().unwrap_or("")).ok().and_then(|b| b.try_into().ok()).unwrap_or([0; 32]),
        };
        let owner_key = self
            .owner_ref(&owner, yew_core::vault::SEL_OWNER)
            .ok_or_else(|| build_error("vault-not-owned: the vault owner key is not in this wallet".into()))?;
        let owner_height = v["ownerHeight"].as_i64().or_else(|| {
            // the V template's ownerHeight (U-23): parse it from the script
            hex::decode(v["scriptPubKey"].as_str().unwrap_or("")).ok().and_then(|s| yew_core::vault::parse_vault(&s)).map(|vp| vp.owner_height)
        }).unwrap_or(0);
        if info.index_height < owner_height {
            return Err(RpcError::new(-26, format!("vault-locked: the vault is locked until height {owner_height} (tip {})", info.index_height)));
        }
        let vault_script = hex::decode(v["scriptPubKey"].as_str().unwrap_or("")).map_err(|_| build_error("vault-not-found: cannot reconstruct the vault script".into()))?;
        let vp = yew_core::vault::parse_vault(&vault_script).ok_or_else(|| build_error("vault-not-found: cannot reconstruct the vault script".into()))?;
        let r = info.index_height;
        let active = status == "ACTIVE";
        let minted = v["mintedCents"].as_i64().unwrap_or(0);
        let collateral = v["collateralZat"].as_i64().unwrap_or(0);
        let (mut yed_inputs, mut change, mut extra_burn) = (Vec::new(), 0i64, 0i64);
        let mut payee: Option<String> = None;
        let mut fee_zat = 0i64;
        let mut early = 0i64;
        if active {
            let coins = self.ranked_coins(node).await?;
            let cents: Vec<i64> = coins.iter().map(|c| c.cents).collect();
            let have: i64 = cents.iter().sum();
            let s = coinselect::select_floor_aware(&cents, minted, MIN_OUTPUT_CENTS as i64, MAX_INPUTS, true);
            if !s.ok {
                if s.insufficient {
                    return Err(build_error(format!("insufficient-yed: need {minted} cents, have {have} confirmed and spendable")));
                }
                return Err(build_error(format!("too-many-inputs: more than {MAX_INPUTS} YED inputs would be needed; consolidate first")));
            }
            yed_inputs = s.inputs.iter().map(|&i| coins[i].clone()).collect();
            change = s.change;
            extra_burn = s.extra_burn;
            payee = Self::spend_payee(node, r, &op).await?;
            if let Some(py) = &payee {
                fee_zat = yew_core::build::terms::protocol_fee(minted as u64, v["pMint"].as_i64().unwrap_or(0), py).map_err(|e| build_error(e.to_string()))?;
            }
            let (e, _, _) = Self::early_fee(node, &v, r, payee.is_some()).await?;
            early = e;
            fee_zat += early;
        }
        let change_script = if change > 0 { self.fresh_holder()? } else { Vec::new() };
        let collateral_script = if to.is_empty() {
            let pk = self.new_wallet_key()?;
            yew_core::script::p2pkh_script(&yew_core::keys::hash160(&pk))
        } else if let Some(sc) = crate::rpc::parse_taddr_script(self.network, &to).filter(|sc| yew_core::script::p2pkh_hash(sc).is_some()) {
            sc
        } else if to.starts_with("ys") || to.starts_with("zregtestsapling") || to.starts_with("zs") {
            return Err(RpcError::new(code::WALLET_ERROR, "yewd: a Sapling destination for the collateral is built in the signer (plan K-24), not served yet; pass a transparent address"));
        } else {
            return Err(build_error("bad-address: to: not a transparent (s1…) or Sapling (ys1…) address of this network".into()));
        };
        let utxos: Vec<yew_core::coins::Utxo> = yed_inputs
            .iter()
            .map(|c| yew_core::coins::Utxo {
                outpoint: c.outpoint,
                address: String::new(),
                script: c.script.clone(),
                value: c.value,
                height: 0,
                class: yew_core::coins::UtxoClass::Token,
                cents: c.cents as u64,
            })
            .collect();
        let payee_script = match &payee {
            Some(a) => Some(crate::rpc::parse_taddr_script(self.network, a).ok_or_else(|| build_error(format!("the payee {a} is not an address")))?),
            None => None,
        };
        let yed_scripts: Vec<&[u8]> = yed_inputs.iter().map(|c| c.script.as_slice()).collect();
        let mut shape = yew_core::build::redeem::VaultSpendShape {
            vault_out: op,
            vault_value: collateral,
            lock_height: v["lockHeight"].as_u64().unwrap_or(0) as u32,
            claim_height: v["claimHeight"].as_u64().unwrap_or(0) as u32,
            owner_height: vp.owner_height as u32,
            app_height: vp.app_height as u32,
            owner_path: true,
            with_payload: active,
            ref_height: r as u32,
            yed_inputs: utxos,
            change_cents: change as u64,
            change_script,
            payee_script,
            fee_zat,
            attest_script: None,
            attest_fee_zat: 0,
            residual_zat: 0,
            owner_script: yew_core::pq::pqpkh_script(&owner).unwrap_or_default(),
            carrier_value: 0,
            collateral_script: collateral_script.clone(),
            network_fee: 0,
        };
        // B L-1: the owner's PQ spend priced by size; clamped for a small vault (review L-1)
        let owner_bytes = pq_input_size(owner.scheme);
        let bytes = 1000 + owner_bytes as i64 + yed_scripts.iter().map(|s| input_bytes(s) as i64).sum::<i64>();
        let priced = info.flat_fee.max((info.rate_per_kb * bytes / 1000).min(info.max_fee));
        let yed_value: i64 = yed_inputs.iter().map(|c| c.value).sum();
        let spendable = collateral + yed_value - if payee.is_some() { fee_zat } else { 0 } - if change > 0 { TOKEN_VALUE } else { 0 };
        let floor_fee = info.flat_fee.max(5_000 * bytes / 1000);
        shape.network_fee = if spendable - priced > 54 { priced } else { priced.min(floor_fee) };
        let expiry = (r + info.ref_window) as u32;
        if expiry < next.height + EXPIRING_SOON {
            return Err(build_error("expiring-too-soon: the transaction would expire too soon; the index is too far behind the chain".into()));
        }
        let mut keys = vec![owner_key];
        keys.extend(yed_inputs.iter().map(|c| self.key_of_script(&c.script).unwrap_or(KeyRef::None)));
        let mut prevs = vec![NodeCoin { value: collateral, script: vault_script.clone(), height: None, coinbase: false }];
        prevs.extend(yed_inputs.iter().map(|c| NodeCoin { value: c.value, script: c.script.clone(), height: None, coinbase: false }));
        let mut signed;
        let mut plan;
        let mut pass = 0;
        loop {
            plan = yew_core::build::redeem::plan_vault_spend(&shape).map_err(|e| build_error(e.to_string()))?;
            let mut tx = Transaction::new_v4();
            tx.lock_time = plan.lock_time;
            tx.expiry_height = expiry;
            tx.vin = plan.vin.clone();
            tx.vout = plan.vout.clone();
            let cap = collateral + yed_value + 1;
            signed = self.sign_inputs(&tx, &prevs, &keys, &[], GatePath::Owner, cap, next.branch).await?;
            // P-2: never below the ZIP-317 conventional fee of the signed shape
            let sizes: Vec<usize> = signed.vin.iter().map(|i| i.script_sig.len()).collect();
            let conventional = signed.zip317_conventional_fee(&sizes).unwrap_or(0);
            pass += 1;
            if conventional <= shape.network_fee || pass >= 3 {
                break;
            }
            shape.network_fee = conventional;
        }
        // MP-1 (K7): an enforcing miner's verdict on the spend, before it is committed
        let raw = crate::build::tx_hex(&signed)?;
        if let Ok(val) = node::call(node, "yed_validaterawtransaction", serde_json::json!([raw])).await {
            if val["wouldBeRejected"].as_bool() == Some(true) {
                let verdict = val["verdict"].as_str().unwrap_or("rejected");
                return Err(RpcError::new(-26, format!("mempool-check-failed:{verdict}: an enforcing miner would refuse this vault spend (MP-1)")));
            }
        }
        let txid = self.broadcast(node, &signed, None).await?;
        let to_text = crate::keys::script_address(self.network, &collateral_script).unwrap_or_default();
        Ok(J::obj()
            .with("txid", txid)
            .with("burnedCents", (plan.burn_cents - extra_burn).max(0))
            .with("feeZat", if payee.is_some() { fee_zat } else { 0 })
            .with("earlyRedeemFeeZat", early)
            .with("payee", payee.map(J::Str).unwrap_or(J::Null))
            .with("collateralOut", plan.collateral_out)
            .with("to", to_text)
            .with("extraBurnCents", extra_burn))
    }

    /// `yed_estimateredeem "vaultTxid"`.
    async fn yed_estimateredeem(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        if p.len() != 1 {
            return Err(RpcError::new(code::MISC_ERROR, "yed_estimateredeem \"vaultTxid\""));
        }
        let txid_s = p[0].as_str().unwrap_or("").to_lowercase();
        let txid = yew_core::tx::txid_from_hex(&txid_s).map_err(|_| invalid("vaultTxid must be hexadecimal string of length 64"))?;
        let op = OutPoint { txid, n: 0 };
        let v = Self::yed_vault(node, &txid_s).await?;
        let info = yed_info(node).await?;
        let tip = info.index_height;
        let status = v["status"].as_str().unwrap_or("").to_string();
        let active = status == "ACTIVE";
        let minted = v["mintedCents"].as_i64().unwrap_or(0);
        let p_mint = v["pMint"].as_i64().unwrap_or(0);
        let payee = Self::spend_payee(node, tip, &op).await?;
        let (early, early_cents, bps) = Self::early_fee(node, &v, tip, payee.is_some()).await?;
        let fee1 = if active && payee.is_some() { yew_core::params::protocol_fee_zat(minted as u64, p_mint).unwrap_or(crate::build::MAX_MONEY) } else { 0 };
        let owner = yew_core::pq::PqKeyId {
            scheme: v["ownerScheme"].as_u64().unwrap_or(0) as u8,
            hash: hex::decode(v["ownerHash"].as_str().unwrap_or("")).ok().and_then(|b| b.try_into().ok()).unwrap_or([0; 32]),
        };
        let owner_height = hex::decode(v["scriptPubKey"].as_str().unwrap_or("")).ok().and_then(|s| yew_core::vault::parse_vault(&s)).map(|vp| vp.owner_height).unwrap_or(0);
        let spendable: i64 = self.ranked_coins(node).await?.iter().map(|c| c.cents).sum();
        let error = if !(active || status == "VOID") {
            format!("vault-not-active: the vault is {status}")
        } else if self.book.pq_by_id(&owner).is_none() {
            "vault-not-owned: the vault owner key is not in this wallet".to_string()
        } else if tip < owner_height {
            format!("vault-locked: the vault is locked until height {owner_height} (tip {tip})")
        } else if let Some(sp) = Self::mempool_spender(node, &op).await? {
            format!("vault-spend-pending: the vault {txid_s}:0 already has a spend in the mempool ({sp}); wait for it to confirm or expire")
        } else if active && spendable < minted {
            format!("insufficient-yed: the redeem burns {minted} cents; the wallet can spend {spendable} now ({spendable} confirmed)")
        } else {
            String::new()
        };
        Ok(J::obj()
            .with("vault", format!("{txid_s}:0"))
            .with("status", status)
            .with("termClass", v["termClass"].as_str().unwrap_or("").to_string())
            .with("lockHeight", v["lockHeight"].as_i64().unwrap_or(0))
            .with("height", tip + 1)
            .with("early", active && tip + 1 < v["lockHeight"].as_i64().unwrap_or(0))
            .with("burnedCents", if active { minted } else { 0 })
            .with("collateralZat", v["collateralZat"].as_i64().unwrap_or(0))
            .with("pMint", p_mint)
            .with("protocolFeeCents", if active && payee.is_some() { yew_core::params::protocol_fee_cents(minted as u64) as i64 } else { 0 })
            .with("protocolFeeZat", fee1)
            .with("feeZat", fee1 + early)
            .with("earlyRedeemFeeBps", bps)
            .with("earlyRedeemFeeCents", early_cents)
            .with("earlyRedeemFeeZat", early)
            .with("payee", if active { payee.map(J::Str).unwrap_or(J::Null) } else { J::Null })
            .with("canRedeem", error.is_empty())
            .with("error", error))
    }
}
