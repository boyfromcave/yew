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
pub const SERVED: &[&str] = &["yed_send", "yed_sendmany", "yed_estimatesend", "yed_lockcoins", "yed_unlockcoin"];

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
struct YedCoin {
    outpoint: OutPoint,
    cents: i64,
    script: Vec<u8>,
    value: i64,
}

/// What the builders need of the node's Yellowback parameters (`yed_getinfo`).
#[derive(Clone, Debug)]
struct YedInfo {
    index_height: i64,
    ref_lag: i64,
    ref_window: i64,
    flat_fee: i64,
    rate_per_kb: i64,
    max_fee: i64,
}

/// `PQSpendInputSize`: a post-quantum input's serialized size.
fn pq_input_size(scheme: u8) -> usize {
    let ss = yew_core::pq::pq_sig_pushes_size(scheme).unwrap_or(0);
    40 + if ss > 252 { 3 } else { 1 } + ss
}

/// The bytes `YedEstimatedSize` counts for one input.
fn input_bytes(script: &[u8]) -> usize {
    match yew_core::pq::pqpkh_of(script) {
        Some(id) => pq_input_size(id.scheme),
        None => 150,
    }
}

impl YedInfo {
    /// `YedNetworkFee`: max(flat, min(max(flat, rate × size), cap)) over the estimated size.
    fn network_fee(&self, scripts: &[&[u8]]) -> i64 {
        let bytes = 1000 + scripts.iter().map(|s| input_bytes(s)).sum::<usize>() as i64;
        let sized = self.flat_fee.max(self.rate_per_kb * bytes / 1000);
        self.flat_fee.max(sized.min(self.max_fee))
    }
}

async fn yed_info(node: &dyn Node) -> Result<YedInfo, RpcError> {
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
    async fn ranked_coins(&self, node: &dyn Node) -> Result<Vec<YedCoin>, RpcError> {
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
    async fn pick_yec(&self, node: &dyn Node, needed: i64, info: &YedInfo, prior: &[Vec<u8>], fee0: i64) -> Result<(Vec<(OutPoint, i64, Vec<u8>)>, i64), RpcError> {
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
    fn fresh_holder(&mut self) -> Result<Vec<u8>, RpcError> {
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
}
