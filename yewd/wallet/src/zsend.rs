// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! `z_sendmany` and its asynchronous operations (`z_getoperationstatus`,
//! `z_getoperationresult`, `z_listoperationids`): workspace plan §3b S4, finding F-S2-8.
//!
//! By ycash6's names, arguments and errors (`src/wallet/rpcwallet.cpp` `z_sendmany`,
//! `asyncrpcoperation_common.cpp`'s input-selection errors, `asyncrpcoperation.cpp`'s status
//! objects). The façade validates the call synchronously (as ycashd does before it queues the
//! operation), then plans the transaction: the inputs (the source's transparent coins, or its
//! Sapling notes with their Merkle paths, computed here from the node's tree state at the note's
//! height and the blocks since), the outputs, the change and the ZIP-317 conventional fee. The
//! signer builds, proves and signs it (K-24); the façade broadcasts it and records the
//! operation's outcome. The operation runs to completion before its id is returned; the
//! status objects are ycashd's.
//!
//! Beta2 (D-2, D-4, D-5): `z_sendmany` is any-to-any across ECC transparent, Sapling and
//! post-quantum addresses, as ycash6 92e434626 (`wallet_tx_builder.cpp` `PreparePQTransaction`)
//! answers it. A post-quantum from address spends its own `TX_PQPKH` coins and its change
//! returns to it; a post-quantum recipient is a transparent output. A shape with a post-quantum
//! party is signed through the signer's [`Request::Sign`] with the Sapling part built beside it
//! (the YED builders' path: every transparent digest is ZIP-243 over the proven Sapling bundle,
//! under the next block's branch ID); every other shape keeps the signer's Sapling build.

use std::collections::BTreeSet;

use serde_json::Value;
use yewd_proto::{
    GatePath, KeyRef, Prevout, Request, Response, SaplingBuildRequest, SaplingOut, SaplingPart,
    SaplingSpend, SaplingTInput,
};

use crate::build::{amount_param, next_block, signer_error, TX_EXPIRY_DELTA};
use crate::json::J;
use crate::keys::Owner;
use crate::node::{self, Node};
use crate::rpc::invalid;
use crate::{code, txid_hex, RpcError, Wallet};

/// `RefusePQSource` (ycashd `wallet/rpcwallet.cpp`, quantum spec A-15), now only for the
/// operations outside K-25 (`z_shieldcoinbase`, D-7; `z_mergetoaddress`, whose merging yewd does
/// not serve): z_sendmany spends and pays `TX_PQPKH` (beta2 D-2).
const PQ_SOURCE: &str = " cannot spend from a post-quantum address; use z_sendmany";
const PQ_RECIPIENT: &str = " cannot pay a post-quantum address; use sendtoaddress or sendmany";

pub(crate) fn refuse_pq(
    network: yew_core::params::Network,
    a: &str,
    method: &str,
    what: &str,
) -> Result<(), RpcError> {
    if yew_core::keys::parse_pq_yec_address(network, a).is_ok() {
        return Err(RpcError::new(
            code::INVALID_ADDRESS_OR_KEY,
            format!("{method}{what}"),
        ));
    }
    Ok(())
}

/// `z_shieldcoinbase` and `z_mergetoaddress` are outside K-25: the façade answers their
/// post-quantum refusals as ycashd does (the scripts call them for nothing else, finding F-S5-10)
/// and refuses the rest as not served.
pub fn pq_refusal_only(
    network: yew_core::params::Network,
    method: &str,
    p: &[Value],
) -> Result<J, RpcError> {
    match method {
        "z_shieldcoinbase" => {
            if let Some(from) = p.first().and_then(|v| v.as_str()) {
                refuse_pq(network, from, method, PQ_SOURCE)?;
            }
        }
        "z_mergetoaddress" => {
            for a in p.first().and_then(|v| v.as_array()).into_iter().flatten() {
                if let Some(a) = a.as_str() {
                    refuse_pq(network, a, method, PQ_SOURCE)?;
                }
            }
            if let Some(to) = p.get(1).and_then(|v| v.as_str()) {
                refuse_pq(network, to, method, PQ_RECIPIENT)?;
            }
        }
        _ => {}
    }
    Err(RpcError::new(
        code::METHOD_NOT_FOUND,
        format!("yewd: not served ({method} is outside the façade's scope, K-25)"),
    ))
}

pub const SERVED: &[&str] = &[
    "z_sendmany",
    "z_getoperationstatus",
    "z_getoperationresult",
    "z_listoperationids",
];

/// `WEIGHT_RATIO_CAP`: an explicit fee above this many conventional fees is refused.
const WEIGHT_RATIO_CAP: i64 = 4;

// The shape planning of a send between address types (policy lattice, PQ fee rule, sizes, dust,
// the post-quantum source's selection) is the YEW core's, one implementation for yewd and the app
// (beta2 D-8): `yew_core::build::any_to_any`.
use yew_core::build::any_to_any::{
    self as plan, checked_total as plan_total, PlanError, CHANGE_DUST_THRESHOLD, PRIVACY_POLICIES,
};
pub use yew_core::build::any_to_any::{
    conventional_fee, conventional_fee_bytes, MAX_PQ_INPUTS_PER_TX,
};

/// A planner refusal as the RPC error ycashd answers with (the node's code and text).
fn plan_err(e: PlanError) -> RpcError {
    RpcError::new(e.rpc_code(), e.to_string())
}

/// The recipients' total, checked (review L2): [`plan::checked_total`].
fn checked_total(amounts: impl Iterator<Item = i64>) -> Result<i64, RpcError> {
    plan_total(amounts).map_err(plan_err)
}

/// One asynchronous operation (`AsyncRPCOperation`).
#[derive(Clone, Debug)]
pub struct Op {
    pub id: String,
    pub status: &'static str,
    pub creation_time: i64,
    pub error: Option<(i64, String)>,
    pub txid: Option<String>,
    pub secs: f64,
    pub params: Value,
}

/// The operation queue (in memory, as ycashd's).
#[derive(Clone, Debug, Default)]
pub struct Operations {
    pub ops: Vec<Op>,
}

impl Op {
    fn status_json(&self) -> J {
        let mut o = J::obj()
            .with("id", self.id.clone())
            .with("status", self.status)
            .with("creation_time", self.creation_time);
        if let Some((c, m)) = &self.error {
            o.push(
                "error",
                J::obj().with("code", *c).with("message", m.clone()),
            );
        }
        if let Some(t) = &self.txid {
            o.push("result", J::obj().with("txid", t.clone()));
            o.push("execution_secs", J::Raw(format!("{:.6}", self.secs)));
        }
        o.push("method", J::Str("z_sendmany".into()));
        o.push("params", J::Raw(self.params.to_string()));
        o
    }
}

fn opid() -> String {
    let mut b = [0u8; 16];
    let _ = getrandom_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex::encode(b);
    format!(
        "opid-{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

fn getrandom_bytes(b: &mut [u8]) -> Result<(), ()> {
    // the façade has no RNG crate of its own; /dev/urandom suffices for an id
    use std::io::Read;
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(b))
        .map_err(|_| ())
}

fn now() -> i64 {
    crate::now()
}

/// A recipient of `z_sendmany`.
#[derive(Clone, Debug)]
enum Dest {
    T(Vec<u8>),
    Z(String),
}

/// The source of `z_sendmany`.
#[derive(Clone, Debug)]
enum Source {
    AnyTaddr,
    T(Vec<u8>),
    Z(String),
    /// A post-quantum address of this wallet (beta2 D-2): its key and its `TX_PQPKH` script.
    Pq(yew_core::pq::PqKeyId, Vec<u8>),
}

/// What an input-selection or build failure reports (`ThrowInputSelectionError`): the
/// operation fails with it.
fn op_error(code: i64, m: impl Into<String>) -> RpcError {
    RpcError::new(code, m)
}

fn money(z: i64) -> String {
    crate::rpc::format_money(z)
}

impl Wallet {
    pub async fn zsend_call(
        &mut self,
        node: &dyn Node,
        method: &str,
        p: &[Value],
    ) -> Result<J, RpcError> {
        match method {
            "z_sendmany" => self.z_sendmany(node, p).await,
            "z_getoperationstatus" => self.z_getoperationstatus(p, false),
            "z_getoperationresult" => self.z_getoperationstatus(p, true),
            "z_listoperationids" => self.z_listoperationids(p),
            _ => Err(RpcError::new(code::METHOD_NOT_FOUND, "Method not found")),
        }
    }

    /// `z_getoperationstatus ( ["operationid", ...] )` / `z_getoperationresult` (which removes
    /// the finished ones it returns).
    fn z_getoperationstatus(&mut self, p: &[Value], remove: bool) -> Result<J, RpcError> {
        let filter: BTreeSet<String> = match p.first() {
            None | Some(Value::Null) => BTreeSet::new(),
            Some(Value::Array(a)) => a
                .iter()
                .map(|v| {
                    v.as_str().map(str::to_string).ok_or_else(|| {
                        RpcError::new(code::MISC_ERROR, "JSON value is not a string as expected")
                    })
                })
                .collect::<Result<_, _>>()?,
            Some(_) => {
                return Err(RpcError::new(
                    code::MISC_ERROR,
                    "JSON value is not an array as expected",
                ))
            }
        };
        let mut out: Vec<Op> = Vec::new();
        let mut keep = Vec::new();
        for op in std::mem::take(&mut self.ops.ops) {
            let wanted = filter.is_empty() || filter.contains(&op.id);
            let finished = matches!(op.status, "success" | "failed" | "cancelled");
            if wanted && (!remove || finished) {
                out.push(op.clone());
                if remove {
                    continue;
                }
            }
            keep.push(op);
        }
        self.ops.ops = keep;
        out.sort_by_key(|o| o.creation_time);
        Ok(J::Arr(out.iter().map(Op::status_json).collect()))
    }

    /// `z_listoperationids ( "state" )`.
    fn z_listoperationids(&self, p: &[Value]) -> Result<J, RpcError> {
        let state = match p.first() {
            None | Some(Value::Null) => None,
            Some(v) => Some(v.as_str().ok_or_else(|| {
                RpcError::new(code::MISC_ERROR, "JSON value is not a string as expected")
            })?),
        };
        Ok(J::Arr(
            self.ops
                .ops
                .iter()
                .filter(|o| state.is_none_or(|s| o.status == s))
                .map(|o| J::Str(o.id.clone()))
                .collect(),
        ))
    }

    /// `z_sendmany "fromaddress" [{"address":..., "amount":..., "memo":...},...] ( minconf fee
    /// "privacyPolicy" )`.
    async fn z_sendmany(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        let next = next_block(node).await?;
        let outputs = p.get(1).and_then(|v| v.as_array()).ok_or_else(|| {
            RpcError::new(code::MISC_ERROR, "JSON value is not an array as expected")
        })?;
        if outputs.is_empty() {
            return Err(invalid("Invalid parameter, amounts array is empty."));
        }
        let mut seen = BTreeSet::new();
        let mut recipients: Vec<(Dest, i64, String)> = Vec::new();
        let mut has_t = false;
        for o in outputs {
            let obj = o
                .as_object()
                .ok_or_else(|| invalid("Invalid parameter, expected object"))?;
            for k in obj.keys() {
                if k != "address" && k != "amount" && k != "memo" {
                    return Err(invalid(format!("Invalid parameter, unknown key: {k}")));
                }
            }
            let a = obj.get("address").and_then(|v| v.as_str()).ok_or_else(|| {
                RpcError::new(code::MISC_ERROR, "JSON value is not a string as expected")
            })?;
            // A post-quantum recipient is a transparent (TX_PQPKH) output (beta2 D-2; reverses
            // quantum spec A-15), payable once the vault upgrade (and for FN-DSA-512 Falcon) is
            // active at the next block
            let pq = yew_core::keys::parse_pq_yec_address(self.network, a).ok();
            let dest = if let Some(id) = pq {
                let s = yew_core::pq::pqpkh_script(&id).ok_or_else(|| {
                    invalid(format!("Invalid parameter, unknown address format: {a}"))
                })?;
                self.ensure_pq_payable(&s)?;
                has_t = true;
                Dest::T(s)
            } else if let Some(s) = crate::rpc::parse_taddr_script(self.network, a) {
                has_t = true;
                Dest::T(s)
            } else if yew_core::shielded_keys::is_sapling_address(self.network, a) {
                Dest::Z(a.to_string())
            } else {
                return Err(invalid(format!(
                    "Invalid parameter, unknown address format: {a}"
                )));
            };
            if !seen.insert(a.to_string()) {
                return Err(invalid(format!(
                    "Invalid parameter, duplicated recipient address: {a}"
                )));
            }
            if pq.is_some() && obj.get("memo").is_some_and(|m| !m.is_null()) {
                return Err(invalid("Memos cannot be sent to transparent addresses."));
            }
            let memo = match obj.get("memo") {
                None | Some(Value::Null) => String::new(),
                Some(Value::String(m)) => {
                    if matches!(dest, Dest::T(_)) {
                        return Err(invalid(
                            "Memo cannot be used with a taddr.  It can only be used with a zaddr.",
                        ));
                    }
                    let b = hex::decode(m).map_err(|_| {
                        invalid("Invalid parameter, expected memo data in hexadecimal format.")
                    })?;
                    if b.len() > 512 {
                        return Err(invalid(format!(
                            "Invalid parameter, memo is longer than the maximum allowed {} bytes.",
                            512
                        )));
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
            let amount = amount_param(obj.get("amount").unwrap_or(&Value::Null))?;
            if amount < 0 {
                return Err(invalid("Invalid parameter, amount must be positive"));
            }
            if let (Some(_), Dest::T(s)) = (pq, &dest) {
                // EnsurePQAmountNotDust: the dust threshold of a PQ output at its real spend size
                let dust = crate::send::dust_threshold(s);
                if amount < dust {
                    return Err(invalid(format!(
                        "Invalid parameter, amount {} is below the dust threshold {} of a post-quantum output",
                        money(amount),
                        money(dust)
                    )));
                }
            }
            recipients.push((dest, amount, memo));
        }
        let from = p.first().and_then(|v| v.as_str()).ok_or_else(|| {
            RpcError::new(code::MISC_ERROR, "JSON value is not a string as expected")
        })?;
        let source = if from == "ANY_TADDR" {
            Source::AnyTaddr
        } else if let Ok(id) = yew_core::keys::parse_pq_yec_address(self.network, from) {
            // A post-quantum from address spends its own TX_PQPKH coins (beta2 D-2)
            self.ensure_pq_spendable(&id)?;
            let s = yew_core::pq::pqpkh_script(&id).ok_or_else(|| {
                RpcError::new(
                    code::INVALID_ADDRESS_OR_KEY,
                    "Invalid from address: should be a taddr, zaddr, UA, or the string 'ANY_TADDR'.",
                )
            })?;
            Source::Pq(id, s)
        } else if let Some(s) = crate::rpc::parse_taddr_script(self.network, from) {
            if yew_core::script::p2pkh_hash(&s)
                .and_then(|h| self.book.by_hash(&h))
                .is_none()
            {
                return Err(RpcError::new(
                    code::INVALID_ADDRESS_OR_KEY,
                    "Invalid from address, no payment source found for address.",
                ));
            }
            Source::T(s)
        } else if yew_core::shielded_keys::is_sapling_address(self.network, from) {
            if self.view.owns_address(from).is_none() {
                return Err(RpcError::new(
                    code::INVALID_ADDRESS_OR_KEY,
                    "Invalid from address, no payment source found for address.",
                ));
            }
            Source::Z(from.to_string())
        } else {
            return Err(RpcError::new(
                code::INVALID_ADDRESS_OR_KEY,
                "Invalid from address: should be a taddr, zaddr, UA, or the string 'ANY_TADDR'.",
            ));
        };
        let policy = match p.get(4) {
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
        let min = crate::rpc::minconf(p, 2, 1)?;
        let fee = match p.get(3) {
            None | Some(Value::Null) => None,
            Some(v) => Some(amount_param(v)?),
        };
        let mut ctx = serde_json::Map::new();
        ctx.insert("fromaddress".into(), p[0].clone());
        ctx.insert("amounts".into(), p[1].clone());
        ctx.insert("minconf".into(), Value::from(min));
        if let Some(f) = fee {
            ctx.insert(
                "fee".into(),
                serde_json::from_str(&money8(f)).unwrap_or(Value::Null),
            );
        }
        let id = opid();
        let started = std::time::Instant::now();
        let created = now();
        let outcome = self
            .run_sendmany(node, &next, &source, &recipients, has_t, min, fee, &policy)
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
        Ok(J::Str(id))
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_sendmany(
        &mut self,
        node: &dyn Node,
        next: &crate::build::Next,
        source: &Source,
        recipients: &[(Dest, i64, String)],
        has_t: bool,
        min: i64,
        fee: Option<i64>,
        policy: &str,
    ) -> Result<String, RpcError> {
        if let Source::Pq(id, script) = source {
            return self
                .run_pq_source(node, next, id, script, recipients, min, fee, policy)
                .await;
        }
        let reveal_recipients = matches!(
            policy,
            "AllowRevealedRecipients" | "AllowFullyTransparent" | "NoPrivacy"
        );
        let reveal_senders = matches!(
            policy,
            "AllowRevealedSenders" | "AllowFullyTransparent" | "NoPrivacy"
        );
        if has_t && !reveal_recipients {
            return Err(op_error(code::INVALID_PARAMETER, "This transaction would have transparent recipients, which is not enabled by default because it will publicly reveal transaction recipients and amounts. THIS MAY AFFECT YOUR PRIVACY. Resubmit with the `privacyPolicy` parameter set to `AllowRevealedRecipients` or weaker if you wish to allow this transaction to proceed anyway."));
        }
        let total = checked_total(recipients.iter().map(|r| r.1))?;
        let n_t_out = recipients
            .iter()
            .filter(|r| matches!(r.0, Dest::T(_)))
            .count();
        let n_z_out = recipients.len() - n_t_out;
        // a TX_PQPKH output's 35-byte script: 10 bytes more than ZIP-317's 34-byte output each
        let n_pq_out = recipients
            .iter()
            .filter(|r| matches!(&r.0, Dest::T(s) if yew_core::pq::pqpkh_of(s).is_some()))
            .count();
        let pq_extra = n_pq_out * 10;
        let tip = self.tip_height();
        // the candidates
        let mut t_coins: Vec<(yew_core::tx::OutPoint, i64, Vec<u8>, bool, KeyRef)> = Vec::new();
        let mut z_notes: Vec<crate::NoteRow> = Vec::new();
        let coinbase_ok = matches!(source, Source::T(_)) && reveal_senders && !has_t;
        match source {
            Source::AnyTaddr | Source::T(_) => {
                if !reveal_senders && !matches!(policy, "AllowLinkingAccountAddresses") {
                    return Err(op_error(
                        code::INVALID_PARAMETER,
                        format!(
                            "Insufficient funds: have {}, need {}.",
                            money(0),
                            money(total)
                        ),
                    ));
                }
                let spent = self.mempool_spent();
                for (c, d) in self.available_coins(None) {
                    if spent.contains(&(c.txid.clone(), c.vout))
                        || d < min.max(1) && !(d == 0 && min == 0)
                    {
                        continue;
                    }
                    let Owner::T(chain, index) = c.owner else {
                        continue;
                    };
                    if let Source::T(s) = source {
                        if &c.script != s {
                            continue;
                        }
                    }
                    if c.coinbase && !coinbase_ok {
                        continue;
                    }
                    let op = yew_core::tx::OutPoint {
                        txid: yew_core::tx::txid_from_hex(&c.txid)
                            .map_err(|e| RpcError::new(code::MISC_ERROR, e))?,
                        n: c.vout,
                    };
                    t_coins.push((
                        op,
                        c.value,
                        c.script.clone(),
                        c.coinbase,
                        KeyRef::Bip32 { chain, index },
                    ));
                }
                let reserved = self.yed_reserved(node).await?;
                t_coins.retain(|c| !reserved.contains(&(txid_hex(&c.0.txid), c.0.n)));
                t_coins.retain(|c| {
                    !self
                        .st
                        .locks
                        .contains(&format!("{}:{}", txid_hex(&c.0.txid), c.0.n))
                });
                // non-coinbase first, then the largest
                t_coins.sort_by(|a, b| a.3.cmp(&b.3).then(b.1.cmp(&a.1)));
            }
            Source::Pq(..) => unreachable!("run_pq_source"),
            Source::Z(addr) => {
                for n in &self.notes {
                    if n.spent || &n.address != addr {
                        continue;
                    }
                    if self.depth(n.height) < min.max(1) || n.position.is_none() {
                        continue;
                    }
                    z_notes.push(n.clone());
                }
                z_notes.sort_by(|a, b| b.value.cmp(&a.value));
            }
        }
        let available: i64 = t_coins.iter().map(|c| c.1).sum::<i64>()
            + z_notes.iter().map(|n| n.value as i64).sum::<i64>();
        // selection at the conventional fee (or the given one), the change decided with it
        let z_source = matches!(source, Source::Z(_));
        // the first pass already asks for the fee of the outputs alone (ycashd's target in its
        // "Insufficient funds: have …, need …" is amount + fee: vault_pq_wallet.py)
        let mut need_fee =
            fee.unwrap_or_else(|| conventional_fee_bytes(0, n_t_out, pq_extra, 0, n_z_out));
        let mut sel_t: Vec<_> = Vec::new();
        let mut sel_z: Vec<crate::NoteRow> = Vec::new();
        let mut change = 0i64;
        for _ in 0..6 {
            sel_t.clear();
            sel_z.clear();
            let need = total + need_fee;
            // SpendableInputs::LimitToAmount: enough is exact, or change above the dust threshold
            let enough = |got: i64| got == need || got - need > CHANGE_DUST_THRESHOLD;
            let mut got = 0i64;
            if z_source {
                for n in &z_notes {
                    if enough(got) {
                        break;
                    }
                    got += n.value as i64;
                    sel_z.push(n.clone());
                }
            } else {
                for c in &t_coins {
                    if enough(got) {
                        break;
                    }
                    got += c.1;
                    sel_t.push(c.clone());
                }
            }
            if got < need {
                let mut msg = format!(
                    "Insufficient funds: have {}, need {}",
                    money(available),
                    money(need)
                );
                if !z_source && !coinbase_ok {
                    msg.push_str("; note that coinbase outputs will not be selected if you specify ANY_TADDR, any transparent recipients are included, or if the `privacyPolicy` parameter is not set to `AllowRevealedSenders` or weaker");
                }
                msg.push('.');
                return Err(op_error(code::INVALID_PARAMETER, msg));
            }
            if !enough(got) {
                // ReportInvalidFunds' DustThresholdError (ycash6 ThrowInputSelectionError)
                let change = got - need;
                let mut msg = format!(
                    "Insufficient funds: have {}, need {} more to avoid creating invalid change output {} (dust threshold is {})",
                    money(available),
                    money(CHANGE_DUST_THRESHOLD - change),
                    money(change),
                    money(CHANGE_DUST_THRESHOLD)
                );
                if !z_source && !coinbase_ok {
                    msg.push_str("; note that coinbase outputs will not be selected if you specify ANY_TADDR, any transparent recipients are included, or if the `privacyPolicy` parameter is not set to `AllowRevealedSenders` or weaker");
                }
                msg.push('.');
                return Err(op_error(code::INVALID_PARAMETER, msg));
            }
            change = got - need;
            let coinbase = sel_t.iter().any(|c| c.3);
            if coinbase && change > 0 {
                return Err(op_error(code::WALLET_ERROR, format!("When shielding coinbase funds, the wallet does not allow any change. The proposed transaction would result in {} in change.", money(change))));
            }
            // the conventional fee of this shape (Sapling change for a Sapling source)
            let t_change = change > 0 && !z_source;
            let z_change = change > 0 && z_source;
            let conventional = conventional_fee_bytes(
                sel_t.len(),
                n_t_out + usize::from(t_change),
                pq_extra,
                sel_z.len(),
                n_z_out + usize::from(z_change),
            );
            match fee {
                Some(f) => {
                    if f > WEIGHT_RATIO_CAP * conventional {
                        return Err(op_error(code::INVALID_PARAMETER, format!("Fee {} is greater than {WEIGHT_RATIO_CAP} times the conventional fee for this tx (which is {}). There is no prioritisation benefit to a fee this large (see https://zips.z.cash/zip-0317#recommended-algorithm-for-block-template-construction), and it likely indicates a mistake in setting the fee.", money(f), money(conventional))));
                    }
                    break;
                }
                None => {
                    if conventional == need_fee {
                        break;
                    }
                    need_fee = conventional;
                }
            }
        }
        let fee_zat = need_fee;
        // the Sapling paths of the spent notes, at the tip
        let (anchor, paths) = if sel_z.is_empty() {
            (String::new(), Vec::new())
        } else {
            self.sapling_paths(node, &sel_z, tip).await?
        };
        let mut outputs: Vec<SaplingOut> = Vec::new();
        for (d, v, memo) in recipients {
            match d {
                Dest::T(s) => outputs.push(SaplingOut::Transparent {
                    script: hex::encode(s),
                    value: *v,
                    own: self.book.owns_script(s).is_some(),
                }),
                Dest::Z(a) => outputs.push(SaplingOut::Shielded {
                    address: a.clone(),
                    value: *v,
                    memo: memo.clone(),
                    own: self.view.owns_address(a).is_some(),
                }),
            }
        }
        if change > 0 {
            if let Source::Z(a) = source {
                // a legacy Sapling source takes its change back (ycashd's legacy-address change)
                outputs.push(SaplingOut::Shielded {
                    address: a.clone(),
                    value: change,
                    memo: String::new(),
                    own: true,
                });
            } else {
                let sc = self.new_change()?;
                outputs.push(SaplingOut::Transparent {
                    script: hex::encode(sc),
                    value: change,
                    own: true,
                });
            }
        }
        let spends: Vec<SaplingSpend> = sel_z
            .iter()
            .zip(paths)
            .map(|(n, (pos, path))| {
                let addr = n.note.recipient().to_bytes();
                let (rseed, after) = match n.note.rseed() {
                    sapling_crypto::Rseed::AfterZip212(r) => (hex::encode(r), true),
                    sapling_crypto::Rseed::BeforeZip212(r) => (hex::encode(r.to_bytes()), false),
                };
                SaplingSpend {
                    recipient: hex::encode(addr),
                    value: n.value,
                    rseed,
                    after_zip212: after,
                    internal: n.internal,
                    position: pos,
                    path,
                }
            })
            .collect();
        if n_pq_out > 0 {
            // a post-quantum recipient: librustzcash's builder pays P2PKH/P2SH only, so the
            // transparent part is built here and the signer adds the Sapling part (beta2 D-2)
            let inputs: Vec<(yew_core::tx::OutPoint, i64, Vec<u8>, KeyRef)> =
                sel_t.iter().map(|c| (c.0, c.1, c.2.clone(), c.4)).collect();
            let hexs = self
                .sign_hybrid(next, &inputs, spends, anchor, outputs, total + fee_zat)
                .await?;
            return self.commit_z(node, &hexs).await;
        }
        let req = SaplingBuildRequest {
            target_height: next.height,
            expiry_height: next.height + TX_EXPIRY_DELTA,
            vault_height: self.chain.vault_activation,
            inputs: sel_t
                .iter()
                .map(|c| SaplingTInput {
                    prevout: Prevout {
                        outpoint: format!("{}:{}", txid_hex(&c.0.txid), c.0.n),
                        script: hex::encode(&c.2),
                        amount_zat: c.1,
                    },
                    key: c.4,
                })
                .collect(),
            spends,
            outputs,
            fee_zat,
            anchor,
            outflow_cap_zat: total + fee_zat,
            params_dir: self.params_dir(),
        };
        let hexs = match self.signer.request(Request::SaplingBuild(req)) {
            Ok(Response::Built(h)) => h,
            Ok(Response::Refused(r)) => {
                return Err(RpcError::new(
                    code::WALLET_ERROR,
                    format!("yewd-signer refused ({}): {}", r.code, r.reason),
                ))
            }
            other => return Err(signer_error(other)),
        };
        self.commit_z(node, &hexs).await
    }

    /// `SendTransaction`: the node's `sendrawtransaction`, then the barrier. A refused transaction
    /// is never recorded: the wallet learns its transactions from the node's mempool and chain
    /// only, so nothing it was told failed is broadcast again later (audit H1's class).
    async fn commit_z(&mut self, node: &dyn Node, hexs: &str) -> Result<String, RpcError> {
        self.submit(node, hexs, serde_json::json!([hexs]), |code, message| {
            RpcError::new(
                code::WALLET_ERROR,
                format!("SendTransaction: Transaction commit failed:: {message} ({code})"),
            )
        })
        .await
    }

    /// The Sapling parameters' directory: `-paramsdir`, else ycashd's default.
    pub(crate) fn params_dir(&self) -> String {
        if let Some(d) = &self.opts.params_dir {
            return d.display().to_string();
        }
        let home = std::env::var("HOME").unwrap_or_default();
        if cfg!(target_os = "macos") {
            format!("{home}/Library/Application Support/ZcashParams")
        } else {
            format!("{home}/.zcash-params")
        }
    }

    /// The Merkle paths of `notes` at the tree of block `anchor_height`, and that root: the
    /// node's tree state below the earliest note (`z_gettreestate`), then every Sapling output
    /// of the blocks up to the anchor appended in chain order.
    pub(crate) async fn sapling_paths(
        &self,
        node: &dyn Node,
        notes: &[crate::NoteRow],
        anchor_height: u32,
    ) -> Result<(String, Vec<(u64, Vec<String>)>), RpcError> {
        use incrementalmerkletree::frontier::CommitmentTree;
        use incrementalmerkletree::witness::IncrementalWitness;
        use sapling_crypto::Node as SNode;
        let first = notes
            .iter()
            .filter_map(|n| n.height)
            .min()
            .ok_or_else(|| RpcError::new(code::WALLET_ERROR, "a spent note is not mined"))?;
        let mut start = first.saturating_sub(1);
        let mut tree: CommitmentTree<SNode, 32>;
        loop {
            let ts = node::call(
                node,
                "z_gettreestate",
                serde_json::json!([start.to_string()]),
            )
            .await?;
            let st = &ts["sapling"];
            if let Some(h) = st["commitments"]["finalState"].as_str() {
                let b =
                    hex::decode(h).map_err(|e| RpcError::new(code::MISC_ERROR, e.to_string()))?;
                tree = zcash_primitives::merkle_tree::read_commitment_tree::<SNode, _, 32>(&b[..])
                    .map_err(|e| {
                        RpcError::new(
                            code::MISC_ERROR,
                            format!("yewd: the Sapling tree state at {start}: {e}"),
                        )
                    })?;
                break;
            }
            match st["skipHash"].as_str() {
                Some(hash) => {
                    let hdr = node::call(node, "getblockheader", serde_json::json!([hash])).await?;
                    start = hdr["height"].as_u64().unwrap_or(0) as u32;
                }
                None => {
                    // no tree before Sapling's first commitment: start empty from block 1
                    tree = CommitmentTree::empty();
                    start = 0;
                    break;
                }
            }
        }
        let want: Vec<u64> = notes
            .iter()
            .map(|n| n.position.unwrap_or(u64::MAX))
            .collect();
        let mut wits: Vec<Option<IncrementalWitness<SNode, 32>>> = vec![None; notes.len()];
        for h in start + 1..=anchor_height {
            let hash = node::call(node, "getblockhash", serde_json::json!([h])).await?;
            let raw = node::call(node, "getblock", serde_json::json!([hash, 0])).await?;
            let bytes = hex::decode(raw.as_str().unwrap_or(""))
                .map_err(|e| RpcError::new(code::MISC_ERROR, e.to_string()))?;
            let (_, txs) = crate::split_block(&bytes)
                .map_err(|e| RpcError::new(code::MISC_ERROR, format!("yewd: block {h}: {e}")))?;
            for (_, tx) in txs {
                let Some(b) = tx.sapling_bundle() else {
                    continue;
                };
                for o in b.shielded_outputs() {
                    let node_ = SNode::from_cmu(o.cmu());
                    for w in wits.iter_mut().flatten() {
                        w.append(node_).map_err(|_| {
                            RpcError::new(code::MISC_ERROR, "the Sapling tree is full")
                        })?;
                    }
                    let pos = tree.size() as u64;
                    tree.append(node_)
                        .map_err(|_| RpcError::new(code::MISC_ERROR, "the Sapling tree is full"))?;
                    for (i, p) in want.iter().enumerate() {
                        if *p == pos {
                            wits[i] = IncrementalWitness::from_tree(tree.clone());
                        }
                    }
                }
            }
        }
        let mut out = Vec::new();
        let mut root = None;
        for (i, w) in wits.into_iter().enumerate() {
            let w = w.ok_or_else(|| {
                RpcError::new(
                    code::WALLET_ERROR,
                    format!(
                        "yewd: the note at position {} is not in the tree at {anchor_height}",
                        want[i]
                    ),
                )
            })?;
            let path = w
                .path()
                .ok_or_else(|| RpcError::new(code::MISC_ERROR, "an empty witness"))?;
            let r = w.root();
            if root.is_some_and(|x: SNode| x != r) {
                return Err(RpcError::new(
                    code::MISC_ERROR,
                    "the witnesses disagree on the root",
                ));
            }
            root = Some(r);
            let nodes: Vec<String> = path
                .path_elems()
                .iter()
                .map(|n| hex::encode(n.to_bytes()))
                .collect();
            out.push((u64::from(path.position()), nodes));
        }
        let root = root.map(|r| hex::encode(r.to_bytes())).unwrap_or_default();
        Ok((root, out))
    }
}

impl Wallet {
    /// ycash6 `EnsurePQSourceSpendable` (`wallet/rpcwallet.cpp`, beta2 D-2): a post-quantum from
    /// address spends only once the vault upgrade (and for FN-DSA-512 Falcon) is active at the
    /// next block, only with its key in this wallet, and only unlocked.
    fn ensure_pq_spendable(&self, id: &yew_core::pq::PqKeyId) -> Result<(), RpcError> {
        if !self.vault_active_next() {
            return Err(RpcError::new(
                code::INVALID_ADDRESS_OR_KEY,
                "post-quantum addresses can be spent from only once the vault upgrade is active at the next block",
            ));
        }
        if id.scheme == yew_core::pq::SCHEME_FN_DSA_512 && !self.falcon_next() {
            return Err(RpcError::new(
                code::INVALID_ADDRESS_OR_KEY,
                "an FN-DSA-512 (scheme 2) post-quantum address can be spent from only once Falcon is active at the next block",
            ));
        }
        if self.book.pq_by_id(id).is_none() {
            return Err(RpcError::new(
                code::INVALID_ADDRESS_OR_KEY,
                "From address does not belong to this node, post-quantum key not found.",
            ));
        }
        self.ensure_unlocked()
    }

    /// ycash6 `WalletTxBuilder::PreparePQTransaction` (beta2 D-2, D-4, D-5): `z_sendmany` from a
    /// post-quantum address. Its own `TX_PQPKH` coins (never a YED output, never a locked coin),
    /// largest first; the fee priced on the transaction's size (`PQBuilderFee`) and settled with
    /// the selection; change below the post-quantum dust threshold folded into the fee, any
    /// other back to the source address; the privacy policy of a transparent sender.
    #[allow(clippy::too_many_arguments)]
    async fn run_pq_source(
        &mut self,
        node: &dyn Node,
        next: &crate::build::Next,
        id: &yew_core::pq::PqKeyId,
        source: &[u8],
        recipients: &[(Dest, i64, String)],
        min: i64,
        fee: Option<i64>,
        policy: &str,
    ) -> Result<String, RpcError> {
        let (rate, cap) = crate::send::pq_fee_params(node).await;
        // the shape: the YEW core's planner (one implementation with the app, beta2 D-8), over
        // the candidates selected here
        let planned: Vec<plan::PlanRecipient> = recipients
            .iter()
            .map(|(d, v, _)| plan::PlanRecipient {
                script: match d {
                    Dest::T(s) => Some(s.clone()),
                    Dest::Z(_) => None,
                },
                amount: *v,
            })
            .collect();
        // the explicit fee against the cap and the recipients against the policy come before
        // any coin is looked at (an empty candidate list answers the same)
        if let Err(e) =
            plan::plan_pq_source::<KeyRef>(&[], source, &planned, fee, policy, rate, cap)
        {
            if e != PlanError::NoCoins {
                return Err(plan_err(e));
            }
        }
        // the source's own coins: unspent, unlocked, mature, at depth >= minconf, not spent by a
        // mempool transaction of this wallet, and never an output YED holds
        let reserved = self.yed_reserved(node).await?;
        let spent = self.mempool_spent();
        let key =
            KeyRef::Pq {
                scheme: id.scheme,
                index: self.book.pq_by_id(id).map(|k| k.index).ok_or_else(|| {
                    RpcError::new(code::WALLET_ERROR, "post-quantum key not found")
                })?,
            };
        let mut coins: Vec<plan::PqCoin<KeyRef>> = Vec::new();
        for (c, d) in self.available_coins(None) {
            if c.script != source
                || c.coinbase
                || d < min
                || spent.contains(&(c.txid.clone(), c.vout))
                || reserved.contains(&(c.txid.clone(), c.vout))
            {
                continue;
            }
            let op = yew_core::tx::OutPoint {
                txid: yew_core::tx::txid_from_hex(&c.txid)
                    .map_err(|e| RpcError::new(code::MISC_ERROR, e))?,
                n: c.vout,
            };
            coins.push(plan::PqCoin {
                outpoint: op,
                value: c.value,
                script: c.script.clone(),
                key,
            });
        }
        let p = plan::plan_pq_source(&coins, source, &planned, fee, policy, rate, cap)
            .map_err(plan_err)?;
        let send = p.send;
        let cur_fee = p.fee;
        let change = p.change;
        let selected: Vec<(yew_core::tx::OutPoint, i64, Vec<u8>, KeyRef)> = p
            .selected
            .iter()
            .map(|c| (c.outpoint, c.value, c.script.clone(), c.key))
            .collect();
        let t_outs: Vec<(Vec<u8>, i64)> =
            p.transparent_outputs[..p.transparent_outputs.len() - usize::from(change > 0)].to_vec();
        // defence in depth: no selected coin is an output YED holds (never true after the filter)
        if let Some(c) = selected
            .iter()
            .find(|c| reserved.contains(&(txid_hex(&c.0.txid), c.0.n)))
        {
            return Err(op_error(
                code::WALLET_ERROR,
                format!(
                    "refusing to spend a Yellowback outpoint as plain YEC: {}:{}",
                    txid_hex(&c.0.txid),
                    c.0.n
                ),
            ));
        }
        let mut outputs: Vec<SaplingOut> = Vec::new();
        for (s, v) in &t_outs {
            outputs.push(SaplingOut::Transparent {
                script: hex::encode(s),
                value: *v,
                own: self.book.owns_script(s).is_some(),
            });
        }
        for (d, v, memo) in recipients {
            if let Dest::Z(a) = d {
                outputs.push(SaplingOut::Shielded {
                    address: a.clone(),
                    value: *v,
                    memo: memo.clone(),
                    own: self.view.owns_address(a).is_some(),
                });
            }
        }
        if change > 0 {
            // beta2 D-4: the change returns to the source address (same scheme, no new key)
            outputs.push(SaplingOut::Transparent {
                script: hex::encode(source),
                value: change,
                own: true,
            });
        }
        let hexs = self
            .sign_hybrid(
                next,
                &selected,
                Vec::new(),
                String::new(),
                outputs,
                send + cur_fee,
            )
            .await?;
        // the signed transaction re-priced: the estimate must cover it
        let raw =
            hex::decode(&hexs).map_err(|e| RpcError::new(code::INTERNAL_ERROR, e.to_string()))?;
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
        // ycash6 PQBuilderFee(fee, signedTx): the base is the fee the estimate settled on
        plan::check_signed_fee(cur_fee, raw.len(), conventional, rate, cap).map_err(plan_err)?;
        self.commit_z(node, &hexs).await
    }

    /// A `z_sendmany` transaction with a post-quantum party, signed by the signer's `Sign` with the
    /// Sapling part (spends, shielded outputs) built beside the transparent one: `inputs` (P2PKH or
    /// `TX_PQPKH` wallet coins, each with its key), `outputs` in order (the transparent ones into
    /// `vout`, the shielded ones into the Sapling part). The YEC gate path: no data output, no
    /// template, no owner key; the outflow at most `cap`.
    async fn sign_hybrid(
        &self,
        next: &crate::build::Next,
        inputs: &[(yew_core::tx::OutPoint, i64, Vec<u8>, KeyRef)],
        spends: Vec<SaplingSpend>,
        anchor: String,
        outputs: Vec<SaplingOut>,
        cap: i64,
    ) -> Result<String, RpcError> {
        let mut tx = yew_core::tx::Transaction::new_v4();
        tx.expiry_height = next.height + TX_EXPIRY_DELTA;
        for i in inputs {
            tx.vin.push(yew_core::tx::TxIn::new(i.0));
        }
        let mut shielded = Vec::new();
        for o in outputs {
            match o {
                SaplingOut::Transparent { script, value, .. } => {
                    tx.vout.push(yew_core::tx::TxOut {
                        value,
                        script_pubkey: hex::decode(&script)
                            .map_err(|e| RpcError::new(code::INTERNAL_ERROR, e.to_string()))?,
                    })
                }
                other => shielded.push(other),
            }
        }
        let sapling = (!spends.is_empty() || !shielded.is_empty()).then(|| SaplingPart {
            target_height: next.height,
            vault_height: self.chain.vault_activation,
            spends,
            outputs: shielded,
            anchor,
            params_dir: self.params_dir(),
        });
        let prevouts: Vec<crate::build::NodeCoin> = inputs
            .iter()
            .map(|i| crate::build::NodeCoin {
                value: i.1,
                script: i.2.clone(),
                height: None,
                coinbase: false,
            })
            .collect();
        let keys: Vec<KeyRef> = inputs.iter().map(|i| i.3).collect();
        self.sign_inputs_hex(
            &tx,
            &prevouts,
            &keys,
            &[],
            GatePath::Yec,
            cap,
            next.branch,
            sapling,
        )
        .await
    }
}

/// `{:.8}` text of an amount, for the operation's context.
fn money8(z: i64) -> String {
    crate::json::amount_text(z)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fees_and_ids() {
        // two transparent actions (the grace minimum)
        assert_eq!(conventional_fee(1, 1, 0, 0), 1000);
        // t -> z: one input, one padded-to-two Sapling output pair: max(1 transparent, 2 sapling)
        // logical actions? the transparent and Sapling actions add: 1 + 2
        assert_eq!(conventional_fee(1, 0, 0, 1), 1500);
        let id = opid();
        assert!(id.starts_with("opid-") && id.len() == 41, "{id}");
    }

    /// Review L4: yewd's fee base and dust constants equal ycash6's computed defaults
    /// (-feepolicy=peroutput, -minrelaytxfee 100 zat/kB = DEFAULT_MIN_RELAY_TX_FEE and
    /// ONE_THIRD_DUST_THRESHOLD_RATE). A node run with another -minrelaytxfee prices the PQ dust
    /// threshold differently; yewd cannot read that setting.
    #[test]
    fn fee_base_and_dust_pins() {
        // CalcZIP317Fee, peroutput: flat 1000 up to 50 padded Sapling outputs, then 1000 each above
        assert_eq!(plan::peroutput_fee(0), 1000);
        assert_eq!(plan::peroutput_fee(2), 1000);
        assert_eq!(plan::peroutput_fee(50), 1000);
        assert_eq!(plan::peroutput_fee(51), 1000);
        assert_eq!(plan::peroutput_fee(52), 2000);
        assert_eq!(plan::peroutput_fee(60), 10_000);
        // DefaultDustThreshold: a P2PKH output, 3 x (34 + 148) x 100 / 1000
        let p2pkh = [&[0x76, 0xa9, 0x14][..], &[0u8; 20], &[0x88, 0xac]].concat();
        assert_eq!(CHANGE_DUST_THRESHOLD, 54);
        assert_eq!(crate::send::dust_threshold(&p2pkh), CHANGE_DUST_THRESHOLD);
        // GetPQDustThreshold at 100 zat/kB: 3 x fee(44-byte output + PQSpendInputSize(scheme))
        // SLH-DSA: scriptSig 7,938 (sig 7,857 in 520-byte chunks + pk 32 + 2), input 7,981, + 44 = 8,025 bytes;
        // FN-DSA-512: scriptSig 1,577 (sig 667 + pk 897, chunked, + 2), input 1,620, + 44 = 1,664 bytes
        for (scheme, want) in [(1u8, 2406), (2u8, 498)] {
            let id = yew_core::pq::PqKeyId {
                scheme,
                hash: [0; 32],
            };
            let script = yew_core::pq::pqpkh_script(&id).unwrap();
            assert_eq!(
                crate::send::dust_threshold(&script),
                want,
                "scheme {scheme}"
            );
        }
        // L2
        assert_eq!(
            checked_total([plan::MAX_MONEY].into_iter()).unwrap(),
            plan::MAX_MONEY
        );
        assert!(checked_total([plan::MAX_MONEY, 1].into_iter()).is_err());
        assert!(checked_total([i64::MAX, i64::MAX].into_iter()).is_err());
    }
}
