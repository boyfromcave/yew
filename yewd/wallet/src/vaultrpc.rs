// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The vault primitive's wallet RPCs (R5; ycash6 `src/rpc/vault.cpp`, `doc/vault-rpc.md` at the
//! revision `yewd/PIN` names): the act RPCs (`set_create`, `set_join`, `set_heartbeat`,
//! `set_leave`, `set_buildact`, `set_signact`, `set_sendact`, `set_equivocation`) and the vault
//! RPCs (`vault_lock`, `vault_buildunlock`, `set_signunlock`, `vault_buildcancel`,
//! `set_signcancel`, `vault_refee`, `set_importsigned`, `set_acknowledgerestore`, `vault_send`,
//! `vault_release`, `vault_ownerspend`, `vault_app`), by ycashd's arguments, result shapes and
//! error messages.
//!
//! Where ycashd reads its in-process state, the façade asks the node: the set state at the next
//! block (`set_getinfo`), template outputs and an intent's originating vault (`vault_list`,
//! `getrawtransaction`), coins (`gettxout`), the upgrade (`vault_getinfo`). Every signature is the
//! signer's (K-24): act signatures (`SignAct`), set signatures through its sign-once record
//! (`SignSet`), and the transparent and owner inputs (`Sign`).

use std::collections::{BTreeSet, HashSet};

use serde_json::Value;
use yew_core::pq::PqKeyId;
use yew_core::tx::{OutPoint, Transaction, TxIn, TxOut};
use yew_core::vault::{self as yv, IntentParams, VaultParams};
use yewd_proto::act::{self, Act, Body};
use yewd_proto::{GatePath, KeyRef, OwnOutput, Request, Response, SignedRecord, SignedRecords};

use crate::build::{
    amount_param, decode_tx_param, money, next_block, node_coin, op_str, outpoint_param,
    signer_error, tx_hex, txid_of, FundMode, Next, NodeCoin, VAULT_RPC_FEE, VAULT_RPC_MIN_CHANGE,
};
use crate::json::J;
use crate::keys::pqkeyid_hex;
use crate::node::{self, Node, NodeError};
use crate::rpc::{invalid, param};
use crate::{code, txid_hex, RpcError, Wallet};

/// The R5 wallet methods S2 serves (with S1's `vault_getnewowner` and `set_listsigned`).
pub const SERVED: &[&str] = &[
    "set_create",
    "set_join",
    "set_heartbeat",
    "set_leave",
    "set_buildact",
    "set_signact",
    "set_sendact",
    "set_equivocation",
    "vault_lock",
    "vault_buildunlock",
    "set_signunlock",
    "vault_buildcancel",
    "set_signcancel",
    "vault_refee",
    "set_importsigned",
    "set_acknowledgerestore",
    "vault_send",
    "vault_release",
    "vault_ownerspend",
    "vault_app",
];

const ROLE_UNLOCK: u8 = 1;
const ROLE_CANCEL: u8 = 2;
const SIGHASH_ALL_ANYONECANPAY: u32 = 0x81;

fn usage(m: &str) -> RpcError {
    RpcError::new(code::MISC_ERROR, m)
}

fn want_params(p: &[Value], min: usize, max: usize, help: &str) -> Result<(), RpcError> {
    if p.len() < min || p.len() > max {
        return Err(usage(help));
    }
    Ok(())
}

/// `ParseHashV`.
fn hash_param(v: &Value, name: &str) -> Result<[u8; 32], RpcError> {
    let s = v
        .as_str()
        .ok_or_else(|| invalid(format!("{name} must be hexadecimal string")))?;
    if !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(invalid(format!(
            "{name} must be hexadecimal string (not '{s}')"
        )));
    }
    if s.len() != 64 {
        return Err(invalid(format!(
            "{name} must be of length 64 (not {}, for '{s}')",
            s.len()
        )));
    }
    yew_core::tx::txid_from_hex(s).map_err(|e| invalid(e.to_string()))
}

/// `ParseHexV`.
fn hex_param(v: &Value, name: &str) -> Result<Vec<u8>, RpcError> {
    let s = v.as_str().unwrap_or("");
    hex::decode(s).map_err(|_| invalid(format!("{name} must be hexadecimal string (not '{s}')")))
}

/// `ParseKey`: a valid compressed public key.
fn key_param(v: &Value, name: &str) -> Result<[u8; 33], RpcError> {
    let b = hex_param(v, name)?;
    let bad = || invalid(format!("{name} must be a valid compressed public key"));
    let k: [u8; 33] = b.try_into().map_err(|_| bad())?;
    if !yew_core::script::is_compressed_key(&k) || secp256k1::PublicKey::from_slice(&k).is_err() {
        return Err(bad());
    }
    Ok(k)
}

/// `ParseRaw32` (a sighash in raw order).
fn raw32_param(v: &Value, name: &str) -> Result<[u8; 32], RpcError> {
    let b = hex_param(v, name)?;
    b.try_into()
        .map_err(|_| invalid(format!("{name} must be 32 bytes")))
}

fn sig65_param(v: &Value, name: &str) -> Result<[u8; 65], RpcError> {
    let b = hex_param(v, name)?;
    b.try_into()
        .map_err(|_| invalid(format!("{name} must be a 65-byte recoverable signature")))
}

/// `ParseTag`.
fn tag_param(v: &Value) -> Result<[u8; 4], RpcError> {
    let s = v
        .as_str()
        .ok_or_else(|| RpcError::new(code::TYPE_ERROR, "Expected type string"))?;
    let mut t = [0u8; 4];
    if s.len() == 8 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        t.copy_from_slice(&hex::decode(s).expect("hex"));
        return Ok(t);
    }
    if s.is_empty() || s.len() > 4 {
        return Err(invalid(
            "tag must be 1-4 ASCII characters (zero-padded) or 8 hex digits",
        ));
    }
    t[..s.len()].copy_from_slice(s.as_bytes());
    Ok(t)
}

fn int_field(o: &Value, k: &str) -> Result<Option<i64>, RpcError> {
    match o.get(k) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_i64()
            .map(Some)
            .ok_or_else(|| RpcError::new(code::TYPE_ERROR, format!("{k}: Expected type number"))),
    }
}

fn bool_field(o: &Value, k: &str) -> Result<bool, RpcError> {
    match o.get(k) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(RpcError::new(
            code::TYPE_ERROR,
            format!("{k}: Expected type bool"),
        )),
    }
}

fn field<'a>(o: &'a Value, k: &str) -> &'a Value {
    static NULL: Value = Value::Null;
    o.get(k).unwrap_or(&NULL)
}

pub fn records_json(r: &SignedRecords) -> J {
    J::obj().with("restored", r.restored).with(
        "records",
        J::Arr(
            r.records
                .iter()
                .map(|x| {
                    J::obj()
                        .with("setid", x.setid.clone())
                        .with("prevout", x.prevout.clone())
                        .with("role", x.role as i64)
                        .with("sighash", x.sighash.clone())
                })
                .collect(),
        ),
    )
}

/// One member of a set, as `set_getinfo` lists it.
#[derive(Clone, Debug)]
struct Member {
    key: [u8; 33],
    status: String,
    current: bool,
}

/// The set state the act and sign RPCs need (`set_getinfo` at the next block).
#[derive(Clone, Debug)]
pub(crate) struct SetView {
    unlock_threshold: i64,
    cancel_threshold: i64,
    slash_threshold: i64,
    open: bool,
    admit_key: [u8; 33],
    pub(crate) maturity: i64,
    current: i64,
    released: bool,
    members: Vec<Member>,
}

impl SetView {
    fn threshold(&self, role: u8) -> i64 {
        if role == ROLE_UNLOCK {
            self.unlock_threshold
        } else {
            self.cancel_threshold
        }
    }

    fn is_current(&self, k: &[u8; 33]) -> bool {
        self.members.iter().any(|m| m.key == *k && m.current)
    }
}

pub(crate) async fn set_view(node: &dyn Node, set: &[u8; 32]) -> Result<Option<SetView>, RpcError> {
    match node::call(node, "set_getinfo", serde_json::json!([txid_hex(set)])).await {
        Ok(v) => {
            let key = |s: &Value| -> [u8; 33] {
                hex::decode(s.as_str().unwrap_or(""))
                    .ok()
                    .and_then(|b| b.try_into().ok())
                    .unwrap_or([0u8; 33])
            };
            let members = v["memberlist"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .map(|m| Member {
                            key: key(&m["key"]),
                            status: m["status"].as_str().unwrap_or("").to_string(),
                            current: m["current"].as_bool().unwrap_or(false),
                        })
                        .collect()
                })
                .unwrap_or_default();
            Ok(Some(SetView {
                unlock_threshold: v["unlockthreshold"].as_i64().unwrap_or(0),
                cancel_threshold: v["cancelthreshold"].as_i64().unwrap_or(0),
                slash_threshold: v["slashthreshold"].as_i64().unwrap_or(0),
                open: v["open"].as_bool().unwrap_or(false),
                admit_key: key(&v["admitkey"]),
                maturity: v["maturity"].as_i64().unwrap_or(0),
                current: v["current"].as_i64().unwrap_or(0),
                released: v["released"].as_bool().unwrap_or(false),
                members,
            }))
        }
        Err(NodeError::Rpc { code: -5, .. }) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// The template input of a transaction (exactly one, S-1).
struct Template {
    idx: usize,
    coin: NodeCoin,
    vault: Option<VaultParams>,
    intent: Option<IntentParams>,
}

/// `HandoffOptions`.
#[derive(Default)]
struct Handoff {
    dryrun: bool,
    allow_inputs: HashSet<OutPoint>,
    allow_outflow: Option<i64>,
}

fn handoff_options(p: &[Value]) -> Result<Handoff, RpcError> {
    let mut h = Handoff::default();
    let Some(o) = param(p, 1) else { return Ok(h) };
    if !o.is_object() {
        return Err(invalid("options must be an object"));
    }
    match o.get("dryrun") {
        None | Some(Value::Null) => {}
        Some(Value::Bool(b)) => h.dryrun = *b,
        Some(_) => return Err(invalid("dryrun must be a boolean")),
    }
    match o.get("allowinputs") {
        None | Some(Value::Null) => {}
        Some(Value::Array(a)) => {
            for v in a {
                h.allow_inputs.insert(outpoint_param(v, "allowinputs")?);
            }
        }
        Some(_) => return Err(invalid("allowinputs must be an array of outpoints")),
    }
    if let Some(f) = o.get("allowoutflow").filter(|v| !v.is_null()) {
        h.allow_outflow = Some(amount_param(f)?);
    }
    Ok(h)
}

fn new_tx() -> Transaction {
    let mut t = Transaction::new_v4();
    t.expiry_height = 0; // built here, signed by other nodes, sent later: no expiry
    t
}

fn act_json(a: &Act, vin0: Option<&OutPoint>) -> J {
    let mut o = J::obj().with("type", a.body.type_name());
    let sid = |s: &[u8; 32]| txid_hex(s);
    match &a.body {
        Body::Create(c) => {
            o.push("seats", J::Int(c.seats as i64));
            o.push("unlockthreshold", J::Int(c.unlock_threshold as i64));
            o.push("cancelthreshold", J::Int(c.cancel_threshold as i64));
            o.push("slashthreshold", J::Int(c.slash_threshold as i64));
            o.push("open", J::Bool(c.open()));
            o.push("ratelimitbps", J::Int(c.rate_limit_bps as i64));
            o.push("ratewindow", J::Int(c.rate_window as i64));
            o.push("livenesswindow", J::Int(c.liveness_window as i64));
            o.push("bondmin", J::Amount(c.bond_min));
            o.push("bondlockmin", J::Int(c.bond_lock_min as i64));
            o.push("maturity", J::Int(c.maturity as i64));
            o.push("admitkey", J::Str(hex::encode(c.admit_key)));
        }
        Body::Join {
            set_id,
            member_key,
            bond_locktime,
            bond_vout,
        } => {
            o.push("setid", J::Str(sid(set_id)));
            o.push("memberkey", J::Str(hex::encode(member_key)));
            o.push("bondlocktime", J::Int(*bond_locktime as i64));
            o.push("bondvout", J::Int(*bond_vout as i64));
        }
        Body::Heartbeat { set_id, member_key } => {
            o.push("setid", J::Str(sid(set_id)));
            o.push("memberkey", J::Str(hex::encode(member_key)));
        }
        Body::Remove {
            set_id,
            member_key,
            burn,
        } => {
            o.push("setid", J::Str(sid(set_id)));
            o.push("memberkey", J::Str(hex::encode(member_key)));
            o.push("burn", J::Int(*burn as i64));
        }
        Body::Equivocation(e) => {
            o.push("setid", J::Str(sid(&e.set_id)));
            o.push(
                "prevout",
                J::Str(format!("{}:{}", txid_hex(&e.prevout.txid), e.prevout.n)),
            );
            o.push("rolea", J::Int(e.role_a as i64));
            o.push("sighasha", J::Str(hex::encode(e.sighash_a)));
            o.push("siga", J::Str(hex::encode(e.sig_a)));
            o.push("roleb", J::Int(e.role_b as i64));
            o.push("sighashb", J::Str(hex::encode(e.sighash_b)));
            o.push("sigb", J::Str(hex::encode(e.sig_b)));
        }
        Body::Winddown { set_id } => {
            o.push("setid", J::Str(sid(set_id)));
        }
    }
    let payload = act::encode_payload(&a.body);
    let msg = vin0.map(|v| act::act_msg(&payload, &act::OutPoint::from(*v)));
    let sigs = a
        .sigs
        .iter()
        .map(|s| {
            let mut so = J::obj().with("sig", hex::encode(s));
            if let Some(k) = msg.and_then(|m| act::recover(&m, s)) {
                so.push("key", J::Str(hex::encode(k)));
            }
            so
        })
        .collect();
    o.push("signatures", J::Arr(sigs));
    o
}

/// The act output of a transaction (index, decoded act): `FindAct`.
fn find_act(tx: &Transaction) -> Result<(usize, Act), RpcError> {
    for (o, out) in tx.vout.iter().enumerate() {
        if !act::is_act_output(&out.script_pubkey) {
            continue;
        }
        return act::decode(&out.script_pubkey)
            .map(|a| (o, a))
            .map_err(|e| invalid(format!("the act does not decode: {e}")));
    }
    Err(invalid("the transaction carries no YV act"))
}

fn act_result(tx: &Transaction, a: &Act, missing: i64, required: i64) -> Result<J, RpcError> {
    Ok(J::obj()
        .with("hex", tx_hex(tx)?)
        .with("type", a.body.type_name())
        .with("complete", missing == 0)
        .with("signatures", a.sigs.len())
        .with("required", required))
}

/// `SameHandoffOutputs`: the same outputs, an act's compared without its signatures.
fn same_handoff_outputs(memo: &Transaction, tx: &Transaction) -> bool {
    if memo.vout.len() != tx.vout.len() {
        return false;
    }
    for (a, b) in memo.vout.iter().zip(&tx.vout) {
        if a.value != b.value {
            return false;
        }
        let (aa, ba) = (
            act::is_act_output(&a.script_pubkey),
            act::is_act_output(&b.script_pubkey),
        );
        if aa || ba {
            let (Ok(x), Ok(y)) = (act::decode(&a.script_pubkey), act::decode(&b.script_pubkey))
            else {
                return false;
            };
            if act::encode_payload(&x.body) != act::encode_payload(&y.body) {
                return false;
            }
        } else if a.script_pubkey != b.script_pubkey {
            return false;
        }
    }
    true
}

fn sighash_set(
    tx: &Transaction,
    idx: usize,
    coin: &NodeCoin,
    branch: u32,
) -> Result<[u8; 32], RpcError> {
    tx.sighash(
        idx,
        &coin.script,
        coin.value,
        SIGHASH_ALL_ANYONECANPAY,
        branch,
    )
    .map_err(|e| RpcError::new(code::INTERNAL_ERROR, e.to_string()))
}

impl Wallet {
    /// Dispatch an R5 build RPC (after the barrier).
    pub async fn vault_call(
        &mut self,
        node: &dyn Node,
        method: &str,
        p: &[Value],
    ) -> Result<J, RpcError> {
        match method {
            "set_create" => self.set_create(node, p).await,
            "set_join" => self.set_join(node, p).await,
            "set_heartbeat" => self.set_heartbeat(node, p).await,
            "set_leave" => self.set_leave(node, p).await,
            "set_buildact" => self.set_buildact(node, p).await,
            "set_signact" => self.set_signact(node, p).await,
            "set_sendact" => self.set_sendact(node, p).await,
            "set_equivocation" => self.set_equivocation(node, p).await,
            "vault_lock" => self.vault_lock(node, p).await,
            "vault_buildunlock" => self.vault_buildunlock(node, p).await,
            "set_signunlock" => self.set_sign_template(node, p, ROLE_UNLOCK).await,
            "vault_buildcancel" => self.vault_buildcancel(node, p).await,
            "set_signcancel" => self.set_sign_template(node, p, ROLE_CANCEL).await,
            "vault_refee" => self.vault_refee(node, p).await,
            "set_importsigned" => self.set_importsigned(p),
            "set_acknowledgerestore" => self.set_acknowledgerestore(p),
            "vault_send" => self.vault_send(node, p).await,
            "vault_release" => self.vault_release(node, p).await,
            "vault_ownerspend" => self.vault_ownerspend(node, p).await,
            "vault_app" => self.vault_app(node, p).await,
            _ => Err(RpcError::new(code::METHOD_NOT_FOUND, "Method not found")),
        }
    }

    // ------------------------------------------------------------------ helpers

    async fn ensure_vault_active(&self, node: &dyn Node) -> Result<Next, RpcError> {
        let next = next_block(node).await?;
        let info = node::call(node, "vault_getinfo", serde_json::json!([])).await?;
        if !info["active"].as_bool().unwrap_or(false) {
            return Err(RpcError::new(
                code::MISC_ERROR,
                format!(
                    "the vault upgrade is not active at the next block (height {})",
                    next.height
                ),
            ));
        }
        Ok(next)
    }

    /// The sign-once records, from the signer.
    pub fn signed_records(&self) -> Result<SignedRecords, RpcError> {
        match self.signer.request(Request::ListSigned) {
            Ok(Response::Records(r)) => Ok(r),
            other => Err(signer_error(other)),
        }
    }

    /// `WalletSignedPrevout`.
    fn wallet_signed_prevout(&self, op: &OutPoint) -> bool {
        let p = op_str(op);
        self.signed_records()
            .map(|r| r.records.iter().any(|x| x.prevout == p))
            .unwrap_or(false)
    }

    /// `WalletKeyParam`: the named key (it must be this wallet's), or a new wallet key.
    fn wallet_key_param(&mut self, v: &Value, name: &str) -> Result<[u8; 33], RpcError> {
        if v.is_null() {
            return self.new_wallet_key();
        }
        let k = key_param(v, name)?;
        if self.key_of_pubkey(&k).is_none() {
            return Err(RpcError::new(
                code::WALLET_ERROR,
                format!("{name} is not a key in this wallet"),
            ));
        }
        Ok(k)
    }

    /// The minimum set maturity (`MinSetMaturity`, D-Q-31).
    fn min_set_maturity(&self) -> u32 {
        if self.network == yew_core::params::Network::Regtest {
            2
        } else {
            16_128
        }
    }

    /// Add act signatures this wallet can add (`SignActInPlace`); returns (missing, required).
    async fn sign_act_in_place(
        &mut self,
        node: &dyn Node,
        tx: &mut Transaction,
        ai: usize,
        a: &mut Act,
    ) -> Result<(i64, i64), RpcError> {
        let vin0 = tx
            .vin
            .first()
            .map(|i| act::OutPoint::from(i.prevout))
            .ok_or_else(|| invalid("an act transaction needs a transparent input (vin[0] is bound by the signatures)"))?;
        let payload = act::encode_payload(&a.body);
        let msg = act::act_msg(&payload, &vin0);
        let mut have: Vec<[u8; 33]> = Vec::new();
        for s in &a.sigs {
            let k = act::recover(&msg, s).ok_or_else(|| {
                invalid("an existing act signature does not recover (vin[0] changed?)")
            })?;
            have.push(k);
        }
        let mut add: Vec<[u8; 33]> = Vec::new();
        let holds = |w: &Wallet, k: &[u8; 33]| w.key_of_pubkey(k).is_some();
        let (missing, required);
        // current members of the set this wallet holds, excluding `exclude`, up to `from + count`
        let cosign = |w: &Wallet,
                      s: &SetView,
                      have: &Vec<[u8; 33]>,
                      add: &mut Vec<[u8; 33]>,
                      from: i64,
                      count: i64,
                      exclude: Option<&[u8; 33]>|
         -> i64 {
            for m in &s.members {
                if (have.len() + add.len()) as i64 >= from + count {
                    break;
                }
                if !m.current
                    || have.contains(&m.key)
                    || add.contains(&m.key)
                    || exclude == Some(&m.key)
                {
                    continue;
                }
                if holds(w, &m.key) {
                    add.push(m.key);
                }
            }
            from + count - (have.len() + add.len()) as i64
        };
        let unknown = |s: &[u8; 32]| invalid(format!("unknown set {}", txid_hex(s)));
        match &a.body {
            Body::Create(_) | Body::Equivocation(_) => {
                required = 0;
                missing = 0;
            }
            Body::Heartbeat { member_key, .. } => {
                required = 1;
                if have.is_empty() && holds(self, member_key) {
                    add.push(*member_key);
                }
                missing = if have.is_empty() && add.is_empty() {
                    1
                } else {
                    0
                };
            }
            Body::Join {
                set_id, member_key, ..
            } => {
                if have.is_empty() {
                    if !holds(self, member_key) {
                        return Ok((1, -1)); // S_1 must come first, from the member
                    }
                    add.push(*member_key);
                }
                let s = set_view(node, set_id)
                    .await?
                    .ok_or_else(|| unknown(set_id))?;
                if s.open {
                    required = 1;
                    missing = 0;
                } else if s.current >= s.slash_threshold {
                    required = 1 + s.slash_threshold;
                    missing = cosign(
                        self,
                        &s,
                        &have,
                        &mut add,
                        1,
                        s.slash_threshold,
                        Some(member_key),
                    );
                } else {
                    required = 2;
                    if have.len() + add.len() < 2 && holds(self, &s.admit_key) {
                        add.push(s.admit_key);
                    }
                    missing = if have.len() + add.len() >= 2 { 0 } else { 1 };
                }
            }
            Body::Remove {
                set_id, member_key, ..
            } => {
                let s = set_view(node, set_id)
                    .await?
                    .ok_or_else(|| unknown(set_id))?;
                required = s.slash_threshold;
                missing = cosign(
                    self,
                    &s,
                    &have,
                    &mut add,
                    0,
                    s.slash_threshold,
                    Some(member_key),
                );
            }
            Body::Winddown { set_id } => {
                let s = set_view(node, set_id)
                    .await?
                    .ok_or_else(|| unknown(set_id))?;
                required = s.slash_threshold;
                missing = cosign(self, &s, &have, &mut add, 0, s.slash_threshold, None);
            }
        }
        if !add.is_empty() {
            let keys: Vec<KeyRef> = add
                .iter()
                .map(|k| self.key_of_pubkey(k).expect("held"))
                .collect();
            let sigs = match self
                .signer
                .request(Request::SignAct(yewd_proto::ActSignRequest {
                    tx: tx_hex(tx)?,
                    keys,
                })) {
                Ok(Response::ActSigs(s)) => s,
                other => return Err(signer_error(other)),
            };
            if sigs.msg != hex::encode(msg) {
                return Err(RpcError::new(
                    code::INTERNAL_ERROR,
                    "the signer signed another act message",
                ));
            }
            for s in sigs.sigs {
                let b: [u8; 65] = hex::decode(&s)
                    .ok()
                    .and_then(|b| b.try_into().ok())
                    .ok_or_else(|| RpcError::new(code::WALLET_ERROR, "signing failed"))?;
                a.sigs.push(b);
            }
        }
        tx.vout[ai].script_pubkey = act::encode(a);
        Ok((missing.max(0), required))
    }

    /// `BuildActTx`: `before` outputs, then the act, funded (change last).
    async fn build_act_tx(
        &mut self,
        node: &dyn Node,
        a: &Act,
        before: Vec<TxOut>,
    ) -> Result<Transaction, RpcError> {
        let mut tx = new_tx();
        tx.vout = before;
        tx.vout.push(TxOut {
            value: 0,
            script_pubkey: act::encode(a),
        });
        self.fund(node, &mut tx, 0, VAULT_RPC_FEE, FundMode::LargestFirst)
            .await?;
        Ok(tx)
    }

    /// `ParseCreateParams`.
    fn parse_create(&mut self, o: &Value) -> Result<act::Create, RpcError> {
        if !o.is_object() {
            return Err(RpcError::new(code::TYPE_ERROR, "Expected type object"));
        }
        let num = |k: &str, def: Option<i64>| -> Result<i64, RpcError> {
            match (int_field(o, k)?, def) {
                (Some(v), _) => Ok(v),
                (None, Some(d)) => Ok(d),
                (None, None) => Err(invalid(format!("missing {k}"))),
            }
        };
        let seats = num("seats", None)?;
        let unlock = num("unlockthreshold", None)?;
        let min_mat = self.min_set_maturity() as i64;
        let maturity = num("maturity", Some(min_mat))?;
        if maturity < min_mat {
            return Err(invalid(format!(
                "maturity must be at least {min_mat} blocks (D-Q-31)"
            )));
        }
        let bond_min = match o.get("bondmin").filter(|v| !v.is_null()) {
            Some(v) => amount_param(v)?,
            None => 100_000_000,
        };
        let c = act::Create {
            seats: seats as u8,
            unlock_threshold: unlock as u8,
            cancel_threshold: num("cancelthreshold", Some(1))? as u8,
            slash_threshold: num("slashthreshold", Some(unlock))? as u8,
            flags: if bool_field(o, "open")? {
                act::SET_FLAG_OPEN
            } else {
                0
            },
            rate_limit_bps: num("ratelimitbps", Some(0))? as u16,
            rate_window: num("ratewindow", Some(144))? as u32,
            liveness_window: num("livenesswindow", Some(1000))? as u32,
            bond_min,
            bond_lock_min: num("bondlockmin", Some(0))? as u32,
            maturity: maturity as u32,
            admit_key: self.wallet_key_param(field(o, "admitkey"), "admitkey")?,
        };
        // the casts above truncate as the node's do; Valid() judges the truncated values
        if !c.valid() || seats > 255 || unlock > 255 {
            return Err(invalid(
                "the set parameters are out of range (plan §15.5 row 0x01)",
            ));
        }
        Ok(c)
    }

    fn parse_proof(o: &Value) -> Result<act::Equivocation, RpcError> {
        let role = |k: &str| -> Result<u8, RpcError> {
            int_field(o, k)?.map(|v| v as u8).ok_or_else(|| {
                RpcError::new(code::TYPE_ERROR, format!("{k}: Expected type number"))
            })
        };
        let po = outpoint_param(field(o, "prevout"), "prevout")?;
        Ok(act::Equivocation {
            set_id: hash_param(field(o, "setid"), "setid")?,
            prevout: act::OutPoint::from(po),
            role_a: role("rolea")?,
            sighash_a: raw32_param(field(o, "sighasha"), "sighasha")?,
            sig_a: sig65_param(field(o, "siga"), "siga")?,
            role_b: role("roleb")?,
            sighash_b: raw32_param(field(o, "sighashb"), "sighashb")?,
            sig_b: sig65_param(field(o, "sigb"), "sigb")?,
        })
    }

    /// `BuildActFromParams`.
    async fn build_act_from_params(
        &mut self,
        node: &dyn Node,
        t: u8,
        p: &Value,
    ) -> Result<(Transaction, Act), RpcError> {
        let empty = serde_json::json!({});
        let o = if p.is_null() { &empty } else { p };
        if !o.is_object() {
            return Err(RpcError::new(code::TYPE_ERROR, "Expected type object"));
        }
        let mut before = Vec::new();
        let body = match t {
            act::SET_CREATE => Body::Create(self.parse_create(o)?),
            act::SET_JOIN => {
                let set_id = hash_param(field(o, "setid"), "setid")?;
                let member_key = match field(o, "memberkey") {
                    Value::Null => self.new_wallet_key()?,
                    v => key_param(v, "memberkey")?,
                };
                let bond = amount_param(field(o, "bondamount"))?;
                let lt = int_field(o, "bondlocktime")?.ok_or_else(|| {
                    RpcError::new(code::TYPE_ERROR, "bondlocktime: Expected type number")
                })?;
                if !(1..500_000_000).contains(&lt) {
                    return Err(invalid("bondlocktime must be a height below 500000000"));
                }
                before.push(TxOut {
                    value: bond,
                    script_pubkey: act::bond_script_pubkey(lt as u32, &member_key),
                });
                Body::Join {
                    set_id,
                    member_key,
                    bond_locktime: lt as u32,
                    bond_vout: 0,
                }
            }
            act::SET_HEARTBEAT => Body::Heartbeat {
                set_id: hash_param(field(o, "setid"), "setid")?,
                member_key: key_param(field(o, "memberkey"), "memberkey")?,
            },
            act::SET_REMOVE => Body::Remove {
                set_id: hash_param(field(o, "setid"), "setid")?,
                member_key: key_param(field(o, "memberkey"), "memberkey")?,
                burn: bool_field(o, "burn")? as u8,
            },
            act::SET_EQUIVOCATION => Body::Equivocation(Box::new(Self::parse_proof(o)?)),
            act::SET_WINDDOWN => Body::Winddown {
                set_id: hash_param(field(o, "setid"), "setid")?,
            },
            _ => return Err(invalid("unknown act type")),
        };
        let a = Act { body, sigs: vec![] };
        let tx = self.build_act_tx(node, &a, before).await?;
        Ok((tx, a))
    }

    /// Sign this wallet's inputs of a one-shot build and broadcast it (`SignWalletInputs` +
    /// `Broadcast`). The signer's outflow cap is what the request itself spends: `spend` (a vault's
    /// amount) plus the flat fee and a change remainder folded into it.
    async fn sign_send(
        &mut self,
        node: &dyn Node,
        tx: &Transaction,
        next: Next,
        spend: i64,
    ) -> Result<String, RpcError> {
        let cap = self.max_tx_fee(node).await;
        let signed = self
            .sign_wallet_inputs(
                node,
                tx,
                GatePath::Vault,
                spend + VAULT_RPC_FEE + VAULT_RPC_MIN_CHANGE,
                next,
            )
            .await?;
        self.broadcast(node, &signed, Some(cap)).await
    }

    // ------------------------------------------------------------------ act RPCs

    async fn set_create(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        want_params(p, 1, 1, "set_create {params}")?;
        let next = self.ensure_vault_active(node).await?;
        let (tx, a) = self
            .build_act_from_params(node, act::SET_CREATE, &p[0])
            .await?;
        let txid = self.sign_send(node, &tx, next, 0).await?;
        let Body::Create(c) = &a.body else {
            unreachable!()
        };
        Ok(J::obj()
            .with("txid", txid.clone())
            .with("setid", txid)
            .with("admitkey", hex::encode(c.admit_key)))
    }

    pub(crate) async fn set_join(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        want_params(
            p,
            3,
            4,
            "set_join \"setid\" bondamount bondlocktime ( \"memberkey\" )",
        )?;
        let next = self.ensure_vault_active(node).await?;
        let mut o = serde_json::json!({"setid": p[0], "bondamount": p[1], "bondlocktime": p[2]});
        if let Some(k) = param(p, 3) {
            self.wallet_key_param(k, "memberkey")?;
            o["memberkey"] = k.clone();
        }
        let set = hash_param(&p[0], "setid")?;
        if set_view(node, &set).await?.is_none() {
            return Err(RpcError::new(
                code::INVALID_ADDRESS_OR_KEY,
                "unknown set (it must be confirmed)",
            ));
        }
        let (mut tx, a) = self.build_act_from_params(node, act::SET_JOIN, &o).await?;
        let (ai, mut decoded) = find_act(&tx)?;
        let (missing, required) = self
            .sign_act_in_place(node, &mut tx, ai, &mut decoded)
            .await?;
        let mut r = J::obj();
        if missing == 0 {
            let txid = self.sign_send(node, &tx, next, 0).await?;
            r.push("txid", J::Str(txid));
        } else {
            self.remember_build(&tx.vin[0].prevout.clone(), &tx)?;
        }
        let J::Obj(fields) = act_result(&tx, &decoded, missing, required)? else {
            unreachable!()
        };
        for (k, v) in fields {
            r.push(&k, v);
        }
        let Body::Join { member_key, .. } = &a.body else {
            unreachable!()
        };
        r.push("memberkey", J::Str(hex::encode(member_key)));
        r.push("bondoutpoint", J::Str(format!("{}:0", txid_of(&tx)?)));
        Ok(r)
    }

    async fn member_key_param(
        &mut self,
        node: &dyn Node,
        p: &[Value],
        set: &[u8; 32],
        active_only: bool,
    ) -> Result<[u8; 33], RpcError> {
        if let Some(k) = param(p, 1) {
            return self.wallet_key_param(k, "memberkey");
        }
        let s = set_view(node, set).await?.ok_or_else(|| {
            RpcError::new(
                code::INVALID_ADDRESS_OR_KEY,
                format!("unknown set {}", txid_hex(set)),
            )
        })?;
        s.members
            .iter()
            .find(|m| {
                (if active_only {
                    m.status == "active"
                } else {
                    m.current
                }) && self.key_of_pubkey(&m.key).is_some()
            })
            .map(|m| m.key)
            .ok_or_else(|| {
                RpcError::new(
                    code::WALLET_ERROR,
                    if active_only {
                        "this wallet holds no active member key of the set"
                    } else {
                        "this wallet holds no current member key of the set"
                    },
                )
            })
    }

    pub(crate) async fn set_heartbeat(
        &mut self,
        node: &dyn Node,
        p: &[Value],
    ) -> Result<J, RpcError> {
        want_params(p, 1, 2, "set_heartbeat \"setid\" ( \"memberkey\" )")?;
        let next = self.ensure_vault_active(node).await?;
        let set = hash_param(&p[0], "setid")?;
        if set_view(node, &set).await?.is_none() {
            return Err(RpcError::new(
                code::INVALID_ADDRESS_OR_KEY,
                format!("unknown set {}", txid_hex(&set)),
            ));
        }
        let key = self.member_key_param(node, p, &set, false).await?;
        let a = Act {
            body: Body::Heartbeat {
                set_id: set,
                member_key: key,
            },
            sigs: vec![],
        };
        let mut tx = self.build_act_tx(node, &a, vec![]).await?;
        let (ai, mut decoded) = find_act(&tx)?;
        self.sign_act_in_place(node, &mut tx, ai, &mut decoded)
            .await?;
        let txid = self.sign_send(node, &tx, next, 0).await?;
        Ok(J::obj()
            .with("txid", txid)
            .with("memberkey", hex::encode(key)))
    }

    async fn set_leave(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        want_params(p, 1, 2, "set_leave \"setid\" ( \"memberkey\" )")?;
        let next = self.ensure_vault_active(node).await?;
        let set = hash_param(&p[0], "setid")?;
        let s = set_view(node, &set).await?.ok_or_else(|| {
            RpcError::new(
                code::INVALID_ADDRESS_OR_KEY,
                format!("unknown set {}", txid_hex(&set)),
            )
        })?;
        let key = self.member_key_param(node, p, &set, true).await?;
        let a = Act {
            body: Body::Remove {
                set_id: set,
                member_key: key,
                burn: 0,
            },
            sigs: vec![],
        };
        let mut tx = self.build_act_tx(node, &a, vec![]).await?;
        let (ai, mut decoded) = find_act(&tx)?;
        // the member's own SET_REMOVE: its key alone
        let k = self.key_of_pubkey(&key).ok_or_else(|| {
            RpcError::new(code::WALLET_ERROR, "the member key is not in this wallet")
        })?;
        let sigs = match self
            .signer
            .request(Request::SignAct(yewd_proto::ActSignRequest {
                tx: tx_hex(&tx)?,
                keys: vec![k],
            })) {
            Ok(Response::ActSigs(s)) => s,
            other => return Err(signer_error(other)),
        };
        decoded.sigs = sigs
            .sigs
            .iter()
            .filter_map(|s| hex::decode(s).ok()?.try_into().ok())
            .collect();
        tx.vout[ai].script_pubkey = act::encode(&decoded);
        let txid = self.sign_send(node, &tx, next, 0).await?;
        Ok(J::obj()
            .with("txid", txid)
            .with("memberkey", hex::encode(key))
            .with("exitheight", next.height as i64)
            .with("bondspendableat", next.height as i64 + s.maturity))
    }

    async fn set_buildact(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        want_params(p, 2, 2, "set_buildact \"type\" {params}")?;
        self.ensure_vault_active(node).await?;
        let t = p[0]
            .as_str()
            .and_then(act::type_of_name)
            .ok_or_else(|| invalid("unknown act type"))?;
        let (tx, a) = self.build_act_from_params(node, t, &p[1]).await?;
        let (mut required, mut missing) = (0, 0);
        if let Some(set) = a
            .body
            .target_set()
            .filter(|_| !matches!(a.body, Body::Create(_) | Body::Equivocation(_)))
        {
            let s = set_view(node, &set).await?.ok_or_else(|| {
                RpcError::new(
                    code::INVALID_ADDRESS_OR_KEY,
                    format!("unknown set {}", txid_hex(&set)),
                )
            })?;
            required = match a.body {
                Body::Heartbeat { .. } => 1,
                Body::Join { .. } => {
                    if s.open {
                        1
                    } else if s.current >= s.slash_threshold {
                        1 + s.slash_threshold
                    } else {
                        2
                    }
                }
                _ => s.slash_threshold,
            };
            missing = required;
        }
        self.remember_build(&tx.vin[0].prevout.clone(), &tx)?;
        act_result(&tx, &a, missing, required)
    }

    async fn set_signact(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        want_params(p, 1, 2, "set_signact \"hex\" ( \"setid\" )")?;
        let mut tx = decode_tx_param(&p[0])?;
        let (ai, mut a) = find_act(&tx)?;
        if let Some(s) = param(p, 1) {
            if !matches!(a.body, Body::Create(_))
                && Some(hash_param(s, "setid")?) != a.body.target_set()
            {
                return Err(invalid(format!(
                    "the act names set {}",
                    txid_hex(&a.body.target_set().unwrap_or([0; 32]))
                )));
            }
        }
        let (missing, required) = self.sign_act_in_place(node, &mut tx, ai, &mut a).await?;
        act_result(&tx, &a, missing, required)
    }

    async fn set_sendact(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        want_params(
            p,
            1,
            2,
            "set_sendact \"hex\" ( {\"dryrun\", \"allowinputs\", \"allowoutflow\"} )",
        )?;
        self.prune_builds(node).await?;
        let tx = decode_tx_param(&p[0])?;
        find_act(&tx)?;
        let key = tx.vin.first().map(|i| i.prevout).ok_or_else(|| {
            invalid(
                "an act transaction needs a transparent input (vin[0] is bound by the signatures)",
            )
        })?;
        let opt = handoff_options(p)?;
        self.handoff_send(node, tx, &key, &opt, J::Null).await
    }

    async fn set_equivocation(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        want_params(p, 1, 1, "set_equivocation {proof}")?;
        let next = self.ensure_vault_active(node).await?;
        let (tx, _) = self
            .build_act_from_params(node, act::SET_EQUIVOCATION, &p[0])
            .await?;
        Ok(J::Str(self.sign_send(node, &tx, next, 0).await?))
    }

    /// `HandoffSend`.
    async fn handoff_send(
        &mut self,
        node: &dyn Node,
        tx: Transaction,
        build_key: &OutPoint,
        opt: &Handoff,
        templ: J,
    ) -> Result<J, RpcError> {
        let memo = self.build_of(build_key);
        let same = memo.as_ref().is_some_and(|m| same_handoff_outputs(m, &tx));
        let funded: HashSet<OutPoint> = if same {
            memo.as_ref()
                .map(|m| m.vin.iter().map(|i| i.prevout).collect())
                .unwrap_or_default()
        } else {
            HashSet::new()
        };
        let prevouts = self.prevouts_of(node, &tx).await?;
        let cap = self.max_tx_fee(node).await;
        let mut sign = Vec::new();
        let mut foreign = Vec::new();
        let mut keys = vec![KeyRef::None; tx.vin.len()];
        let mut signed_in = 0i64;
        let mut refuse: Option<String> = None;
        for (i, p) in prevouts.iter().enumerate() {
            let Some(p) = p else { continue };
            if yv::parse_vault(&p.script).is_some() || yv::parse_intent(&p.script).is_some() {
                continue;
            }
            let Some(k) = self.key_of_script(&p.script) else {
                continue;
            };
            let op = tx.vin[i].prevout;
            let chosen = same && funded.contains(&op);
            let row = J::obj()
                .with("vin", i as i64)
                .with("outpoint", op_str(&op))
                .with("amount", J::Amount(p.value));
            if !chosen {
                foreign.push(row.clone());
                if !opt.allow_inputs.contains(&op) && refuse.is_none() {
                    refuse = Some(format!(
                        "vault-send-foreign-input: input {i} ({}, {}) is this wallet's coin but was not chosen by this wallet for these outputs; nothing was signed",
                        op_str(&op),
                        money(p.value)
                    ));
                }
            }
            if chosen || opt.allow_inputs.contains(&op) {
                sign.push(row);
                signed_in += p.value;
                keys[i] = k;
            }
        }
        let mut own: BTreeSet<u32> = BTreeSet::new();
        let mut extra_own: Vec<OwnOutput> = Vec::new();
        let mut act_field = J::Null;
        for (n, o) in tx.vout.iter().enumerate() {
            if self.key_of_script(&o.script_pubkey).is_some() {
                own.insert(n as u32);
            }
            if !matches!(act_field, J::Null) || !act::is_act_output(&o.script_pubkey) {
                continue;
            }
            let Ok(a) = act::decode(&o.script_pubkey) else {
                continue;
            };
            act_field = act_json(&a, tx.vin.first().map(|i| &i.prevout));
            if let Body::Join {
                member_key,
                bond_locktime,
                bond_vout,
                ..
            } = a.body
            {
                if let Some(k) = self.key_of_pubkey(&member_key) {
                    if (bond_vout as usize) < tx.vout.len() && own.insert(bond_vout as u32) {
                        extra_own.push(OwnOutput {
                            n: bond_vout as u32,
                            key: k,
                            bond_locktime: Some(bond_locktime),
                        });
                    }
                }
            }
        }
        let own_out: i64 = own.iter().map(|n| tx.vout[*n as usize].value).sum();
        let outflow = signed_in - own_out;
        if refuse.is_none() && outflow > cap && opt.allow_outflow.is_none_or(|a| a < outflow) {
            refuse = Some(format!(
                "vault-send-outflow: this wallet would pay {} beyond its own outputs (the fee cap is {}); nothing was signed",
                money(outflow),
                money(cap)
            ));
        }
        let mut outputs = Vec::new();
        for (n, o) in tx.vout.iter().enumerate() {
            let mut row = J::obj()
                .with("n", n as i64)
                .with("amount", J::Amount(o.value));
            match yewd_proto::preview::script_address(self.network, &o.script_pubkey) {
                Some(a) => row.push("address", J::Str(a)),
                None => row.push("script", J::Str(hex::encode(&o.script_pubkey))),
            };
            row.push("mine", J::Bool(own.contains(&(n as u32))));
            row.push(
                "kind",
                J::Str(yewd_proto::preview::output_kind(&o.script_pubkey).into()),
            );
            outputs.push(row);
        }
        let all_in = prevouts.iter().all(Option::is_some);
        let fee = if all_in {
            J::Amount(prevouts.iter().flatten().map(|p| p.value).sum::<i64>() - tx.output_total())
        } else {
            J::Null
        };
        if opt.dryrun {
            return Ok(J::obj()
                .with("template", templ)
                .with("act", act_field)
                .with("sign", J::Arr(sign))
                .with("foreign", J::Arr(foreign))
                .with("outputs", J::Arr(outputs))
                .with("fee", fee)
                .with("outflow", J::Amount(outflow))
                .with("wouldrefuse", refuse.map(J::Str).unwrap_or(J::Null)));
        }
        if let Some(r) = refuse {
            return Err(RpcError::new(code::WALLET_ERROR, r));
        }
        let coins: Vec<NodeCoin> = prevouts
            .into_iter()
            .enumerate()
            .map(|(i, p)| {
                p.ok_or_else(|| {
                    RpcError::new(
                        code::TRANSACTION_ERROR,
                        format!("Missing inputs: input {i} is spent or unknown"),
                    )
                })
            })
            .collect::<Result<_, _>>()?;
        let next = next_block(node).await?;
        let cap_for_signer = opt.allow_outflow.map(|a| a.max(cap)).unwrap_or(cap);
        let signed = self
            .sign_inputs(
                &tx,
                &coins,
                &keys,
                &extra_own,
                GatePath::Vault,
                cap_for_signer,
                next.branch,
            )
            .await?;
        Ok(J::Str(self.broadcast(node, &signed, Some(cap)).await?))
    }

    // ------------------------------------------------------------------ vault RPCs

    /// `ParsePQOwner`.
    fn owner_param(&self, v: &Value, name: &str) -> Result<PqKeyId, RpcError> {
        let unreg = || invalid(format!("{name}: unregistered post-quantum scheme"));
        if let Some(o) = v.as_object() {
            let sc = o
                .get("scheme")
                .and_then(|s| s.as_i64())
                .ok_or_else(|| invalid(format!("{name}.scheme must be a number")))?;
            let h = hex_param(
                o.get("keyhash").unwrap_or(&Value::Null),
                &format!("{name}.keyhash"),
            )?;
            let hash: [u8; 32] = h
                .try_into()
                .map_err(|_| invalid(format!("{name}.keyhash must be 32 bytes (64 hex digits)")))?;
            if !(0..=255).contains(&sc) {
                return Err(unreg());
            }
            let id = PqKeyId {
                scheme: sc as u8,
                hash,
            };
            if !id.is_known() {
                return Err(unreg());
            }
            return Ok(id);
        }
        let s = v
            .as_str()
            .ok_or_else(|| RpcError::new(code::TYPE_ERROR, "Expected type string"))?;
        let id = if s.len() == 66 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            PqKeyId::from_bytes(&hex::decode(s).expect("hex")).expect("33 bytes")
        } else if let Ok(id) = yew_core::keys::parse_pq_address(self.network, s) {
            id
        } else if let Ok(id) = yew_core::keys::parse_pq_yec_address(self.network, s) {
            id
        } else {
            return Err(invalid(format!(
                "{name} must be a pqkeyid (66 hex digits, scheme || keyhash) or a PQ address"
            )));
        };
        if !id.is_known() {
            return Err(unreg());
        }
        Ok(id)
    }

    /// `ParseRecipient`.
    fn recipient_param(&self, o: &Value) -> Result<Vec<u8>, RpcError> {
        let addr = field(o, "address");
        let script = field(o, "script");
        if addr.is_null() == script.is_null() {
            return Err(invalid(
                "a recipient needs exactly one of \"address\" or \"script\"",
            ));
        }
        if let Some(a) = addr.as_str() {
            return crate::rpc::parse_taddr_script(self.network, a).ok_or_else(|| {
                RpcError::new(
                    code::INVALID_ADDRESS_OR_KEY,
                    format!("invalid transparent address: {a}"),
                )
            });
        }
        hex_param(script, "script")
    }

    async fn vault_lock(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        want_params(p, 1, 1, "vault_lock {params}")?;
        let next = self.ensure_vault_active(node).await?;
        let o = &p[0];
        if !o.is_object() {
            return Err(RpcError::new(code::TYPE_ERROR, "Expected type object"));
        }
        let tag = tag_param(field(o, "tag"))?;
        let set_id = hash_param(field(o, "setid"), "setid")?;
        let cancel_set_id = match field(o, "cancelsetid") {
            Value::Null => set_id,
            v => hash_param(v, "cancelsetid")?,
        };
        let delay = int_field(o, "delay")?
            .ok_or_else(|| RpcError::new(code::TYPE_ERROR, "delay: Expected type number"))?;
        let owner_height = int_field(o, "ownerheight")?
            .ok_or_else(|| RpcError::new(code::TYPE_ERROR, "ownerheight: Expected type number"))?;
        let app_height = int_field(o, "appheight")?.unwrap_or(0);
        if app_height != 0 {
            let info = node::call(node, "vault_getinfo", serde_json::json!([])).await?;
            let governed = tag == yv::YED_TAG && !info["attestorsetid"].is_null();
            if !governed {
                return Err(invalid("appheight on a tag no module governs: the APP branch has no signer and only a module with its set may govern it (V-1, bad-txns-vault-app)"));
            }
        }
        if !field(o, "ownerkey").is_null() {
            return Err(invalid("ownerkey-removed: use owner (pqkeyid)"));
        }
        let new_owner = field(o, "owner").is_null();
        let mut owner = if new_owner {
            PqKeyId {
                scheme: 1,
                hash: [0; 32],
            }
        } else {
            self.owner_param(field(o, "owner"), "owner")?
        };
        if owner.scheme == 2 && !self.falcon_next() {
            return Err(invalid(
                "a scheme-2 (FN-DSA-512) owner before Falcon is active",
            ));
        }
        let amount = amount_param(field(o, "amount"))?;
        let mut vp = VaultParams {
            tag,
            cancel_set_id,
            delay,
            set_id,
            owner_height,
            owner,
            app_height,
        };
        if !yv::vault_params_valid(&vp) {
            return Err(invalid("vault parameters out of range (plan §15.3)"));
        }
        if set_view(node, &set_id).await?.is_none()
            || set_view(node, &cancel_set_id).await?.is_none()
        {
            return Err(RpcError::new(
                code::INVALID_ADDRESS_OR_KEY,
                "setid and cancelsetid must be confirmed sets",
            ));
        }
        if new_owner {
            owner = self.new_pq(1)?;
            self.st.owners.insert(pqkeyid_hex(&owner));
            vp.owner = owner;
        }
        let spk = yv::build_vault(&vp)
            .ok_or_else(|| invalid("vault parameters out of range (plan §15.3)"))?;
        let mut tx = new_tx();
        tx.vout.push(TxOut {
            value: amount,
            script_pubkey: spk.clone(),
        });
        self.fund(node, &mut tx, 0, VAULT_RPC_FEE, FundMode::LargestFirst)
            .await?;
        let txid = self.sign_send(node, &tx, next, amount).await?;
        Ok(J::obj()
            .with("txid", txid.clone())
            .with("vout", 0i64)
            .with("outpoint", format!("{txid}:0"))
            .with("script", hex::encode(&spk))
            .with("owner", pqkeyid_hex(&vp.owner)))
    }

    /// `AddIntents`: one intent per recipient, the remainder re-locked byte-identically (S-2).
    fn add_intents(
        &mut self,
        tx: &mut Transaction,
        vp: &VaultParams,
        coin: &NodeCoin,
        recipients: &Value,
    ) -> Result<J, RpcError> {
        let arr = recipients
            .as_array()
            .ok_or_else(|| RpcError::new(code::TYPE_ERROR, "Expected type array"))?;
        let mut out = Vec::new();
        let mut sum = 0i64;
        for r in arr {
            if !r.is_object() {
                return Err(RpcError::new(code::TYPE_ERROR, "Expected type object"));
            }
            let dest = self.recipient_param(r)?;
            let amt = amount_param(field(r, "amount"))?;
            sum = sum.saturating_add(amt);
            if sum > coin.value || sum > crate::build::MAX_MONEY {
                return Err(invalid("the recipients' amounts exceed the vault's value"));
            }
            let ip = yv::intent_for(vp, &coin.script, &dest);
            self.st
                .recipients
                .insert(hex::encode(ip.recipient_hash), hex::encode(&dest));
            let spk = yv::build_intent(&ip).ok_or_else(|| invalid("the intent is out of range"))?;
            tx.vout.push(TxOut {
                value: amt,
                script_pubkey: spk,
            });
            out.push(
                J::obj()
                    .with("vout", (tx.vout.len() - 1) as i64)
                    .with("amount", J::Amount(amt))
                    .with("recipient", hex::encode(&dest))
                    .with("recipienthash", hex::encode(ip.recipient_hash)),
            );
        }
        if sum < coin.value {
            tx.vout.push(TxOut {
                value: coin.value - sum,
                script_pubkey: coin.script.clone(),
            });
        }
        self.persist_state()?;
        Ok(J::Arr(out))
    }

    /// `FeeInputsUnspent`.
    async fn fee_inputs_unspent(
        &self,
        node: &dyn Node,
        templ: &OutPoint,
        t: &Transaction,
    ) -> Result<bool, RpcError> {
        let spent = self.mempool_spent();
        for i in &t.vin {
            if i.prevout == *templ {
                continue;
            }
            if node_coin(node, &i.prevout).await?.is_none()
                || spent.contains(&(txid_hex(&i.prevout.txid), i.prevout.n))
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// `ExactCoin`: a wallet coin of exactly `value` (within `VAULT_RPC_MIN_CHANGE` above), or a
    /// self-send of exactly that amount broadcast now.
    async fn exact_coin(
        &mut self,
        node: &dyn Node,
        value: i64,
        exclude: &HashSet<OutPoint>,
        replacing: &HashSet<OutPoint>,
    ) -> Result<OutPoint, RpcError> {
        let mut not_exact = exclude.clone();
        not_exact.extend(replacing.iter().copied());
        let eligible = self.eligible(node, &not_exact).await?;
        if let Some(c) = eligible
            .iter()
            .rev()
            .find(|c| c.value >= value && c.value < value + VAULT_RPC_MIN_CHANGE)
        {
            let op = c.outpoint;
            self.lock_coin(&op);
            self.persist_state()?;
            return Ok(op);
        }
        let mut split = new_tx();
        let k = self.new_wallet_key()?;
        split.vout.push(TxOut {
            value,
            script_pubkey: yew_core::script::p2pkh_script(&yew_core::keys::hash160(&k)),
        });
        self.fund(node, &mut split, 0, VAULT_RPC_FEE, FundMode::LargestFirst)
            .await?;
        let next = next_block(node).await?;
        let txid = self.sign_send(node, &split, next, 0).await?;
        let op = OutPoint {
            txid: yew_core::tx::txid_from_hex(&txid)
                .map_err(|e| RpcError::new(code::INTERNAL_ERROR, e))?,
            n: 0,
        };
        self.lock_coin(&op);
        self.persist_state()?;
        Ok(op)
    }

    /// `Refee`: replace every input but the template input by one wallet coin worth exactly what
    /// the outputs need beyond the template coin plus the fee; the sighash is unchanged.
    async fn refee(
        &mut self,
        node: &dyn Node,
        tx: &mut Transaction,
        idx: usize,
        coin: &NodeCoin,
    ) -> Result<Vec<OutPoint>, RpcError> {
        let next = next_block(node).await?;
        let before = sighash_set(tx, idx, coin, next.branch)?;
        let old: Vec<OutPoint> = tx
            .vin
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != idx)
            .map(|(_, i)| i.prevout)
            .collect();
        let templ = tx.vin[idx].clone();
        let mut released = Vec::new();
        for op in &old {
            if self.is_locked(op) {
                self.unlock_coin(op);
                released.push(*op);
            }
        }
        tx.vin = vec![templ.clone()];
        let needed = tx.output_total() + VAULT_RPC_FEE - coin.value;
        if needed > 0 {
            let exclude: HashSet<OutPoint> = [templ.prevout].into_iter().collect();
            let replacing: HashSet<OutPoint> = old.iter().copied().collect();
            match self.exact_coin(node, needed, &exclude, &replacing).await {
                Ok(op) => tx.vin.push(TxIn::new(op)),
                Err(e) => {
                    for op in &released {
                        self.lock_coin(op);
                    }
                    self.persist_state()?;
                    return Err(e);
                }
            }
        }
        if sighash_set(tx, 0, coin, next.branch)? != before {
            return Err(RpcError::new(
                code::INTERNAL_ERROR,
                "re-funding changed the set sighash",
            ));
        }
        let cap = self.max_tx_fee(node).await;
        let mut input = coin.value;
        for i in tx.vin.iter().skip(1) {
            match node_coin(node, &i.prevout).await? {
                Some(c) if !old.contains(&i.prevout) => input += c.value,
                _ => {
                    let t = tx.clone();
                    self.unlock_build_inputs(&templ.prevout, &t);
                    for op in &released {
                        self.lock_coin(op);
                    }
                    self.persist_state()?;
                    return Err(RpcError::new(
                        code::WALLET_ERROR,
                        format!("vault_refee: the new fee input {} is spent or is a replaced input; nothing was changed", op_str(&i.prevout)),
                    ));
                }
            }
        }
        let fee = input - tx.output_total();
        if fee <= 0 || fee > cap {
            let t = tx.clone();
            self.unlock_build_inputs(&templ.prevout, &t);
            for op in &released {
                self.lock_coin(op);
            }
            self.persist_state()?;
            return Err(RpcError::new(
                code::WALLET_ERROR,
                format!("vault_refee: the re-funded spend would pay a fee of {} (allowed: above 0, at most {}); nothing was changed", money(fee), money(cap)),
            ));
        }
        let now: HashSet<OutPoint> = tx.vin.iter().map(|i| i.prevout).collect();
        for op in &old {
            if !now.contains(op) {
                self.unlock_coin(op);
            }
        }
        self.persist_state()?;
        Ok(old)
    }

    async fn vault_buildunlock(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        want_params(p, 2, 3, "vault_buildunlock \"outpoint\" [{\"address\"|\"script\", \"amount\"}, ...] ( rebuild )")?;
        let next = self.ensure_vault_active(node).await?;
        let op = outpoint_param(&p[0], "outpoint")?;
        let rebuild = param(p, 2).and_then(|v| v.as_bool()).unwrap_or(false);
        let coin = node_coin(node, &op).await?;
        let (coin, vp) = match coin
            .as_ref()
            .and_then(|c| yv::parse_vault(&c.script).map(|v| (c.clone(), v)))
        {
            Some(x) => x,
            None => return Err(invalid("not an unspent vault output")),
        };
        self.prune_builds(node).await?;
        let mut tx = new_tx();
        tx.vin.push(TxIn::new(op));
        let intents = self.add_intents(&mut tx, &vp, &coin, &p[1])?;
        let mut build = "new";
        let memo = self.build_of(&op);
        let keep_signed = memo.is_some() && rebuild && self.wallet_signed_prevout(&op);
        if let Some(c) = memo {
            if rebuild {
                if !keep_signed {
                    self.unlock_build_inputs(&op, &c);
                }
            } else {
                let same = !c.vin.is_empty()
                    && c.vin[0].prevout == op
                    && c.vout.len() >= tx.vout.len()
                    && c.vout.len() <= tx.vout.len() + 1
                    && c.vout[..tx.vout.len()] == tx.vout[..];
                if !same {
                    return Err(invalid(format!(
                        "this wallet already built a different unlock of {} (sighash {}): members sign once, so collect signatures on that build (call again with its recipients), or pass rebuild=true if no member has signed it",
                        op_str(&op),
                        hex::encode(sighash_set(&c, 0, &coin, next.branch)?)
                    )));
                }
                tx = c;
                build = "reused";
                if !self.fee_inputs_unspent(node, &op, &tx).await? {
                    self.refee(node, &mut tx, 0, &coin).await?;
                    build = "refunded";
                }
            }
        }
        if build == "new" {
            self.fund(
                node,
                &mut tx,
                coin.value,
                VAULT_RPC_FEE,
                FundMode::SmallChange,
            )
            .await?;
        }
        if !keep_signed {
            self.remember_build(&op, &tx)?;
        }
        let required = set_view(node, &vp.set_id)
            .await?
            .map(|s| s.unlock_threshold)
            .unwrap_or(0);
        let sighash = sighash_set(&tx, 0, &coin, next.branch)?;
        Ok(J::obj()
            .with("hex", tx_hex(&tx)?)
            .with("intents", intents)
            .with("required", required)
            .with("sighash", hex::encode(sighash))
            .with("build", build))
    }

    /// `FindTemplateInput`.
    async fn find_template(&self, node: &dyn Node, tx: &Transaction) -> Result<Template, RpcError> {
        let mut found: Option<Template> = None;
        for (i, vin) in tx.vin.iter().enumerate() {
            let Some(c) = node_coin(node, &vin.prevout).await? else {
                continue;
            };
            let vault = yv::parse_vault(&c.script);
            let intent = if vault.is_none() {
                yv::parse_intent(&c.script)
            } else {
                None
            };
            if vault.is_none() && intent.is_none() {
                continue;
            }
            if found.is_some() {
                return Err(invalid("more than one template input (S-1)"));
            }
            found = Some(Template {
                idx: i,
                coin: c,
                vault,
                intent,
            });
        }
        found.ok_or_else(|| invalid("no unspent vault or intent input"))
    }

    /// `ValidateSetSpend`, the structural part the façade can judge from public state (finding
    /// F-S2-3): an intent's cancel only before it matured, an unlock's outputs within S-2 (the
    /// intents of this vault, the re-lock byte-identical, nothing above the vault's value).
    async fn validate_set_spend(
        &self,
        node: &dyn Node,
        tx: &Transaction,
        t: &Template,
        role: u8,
        next: Next,
    ) -> Result<(), RpcError> {
        let bad = |r: &str| {
            invalid(format!(
                "set-sign-invalid: {r}; nothing was recorded or signed"
            ))
        };
        if role == ROLE_CANCEL {
            let ip = t.intent.as_ref().expect("an intent");
            let h = t.coin.height.unwrap_or(next.height) as i64;
            if next.height as i64 - h >= ip.delay {
                return Err(bad("bad-txns-vault-cancel-late"));
            }
            let Some(out0) = tx.vout.first() else {
                return Err(bad("bad-txns-vault-cancel"));
            };
            if yew_core::keys::sha256(&out0.script_pubkey) != ip.vault_hash
                || out0.value < t.coin.value
            {
                return Err(bad("bad-txns-vault-cancel"));
            }
        } else {
            let vp = t.vault.as_ref().expect("a vault");
            let vhash = yew_core::keys::sha256(&t.coin.script);
            let mut total = 0i64;
            let mut relock = false;
            for o in &tx.vout {
                if let Some(ip) = yv::parse_intent(&o.script_pubkey) {
                    if ip.vault_hash != vhash
                        || ip.delay != vp.delay
                        || ip.cancel_set_id != vp.cancel_set_id
                        || ip.set_id != vp.set_id
                        || ip.owner != vp.owner
                        || ip.tag != vp.tag
                    {
                        return Err(bad("bad-txns-vault-intent"));
                    }
                    total += o.value;
                } else if o.script_pubkey == t.coin.script {
                    relock = true;
                    total += o.value;
                }
            }
            if total < t.coin.value || (total > t.coin.value && relock) {
                return Err(bad("bad-txns-vault-unlock-value"));
            }
        }
        let _ = node;
        Ok(())
    }

    /// `set_signunlock` / `set_signcancel` (`SignSetInPlace`).
    async fn set_sign_template(
        &mut self,
        node: &dyn Node,
        p: &[Value],
        role: u8,
    ) -> Result<J, RpcError> {
        want_params(
            p,
            1,
            2,
            if role == ROLE_UNLOCK {
                "set_signunlock \"hex\" ( {\"acknowledgerestore\": true} )"
            } else {
                "set_signcancel \"hex\" ( {\"acknowledgerestore\": true} )"
            },
        )?;
        let mut tx = decode_tx_param(&p[0])?;
        let ack = match param(p, 1) {
            None => false,
            Some(o) if !o.is_object() => return Err(invalid("options must be an object")),
            Some(o) => match o.get("acknowledgerestore") {
                None | Some(Value::Null) => false,
                Some(Value::Bool(b)) => *b,
                Some(_) => return Err(invalid("acknowledgerestore must be a boolean")),
            },
        };
        let t = self.find_template(node, &tx).await?;
        let set = match (role, &t.vault, &t.intent) {
            (ROLE_UNLOCK, Some(v), _) => v.set_id,
            (ROLE_UNLOCK, None, _) => return Err(invalid("the template input is not a vault")),
            (_, _, Some(i)) => i.cancel_set_id,
            _ => return Err(invalid("the template input is not an intent")),
        };
        let next = next_block(node).await?;
        let s = set_view(node, &set).await?.ok_or_else(|| {
            RpcError::new(
                code::INVALID_ADDRESS_OR_KEY,
                format!("unknown set {}", txid_hex(&set)),
            )
        })?;
        let k = s.threshold(role);
        let idx = t.idx;
        let sighash = sighash_set(&tx, idx, &t.coin, next.branch)?;
        let prevout = act::OutPoint::from(tx.vin[idx].prevout);
        let msg = act::set_sig_msg(&set, role, &prevout, &sighash);
        let kind = if t.vault.is_some() {
            yv::Kind::Vault
        } else {
            yv::Kind::Intent
        };
        let mut sigs: Vec<[u8; 65]> = Vec::new();
        if !tx.vin[idx].script_sig.is_empty() {
            let (sel, pushes) = yv::parse_selector(kind, &tx.vin[idx].script_sig)
                .ok_or_else(|| invalid("the template input's scriptSig is for another branch"))?;
            if sel != role {
                return Err(invalid(
                    "the template input's scriptSig is for another branch",
                ));
            }
            for p in pushes {
                sigs.push(p.try_into().map_err(|_| {
                    invalid("an existing set signature does not verify (the transaction changed?)")
                })?);
            }
        }
        let mut have: Vec<[u8; 33]> = Vec::new();
        for sig in &sigs {
            let key = act::recover(&msg, sig).ok_or_else(|| {
                invalid("an existing set signature does not verify (the transaction changed?)")
            })?;
            if !s.is_current(&key) || have.contains(&key) {
                return Err(invalid(format!("set-sign-invalid: an existing signature is not by a distinct current member of {}", txid_hex(&set))));
            }
            have.push(key);
        }
        self.validate_set_spend(node, &tx, &t, role, next).await?;
        let mut keys = Vec::new();
        let mut adding = Vec::new();
        for m in &s.members {
            if (sigs.len() + adding.len()) as i64 >= k {
                break;
            }
            if !m.current || have.contains(&m.key) {
                continue;
            }
            if let Some(r) = self.key_of_pubkey(&m.key) {
                keys.push(r);
                adding.push(m.key);
            }
        }
        // the signer checks (and writes) its sign-once record whenever this wallet holds a member key
        let holds_member = s
            .members
            .iter()
            .any(|m| self.key_of_pubkey(&m.key).is_some());
        if holds_member {
            let req = yewd_proto::SetSignRequest {
                tx: tx_hex(&tx)?,
                branch_id: next.branch,
                index: idx as u32,
                prevout: yewd_proto::Prevout {
                    outpoint: op_str(&tx.vin[idx].prevout),
                    script: hex::encode(&t.coin.script),
                    amount_zat: t.coin.value,
                },
                set_id: txid_hex(&set),
                role,
                keys,
                acknowledge_restore: ack,
            };
            let r = match self.signer.request(Request::SignSet(req)) {
                Ok(Response::SetSigs(r)) => r,
                other => {
                    let e = signer_error(other);
                    // ycashd's codes: a record conflict and the restore marker are wallet errors (-4)
                    return Err(e);
                }
            };
            if r.sighash != hex::encode(sighash) {
                return Err(RpcError::new(
                    code::INTERNAL_ERROR,
                    "the signer computed another sighash",
                ));
            }
            for sg in r.sigs {
                sigs.push(
                    hex::decode(&sg)
                        .ok()
                        .and_then(|b| b.try_into().ok())
                        .ok_or_else(|| RpcError::new(code::WALLET_ERROR, "signing failed"))?,
                );
            }
            have.extend(adding);
        }
        let mut ss = Vec::new();
        for sig in &sigs {
            yew_core::script::push_data(&mut ss, sig);
        }
        ss.push(if role == ROLE_UNLOCK {
            yew_core::script::op::OP_1
        } else {
            yew_core::script::op::OP_1 + 1
        });
        tx.vin[idx].script_sig = ss;
        Ok(J::obj()
            .with("hex", tx_hex(&tx)?)
            .with("complete", sigs.len() as i64 == k)
            .with("signatures", sigs.len())
            .with("required", k)
            .with("sighash", hex::encode(sighash))
            .with(
                "setsigs",
                J::Arr(
                    have.iter()
                        .zip(&sigs)
                        .map(|(k, s)| {
                            J::obj()
                                .with("key", hex::encode(k))
                                .with("sig", hex::encode(s))
                        })
                        .collect(),
                ),
            ))
    }

    /// An intent's originating vault script and its coin height (`BuildIntentCancel`).
    async fn intent_origin(
        &self,
        node: &dyn Node,
        op: &OutPoint,
        coin: &NodeCoin,
        ip: &IntentParams,
        next: Next,
    ) -> Result<(Vec<u8>, i64, bool), RpcError> {
        if let Some(h) = coin.height {
            let rows = node::call(
                node,
                "vault_list",
                serde_json::json!([{"kind": "intent", "setid": txid_hex(&ip.set_id)}]),
            )
            .await?;
            let want = op_str(op);
            let origin = rows
                .as_array()
                .and_then(|a| {
                    a.iter()
                        .find(|r| r["outpoint"].as_str() == Some(want.as_str()))
                })
                .and_then(|r| r["origin"].as_str())
                .and_then(|s| hex::decode(s).ok())
                .filter(|o| !o.is_empty())
                .ok_or_else(|| {
                    RpcError::new(
                        code::INTERNAL_ERROR,
                        "the intent's originating vault script is missing from the vault database",
                    )
                })?;
            return Ok((origin, h as i64, true));
        }
        let parent = match node::call(
            node,
            "getrawtransaction",
            serde_json::json!([txid_hex(&op.txid), 0]),
        )
        .await
        {
            Ok(v) => v.as_str().and_then(crate::build::parse_hex_tx),
            Err(_) => None,
        }
        .ok_or_else(|| invalid("not an unspent intent output"))?;
        for i in &parent.vin {
            if let Some(vc) = node_coin(node, &i.prevout).await? {
                if yv::parse_vault(&vc.script).is_some()
                    && yew_core::keys::sha256(&vc.script) == ip.vault_hash
                {
                    return Ok((vc.script, next.height as i64, false));
                }
            }
        }
        Err(invalid(
            "the mempool intent's originating vault is not among its transaction's inputs",
        ))
    }

    /// `BuildIntentCancel` (vault_buildcancel; `yed_buildcancel` passes `extra` and `yed`).
    pub(crate) async fn build_intent_cancel(
        &mut self,
        node: &dyn Node,
        op: &OutPoint,
        extra: &[TxOut],
        yed_allowed: bool,
        rebuild: bool,
        build_fields: bool,
    ) -> Result<J, RpcError> {
        let next = self.ensure_vault_active(node).await?;
        let coin = node_coin(node, op).await?;
        let (coin, ip) = match coin
            .as_ref()
            .and_then(|c| yv::parse_intent(&c.script).map(|i| (c.clone(), i)))
        {
            Some(x) => x,
            None => return Err(invalid("not an unspent intent output")),
        };
        if !yed_allowed && ip.tag == yv::YED_TAG {
            return Err(invalid("a YED claim intent is cancelled with yed_buildcancel (its cancel refunds the claim's burn, CAN-1)"));
        }
        let (origin, coin_height, confirmed) =
            self.intent_origin(node, op, &coin, &ip, next).await?;
        if next.height as i64 - coin_height >= ip.delay {
            return Err(RpcError::new(
                code::MISC_ERROR,
                format!(
                    "the intent matured at height {}; it can no longer be cancelled",
                    coin_height + ip.delay
                ),
            ));
        }
        self.prune_builds(node).await?;
        let mut build = "new";
        let mut tx = new_tx();
        let mut keep_signed = false;
        if let Some(c) = self.build_of(op) {
            let differs = rebuild
                || c.vin.is_empty()
                || c.vin[0].prevout != *op
                || c.vout.len() <= extra.len()
                || c.vout[0].script_pubkey != origin
                || c.vout[0].value != coin.value
                || c.vout[1..1 + extra.len()] != extra[..];
            if differs {
                keep_signed = self.wallet_signed_prevout(op);
                if !keep_signed {
                    self.unlock_build_inputs(op, &c);
                }
            } else {
                tx = c;
                build = "reused";
                if !self.fee_inputs_unspent(node, op, &tx).await? {
                    self.refee(node, &mut tx, 0, &coin).await?;
                    build = "refunded";
                }
            }
        }
        if build == "new" {
            tx = new_tx();
            tx.vin.push(TxIn::new(*op));
            tx.vout.push(TxOut {
                value: coin.value,
                script_pubkey: origin.clone(),
            });
            tx.vout.extend(extra.iter().cloned());
            self.fund(
                node,
                &mut tx,
                coin.value,
                VAULT_RPC_FEE,
                FundMode::SmallChange,
            )
            .await?;
        }
        if !keep_signed {
            self.remember_build(op, &tx)?;
        }
        let sighash = sighash_set(&tx, 0, &coin, next.branch)?;
        let required = set_view(node, &ip.cancel_set_id)
            .await?
            .map(|s| s.cancel_threshold)
            .unwrap_or(0);
        let mut o = J::obj()
            .with("hex", tx_hex(&tx)?)
            .with("required", required)
            .with("cancelsetid", txid_hex(&ip.cancel_set_id))
            .with("deadline", coin_height + ip.delay - 1)
            .with("intentconfirmed", confirmed);
        if build_fields {
            o.push("sighash", J::Str(hex::encode(sighash)));
            o.push("build", J::Str(build.into()));
        }
        Ok(o)
    }

    async fn vault_buildcancel(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        want_params(p, 1, 2, "vault_buildcancel \"intentoutpoint\" ( rebuild )")?;
        let rebuild = param(p, 1).and_then(|v| v.as_bool()).unwrap_or(false);
        let op = outpoint_param(&p[0], "intentoutpoint")?;
        self.build_intent_cancel(node, &op, &[], false, rebuild, true)
            .await
    }

    async fn vault_refee(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        want_params(p, 1, 1, "vault_refee \"hex\"")?;
        let next = self.ensure_vault_active(node).await?;
        let mut tx = decode_tx_param(&p[0])?;
        let t = self.find_template(node, &tx).await?;
        let templ = tx.vin[t.idx].prevout;
        self.prune_builds(node).await?;
        let replaced = self.refee(node, &mut tx, t.idx, &t.coin).await?;
        let memo = self.build_of(&templ);
        if memo.as_ref().is_none_or(|m| m.vout == tx.vout) || !self.wallet_signed_prevout(&templ) {
            self.remember_build(&templ, &tx)?;
        }
        let mut input = t.coin.value;
        for i in tx.vin.iter().skip(1) {
            if let Some(c) = node_coin(node, &i.prevout).await? {
                input += c.value;
            }
        }
        let sighash = sighash_set(&tx, 0, &t.coin, next.branch)?;
        Ok(J::obj()
            .with("hex", tx_hex(&tx)?)
            .with("sighash", hex::encode(sighash))
            .with("fee", J::Amount(input - tx.output_total()))
            .with(
                "replaced",
                J::Arr(replaced.iter().map(|o| J::Str(op_str(o))).collect()),
            ))
    }

    fn set_importsigned(&mut self, p: &[Value]) -> Result<J, RpcError> {
        want_params(
            p,
            1,
            1,
            "set_importsigned [{\"setid\", \"prevout\", \"role\", \"sighash\"}, ...]",
        )?;
        let arr = p[0]
            .as_array()
            .ok_or_else(|| RpcError::new(code::TYPE_ERROR, "Expected type array"))?;
        let mut recs = Vec::new();
        for o in arr {
            if !o.is_object() {
                return Err(RpcError::new(code::TYPE_ERROR, "Expected type object"));
            }
            let set = hash_param(field(o, "setid"), "setid")?;
            let prevout = outpoint_param(field(o, "prevout"), "prevout")?;
            let role = field(o, "role")
                .as_i64()
                .filter(|r| *r == 1 || *r == 2)
                .ok_or_else(|| invalid("role must be 1 (unlock) or 2 (cancel)"))?;
            let sighash = raw32_param(field(o, "sighash"), "sighash")?;
            recs.push(SignedRecord {
                setid: txid_hex(&set),
                prevout: op_str(&prevout),
                role: role as u8,
                sighash: hex::encode(sighash),
            });
        }
        match self.signer.request(Request::ImportSigned(recs)) {
            Ok(Response::Imported(i)) => Ok(J::obj()
                .with("imported", i.imported as i64)
                .with("present", i.present as i64)),
            other => Err(signer_error(other)),
        }
    }

    fn set_acknowledgerestore(&mut self, p: &[Value]) -> Result<J, RpcError> {
        want_params(p, 0, 0, "set_acknowledgerestore")?;
        match self.signer.request(Request::AcknowledgeRestore) {
            Ok(Response::Acknowledged(r)) => Ok(J::obj()
                .with("restored", r.restored)
                .with("pendingkeys", 0i64)),
            other => Err(signer_error(other)),
        }
    }

    async fn vault_send(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        want_params(
            p,
            1,
            2,
            "vault_send \"hex\" ( {\"dryrun\", \"allowinputs\", \"allowoutflow\"} )",
        )?;
        self.prune_builds(node).await?;
        let tx = decode_tx_param(&p[0])?;
        let t = self.find_template(node, &tx).await?;
        let kind = if t.vault.is_some() {
            yv::Kind::Vault
        } else {
            yv::Kind::Intent
        };
        let sel = yv::parse_selector(kind, &tx.vin[t.idx].script_sig)
            .map(|(s, _)| J::Int(s as i64))
            .unwrap_or(J::Null);
        let templ = J::obj()
            .with("outpoint", op_str(&tx.vin[t.idx].prevout))
            .with("kind", if t.vault.is_some() { "vault" } else { "intent" })
            .with("selector", sel);
        let opt = handoff_options(p)?;
        let key = tx.vin[t.idx].prevout;
        self.handoff_send(node, tx, &key, &opt, templ).await
    }

    /// `KeyIO::DecodeDestination` for an address argument.
    fn destination(&self, s: &str) -> Option<Vec<u8>> {
        crate::rpc::parse_taddr_script(self.network, s)
    }

    async fn vault_release(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        want_params(
            p,
            1,
            2,
            "vault_release \"intentoutpoint\" ( \"address\"|\"script\" )",
        )?;
        let next = self.ensure_vault_active(node).await?;
        let op = outpoint_param(&p[0], "intentoutpoint")?;
        let coin = node_coin(node, &op).await?;
        let (coin, ip) = match coin
            .as_ref()
            .and_then(|c| yv::parse_intent(&c.script).map(|i| (c.clone(), i)))
        {
            Some(x) => x,
            None => return Err(invalid("not an unspent intent output")),
        };
        match coin.height {
            None => {
                return Err(RpcError::new(
                    code::MISC_ERROR,
                    "the intent is not confirmed",
                ))
            }
            Some(h) if h as i64 + ip.delay > next.height as i64 => {
                return Err(RpcError::new(
                    code::MISC_ERROR,
                    format!("the intent matures at height {}", h as i64 + ip.delay),
                ))
            }
            Some(_) => {}
        }
        let dest: Option<Vec<u8>> = if let Some(a) = param(p, 1).and_then(|v| v.as_str()) {
            let d = if let Some(d) = self.destination(a) {
                d
            } else if !a.is_empty() && a.len() % 2 == 0 && a.chars().all(|c| c.is_ascii_hexdigit())
            {
                hex::decode(a).expect("hex")
            } else {
                return Err(RpcError::new(
                    code::INVALID_ADDRESS_OR_KEY,
                    format!("not an address or a script: {a}"),
                ));
            };
            if yew_core::keys::sha256(&d) != ip.recipient_hash
                && a.len() == 66
                && yew_core::pq::is_known_scheme(d[0])
            {
                return Err(invalid(
                    "that looks like a pqkeyid: pass the address or the script, not a pqkeyid",
                ));
            }
            Some(d)
        } else if let Some(s) = self.st.recipients.get(&hex::encode(ip.recipient_hash)) {
            hex::decode(s).ok()
        } else {
            let mut found = None;
            for k in &self.book.tkeys {
                let s = yew_core::script::p2pkh_script(&k.hash);
                if yew_core::keys::sha256(&s) == ip.recipient_hash {
                    found = Some(s);
                    break;
                }
            }
            if found.is_none() {
                for k in self.book.pq.values() {
                    if let Some(s) = yew_core::pq::pqpkh_script(&k.id) {
                        if yew_core::keys::sha256(&s) == ip.recipient_hash {
                            found = Some(s);
                            break;
                        }
                    }
                }
            }
            found
        };
        let dest = dest.ok_or_else(|| invalid("the recipient script is unknown here; pass it"))?;
        if yew_core::keys::sha256(&dest) != ip.recipient_hash {
            return Err(invalid("that script is not the intent's recipient"));
        }
        let mut tx = new_tx();
        let mut vin = TxIn::new(op);
        vin.script_sig = yv::intent_release_script_sig();
        vin.sequence = ip.delay as u32;
        tx.vin.push(vin);
        tx.vout.push(TxOut {
            value: coin.value,
            script_pubkey: dest,
        });
        self.fund(
            node,
            &mut tx,
            coin.value,
            VAULT_RPC_FEE,
            FundMode::LargestFirst,
        )
        .await?;
        Ok(J::Str(self.sign_send(node, &tx, next, 0).await?))
    }

    /// The owner spend's network fee: max(the flat fee, the ZIP-317 conventional fee, the
    /// vault/Yellowback rate × size) capped at the cap, never below the conventional fee; clamped
    /// to the floor for a small vault (`ClampOwnerNetworkFee`).
    async fn owner_fee(
        &self,
        node: &dyn Node,
        size: usize,
        conventional: i64,
        value: i64,
        dust: i64,
    ) -> i64 {
        let info = node::call(node, "yed_getinfo", serde_json::json!([]))
            .await
            .ok();
        let net = info.as_ref().map(|v| &v["params"]["fees"]["network"]);
        // without a live Yellowback (no yed_getinfo) ycashd's YedFeeRate() is -pqfeerate, by default
        // the relay floor (DEFAULT_MIN_RELAY_TX_FEE, 100 zat/kB); its floor rate (YedFloorSizeFee) is
        // max(floorZatPerKB, -pqfeerate) with a price and -pqfeerate without one (vault_pq_wallet.py)
        const RELAY_FLOOR: i64 = 100;
        let fallback = net
            .and_then(|n| n["fallbackZatPerKB"].as_i64())
            .unwrap_or(RELAY_FLOOR);
        let priced_now = net.is_some_and(|n| !n["priceMicroUsd"].is_null());
        let rate = net
            .and_then(|n| n["yellowback"]["zatPerKB"].as_i64())
            .unwrap_or(fallback);
        let floor_rate = if priced_now {
            net.and_then(|n| n["floorZatPerKB"].as_i64())
                .unwrap_or(5_000)
                .max(fallback)
        } else {
            fallback
        };
        let cap = net
            .and_then(|n| n["yellowback"]["maxTxFeeZat"].as_i64())
            .unwrap_or(crate::build::DEFAULT_MAX_TX_FEE);
        let per = |r: i64| (r * size as i64 + 999) / 1000;
        let floor_fee = VAULT_RPC_FEE.max(per(floor_rate)).max(conventional);
        let priced = VAULT_RPC_FEE.max(per(rate)).min(cap).max(conventional);
        if value - priced < dust.max(1) {
            floor_fee
        } else {
            priced
        }
    }

    async fn vault_ownerspend(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        want_params(p, 2, 2, "vault_ownerspend \"outpoint\" \"address\"")?;
        let next = self.ensure_vault_active(node).await?;
        let op = outpoint_param(&p[0], "outpoint")?;
        let coin = node_coin(node, &op)
            .await?
            .ok_or_else(|| invalid("not an unspent output"))?;
        let addr = p[1].as_str().unwrap_or("");
        let dest = self.destination(addr).ok_or_else(|| {
            RpcError::new(code::INVALID_ADDRESS_OR_KEY, "invalid transparent address")
        })?;
        let mut tx = new_tx();
        let mut seq = yew_core::params::SEQUENCE_FINAL;
        let (owner, selector) = if let Some(vp) = yv::parse_vault(&coin.script) {
            if next.height as i64 > vp.owner_height {
                tx.lock_time = vp.owner_height as u32;
                seq = yew_core::params::SEQUENCE_FINAL - 1;
                (vp.owner, yv::SEL_OWNER)
            } else if set_view(node, &vp.set_id)
                .await?
                .is_some_and(|s| s.released)
            {
                (vp.owner, yv::SEL_RELEASED)
            } else {
                return Err(RpcError::new(
                    code::MISC_ERROR,
                    format!(
                        "the owner branch opens at height {} and the set is not released",
                        vp.owner_height + 1
                    ),
                ));
            }
        } else if let Some(ip) = yv::parse_intent(&coin.script) {
            if !set_view(node, &ip.set_id)
                .await?
                .is_some_and(|s| s.released)
            {
                return Err(RpcError::new(
                    code::MISC_ERROR,
                    "the intent's set is not released",
                ));
            }
            (ip.owner, yv::SEL_RELEASED)
        } else {
            return Err(invalid("not a vault or intent output"));
        };
        if coin.value <= VAULT_RPC_FEE {
            return Err(invalid("the output does not cover the fee"));
        }
        let key = self.owner_ref(&owner, selector).ok_or_else(|| {
            RpcError::new(
                code::WALLET_ERROR,
                format!(
                    "owner {} is not a post-quantum key of this wallet",
                    pqkeyid_hex(&owner)
                ),
            )
        })?;
        let mut vin = TxIn::new(op);
        vin.sequence = seq;
        tx.vin.push(vin);
        tx.vout.push(TxOut {
            value: coin.value - VAULT_RPC_FEE,
            script_pubkey: dest.clone(),
        });
        // GetDustThreshold at the default relay fee (100 zat/kB): 3 x 100 x (size + 148) / 1000
        let dust = 3 * 100 * (8 + 1 + dest.len() as i64 + 148) / 1000;
        let cap = self.max_tx_fee(node).await;
        let mut fee = VAULT_RPC_FEE;
        let mut signed = tx.clone();
        for _ in 0..3 {
            if coin.value - fee < dust.max(1) {
                return Err(invalid(format!(
                    "the output does not cover the fee {} and a non-dust output",
                    money(fee)
                )));
            }
            tx.vout[0].value = coin.value - fee;
            signed = self
                .sign_inputs(
                    &tx,
                    std::slice::from_ref(&coin),
                    &[key],
                    &[],
                    GatePath::Owner,
                    coin.value,
                    next.branch,
                )
                .await?;
            let size = signed.serialize().map(|b| b.len()).unwrap_or(0);
            let sizes: Vec<usize> = signed.vin.iter().map(|i| i.script_sig.len()).collect();
            let conventional = signed
                .zip317_conventional_fee(&sizes)
                .unwrap_or(VAULT_RPC_FEE);
            let sized = self
                .owner_fee(node, size, conventional, coin.value, dust)
                .await;
            if sized == fee {
                break;
            }
            fee = sized;
        }
        let txid = self.broadcast(node, &signed, Some(cap.max(fee))).await?;
        Ok(J::obj()
            .with("txid", txid)
            .with("selector", selector as i64))
    }

    async fn vault_app(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        want_params(
            p,
            1,
            2,
            "vault_app \"outpoint\" ( [{\"address\"|\"script\", \"amount\"}, ...] )",
        )?;
        let next = self.ensure_vault_active(node).await?;
        let op = outpoint_param(&p[0], "outpoint")?;
        let coin = node_coin(node, &op).await?;
        let (coin, vp) = match coin
            .as_ref()
            .and_then(|c| yv::parse_vault(&c.script).map(|v| (c.clone(), v)))
        {
            Some(x) => x,
            None => return Err(invalid("not an unspent vault output")),
        };
        if vp.app_height == 0 {
            return Err(invalid("the vault has no APP branch (appheight 0, S-4)"));
        }
        if next.height as i64 <= vp.app_height {
            return Err(RpcError::new(
                code::MISC_ERROR,
                format!("the APP branch opens at height {}", vp.app_height + 1),
            ));
        }
        let mut tx = new_tx();
        tx.lock_time = vp.app_height as u32;
        let mut vin = TxIn::new(op);
        vin.script_sig = yv::vault_app_script_sig();
        vin.sequence = yew_core::params::SEQUENCE_FINAL - 1;
        tx.vin.push(vin);
        let empty = Value::Array(vec![]);
        let intents = self.add_intents(&mut tx, &vp, &coin, param(p, 1).unwrap_or(&empty))?;
        self.fund(
            node,
            &mut tx,
            coin.value,
            VAULT_RPC_FEE,
            FundMode::LargestFirst,
        )
        .await?;
        if let Some(prev) = self.build_of(&op) {
            let app = !prev.vin.is_empty()
                && prev.vin[0].prevout == op
                && prev.vin[0].sequence != yew_core::params::SEQUENCE_FINAL;
            if !app {
                let t = tx.clone();
                self.unlock_build_inputs(&op, &t);
                self.persist_state()?;
                return Err(invalid(
                    "this wallet already built a different spend of this vault",
                ));
            }
            if prev.vout != tx.vout {
                self.unlock_build_inputs(&op, &prev);
            }
        }
        self.remember_build(&op, &tx)?;
        Ok(J::obj().with("hex", tx_hex(&tx)?).with("intents", intents))
    }
}
