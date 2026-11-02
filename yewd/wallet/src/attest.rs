// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The roles' wallet RPCs (workspace plan §3b S3): the attestor (`yed_registerattestor`,
//! `yed_signattestation`, `yed_revive`, `yed_withdrawbond`, `yed_reportequivocation`), the cancel
//! co-signer (`yed_signcancelcosign`, `yed_buildcancel`), and the stock key RPCs the roles call
//! (`signmessage` for the attestor agent's endpoint binding, `importprivkey` / `dumpprivkey` for
//! the attestor wallets of the role scripts and a Hawkeye member).
//!
//! The sources are ycash6 `src/rpc/yellowbackwallet.cpp` (the RPCs, `CancelTargetOf`,
//! `CurrentMember`, `CompleteEquivocation`), `src/yellowback/txbuilder.cpp`
//! (`SignAttestationGuarded`, `BuildRevive`, `BuildWithdrawBond`, `CheckEquivocation`,
//! `BuildEquivocation`) and `src/wallet/rpcwallet.cpp` / `rpcdump.cpp` at the revision `yewd/PIN`
//! names. What ycashd reads in-process from its index the façade reads from the node:
//! `yed_listattestors` (the Attestors records), `set_getinfo` of the attestor set (its maturity),
//! `yed_getvault` (a claim's vault, its intents, `refundHolder`, `cancelsRequired`),
//! `getblockhash` (the cited block), `yed_listtokens` (a mempool claim's YED inputs). Every
//! signature, and the equivocation guard, are the signer's (K-24).

use base64::Engine;
use serde_json::Value;
use yew_core::bundle::{self, Attestation};
use yew_core::params::{CARRIER_VALUE, TOKEN_VALUE};
use yew_core::payload::{self, PayloadType};
use yew_core::tx::{OutPoint, Transaction, TxIn, TxOut};
use yewd_proto::attest as pa;
use yewd_proto::{
    AttestRequest, CosignRequest, GatePath, ImportKeyRequest, KeyRef, MessageRequest, Request,
    Response,
};

use crate::build::{next_block, node_coin, op_str, outpoint_param, signer_error, tx_hex, NodeCoin};
use crate::json::J;
use crate::keys::IMPORTED;
use crate::mint::build_error;
use crate::node::{self, Node};
use crate::rpc::{invalid, param};
use crate::{code, txid_hex, RpcError, Wallet};

pub const SERVED: &[&str] = &[
    "yed_registerattestor",
    "yed_withdrawbond",
    "yed_revive",
    "yed_reportequivocation",
    "yed_signattestation",
    "yed_signcancelcosign",
    "yed_buildcancel",
    "signmessage",
    "importprivkey",
    "dumpprivkey",
];

/// `CANCEL_COSIGN` (payload type 0x09, empty body): the cancel's marker output.
const CANCEL_COSIGN_TYPE: u8 = 0x09;
/// `LOCKTIME_THRESHOLD`.
const LOCKTIME_THRESHOLD: i64 = 500_000_000;
/// `CTxIn::SEQUENCE_FINAL - 1`: the bond's CLTV path needs a non-final input.
const SEQUENCE_CLTV: u32 = 0xffff_fffe;
/// How long `wait = true` waits for an equivocation report's carrier (as `yed_mint`'s).
const CARRIER_WAIT_SECS: u64 = 300;

/// One Attestors record (`yed_listattestors`).
#[derive(Clone, Debug)]
pub(crate) struct AttRec {
    pub seq: u16,
    pub pubkey: [u8; 33],
    pub status: String,
    pub bond_outpoint: Option<OutPoint>,
    pub bond_zat: i64,
    pub bond_locktime: u32,
    pub status_height: i64,
    pub register_height: i64,
    pub bond_spent: bool,
    pub frozen: bool,
}

pub(crate) async fn attestors(node: &dyn Node) -> Result<Vec<AttRec>, RpcError> {
    let v = node::call(node, "yed_listattestors", serde_json::json!([])).await?;
    let mut out = Vec::new();
    for r in v.as_array().cloned().unwrap_or_default() {
        let Some(pubkey) = r["attestorPubKey"]
            .as_str()
            .and_then(|s| hex::decode(s).ok())
            .and_then(|b| <[u8; 33]>::try_from(b).ok())
        else {
            continue;
        };
        let bond_outpoint = match (
            r["bondOutpoint"]["txid"].as_str(),
            r["bondOutpoint"]["vout"].as_u64(),
        ) {
            (Some(t), Some(n)) => yew_core::tx::txid_from_hex(t)
                .ok()
                .map(|txid| OutPoint { txid, n: n as u32 }),
            _ => None,
        };
        out.push(AttRec {
            seq: r["seq"].as_u64().unwrap_or(0) as u16,
            pubkey,
            status: r["status"].as_str().unwrap_or("").to_string(),
            bond_outpoint,
            bond_zat: r["bondZat"].as_i64().unwrap_or(0),
            bond_locktime: r["bondLocktime"].as_u64().unwrap_or(0) as u32,
            status_height: r["statusHeight"].as_i64().unwrap_or(0),
            register_height: r["registerHeight"].as_i64().unwrap_or(0),
            bond_spent: !r["bondSpentHeight"].is_null(),
            frozen: r["bondFrozen"].as_bool().unwrap_or(false),
        });
    }
    Ok(out)
}

/// What the role RPCs read of `yed_getinfo`.
struct RoleInfo {
    index_height: i64,
    ref_lag: i64,
    start_height: i64,
    set_id: [u8; 32],
    set_id_hex: String,
    claim_threshold_bps: i64,
    bond_min: i64,
    bond_min_cap: i64,
    bond_min_lock: i64,
    bond_maturity: i64,
}

async fn role_info(node: &dyn Node) -> Result<RoleInfo, RpcError> {
    let v = node::call(node, "yed_getinfo", serde_json::json!([])).await?;
    let p = &v["params"];
    let set_id_hex = p["attestorSetId"].as_str().unwrap_or("").to_string();
    let set_id = yew_core::tx::txid_from_hex(&set_id_hex).unwrap_or([0u8; 32]);
    Ok(RoleInfo {
        index_height: v["height"].as_i64().unwrap_or(0),
        ref_lag: p["refLag"].as_i64().unwrap_or(2),
        start_height: p["startHeight"].as_i64().unwrap_or(0),
        set_id,
        set_id_hex,
        claim_threshold_bps: p["claimThresholdBps"].as_i64().unwrap_or(0),
        bond_min: p["attest"]["bondMinZat"].as_i64().unwrap_or(0),
        bond_min_cap: p["attest"]["bondMinCapZat"].as_i64().unwrap_or(0),
        bond_min_lock: p["attest"]["bondMinLock"].as_i64().unwrap_or(0),
        bond_maturity: p["attest"]["bondMaturity"].as_i64().unwrap_or(0),
    })
}

/// `UniValue::get_int` / `get_int64`: an integer, or ycashd's type error.
fn get_int(p: &[Value], i: usize) -> Result<i64, RpcError> {
    p.get(i)
        .and_then(|v| v.as_i64())
        .ok_or_else(|| RpcError::new(code::MISC_ERROR, "JSON value is not an integer as expected"))
}

fn seq_param(p: &[Value], i: usize) -> Result<u16, RpcError> {
    let s = get_int(p, i)?;
    if !(0..=65535).contains(&s) {
        return Err(invalid("seq must be a u16"));
    }
    Ok(s as u16)
}

/// `"txid:n"` (`yed_signcancelcosign`, `yed_buildcancel`).
fn intent_param(v: &Value) -> Result<OutPoint, RpcError> {
    let bad = || invalid("intentoutpoint must be \"txid:n\"");
    let s = v.as_str().ok_or_else(bad)?;
    let (t, n) = s.split_once(':').ok_or_else(bad)?;
    if t.is_empty() || n.is_empty() {
        return Err(bad());
    }
    let n: i64 = n.parse().map_err(|_| bad())?;
    if !(0..=i32::MAX as i64).contains(&n) {
        return Err(bad());
    }
    let txid = yew_core::tx::txid_from_hex(t).map_err(|_| {
        invalid(format!(
            "intentoutpoint must be hexadecimal string (not '{t}')"
        ))
    })?;
    Ok(OutPoint { txid, n: n as u32 })
}

/// `ParseAttestationArg`.
fn attestation_param(v: &Value, what: &str) -> Result<Attestation, RpcError> {
    let bad = || invalid(format!("attest-malformed: {what} is not 74 bytes of hex"));
    let b = v
        .as_str()
        .and_then(|s| hex::decode(s).ok())
        .ok_or_else(bad)?;
    Attestation::decode(&b).ok_or_else(bad)
}

/// `ParseWaitArg`.
fn wait_param(p: &[Value], i: usize) -> Result<bool, RpcError> {
    match param(p, i) {
        None => Ok(true),
        Some(Value::Bool(b)) => Ok(*b),
        Some(Value::String(s)) => Ok(s != "false" && s != "0"),
        Some(v) => v.as_i64().map(|n| n != 0).ok_or_else(|| {
            RpcError::new(code::MISC_ERROR, "JSON value is not an integer as expected")
        }),
    }
}

async fn block_hash(node: &dyn Node, h: i64) -> Result<String, RpcError> {
    let v = node::call(node, "getblockhash", serde_json::json!([h])).await?;
    Ok(v.as_str().unwrap_or("").to_string())
}

/// A refusal of the signer for a role request: its reason carries ycashd's text, classified as
/// `ThrowBuildError` does (the rule identifiers `-26`, the parameter ones `-8`, the rest `-4`).
fn role_error(e: Result<Response, String>) -> RpcError {
    match e {
        Ok(Response::Refused(r)) if r.reason.starts_with(&r.code) => build_error(r.reason),
        other => signer_error(other),
    }
}

/// The same, where ycashd throws the RPC's own `-8` (`yed_signcancelcosign`'s checks).
fn cosign_error(e: Result<Response, String>) -> RpcError {
    match e {
        Ok(Response::Refused(r)) if r.code == yewd_proto::refuse::GUARD_WRITE_FAILED => {
            RpcError::new(code::WALLET_ERROR, r.reason)
        }
        Ok(Response::Refused(r)) if r.reason.starts_with(&r.code) => {
            RpcError::new(code::INVALID_PARAMETER, r.reason)
        }
        other => signer_error(other),
    }
}

/// `CurrentMember`: the seq of `key` when it is a current member of the attestor set at `height`.
fn current_member(recs: &[AttRec], maturity: i64, key: &[u8; 33], height: i64) -> Option<u16> {
    let r = recs.iter().rev().find(|r| r.pubkey == *key)?;
    if r.status == "EJECTED" || r.status == "WITHDRAWN" || r.bond_spent || r.frozen {
        return None;
    }
    if height < r.register_height + maturity {
        return None;
    }
    Some(r.seq)
}

/// `CancelTarget`: the claim's refHeight and the vault record a cancel is judged against.
struct CancelTarget {
    ref_height: i64,
    vault: Value,
    confirmed: bool,
    /// The refund holder and the burn (`yed_buildcancel`).
    holder: Vec<u8>,
    cents: i64,
}

/// The `YB` payload's refHeight of a claim (`REDEEM`), from its bytes.
fn claim_ref_height(claim: &Transaction) -> Option<(i64, i64)> {
    let fp = payload::find_payload(claim)?;
    if fp.payload.payload_type() != PayloadType::Redeem {
        return None;
    }
    match &fp.payload {
        payload::Payload::Redeem { ref_height, .. } => {
            Some((*ref_height as i64, fp.payload.assigned_cents()))
        }
        _ => None,
    }
}

impl Wallet {
    pub async fn attest_call(
        &mut self,
        node: &dyn Node,
        method: &str,
        p: &[Value],
    ) -> Result<J, RpcError> {
        match method {
            "yed_registerattestor" => self.yed_registerattestor(node, p).await,
            "yed_withdrawbond" => self.yed_withdrawbond(node, p).await,
            "yed_revive" => self.yed_revive(node, p).await,
            "yed_reportequivocation" => self.yed_reportequivocation(node, p).await,
            "yed_signattestation" => self.yed_signattestation(node, p).await,
            "yed_signcancelcosign" => self.yed_signcancelcosign(node, p).await,
            "yed_buildcancel" => self.yed_buildcancel(node, p).await,
            "signmessage" => self.signmessage(p),
            "importprivkey" => self.importprivkey(node, p).await,
            "dumpprivkey" => self.dumpprivkey(p),
            _ => Err(RpcError::new(code::METHOD_NOT_FOUND, "Method not found")),
        }
    }

    // ------------------------------------------------------------------ attestor

    /// `yed_registerattestor bondYec lockBlocks ( flags )`: a `set_join` of a fresh wallet key to
    /// the attestor set.
    async fn yed_registerattestor(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        if p.len() < 2 || p.len() > 3 {
            return Err(RpcError::new(
                code::MISC_ERROR,
                "yed_registerattestor bondYec lockBlocks ( flags )",
            ));
        }
        let bond = crate::build::amount_param(&p[0])?;
        let lock_blocks = get_int(p, 1)?;
        let flags = match param(p, 2) {
            None => 0,
            Some(_) => get_int(p, 2)?,
        };
        if !(0..=255).contains(&flags) {
            return Err(invalid("flags must be a byte"));
        }
        let info = role_info(node).await?;
        if info.set_id == [0u8; 32] {
            return Err(RpcError::new(
                code::TRANSACTION_REJECTED,
                "yellowback-no-attestor-set: this network has no YED attestor set",
            ));
        }
        let money = crate::rpc::format_money;
        if bond < info.bond_min {
            return Err(RpcError::new(
                code::TRANSACTION_REJECTED,
                format!(
                    "bond-below-min: the bond must be at least {} YEC",
                    money(info.bond_min)
                ),
            ));
        }
        let mut warning = String::new();
        if bond < info.bond_min_cap && bond < info.bond_min + info.bond_min / 10 {
            warning = format!(
                "bond-near-min: {} YEC is within 10 % of the minimum for the next block ({} YEC); if YED vault collateral grows before the join confirms it becomes invalid and is not mined. Post at least {} YEC (+10 %), or {} YEC, which always qualifies",
                money(bond),
                money(info.bond_min),
                money(info.bond_min_cap.min(info.bond_min + info.bond_min / 10)),
                money(info.bond_min_cap)
            );
        }
        if lock_blocks < info.bond_min_lock {
            return Err(RpcError::new(
                code::TRANSACTION_REJECTED,
                format!(
                    "lock-below-min: the lock must be at least {} blocks",
                    info.bond_min_lock
                ),
            ));
        }
        let chain = node::block_count(node).await? as i64;
        let locktime = chain + 1 + lock_blocks;
        if locktime >= LOCKTIME_THRESHOLD {
            return Err(RpcError::new(
                code::TRANSACTION_REJECTED,
                "lock-below-min: bondLocktime reaches LOCKTIME_THRESHOLD",
            ));
        }
        let set_maturity = crate::vaultrpc::set_view(node, &info.set_id)
            .await?
            .map(|s| s.maturity)
            .unwrap_or(0);
        let matures_at = chain + 1 + set_maturity.max(info.bond_maturity);
        let joined = self
            .set_join(
                node,
                &[
                    Value::String(info.set_id_hex.clone()),
                    Value::String(crate::json::amount_text(bond)),
                    Value::from(locktime),
                ],
            )
            .await?;
        let jv: Value = serde_json::from_str(&joined.text())
            .map_err(|e| RpcError::new(code::INTERNAL_ERROR, e.to_string()))?;
        if jv["complete"].as_bool() != Some(true) {
            return Err(RpcError::new(
                code::WALLET_ERROR,
                format!(
                    "register-needs-admission: the attestor set is not open; collect the admission signatures with set_signact and send with set_sendact: {}",
                    jv["hex"].as_str().unwrap_or("")
                ),
            ));
        }
        let member_hex = jv["memberkey"].as_str().unwrap_or("").to_string();
        let member: [u8; 33] = hex::decode(&member_hex)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| RpcError::new(code::INTERNAL_ERROR, "set_join gave no member key"))?;
        let txid = jv["txid"].as_str().unwrap_or("").to_string();
        let bond_spk = yewd_proto::act::bond_script_pubkey(locktime as u32, &member);
        Ok(J::obj()
            .with("txid", txid.clone())
            .with("seq", J::Null)
            .with("attestorPubKey", member_hex)
            .with(
                "bondAddress",
                crate::keys::script_address(self.network, &bond_spk).unwrap_or_default(),
            )
            .with(
                "bondKeyAddress",
                yew_core::keys::encode_p2pkh(self.network, &yew_core::keys::hash160(&member)),
            )
            .with(
                "bondOutpoint",
                J::obj().with("txid", txid).with("vout", 0i64),
            )
            .with("bondZat", bond)
            .with("bondLocktime", locktime)
            .with("flags", J::obj().with("tier", 0i64).with("pool", false))
            .with("maturesAt", matures_at)
            .with("warning", warning))
    }

    /// `SignAttestationGuarded`'s checks before the signer: the record, the key, the range, the
    /// cited height; then the signer's guard.
    async fn guarded_attestation(
        &self,
        node: &dyn Node,
        recs: &[AttRec],
        info: &RoleInfo,
        seq: u16,
        price: i64,
        cited: i64,
    ) -> Result<(Attestation, bool, [u8; 33]), RpcError> {
        let rec = recs.iter().find(|r| r.seq == seq).ok_or_else(|| {
            build_error(format!("attest-unknown-seq: no attestor with seq {seq}"))
        })?;
        let key = self.key_of_pubkey(&rec.pubkey).ok_or_else(|| {
            build_error(format!(
                "attest-key-not-held: the hot key of seq {seq} is not in this wallet"
            ))
        })?;
        if !(pa::PRICE_MIN..=pa::PRICE_MAX).contains(&price) {
            return Err(build_error(format!(
                "attest-range: priceMicroUsd must be in [{}, {}]",
                pa::PRICE_MIN,
                pa::PRICE_MAX
            )));
        }
        let chain = node::block_count(node).await? as i64;
        if cited < info.start_height || cited > chain {
            return Err(build_error(format!(
                "attest-stale: citedHeight {cited} must be in [{}, {chain}]",
                info.start_height
            )));
        }
        let bh = block_hash(node, cited).await?;
        let r = self.signer.request(Request::SignAttestation(AttestRequest {
            key,
            pubkey: hex::encode(rec.pubkey),
            seq,
            price_micro_usd: price as u32,
            cited_height: cited as u32,
            block_hash: bh,
        }));
        match r {
            Ok(Response::Attestation(a)) => {
                let bytes = hex::decode(&a.hex)
                    .ok()
                    .and_then(|b| Attestation::decode(&b))
                    .ok_or_else(|| {
                        RpcError::new(
                            code::INTERNAL_ERROR,
                            "the signer's attestation does not decode",
                        )
                    })?;
                Ok((bytes, a.reused, rec.pubkey))
            }
            other => Err(role_error(other)),
        }
    }

    /// `yed_signattestation seq priceMicroUsd ( citedHeight )`.
    async fn yed_signattestation(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        if p.len() < 2 || p.len() > 3 {
            return Err(RpcError::new(
                code::MISC_ERROR,
                "yed_signattestation seq priceMicroUsd ( citedHeight )",
            ));
        }
        let seq = seq_param(p, 0)?;
        let price = get_int(p, 1)?;
        let info = role_info(node).await?;
        let cited = match param(p, 2) {
            None => info.index_height - info.ref_lag,
            Some(_) => get_int(p, 2)?,
        };
        let recs = attestors(node).await?;
        let (a, reused, _) = self
            .guarded_attestation(node, &recs, &info, seq, price, cited)
            .await?;
        Ok(J::obj()
            .with("hex", hex::encode(a.encode()))
            .with("seq", a.seq as i64)
            .with("priceMicroUsd", a.price_micro_usd as i64)
            .with("citedHeight", a.cited_height as i64)
            .with("reused", reused))
    }

    /// `yed_revive seq priceMicroUsd`: one guarded attestation at `tip − REF_LAG`, then a
    /// `SET_HEARTBEAT` of the member key to the attestor set.
    async fn yed_revive(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        if p.len() != 2 {
            return Err(RpcError::new(
                code::MISC_ERROR,
                "yed_revive seq priceMicroUsd",
            ));
        }
        let seq = seq_param(p, 0)?;
        let price = get_int(p, 1)?;
        let info = role_info(node).await?;
        let recs = attestors(node).await?;
        let rec = recs.iter().find(|r| r.seq == seq).ok_or_else(|| {
            build_error(format!("attest-unknown-seq: no attestor with seq {seq}"))
        })?;
        if rec.status != "DORMANT" {
            return Err(build_error(format!(
                "not-dormant: seq {seq} is {}",
                rec.status
            )));
        }
        if self.key_of_pubkey(&rec.pubkey).is_none() {
            return Err(build_error(format!(
                "attest-key-not-held: the hot key of seq {seq} is not in this wallet"
            )));
        }
        let cited = info.index_height - info.ref_lag;
        let (a, _, pk) = self
            .guarded_attestation(node, &recs, &info, seq, price, cited)
            .await?;
        let hb = self
            .set_heartbeat(
                node,
                &[
                    Value::String(info.set_id_hex.clone()),
                    Value::String(hex::encode(pk)),
                ],
            )
            .await?;
        let hv: Value = serde_json::from_str(&hb.text())
            .map_err(|e| RpcError::new(code::INTERNAL_ERROR, e.to_string()))?;
        Ok(J::obj()
            .with("txid", hv["txid"].as_str().unwrap_or("").to_string())
            .with("seq", seq as i64)
            .with("citedHeight", a.cited_height as i64)
            .with("priceMicroUsd", a.price_micro_usd as i64)
            .with("hex", hex::encode(a.encode())))
    }

    /// `yed_withdrawbond seq ( "to" )`: the bond's CLTV path, signed in the signer.
    async fn yed_withdrawbond(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        if p.is_empty() || p.len() > 2 {
            return Err(RpcError::new(
                code::MISC_ERROR,
                "yed_withdrawbond seq ( \"to\" )",
            ));
        }
        let seq = seq_param(p, 0)?;
        let to = match param(p, 1) {
            None => String::new(),
            Some(v) => v
                .as_str()
                .ok_or_else(|| {
                    RpcError::new(code::MISC_ERROR, "JSON value is not a string as expected")
                })?
                .to_string(),
        };
        // ParseAddressChoice: "" (a fresh key), a transparent address; a Sapling one is the
        // signer's Sapling build (F-S2-8)
        let dest: Option<Vec<u8>> = if to.is_empty() {
            None
        } else if let Some(s) = crate::rpc::parse_taddr_script(self.network, &to)
            .filter(|s| yew_core::script::p2pkh_hash(s).is_some())
        {
            Some(s)
        } else if to.starts_with("ys")
            || to.starts_with("zregtestsapling")
            || to.starts_with("ytestsapling")
            || to.starts_with("zs")
        {
            return Err(RpcError::new(
                code::WALLET_ERROR,
                "yewd: a bond withdrawal to a Sapling address is the signer's Sapling build (plan K-24, finding F-S2-8), not served yet; pass a transparent address or \"\"",
            ));
        } else {
            return Err(build_error(
                "bad-address: to: not a transparent (s1…) or Sapling (ys1…) address of this network".into(),
            ));
        };
        let info = crate::yed::yed_info(node).await?;
        let recs = attestors(node).await?;
        let rec = recs.iter().find(|r| r.seq == seq).cloned().ok_or_else(|| {
            build_error(format!("attest-unknown-seq: no attestor with seq {seq}"))
        })?;
        let (chain_ix, index) = match self.key_of_pubkey(&rec.pubkey) {
            Some(KeyRef::Bip32 { chain, index }) => (chain, index),
            _ => {
                return Err(build_error(format!(
                    "attest-key-not-held: the bond key of seq {seq} is not in this wallet"
                )))
            }
        };
        let bond_op = rec.bond_outpoint.ok_or_else(|| {
            build_error(format!(
                "bond-spent: the bond of seq {seq} is already spent"
            ))
        })?;
        let coin = node_coin(node, &bond_op).await?;
        if rec.bond_spent || coin.is_none() {
            return Err(build_error(format!(
                "bond-spent: the bond of seq {seq} is already spent"
            )));
        }
        let chain = node::block_count(node).await? as i64;
        if chain < rec.bond_locktime as i64 {
            return Err(build_error(format!(
                "bond-locked: the bond is locked until height {} (tip {chain})",
                rec.bond_locktime
            )));
        }
        if rec.frozen {
            return Err(build_error(format!(
                "bond-locked: the bond of seq {seq} is frozen (slashed)"
            )));
        }
        if rec.status != "WITHDRAWN" {
            return Err(build_error(format!(
                "bond-locked: seq {seq} is still a member ({}); leave the set first (set_leave)",
                rec.status
            )));
        }
        let role = role_info(node).await?;
        let maturity = crate::vaultrpc::set_view(node, &role.set_id)
            .await?
            .map(|s| s.maturity)
            .unwrap_or(0);
        let spendable_at = rec.status_height + maturity;
        if chain + 1 < spendable_at {
            return Err(build_error(format!(
                "bond-locked: the bond is returned at height {spendable_at} (left at {}; tip {chain})",
                rec.status_height
            )));
        }
        let redeem = yewd_proto::act::bond_redeem_script(rec.bond_locktime, &rec.pubkey);
        let dest_script = match dest {
            Some(s) => s,
            None => {
                let pk = self.new_wallet_key()?;
                let h = yew_core::keys::hash160(&pk);
                self.st.book.insert(
                    yew_core::keys::encode_p2pkh(self.network, &h),
                    crate::state::BookEntry {
                        label: String::new(),
                        purpose: "yellowback-bond-withdrawal".into(),
                    },
                );
                yew_core::script::p2pkh_script(&h)
            }
        };
        let mut tx = Transaction::new_v4();
        tx.lock_time = rec.bond_locktime;
        tx.expiry_height = (chain + info.ref_window) as u32;
        let mut i = TxIn::new(bond_op);
        i.sequence = SEQUENCE_CLTV;
        tx.vin.push(i);
        tx.vout.push(TxOut {
            value: 0,
            script_pubkey: dest_script.clone(),
        });
        // P-2: one bond input, one P2PKH output; the fee never moves the shape
        let ss_size = 1 + 73 + 1 + redeem.len();
        let fee = info.flat_fee.max(
            tx.zip317_conventional_fee(&[ss_size])
                .unwrap_or(info.flat_fee),
        );
        let out = rec.bond_zat - fee;
        if out <= 0 {
            return Err(build_error(
                "vault-value-too-small: the bond does not cover the network fee".into(),
            ));
        }
        tx.vout[0].value = out;
        let next = next_block(node).await?;
        let coin = coin.expect("checked");
        let key = KeyRef::Bond {
            chain: chain_ix,
            index,
            locktime: rec.bond_locktime,
        };
        let signed = self
            .sign_inputs(
                &tx,
                &[coin],
                &[key],
                &[],
                GatePath::Vault,
                rec.bond_zat,
                next.branch,
            )
            .await?;
        let txid = self.broadcast(node, &signed, None).await?;
        self.persist_state()?;
        Ok(J::obj()
            .with("txid", txid)
            .with("seq", seq as i64)
            .with("bondZat", rec.bond_zat)
            .with("bondOut", out)
            .with(
                "to",
                crate::keys::script_address(self.network, &dest_script).unwrap_or_default(),
            ))
    }

    /// `CheckEquivocation` (EQV-1's conditions, wallet side).
    async fn check_equivocation(
        &self,
        node: &dyn Node,
        a: &Attestation,
        b: &Attestation,
    ) -> Result<(), RpcError> {
        if a.seq != b.seq {
            return Err(build_error(format!(
                "not-equivocation: different seqs ({}, {})",
                a.seq, b.seq
            )));
        }
        if a.cited_height != b.cited_height {
            return Err(build_error(format!(
                "not-equivocation: different cited heights ({}, {})",
                a.cited_height, b.cited_height
            )));
        }
        if a.price_micro_usd == b.price_micro_usd {
            return Err(build_error("not-equivocation: the prices are equal".into()));
        }
        let recs = attestors(node).await?;
        let rec = recs.iter().find(|r| r.seq == a.seq).ok_or_else(|| {
            build_error(format!("not-equivocation: no attestor with seq {}", a.seq))
        })?;
        if rec.bond_spent || rec.frozen {
            return Err(build_error(format!(
                "not-equivocation: the bond of seq {} is {}",
                a.seq,
                if rec.frozen { "frozen" } else { "spent" }
            )));
        }
        let info = role_info(node).await?;
        let chain = node::block_count(node).await? as i64;
        if (a.cited_height as i64) < info.start_height || a.cited_height as i64 > chain {
            return Err(build_error(format!(
                "not-equivocation: cited height {} is not in this chain's index",
                a.cited_height
            )));
        }
        let bh = yew_core::tx::txid_from_hex(&block_hash(node, a.cited_height as i64).await?)
            .map_err(|e| RpcError::new(code::INTERNAL_ERROR, e))?;
        for (x, name) in [(a, "A"), (b, "B")] {
            let msg = bundle::attest_message(x.seq, x.price_micro_usd, x.cited_height, &bh);
            if !bundle::verify_compact_sig(&rec.pubkey, &msg, &x.sig) {
                return Err(build_error(format!(
                    "not-equivocation: attestation {name} does not verify on this chain"
                )));
            }
        }
        Ok(())
    }

    /// `yed_reportequivocation "attestationHexA" "attestationHexB" ( wait )`.
    async fn yed_reportequivocation(
        &mut self,
        node: &dyn Node,
        p: &[Value],
    ) -> Result<J, RpcError> {
        if p.len() < 2 || p.len() > 3 {
            return Err(RpcError::new(
                code::MISC_ERROR,
                "yed_reportequivocation \"attestationHexA\" \"attestationHexB\" ( wait )",
            ));
        }
        let a = attestation_param(&p[0], "attestationHexA")?;
        let b = attestation_param(&p[1], "attestationHexB")?;
        let wait = wait_param(p, 2)?;
        self.check_equivocation(node, &a, &b).await?;
        let info = crate::yed::yed_info(node).await?;
        let r = info.index_height - info.ref_lag;
        let bundle_bytes = bundle::encode(&[a.clone(), b.clone()]);
        let carrier = self.build_carrier(node, &bundle_bytes, r, "", None).await?;
        let shape = J::obj()
            .with("seq", a.seq as i64)
            .with("citedHeight", a.cited_height as i64)
            .with("priceA", a.price_micro_usd as i64)
            .with("priceB", b.price_micro_usd as i64);
        if !wait {
            self.pending.push(crate::mint::PendingMint {
                claim: None,
                equivocation: Some((hex::encode(a.encode()), hex::encode(b.encode()))),
                notice: None,
                carrier,
                cents: 0,
                lock_blocks: 0,
                from: String::new(),
                max_collateral: 0,
                est: Value::Null,
                facts: Default::default(),
            });
            let mut o = J::obj()
                .with("txid", "")
                .with("carrierTxid", txid_hex(&carrier.txid))
                .with("pending", true)
                .with("refHeight", r);
            if let J::Obj(f) = shape {
                for (k, v) in f {
                    o.push(&k, v);
                }
            }
            return Ok(o);
        }
        self.wait_equivocation_carrier(node, &carrier).await?;
        self.complete_equivocation(node, &a, &b, &carrier).await
    }

    async fn wait_equivocation_carrier(
        &mut self,
        node: &dyn Node,
        carrier: &OutPoint,
    ) -> Result<(), RpcError> {
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(CARRIER_WAIT_SECS);
        while std::time::Instant::now() < deadline {
            if let Some(c) = node_coin(node, carrier).await? {
                if c.height.is_some() {
                    self.sync(node).await?;
                    return Ok(());
                }
            } else {
                return Err(build_error(format!(
                    "carrier-unconfirmed: the carrier {} is not an unspent output",
                    op_str(carrier)
                )));
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
        Err(RpcError::new(code::WALLET_ERROR, "carrier-wait-timeout: the carrier did not confirm; call again (yed_sweepcarriers reclaims it once it lapses)"))
    }

    /// `CompleteEquivocation` / `BuildEquivocation`: the carrier (whose bundle is exactly
    /// `{a, b}`) as the last input, the `EQUIVOCATION` payload, YEC for the fee, change.
    pub(crate) async fn complete_equivocation(
        &mut self,
        node: &dyn Node,
        a: &Attestation,
        b: &Attestation,
        carrier: &OutPoint,
    ) -> Result<J, RpcError> {
        self.check_equivocation(node, a, b).await?;
        let rec = self
            .st
            .carriers
            .get(&op_str(carrier))
            .cloned()
            .ok_or_else(|| {
                RpcError::new(
                    code::WALLET_ERROR,
                    "carrier-key-missing: the carrier is not this wallet's",
                )
            })?;
        if rec.bundle != hex::encode(bundle::encode(&[a.clone(), b.clone()])) {
            return Err(build_error(
                "carrier-selector: the carrier does not commit to these two attestations".into(),
            ));
        }
        match node_coin(node, carrier).await? {
            Some(c) if c.height.is_some() => {}
            _ => {
                return Err(build_error(format!(
                    "carrier-unconfirmed: the carrier {} is not a confirmed unspent output",
                    op_str(carrier)
                )))
            }
        }
        let info = crate::yed::yed_info(node).await?;
        let next = next_block(node).await?;
        if next.height as i64 - info.ref_window > rec.ref_height {
            return Err(build_error(format!("carrier-lapsed: the carrier's reference height {} is outside the window at height {}; yed_sweepcarriers reclaims it", rec.ref_height, next.height)));
        }
        let data = payload::encode(&payload::Payload::Equivocation).ok_or_else(|| {
            RpcError::new(
                code::INTERNAL_ERROR,
                "cannot encode the equivocation payload",
            )
        })?;
        let mut base = Transaction::new_v4();
        base.expiry_height = (rec.ref_height + info.ref_window) as u32;
        base.vout.push(TxOut {
            value: 0,
            script_pubkey: payload::payload_script(&data),
        });
        let redeem = yew_core::script::carrier_script(
            &hex::decode(&rec.pk)
                .ok()
                .and_then(|b| <[u8; 33]>::try_from(b).ok())
                .ok_or_else(|| RpcError::new(code::INTERNAL_ERROR, "the carrier record's key"))?,
            &yew_core::keys::sha256(&hex::decode(&rec.bundle).unwrap_or_default()),
        )
        .map_err(|e| RpcError::new(code::INTERNAL_ERROR, e.to_string()))?;
        let carrier_ss = 1 + 520 + 3 + 73 + 1 + redeem.len();
        let (tx, coins) = self
            .fund_yed(
                node,
                &base,
                CARRIER_VALUE,
                info.flat_fee,
                None,
                &[(*carrier, carrier_ss)],
            )
            .await?;
        let mut prevs: Vec<NodeCoin> = coins
            .iter()
            .map(|c| NodeCoin {
                value: c.1,
                script: c.2.clone(),
                height: None,
                coinbase: false,
            })
            .collect();
        prevs.push(NodeCoin {
            value: CARRIER_VALUE,
            script: yew_core::script::p2sh_of(&redeem),
            height: None,
            coinbase: false,
        });
        let mut keys: Vec<KeyRef> = coins
            .iter()
            .map(|c| self.key_of_script(&c.2).unwrap_or(KeyRef::None))
            .collect();
        keys.push(KeyRef::Carrier {
            chain: crate::keys::EXTERNAL,
            index: rec.index,
        });
        let cap = prevs.iter().map(|c| c.value).sum::<i64>();
        let signed = self
            .sign_inputs(&tx, &prevs, &keys, &[], GatePath::Yed, cap, next.branch)
            .await?;
        let hexs = tx_hex(&signed)?;
        let val = node::call(
            node,
            "yed_validaterawtransaction",
            serde_json::json!([hexs]),
        )
        .await?;
        let verdict = val["verdict"].as_str().unwrap_or("").to_string();
        if verdict != "ok" {
            return Err(build_error(format!(
                "{verdict}: the wallet's dry run of EQV-1 refused this report at height {}",
                next.height
            )));
        }
        let txid = self.broadcast(node, &signed, None).await?;
        self.st.carriers.remove(&op_str(carrier));
        self.persist_state()?;
        Ok(J::obj()
            .with("txid", txid)
            .with("carrierTxid", txid_hex(&carrier.txid))
            .with("pending", false)
            .with("refHeight", rec.ref_height)
            .with("seq", a.seq as i64)
            .with("citedHeight", a.cited_height as i64)
            .with("priceA", a.price_micro_usd as i64)
            .with("priceB", b.price_micro_usd as i64))
    }

    // ------------------------------------------------------------------ cancel co-signer

    /// `CancelTargetOf`, plus the refund holder and the burn `yed_buildcancel` needs.
    async fn cancel_target(
        &self,
        node: &dyn Node,
        op: &OutPoint,
    ) -> Result<CancelTarget, RpcError> {
        let not_claim =
            || invalid("not a YED claim intent (confirmed in the index or in the mempool)");
        let coin = node_coin(node, op).await?.ok_or_else(not_claim)?;
        let ip = yew_core::vault::parse_intent(&coin.script).ok_or_else(not_claim)?;
        if ip.tag != yew_core::vault::YED_TAG {
            return Err(not_claim());
        }
        let raw = node::raw_tx(node, &txid_hex(&op.txid))
            .await?
            .ok_or_else(not_claim)?;
        let (claim, _) = Transaction::parse(&raw).map_err(|_| not_claim())?;
        let vault_op = claim.vin.first().map(|i| i.prevout).ok_or_else(not_claim)?;
        if coin.height.is_some() {
            // confirmed: the index's intent record (the vault CLAIMING, the intent's role)
            let v = Self::yed_vault(node, &txid_hex(&vault_op.txid))
                .await
                .map_err(|_| not_claim())?;
            let row = v["intents"].as_array().and_then(|a| {
                a.iter()
                    .find(|r| {
                        r["txid"].as_str() == Some(txid_hex(&op.txid).as_str())
                            && r["vout"].as_u64() == Some(op.n as u64)
                    })
                    .cloned()
            });
            let Some(row) = row else {
                if v["status"].as_str() != Some("CLAIMING") {
                    return Err(invalid("the intent's vault is not CLAIMING"));
                }
                return Err(not_claim());
            };
            if row["role"].as_str() != Some("claimant") {
                return Err(invalid(
                    "the owner's residual intent is never cancelled (intent-cancel-residual)",
                ));
            }
            if v["status"].as_str() != Some("CLAIMING") {
                return Err(invalid("the intent's vault is not CLAIMING"));
            }
            let (r, _) = claim_ref_height(&claim).ok_or_else(not_claim)?;
            let holder = v["refundHolder"]
                .as_str()
                .and_then(|h| hex::decode(h).ok())
                .unwrap_or_default();
            let cents = v["burnedCents"].as_i64().unwrap_or(0);
            return Ok(CancelTarget {
                ref_height: r,
                vault: v,
                confirmed: true,
                holder,
                cents,
            });
        }
        // a claim in the mempool: its vault ACTIVE, every input confirmed, the index at the tip
        let (r, assigned) = claim_ref_height(&claim).ok_or_else(not_claim)?;
        let v = Self::yed_vault(node, &txid_hex(&vault_op.txid))
            .await
            .map_err(|_| not_claim())?;
        if v["status"].as_str() != Some("ACTIVE") || vault_op.n != 0 {
            return Err(not_claim());
        }
        Ok(CancelTarget {
            ref_height: r,
            vault: v,
            confirmed: false,
            holder: Vec::new(),
            cents: -assigned,
        })
    }

    /// A mempool claim's refund holder and burn (`yed_buildcancel`): the token at its
    /// lowest-index YED input, the YED in minus what its payload assigns.
    async fn mempool_claim_refund(
        &self,
        node: &dyn Node,
        op: &OutPoint,
        assigned_neg: i64,
    ) -> Result<(Vec<u8>, i64), RpcError> {
        let raw = node::raw_tx(node, &txid_hex(&op.txid))
            .await?
            .unwrap_or_default();
        let (claim, _) =
            Transaction::parse(&raw).map_err(|_| invalid("the claim does not decode"))?;
        let mempool: std::collections::BTreeSet<String> =
            node::mempool(node).await?.into_iter().collect();
        for i in &claim.vin {
            if mempool.contains(&txid_hex(&i.prevout.txid)) {
                return Err(RpcError::new(code::MISC_ERROR, "the mempool claim spends an unconfirmed output: its refund holder is known once its inputs confirm (or once the claim does)"));
            }
        }
        let info = crate::yed::yed_info(node).await?;
        if info.index_height != node::block_count(node).await? as i64 {
            return Err(RpcError::new(
                code::MISC_ERROR,
                "the Yellowback index is behind the chain tip; retry when it has caught up",
            ));
        }
        let mut holder = Vec::new();
        let mut yed_in = 0i64;
        for i in &claim.vin {
            let Some(c) = node_coin(node, &i.prevout).await? else {
                continue;
            };
            let Some(addr) = crate::keys::script_address(self.network, &c.script) else {
                continue;
            };
            let toks = match node::call(node, "yed_listtokens", serde_json::json!([[addr]])).await {
                Ok(t) => t,
                Err(_) => continue,
            };
            let want = txid_hex(&i.prevout.txid);
            if let Some(t) = toks.as_array().and_then(|a| {
                a.iter().find(|t| {
                    t["txid"].as_str() == Some(want.as_str())
                        && t["vout"].as_u64() == Some(i.prevout.n as u64)
                })
            }) {
                if holder.is_empty() {
                    holder = c.script.clone();
                }
                yed_in += t["cents"].as_i64().unwrap_or(0);
            }
        }
        Ok((holder, yed_in + assigned_neg))
    }

    /// `yed_signcancelcosign "intentoutpoint" ( priceMicroUsd seq )`.
    async fn yed_signcancelcosign(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        if p.is_empty() || p.len() > 3 {
            return Err(RpcError::new(
                code::MISC_ERROR,
                "yed_signcancelcosign \"intentoutpoint\" ( priceMicroUsd seq )",
            ));
        }
        let op = intent_param(&p[0])?;
        let t = self.cancel_target(node, &op).await?;
        if !t.confirmed {
            return Err(RpcError::new(code::MISC_ERROR, "claim-unconfirmed: co-sign the cancel once the claim has confirmed (its txid is malleable until then; re-sign after a reorg that re-mines it)"));
        }
        let info = role_info(node).await?;
        let next = info.index_height + 1;
        let recs = attestors(node).await?;
        let maturity = crate::vaultrpc::set_view(node, &info.set_id)
            .await?
            .map(|s| s.maturity)
            .unwrap_or(0);
        let seq = match param(p, 2) {
            Some(_) => {
                let a = get_int(p, 2)?;
                if !(0..=65535).contains(&a) {
                    return Err(invalid("seq must be a u16"));
                }
                a as u16
            }
            None => recs
                .iter()
                .find(|r| {
                    self.key_of_pubkey(&r.pubkey).is_some()
                        && current_member(&recs, maturity, &r.pubkey, next) == Some(r.seq)
                })
                .map(|r| r.seq)
                .ok_or_else(|| {
                    invalid("attest-key-not-held: this wallet holds no current member key of the attestor set")
                })?,
        };
        let rec = recs
            .iter()
            .find(|r| r.seq == seq)
            .ok_or_else(|| invalid(format!("attest-unknown-seq: no attestor with seq {seq}")))?;
        if current_member(&recs, maturity, &rec.pubkey, next) != Some(seq) {
            return Err(invalid(format!(
                "attest-not-eligible: seq {seq} is not a current member of the attestor set"
            )));
        }
        let key = self
            .key_of_pubkey(&rec.pubkey)
            .ok_or_else(|| invalid("attest-key-not-held: the member key is not in this wallet"))?;
        let price = match param(p, 1) {
            None => None,
            Some(_) => {
                let x = get_int(p, 1)?;
                if !(pa::PRICE_MIN..=pa::PRICE_MAX).contains(&x) {
                    return Err(invalid(format!(
                        "attest-range: priceMicroUsd must be in [{}, {}]",
                        pa::PRICE_MIN,
                        pa::PRICE_MAX
                    )));
                }
                Some(x as u32)
            }
        };
        let bh = block_hash(node, t.ref_height).await?;
        let r = self.signer.request(Request::CancelCosign(CosignRequest {
            key,
            pubkey: hex::encode(rec.pubkey),
            seq,
            set_id: info.set_id_hex.clone(),
            intent: op_str(&op),
            ref_height: t.ref_height as u32,
            block_hash: bh,
            price_micro_usd: price,
            collateral_zat: t.vault["collateralZat"].as_i64().unwrap_or(0),
            minted_cents: t.vault["mintedCents"].as_i64().unwrap_or(0),
            claim_threshold_bps: info.claim_threshold_bps,
        }));
        match r {
            Ok(Response::Cosign(c)) => Ok(J::obj()
                .with("cosig", c.cosig)
                .with("seq", seq as i64)
                .with("priceMicroUsd", c.price_micro_usd as i64)
                .with("citedHeight", t.ref_height)
                .with("reused", c.reused)),
            other => Err(cosign_error(other)),
        }
    }

    /// `yed_buildcancel "intentoutpoint" ( ["cosig",...] )`: `vault_buildcancel`'s transaction with
    /// the refund of the claim's burn and the `CANCEL_COSIGN` marker, and the carrier of the
    /// co-signatures as its last input, signed.
    async fn yed_buildcancel(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        if p.is_empty() || p.len() > 2 {
            return Err(RpcError::new(
                code::MISC_ERROR,
                "yed_buildcancel \"intentoutpoint\" ( [\"cosig\",...] )",
            ));
        }
        let op = intent_param(&p[0])?;
        let mut t = self.cancel_target(node, &op).await?;
        if !t.confirmed {
            let (holder, cents) = self.mempool_claim_refund(node, &op, t.cents).await?;
            t.holder = holder;
            t.cents = cents;
        }
        if t.holder.is_empty() || t.cents <= 0 {
            return Err(invalid("the claim recorded no refund holder"));
        }
        let info = role_info(node).await?;
        let next = info.index_height + 1;
        let required = t.vault["cancelsRequired"].as_i64().unwrap_or(1);
        let recs = attestors(node).await?;
        let maturity = crate::vaultrpc::set_view(node, &info.set_id)
            .await?
            .map(|s| s.maturity)
            .unwrap_or(0);
        let bh =
            yew_core::tx::txid_from_hex(&block_hash(node, t.ref_height).await?).map_err(|e| {
                RpcError::new(
                    code::MISC_ERROR,
                    format!("the claim's refHeight {} is not indexed: {e}", t.ref_height),
                )
            })?;
        let collateral = t.vault["collateralZat"].as_i64().unwrap_or(0);
        let minted = t.vault["mintedCents"].as_i64().unwrap_or(0);
        let cos: Vec<Value> = match param(p, 1) {
            None => Vec::new(),
            Some(Value::Array(a)) => a.clone(),
            Some(_) => {
                return Err(RpcError::new(
                    code::MISC_ERROR,
                    "JSON value is not an array as expected",
                ))
            }
        };
        let mut warnings: Vec<String> = Vec::new();
        let mut entries: Vec<pa::CosignEntry> = Vec::new();
        let mut cosigners: Vec<u16> = Vec::new();
        let mut seen: Vec<[u8; 33]> = Vec::new();
        for (i, c) in cos.iter().enumerate() {
            let mut drop = |why: String| warnings.push(format!("cosigs[{i}] dropped: {why}"));
            let Some(e) = c
                .as_str()
                .and_then(|h| hex::decode(h).ok())
                .and_then(|b| pa::CosignEntry::from_bytes(&b))
            else {
                drop("cancel-cosign-malformed: not a 69-byte co-signature".into());
                continue;
            };
            let msg = pa::cancel_cosign_message(
                &info.set_id,
                &op.txid,
                op.n,
                t.ref_height as u32,
                e.price_micro_usd,
                &bh,
            );
            let Some(key) = yewd_proto::act::recover(&msg, &e.sig) else {
                drop("cancel-cosign-malformed: does not sign this intent's cancel".into());
                continue;
            };
            if seen.contains(&key) {
                drop(format!("a repeat of key {}", hex::encode(key)));
                continue;
            }
            let Some(seq) = current_member(&recs, maturity, &key, next) else {
                drop(format!(
                    "cancel-cosign-not-member: key {} is not a current member of the attestor set at height {next}",
                    hex::encode(key)
                ));
                continue;
            };
            let price = e.price_micro_usd as i64;
            if !(pa::PRICE_MIN..=pa::PRICE_MAX).contains(&price) {
                drop(format!(
                    "attest-range: seq {seq} states {price} micro-USD, outside [{}, {}]",
                    pa::PRICE_MIN,
                    pa::PRICE_MAX
                ));
                continue;
            }
            if pa::is_underwater(collateral, price, minted, info.claim_threshold_bps) {
                drop(format!(
                    "cancel-statement-claimable: seq {seq} states {price} micro-USD, at which the vault was claimable at refHeight {}",
                    t.ref_height
                ));
                continue;
            }
            if entries.len() >= pa::CANCEL_COSIGN_MAX {
                drop(format!(
                    "beyond the carrier's {} entries",
                    pa::CANCEL_COSIGN_MAX
                ));
                continue;
            }
            seen.push(key);
            entries.push(e);
            cosigners.push(seq);
        }
        if (entries.len() as i64) < required {
            let why: String = warnings.iter().map(|w| format!("; {w}")).collect();
            return Err(invalid(format!(
                "cancel-cosign-needed: this cancel needs {required} co-signature(s) of distinct current members (cancelsRequired), {} valid given (yed_signcancelcosign){why}",
                entries.len()
            )));
        }
        let carrier_ref = info.index_height;
        // the cancel first (its fee inputs chosen and locked by the remembered build), then the carrier
        let marker = vec![
            payload::MAGIC[0],
            payload::MAGIC[1],
            payload::VERSION,
            CANCEL_COSIGN_TYPE,
        ];
        let extra = [
            TxOut {
                value: TOKEN_VALUE,
                script_pubkey: t.holder.clone(),
            },
            TxOut {
                value: 0,
                script_pubkey: payload::payload_script(&marker),
            },
        ];
        let built = self
            .build_intent_cancel(node, &op, &extra, true, false, false)
            .await?;
        let bv: Value = serde_json::from_str(&built.text())
            .map_err(|e| RpcError::new(code::INTERNAL_ERROR, e.to_string()))?;
        let blob = pa::encode_cosigns(&entries).ok_or_else(|| {
            RpcError::new(
                code::INTERNAL_ERROR,
                "the co-signature list does not encode",
            )
        })?;
        let blob_hex = hex::encode(&blob);
        // an outstanding carrier of this wallet with exactly these bytes is reused (sign once)
        let mut reuse: Option<OutPoint> = None;
        let mempool_spent = self.mempool_spent();
        for (k, c) in self.st.carriers.clone() {
            if c.bundle != blob_hex || !c.selector.is_empty() {
                continue;
            }
            let Ok(o) = outpoint_param(&Value::String(k), "carrier") else {
                continue;
            };
            if node_coin(node, &o).await?.is_some()
                && !mempool_spent.contains(&(txid_hex(&o.txid), o.n))
            {
                reuse = Some(o);
                break;
            }
        }
        let carrier = match reuse {
            Some(o) => o,
            None => {
                self.build_carrier(node, &blob, carrier_ref, "", None)
                    .await?
            }
        };
        let crec = self
            .st
            .carriers
            .get(&op_str(&carrier))
            .cloned()
            .ok_or_else(|| RpcError::new(code::INTERNAL_ERROR, "the carrier record"))?;
        let mut tx = crate::build::parse_hex_tx(bv["hex"].as_str().unwrap_or(""))
            .ok_or_else(|| RpcError::new(code::INTERNAL_ERROR, "the cancel does not decode"))?;
        tx.vin.push(TxIn::new(carrier));
        // the carrier input alone is signed here; the template keeps its place for the set's
        // signatures, the fee inputs are signed by vault_send
        let next_b = next_block(node).await?;
        let mut prevs = Vec::with_capacity(tx.vin.len());
        for i in &tx.vin {
            prevs.push(node_coin(node, &i.prevout).await?.ok_or_else(|| {
                RpcError::new(
                    code::TRANSACTION_ERROR,
                    format!("Missing inputs: {} is spent or unknown", op_str(&i.prevout)),
                )
            })?);
        }
        let mut keys = vec![KeyRef::None; tx.vin.len()];
        *keys.last_mut().expect("the carrier") = KeyRef::Carrier {
            chain: crate::keys::EXTERNAL,
            index: crec.index,
        };
        let signed = self
            .sign_inputs(
                &tx,
                &prevs,
                &keys,
                &[],
                GatePath::Vault,
                CARRIER_VALUE,
                next_b.branch,
            )
            .await?;
        let mut o = J::obj()
            .with("hex", tx_hex(&signed)?)
            .with("required", bv["required"].as_i64().unwrap_or(0))
            .with(
                "cancelsetid",
                bv["cancelsetid"].as_str().unwrap_or("").to_string(),
            )
            .with("deadline", bv["deadline"].as_i64().unwrap_or(0))
            .with(
                "intentconfirmed",
                bv["intentconfirmed"].as_bool().unwrap_or(false),
            )
            .with(
                "refund",
                J::obj()
                    .with("vout", 1i64)
                    .with("script", hex::encode(&t.holder))
                    .with("cents", t.cents),
            )
            .with("cancelsRequired", required)
            .with(
                "cosigners",
                J::Arr(cosigners.iter().map(|s| J::Int(*s as i64)).collect()),
            )
            .with("carrierTxid", txid_hex(&carrier.txid));
        if !warnings.is_empty() {
            o.push(
                "warnings",
                J::Arr(warnings.into_iter().map(J::Str).collect()),
            );
        }
        Ok(o)
    }

    // ------------------------------------------------------------------ stock key RPCs

    /// The transparent key of an `s…` address, ycashd's errors for the rest.
    fn address_key(
        &self,
        addr: &str,
        invalid_msg: String,
        pq_msg: &str,
        not_key: &str,
    ) -> Result<Option<KeyRef>, RpcError> {
        if yew_core::keys::parse_pq_yec_address(self.network, addr).is_ok() {
            return Err(RpcError::new(code::TYPE_ERROR, pq_msg));
        }
        let script = crate::rpc::parse_taddr_script(self.network, addr)
            .ok_or_else(|| RpcError::new(code::INVALID_ADDRESS_OR_KEY, invalid_msg))?;
        let Some(h) = yew_core::script::p2pkh_hash(&script) else {
            return Err(RpcError::new(code::TYPE_ERROR, not_key));
        };
        Ok(self.book.by_hash(&h).map(|k| KeyRef::Bip32 {
            chain: k.chain,
            index: k.index,
        }))
    }

    /// `signmessage "t-addr" "message"`.
    fn signmessage(&mut self, p: &[Value]) -> Result<J, RpcError> {
        if p.len() != 2 {
            return Err(RpcError::new(
                code::MISC_ERROR,
                "signmessage \"t-addr\" \"message\"",
            ));
        }
        let (Some(addr), Some(msg)) = (p[0].as_str(), p[1].as_str()) else {
            return Err(RpcError::new(
                code::MISC_ERROR,
                "JSON value is not a string as expected",
            ));
        };
        let key = self
            .address_key(
                addr,
                format!("Invalid Ycash transparent address: {addr}"),
                "Address does not refer to key",
                "Address does not refer to key",
            )?
            .ok_or_else(|| RpcError::new(code::WALLET_ERROR, "Private key not available"))?;
        match self.signer.request(Request::SignMessage(MessageRequest {
            key,
            message: msg.to_string(),
        })) {
            Ok(Response::MessageSig(h)) => {
                let b = hex::decode(&h)
                    .map_err(|e| RpcError::new(code::INTERNAL_ERROR, e.to_string()))?;
                Ok(J::Str(base64::engine::general_purpose::STANDARD.encode(b)))
            }
            other => Err(signer_error(other)),
        }
    }

    /// `dumpprivkey "t-addr"`: the WIF, from the signer.
    fn dumpprivkey(&mut self, p: &[Value]) -> Result<J, RpcError> {
        if p.len() != 1 {
            return Err(RpcError::new(code::MISC_ERROR, "dumpprivkey \"t-addr\""));
        }
        let addr = p[0].as_str().ok_or_else(|| {
            RpcError::new(code::MISC_ERROR, "JSON value is not a string as expected")
        })?;
        let key = self
            .address_key(
                addr,
                "Invalid Ycash address".into(),
                "A post-quantum address has no WIF key; dumpwallet / z_exportwallet write its pqseed line",
                "Address does not refer to a key",
            )?
            .ok_or_else(|| {
                RpcError::new(
                    code::WALLET_ERROR,
                    format!("Private key for address {addr} is not known"),
                )
            })?;
        match self.signer.request(Request::DumpKey(key)) {
            Ok(Response::Dumped(w)) => Ok(J::Str(w)),
            other => Err(signer_error(other)),
        }
    }

    /// `importprivkey "privkey" ( "label" rescan )`: the key into the signer's store, its public
    /// key into the wallet; `rescan` (default true) scans the chain again from the birthday.
    async fn importprivkey(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        if p.is_empty() || p.len() > 3 {
            return Err(RpcError::new(
                code::MISC_ERROR,
                "importprivkey \"zcashprivkey\" ( \"label\" rescan )",
            ));
        }
        let wif = p[0].as_str().ok_or_else(|| {
            RpcError::new(code::MISC_ERROR, "JSON value is not a string as expected")
        })?;
        let label = match param(p, 1) {
            None => String::new(),
            Some(v) => v
                .as_str()
                .ok_or_else(|| {
                    RpcError::new(code::MISC_ERROR, "JSON value is not a string as expected")
                })?
                .to_string(),
        };
        let rescan = match p.get(2) {
            None => true,
            Some(Value::Bool(b)) => *b,
            Some(_) => {
                return Err(RpcError::new(
                    code::MISC_ERROR,
                    "JSON value is not a boolean as expected",
                ))
            }
        };
        let k = yew_core::keys::decode_wif(self.network, wif.trim()).map_err(|_| {
            RpcError::new(code::INVALID_ADDRESS_OR_KEY, "Invalid private key encoding")
        })?;
        let addr = yew_core::keys::encode_p2pkh(self.network, &k.hash160);
        self.st.book.insert(
            addr.clone(),
            crate::state::BookEntry {
                label,
                purpose: "receive".into(),
            },
        );
        // "Don't throw error in case a key is already there"
        if self.book.by_hash(&k.hash160).is_some() {
            self.persist_state()?;
            return Ok(J::Str(addr));
        }
        let ik = match self.signer.request(Request::ImportKey(ImportKeyRequest {
            wif: wif.trim().to_string(),
        })) {
            Ok(Response::ImportedKey(ik)) => ik,
            Ok(Response::Refused(r)) if r.code == yewd_proto::refuse::KEY_NOT_HELD => {
                return Err(RpcError::new(code::INVALID_ADDRESS_OR_KEY, r.reason))
            }
            other => return Err(signer_error(other)),
        };
        let idx = ik.index as usize;
        if self.st.public.imported.len() <= idx {
            self.st.public.imported.resize(idx + 1, String::new());
        }
        self.st.public.imported[idx] = ik.pubkey.clone();
        self.refresh_keys()
            .map_err(|e| RpcError::new(code::WALLET_ERROR, e))?;
        debug_assert!(self.book.key(IMPORTED, ik.index).is_some());
        self.persist_state()?;
        if rescan {
            self.rewind(None);
            self.sync(node).await?;
        }
        Ok(J::Str(addr))
    }
}
