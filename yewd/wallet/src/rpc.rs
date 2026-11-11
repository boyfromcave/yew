// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The read RPCs of S1 (workspace plan §3b S1), by ycashd's names, arguments, result shapes and
//! error codes: the stock wallet reads (`getbalance`, `listunspent`, `gettransaction`,
//! `getwalletinfo`, `getreceivedbyaddress`, `listlockunspent`), the address RPCs (`getnewaddress`
//! incl. `"pq"`, `z_getnewaddress`, `yed_getnewaddress`, `vault_getnewowner`), the Sapling reads
//! (`z_getbalance`, `z_listunspent`), the YED reads (`yed_getbalance`, `yed_listunspent`,
//! `yed_listaddresses`, `yed_listtransactions`, `yed_listpositions`, `yed_validateaddress`), the
//! sign-once listing (`set_listsigned`), and the wallet fields of the node reads the façade
//! augments (`getinfo`, `validateaddress`, `z_validateaddress`, `vault_list`, `set_getinfo`).
//!
//! The sources are ycash6 `src/wallet/rpcwallet.cpp`, `src/rpc/yellowbackwallet.cpp` and
//! `src/rpc/vault.cpp` at the revision `yewd/PIN` names; each function names its counterpart.
//! The YED reads take the index's view from the node (`yed_listtokens`, `yed_getvault`,
//! `yed_listvaults`, `yed_gettxinfo`) and add what only the wallet knows (which scripts and
//! owners are its own), as ycashd's `YellowbackWallet` does over its in-process index.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::value::RawValue;
use serde_json::Value;
use yew_core::keys as ykeys;
use yew_core::pq::PqKeyId;

use crate::json::J;
use crate::keys::{pqkeyid_hex, script_address, yed_address, Owner, EXTERNAL};
use crate::node::{self, Node, NodeError};
use crate::state::BookEntry;
use crate::{code, txid_hex, Coin, RpcError, Wallet, COINBASE_MATURITY};

/// The wallet methods this build serves (the rest of the façade's wallet table still answers
/// `-32601 yewd: not yet implemented`).
pub const SERVED: &[&str] = &[
    // R5
    "vault_getnewowner",
    "set_listsigned",
    // R6
    "yed_getnewaddress",
    "yed_validateaddress",
    "yed_getbalance",
    "yed_listunspent",
    "yed_listpositions",
    "yed_listtransactions",
    "yed_listaddresses",
    // K-25 stock
    "getbalance",
    "getnewaddress",
    "getreceivedbyaddress",
    "gettransaction",
    "getwalletinfo",
    "listlockunspent",
    "listunspent",
    "z_getbalance",
    "z_getnewaddress",
    "z_listunspent",
];

/// The node reads whose answers the wallet completes (the façade's `Augmented` class).
pub const AUGMENTED: &[&str] = &[
    "getinfo",
    "validateaddress",
    "z_validateaddress",
    "vault_list",
    "set_getinfo",
    "yed_gettxinfo",
    "yed_getinfo",
];

pub fn served(method: &str) -> bool {
    SERVED.contains(&method)
        || crate::vaultrpc::SERVED.contains(&method)
        || crate::send::SERVED.contains(&method)
        || crate::yed::SERVED.contains(&method)
        || crate::mint::SERVED.contains(&method)
        || crate::claim::SERVED.contains(&method)
        || crate::attest::SERVED.contains(&method)
        || crate::admin::SERVED.contains(&method)
        || crate::zsend::SERVED.contains(&method)
        || crate::legacy::SERVED.contains(&method)
        || crate::bytype::SERVED.contains(&method)
}

/// Every served wallet method, S1's reads and S2's builders.
pub fn all_served() -> Vec<&'static str> {
    SERVED
        .iter()
        .chain(crate::vaultrpc::SERVED)
        .chain(crate::send::SERVED)
        .chain(crate::yed::SERVED)
        .chain(crate::mint::SERVED)
        .chain(crate::claim::SERVED)
        .chain(crate::attest::SERVED)
        .chain(crate::admin::SERVED)
        .chain(crate::zsend::SERVED)
        .chain(crate::legacy::SERVED)
        .chain(crate::bytype::SERVED)
        .copied()
        .collect()
}

pub(crate) fn invalid(m: impl Into<String>) -> RpcError {
    RpcError::new(code::INVALID_PARAMETER, m)
}

pub(crate) fn param(p: &[Value], i: usize) -> Option<&Value> {
    p.get(i).filter(|v| !v.is_null())
}

pub(crate) fn p_int(p: &[Value], i: usize, default: i64) -> Result<i64, RpcError> {
    match param(p, i) {
        None => Ok(default),
        Some(Value::Number(n)) => n
            .as_i64()
            .ok_or_else(|| RpcError::new(code::TYPE_ERROR, "JSON integer out of range")),
        Some(_) => Err(RpcError::new(code::TYPE_ERROR, "Expected type number")),
    }
}

pub(crate) fn p_bool(p: &[Value], i: usize, default: bool) -> Result<bool, RpcError> {
    match param(p, i) {
        None => Ok(default),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(RpcError::new(code::TYPE_ERROR, "Expected type bool")),
    }
}

pub(crate) fn p_str(p: &[Value], i: usize) -> Result<Option<&str>, RpcError> {
    match param(p, i) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(RpcError::new(code::TYPE_ERROR, "Expected type string")),
    }
}

pub(crate) fn arity(method: &str, p: &[Value], max: usize) -> Result<(), RpcError> {
    if p.len() > max {
        return Err(RpcError::new(
            code::MISC_ERROR,
            format!("{method}: at most {max} arguments"),
        ));
    }
    Ok(())
}

/// `parseMinconf`: a non-negative integer.
pub(crate) fn minconf(p: &[Value], i: usize, default: i64) -> Result<i64, RpcError> {
    let m = p_int(p, i, default)?;
    if m < 0 {
        return Err(invalid("Invalid parameter, minconf must be non-negative"));
    }
    Ok(m)
}

/// `parseAsOfHeight`: absent or -1 = now (with the mempool), else a height (no mempool).
fn as_of(p: &[Value], i: usize) -> Result<Option<u32>, RpcError> {
    match p_int(p, i, -1)? {
        -1 => Ok(None),
        h if h < 0 => Err(invalid(
            "Can not perform the query as of a negative block height",
        )),
        h => Ok(Some(h as u32)),
    }
}

/// `EstimateClaim`'s `canNotice` (ycash6 `src/rpc/yellowback.cpp`; finding F-S1-4): armed at the
/// index tip `h`, the vault ACTIVE, no standing notice, not claimable, and underwater at
/// `pEmerg` by `EMERGENCY_RATIO_BPS` — `pEmerg = min(xClaim, aClaim)` with the pool's bundle for
/// the vault's outpoint, `xClaim` alone when the pool cannot build one.
async fn can_notice(node: &dyn Node, v: &Value, h: i64, info: &Value) -> Result<bool, RpcError> {
    if v["status"].as_str() != Some("ACTIVE") || v["claimable"].as_bool() == Some(true) {
        return Ok(false);
    }
    if !crate::armed::armed_at(node, h).await? {
        return Ok(false);
    }
    let txid = v["txid"].as_str().unwrap_or("").to_string();
    let at = &info["params"]["attest"];
    let ttl = at["emergencyNoticeTtl"].as_i64().unwrap_or(0);
    let notice = node::call(node, "yed_getnotice", serde_json::json!([txid])).await?;
    if notice["found"].as_bool() == Some(true) && h - notice["height"].as_i64().unwrap_or(0) <= ttl
    {
        return Ok(false);
    }
    let (_, x_claim) = crate::armed::cross_section(node, h).await?;
    let mut sel = yew_core::tx::txid_from_hex(&txid)
        .map(|t| t.to_vec())
        .unwrap_or_default();
    sel.extend_from_slice(&0u32.to_le_bytes());
    let p_emerg = match node::call(
        node,
        "yed_buildbundle",
        serde_json::json!([h, hex::encode(sel)]),
    )
    .await
    {
        Ok(b) => match (x_claim, b["aClaim"].as_i64()) {
            (Some(x), Some(a)) => Some(x.min(a)),
            _ => x_claim,
        },
        Err(_) => x_claim,
    };
    Ok(crate::armed::is_underwater(
        v["collateralZat"].as_i64().unwrap_or(0),
        p_emerg,
        v["mintedCents"].as_i64().unwrap_or(0),
        at["emergencyRatioBps"].as_i64().unwrap_or(0),
    ))
}

/// `FormatMoney`: at least two decimals, trailing zeros trimmed (`"0.00"`, `"1.50"`, `"0.00000244"`).
pub fn format_money(zat: i64) -> String {
    let full = crate::json::amount_text(zat);
    let (int, frac) = full.split_once('.').expect("eight decimals");
    let mut frac = frac.trim_end_matches('0').to_string();
    while frac.len() < 2 {
        frac.push('0');
    }
    format!("{int}.{frac}")
}

fn hash_hex(b: &[u8]) -> String {
    hex::encode(b)
}

/// The schemes a balance split reports, always both and in this order (beta2 item 15; ycashd's
/// `PQ_BALANCE_SCHEMES`): SLH-DSA-SHA2-128s, then FN-DSA-512.
pub(crate) const PQ_BALANCE_SCHEMES: [u8; 2] = [
    yew_core::pq::SCHEME_SLH_DSA_SHA2_128S,
    yew_core::pq::SCHEME_FN_DSA_512,
];

/// ycashd's `PQSchemeName`: the registry's names, `"unknown"` for anything else.
pub(crate) fn pq_scheme_name(scheme: u8) -> &'static str {
    ykeys::pq_scheme_name(scheme).unwrap_or("unknown")
}

impl Wallet {
    // ------------------------------------------------------------------ chain views

    /// Depth of a height as of `asof` (`None`: now, with the mempool at 0).
    pub(crate) fn depth_at(&self, height: Option<u32>, asof: Option<u32>) -> i64 {
        let top = asof
            .map(|a| a.min(self.tip_height()))
            .unwrap_or(self.tip_height());
        match height {
            Some(h) if h <= top => (top - h + 1) as i64,
            Some(_) => -1, // above the as-of height: not in this view
            None if asof.is_some() => -1,
            None => 0,
        }
    }

    pub(crate) fn tx_depth(&self, txid: &str, asof: Option<u32>) -> i64 {
        self.st
            .wtx
            .get(txid)
            .map(|w| self.depth_at(w.block.as_ref().map(|b| b.height), asof))
            .unwrap_or(-1)
    }

    pub(crate) fn immature(&self, coinbase: bool, depth: i64) -> bool {
        coinbase && depth < (COINBASE_MATURITY + 1) as i64
    }

    /// Whether `outpoint` is spent by a wallet transaction in the `asof` view.
    fn spent_at(&self, txid: &str, vout: u32, asof: Option<u32>) -> bool {
        self.parsed_all().any(|(t, p)| {
            self.tx_depth(t, asof) >= 0
                && p.tx
                    .vin
                    .iter()
                    .any(|i| i.prevout.n == vout && txid_hex(&i.prevout.txid) == txid)
        })
    }

    /// ycashd's `IsFromMe` debit: the value of own outputs a transaction spends.
    pub(crate) fn debit(&self, txid: &str) -> i64 {
        let Some(p) = self.parsed(txid) else { return 0 };
        p.tx.vin
            .iter()
            .filter_map(|i| {
                let prev = txid_hex(&i.prevout.txid);
                let pp = self.parsed(&prev)?;
                let o = pp.tx.vout.get(i.prevout.n as usize)?;
                self.book.owns_script(&o.script_pubkey).map(|_| o.value)
            })
            .sum()
    }

    /// `CWalletTx::IsTrusted`: confirmed, or in the mempool with every input an own output.
    pub fn trusted(&self, txid: &str, asof: Option<u32>) -> bool {
        let d = self.tx_depth(txid, asof);
        if d >= 1 {
            return true;
        }
        if d < 0 || asof.is_some() {
            return false;
        }
        let Some(p) = self.parsed(txid) else {
            return false;
        };
        !p.tx.vin.is_empty()
            && p.tx.vin.iter().all(|i| {
                let prev = txid_hex(&i.prevout.txid);
                self.parsed(&prev)
                    .and_then(|pp| pp.tx.vout.get(i.prevout.n as usize))
                    .is_some_and(|o| self.book.owns_script(&o.script_pubkey).is_some())
            })
    }

    /// `GetAvailableCredit` of one wallet transaction: its own unspent outputs, nothing for an
    /// immature coinbase. The total of [`Self::available_credit_split`], so the ECC and
    /// post-quantum parts add up to it by construction.
    fn available_credit(&self, txid: &str, asof: Option<u32>) -> i64 {
        self.available_credit_split(txid, asof).0
    }

    /// `GetAvailableCredit` of one wallet transaction and its post-quantum part by scheme (index
    /// = scheme byte): the `TX_PQPKH` outputs among the counted ones (ycashd's `GetWalletBalanceSplit`, beta2
    /// item 15).
    fn available_credit_split(&self, txid: &str, asof: Option<u32>) -> (i64, [i64; 3]) {
        let mut pq = [0i64; 3];
        let Some(p) = self.parsed(txid) else {
            return (0, pq);
        };
        if self.immature(p.coinbase, self.tx_depth(txid, asof)) {
            return (0, pq);
        }
        let mut total = 0;
        for (n, o) in p.tx.vout.iter().enumerate() {
            if self.book.owns_script(&o.script_pubkey).is_none()
                || self.spent_at(txid, n as u32, asof)
            {
                continue;
            }
            total += o.value;
            if let Some(id) = yew_core::pq::pqpkh_of(&o.script_pubkey) {
                if let Some(slot) = pq.get_mut(id.scheme as usize) {
                    *slot += o.value;
                }
            }
        }
        (total, pq)
    }

    /// `GetBalance(asOfHeight, ISMINE_SPENDABLE, min_depth)`.
    pub fn balance(&self, asof: Option<u32>, min_depth: i64) -> i64 {
        self.st
            .wtx
            .keys()
            .filter(|t| self.trusted(t, asof) && self.tx_depth(t, asof) >= min_depth)
            .map(|t| self.available_credit(t, asof))
            .sum()
    }

    /// The coins `AvailableCoins` lists: unspent, not locked, mature, in the view.
    pub fn available_coins(&self, asof: Option<u32>) -> Vec<(&Coin, i64)> {
        self.coins
            .iter()
            .filter_map(|c| {
                let d = self.depth_at(c.height, asof);
                if d < 0 || self.immature(c.coinbase, d) || self.spent_at(&c.txid, c.vout, asof) {
                    return None;
                }
                if self.st.locks.contains(&format!("{}:{}", c.txid, c.vout)) {
                    return None;
                }
                Some((c, d))
            })
            .collect()
    }

    /// Whether `addr` (an `s…`/`t…`/`sq…` address) is in the address book: ycashd's `IsChange`
    /// is "mine and not in the book".
    pub(crate) fn in_book(&self, script: &[u8]) -> bool {
        script_address(self.network, script).is_some_and(|a| self.st.book.contains_key(&a))
    }

    fn address_book_label(&self, script: &[u8]) -> Option<String> {
        script_address(self.network, script)
            .and_then(|a| self.st.book.get(&a).map(|e| e.label.clone()))
    }

    // ------------------------------------------------------------------ dispatch

    /// Answer a served wallet method (after the barrier: the caller ran [`Wallet::sync`]).
    pub async fn call(
        &mut self,
        node: &dyn Node,
        method: &str,
        p: &[Value],
    ) -> Result<J, RpcError> {
        if crate::admin::NEEDS_UNLOCK.contains(&method) {
            self.ensure_unlocked()?;
        }
        match method {
            "getbalance" => self.getbalance(p),
            "getnewaddress" => self.getnewaddress(p),
            "getreceivedbyaddress" => self.getreceivedbyaddress(p),
            "gettransaction" => self.gettransaction(p),
            "getwalletinfo" => self.getwalletinfo(p),
            "listlockunspent" => self.listlockunspent(p),
            "listunspent" => self.listunspent(p),
            "z_getbalance" => self.z_getbalance(p),
            "z_getnewaddress" => self.z_getnewaddress(p),
            "z_listunspent" => self.z_listunspent(p),
            "vault_getnewowner" => self.vault_getnewowner(p),
            "set_listsigned" => self.set_listsigned(p),
            "yed_getnewaddress" => self.yed_getnewaddress(node, p).await,
            "yed_validateaddress" => self.yed_validateaddress(node, p).await,
            "yed_getbalance" => self.yed_getbalance(node, p).await,
            "yed_listunspent" => self.yed_listunspent(node, p).await,
            "yed_listaddresses" => self.yed_listaddresses(node, p).await,
            "yed_listtransactions" => self.yed_listtransactions(node, p).await,
            "yed_listpositions" => self.yed_listpositions(node, p).await,
            m if crate::vaultrpc::SERVED.contains(&m) => self.vault_call(node, m, p).await,
            m if crate::send::SERVED.contains(&m) => self.send_call(node, m, p).await,
            m if crate::yed::SERVED.contains(&m) => self.yed_call(node, m, p).await,
            m if crate::mint::SERVED.contains(&m) => self.mint_call(node, m, p).await,
            m if crate::claim::SERVED.contains(&m) => self.claim_call(node, m, p).await,
            m if crate::attest::SERVED.contains(&m) => self.attest_call(node, m, p).await,
            m if crate::admin::SERVED.contains(&m) => self.admin_call(node, m, p).await,
            m if crate::zsend::SERVED.contains(&m) => self.zsend_call(node, m, p).await,
            m if crate::legacy::SERVED.contains(&m) => self.legacy_call(node, m, p).await,
            m if crate::bytype::SERVED.contains(&m) => self.bytype_call(node, m, p).await,
            _ => Err(RpcError::new(code::METHOD_NOT_FOUND, "Method not found")),
        }
    }

    // ------------------------------------------------------------------ stock reads

    /// `getbalance ( "(dummy)" minconf includeWatchonly inZat asOfHeight )`.
    fn getbalance(&self, p: &[Value]) -> Result<J, RpcError> {
        arity("getbalance", p, 5)?;
        if let Some(d) = p_str(p, 0)? {
            if d != "*" && !d.is_empty() {
                return Err(invalid(
                    "dummy first argument must be excluded or set to \"*\".",
                ));
            }
        }
        let asof = as_of(p, 4)?;
        let min_depth = minconf(p, 1, 0)?;
        let _watch = p_bool(p, 2, false)?;
        let b = self.balance(asof, min_depth);
        Ok(if p_bool(p, 3, false)? {
            J::Int(b)
        } else {
            J::Amount(b)
        })
    }

    /// `listunspent ( minconf maxconf ["address",...] includeUnsafe queryOptions asOfHeight )`.
    fn listunspent(&self, p: &[Value]) -> Result<J, RpcError> {
        arity("listunspent", p, 6)?;
        let asof = as_of(p, 5)?;
        let min = minconf(p, 0, 1)?;
        let max = p_int(p, 1, 9_999_999)?;
        let mut filter: BTreeSet<Vec<u8>> = BTreeSet::new();
        if let Some(a) = param(p, 2) {
            let arr = a
                .as_array()
                .ok_or_else(|| RpcError::new(code::TYPE_ERROR, "Expected type array"))?;
            for v in arr {
                let s = v
                    .as_str()
                    .ok_or_else(|| invalid("Invalid parameter, expected string"))?;
                let script = parse_taddr_script(self.network, s).ok_or_else(|| {
                    RpcError::new(
                        code::INVALID_ADDRESS_OR_KEY,
                        format!("Invalid Ycash transparent address: {s}"),
                    )
                })?;
                if !filter.insert(script) {
                    return Err(invalid(format!(
                        "Invalid parameter, duplicated address: {s}"
                    )));
                }
            }
        }
        if p_bool(p, 3, false)? {
            return Err(invalid("includeUnsafe must be set to false"));
        }
        if let Some(q) = param(p, 4) {
            if q.as_object().is_none_or(|o| !o.is_empty()) {
                return Err(invalid("queryOptions must be set to {}"));
            }
        }
        let mut rows = Vec::new();
        let mut coins = self.available_coins(asof);
        coins.sort_by(|a, b| (&a.0.txid, a.0.vout).cmp(&(&b.0.txid, b.0.vout)));
        for (c, d) in coins {
            if d < min || d > max || (!filter.is_empty() && !filter.contains(&c.script)) {
                continue;
            }
            let mut o = J::obj()
                .with("txid", c.txid.clone())
                .with("vout", c.vout)
                .with("generated", c.coinbase);
            if let Some(a) = script_address(self.network, &c.script) {
                o.push("address", J::Str(a));
            }
            o.push("scriptPubKey", J::Str(hex::encode(&c.script)));
            o.push("amount", J::Amount(c.value));
            o.push("amountZat", J::Int(c.value));
            o.push("confirmations", J::Int(d));
            o.push("spendable", J::Bool(true));
            rows.push(o);
        }
        Ok(J::Arr(rows))
    }

    /// `gettransaction "txid" ( includeWatchonly verbose asOfHeight )`.
    fn gettransaction(&self, p: &[Value]) -> Result<J, RpcError> {
        arity("gettransaction", p, 4)?;
        let txid = p_str(p, 0)?.ok_or_else(|| {
            RpcError::new(
                code::MISC_ERROR,
                "gettransaction \"txid\" ( includeWatchonly verbose asOfHeight )",
            )
        })?;
        if p_bool(p, 2, false)? {
            return Err(invalid("Invalid parameter, verbose must be set to false"));
        }
        let asof = as_of(p, 3)?;
        let txid = txid.to_lowercase();
        if !self.st.wtx.contains_key(&txid) {
            if let Some(w) = self.st.evicted.get(&txid) {
                return Ok(self.evicted_tx(&txid, w));
            }
        }
        let (Some(w), Some(px)) = (self.st.wtx.get(&txid), self.parsed(&txid)) else {
            return Err(RpcError::new(
                code::INVALID_ADDRESS_OR_KEY,
                "Invalid or non-wallet transaction id",
            ));
        };
        let depth = self.tx_depth(&txid, asof);
        if depth < 0 {
            return Err(RpcError::new(
                code::INVALID_ADDRESS_OR_KEY,
                "Invalid or non-wallet transaction id",
            ));
        }
        let debit = self.debit(&txid);
        let credit: i64 = if self.immature(px.coinbase, depth) {
            0
        } else {
            px.tx
                .vout
                .iter()
                .filter(|o| self.book.owns_script(&o.script_pubkey).is_some())
                .map(|o| o.value)
                .sum()
        };
        let vout_total: i64 = px.tx.vout.iter().map(|o| o.value).sum();
        let fee = if debit > 0 {
            debit - vout_total + px.tx.shielded.value_balance
        } else {
            0
        };
        let amount = credit - debit + fee;
        let mut o = J::obj()
            .with("version", px.tx.version() as i64)
            .with("amount", J::Amount(amount))
            .with("amountZat", amount);
        if debit > 0 {
            o.push("fee", J::Amount(-fee));
        }
        o.push("confirmations", J::Int(depth));
        if px.coinbase {
            o.push("generated", J::Bool(true));
        }
        if depth > 0 {
            if let Some(b) = &w.block {
                o.push("blockhash", J::Str(b.hash.clone()));
                o.push("blockindex", J::Int(b.index as i64));
                o.push("blocktime", J::Int(b.time));
            }
        }
        o.push("expiryheight", J::Int(px.tx.expiry_height as i64));
        o.push(
            "status",
            J::Str(self.status(px.tx.expiry_height, depth).into()),
        );
        o.push("txid", J::Str(txid.clone()));
        o.push("walletconflicts", J::Arr(vec![]));
        o.push("time", J::Int(w.time_received));
        o.push("timereceived", J::Int(w.time_received));
        o.push("vjoinsplit", J::Arr(vec![]));
        let mut details = Vec::new();
        let size = px.size as i64;
        for (n, out) in px.tx.vout.iter().enumerate() {
            let mine = self.book.owns_script(&out.script_pubkey).is_some();
            let address = script_address(self.network, &out.script_pubkey);
            if debit > 0 {
                if mine && !self.in_book(&out.script_pubkey) {
                    continue; // change
                }
                let mut d = J::obj();
                if let Some(a) = &address {
                    d.push("address", J::Str(a.clone()));
                }
                d.push("category", J::Str("send".into()));
                d.push("amount", J::Amount(-out.value));
                d.push("amountZat", J::Int(-out.value));
                d.push("vout", J::Int(n as i64));
                d.push("fee", J::Amount(-fee));
                d.push("size", J::Int(size));
                details.push(d);
            }
            if mine {
                let category = if px.coinbase {
                    if depth < 1 {
                        "orphan"
                    } else if self.immature(true, depth) {
                        "immature"
                    } else {
                        "generate"
                    }
                } else {
                    "receive"
                };
                let mut d = J::obj();
                if let Some(a) = &address {
                    d.push("address", J::Str(a.clone()));
                }
                d.push("category", J::Str(category.into()));
                d.push("amount", J::Amount(out.value));
                d.push("amountZat", J::Int(out.value));
                d.push("vout", J::Int(n as i64));
                d.push("size", J::Int(size));
                details.push(d);
            }
        }
        o.push("details", J::Arr(details));
        o.push("hex", J::Str(w.hex.clone()));
        Ok(o)
    }

    /// The `status` of `gettransaction` (`mined`, `waiting`, `expiringsoon`, `expired`).
    /// `gettransaction` of an own transaction the node no longer holds (evicted or expired from
    /// the mempool, never mined): depth 0, its status by its expiry height, its bytes.
    fn evicted_tx(&self, txid: &str, w: &crate::state::WalletTx) -> J {
        let expiry = crate::build::parse_hex_tx(&w.hex)
            .map(|t| t.expiry_height)
            .unwrap_or(0);
        J::obj()
            .with("confirmations", 0i64)
            .with("expiryheight", expiry as i64)
            .with("status", self.status(expiry, 0))
            .with("txid", txid.to_string())
            .with("walletconflicts", J::Arr(vec![]))
            .with("time", w.time_received)
            .with("timereceived", w.time_received)
            .with("vjoinsplit", J::Arr(vec![]))
            .with("details", J::Arr(vec![]))
            .with("hex", w.hex.clone())
    }

    /// `yed_gettxinfo` of an own transaction with a payload the node has no trace of (§4.6 / N39):
    /// ycashd's `TxLogToJSON(..., expired=true)` once it is past its expiry height, else `None`.
    pub fn expired_txinfo(&self, txid: &str) -> Option<String> {
        let txid = txid.to_lowercase();
        if self.st.wtx.contains_key(&txid) {
            return None;
        }
        let hex = self
            .st
            .expired
            .get(&txid)
            .cloned()
            .or_else(|| self.st.evicted.get(&txid).map(|w| w.hex.clone()))?;
        let t = crate::build::parse_hex_tx(&hex)?;
        if t.expiry_height == 0 || t.expiry_height as i64 > self.tip_height() as i64 {
            return None;
        }
        let fp = yew_core::payload::find_payload(&t)?;
        let typ = fp.payload.payload_type();
        let redeem = typ == yew_core::payload::PayloadType::Redeem;
        let carrier_vin = t
            .vin
            .iter()
            .enumerate()
            .find(|(i, v)| {
                !(redeem && *i == 0)
                    && yew_core::script::parse_carrier_script_sig(&v.script_sig).is_some()
            })
            .map(|(i, _)| i as i64);
        let o = J::obj()
            .with("txid", txid)
            .with("height", -1i64)
            .with("type", typ.name())
            .with("path", "")
            .with("verdict", "expired")
            .with("yedIn", 0i64)
            .with("yedOut", 0i64)
            .with("burned", 0i64)
            .with("feeZat", 0i64)
            .with("payee", J::Null)
            .with("assigned", J::Arr(vec![]))
            .with("spentTokens", J::Arr(vec![]))
            .with("closedVaults", J::Arr(vec![]))
            .with("reopenedVaults", J::Arr(vec![]))
            .with("expired", true)
            .with("xMint", J::Null)
            .with("xClaim", J::Null)
            .with("aMint", J::Null)
            .with("aClaim", J::Null)
            .with("pMint", J::Null)
            .with("pClaim", J::Null)
            .with("bundleSeqs", J::Arr(vec![]))
            .with("attestFeeZat", 0i64)
            .with("attestPayee", J::Null)
            .with("residualZat", 0i64)
            .with("claimPath", "")
            .with("notice", false)
            .with("carrierVin", carrier_vin.unwrap_or(-1))
            .with(
                "bundleSource",
                if carrier_vin.is_some() {
                    "scriptsig"
                } else {
                    ""
                },
            );
        Some(o.text())
    }

    pub(crate) fn status(&self, expiry: u32, depth: i64) -> &'static str {
        if depth > 0 {
            return "mined";
        }
        let next = self.tip_height() + 1;
        if expiry != 0 && expiry < next {
            "expired"
        } else if expiry != 0 && expiry <= next + 3 {
            "expiringsoon"
        } else {
            "waiting"
        }
    }

    /// `getwalletinfo`.
    fn getwalletinfo(&self, p: &[Value]) -> Result<J, RpcError> {
        arity("getwalletinfo", p, 1)?;
        // One pass (ycashd's GetWalletBalanceSplit, beta2 item 15): balance = the available
        // credit of every trusted transaction, unconfirmed = that of every untrusted one in the
        // mempool, each with its post-quantum part by scheme.
        let (mut balance, mut unconfirmed) = (0i64, 0i64);
        let (mut pq_bal, mut pq_unc) = ([0i64; 3], [0i64; 3]);
        for t in self.st.wtx.keys() {
            let (sum, into) = if self.trusted(t, None) {
                (&mut balance, &mut pq_bal)
            } else if self.tx_depth(t, None) == 0 {
                (&mut unconfirmed, &mut pq_unc)
            } else {
                continue;
            };
            let (credit, pq) = self.available_credit_split(t, None);
            *sum += credit;
            for (a, b) in into.iter_mut().zip(pq) {
                *a += b;
            }
        }
        let pq_total = |v: &[i64; 3]| v[1] + v[2];
        let by_scheme = J::Arr(
            PQ_BALANCE_SCHEMES
                .iter()
                .map(|&s| {
                    J::obj()
                        .with("pqscheme", s as i64)
                        .with("pqschemename", pq_scheme_name(s))
                        .with("balance_pq", J::Amount(pq_bal[s as usize]))
                        .with("unconfirmed_balance_pq", J::Amount(pq_unc[s as usize]))
                })
                .collect(),
        );
        let immature: i64 = self
            .coins
            .iter()
            .filter(|c| {
                c.coinbase && !c.spent && {
                    let d = self.depth(c.height);
                    d >= 1 && self.immature(true, d)
                }
            })
            .map(|c| c.value)
            .sum();
        let (shielded, shielded_unconfirmed) = self.shielded_balances();
        let o = J::obj()
            .with("walletversion", 60_000i64)
            .with("balance", J::Amount(balance))
            .with("unconfirmed_balance", J::Amount(unconfirmed))
            .with("immature_balance", J::Amount(immature))
            // the split by address type (beta2 item 15): ECC = the figure minus its PQ part
            .with("balance_ecc", J::Amount(balance - pq_total(&pq_bal)))
            .with("balance_pq", J::Amount(pq_total(&pq_bal)))
            .with(
                "unconfirmed_balance_ecc",
                J::Amount(unconfirmed - pq_total(&pq_unc)),
            )
            .with("unconfirmed_balance_pq", J::Amount(pq_total(&pq_unc)))
            .with("pq_by_scheme", by_scheme)
            .with("shielded_balance", format_money(shielded))
            .with(
                "shielded_unconfirmed_balance",
                format_money(shielded_unconfirmed),
            )
            .with("txcount", self.st.wtx.len())
            .with("keypoololdest", self.st.created)
            .with("keypoolsize", crate::keys::LOOKAHEAD);
        let mut o = o;
        let (enc, until) = self.signer_state();
        if enc {
            o.push("unlocked_until", J::Int(until));
        }
        o.push("paytxfee", J::Amount(self.opts.paytxfee));
        o.push("mnemonic_seedfp", J::Str(self.st.public.seed_fp.clone()));
        if !self.st.public.imported.is_empty()
            || self
                .st
                .public
                .pq
                .iter()
                .any(|k| k.index >= yewd_proto::IMPORTED_PQ_BASE)
        {
            o.push("has_external_imports", J::Bool(true));
            o.push("external_imports_warning", J::Str("Wallet contains keys imported from outside the ZIP-32 derivation tree. Restoring from the emergency recovery phrase alone will NOT recover funds at these addresses. Back up wallet.dat or run z_exportwallet to preserve the imported keys.".into()));
        }
        Ok(o)
    }

    fn shielded_balances(&self) -> (i64, i64) {
        let mut confirmed = 0i64;
        let mut unconfirmed = 0i64;
        for n in self.notes.iter().filter(|n| !n.spent) {
            if self.depth(n.height) >= 1 {
                confirmed += n.value as i64;
            } else {
                unconfirmed += n.value as i64;
            }
        }
        (confirmed, unconfirmed)
    }

    /// `getreceivedbyaddress "address" ( minconf inZat asOfHeight )`.
    fn getreceivedbyaddress(&self, p: &[Value]) -> Result<J, RpcError> {
        arity("getreceivedbyaddress", p, 4)?;
        let a = p_str(p, 0)?.ok_or_else(|| {
            RpcError::new(
                code::MISC_ERROR,
                "getreceivedbyaddress \"address\" ( minconf inZat asOfHeight )",
            )
        })?;
        let script = parse_taddr_script(self.network, a)
            .ok_or_else(|| RpcError::new(code::INVALID_ADDRESS_OR_KEY, "Invalid Ycash address"))?;
        let asof = as_of(p, 3)?;
        let min = minconf(p, 1, 1)?;
        let mut total = 0i64;
        if self.book.owns_script(&script).is_some() {
            for (t, px) in self.parsed_all() {
                if px.coinbase || self.tx_depth(t, asof) < min {
                    continue;
                }
                total += px
                    .tx
                    .vout
                    .iter()
                    .filter(|o| o.script_pubkey == script)
                    .map(|o| o.value)
                    .sum::<i64>();
            }
        }
        Ok(if p_bool(p, 2, false)? {
            J::Int(total)
        } else {
            J::Amount(total)
        })
    }

    /// `listlockunspent`.
    fn listlockunspent(&self, p: &[Value]) -> Result<J, RpcError> {
        arity("listlockunspent", p, 0)?;
        Ok(J::Arr(
            self.st
                .locks
                .iter()
                .filter_map(|l| l.split_once(':'))
                .map(|(t, n)| {
                    J::obj()
                        .with("txid", t)
                        .with("vout", n.parse::<i64>().unwrap_or(0))
                })
                .collect(),
        ))
    }

    // ------------------------------------------------------------------ addresses

    /// The wallet's first Sapling address (diversifier index 0 or the next valid one), for a
    /// coinbase that must name no YED payout key (`yewd -initwallet`, F-S5-9).
    pub fn sapling_coinbase_address(&self) -> Option<String> {
        self.view.address_at(0).map(|(_, a)| a)
    }

    /// A seed restored from `-mnemonicfile`: issue the first Sapling address before the rescan,
    /// as ycashd's review B-1 does (`GenerateNewLegacySaplingZKey`, `wallet.cpp`), so a wallet
    /// with one z-address restores it and its notes. A no-op when one is issued already.
    pub fn restore_first_sapling(&mut self) -> Result<(), String> {
        if !self.st.issued.sapling.is_empty() {
            return Ok(());
        }
        if let Some((j, _)) = self.view.address_at(0) {
            self.st.issued.sapling.push(j);
            self.persist().map_err(|e| e.message)?;
        }
        Ok(())
    }

    pub(crate) fn vault_active_next(&self) -> bool {
        self.chain
            .vault_activation
            .is_some_and(|h| h <= self.tip_height() + 1)
    }

    /// The holder policy (quantum spec A-13): FN-DSA-512 once Falcon is active at the next block.
    pub(crate) fn falcon_next(&self) -> bool {
        match self.chain.falcon_active {
            Some(f) => f,
            // mainnet and testnet run Falcon from the vault activation (D-Q-2); regtest only with
            // -pqfalconheight, which the node reports in yed_getinfo
            None => match crate::falcon_height() {
                // regtest -pqfalconheight: from that height, with the vault upgrade (IsPQFalconActive)
                Some(h) => self.vault_active_next() && (self.tip_height() as i64 + 1) >= h,
                None => {
                    self.network != yew_core::params::Network::Regtest && self.vault_active_next()
                }
            },
        }
    }

    /// Hand out the next PQ key of `scheme`.
    pub(crate) fn new_pq(&mut self, scheme: u8) -> Result<PqKeyId, RpcError> {
        let index = self.st.pq_issued(scheme);
        self.st.set_pq_issued(scheme, index + 1);
        self.refresh_keys().map_err(|e| {
            RpcError::new(
                code::WALLET_ERROR,
                format!("cannot derive a post-quantum key ({e})"),
            )
        })?;
        let id = self
            .book
            .pq_key(scheme, index)
            .map(|k| k.id)
            .ok_or_else(|| {
                RpcError::new(
                    code::WALLET_ERROR,
                    "cannot derive a post-quantum key (the signer did not provide it)",
                )
            })?;
        Ok(id)
    }

    fn new_external(&mut self) -> Result<[u8; 20], RpcError> {
        let index = self.st.issued.external;
        self.st.issued.external = index + 1;
        self.refresh_keys()
            .map_err(|e| RpcError::new(code::WALLET_ERROR, e))?;
        Ok(self
            .book
            .key(EXTERNAL, index)
            .expect("derived by refresh_keys")
            .hash)
    }

    fn persist(&self) -> Result<(), RpcError> {
        self.save()
            .map_err(|e| RpcError::new(code::WALLET_ERROR, e))
    }

    /// `getnewaddress ( "type" )` or `getnewaddress ( "" "type" )` (beta2 item 10, ycash6
    /// c33854654 / ycash-dd#164): the first slot is the address type or the old placeholder `""`;
    /// a type given first takes no second argument; any other first string, a type name in
    /// another case too, is refused with the node's "Accounts are unsupported" error. The
    /// arguments are judged before any key is issued.
    fn getnewaddress(&mut self, p: &[Value]) -> Result<J, RpcError> {
        arity("getnewaddress", p, 2)?;
        let second = p.get(1).filter(|v| !v.is_null());
        let typ = match p_str(p, 0)? {
            Some(t @ ("p2pkh" | "pq" | "pqslh")) => {
                if second.is_some() {
                    return Err(invalid(
                        "the address type is given first, so there is no second argument (getnewaddress pq, or getnewaddress \"\" pq)",
                    ));
                }
                t
            }
            Some(d) if !d.is_empty() => {
                return Err(RpcError::new(
                    code::WALLET_ACCOUNTS_UNSUPPORTED,
                    "Accounts are unsupported; the first argument is the address type, \"p2pkh\", \"pq\" or \"pqslh\" (lower case), or \"\" followed by the type",
                ));
            }
            _ => p_str(p, 1)?.unwrap_or("p2pkh"),
        };
        if typ == "pq" || typ == "pqslh" {
            if !self.vault_active_next() {
                return Err(invalid(
                    "post-quantum addresses need the vault upgrade active at the next block",
                ));
            }
            let scheme = if typ == "pq" && self.falcon_next() {
                2
            } else {
                1
            };
            let id = self.new_pq(scheme)?;
            let addr = ykeys::encode_pq_yec(self.network, &id).expect("a registered scheme");
            self.st.book.insert(
                addr.clone(),
                BookEntry {
                    label: String::new(),
                    purpose: "receive".into(),
                },
            );
            self.persist()?;
            return Ok(J::Str(addr));
        }
        if typ != "p2pkh" {
            return Err(invalid("type must be \"p2pkh\", \"pq\" or \"pqslh\""));
        }
        let h = self.new_external()?;
        let addr = ykeys::encode_p2pkh(self.network, &h);
        self.st.book.insert(
            addr.clone(),
            BookEntry {
                label: String::new(),
                purpose: "receive".into(),
            },
        );
        self.persist()?;
        Ok(J::Str(addr))
    }

    /// `z_getnewaddress ( type )`: a diversified address of the one Sapling account.
    fn z_getnewaddress(&mut self, p: &[Value]) -> Result<J, RpcError> {
        arity("z_getnewaddress", p, 1)?;
        let typ = p_str(p, 0)?.unwrap_or("sapling");
        if typ != "sapling" {
            return Err(invalid("Invalid address type"));
        }
        let from = self.st.issued.sapling.last().map(|j| j + 1).unwrap_or(0);
        let (j, addr) = self
            .view
            .address_at(from)
            .ok_or_else(|| RpcError::new(code::WALLET_ERROR, "no valid diversifier left"))?;
        self.st.issued.sapling.push(j);
        self.persist()?;
        Ok(J::Str(addr))
    }

    /// `vault_getnewowner ( scheme )` (`rpc/vault.cpp`).
    fn vault_getnewowner(&mut self, p: &[Value]) -> Result<J, RpcError> {
        arity("vault_getnewowner", p, 1)?;
        let scheme = p_int(p, 0, 1)?;
        if !(0..=255).contains(&scheme) {
            return Err(invalid("unknown post-quantum scheme"));
        }
        let scheme = scheme as u8;
        if !yew_core::pq::is_known_scheme(scheme) {
            return Err(invalid(format!(
                "unknown post-quantum scheme {scheme} (1 = SLH-DSA-SHA2-128s, 2 = FN-DSA-512)"
            )));
        }
        if scheme == 2 && !self.falcon_next() {
            return Err(invalid(
                "scheme 2 (FN-DSA-512) is not active at the next block",
            ));
        }
        let id = self.new_pq(scheme)?;
        self.st.owners.insert(pqkeyid_hex(&id));
        self.persist()?;
        Ok(J::obj()
            .with("scheme", scheme as i64)
            .with("keyhash", hash_hex(&id.hash))
            .with("owner", pqkeyid_hex(&id))
            .with(
                "address",
                ykeys::encode_pq_yellowback(self.network, &id).unwrap_or_default(),
            ))
    }

    /// `set_listsigned`: the sign-once records live with the member keys, in the signer (K-24).
    fn set_listsigned(&self, p: &[Value]) -> Result<J, RpcError> {
        if !p.is_empty() {
            return Err(RpcError::new(code::MISC_ERROR, "set_listsigned"));
        }
        let r = self.signed_records()?;
        Ok(crate::vaultrpc::records_json(&r))
    }

    // ------------------------------------------------------------------ Sapling

    /// `z_getbalance "address" ( minconf inZat )`.
    fn z_getbalance(&self, p: &[Value]) -> Result<J, RpcError> {
        arity("z_getbalance", p, 3)?;
        let a = p_str(p, 0)?.unwrap_or("");
        let min = minconf(p, 1, 1)?;
        // A transparent address, ECC or post-quantum (beta2 item 15, finding L-3: a PQ address of
        // the wallet answers its balance), that the wallet does not hold is refused (the lead
        // architect's decision 2026-11-11, ycash-dd 322be29c5); a foreign Sapling address keeps
        // ycashd 6.x's string.
        let total: i64 = if let Some(script) = parse_taddr_script(self.network, a) {
            if self.book.owns_script(&script).is_none() {
                return Err(RpcError::new(
                    code::INVALID_ADDRESS_OR_KEY,
                    "From address does not belong to this node, transparent or post-quantum key or watch-only script not found.",
                ));
            }
            self.available_coins(None)
                .into_iter()
                .filter(|(c, d)| c.script == script && *d >= min)
                .map(|(c, _)| c.value)
                .sum()
        } else if yew_core::shielded_keys::is_sapling_address(self.network, a) {
            if self.view.owns_address(a).is_none() {
                return Err(RpcError::new(
                    code::INVALID_ADDRESS_OR_KEY,
                    "From address does not belong to this node.",
                ));
            }
            self.notes
                .iter()
                .filter(|n| {
                    !n.spent && !n.internal && n.address == a && self.depth(n.height) >= min
                })
                .map(|n| n.value as i64)
                .sum()
        } else {
            return Err(RpcError::new(
                code::INVALID_ADDRESS_OR_KEY,
                "Invalid from address, should be a taddr or zaddr.",
            ));
        };
        Ok(if p_bool(p, 2, false)? {
            J::Int(total)
        } else {
            J::Amount(total)
        })
    }

    /// `z_listunspent ( minconf maxconf includeWatchonly ["zaddr",...] asOfHeight )`.
    fn z_listunspent(&self, p: &[Value]) -> Result<J, RpcError> {
        arity("z_listunspent", p, 5)?;
        let min = minconf(p, 0, 1)?;
        let max = p_int(p, 1, 9_999_999)?;
        if max < min {
            return Err(invalid("Maximum number of confirmations must be greater or equal to the minimum number of confirmations"));
        }
        let _watch = p_bool(p, 2, false)?;
        let mut filter: BTreeSet<String> = BTreeSet::new();
        if let Some(a) = param(p, 3) {
            let arr = a
                .as_array()
                .ok_or_else(|| RpcError::new(code::TYPE_ERROR, "Expected type array"))?;
            if arr.is_empty() {
                return Err(invalid("Invalid parameter, addresses array is empty."));
            }
            for v in arr {
                let s = v
                    .as_str()
                    .ok_or_else(|| invalid("Invalid parameter, expected string"))?;
                if !yew_core::shielded_keys::is_sapling_address(self.network, s) {
                    return Err(invalid(format!(
                        "Invalid parameter, not a valid Ycash address: {s}"
                    )));
                }
                if self.view.owns_address(s).is_none() {
                    return Err(invalid("Invalid parameter, spending key for an address does not belong to the wallet."));
                }
                filter.insert(s.to_string());
            }
        }
        let mut rows = Vec::new();
        let mut notes: Vec<_> = self.notes.iter().filter(|n| !n.spent).collect();
        notes.sort_by(|a, b| (&a.txid, a.outindex).cmp(&(&b.txid, b.outindex)));
        for n in notes {
            let d = self.depth(n.height);
            if d < min || d > max || (!filter.is_empty() && !filter.contains(&n.address)) {
                continue;
            }
            let mut o = J::obj()
                .with("txid", n.txid.clone())
                .with("pool", "sapling")
                .with("type", "sapling")
                .with("outindex", n.outindex)
                .with("confirmations", d)
                // spendable: ycashd's "has the spending key"; the key is the signer's (K-24)
                .with("spendable", true);
            if !n.internal {
                o.push("address", J::Str(n.address.clone()));
            }
            o.push("amount", J::Amount(n.value as i64));
            o.push("memo", J::Str(hex::encode(n.memo)));
            if let Some(s) = memo_str(&n.memo) {
                o.push("memoStr", J::Str(s));
            }
            o.push("change", J::Bool(n.internal));
            rows.push(o);
        }
        Ok(J::Arr(rows))
    }

    // ------------------------------------------------------------------ YED

    /// The wallet's holder scripts: P2PKH to every held key, `TX_PQPKH` to every held PQ key
    /// (ycashd's `YellowbackWallet::IsMineScript`).
    fn holder_scripts(&self) -> Vec<Vec<u8>> {
        let mut v: Vec<Vec<u8>> = self
            .book
            .tkeys
            .iter()
            .map(|k| yew_core::script::p2pkh_script(&k.hash))
            .collect();
        v.extend(
            self.book
                .pq
                .values()
                .filter_map(|k| yew_core::pq::pqpkh_script(&k.id)),
        );
        v
    }

    /// The YED tokens at this wallet's holder scripts, from the node's index (`yed_listtokens`,
    /// at most 100 addresses a call). Only the scripts that ever received an output are asked
    /// about (a token output is an output to the script, so the wallet has seen it).
    pub(crate) async fn tokens(&self, node: &dyn Node) -> Result<Vec<Value>, RpcError> {
        let used: BTreeSet<Vec<u8>> = self.coins.iter().map(|c| c.script.clone()).collect();
        let addrs: Vec<String> = self
            .holder_scripts()
            .into_iter()
            .filter(|s| used.contains(s))
            .filter_map(|s| yed_address(self.network, &s))
            .collect();
        let mut out = Vec::new();
        for chunk in addrs.chunks(100) {
            let v = node::call(
                node,
                "yed_listtokens",
                serde_json::json!([chunk, 0, 1_000_000, 0]),
            )
            .await?;
            out.extend(v.as_array().cloned().unwrap_or_default());
        }
        Ok(out)
    }

    /// The scripts at which the node's Yellowback index holds a YED token of this wallet (ycashd's
    /// `YedHolderScripts`, beta2: the `yed_holder` mark of `listreceivedbyaddress` and
    /// `validateaddress`). Empty when the node serves no `yed_*` (no `-yellowback`).
    pub(crate) async fn yed_holder_scripts(&self, node: &dyn Node) -> BTreeSet<Vec<u8>> {
        let Ok(tokens) = self.tokens(node).await else {
            return BTreeSet::new();
        };
        tokens
            .iter()
            .filter_map(|t| {
                let txid = t["txid"].as_str()?;
                let vout = t["vout"].as_u64()? as u32;
                self.coins
                    .iter()
                    .find(|c| c.txid == txid && c.vout == vout)
                    .map(|c| c.script.clone())
            })
            .collect()
    }

    /// The node's Yellowback index height (`yed_getinfo.height`) and its Falcon flag.
    async fn yed_info(&mut self, node: &dyn Node) -> Result<i64, RpcError> {
        let info = node::call(node, "yed_getinfo", serde_json::json!([])).await?;
        if let Some(f) = info["params"]["pq"]["falconActive"].as_bool() {
            self.chain.falcon_active = Some(f);
        }
        Ok(info["height"].as_i64().unwrap_or(self.tip_height() as i64))
    }

    /// Outpoints the wallet's own mempool transactions spend.
    pub fn mempool_spent(&self) -> BTreeSet<(String, u32)> {
        self.parsed_all()
            .filter(|(t, _)| self.tx_depth(t, None) == 0)
            .flat_map(|(_, p)| {
                p.tx.vin
                    .iter()
                    .map(|i| (txid_hex(&i.prevout.txid), i.prevout.n))
            })
            .collect()
    }

    /// `yed_getnewaddress ( "type" "label" )`.
    async fn yed_getnewaddress(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        arity("yed_getnewaddress", p, 2)?;
        self.yed_info(node).await?;
        let falcon = self.falcon_next();
        let mut typ = p_str(p, 0)?.unwrap_or("").to_string();
        if typ.is_empty() {
            typ = if falcon { "pq".into() } else { "p2pkh".into() };
        }
        let label = p_str(p, 1)?.unwrap_or("").to_string();
        if typ == "pqowner" && !label.is_empty() {
            return Err(invalid(
                "a \"pqowner\" key stays out of the address book, so it takes no label",
            ));
        }
        if typ == "pq" || typ == "pqowner" {
            let scheme = if typ == "pq" && falcon { 2 } else { 1 };
            let id = self.new_pq(scheme)?;
            if typ == "pq" {
                let book_addr = ykeys::encode_pq_yec(self.network, &id).expect("registered");
                self.st.book.insert(
                    book_addr,
                    BookEntry {
                        label,
                        purpose: "yed".into(),
                    },
                );
            } else {
                self.st.owners.insert(pqkeyid_hex(&id));
            }
            self.persist()?;
            return Ok(J::Str(
                ykeys::encode_pq_yellowback(self.network, &id).expect("registered"),
            ));
        }
        if typ != "p2pkh" {
            return Err(invalid("type must be \"p2pkh\", \"pq\" or \"pqowner\""));
        }
        let h = self.new_external()?;
        self.st.book.insert(
            ykeys::encode_p2pkh(self.network, &h),
            BookEntry {
                label,
                purpose: "yed".into(),
            },
        );
        self.persist()?;
        Ok(J::Str(ykeys::encode_yellowback(self.network, &h)))
    }

    /// `yed_validateaddress "address"`: never throws for a bad address.
    async fn yed_validateaddress(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        if p.len() != 1 {
            return Err(RpcError::new(
                code::MISC_ERROR,
                "yed_validateaddress \"address\"",
            ));
        }
        // the command exists only where the node runs the module (as on ycashd)
        self.yed_info(node).await?;
        let a = p_str(p, 0)?.unwrap_or("");
        let mut o = J::obj();
        if let Ok(id) = ykeys::parse_pq_address(self.network, a) {
            o.push("isvalid", J::Bool(true));
            o.push("address", J::Str(a.into()));
            o.push("type", J::Str("pq".into()));
            o.push("keyid", J::Str(pqkeyid_hex(&id)));
            o.push("pqscheme", J::Int(id.scheme as i64));
            o.push("ismine", J::Bool(self.book.pq_by_id(&id).is_some()));
            o.push(
                "transparentAddress",
                J::Str(ykeys::encode_pq_yec(self.network, &id).unwrap_or_default()),
            );
        } else if let Some(h) = parse_yed_p2pkh(self.network, a) {
            o.push("isvalid", J::Bool(true));
            o.push("address", J::Str(a.into()));
            o.push("type", J::Str("p2pkh".into()));
            let mut keyid = h;
            keyid.reverse(); // uint160::GetHex
            o.push("keyid", J::Str(hex::encode(keyid)));
            o.push("ismine", J::Bool(self.book.by_hash(&h).is_some()));
            o.push(
                "transparentAddress",
                J::Str(ykeys::encode_p2pkh(self.network, &h)),
            );
        } else {
            o.push("isvalid", J::Bool(false));
        }
        let valid =
            matches!(&o, J::Obj(v) if v.iter().any(|(k, v)| k == "isvalid" && *v == J::Bool(true)));
        o.push(
            "reason",
            J::Str(
                if valid {
                    ""
                } else {
                    "not-a-yellowback-address"
                }
                .into(),
            ),
        );
        Ok(o)
    }

    /// `yed_getbalance`.
    async fn yed_getbalance(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        arity("yed_getbalance", p, 1)?;
        let height = self.yed_info(node).await?;
        let tokens = self.tokens(node).await?;
        let confirmed: i64 = tokens.iter().filter_map(|t| t["cents"].as_i64()).sum();
        let spent = self.mempool_spent();
        let spendable: i64 = tokens
            .iter()
            .filter(|t| {
                let k = (
                    t["txid"].as_str().unwrap_or("").to_string(),
                    t["vout"].as_u64().unwrap_or(0) as u32,
                );
                !spent.contains(&k)
            })
            .filter_map(|t| t["cents"].as_i64())
            .sum();
        // mempool transactions that assign YED to this wallet (MINT vout 1; TRANSFER / REDEEM assignments)
        let mut unconfirmed = 0i64;
        for (t, px) in self.parsed_all() {
            if self.tx_depth(t, None) != 0 {
                continue;
            }
            let Some(fp) = yew_core::payload::find_payload(&px.tx) else {
                continue;
            };
            match &fp.payload {
                yew_core::payload::Payload::Mint { cents, .. } => {
                    if px
                        .tx
                        .vout
                        .get(1)
                        .is_some_and(|o| self.book.owns_script(&o.script_pubkey).is_some())
                    {
                        unconfirmed += *cents as i64;
                    }
                }
                pl => {
                    for a in pl.assignments() {
                        if px
                            .tx
                            .vout
                            .get(a.vout as usize)
                            .is_some_and(|o| self.book.owns_script(&o.script_pubkey).is_some())
                        {
                            unconfirmed += a.cents as i64;
                        }
                    }
                }
            }
        }
        Ok(J::obj()
            .with("confirmedCents", confirmed)
            .with("spendableCents", spendable)
            .with("unconfirmedCents", unconfirmed)
            .with("height", height))
    }

    /// `yed_listunspent`.
    async fn yed_listunspent(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        arity("yed_listunspent", p, 1)?;
        let height = self.yed_info(node).await?;
        let tokens = self.tokens(node).await?;
        let spent = self.mempool_spent();
        let mut rows = Vec::new();
        for t in tokens {
            let txid = t["txid"].as_str().unwrap_or("").to_string();
            let vout = t["vout"].as_u64().unwrap_or(0) as u32;
            let h = t["height"].as_i64().unwrap_or(0);
            rows.push(
                J::obj()
                    .with("txid", txid.clone())
                    .with("vout", vout)
                    .with("cents", t["cents"].as_i64().unwrap_or(0))
                    .with("valueZat", t["valueZat"].as_i64().unwrap_or(0))
                    .with("address", t["address"].as_str().unwrap_or(""))
                    .with("height", h)
                    .with("confirmations", height - h + 1)
                    .with("spentUnconfirmed", spent.contains(&(txid.clone(), vout)))
                    .with("locked", self.st.locks.contains(&format!("{txid}:{vout}"))),
            );
        }
        Ok(J::Arr(rows))
    }

    /// The node's index record of a transaction (`yed_gettxinfo`), `None` when it has none.
    pub(crate) async fn txinfo(node: &dyn Node, txid: &str) -> Result<Option<Value>, RpcError> {
        match node::call(node, "yed_gettxinfo", serde_json::json!([txid])).await {
            Ok(v) => Ok(Some(v)),
            Err(NodeError::Rpc { code, .. }) if code != crate::code::METHOD_NOT_FOUND => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// The wallet transactions that touch YED (a payload, and an own output or input), with the
    /// index's record of each: `(txid, info, received cents, spent cents)`.
    async fn yed_history(
        &self,
        node: &dyn Node,
    ) -> Result<Vec<(String, Value, i64, i64, BTreeSet<Vec<u8>>)>, RpcError> {
        let mut assigned_cache: BTreeMap<String, Value> = BTreeMap::new();
        let mut rows = Vec::new();
        let has_payload = |t: &str| {
            self.parsed(t)
                .is_some_and(|p| yew_core::payload::find_payload(&p.tx).is_some())
        };
        let candidates: Vec<String> = self
            .parsed_all()
            .filter(|(t, px)| {
                self.tx_depth(t, None) >= 1
                    && !px.coinbase
                    && (yew_core::payload::find_payload(&px.tx).is_some()
                        // a claim's release or cancel spends the intent of an own claim
                        || px
                            .tx
                            .vin
                            .first()
                            .is_some_and(|i| has_payload(&txid_hex(&i.prevout.txid))))
            })
            .map(|(t, _)| t.clone())
            .collect();
        for txid in candidates {
            let Some(info) = Self::txinfo(node, &txid).await? else {
                continue;
            };
            let px = self.parsed(&txid).expect("candidate");
            let mut received = 0i64;
            let mut spent = 0i64;
            let mut touched: BTreeSet<Vec<u8>> = BTreeSet::new();
            for a in info["assigned"].as_array().cloned().unwrap_or_default() {
                let vout = a["vout"].as_u64().unwrap_or(u64::MAX) as usize;
                if let Some(o) = px.tx.vout.get(vout) {
                    if self.book.owns_script(&o.script_pubkey).is_some() {
                        received += a["cents"].as_i64().unwrap_or(0);
                        touched.insert(o.script_pubkey.clone());
                    }
                }
            }
            for s in info["spentTokens"].as_array().cloned().unwrap_or_default() {
                let st = s["txid"].as_str().unwrap_or("").to_string();
                let n = s["vout"].as_u64().unwrap_or(u64::MAX);
                let Some(prev) = self.parsed(&st) else {
                    continue;
                };
                let Some(o) = prev.tx.vout.get(n as usize) else {
                    continue;
                };
                if self.book.owns_script(&o.script_pubkey).is_none() {
                    continue;
                }
                touched.insert(o.script_pubkey.clone());
                if !assigned_cache.contains_key(&st) {
                    if let Some(v) = Self::txinfo(node, &st).await? {
                        assigned_cache.insert(st.clone(), v);
                    }
                }
                if let Some(pi) = assigned_cache.get(&st) {
                    spent += pi["assigned"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter(|x| x["vout"].as_u64() == Some(n))
                                .filter_map(|x| x["cents"].as_i64())
                                .sum::<i64>()
                        })
                        .unwrap_or(0);
                }
            }
            rows.push((txid, info, received, spent, touched));
        }
        Ok(rows)
    }

    /// `yed_listtransactions ( count skip )`: the index's history of this wallet, newest first.
    async fn yed_listtransactions(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        arity("yed_listtransactions", p, 2)?;
        let count = p_int(p, 0, 100)?;
        let skip = p_int(p, 1, 0)?;
        if count < 0 || skip < 0 {
            return Err(invalid("count and skip must be >= 0"));
        }
        let height = self.yed_info(node).await?;
        let tip = self.tip_height() as i64;
        // Plan A6: this wallet's carriers and what spent them (a carrier input is recognised by its
        // scriptSig; a spender with a payload is the main transaction, one without a sweep)
        #[derive(Default)]
        struct CarrierUse {
            main: Option<String>,
            main_live: bool,
            live: bool,
            live_payload: bool,
        }
        let mut uses: BTreeMap<(String, u32), CarrierUse> = BTreeMap::new();
        let mut carrier_of: BTreeMap<String, (String, u32)> = BTreeMap::new();
        for (txid, px) in self.parsed_all() {
            let carriers: Vec<(String, u32)> = px
                .tx
                .vin
                .iter()
                .filter(|i| yew_core::script::parse_carrier_script_sig(&i.script_sig).is_some())
                .map(|i| (txid_hex(&i.prevout.txid), i.prevout.n))
                .collect();
            if carriers.is_empty() {
                continue;
            }
            let live = true; // in the wallet: confirmed or in the node's mempool
            let payload = yew_core::payload::find_payload(&px.tx).is_some();
            for c in carriers {
                let u = uses.entry(c.clone()).or_default();
                if payload {
                    carrier_of.insert(txid.clone(), c.clone());
                    if u.main.is_none() || (live && !u.main_live) {
                        u.main = Some(txid.clone());
                        u.main_live = live;
                    }
                }
                if live {
                    u.live = true;
                    u.live_payload = payload;
                }
            }
        }
        for (txid, h) in &self.st.expired {
            if let Some(t) = crate::build::parse_hex_tx(h) {
                if yew_core::payload::find_payload(&t).is_some() {
                    for i in &t.vin {
                        if yew_core::script::parse_carrier_script_sig(&i.script_sig).is_some() {
                            let c = (txid_hex(&i.prevout.txid), i.prevout.n);
                            carrier_of.insert(txid.clone(), c.clone());
                            let u = uses.entry(c).or_default();
                            if u.main.is_none() {
                                u.main = Some(txid.clone());
                            }
                        }
                    }
                }
            }
        }
        for k in self.st.carriers.keys() {
            if let Some((t, n)) = k.split_once(':') {
                uses.entry((t.to_string(), n.parse().unwrap_or(0)))
                    .or_default();
            }
        }
        let outcome = |c: &(String, u32), u: &CarrierUse| -> String {
            if u.live {
                return if u.live_payload { "completed" } else { "swept" }.into();
            }
            let expiry = self
                .parsed(&c.0)
                .map(|p| p.tx.expiry_height as i64)
                .unwrap_or(0);
            if expiry != 0 && tip > expiry {
                "lapsed".into()
            } else {
                "pending".into()
            }
        };
        let carrier_fields = |o: J, txid: &str| -> J {
            match carrier_of.get(txid) {
                Some(c) => o
                    .with("carrierTxid", c.0.clone())
                    .with("mainTxid", txid.to_string())
                    .with("carrierOutcome", outcome(c, &uses[c])),
                None => o
                    .with("carrierTxid", "")
                    .with("mainTxid", "")
                    .with("carrierOutcome", ""),
            }
        };
        let history = self.yed_history(node).await?;
        // U-23: the vaults this wallet claimed (its claim burned its YED)
        let claimed_by_me: BTreeSet<String> = history
            .iter()
            .filter(|(_, info, _, spent, _)| {
                info["type"].as_str() == Some("redeem")
                    && info["verdict"].as_str() == Some("ok")
                    && info["path"].as_str() == Some("claim")
                    && *spent > 0
            })
            .flat_map(|(_, info, _, _, _)| {
                info["closedVaults"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|c| {
                        format!(
                            "{}:{}",
                            c["txid"].as_str().unwrap_or(""),
                            c["vout"].as_u64().unwrap_or(0)
                        )
                    })
            })
            .collect();
        let mut rows: Vec<(i64, J)> = Vec::new();
        for (txid, info, received, spent, _) in history {
            let px = self.parsed(&txid).expect("history");
            let typ_node = info["type"].as_str().unwrap_or("");
            let mut path = info["path"].as_str().unwrap_or("").to_string();
            let ok = info["verdict"].as_str() == Some("ok");
            let mint_mine = typ_node == "mint" && px.owned_templates.contains(&0);
            let closed: Vec<String> = info["closedVaults"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .iter()
                .map(|c| {
                    format!(
                        "{}:{}",
                        c["txid"].as_str().unwrap_or(""),
                        c["vout"].as_u64().unwrap_or(0)
                    )
                })
                .collect();
            let closed_mine = info["closedVaults"].as_array().is_some_and(|a| {
                a.iter().any(|c| {
                    let t = c["txid"].as_str().unwrap_or("");
                    let n = c["vout"].as_u64().unwrap_or(u64::MAX) as u32;
                    self.parsed(t)
                        .is_some_and(|pp| pp.owned_templates.contains(&n))
                })
            });
            let intent_spend = typ_node == "claim_release" || typ_node == "claim_cancel";
            let claimant_mine = closed.iter().any(|c| claimed_by_me.contains(c));
            if received == 0
                && spent == 0
                && !closed_mine
                && !mint_mine
                && !(intent_spend && claimant_mine)
            {
                continue;
            }
            let burned = info["burned"].as_i64().unwrap_or(0);
            let yed_out = info["yedOut"].as_i64().unwrap_or(0);
            let typ = if typ_node == "mint" {
                "mint"
            } else if intent_spend {
                path = "claim".into();
                let release = typ_node == "claim_release";
                match (claimant_mine, release) {
                    (true, true) => "claim_release",
                    (true, false) => "claim_cancel",
                    (false, true) => "claim_released",
                    (false, false) => "claim_cancelled",
                }
            } else if typ_node == "redeem" && ok && path == "claim" && spent > 0 {
                "claim"
            } else if closed_mine {
                if ok {
                    if path == "claim" {
                        "claimed"
                    } else {
                        "redeem"
                    }
                } else if path == "owner" {
                    "sweep"
                } else {
                    "claimed"
                }
            } else if spent > 0 && burned > 0 && yed_out == received {
                "burn"
            } else if spent > 0 {
                "send"
            } else {
                "receive"
            };
            let h = info["height"].as_i64().unwrap_or(-1);
            let time = self
                .st
                .wtx
                .get(&txid)
                .and_then(|w| w.block.as_ref().map(|b| b.time));
            let o = J::obj()
                .with("txid", txid.clone())
                .with("height", h)
                .with("confirmations", height - h + 1)
                .with("type", typ)
                .with("verdict", info["verdict"].as_str().unwrap_or(""))
                .with("path", path)
                .with("yedIn", info["yedIn"].as_i64().unwrap_or(0))
                .with("yedOut", yed_out)
                .with("burned", burned)
                .with("amountCents", received - spent)
                .with("feeZat", info["feeZat"].as_i64().unwrap_or(0))
                .with("payee", J::Raw(info["payee"].to_string()))
                .with("unbacked", false)
                .with("expired", false)
                .with("time", time);
            rows.push((h, carrier_fields(o, &txid)));
        }
        // own transactions with a payload that expired unmined, typed by the payload
        for (txid, h) in &self.st.expired {
            if self.st.wtx.contains_key(txid) {
                continue;
            }
            let Some(t) = crate::build::parse_hex_tx(h) else {
                continue;
            };
            if t.expiry_height == 0 || t.expiry_height as i64 > tip {
                continue;
            }
            let Some(fp) = yew_core::payload::find_payload(&t) else {
                continue;
            };
            let typ = match fp.payload.payload_type() {
                yew_core::payload::PayloadType::Mint => "mint",
                yew_core::payload::PayloadType::Redeem => {
                    let foreign = t.vin.first().is_some_and(|i| {
                        !self
                            .parsed(&txid_hex(&i.prevout.txid))
                            .is_some_and(|p| p.owned_templates.contains(&i.prevout.n))
                    });
                    if foreign {
                        "claim"
                    } else {
                        "redeem"
                    }
                }
                yew_core::payload::PayloadType::ClaimNotice => "notice",
                yew_core::payload::PayloadType::Equivocation => "equivocation",
                yew_core::payload::PayloadType::AttestorRegister => "register",
                yew_core::payload::PayloadType::AttestorRevive => "revive",
                yew_core::payload::PayloadType::Transfer => "send",
            };
            let o = J::obj()
                .with("txid", txid.clone())
                .with("height", -1i64)
                .with("confirmations", 0i64)
                .with("type", typ)
                .with("verdict", "expired")
                .with("path", "")
                .with("yedIn", 0i64)
                .with("yedOut", 0i64)
                .with("burned", 0i64)
                .with("amountCents", 0i64)
                .with("feeZat", 0i64)
                .with("payee", J::Null)
                .with("unbacked", false)
                .with("expired", true)
                .with("time", J::Null);
            rows.push((t.expiry_height as i64, carrier_fields(o, txid)));
        }
        // A6: a row for each own carrier its main transaction did not complete
        for (c, u) in &uses {
            let Some(cp) = self.parsed(&c.0) else {
                continue;
            };
            let oc = outcome(c, u);
            if oc == "completed" {
                continue;
            }
            let block = self.st.wtx.get(&c.0).and_then(|w| w.block.clone());
            let (h, conf, sort) = match &block {
                Some(b) => (b.height as i64, tip - b.height as i64 + 1, b.height as i64),
                None => (-1, 0, tip + 1),
            };
            let _ = cp;
            let o = J::obj()
                .with("txid", c.0.clone())
                .with("height", h)
                .with("confirmations", conf)
                .with("type", "carrier")
                .with("verdict", "")
                .with("path", "")
                .with("yedIn", 0i64)
                .with("yedOut", 0i64)
                .with("burned", 0i64)
                .with("amountCents", 0i64)
                .with("feeZat", 0i64)
                .with("payee", J::Null)
                .with("unbacked", false)
                .with("expired", false)
                .with("time", block.map(|b| J::Int(b.time)).unwrap_or(J::Null))
                .with("carrierTxid", c.0.clone())
                .with("mainTxid", u.main.clone().unwrap_or_default())
                .with("carrierOutcome", oc);
            rows.push((sort, o));
        }
        rows.sort_by(|a, b| b.0.cmp(&a.0));
        Ok(J::Arr(
            rows.into_iter()
                .skip(skip as usize)
                .take(count as usize)
                .map(|(_, o)| o)
                .collect(),
        ))
    }

    /// `yed_listaddresses ( includeEmpty )`.
    async fn yed_listaddresses(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        arity("yed_listaddresses", p, 1)?;
        let include_empty = p_bool(p, 0, false)?;
        self.yed_info(node).await?;
        #[derive(Default)]
        struct Entry {
            cents: i64,
            tx_count: i64,
            last_time: Option<i64>,
        }
        let mut by_script: BTreeMap<Vec<u8>, Entry> = BTreeMap::new();
        for t in self.tokens(node).await? {
            if let Some(s) = t["address"]
                .as_str()
                .and_then(|a| yed_script(self.network, a))
            {
                by_script.entry(s).or_default().cents += t["cents"].as_i64().unwrap_or(0);
            }
        }
        for (txid, _, _, _, touched) in self.yed_history(node).await? {
            let time = self
                .st
                .wtx
                .get(&txid)
                .and_then(|w| w.block.as_ref().map(|b| b.time));
            for s in touched {
                let e = by_script.entry(s).or_default();
                e.tx_count += 1;
                e.last_time = e.last_time.max(time);
            }
        }
        if include_empty {
            for (addr, e) in &self.st.book {
                if e.purpose != "yed" {
                    continue;
                }
                if let Some(s) = parse_taddr_script(self.network, addr) {
                    by_script.entry(s).or_default();
                }
            }
        }
        let mut out: BTreeMap<String, J> = BTreeMap::new();
        for (s, e) in by_script {
            let Some(address) = yed_address(self.network, &s) else {
                continue;
            };
            let label = self.address_book_label(&s).unwrap_or_default();
            out.insert(
                address.clone(),
                J::obj()
                    .with("address", address)
                    .with("label", label)
                    .with("confirmedCents", e.cents)
                    .with("txCount", e.tx_count)
                    .with("lastUsed", e.last_time),
            );
        }
        Ok(J::Arr(out.into_values().collect()))
    }

    /// `yed_listpositions ( status )`: the node's vault rows (`yed_getvault`) for every vault
    /// whose owner key the wallet holds, plus the wallet's own columns.
    async fn yed_listpositions(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        arity("yed_listpositions", p, 1)?;
        let status = p_str(p, 0)?.unwrap_or("").to_string();
        let h = self.yed_info(node).await?;
        // spendable YED (canClaim) and the early-redeem schedule (yed_getinfo params)
        let spent = self.mempool_spent();
        let tokens = self.tokens(node).await?;
        let spendable: i64 = tokens
            .iter()
            .filter(|t| {
                !spent.contains(&(
                    t["txid"].as_str().unwrap_or("").to_string(),
                    t["vout"].as_u64().unwrap_or(0) as u32,
                ))
            })
            .filter_map(|t| t["cents"].as_i64())
            .sum();
        let info = node::call(node, "yed_getinfo", serde_json::json!([])).await?;
        let mut rows = Vec::new();
        let mut skip = 0i64;
        loop {
            let page = node::call(
                node,
                "yed_listvaults",
                serde_json::json!([status.as_str(), 1000, skip]),
            )
            .await?;
            let arr = page.as_array().cloned().unwrap_or_default();
            if arr.is_empty() {
                break;
            }
            skip += arr.len() as i64;
            for v in arr {
                let owner = (
                    v["ownerScheme"].as_u64(),
                    v["ownerHash"].as_str().and_then(|h| hex::decode(h).ok()),
                );
                let (Some(scheme), Some(hash)) = owner else {
                    continue;
                };
                let Ok(hash) = <[u8; 32]>::try_from(hash) else {
                    continue;
                };
                if self
                    .book
                    .pq_by_id(&PqKeyId {
                        scheme: scheme as u8,
                        hash,
                    })
                    .is_none()
                {
                    continue;
                }
                let txid = v["txid"].as_str().unwrap_or("").to_string();
                let full = node::call(node, "yed_getvault", serde_json::json!([txid])).await?;
                let notice = can_notice(node, &full, h, &info).await?;
                rows.push(self.position_row(&full, h, spendable, &info, notice)?);
            }
            if !(skip as usize).is_multiple_of(1000) {
                break;
            }
        }
        Ok(J::Arr(rows))
    }

    fn position_row(
        &self,
        v: &Value,
        h: i64,
        spendable: i64,
        info: &Value,
        can_notice: bool,
    ) -> Result<J, RpcError> {
        let obj: BTreeMap<String, Box<RawValue>> = serde_json::from_str(&v.to_string())
            .map_err(|e| RpcError::new(code::MISC_ERROR, format!("yewd: yed_getvault: {e}")))?;
        let mut o = J::Obj(
            obj.into_iter()
                .map(|(k, r)| (k, J::Raw(r.get().to_string())))
                .collect(),
        );
        let st = v["status"].as_str().unwrap_or("");
        let open = st == "ACTIVE" || st == "VOID";
        let pending = v["spendPending"].as_bool().unwrap_or(false);
        // the owner branch opens at ownerHeight = refHeight + 1 (IT-1)
        let owner_height = v["refHeight"].as_i64().map(|r| r + 1).unwrap_or(i64::MAX);
        o.push("canRedeem", J::Bool(open && h >= owner_height && !pending));
        let early = if st == "ACTIVE" && h + 1 < v["lockHeight"].as_i64().unwrap_or(0) {
            let class = v["termClass"].as_str().unwrap_or("");
            let bps = info["params"]["classes"]
                .as_array()
                .and_then(|a| a.iter().find(|c| c["class"].as_str() == Some(class)))
                .and_then(|c| c["earlyRedeemFeeBps"].as_i64());
            match (bps, v["mintedCents"].as_u64(), v["pMint"].as_i64()) {
                (Some(bps), Some(cents), Some(p)) => {
                    yew_core::params::early_redeem_fee_zat(cents, bps, p)
                }
                _ => 0,
            }
        } else {
            0
        };
        o.push("earlyRedeemFeeZat", J::Int(early));
        let claimable = v["claimable"].as_bool().unwrap_or(false);
        let minted = v["mintedCents"].as_i64().unwrap_or(i64::MAX);
        o.push(
            "canClaim",
            J::Bool(claimable && spendable >= minted && !pending),
        );
        o.push("canNotice", J::Bool(can_notice));
        Ok(o)
    }

    // ------------------------------------------------------------------ augmented node reads

    /// Complete a node read with the wallet's fields. `result` is the node's `result` JSON text.
    pub async fn augment(
        &mut self,
        node: &dyn Node,
        method: &str,
        p: &[Value],
        result: &str,
    ) -> Result<String, RpcError> {
        let bad =
            |e: serde_json::Error| RpcError::new(code::MISC_ERROR, format!("yewd: {method}: {e}"));
        match method {
            "getinfo" => {
                let mut o = raw_obj(result).map_err(bad)?;
                let bal = J::Amount(self.balance(None, 0)).text();
                for (k, v) in [
                    ("walletversion", "60000".to_string()),
                    ("balance", bal),
                    ("keypoololdest", self.st.created.to_string()),
                    ("keypoolsize", crate::keys::LOOKAHEAD.to_string()),
                    ("paytxfee", J::Amount(self.opts.paytxfee).text()),
                ] {
                    o.insert(k.to_string(), v);
                }
                let (enc, until) = self.signer_state();
                if enc {
                    o.insert("unlocked_until".into(), until.to_string());
                }
                Ok(write_raw_obj(&o))
            }
            "yed_getinfo" => {
                // the wallet half of yed_getinfo (ENABLE_WALLET): the overlay's lock count (H10)
                // yed_getinfo never refuses while the index is unhealthy (its `healthy` says so);
                // when the YED outpoint set cannot be read, protectedByIndex is false: the count
                // below is then not a statement that nothing is held
                let mut o = raw_obj(result).map_err(bad)?;
                let (locked, protected) = match self.yed_reserved(node).await {
                    Ok(r) => (
                        r.into_iter()
                            .filter(|(t, n)| self.st.locks.contains(&format!("{t}:{n}")))
                            .count(),
                        true,
                    ),
                    Err(_) => (0, false),
                };
                o.insert("lockedOutputs".into(), locked.to_string());
                o.insert("protectedByIndex".into(), protected.to_string());
                Ok(write_raw_obj(&o))
            }
            "validateaddress" => {
                let mut o = raw_obj(result).map_err(bad)?;
                let valid = o.get("isvalid").is_some_and(|v| v == "true");
                let a = p_str(p, 0)?.unwrap_or("");
                if valid {
                    let script = parse_taddr_script(self.network, a);
                    let owner = script.as_ref().and_then(|s| self.book.owns_script(s));
                    o.insert("ismine".into(), (owner.is_some()).to_string());
                    o.insert("iswatchonly".into(), "false".into());
                    let isscript = script
                        .as_ref()
                        .is_some_and(|s| yew_core::script::p2sh_hash(s).is_some());
                    o.entry("isscript".into())
                        .or_insert_with(|| isscript.to_string());
                    if let Some(Owner::T(c, i)) = owner {
                        let k = self.book.key(c, i).expect("held");
                        o.insert("pubkey".into(), J::Str(hex::encode(k.pubkey)).text());
                        o.insert("iscompressed".into(), "true".into());
                    }
                    if owner.is_some() {
                        let label = script
                            .as_ref()
                            .and_then(|s| self.address_book_label(s))
                            .unwrap_or_default();
                        o.insert("account".into(), J::Str(label).text());
                        // beta2: a YED holder key of this wallet (ycash-dd 322be29c5)
                        let holders = self.yed_holder_scripts(node).await;
                        if script.as_ref().is_some_and(|s| holders.contains(s)) {
                            o.insert("yed_holder".into(), "true".into());
                        }
                    }
                    // beta2 item 15: the scheme's name beside its number (ycashd's misc.cpp),
                    // when the backend answered only the number
                    if let Some(n) = o.get("pqscheme").and_then(|v| v.parse::<u8>().ok()) {
                        o.entry("pqschemename".into())
                            .or_insert_with(|| J::Str(pq_scheme_name(n).into()).text());
                    }
                    // a redeem script this wallet knows (addmultisigaddress): DescribeAddressVisitor
                    if let Some(redeem) = self.st.scripts.get(a).and_then(|h| hex::decode(h).ok()) {
                        let (typ, dest) = crate::raw::solve(self.network, &redeem);
                        o.insert("script".into(), J::Str(typ.into()).text());
                        o.insert("hex".into(), J::Str(hex::encode(&redeem)).text());
                        let (req, addrs) = dest.unwrap_or((0, Vec::new()));
                        // IsMine: a multisig is the wallet's only when it holds every key
                        let all = !addrs.is_empty()
                            && addrs.iter().all(|x| {
                                parse_taddr_script(self.network, x)
                                    .is_some_and(|s| self.book.owns_script(&s).is_some())
                            });
                        o.insert("ismine".into(), all.to_string());
                        o.insert(
                            "addresses".into(),
                            J::Arr(addrs.into_iter().map(J::Str).collect()).text(),
                        );
                        if typ == "multisig" {
                            o.insert("sigsrequired".into(), req.to_string());
                        }
                    }
                }
                Ok(write_raw_obj(&o))
            }
            "z_validateaddress" => {
                let mut o = raw_obj(result).map_err(bad)?;
                if o.get("isvalid").is_some_and(|v| v == "true") {
                    let a = p_str(p, 0)?.unwrap_or("");
                    let mine = if yew_core::shielded_keys::is_sapling_address(self.network, a) {
                        self.view.owns_address(a).is_some()
                    } else {
                        parse_taddr_script(self.network, a)
                            .is_some_and(|s| self.book.owns_script(&s).is_some())
                    };
                    o.insert("ismine".into(), mine.to_string());
                }
                Ok(write_raw_obj(&o))
            }
            "vault_list" => {
                // `mine` filters on the wallet's owner keys; the node is asked without it
                let mine = param(p, 0)
                    .and_then(|f| f.get("mine"))
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let rows: Vec<BTreeMap<String, Box<RawValue>>> =
                    serde_json::from_str(result).map_err(bad)?;
                let mut out = Vec::new();
                for r in rows {
                    let owner = r
                        .get("owner")
                        .and_then(|o| serde_json::from_str::<String>(o.get()).ok())
                        .and_then(|h| hex::decode(h).ok())
                        .and_then(|b| PqKeyId::from_bytes(&b));
                    let wallet = owner.is_some_and(|id| self.book.pq_by_id(&id).is_some());
                    if mine && !wallet {
                        continue;
                    }
                    let mut o: BTreeMap<String, String> = r
                        .into_iter()
                        .map(|(k, v)| (k, v.get().to_string()))
                        .collect();
                    o.insert("wallet".into(), wallet.to_string());
                    out.push(write_raw_obj(&o));
                }
                Ok(format!("[{}]", out.join(",")))
            }
            "set_getinfo" => {
                let mut o = raw_obj(result).map_err(bad)?;
                if let Some(ml) = o.get("memberlist").cloned() {
                    let members: Vec<BTreeMap<String, Box<RawValue>>> =
                        serde_json::from_str(&ml).map_err(bad)?;
                    let rows: Vec<String> = members
                        .into_iter()
                        .map(|m| {
                            let mut mo: BTreeMap<String, String> = m
                                .into_iter()
                                .map(|(k, v)| (k, v.get().to_string()))
                                .collect();
                            let key = mo
                                .get("key")
                                .and_then(|k| serde_json::from_str::<String>(k).ok())
                                .and_then(|k| hex::decode(k).ok());
                            // a member key is a wallet key when its hash160 is held (member keys come from
                            // set_join, S2; ycashd's WalletHasKey)
                            let held = key
                                .is_some_and(|k| self.book.by_hash(&ykeys::hash160(&k)).is_some());
                            mo.insert("wallet".into(), held.to_string());
                            write_raw_obj(&mo)
                        })
                        .collect();
                    o.insert("memberlist".into(), format!("[{}]", rows.join(",")));
                }
                Ok(write_raw_obj(&o))
            }
            // yed_gettxinfo carries no wallet field in rpcversion 8: forwarded as is
            _ => {
                let _ = node;
                Ok(result.to_string())
            }
        }
    }

    /// `z_validateaddress "address"`, answered here (`rpc/misc.cpp` `DescribePaymentAddressVisitor`):
    /// ycash6 started with `-disablewallet` dereferences its absent wallet in this call
    /// (`LOCK2(cs_main, pwalletMain->cs_wallet)`) and stops, so it is never forwarded to it. Every
    /// field comes from the address itself plus `ismine`. Sprout and unified addresses are not
    /// Ycash v4 wallet forms; they answer `isvalid: false` here.
    pub fn z_validateaddress(&self, p: &[Value]) -> Result<J, RpcError> {
        if p.len() != 1 {
            return Err(RpcError::new(
                code::MISC_ERROR,
                "z_validateaddress \"address\"",
            ));
        }
        let a = p_str(p, 0)?.unwrap_or("");
        let mut o = J::obj();
        if let Ok(pa) =
            zcash_keys::encoding::decode_payment_address(self.network.sapling_address_hrp(), a)
        {
            let bytes = pa.to_bytes();
            let mut pkd = bytes[11..].to_vec();
            pkd.reverse(); // uint256::GetHex
            o.push("isvalid", J::Bool(true));
            o.push("address", J::Str(a.into()));
            o.push("address_type", J::Str("sapling".into()));
            o.push("type", J::Str("sapling".into()));
            o.push("diversifier", J::Str(hex::encode(&bytes[..11])));
            o.push("diversifiedtransmissionkey", J::Str(hex::encode(pkd)));
            o.push("ismine", J::Bool(self.view.owns_address(a).is_some()));
        } else if let Some(script) = parse_taddr_script(self.network, a)
            .filter(|_| ykeys::parse_pq_yec_address(self.network, a).is_err())
        {
            let kind = if yew_core::script::p2sh_hash(&script).is_some() {
                "p2sh"
            } else {
                "p2pkh"
            };
            o.push("isvalid", J::Bool(true));
            o.push("address", J::Str(a.into()));
            o.push("address_type", J::Str(kind.into()));
            o.push("type", J::Str(kind.into()));
            o.push("ismine", J::Bool(self.book.owns_script(&script).is_some()));
        } else {
            o.push("isvalid", J::Bool(false));
        }
        Ok(o)
    }

    /// The node's `vault_list` filter without the wallet-only `mine` key.
    pub fn strip_mine(params: &[Value]) -> Vec<Value> {
        let mut p = params.to_vec();
        if let Some(Value::Object(f)) = p.get_mut(0) {
            f.remove("mine");
        }
        p
    }
}

fn raw_obj(text: &str) -> Result<BTreeMap<String, String>, serde_json::Error> {
    let m: BTreeMap<String, Box<RawValue>> = serde_json::from_str(text)?;
    Ok(m.into_iter()
        .map(|(k, v)| (k, v.get().to_string()))
        .collect())
}

fn write_raw_obj(o: &BTreeMap<String, String>) -> String {
    J::Obj(
        o.iter()
            .map(|(k, v)| (k.clone(), J::Raw(v.clone())))
            .collect(),
    )
    .text()
}

/// A transparent address (`s…`/`t…` P2PKH or P2SH, `sq…`/`tq…`/`rq…` PQ) → its script.
pub fn parse_taddr_script(network: yew_core::params::Network, s: &str) -> Option<Vec<u8>> {
    if let Ok(id) = ykeys::parse_pq_yec_address(network, s) {
        return yew_core::pq::pqpkh_script(&id);
    }
    let a = ykeys::parse_address(network, s).ok()?;
    // parse_address also takes the `yb…` YED form of the same key; ycashd's DecodeDestination does not
    if s.len() == 35 && ykeys::encode_yellowback(network, &a.hash()) == s {
        return None;
    }
    Some(match a.kind {
        ykeys::AddressKind::P2pkh(h) => yew_core::script::p2pkh_script(&h),
        ykeys::AddressKind::P2sh(h) => yew_core::script::p2sh_script(&h),
    })
}

/// A Yellowback P2PKH address (`yb…`/`yt…`/`yr…`) → its key hash.
fn parse_yed_p2pkh(network: yew_core::params::Network, s: &str) -> Option<[u8; 20]> {
    let a = ykeys::parse_address(network, s).ok()?;
    match a.kind {
        ykeys::AddressKind::P2pkh(h) if ykeys::encode_yellowback(network, &h) == s => Some(h),
        _ => None,
    }
}

/// A Yellowback address (either form, or the transparent twin) → its holder script.
fn yed_script(network: yew_core::params::Network, s: &str) -> Option<Vec<u8>> {
    if let Ok(id) = ykeys::parse_pq_address(network, s) {
        return yew_core::pq::pqpkh_script(&id);
    }
    if let Some(h) = parse_yed_p2pkh(network, s) {
        return Some(yew_core::script::p2pkh_script(&h));
    }
    parse_taddr_script(network, s)
}

/// `Memo::Interpret`'s text case: a first byte at most 0xF4, valid UTF-8 once the zero padding
/// is trimmed.
pub(crate) fn memo_str(memo: &[u8; 512]) -> Option<String> {
    if memo[0] > 0xf4 {
        return None;
    }
    let end = memo
        .iter()
        .rposition(|&b| b != 0)
        .map(|i| i + 1)
        .unwrap_or(0);
    std::str::from_utf8(&memo[..end]).ok().map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn money_and_memo() {
        assert_eq!(format_money(0), "0.00");
        assert_eq!(format_money(150_000_000), "1.50");
        assert_eq!(format_money(244), "0.00000244");
        let mut m = [0u8; 512];
        m[..2].copy_from_slice(b"hi");
        assert_eq!(memo_str(&m), Some("hi".into()));
        m[0] = 0xf6;
        assert_eq!(memo_str(&m), None);
    }

    #[test]
    fn served_methods_are_in_no_other_list() {
        for m in SERVED {
            assert!(!AUGMENTED.contains(m), "{m}");
        }
    }
}
