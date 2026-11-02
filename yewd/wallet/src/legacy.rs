// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! Four stock wallet reads the scripts call beyond K-25's list (finding F-S5-1, found by the S5
//! gate): `getaddressesbyaccount`, `listreceivedbyaddress`, `listtransactions` and
//! `z_listaddresses`, each as ycash6's `src/wallet/rpcwallet.cpp` answers it (`getaddressesbyaccount`
//! :1358, `ListReceived` :1846, `ListTransactions` :2006 with `WalletTxToJSON`, `z_listaddresses`
//! :3982), over the wallet's own transactions and address book.

use serde_json::Value;

use crate::json::J;
use crate::keys::script_address;
use crate::rpc::{arity, invalid, minconf, p_bool, p_int, p_str, param, parse_taddr_script};
use crate::{code, RpcError, Wallet};

pub const SERVED: &[&str] = &[
    "getaddressesbyaccount",
    "listreceivedbyaddress",
    "listtransactions",
    "z_listaddresses",
];

impl Wallet {
    pub(crate) async fn legacy_call(&mut self, method: &str, p: &[Value]) -> Result<J, RpcError> {
        match method {
            "getaddressesbyaccount" => self.getaddressesbyaccount(p),
            "listreceivedbyaddress" => self.listreceivedbyaddress(p),
            "listtransactions" => self.listtransactions(p),
            "z_listaddresses" => self.z_listaddresses(p),
            _ => Err(RpcError::new(code::METHOD_NOT_FOUND, "Method not found")),
        }
    }

    /// The address book's transparent destinations (`mapAddressBook`, in its order).
    fn book_taddrs(&self) -> Vec<(String, Vec<u8>)> {
        self.st
            .book
            .keys()
            .filter_map(|a| parse_taddr_script(self.network, a).map(|s| (a.clone(), s)))
            .collect()
    }

    /// `getaddressesbyaccount "account"`: every transparent address of the book for `""`, none
    /// for any other account.
    fn getaddressesbyaccount(&self, p: &[Value]) -> Result<J, RpcError> {
        if p.len() != 1 {
            return Err(RpcError::new(
                code::MISC_ERROR,
                "getaddressesbyaccount \"account\"",
            ));
        }
        let account = p[0].as_str().ok_or_else(|| {
            RpcError::new(code::TYPE_ERROR, "JSON value is not a string as expected")
        })?;
        if !account.is_empty() {
            return Ok(J::Arr(vec![]));
        }
        Ok(J::Arr(
            self.book_taddrs()
                .into_iter()
                .map(|(a, _)| J::Str(a))
                .collect(),
        ))
    }

    /// `listreceivedbyaddress ( minconf includeempty includeWatchonly addressFilter
    /// includeImmatureCoinbase asOfHeight )` (`ListReceived`).
    fn listreceivedbyaddress(&self, p: &[Value]) -> Result<J, RpcError> {
        arity("listreceivedbyaddress", p, 6)?;
        if let Some(f) = p_str(p, 3)? {
            if !f.is_empty() {
                return Err(invalid("addressFilter must be set to \"\""));
            }
        }
        if p_bool(p, 4, false)? {
            return Err(invalid("includeImmatureCoinbase must be set to false"));
        }
        let asof = match param(p, 5) {
            None => None,
            Some(_) => Some(p_int(p, 5, 0)? as u32),
        };
        let min = minconf(p, 0, 1)?;
        let include_empty = p_bool(p, 1, false)?;
        let mut rows = Vec::new();
        for (addr, script) in self.book_taddrs() {
            if self.book.owns_script(&script).is_none() {
                continue;
            }
            let mut amount = 0i64;
            let mut conf = i64::MAX;
            let mut txids = Vec::new();
            for (t, px) in self.parsed_all() {
                if px.coinbase {
                    continue;
                }
                let depth = self.tx_depth(t, asof);
                if depth < min {
                    continue;
                }
                let got: i64 = px
                    .tx
                    .vout
                    .iter()
                    .filter(|o| o.script_pubkey == script)
                    .map(|o| o.value)
                    .sum();
                let hits = px
                    .tx
                    .vout
                    .iter()
                    .filter(|o| o.script_pubkey == script)
                    .count();
                if hits > 0 {
                    amount += got;
                    conf = conf.min(depth);
                    for _ in 0..hits {
                        txids.push(J::Str(t.clone()));
                    }
                }
            }
            if txids.is_empty() && !include_empty {
                continue;
            }
            rows.push(
                J::obj()
                    .with("address", addr)
                    .with("amount", J::Amount(amount))
                    .with("amountZat", amount)
                    .with("confirmations", if conf == i64::MAX { 0 } else { conf })
                    .with("txids", J::Arr(txids)),
            );
        }
        Ok(J::Arr(rows))
    }

    /// `WalletTxToJSON`'s fields of one wallet transaction.
    fn wtx_fields(&self, txid: &str, asof: Option<u32>, o: &mut J) {
        let (Some(w), Some(px)) = (self.st.wtx.get(txid), self.parsed(txid)) else {
            return;
        };
        let depth = self.tx_depth(txid, asof);
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
        o.push("txid", J::Str(txid.to_string()));
        o.push("walletconflicts", J::Arr(vec![]));
        o.push("time", J::Int(w.time_received));
        o.push("timereceived", J::Int(w.time_received));
        o.push("vjoinsplit", J::Arr(vec![]));
    }

    /// `ListTransactions(wtx, 0, true, ...)`: the sent entries, then the received ones.
    fn list_rows(&self, txid: &str, asof: Option<u32>) -> Vec<J> {
        let Some(px) = self.parsed(txid) else {
            return vec![];
        };
        let depth = self.tx_depth(txid, asof);
        if depth < 0 {
            return vec![];
        }
        let debit = self.debit(txid);
        let vout_total: i64 = px.tx.vout.iter().map(|o| o.value).sum();
        let fee = if debit > 0 {
            debit - vout_total + px.tx.shielded.value_balance
        } else {
            0
        };
        let size = px.size as i64;
        let mut rows = Vec::new();
        if debit > 0 {
            for (n, out) in px.tx.vout.iter().enumerate() {
                let mine = self.book.owns_script(&out.script_pubkey).is_some();
                if mine && !self.in_book(&out.script_pubkey) {
                    continue; // change
                }
                let mut e = J::obj();
                if let Some(a) = script_address(self.network, &out.script_pubkey) {
                    e.push("address", J::Str(a));
                }
                e.push("category", J::Str("send".into()));
                e.push("amount", J::Amount(-out.value));
                e.push("amountZat", J::Int(-out.value));
                e.push("vout", J::Int(n as i64));
                e.push("fee", J::Amount(-fee));
                self.wtx_fields(txid, asof, &mut e);
                e.push("size", J::Int(size));
                rows.push(e);
            }
        }
        for (n, out) in px.tx.vout.iter().enumerate() {
            if self.book.owns_script(&out.script_pubkey).is_none() {
                continue;
            }
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
            let mut e = J::obj();
            if let Some(a) = script_address(self.network, &out.script_pubkey) {
                e.push("address", J::Str(a));
            }
            e.push("category", J::Str(category.into()));
            e.push("amount", J::Amount(out.value));
            e.push("amountZat", J::Int(out.value));
            e.push("vout", J::Int(n as i64));
            self.wtx_fields(txid, asof, &mut e);
            e.push("size", J::Int(size));
            rows.push(e);
        }
        rows
    }

    /// `listtransactions ( "dummy" count from includeWatchonly asOfHeight )`: the most recent
    /// `count` entries after skipping `from`, oldest first.
    fn listtransactions(&self, p: &[Value]) -> Result<J, RpcError> {
        arity("listtransactions", p, 5)?;
        if let Some(d) = p_str(p, 0)? {
            if d != "*" {
                return Err(invalid("Invalid account name. Only \"*\" is supported."));
            }
        }
        let count = p_int(p, 1, 10)?;
        let from = p_int(p, 2, 0)?;
        if count < 0 {
            return Err(invalid("Negative count"));
        }
        if from < 0 {
            return Err(invalid("Negative from"));
        }
        let _watch = p_bool(p, 3, false)?;
        let asof = match param(p, 4) {
            None => None,
            Some(_) => Some(p_int(p, 4, 0)? as u32),
        };
        // the wallet's insertion order (ycashd's wtxOrdered): time received, then txid
        let mut txs: Vec<(&String, i64)> = self
            .st
            .wtx
            .iter()
            .map(|(t, w)| (t, w.time_received))
            .collect();
        txs.sort_by(|a, b| a.1.cmp(&b.1).then(a.0.cmp(b.0)));
        let mut rows = Vec::new();
        for (t, _) in txs.iter().rev() {
            let mut r = self.list_rows(t, asof);
            r.reverse();
            rows.extend(r);
            if rows.len() as i64 >= count + from {
                break;
            }
        }
        let rows: Vec<J> = rows
            .into_iter()
            .skip(from as usize)
            .take(count as usize)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        Ok(J::Arr(rows))
    }

    /// `z_listaddresses ( includeWatchonly )`: the wallet's Sapling addresses, in issue order.
    fn z_listaddresses(&self, p: &[Value]) -> Result<J, RpcError> {
        arity("z_listaddresses", p, 1)?;
        let _watch = p_bool(p, 0, false)?;
        Ok(J::Arr(
            self.st
                .issued
                .sapling
                .iter()
                .filter_map(|j| self.view.address_at(*j).map(|(_, a)| J::Str(a)))
                .collect(),
        ))
    }
}
