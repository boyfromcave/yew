// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! Two read-only stock wallet RPCs served by the K-25 amendment for beta2 (2026-11-11), so the
//! balances by address type read the same on the Rust line as on the C++ lines (beta2 item 15,
//! decision 1 of item 37): `z_gettotalbalance` (ycash6 `src/wallet/rpcwallet.cpp`
//! `z_gettotalbalance` at e2a8bdace / e9a6cf33f, ycash-dd 322be29c5, the same fields and help on
//! both) and `listaddresses` (ycash6 only: ycash-dd v4.5.0 has no `listaddresses`).

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;
use yew_core::pq::PqKeyId;

use crate::json::J;
use crate::keys::{Owner, IMPORTED};
use crate::node::Node;
use crate::rpc::{
    arity, format_money, invalid, p_bool, p_int, parse_taddr_script, pq_scheme_name,
    PQ_BALANCE_SCHEMES,
};
use crate::{code, RpcError, Wallet};

pub const SERVED: &[&str] = &["z_gettotalbalance", "listaddresses"];

/// ycashd's `listaddresses` sources, in the order it lists them (no `imported_watchonly` and no
/// `legacy_hdseed`: yewd watches no script without its key and derives Sapling from the
/// mnemonic only).
const SOURCES: [&str; 3] = ["legacy_random", "imported", "mnemonic_seed"];

/// The keys of one source: `transparent.addresses`, `transparent.changeAddresses`, Sapling
/// addresses, post-quantum entries.
#[derive(Default)]
struct Source {
    t: BTreeSet<(u8, Vec<u8>, String)>,
    t_change: BTreeSet<(u8, Vec<u8>, String)>,
    sapling: Vec<String>,
    pq: Vec<J>,
}

impl Wallet {
    pub(crate) async fn bytype_call(
        &mut self,
        node: &dyn Node,
        method: &str,
        p: &[Value],
    ) -> Result<J, RpcError> {
        match method {
            "z_gettotalbalance" => self.z_gettotalbalance(node, p).await,
            "listaddresses" => self.listaddresses(node, p).await,
            _ => Err(RpcError::new(code::METHOD_NOT_FOUND, "Method not found")),
        }
    }

    /// `z_gettotalbalance ( minconf includeWatchonly )`: `transparent` counts what
    /// `AvailableCoins` lists (unspent, not locked, mature, depth >= minconf; the outputs YED
    /// holds are locked in ycashd and left out here too), `private` the unspent Sapling notes at
    /// depth >= minconf, and the split by address type and scheme as ycashd answers it
    /// (`transparent_ecc` = `transparent` minus `transparent_pq`). Amounts are strings
    /// (`FormatMoney`). yewd holds no watch-only script, so `includeWatchonly` changes nothing.
    async fn z_gettotalbalance(&self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        arity("z_gettotalbalance", p, 2)?;
        let min = p_int(p, 0, 1)?;
        if min < 0 {
            return Err(invalid(
                "Minimum number of confirmations cannot be less than 0",
            ));
        }
        let _watch = p_bool(p, 1, false)?;
        let reserved = self.yed_reserved(node).await?;
        let mut transparent = 0i64;
        let mut pq = [0i64; 3];
        for (c, d) in self.available_coins(None) {
            if d < min || reserved.contains(&(c.txid.clone(), c.vout)) {
                continue;
            }
            transparent += c.value;
            if let Some(id) = yew_core::pq::pqpkh_of(&c.script) {
                if let Some(slot) = pq.get_mut(id.scheme as usize) {
                    *slot += c.value;
                }
            }
        }
        let private: i64 = self
            .notes
            .iter()
            .filter(|n| !n.spent && self.depth(n.height) >= min)
            .map(|n| n.value as i64)
            .sum();
        let pq_total = pq[1] + pq[2];
        Ok(J::obj()
            .with("transparent", format_money(transparent))
            .with("private", format_money(private))
            .with("total", format_money(transparent + private))
            .with("transparent_ecc", format_money(transparent - pq_total))
            .with("transparent_pq", format_money(pq_total))
            .with(
                "pq_by_scheme",
                J::Arr(
                    PQ_BALANCE_SCHEMES
                        .iter()
                        .map(|&s| {
                            J::obj()
                                .with("pqscheme", s as i64)
                                .with("pqschemename", pq_scheme_name(s))
                                .with("transparent_pq", format_money(pq[s as usize]))
                        })
                        .collect(),
                ),
            ))
    }

    /// The source ycashd names for a transparent key of this wallet: a seed key is
    /// `mnemonic_seed`; an `importprivkey` key has no HD path, which ycashd lists as
    /// `legacy_random` (`GetSourceForPaymentAddress(CKeyID)`: `HaveKey` → `Random`).
    fn t_source(chain: u32) -> &'static str {
        if chain == IMPORTED {
            "legacy_random"
        } else {
            "mnemonic_seed"
        }
    }

    /// `listaddresses`: the wallet's addresses by source, as ycash6 lists them (beta2 item 15):
    /// the transparent addresses of the address book, the change addresses (own P2PKH outputs
    /// of trusted transactions whose address is not in the book, ycashd's `GetAddressBalances`),
    /// the issued Sapling addresses (one IVK group with its ZIP-32 path), and the post-quantum
    /// addresses of the book and every PQ key of this wallet that received coins, each with
    /// `pqscheme`, `pqschemename` and `yed_holder` where the index holds a YED token of this
    /// wallet at it. A key of the seed is `mnemonic_seed`, an imported one `imported` (PQ,
    /// `z_importpqkey`; a P2SH of `addmultisigaddress`, whose redeem script the wallet keeps) or
    /// `legacy_random` (an `importprivkey` key, as ycashd lists it).
    async fn listaddresses(&self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        arity("listaddresses", p, 0)?;
        let holders = self.yed_holder_scripts(node).await;
        let mut by: BTreeMap<&'static str, Source> = BTreeMap::new();
        // the address book's transparent destinations
        for a in self.st.book.keys() {
            let Some(script) = parse_taddr_script(self.network, a) else {
                continue;
            };
            if let Some(h) = yew_core::script::p2pkh_hash(&script) {
                if let Some(Owner::T(chain, _)) = self.book.owns_script(&script) {
                    by.entry(Self::t_source(chain)).or_default().t.insert((
                        0,
                        h.to_vec(),
                        a.clone(),
                    ));
                }
            } else if let Some(h) = yew_core::script::p2sh_hash(&script) {
                if self.st.scripts.contains_key(a) {
                    by.entry("imported")
                        .or_default()
                        .t
                        .insert((1, h.to_vec(), a.clone()));
                }
            }
        }
        // change: own P2PKH outputs of trusted transactions (depth >= 1, or 0 when from me)
        // not in the book
        for (txid, px) in self.parsed_all() {
            if !self.trusted(txid, None) {
                continue;
            }
            let d = self.tx_depth(txid, None);
            if d < if self.debit(txid) > 0 { 0 } else { 1 } {
                continue;
            }
            for o in &px.tx.vout {
                let Some(h) = yew_core::script::p2pkh_hash(&o.script_pubkey) else {
                    continue;
                };
                let Some(Owner::T(chain, _)) = self.book.owns_script(&o.script_pubkey) else {
                    continue;
                };
                let a = yew_core::keys::encode_p2pkh(self.network, &h);
                if !self.st.book.contains_key(&a) {
                    by.entry(Self::t_source(chain))
                        .or_default()
                        .t_change
                        .insert((0, h.to_vec(), a));
                }
            }
        }
        // Sapling: the issued addresses of the seed's one account (one IVK)
        let sapling: Vec<String> = self
            .st
            .issued
            .sapling
            .iter()
            .filter_map(|j| self.view.address_at(*j).map(|(_, a)| a))
            .collect();
        if !sapling.is_empty() {
            by.entry("mnemonic_seed").or_default().sapling = sapling;
        }
        // post-quantum: the book's and every own PQ key that received coins, by (scheme, hash)
        let mut pq_ids: BTreeMap<[u8; 33], PqKeyId> = BTreeMap::new();
        for a in self.st.book.keys() {
            if let Some(script) = parse_taddr_script(self.network, a) {
                if let Some(id) = yew_core::pq::pqpkh_of(&script) {
                    pq_ids.insert(id.to_bytes(), id);
                }
            }
        }
        for (_, px) in self.parsed_all() {
            for o in &px.tx.vout {
                if let Some(id) = yew_core::pq::pqpkh_of(&o.script_pubkey) {
                    pq_ids.insert(id.to_bytes(), id);
                }
            }
        }
        for id in pq_ids.values() {
            let Some(own) = self.book.pq_by_id(id) else {
                continue; // a book entry this wallet does not hold
            };
            let Some(address) = yew_core::keys::encode_pq_yec(self.network, id) else {
                continue;
            };
            let mut e = J::obj()
                .with("address", address)
                .with("pqscheme", id.scheme as i64)
                .with("pqschemename", pq_scheme_name(id.scheme));
            if yew_core::pq::pqpkh_script(id).is_some_and(|s| holders.contains(&s)) {
                e.push("yed_holder", J::Bool(true));
            }
            let source = if own.index >= yewd_proto::IMPORTED_PQ_BASE {
                "imported"
            } else {
                "mnemonic_seed"
            };
            by.entry(source).or_default().pq.push(e);
        }
        let list = |s: &BTreeSet<(u8, Vec<u8>, String)>| {
            J::Arr(s.iter().map(|(_, _, a)| J::Str(a.clone())).collect())
        };
        let mut out = Vec::new();
        for name in SOURCES {
            let Some(s) = by.get_mut(name) else { continue };
            let mut e = J::obj().with("source", name);
            if !s.t.is_empty() || !s.t_change.is_empty() {
                let mut t = J::obj();
                if !s.t.is_empty() {
                    t.push("addresses", list(&s.t));
                }
                if !s.t_change.is_empty() {
                    t.push("changeAddresses", list(&s.t_change));
                }
                e.push("transparent", t);
            }
            if !s.sapling.is_empty() {
                e.push(
                    "sapling",
                    J::Arr(vec![J::obj()
                        .with(
                            "zip32KeyPath",
                            format!(
                                "m/32'/{}'/{}'",
                                yew_core::params::COIN_TYPE,
                                yew_core::params::ACCOUNT
                            ),
                        )
                        .with(
                            "addresses",
                            J::Arr(s.sapling.iter().map(|a| J::Str(a.clone())).collect()),
                        )]),
                );
            }
            if !s.pq.is_empty() {
                e.push("pq", J::Arr(std::mem::take(&mut s.pq)));
            }
            if matches!(&e, J::Obj(kv) if kv.len() > 1) {
                out.push(e);
            }
        }
        Ok(J::Arr(out))
    }
}
