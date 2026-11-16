// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! Watch-only scripts (beta3 item 14): `importaddress` and `importpubkey` (ycash6
//! `src/wallet/rpcdump.cpp`), and what ycashd's `ISMINE_WATCH_ONLY` filter adds to the reads.
//!
//! A watched script is followed like an own one (a transaction paying it, or spending one of its
//! coins, is a wallet transaction, as in ycashd's `mapWallet`), but its coins are kept apart, in
//! [`WatchCoin`]s, never in [`Wallet::coins`]: every coin selection, change output, vault and YED
//! path reads `coins` and `KeyBook::owns_script` only, so a watched coin is never spent, never
//! made change and never taken for a coin the wallet owns. The reads that take ycashd's
//! `includeWatchonly` (`getbalance`, `listtransactions`, `gettransaction`,
//! `listreceivedbyaddress`, `z_gettotalbalance`) add them when asked; `listunspent` lists them
//! with `spendable: false`, `validateaddress` says `iswatchonly`, `listaddresses` lists them under
//! `imported_watchonly`, as ycashd does.
//!
//! A rescan (`rescan`, the default) reads the whole chain again from genesis, as ycashd's
//! `ScanForWalletTransactions(chainActive.Genesis())`: over JSON-RPC that is every block of the
//! chain (on mainnet, hours). With `rescan = false` only later transactions are found.
//!
//! Watched scripts are kept in `wallet.json` (`watch`), so they survive a restart and a
//! `backupwallet` copy. Like ycashd's, they are not in a `z_exportwallet` file and cannot be
//! derived from the recovery phrase: a restore from the phrase or from an export does not bring
//! them back; import them again.

use std::collections::BTreeSet;

use serde_json::Value;

use crate::json::J;
use crate::keys::script_address;
use crate::node::Node;
use crate::rpc::{param, parse_taddr_script};
use crate::state::{BookEntry, WatchRec};
use crate::{code, txid_hex, RpcError, Wallet};

/// The watch-only import RPCs.
pub const SERVED: &[&str] = &["importaddress", "importpubkey"];

/// One coin of a watched script.
#[derive(Clone, Debug)]
pub struct WatchCoin {
    pub txid: String,
    pub vout: u32,
    pub value: i64,
    pub script: Vec<u8>,
    pub height: Option<u32>,
    pub coinbase: bool,
    /// Spent by a wallet transaction (confirmed or in the mempool).
    pub spent: bool,
}

const OWN_KEY: &str = "The wallet already contains the private key for this address or script";

fn str_arg(v: &Value) -> Result<&str, RpcError> {
    v.as_str()
        .ok_or_else(|| RpcError::new(code::MISC_ERROR, "JSON value is not a string as expected"))
}

fn bool_arg(p: &[Value], i: usize, default: bool) -> Result<bool, RpcError> {
    match param(p, i) {
        None => Ok(default),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(RpcError::new(
            code::MISC_ERROR,
            "JSON value is not a boolean as expected",
        )),
    }
}

/// ycashd's `IsHex`: non-empty, even length, hex digits only.
fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.len().is_multiple_of(2) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The public key of a pay-to-pubkey script (`<33 or 65 bytes> OP_CHECKSIG`).
fn p2pk_key(script: &[u8]) -> Option<&[u8]> {
    match script {
        [0x21, k @ .., 0xac] if k.len() == 33 => Some(k),
        [0x41, k @ .., 0xac] if k.len() == 65 => Some(k),
        _ => None,
    }
}

fn p2pk_script(pk: &[u8]) -> Vec<u8> {
    let mut s = Vec::with_capacity(pk.len() + 2);
    s.push(pk.len() as u8);
    s.extend_from_slice(pk);
    s.push(0xac);
    s
}

impl Wallet {
    /// The watched scripts from the state (at open, after an import).
    pub(crate) fn load_watched(&mut self) {
        self.watched = self
            .st
            .watch
            .keys()
            .filter_map(|h| hex::decode(h).ok())
            .collect();
    }

    /// ycashd's `IsMine(script) & ISMINE_WATCH_ONLY`: watched, and not spendable by this wallet
    /// (a key the wallet holds wins, as in ycashd's `IsMineInner`).
    pub fn is_watched(&self, script: &[u8]) -> bool {
        self.watched.contains(script) && !self.spendable_script(script)
    }

    /// How many watched scripts the wallet can spend (a key it derived or imported after the
    /// import): [`Wallet::refresh_keys`] rebuilds the coins when this changes.
    pub(crate) fn watched_own(&self) -> usize {
        self.watched
            .iter()
            .filter(|s| self.spendable_script(s))
            .count()
    }

    /// ycashd's `IsMine(script) == ISMINE_SPENDABLE` for the scripts yewd can hold: P2PKH and
    /// `TX_PQPKH` of its keys, and pay-to-pubkey of one of its transparent keys.
    pub(crate) fn spendable_script(&self, script: &[u8]) -> bool {
        if self.book.owns_script(script).is_some() {
            return true;
        }
        p2pk_key(script).is_some_and(|k| {
            self.book
                .by_hash(&yew_core::keys::hash160(k))
                .is_some_and(|t| t.pubkey.as_slice() == k)
        })
    }

    /// An output counts under the filter: own, or watched when `watch` (ISMINE_WATCH_ONLY) is in it.
    pub(crate) fn mine_f(&self, script: &[u8], watch: bool) -> bool {
        self.book.owns_script(script).is_some() || (watch && self.is_watched(script))
    }

    /// The previous output an input of `txid` spends, when it is a wallet transaction's.
    fn prev_out(&self, i: &yew_core::tx::TxIn) -> Option<&yew_core::tx::TxOut> {
        self.parsed(&txid_hex(&i.prevout.txid))?
            .tx
            .vout
            .get(i.prevout.n as usize)
    }

    /// `GetDebit(filter)`: the value of the outputs counted by the filter that `txid` spends.
    pub(crate) fn debit_f(&self, txid: &str, watch: bool) -> i64 {
        let Some(p) = self.parsed(txid) else { return 0 };
        p.tx.vin
            .iter()
            .filter_map(|i| self.prev_out(i))
            .filter(|o| self.mine_f(&o.script_pubkey, watch))
            .map(|o| o.value)
            .sum()
    }

    /// `IsFromMe(ISMINE_WATCH_ONLY)`: `txid` spends a coin of a watched script.
    pub(crate) fn spends_watched(&self, txid: &str) -> bool {
        let Some(p) = self.parsed(txid) else {
            return false;
        };
        p.tx.vin
            .iter()
            .filter_map(|i| self.prev_out(i))
            .any(|o| self.is_watched(&o.script_pubkey))
    }

    /// The watched coins of the wallet transactions (`rebuild`), `spent` the outpoints the wallet
    /// transactions spend.
    pub(crate) fn watched_coins(&self, spent: &BTreeSet<(String, u32)>) -> Vec<WatchCoin> {
        let mut v = Vec::new();
        if self.watched.is_empty() {
            return v;
        }
        for (txid, p) in self.parsed_all() {
            let height = self.st.wtx[txid].block.as_ref().map(|b| b.height);
            for (n, o) in p.tx.vout.iter().enumerate() {
                if self.is_watched(&o.script_pubkey) {
                    v.push(WatchCoin {
                        txid: txid.clone(),
                        vout: n as u32,
                        value: o.value,
                        script: o.script_pubkey.clone(),
                        height,
                        coinbase: p.coinbase,
                        spent: spent.contains(&(txid.clone(), n as u32)),
                    });
                }
            }
        }
        v.sort_by(|a, b| {
            (a.height.unwrap_or(u32::MAX), &a.txid, a.vout).cmp(&(
                b.height.unwrap_or(u32::MAX),
                &b.txid,
                b.vout,
            ))
        });
        v
    }

    /// The watched coins `AvailableCoins` would list: unspent in the view, mature, not locked,
    /// with their depth.
    pub(crate) fn available_watch_coins(&self, asof: Option<u32>) -> Vec<(&WatchCoin, i64)> {
        self.watch_coins
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

    /// The watch-only part of `GetBalance(asOfHeight, filter, min_depth)`: the unspent watched
    /// outputs of trusted transactions at depth >= `min_depth`, mature.
    pub(crate) fn watch_balance(&self, asof: Option<u32>, min_depth: i64) -> i64 {
        self.st
            .wtx
            .keys()
            .filter(|t| self.trusted(t, asof) && self.tx_depth(t, asof) >= min_depth)
            .filter_map(|t| {
                let p = self.parsed(t)?;
                if self.immature(p.coinbase, self.tx_depth(t, asof)) {
                    return None;
                }
                Some(
                    p.tx.vout
                        .iter()
                        .enumerate()
                        .filter(|(n, o)| {
                            self.is_watched(&o.script_pubkey) && !self.spent_at(t, *n as u32, asof)
                        })
                        .map(|(_, o)| o.value)
                        .sum::<i64>(),
                )
            })
            .sum()
    }

    // ------------------------------------------------------------------ the imports

    pub(crate) async fn watch_call(
        &mut self,
        node: &dyn Node,
        method: &str,
        p: &[Value],
    ) -> Result<J, RpcError> {
        match method {
            "importaddress" => self.importaddress(node, p).await,
            "importpubkey" => self.importpubkey(node, p).await,
            _ => Err(RpcError::new(code::METHOD_NOT_FOUND, "Method not found")),
        }
    }

    /// `ImportScript(script, label, isRedeemScript)` (rpcdump.cpp): refused for a script the
    /// wallet can spend; watched; filed in the address book under its destination. A redeem
    /// script is kept (`st.scripts`) and its P2SH watched and filed (`ImportAddress`).
    fn import_script(
        &mut self,
        script: Vec<u8>,
        label: &str,
        redeem: bool,
    ) -> Result<(), RpcError> {
        if !redeem && self.spendable_script(&script) {
            return Err(RpcError::new(code::WALLET_ERROR, OWN_KEY));
        }
        self.st.watch.entry(hex::encode(&script)).or_default();
        if redeem {
            let h = yew_core::keys::hash160(&script);
            let p2sh = yew_core::script::p2sh_script(&h);
            let addr = yew_core::keys::encode_p2sh(self.network, &h);
            self.st.scripts.insert(addr, hex::encode(&script));
            self.import_script(p2sh, label, false)?;
        } else if let Some(a) = self.destination_address(&script) {
            self.st.book.insert(
                a,
                BookEntry {
                    label: label.to_string(),
                    purpose: "receive".into(),
                },
            );
        }
        Ok(())
    }

    /// `ExtractDestination` + `EncodeDestination`: P2PKH, P2SH, `TX_PQPKH`, and pay-to-pubkey as
    /// its key's P2PKH address (ycashd maps `TX_PUBKEY` to its key ID, so a pay-to-pubkey output
    /// to a key `importpubkey` filed is in the address book and has an address).
    pub(crate) fn destination_address(&self, script: &[u8]) -> Option<String> {
        if let Some(k) = p2pk_key(script) {
            return Some(yew_core::keys::encode_p2pkh(
                self.network,
                &yew_core::keys::hash160(k),
            ));
        }
        script_address(self.network, script)
    }

    /// After an import: the wallet's transactions read again (one may pay the new script), and
    /// with `rescan` the whole chain from genesis (ycashd `ScanForWalletTransactions(Genesis)`).
    async fn after_import(&mut self, node: &dyn Node, rescan: bool) -> Result<(), RpcError> {
        self.load_watched();
        self.rebuild();
        if rescan {
            self.st.birthday = 0;
            self.rewind(None);
        }
        // written before the scan: a restart before its first checkpoint still owes the rescan
        // (from genesis), never leaves it undone
        self.save()
            .map_err(|e| RpcError::new(code::WALLET_ERROR, e))?;
        if rescan {
            self.sync(node).await?;
        }
        Ok(())
    }

    /// `importaddress "address" ( "label" rescan p2sh )`: an ECC (P2PKH or P2SH) or post-quantum
    /// address, or a script in hex (with `p2sh`, a redeem script whose P2SH is watched too).
    async fn importaddress(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        let s = str_arg(p.first().unwrap_or(&Value::Null))?.to_string();
        let label = match param(p, 1) {
            None => String::new(),
            Some(v) => str_arg(v)?.to_string(),
        };
        let rescan = bool_arg(p, 2, true)?;
        let p2sh = bool_arg(p, 3, false)?;
        if let Some(script) = parse_taddr_script(self.network, &s) {
            if p2sh {
                return Err(RpcError::new(
                    code::INVALID_ADDRESS_OR_KEY,
                    "Cannot use the p2sh flag with an address - use a script instead",
                ));
            }
            self.import_script(script, &label, false)?;
        } else if is_hex(&s) {
            let script = hex::decode(&s).map_err(|_| {
                RpcError::new(
                    code::INVALID_ADDRESS_OR_KEY,
                    "Invalid Ycash address or script",
                )
            })?;
            self.import_script(script, &label, p2sh)?;
        } else {
            return Err(RpcError::new(
                code::INVALID_ADDRESS_OR_KEY,
                "Invalid Ycash address or script",
            ));
        }
        self.after_import(node, rescan).await?;
        Ok(J::Null)
    }

    /// `importpubkey "pubkey" ( "label" rescan )`: its P2PKH address and its pay-to-pubkey script
    /// watched; the key is kept for `validateaddress`.
    async fn importpubkey(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        let s = str_arg(p.first().unwrap_or(&Value::Null))?.to_string();
        let label = match param(p, 1) {
            None => String::new(),
            Some(v) => str_arg(v)?.to_string(),
        };
        let rescan = bool_arg(p, 2, true)?;
        if !is_hex(&s) {
            return Err(RpcError::new(
                code::INVALID_ADDRESS_OR_KEY,
                "Pubkey must be a hex string",
            ));
        }
        let pk = hex::decode(&s).map_err(|_| {
            RpcError::new(code::INVALID_ADDRESS_OR_KEY, "Pubkey must be a hex string")
        })?;
        if secp256k1::PublicKey::from_slice(&pk).is_err() {
            return Err(RpcError::new(
                code::INVALID_ADDRESS_OR_KEY,
                "Pubkey is not a valid public key",
            ));
        }
        let p2pkh = yew_core::script::p2pkh_script(&yew_core::keys::hash160(&pk));
        self.import_script(p2pkh.clone(), &label, false)?;
        self.import_script(p2pk_script(&pk), &label, false)?;
        self.st.watch.insert(
            hex::encode(&p2pkh),
            WatchRec {
                pubkey: Some(hex::encode(&pk)),
            },
        );
        self.after_import(node, rescan).await?;
        Ok(J::Null)
    }

    /// The key `importpubkey` gave for a watched P2PKH script.
    pub(crate) fn watched_pubkey(&self, script: &[u8]) -> Option<Vec<u8>> {
        self.st
            .watch
            .get(&hex::encode(script))?
            .pubkey
            .as_ref()
            .and_then(|h| hex::decode(h).ok())
    }
}
