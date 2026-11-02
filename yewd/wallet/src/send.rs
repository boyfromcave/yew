// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The stock YEC builders of the K-25 set (ycash6 `src/wallet/rpcwallet.cpp`,
//! `src/rpc/rawtransaction.cpp`): `sendtoaddress`, `sendmany`, `lockunspent`,
//! `getrawchangeaddress`, and `signrawtransaction` with the wallet's keys (in the signer).
//!
//! Parity is not byte-identity (plan §4.3 rule 3): the coins chosen and the change key differ from
//! a ycashd wallet's; the fee is the ZIP-317 conventional fee ycashd 6.20.0 pays.

use std::collections::BTreeSet;

use serde_json::Value;
use yew_core::tx::{OutPoint, Transaction, TxIn, TxOut, MAX_P2PKH_SCRIPT_SIG};
use yewd_proto::{GatePath, KeyRef};

use crate::build::{
    amount_param, next_block, node_coin, op_str, tx_hex, NodeCoin, MAX_MONEY, TX_EXPIRY_DELTA,
};
use crate::json::J;
use crate::keys::{script_address, Owner};
use crate::node::{self, Node, NodeError};
use crate::rpc::{invalid, p_bool, p_str, param};
use crate::{code, txid_hex, RpcError, Wallet};

/// The stock wallet methods S2 serves.
pub const SERVED: &[&str] = &[
    "sendtoaddress",
    "sendmany",
    "lockunspent",
    "signrawtransaction",
    "getrawchangeaddress",
    "fundrawtransaction",
];

/// A change output below this is left to the fee (`GetDustThreshold` of a P2PKH output at the
/// default relay fee, 54 zat; ycashd adds such change to the fee).
const DUST: i64 = 54;

impl Wallet {
    pub async fn send_call(
        &mut self,
        node: &dyn Node,
        method: &str,
        p: &[Value],
    ) -> Result<J, RpcError> {
        match method {
            "sendtoaddress" => self.sendtoaddress(node, p).await,
            "sendmany" => self.sendmany(node, p).await,
            "lockunspent" => self.lockunspent(node, p).await,
            "getrawchangeaddress" => self.getrawchangeaddress(p),
            "signrawtransaction" => self.signrawtransaction(node, p).await,
            "fundrawtransaction" => self.fundrawtransaction(node, p).await,
            _ => Err(RpcError::new(code::METHOD_NOT_FOUND, "Method not found")),
        }
    }

    /// The coins `CreateTransaction` may spend: mature, unlocked, unspent wallet P2PKH coins,
    /// confirmed or trusted mempool change (`-spendzeroconfchange`), never YED (H5); largest first.
    async fn spendable_yec(
        &self,
        node: &dyn Node,
        min_depth: i64,
    ) -> Result<Vec<(OutPoint, i64, Vec<u8>)>, RpcError> {
        let spent = self.mempool_spent();
        let reserved = self.yed_reserved(node).await?;
        let mut v = Vec::new();
        for (c, d) in self.available_coins(None) {
            if !matches!(c.owner, Owner::T(..))
                || spent.contains(&(c.txid.clone(), c.vout))
                || reserved.contains(&(c.txid.clone(), c.vout))
            {
                continue;
            }
            if d < min_depth.max(0) || (d == 0 && !self.trusted(&c.txid, None)) {
                continue;
            }
            let op = OutPoint {
                txid: yew_core::tx::txid_from_hex(&c.txid)
                    .map_err(|e| RpcError::new(code::MISC_ERROR, e))?,
                n: c.vout,
            };
            v.push((d == 0, op, c.value, c.script.clone()));
        }
        // SelectCoins' passes: confirmed coins first (nConfMine = 1), the trusted mempool change
        // only when they do not cover the payment; largest first within each
        v.sort_by(|a, b| {
            a.0.cmp(&b.0)
                .then(b.2.cmp(&a.2))
                .then((a.1.txid, a.1.n).cmp(&(b.1.txid, b.1.n)))
        });
        Ok(v.into_iter()
            .map(|(_, op, value, s)| (op, value, s))
            .collect())
    }

    /// `CreateTransaction` + `CommitTransaction` for plain YEC recipients: largest-first coins, the
    /// ZIP-317 conventional fee, change to a new change key.
    async fn send_yec(
        &mut self,
        node: &dyn Node,
        recipients: &[(Vec<u8>, i64, bool)],
        min_depth: i64,
    ) -> Result<String, RpcError> {
        let next = next_block(node).await?;
        let coins = self.spendable_yec(node, min_depth).await?;
        let total: i64 = recipients.iter().map(|r| r.1).sum();
        let subtract = recipients.iter().filter(|r| r.2).count() as i64;
        let mut fee = 10_000i64;
        for _ in 0..8 {
            let mut tx = Transaction::new_v4();
            tx.expiry_height = next.height + TX_EXPIRY_DELTA;
            let mut first_sub = true;
            for (s, v, sub) in recipients {
                let mut v = *v;
                if *sub {
                    let share = fee / subtract + if first_sub { fee % subtract } else { 0 };
                    first_sub = false;
                    v -= share;
                    if v <= DUST {
                        return Err(RpcError::new(
                            code::WALLET_ERROR,
                            "The transaction amount is too small to pay the fee",
                        ));
                    }
                }
                tx.vout.push(TxOut {
                    value: v,
                    script_pubkey: s.clone(),
                });
            }
            let need = total + if subtract > 0 { 0 } else { fee };
            let mut got = 0i64;
            let mut chosen = Vec::new();
            for c in &coins {
                if got >= need {
                    break;
                }
                got += c.1;
                chosen.push(c.clone());
            }
            if got < need {
                let available: i64 = coins.iter().map(|c| c.1).sum();
                if subtract == 0 && total <= available {
                    return Err(RpcError::new(
                        code::WALLET_INSUFFICIENT_FUNDS,
                        format!(
                            "Error: Insufficient funds to pay the fee. This transaction needs to spend {} plus a fee of at least {}, but only {} is available",
                            crate::rpc::format_money(total),
                            crate::rpc::format_money(fee),
                            crate::rpc::format_money(available)
                        ),
                    ));
                }
                return Err(RpcError::new(
                    code::WALLET_INSUFFICIENT_FUNDS,
                    "Insufficient funds",
                ));
            }
            for c in &chosen {
                tx.vin.push(TxIn::new(c.0));
            }
            let change = got - need;
            if change > DUST {
                let s = self.new_change()?;
                tx.vout.push(TxOut {
                    value: change,
                    script_pubkey: s,
                });
            }
            let sizes = vec![MAX_P2PKH_SCRIPT_SIG; tx.vin.len()];
            let want = tx
                .zip317_conventional_fee(&sizes)
                .map_err(|e| RpcError::new(code::INTERNAL_ERROR, e.to_string()))?;
            if want > fee {
                fee = want;
                continue;
            }
            let prevs: Vec<NodeCoin> = chosen
                .iter()
                .map(|c| NodeCoin {
                    value: c.1,
                    script: c.2.clone(),
                    height: None,
                    coinbase: false,
                })
                .collect();
            let keys: Vec<KeyRef> = chosen
                .iter()
                .map(|c| self.key_of_script(&c.2).unwrap_or(KeyRef::None))
                .collect();
            // the outflow of a payment is the payment: the caller asked for it
            let signed = self
                .sign_inputs(
                    &tx,
                    &prevs,
                    &keys,
                    &[],
                    GatePath::Yec,
                    total + fee,
                    next.branch,
                )
                .await?;
            return self.broadcast(node, &signed, None).await;
        }
        Err(RpcError::new(
            code::WALLET_ERROR,
            "the fee did not converge",
        ))
    }

    /// `sendtoaddress "address" amount ( "comment" "comment_to" subtractfeefromamount )`.
    async fn sendtoaddress(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        if p.len() < 2 || p.len() > 5 {
            return Err(RpcError::new(code::MISC_ERROR, "sendtoaddress \"address\" amount ( \"comment\" \"comment-to\" subtractfeefromamount )"));
        }
        let a = p[0]
            .as_str()
            .ok_or_else(|| RpcError::new(code::TYPE_ERROR, "Expected type string"))?;
        let script = crate::rpc::parse_taddr_script(self.network, a).ok_or_else(|| {
            RpcError::new(
                code::INVALID_ADDRESS_OR_KEY,
                format!("Invalid Ycash transparent address: {a}"),
            )
        })?;
        let amount = amount_param(&p[1])?;
        if amount <= 0 {
            return Err(RpcError::new(code::TYPE_ERROR, "Invalid amount for send"));
        }
        let sub = p_bool(p, 4, false)?;
        if amount > self.balance(None, 0) {
            return Err(RpcError::new(
                code::WALLET_INSUFFICIENT_FUNDS,
                "Insufficient funds",
            ));
        }
        Ok(J::Str(
            self.send_yec(node, &[(script, amount, sub)], 0).await?,
        ))
    }

    /// `sendmany "" {"address":amount,...} ( minconf "comment" ["address",...] )`.
    async fn sendmany(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        if p.len() < 2 || p.len() > 5 {
            return Err(RpcError::new(
                code::MISC_ERROR,
                "sendmany \"\" {\"address\":amount,...} ( minconf \"comment\" [\"address\",...] )",
            ));
        }
        if let Some(d) = p_str(p, 0)? {
            if !d.is_empty() {
                return Err(invalid("Dummy value must be set to \"\""));
            }
        }
        let to = p[1]
            .as_object()
            .ok_or_else(|| RpcError::new(code::TYPE_ERROR, "Expected type object"))?;
        let min = crate::rpc::minconf(p, 2, 1)?;
        let subtract: BTreeSet<String> = param(p, 4)
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let mut seen = BTreeSet::new();
        let mut recipients = Vec::new();
        let mut total = 0i64;
        for (name, v) in to {
            let script = crate::rpc::parse_taddr_script(self.network, name).ok_or_else(|| {
                RpcError::new(
                    code::INVALID_ADDRESS_OR_KEY,
                    format!("Invalid Ycash transparent address: {name}"),
                )
            })?;
            if !seen.insert(script.clone()) {
                return Err(invalid(format!(
                    "Invalid parameter, duplicated address: {name}"
                )));
            }
            let amount = amount_param(v)?;
            if amount <= 0 {
                return Err(RpcError::new(code::TYPE_ERROR, "Invalid amount for send"));
            }
            total += amount;
            recipients.push((script, amount, subtract.contains(name)));
        }
        if total > self.balance(None, min) {
            return Err(RpcError::new(
                code::WALLET_INSUFFICIENT_FUNDS,
                "Wallet has insufficient funds",
            ));
        }
        Ok(J::Str(self.send_yec(node, &recipients, min).await?))
    }

    /// `lockunspent unlock ( [{"txid","vout"},...] )`.
    async fn lockunspent(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        if p.is_empty() || p.len() > 2 {
            return Err(RpcError::new(
                code::MISC_ERROR,
                "lockunspent unlock [{\"txid\":\"txid\",\"vout\":n},...]",
            ));
        }
        let unlock = p[0].as_bool().ok_or_else(|| {
            RpcError::new(
                code::TYPE_ERROR,
                "Expected type bool, got ".to_string() + type_name(&p[0]),
            )
        })?;
        let Some(list) = param(p, 1) else {
            if unlock {
                // the locks of remembered vault builds stay (ycashd re-locks them from mapVaultBuilds),
                // and so do the YED locks (H5: ReapplyLocks)
                let mut keep: BTreeSet<String> = self.build_locks();
                keep.extend(self.yed_held_locks(node).await?);
                self.st.locks.retain(|l| keep.contains(l));
                self.persist_state()?;
            }
            return Ok(J::Bool(true));
        };
        let arr = list.as_array().ok_or_else(|| {
            RpcError::new(
                code::TYPE_ERROR,
                "Expected type array, got ".to_string() + type_name(list),
            )
        })?;
        let mut ops = Vec::new();
        for o in arr {
            let obj = o
                .as_object()
                .ok_or_else(|| invalid("Invalid parameter, expected object"))?;
            let txid = obj
                .get("txid")
                .and_then(|t| t.as_str())
                .ok_or_else(|| RpcError::new(code::TYPE_ERROR, "Expected type string for txid"))?;
            if !txid.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(invalid("Invalid parameter, expected hex txid"));
            }
            let vout = obj
                .get("vout")
                .and_then(|v| v.as_i64())
                .ok_or_else(|| RpcError::new(code::TYPE_ERROR, "Expected type number for vout"))?;
            if vout < 0 {
                return Err(invalid("Invalid parameter, vout must be positive"));
            }
            ops.push(format!("{}:{vout}", txid.to_lowercase()));
        }
        // H5: a YED-held outpoint is not unlockable here; a call naming one applies nothing
        if unlock {
            let held = self.yed_held_locks(node).await?;
            for op in &ops {
                if held.contains(op) {
                    let (t, n) = op.split_once(':').unwrap_or((op.as_str(), "0"));
                    let shown: String = yew_core::tx::txid_from_hex(t)
                        .map(|_| t.chars().take(10).collect())
                        .unwrap_or_default();
                    return Err(RpcError::new(code::WALLET_ERROR, format!(
                        "yed-locked-outpoint: COutPoint({shown}, {n}) holds YED; spending it outside the overlay would burn it. Use yed_unlockcoin \"<txid>\" <n> \"I understand this burns YED\" to release it deliberately."
                    )));
                }
            }
        }
        for op in ops {
            if unlock {
                self.st.locks.remove(&op);
            } else {
                self.st.locks.insert(op);
            }
        }
        self.persist_state()?;
        Ok(J::Bool(true))
    }

    /// The outpoints the YED overlay holds locked (`IsYellowbackLocked`): locked and holding YED.
    async fn yed_held_locks(&self, node: &dyn Node) -> Result<BTreeSet<String>, RpcError> {
        let reserved = self.yed_reserved(node).await?;
        Ok(reserved
            .into_iter()
            .map(|(t, n)| format!("{t}:{n}"))
            .filter(|k| self.st.locks.contains(k))
            .collect())
    }

    /// The fee-input locks of the remembered builds.
    fn build_locks(&self) -> BTreeSet<String> {
        let mut s = BTreeSet::new();
        for (k, h) in &self.st.builds {
            if let Some(t) = crate::build::parse_hex_tx(h) {
                for i in &t.vin {
                    let o = op_str(&i.prevout);
                    if &o != k {
                        s.insert(o);
                    }
                }
            }
        }
        s
    }

    /// `getrawchangeaddress`.
    fn getrawchangeaddress(&mut self, p: &[Value]) -> Result<J, RpcError> {
        if p.len() > 1 {
            return Err(RpcError::new(code::MISC_ERROR, "getrawchangeaddress"));
        }
        let s = self.new_change()?;
        self.persist_state()?;
        Ok(J::Str(script_address(self.network, &s).unwrap_or_default()))
    }

    /// `signrawtransaction "hexstring" ( [{"txid","vout","scriptPubKey","redeemScript","amount"},...] ["privatekey",...] sighashtype branchid )`.
    ///
    /// With private keys (`privatekeys` given, even empty) ycashd signs with those keys only and
    /// never the wallet's: the façade forwards such a call to the node, which signs (or, with
    /// `[]`, verifies) without a wallet. Otherwise the wallet's keys sign in the signer, every
    /// input bound to its prevout (the node's view, or `prevtxs` for one the node lacks), and the
    /// node verifies the result (`complete`, `errors`).
    async fn signrawtransaction(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        if p.is_empty() || p.len() > 5 {
            return Err(RpcError::new(code::MISC_ERROR, "signrawtransaction \"hexstring\" ( [{\"txid\":\"id\",\"vout\":n,\"scriptPubKey\":\"hex\",\"redeemScript\":\"hex\"},...] [\"privatekey1\",...] sighashtype )"));
        }
        if param(p, 2).is_some() {
            return forward(node, "signrawtransaction", p).await;
        }
        if let Some(t) = param(p, 3).and_then(|v| v.as_str()) {
            if t != "ALL" {
                return Err(invalid(format!("yewd: sighash type {t} is not signed by the wallet (ALL only); pass privatekeys to sign with the node")));
            }
        }
        let hexs = p[0]
            .as_str()
            .ok_or_else(|| RpcError::new(code::TYPE_ERROR, "Expected type string"))?;
        let raw =
            hex::decode(hexs).map_err(|_| invalid("argument 1 must be hexadecimal string"))?;
        let (tx, _) = Transaction::parse(&raw)
            .map_err(|_| RpcError::new(code::DESERIALIZATION_ERROR, "TX decode failed"))?;
        // prevouts: the caller's prevtxs first, then the node's view
        let mut given: Vec<(OutPoint, NodeCoin)> = Vec::new();
        if let Some(arr) = param(p, 1).and_then(|v| v.as_array()) {
            for o in arr {
                let txid = o["txid"].as_str().unwrap_or("");
                let vout = o["vout"].as_i64().unwrap_or(-1);
                if vout < 0 {
                    return Err(RpcError::new(
                        code::DESERIALIZATION_ERROR,
                        "vout must be positive",
                    ));
                }
                let op = OutPoint {
                    txid: yew_core::tx::txid_from_hex(txid)
                        .map_err(|_| invalid("txid must be hexadecimal string"))?,
                    n: vout as u32,
                };
                let script = hex::decode(o["scriptPubKey"].as_str().unwrap_or(""))
                    .map_err(|_| invalid("scriptPubKey must be hexadecimal string"))?;
                let value = o
                    .get("amount")
                    .filter(|v| !v.is_null())
                    .map(amount_param)
                    .transpose()?
                    .unwrap_or(0);
                given.push((
                    op,
                    NodeCoin {
                        value,
                        script,
                        height: None,
                        coinbase: false,
                    },
                ));
            }
        }
        let mut coins = Vec::with_capacity(tx.vin.len());
        let mut keys = Vec::with_capacity(tx.vin.len());
        let mut bound = true;
        for i in &tx.vin {
            let c = match given.iter().find(|(o, _)| *o == i.prevout) {
                Some((_, c)) => Some(c.clone()),
                None => node_coin(node, &i.prevout).await?,
            };
            match c {
                Some(c) => {
                    let template = yew_core::vault::parse_vault(&c.script).is_some()
                        || yew_core::vault::parse_intent(&c.script).is_some();
                    keys.push(if template || !i.script_sig.is_empty() {
                        KeyRef::None
                    } else {
                        self.key_of_script(&c.script).unwrap_or(KeyRef::None)
                    });
                    coins.push(c);
                }
                None => {
                    bound = false;
                    keys.push(KeyRef::None);
                    coins.push(NodeCoin {
                        value: 0,
                        script: vec![],
                        height: None,
                        coinbase: false,
                    });
                }
            }
        }
        let mut out = tx.clone();
        if bound && keys.iter().any(|k| *k != KeyRef::None) {
            let next = next_block(node).await?;
            out = self
                .sign_inputs(
                    &tx,
                    &coins,
                    &keys,
                    &[],
                    GatePath::Raw,
                    MAX_MONEY,
                    next.branch,
                )
                .await?;
        }
        // the node verifies (ycash6: its own signrawtransaction with no keys; kogany: yed_validaterawtransaction)
        let signed_hex = tx_hex(&out)?;
        // the caller's prevtxs as given (a P2SH one needs its redeemScript with keys given, even
        // none); the node finds the rest in its own view
        let prevtxs: Vec<Value> = param(p, 1)
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|o| {
                let spk = hex::decode(o["scriptPubKey"].as_str().unwrap_or("")).unwrap_or_default();
                yew_core::script::p2sh_hash(&spk).is_none() || o.get("redeemScript").is_some()
            })
            .collect();
        match node::call(
            node,
            "signrawtransaction",
            serde_json::json!([signed_hex, prevtxs, []]),
        )
        .await
        {
            Ok(v) => Ok(J::Raw(v.to_string())),
            Err(NodeError::Rpc { code: -32601, .. }) => {
                let v = node::call(
                    node,
                    "yed_validaterawtransaction",
                    serde_json::json!([signed_hex]),
                )
                .await?;
                let complete = v["valid"].as_bool().unwrap_or(false);
                let mut o = J::obj().with("hex", signed_hex).with("complete", complete);
                if !complete {
                    o.push(
                        "errors",
                        J::Arr(vec![J::obj().with(
                            "error",
                            v["invalidReason"].as_str().unwrap_or("").to_string(),
                        )]),
                    );
                }
                Ok(o)
            }
            Err(e) => Err(e.into()),
        }
    }
}

impl Wallet {
    /// `fundrawtransaction "hexstring" ( includeWatching )` (`CWallet::FundTransaction`): the
    /// transaction's outputs paid from its own inputs plus this wallet's coins, a change output
    /// appended, the ZIP-317 conventional fee; nothing is signed.
    async fn fundrawtransaction(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        if p.is_empty() || p.len() > 2 {
            return Err(RpcError::new(
                code::MISC_ERROR,
                "fundrawtransaction \"hexstring\" includeWatching",
            ));
        }
        let hexs = p[0]
            .as_str()
            .ok_or_else(|| RpcError::new(code::TYPE_ERROR, "Expected type string"))?;
        let raw = hex::decode(hexs).map_err(|e| {
            RpcError::new(
                code::DESERIALIZATION_ERROR,
                format!("TX decode failed: {e}"),
            )
        })?;
        let (base, _) = Transaction::parse(&raw).map_err(|e| {
            RpcError::new(
                code::DESERIALIZATION_ERROR,
                format!("TX decode failed: {e}"),
            )
        })?;
        let mut preset = 0i64;
        for i in &base.vin {
            match node_coin(node, &i.prevout).await? {
                Some(c) => preset += c.value,
                None => return Err(RpcError::new(code::INTERNAL_ERROR, "Insufficient funds")),
            }
        }
        let used: BTreeSet<(String, u32)> = base
            .vin
            .iter()
            .map(|i| (txid_hex(&i.prevout.txid), i.prevout.n))
            .collect();
        let coins: Vec<_> = self
            .spendable_yec(node, 0)
            .await?
            .into_iter()
            .filter(|c| !used.contains(&(txid_hex(&c.0.txid), c.0.n)))
            .collect();
        let mut fee = 10_000i64;
        for _ in 0..8 {
            let mut tx = base.clone();
            let need = tx.output_total() + fee - preset;
            let mut got = 0i64;
            let mut n_new = 0usize;
            for c in &coins {
                if got >= need {
                    break;
                }
                got += c.1;
                tx.vin.push(TxIn::new(c.0));
                n_new += 1;
            }
            if got < need {
                return Err(RpcError::new(code::INTERNAL_ERROR, "Insufficient funds"));
            }
            let change = got - need.max(0);
            let mut changepos = -1i64;
            if change > DUST {
                let sc = self.new_change()?;
                tx.vout.push(TxOut {
                    value: change,
                    script_pubkey: sc,
                });
                changepos = tx.vout.len() as i64 - 1;
            }
            let sizes = vec![MAX_P2PKH_SCRIPT_SIG; tx.vin.len()];
            let want = tx
                .zip317_conventional_fee(&sizes)
                .map_err(|e| RpcError::new(code::INTERNAL_ERROR, e.to_string()))?;
            if want > fee {
                fee = want;
                continue;
            }
            let _ = n_new;
            self.persist_state()?;
            let paid = preset + got - tx.output_total();
            return Ok(J::obj()
                .with("hex", tx_hex(&tx)?)
                .with("changepos", changepos)
                .with("fee", J::Amount(paid)));
        }
        Err(RpcError::new(
            code::INTERNAL_ERROR,
            "the fee did not converge",
        ))
    }
}

impl Wallet {
    /// `YedBurnedByRawTransaction` (H7, ycash6 `src/yellowback/wallet.cpp`): a raw transaction that
    /// spends this wallet's YED tokens and whose payload reassigns fewer cents than they hold is
    /// refused (`-4 yed-burn-refused`); a REDEEM spending a vault is MP-1's, never this guard's.
    pub async fn yed_burn_guard(&self, node: &dyn Node, p: &[Value]) -> Result<(), RpcError> {
        let Some(raw) = p
            .first()
            .and_then(|v| v.as_str())
            .and_then(|h| hex::decode(h).ok())
        else {
            return Ok(()); // the node's own decode error answers
        };
        let Ok((tx, _)) = Transaction::parse(&raw) else {
            return Ok(());
        };
        let found = yew_core::payload::find_payload(&tx).map(|f| f.payload);
        let (is_redeem, assigned) = match &found {
            Some(p @ yew_core::payload::Payload::Transfer { .. }) => (false, p.assigned_cents()),
            Some(p @ yew_core::payload::Payload::Redeem { .. }) => (true, p.assigned_cents()),
            _ => (false, 0),
        };
        let tokens = match self.tokens(node).await {
            Ok(t) => t,
            Err(_) => return Ok(()), // no Yellowback index: no guard (ycashd without -yellowback)
        };
        let mut cents = 0i64;
        let mut outpoints = Vec::new();
        for i in &tx.vin {
            let (t, n) = (txid_hex(&i.prevout.txid), i.prevout.n);
            if is_redeem {
                if let Ok(v) = node::call(node, "yed_getvault", serde_json::json!([t])).await {
                    if n == 0 && v["status"].is_string() {
                        return Ok(());
                    }
                }
            }
            if let Some(tok) = tokens.iter().find(|x| {
                x["txid"].as_str() == Some(t.as_str()) && x["vout"].as_u64() == Some(n as u64)
            }) {
                cents += tok["cents"].as_i64().unwrap_or(0);
                outpoints.push(format!("{t}:{n}"));
            }
        }
        if cents <= 0 || assigned >= cents {
            return Ok(());
        }
        Err(RpcError::new(
            code::WALLET_ERROR,
            format!(
                "yed-burn-refused: this transaction spends {cents} cents of this wallet's YED ({}) and its payload reassigns {assigned} of them, so {} cents of YED would be destroyed. Pass allowyedburn = true to send it anyway.",
                outpoints.join(", "),
                cents - assigned
            ),
        ))
    }
}

fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

async fn forward(node: &dyn Node, method: &str, p: &[Value]) -> Result<J, RpcError> {
    match node::call(node, method, Value::Array(p.to_vec())).await {
        Ok(v) => Ok(J::Raw(v.to_string())),
        Err(NodeError::Rpc { code, message }) => Err(RpcError::new(code, message)),
        Err(e) => Err(e.into()),
    }
}
