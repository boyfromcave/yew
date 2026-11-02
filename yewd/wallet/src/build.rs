// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The build machinery every build RPC shares (workspace plan §3b S2): the next block's height and
//! branch ID, the node's view of a coin (`gettxout`), funding from the wallet's confirmed P2PKH
//! coins (ycash6 `src/rpc/vault.cpp` `EligibleCoins`, `Fund`), coin locks, change keys, the sign
//! request to the signer (K-24: the façade builds the unsigned transaction and names every
//! prevout and key; the signer recomputes every digest), and the broadcast through the node.

use std::collections::{BTreeSet, HashSet};

use serde_json::Value;
use yew_core::tx::{OutPoint, Transaction, TxIn, TxOut};
use yewd_proto::{
    refuse, GatePath, KeyRef, OwnOutput, Prevout, Request, Response, SignInput, SignRequest,
};

use crate::keys::{Owner, INTERNAL};
use crate::node::{self, Node, NodeError};
use crate::{code, txid_hex, RpcError, Wallet};

/// The flat fee every vault RPC transaction pays (`VAULT_RPC_FEE`).
pub const VAULT_RPC_FEE: i64 = 10_000;
/// The smallest change output a vault build writes (`VAULT_RPC_MIN_CHANGE`); less goes to the fee.
pub const VAULT_RPC_MIN_CHANGE: i64 = 1_000;
/// `-txexpirydelta`'s default: a wallet payment expires 20 blocks after the next.
pub const TX_EXPIRY_DELTA: u32 = 20;
/// `-maxtxfee`'s default (0.1 YEC), the cap when the node reports none.
pub const DEFAULT_MAX_TX_FEE: i64 = 10_000_000;
/// `MAX_MONEY`.
pub const MAX_MONEY: i64 = 21_000_000 * 100_000_000;

/// The block the next transaction is judged in.
#[derive(Clone, Copy, Debug)]
pub struct Next {
    pub height: u32,
    pub branch: u32,
}

/// A coin as the node sees it (`gettxout … true`).
#[derive(Clone, Debug)]
pub struct NodeCoin {
    pub value: i64,
    pub script: Vec<u8>,
    /// `None` while in the mempool.
    pub height: Option<u32>,
    pub coinbase: bool,
}

/// An amount from a node's JSON number (eight decimals at most).
pub fn zat_of(v: &Value) -> Option<i64> {
    let f = v.as_f64()?;
    let z = (f * 100_000_000.0).round();
    (z.abs() <= MAX_MONEY as f64).then_some(z as i64)
}

/// `AmountFromValue`: a YEC amount parameter (number or numeric string), 8 decimals, in range.
pub fn amount_param(v: &Value) -> Result<i64, RpcError> {
    let text = match v {
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        _ => {
            return Err(RpcError::new(
                code::TYPE_ERROR,
                "Amount is not a number or string",
            ))
        }
    };
    let bad = || RpcError::new(code::TYPE_ERROR, "Invalid amount");
    let (neg, t) = match text.strip_prefix('-') {
        Some(t) => (true, t),
        None => (false, text.as_str()),
    };
    // exponent forms (1e-8) go through f64, still checked for eight decimals
    if t.contains(['e', 'E']) {
        let f: f64 = t.parse().map_err(|_| bad())?;
        let z = (f * 1e8).round();
        if (z / 1e8 - f).abs() > 1e-12 || z > MAX_MONEY as f64 {
            return Err(bad());
        }
        return Ok(if neg { -(z as i64) } else { z as i64 });
    }
    let (i, frac) = t.split_once('.').unwrap_or((t, ""));
    if i.is_empty() && frac.is_empty()
        || frac.len() > 8
        || !i.chars().all(|c| c.is_ascii_digit())
        || !frac.chars().all(|c| c.is_ascii_digit())
    {
        return Err(bad());
    }
    let whole: i64 = if i.is_empty() {
        0
    } else {
        i.parse().map_err(|_| bad())?
    };
    let mut f = frac.to_string();
    while f.len() < 8 {
        f.push('0');
    }
    let z = whole
        .checked_mul(100_000_000)
        .and_then(|w| w.checked_add(f.parse::<i64>().unwrap_or(0)))
        .ok_or_else(|| RpcError::new(code::TYPE_ERROR, "Amount out of range"))?;
    if z > MAX_MONEY {
        return Err(RpcError::new(code::TYPE_ERROR, "Amount out of range"));
    }
    Ok(if neg { -z } else { z })
}

/// `ParseOutPoint`: `"txid:n"` or `{"txid", "vout"}`.
pub fn outpoint_param(v: &Value, name: &str) -> Result<OutPoint, RpcError> {
    let bad = || {
        RpcError::new(
            code::INVALID_PARAMETER,
            format!("{name} must be \"txid:n\" or {{\"txid\", \"vout\"}}"),
        )
    };
    let (t, n) = match v {
        Value::String(s) => {
            let (t, n) = s.rsplit_once(':').ok_or_else(bad)?;
            (t.to_string(), n.parse::<u32>().map_err(|_| bad())?)
        }
        Value::Object(o) => (
            o.get("txid")
                .and_then(|t| t.as_str())
                .ok_or_else(bad)?
                .to_string(),
            o.get("vout").and_then(|n| n.as_u64()).ok_or_else(bad)? as u32,
        ),
        _ => return Err(bad()),
    };
    if t.len() != 64 {
        return Err(bad());
    }
    let txid = yew_core::tx::txid_from_hex(&t).map_err(|_| bad())?;
    Ok(OutPoint { txid, n })
}

pub fn op_str(o: &OutPoint) -> String {
    format!("{}:{}", txid_hex(&o.txid), o.n)
}

/// `FormatMoney` for messages.
pub fn money(z: i64) -> String {
    crate::rpc::format_money(z)
}

impl From<NodeError> for Box<RpcError> {
    fn from(e: NodeError) -> Box<RpcError> {
        Box::new(e.into())
    }
}

/// Funding modes (`FundMode`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FundMode {
    LargestFirst,
    SmallChange,
}

/// One input of a build: the coin the wallet chose and its key.
#[derive(Clone, Debug)]
pub struct Chosen {
    pub outpoint: OutPoint,
    pub value: i64,
    pub script: Vec<u8>,
}

pub async fn next_block(node: &dyn Node) -> Result<Next, RpcError> {
    let info = node::call(node, "getblockchaininfo", serde_json::json!([])).await?;
    let height = info["blocks"].as_u64().unwrap_or(0) as u32 + 1;
    let branch = info["consensus"]["nextblock"]
        .as_str()
        .and_then(|s| u32::from_str_radix(s, 16).ok())
        .ok_or_else(|| {
            RpcError::new(
                code::MISC_ERROR,
                "yewd: the node reports no consensus.nextblock",
            )
        })?;
    Ok(Next { height, branch })
}

/// The node's view of an unspent output (chain tip and mempool); `None` when spent or unknown.
pub async fn node_coin(node: &dyn Node, o: &OutPoint) -> Result<Option<NodeCoin>, RpcError> {
    let v = node::call(
        node,
        "gettxout",
        serde_json::json!([txid_hex(&o.txid), o.n, true]),
    )
    .await?;
    if v.is_null() {
        return Ok(None);
    }
    let value = zat_of(&v["value"])
        .ok_or_else(|| RpcError::new(code::MISC_ERROR, "yewd: gettxout: no value"))?;
    let script = hex::decode(v["scriptPubKey"]["hex"].as_str().unwrap_or(""))
        .map_err(|e| RpcError::new(code::MISC_ERROR, format!("yewd: gettxout: {e}")))?;
    let conf = v["confirmations"].as_u64().unwrap_or(0) as u32;
    let height = if conf == 0 {
        None
    } else {
        let best = v["bestblock"].as_str().unwrap_or("");
        // the tip the answer is relative to: the wallet syncs to it before every build
        let tip = match node::call(node, "getblockheader", serde_json::json!([best])).await {
            Ok(h) => h["height"].as_u64().unwrap_or(0) as u32,
            Err(_) => node::block_count(node).await?,
        };
        Some(tip + 1 - conf)
    };
    Ok(Some(NodeCoin {
        value,
        script,
        height,
        coinbase: v["coinbase"].as_bool().unwrap_or(false),
    }))
}

/// A signer refusal or failure as ycashd's error.
pub fn signer_error(e: Result<Response, String>) -> RpcError {
    match e {
        Ok(Response::Refused(r)) => {
            let c = match r.code.as_str() {
                refuse::SET_SIGN_ONCE
                | refuse::SET_SIGN_RESTORED
                | refuse::OUTFLOW
                | refuse::FOREIGN_INPUT => code::WALLET_ERROR,
                refuse::BAD_VERSION => code::WALLET_UNLOCK_NEEDED,
                _ => code::WALLET_ERROR,
            };
            // the set refusals already carry ycashd's text
            if r.reason.starts_with(&r.code) {
                RpcError::new(c, r.reason)
            } else {
                RpcError::new(c, format!("yewd-signer refused ({}): {}", r.code, r.reason))
            }
        }
        Ok(other) => RpcError::new(
            code::INTERNAL_ERROR,
            format!("yewd: unexpected signer answer {other:?}"),
        ),
        Err(m) => RpcError::new(
            code::WALLET_UNLOCK_NEEDED,
            format!("Error: the signer is not available ({m})"),
        ),
    }
}

impl Wallet {
    /// The vault/Yellowback fee cap (`YedMaxTxFee`), from `yed_getinfo` when the node has the
    /// Yellowback index, else `-maxtxfee`'s default.
    pub async fn max_tx_fee(&self, node: &dyn Node) -> i64 {
        match node::call(node, "yed_getinfo", serde_json::json!([])).await {
            Ok(v) => v["params"]["fees"]["network"]["yellowback"]["maxTxFeeZat"]
                .as_i64()
                .unwrap_or(DEFAULT_MAX_TX_FEE),
            Err(_) => DEFAULT_MAX_TX_FEE,
        }
    }

    /// The key reference of a script this wallet owns.
    pub fn key_of_script(&self, script: &[u8]) -> Option<KeyRef> {
        match self.book.owns_script(script)? {
            Owner::T(chain, index) => Some(KeyRef::Bip32 { chain, index }),
            Owner::Pq(scheme, index) => Some(KeyRef::Pq { scheme, index }),
        }
    }

    /// The BIP32 reference of a compressed public key this wallet holds.
    pub fn key_of_pubkey(&self, pk: &[u8; 33]) -> Option<KeyRef> {
        let k = self.book.by_hash(&yew_core::keys::hash160(pk))?;
        (k.pubkey == *pk).then_some(KeyRef::Bip32 {
            chain: k.chain,
            index: k.index,
        })
    }

    /// The PQ owner reference of a key id this wallet holds.
    pub fn owner_ref(&self, id: &yew_core::pq::PqKeyId, selector: u8) -> Option<KeyRef> {
        let k = self.book.pq_by_id(id)?;
        Some(KeyRef::PqOwner {
            scheme: k.scheme,
            index: k.index,
            selector,
        })
    }

    /// A new change key on the internal chain (`m/44'/347'/0'/1/i`); its P2PKH script.
    pub fn new_change(&mut self) -> Result<Vec<u8>, RpcError> {
        let index = self.st.issued.internal;
        self.st.issued.internal = index + 1;
        self.refresh_keys()
            .map_err(|e| RpcError::new(code::WALLET_ERROR, e))?;
        let k = self
            .book
            .key(INTERNAL, index)
            .expect("derived by refresh_keys");
        Ok(yew_core::script::p2pkh_script(&k.hash))
    }

    /// A new receive key (`NewWalletKey`: a fresh external HD key, as `getnewaddress`, without
    /// an address-book entry); its compressed public key.
    pub fn new_wallet_key(&mut self) -> Result<[u8; 33], RpcError> {
        let index = self.st.issued.external;
        self.st.issued.external = index + 1;
        self.refresh_keys()
            .map_err(|e| RpcError::new(code::WALLET_ERROR, e))?;
        Ok(self
            .book
            .key(crate::keys::EXTERNAL, index)
            .expect("derived")
            .pubkey)
    }

    pub fn lock_coin(&mut self, o: &OutPoint) {
        self.st.locks.insert(op_str(o));
    }

    pub fn unlock_coin(&mut self, o: &OutPoint) {
        self.st.locks.remove(&op_str(o));
    }

    pub fn is_locked(&self, o: &OutPoint) -> bool {
        self.st.locks.contains(&op_str(o))
    }

    /// `EligibleCoins`: the wallet's confirmed, mature, unlocked P2PKH coins outside `used`,
    /// largest first, each also unspent and confirmed in the node's view.
    pub async fn eligible(
        &self,
        node: &dyn Node,
        used: &HashSet<OutPoint>,
    ) -> Result<Vec<Chosen>, RpcError> {
        let spent = self.mempool_spent();
        let reserved = self.yed_reserved(node).await?;
        let mut out = Vec::new();
        for (c, d) in self.available_coins(None) {
            if d < 1
                || !matches!(c.owner, Owner::T(..))
                || spent.contains(&(c.txid.clone(), c.vout))
                || reserved.contains(&(c.txid.clone(), c.vout))
            {
                continue;
            }
            let op = OutPoint {
                txid: yew_core::tx::txid_from_hex(&c.txid)
                    .map_err(|e| RpcError::new(code::MISC_ERROR, e))?,
                n: c.vout,
            };
            if used.contains(&op) {
                continue;
            }
            match node_coin(node, &op).await? {
                Some(n) if n.height.is_some() && n.value == c.value && n.script == c.script => {}
                _ => continue,
            }
            out.push(Chosen {
                outpoint: op,
                value: c.value,
                script: c.script.clone(),
            });
        }
        out.sort_by(|a, b| {
            b.value
                .cmp(&a.value)
                .then((a.outpoint.txid, a.outpoint.n).cmp(&(b.outpoint.txid, b.outpoint.n)))
        });
        Ok(out)
    }

    /// The outputs YED holds, never spent as YEC (ycashd's overlay locks them, H5): the index's
    /// tokens at this wallet's scripts, and every output of a mempool wallet transaction that
    /// carries a payload (its tokens are not indexed until it confirms).
    pub async fn yed_reserved(&self, node: &dyn Node) -> Result<BTreeSet<(String, u32)>, RpcError> {
        let mut r = BTreeSet::new();
        if let Ok(tokens) = self.tokens(node).await {
            for t in tokens {
                if let (Some(txid), Some(vout)) = (t["txid"].as_str(), t["vout"].as_u64()) {
                    r.insert((txid.to_string(), vout as u32));
                }
            }
        }
        for (txid, p) in self.parsed_all() {
            let mempool = self.st.wtx.get(txid).is_some_and(|w| w.block.is_none());
            let payload = p.tx.vout.iter().any(|o| {
                yew_core::script::is_op_return(&o.script_pubkey)
                    && !yewd_proto::act::is_act_output(&o.script_pubkey)
            });
            if mempool && payload {
                for n in 0..p.tx.vout.len() {
                    r.insert((txid.clone(), n as u32));
                }
            }
        }
        Ok(r)
    }

    /// `Fund`: add wallet P2PKH inputs (and a change output) so inputs = outputs + `fee`, given
    /// `input_value` already provided by the transaction's inputs. The chosen coins are locked.
    pub async fn fund(
        &mut self,
        node: &dyn Node,
        tx: &mut Transaction,
        input_value: i64,
        fee: i64,
        mode: FundMode,
    ) -> Result<Vec<Chosen>, RpcError> {
        let out: i64 = tx.output_total();
        let needed = out + fee - input_value;
        let used: HashSet<OutPoint> = tx.vin.iter().map(|i| i.prevout).collect();
        let eligible = self.eligible(node, &used).await?;
        let mut chosen: Vec<Chosen> = Vec::new();
        let mut got = 0i64;
        if needed > 0 && mode == FundMode::SmallChange {
            if let Some(c) = eligible.iter().rev().find(|c| c.value >= needed) {
                got = c.value;
                chosen.push(c.clone());
            }
        }
        if chosen.is_empty() {
            for c in &eligible {
                if needed <= 0 || got >= needed {
                    break;
                }
                got += c.value;
                chosen.push(c.clone());
            }
        }
        if got < needed {
            return Err(RpcError::new(
                code::WALLET_INSUFFICIENT_FUNDS,
                format!(
                    "insufficient confirmed transparent funds: need {} more",
                    money(needed - got)
                ),
            ));
        }
        for c in &chosen {
            tx.vin.push(TxIn::new(c.outpoint));
        }
        let change = got - needed;
        if change >= VAULT_RPC_MIN_CHANGE {
            let script = self.new_change()?;
            tx.vout.push(TxOut {
                value: change,
                script_pubkey: script,
            });
        }
        for c in &chosen {
            self.lock_coin(&c.outpoint);
        }
        self.persist_state()?;
        Ok(chosen)
    }

    pub fn persist_state(&self) -> Result<(), RpcError> {
        self.save()
            .map_err(|e| RpcError::new(code::WALLET_ERROR, e))
    }

    /// Every input's prevout from the node's view (`None` for an input the node does not know:
    /// spent, or never seen).
    pub async fn prevouts_of(
        &self,
        node: &dyn Node,
        tx: &Transaction,
    ) -> Result<Vec<Option<NodeCoin>>, RpcError> {
        let mut v = Vec::with_capacity(tx.vin.len());
        for i in &tx.vin {
            v.push(node_coin(node, &i.prevout).await?);
        }
        Ok(v)
    }

    /// Ask the signer to sign the inputs `sign` names (by index) of `tx`; every prevout must be
    /// known. The preview, the own outputs and the outflow are computed here and recomputed by
    /// the signer.
    #[allow(clippy::too_many_arguments)]
    pub async fn sign_inputs(
        &self,
        tx: &Transaction,
        prevouts: &[NodeCoin],
        keys: &[KeyRef],
        extra_own: &[OwnOutput],
        path: GatePath,
        cap: i64,
        branch: u32,
    ) -> Result<Transaction, RpcError> {
        let mut inputs = Vec::with_capacity(tx.vin.len());
        let mut signed = BTreeSet::new();
        for (i, (vin, p)) in tx.vin.iter().zip(prevouts).enumerate() {
            if keys[i] != KeyRef::None {
                signed.insert(i as u32);
            }
            inputs.push(SignInput {
                prevout: Prevout {
                    outpoint: op_str(&vin.prevout),
                    script: hex::encode(&p.script),
                    amount_zat: p.value,
                },
                key: keys[i],
                carrier_bundle: match keys[i] {
                    KeyRef::Carrier { .. } => self
                        .st
                        .carriers
                        .get(&op_str(&vin.prevout))
                        .map(|c| c.bundle.clone()),
                    _ => None,
                },
            });
        }
        let mut own_outputs: Vec<OwnOutput> = Vec::new();
        let mut own = BTreeSet::new();
        for (n, o) in tx.vout.iter().enumerate() {
            if let Some(k) = self.key_of_script(&o.script_pubkey) {
                own.insert(n as u32);
                own_outputs.push(OwnOutput {
                    n: n as u32,
                    key: k,
                    bond_locktime: None,
                });
            }
        }
        for e in extra_own {
            if own.insert(e.n) {
                own_outputs.push(e.clone());
            }
        }
        let proto_prevouts: Vec<Prevout> = inputs.iter().map(|i| i.prevout.clone()).collect();
        let preview =
            yewd_proto::preview::compute(self.network, tx, &proto_prevouts, &signed, &own);
        let req = SignRequest {
            tx: hex::encode(
                tx.serialize()
                    .map_err(|e| RpcError::new(code::INTERNAL_ERROR, e.to_string()))?,
            ),
            branch_id: branch,
            inputs,
            own_outputs,
            gate_path: path,
            outflow_cap_zat: cap,
            preview,
        };
        match self.signer.request(Request::Sign(req)) {
            Ok(Response::Signed(s)) => {
                let raw = hex::decode(&s.tx)
                    .map_err(|e| RpcError::new(code::INTERNAL_ERROR, e.to_string()))?;
                Transaction::parse(&raw).map(|(t, _)| t).map_err(|e| {
                    RpcError::new(
                        code::INTERNAL_ERROR,
                        format!("yewd: the signer's transaction: {e}"),
                    )
                })
            }
            other => Err(signer_error(other)),
        }
    }

    /// `SignWalletInputs` for a transaction this wallet built: every input whose coin this wallet
    /// can sign (P2PKH and `TX_PQPKH`, not a template) is signed; template and foreign inputs keep
    /// their scriptSigs.
    pub async fn sign_wallet_inputs(
        &self,
        node: &dyn Node,
        tx: &Transaction,
        path: GatePath,
        cap: i64,
        next: Next,
    ) -> Result<Transaction, RpcError> {
        let prevouts = self.prevouts_of(node, tx).await?;
        let mut coins = Vec::with_capacity(prevouts.len());
        let mut keys = Vec::with_capacity(prevouts.len());
        for (i, p) in prevouts.into_iter().enumerate() {
            let p = p.ok_or_else(|| {
                RpcError::new(
                    code::TRANSACTION_ERROR,
                    format!(
                        "Missing inputs: input {i} ({}) is spent or unknown",
                        op_str(&tx.vin[i].prevout)
                    ),
                )
            })?;
            let template = yew_core::vault::parse_vault(&p.script).is_some()
                || yew_core::vault::parse_intent(&p.script).is_some();
            keys.push(if template {
                KeyRef::None
            } else {
                self.key_of_script(&p.script).unwrap_or(KeyRef::None)
            });
            coins.push(p);
        }
        // a SET_JOIN bond of a member key this wallet holds is its own output (HandoffSend's rule)
        let mut own = Vec::new();
        for o in &tx.vout {
            if let Ok(a) = yewd_proto::act::decode(&o.script_pubkey) {
                if let yewd_proto::act::Body::Join {
                    member_key,
                    bond_locktime,
                    bond_vout,
                    ..
                } = a.body
                {
                    if let Some(k) = self.key_of_pubkey(&member_key) {
                        own.push(OwnOutput {
                            n: bond_vout as u32,
                            key: k,
                            bond_locktime: Some(bond_locktime),
                        });
                    }
                }
            }
        }
        self.sign_inputs(tx, &coins, &keys, &own, path, cap, next.branch)
            .await
    }

    /// `Broadcast`: the vault/Yellowback fee cap (`absurdly-high-fee`), then the node's
    /// `sendrawtransaction`; the wallet picks the transaction up from the mempool at once.
    pub async fn broadcast(
        &mut self,
        node: &dyn Node,
        tx: &Transaction,
        cap: Option<i64>,
    ) -> Result<String, RpcError> {
        let raw = tx
            .serialize()
            .map_err(|e| RpcError::new(code::INTERNAL_ERROR, e.to_string()))?;
        if let Some(cap) = cap {
            let prevouts = self.prevouts_of(node, tx).await?;
            if prevouts.iter().all(Option::is_some) {
                let fee: i64 =
                    prevouts.iter().flatten().map(|p| p.value).sum::<i64>() - tx.output_total();
                if fee > cap {
                    return Err(RpcError::new(
                        code::TRANSACTION_REJECTED,
                        format!(
                            "absurdly-high-fee: {} exceeds the vault/Yellowback cap {} (-maxtxfee, -yellowbackmaxtxfeeusd, -yellowbackmaxtxfee)",
                            money(fee),
                            money(cap)
                        ),
                    ));
                }
            }
        }
        let txid = match node::call(
            node,
            "sendrawtransaction",
            serde_json::json!([hex::encode(&raw), true]),
        )
        .await
        {
            Ok(v) => v.as_str().unwrap_or_default().to_string(),
            Err(NodeError::Rpc { code, message }) => return Err(RpcError::new(code, message)),
            Err(e) => return Err(e.into()),
        };
        self.sync(node).await?;
        Ok(txid)
    }

    /// `PruneVaultBuilds`: forget the remembered builds whose template coin is gone, releasing
    /// their locks.
    pub async fn prune_builds(&mut self, node: &dyn Node) -> Result<(), RpcError> {
        let keys: Vec<String> = self.st.builds.keys().cloned().collect();
        let mut changed = false;
        for k in keys {
            let op = outpoint_param(&Value::String(k.clone()), "build")?;
            if node_coin(node, &op).await?.is_some() {
                continue;
            }
            if let Some(hex) = self.st.builds.remove(&k) {
                if let Some(t) = parse_hex_tx(&hex) {
                    self.unlock_build_inputs(&op, &t);
                }
            }
            changed = true;
        }
        if changed {
            self.persist_state()?;
        }
        Ok(())
    }

    pub fn unlock_build_inputs(&mut self, templ: &OutPoint, t: &Transaction) {
        for i in &t.vin {
            if i.prevout != *templ {
                self.unlock_coin(&i.prevout);
            }
        }
    }

    /// `RememberBuild`: the unsigned build of `templ` (the template input's scriptSig cleared).
    pub fn remember_build(&mut self, templ: &OutPoint, tx: &Transaction) -> Result<(), RpcError> {
        let mut t = tx.clone();
        for i in t.vin.iter_mut() {
            if i.prevout == *templ {
                i.script_sig.clear();
            }
        }
        let hex = hex::encode(
            t.serialize()
                .map_err(|e| RpcError::new(code::INTERNAL_ERROR, e.to_string()))?,
        );
        self.st.builds.insert(op_str(templ), hex);
        self.persist_state()
    }

    pub fn build_of(&self, templ: &OutPoint) -> Option<Transaction> {
        self.st
            .builds
            .get(&op_str(templ))
            .and_then(|h| parse_hex_tx(h))
    }
}

pub fn parse_hex_tx(h: &str) -> Option<Transaction> {
    let raw = hex::decode(h).ok()?;
    Transaction::parse(&raw).ok().map(|(t, _)| t)
}

/// `DecodeMutable`: `-22 TX decode failed`.
pub fn decode_tx_param(v: &Value) -> Result<Transaction, RpcError> {
    let s = v
        .as_str()
        .ok_or_else(|| RpcError::new(code::TYPE_ERROR, "Expected type string"))?;
    parse_hex_tx(s).ok_or_else(|| RpcError::new(code::DESERIALIZATION_ERROR, "TX decode failed"))
}

pub fn tx_hex(t: &Transaction) -> Result<String, RpcError> {
    Ok(hex::encode(t.serialize().map_err(|e| {
        RpcError::new(code::INTERNAL_ERROR, e.to_string())
    })?))
}

pub fn txid_of(t: &Transaction) -> Result<String, RpcError> {
    Ok(txid_hex(&t.txid().map_err(|e| {
        RpcError::new(code::INTERNAL_ERROR, e.to_string())
    })?))
}
