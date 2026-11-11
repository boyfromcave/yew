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

use crate::json::J;
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

/// The node rejections `sendrawtransaction` answers when it certainly did not take the
/// transaction: `RPC_VERIFY_ERROR` (-25), `RPC_VERIFY_REJECTED` (-26),
/// `RPC_VERIFY_ALREADY_IN_CHAIN` (-27). Any other error is "status unknown" (review
/// YEW-REVIEW-3 L2).
pub const DEFINITE_REFUSALS: [i64; 3] = [-25, -26, -27];

/// How far past its `nExpiryHeight` (or below a conflicting spend) the tip must be before a
/// submission of unknown status is judged dead and its inputs released: a reorganization of
/// fewer blocks cannot bring it back (review YEW-REVIEW-3 L1).
pub const UNKNOWN_REORG_MARGIN: u32 = 10;

/// `clearunknownsubmission`'s help (yewd's own RPC; not a ycashd method).
pub const CLEAR_UNKNOWN_HELP: &str = "clearunknownsubmission \"txid\"\n\nRelease the coins of a submission whose status is unknown (sendrawtransaction's answer was lost), before yewd judges it dead.\nyewd releases them by itself once the chain is 10 blocks past the transaction's expiry height, or once one of its inputs is spent by another transaction 10 blocks deep; until then every send is refused.\n\nRISK: if the transaction reached any node it can still be mined until its expiry height. A payment sent again from the released coins can then go out twice. Use this only when you know it reached no node.\n\nArguments:\n1. \"txid\"    (string, required) the txid of the submission of unknown status (the one named in the refusal)\n\nResult:\n{\n  \"txid\": \"txid\",          (string) the cleared submission\n  \"released\": [\"txid:n\"],  (array) the coins released\n  \"expiryheight\": n        (numeric) its expiry height: it may be mined until then\n}\n";

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
        if neg && z > 0.0 {
            return Err(RpcError::new(code::TYPE_ERROR, "Amount out of range"));
        }
        return Ok(z as i64);
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
    // MoneyRange: a negative amount is out of range (ParseFixedPoint keeps the sign)
    if z > MAX_MONEY || (neg && z > 0) {
        return Err(RpcError::new(code::TYPE_ERROR, "Amount out of range"));
    }
    Ok(z)
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
            let c =
                match r.code.as_str() {
                    refuse::SET_SIGN_ONCE
                    | refuse::SET_SIGN_RESTORED
                    | refuse::OUTFLOW
                    | refuse::FOREIGN_INPUT => code::WALLET_ERROR,
                    refuse::BAD_VERSION => code::WALLET_UNLOCK_NEEDED,
                    refuse::LOCKED => return RpcError::new(
                        code::WALLET_UNLOCK_NEEDED,
                        "Error: Please enter the wallet passphrase with walletpassphrase first.",
                    ),
                    refuse::BAD_PASSPHRASE => code::WALLET_PASSPHRASE_INCORRECT,
                    refuse::WRONG_ENC_STATE => code::WALLET_WRONG_ENC_STATE,
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

/// The refusal of a plain YEC spend by a wallet that has held YED while the node reports
/// Yellowback not live (the C++ lines refuse to start; yewd refuses at send time, since it can be
/// pointed at another node without a restart).
pub const HELD_YED_REFUSAL: &str = "This wallet has held YED, but Yellowback is not live on the connected node, so its YED outputs cannot be told apart from plain YEC. Connect to a node with the network's attestor set, or start yewd with -yellowback=0 to acknowledge that they are spendable as plain YEC.";

/// What `-yellowback=0` logs at start and on each such send.
pub const HELD_YED_ACK_WARNING: &str = "This wallet has held YED and Yellowback is not live (-yellowback=0): its YED outputs are not locked, and any send that spends one destroys the YED it carries.";

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
    ///
    /// Fail closed (beta2, burn safety): every path that selects transparent or post-quantum
    /// coins for a plain YEC spend takes the set from here, and gets it only when the node can
    /// answer for its Yellowback index. The test for "Yellowback is not live on this node" is
    /// what the node reports, by JSON-RPC code, not by message text: `yed_getinfo` answers
    /// `-32601` (ycashd's and kogany's `EnsureIndex`: the yed_* commands exist only while the
    /// vault upgrade and a YED attestor set are configured; lightwalletd-dd's `ProbeYellowback`
    /// reads the same code the same way), and then no token can exist, so the send proceeds,
    /// with every own output of exactly `TOKEN_VALUE` still reserved unless `-yellowback=0`
    /// (a proxy that filters the yed_* commands answers the same code; review YEW-REVIEW-3 L3).
    /// Every other answer is "live": `healthy` must be `true` and `yed_listtokens` must answer;
    /// an unhealthy index, any `yed_getinfo` failure other than `-32601` (node unreachable,
    /// warming up, malformed) or any `yed_listtokens` failure while live refuses with the C++
    /// lines' string (ycash-dd 8e67b2a35 `YellowbackInputRefusal`). yewd is a sidecar, so the
    /// "restart with -reindex-yellowback" in that string is advice for the node; the node's own
    /// error is logged here. On the vault line `-yellowback` is accepted and ignored (ycash6
    /// `init.cpp`): the yed_* commands exist exactly where the vault upgrade and a YED attestor set
    /// are configured, consensus-wide, so a `-32601` node is on a chain where no token can exist.
    /// This is the only reservation: the reads that depend on it (`z_gettotalbalance`, the lock
    /// RPCs, `yed_getinfo.lockedOutputs`) fail or say so too, never answer as if nothing were held.
    pub async fn yed_reserved(&self, node: &dyn Node) -> Result<BTreeSet<(String, u32)>, RpcError> {
        let refuse = |reason: String, logged: String| {
            eprintln!("yewd: refusing plain YEC spends: the node's Yellowback index cannot be read ({logged})");
            RpcError::new(
                code::WALLET_ERROR,
                format!("refusing to spend as plain YEC while the Yellowback index is unhealthy ({reason}): the wallet's YED coin locks cannot be trusted; restart with -reindex-yellowback"),
            )
        };
        let live = match node::call(node, "yed_getinfo", serde_json::json!([])).await {
            Err(NodeError::Rpc { code: c, .. }) if c == code::METHOD_NOT_FOUND => {
                // a wallet that has held YED cannot tell its YED outputs from plain YEC here
                if self.st.yed_held {
                    if !self.opts.yellowback_ack {
                        return Err(RpcError::new(code::WALLET_ERROR, HELD_YED_REFUSAL));
                    }
                    eprintln!("yewd: {HELD_YED_ACK_WARNING}");
                }
                false
            }
            Err(e) => return Err(refuse(e.to_string(), format!("yed_getinfo: {e}"))),
            Ok(v) => {
                if v["healthy"].as_bool() != Some(true) {
                    let reason = v["unhealthyReason"].as_str().unwrap_or("").to_string();
                    return Err(refuse(
                        reason.clone(),
                        format!(
                            "yed_getinfo: healthy {}, unhealthyReason {reason:?}",
                            v["healthy"]
                        ),
                    ));
                }
                true
            }
        };
        let mut r = BTreeSet::new();
        match self.tokens(node).await {
            Ok(tokens) => {
                for t in tokens {
                    if let (Some(txid), Some(vout)) = (t["txid"].as_str(), t["vout"].as_u64()) {
                        r.insert((txid.to_string(), vout as u32));
                    }
                }
            }
            // not live: the node has no yed_* command at all, so it lists no token; but a node
            // that hides them (an RPC-filtering proxy answers -32601 too) cannot be told apart,
            // so every own output of exactly TOKEN_VALUE stays reserved, as the app's classifier
            // keeps it HELD, unless the operator acknowledged with -yellowback=0 (review
            // YEW-REVIEW-3 L3)
            Err(e) if !live && e.code == code::METHOD_NOT_FOUND => {
                if !self.opts.yellowback_ack {
                    for c in &self.coins {
                        if c.value == yew_core::params::TOKEN_VALUE {
                            r.insert((c.txid.clone(), c.vout));
                        }
                    }
                }
            }
            Err(e) => {
                let reason = e
                    .message
                    .trim_start_matches("yellowback-unhealthy: ")
                    .trim_end_matches("; restart with -reindex-yellowback")
                    .to_string();
                return Err(refuse(
                    reason,
                    format!("yed_listtokens: node error {}: {}", e.code, e.message),
                ));
            }
        }
        r.extend(self.payload_reserved());
        Ok(r)
    }

    /// Every output of a mempool wallet transaction that carries a Yellowback payload.
    fn payload_reserved(&self) -> BTreeSet<(String, u32)> {
        let mut r = BTreeSet::new();
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
        r
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
        let hexs = self
            .sign_inputs_hex(tx, prevouts, keys, extra_own, path, cap, branch, None)
            .await?;
        let raw =
            hex::decode(&hexs).map_err(|e| RpcError::new(code::INTERNAL_ERROR, e.to_string()))?;
        Transaction::parse(&raw).map(|(t, _)| t).map_err(|e| {
            RpcError::new(
                code::INTERNAL_ERROR,
                format!("yewd: the signer's transaction: {e}"),
            )
        })
    }

    /// [`Wallet::sign_inputs`] with a Sapling part (S4): the signer builds, proves and
    /// authorizes it with the transparent part; the whole transaction comes back as hex.
    #[allow(clippy::too_many_arguments)]
    pub async fn sign_inputs_hex(
        &self,
        tx: &Transaction,
        prevouts: &[NodeCoin],
        keys: &[KeyRef],
        extra_own: &[OwnOutput],
        path: GatePath,
        cap: i64,
        branch: u32,
        sapling: Option<yewd_proto::SaplingPart>,
    ) -> Result<String, RpcError> {
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
        let preview = yewd_proto::preview::with_sapling(
            yewd_proto::preview::compute(self.network, tx, &proto_prevouts, &signed, &own),
            sapling.as_ref(),
        );
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
            sapling,
        };
        match self.signer.request(Request::Sign(req)) {
            Ok(Response::Signed(s)) => Ok(s.tx),
            other => Err(signer_error(other)),
        }
    }

    /// `sendrawtransaction` of a whole transaction's hex (one with a Sapling part), then the
    /// barrier: the wallet sees it before the call returns.
    pub async fn broadcast_hex(&mut self, node: &dyn Node, hexs: &str) -> Result<String, RpcError> {
        self.submit(node, hexs, serde_json::json!([hexs, true]), RpcError::new)
            .await
    }

    /// The one submission path (review M1: never report a payment the node may have accepted as
    /// failed). A transaction still of unknown status from an earlier call is resolved first and
    /// this call refused once with its outcome ([`Wallet::resolve_unknown`]). Then
    /// `sendrawtransaction`: a node refusal (a JSON-RPC error) is `refused(code, message)`;
    /// an accepted transaction always returns its txid, and the barrier sync after it is a
    /// logged warning only; a lost answer (transport error, timeout) is settled by asking the
    /// node for the txid computed from the bytes, a few times over about a second, and is
    /// either the txid (the node has it) or "status unknown, txid …: check before sending
    /// again", with the inputs kept locked. Nothing is ever submitted again automatically.
    pub(crate) async fn submit(
        &mut self,
        node: &dyn Node,
        hexs: &str,
        params: Value,
        refused: impl Fn(i64, String) -> RpcError,
    ) -> Result<String, RpcError> {
        self.resolve_unknown(node).await?;
        // the txid parse computes over the bytes (Transaction::txid re-serializes, which a
        // Sapling part does not allow)
        let (tx, txid_bytes) = hex::decode(hexs)
            .ok()
            .and_then(|b| Transaction::parse(&b).ok())
            .ok_or_else(|| {
                RpcError::new(code::INTERNAL_ERROR, "submit: unparseable transaction")
            })?;
        let local = txid_hex(&txid_bytes);
        let txid = match node::call(node, "sendrawtransaction", params).await {
            Ok(v) => v.as_str().map_or(local.clone(), str::to_string),
            // review YEW-REVIEW-3 L2: only the node's own rejections are a refusal
            // (RPC_VERIFY_ERROR, RPC_VERIFY_REJECTED, RPC_VERIFY_ALREADY_IN_CHAIN); any other
            // JSON-RPC error (-32603 or -1 from a proxy that timed out, …) is a lost answer
            Err(NodeError::Rpc { code, message }) if DEFINITE_REFUSALS.contains(&code) => {
                return Err(refused(code, message))
            }
            Err(e) => {
                let mut found = false;
                for wait_ms in [0u64, 300, 700] {
                    tokio::time::sleep(std::time::Duration::from_millis(wait_ms)).await;
                    if self.node_has(node, &local).await == Some(true) {
                        found = true;
                        break;
                    }
                }
                if !found {
                    let mut locked = Vec::new();
                    for i in &tx.vin {
                        let k = op_str(&i.prevout);
                        if self.st.locks.insert(k.clone()) {
                            locked.push(k);
                        }
                    }
                    self.st.unknown = Some(crate::state::UnknownSubmit {
                        txid: local.clone(),
                        locked,
                        expiry_height: tx.expiry_height,
                        inputs: tx.vin.iter().map(|i| op_str(&i.prevout)).collect(),
                    });
                    self.persist_state()?;
                    eprintln!("yewd: sendrawtransaction of {local} got no answer ({e}); its status is unknown, its inputs stay locked");
                    return Err(RpcError::new(
                        code::WALLET_ERROR,
                        format!("the node did not answer the submission ({e}); status unknown, txid {local}: check before sending again"),
                    ));
                }
                local
            }
        };
        self.lock_own_yed(&tx, &txid);
        if let Err(e) = self.sync(node).await {
            eprintln!(
                "yewd: {txid} was accepted by the node; the sync after it failed ({}), the next sync picks it up",
                e.message
            );
        }
        Ok(txid)
    }

    /// Whether the node (or the wallet's synced view of it) has `txid`: `Some(false)` only on the
    /// node's definite "no such transaction" (`-5`) after a successful sync, `None` when it
    /// cannot be told.
    async fn node_has(&mut self, node: &dyn Node, txid: &str) -> Option<bool> {
        self.sync(node).await.ok()?;
        if self.st.wtx.contains_key(txid) {
            return Some(true);
        }
        match node::call(node, "getrawtransaction", serde_json::json!([txid, 0])).await {
            Ok(_) => Some(true),
            Err(NodeError::Rpc { code: -5, .. }) => Some(false),
            Err(_) => None,
        }
    }

    /// A submission of unknown status (review M1) blocks the next one: resolved here, the
    /// caller's submission is refused with the outcome (nothing is sent), so a re-send is a
    /// decision taken knowing whether the first payment went out.
    ///
    /// Review YEW-REVIEW-3 L1: one "not found" (`-5`) is not final (a timed-out submission can
    /// still be processed late, and yewd can be re-pointed at another node), so the locked
    /// inputs are released only when the transaction is certainly dead:
    /// - its `nExpiryHeight` is at least [`UNKNOWN_REORG_MARGIN`] blocks behind the chain's tip
    ///   (no later block may include it; the margin covers a reorganization), the tip being the
    ///   node's or, when the node cannot answer, the wallet's last synced tip (so a node that
    ///   keeps failing still lets it clear); or
    /// - one of its inputs is spent by another transaction the wallet has seen confirmed at
    ///   least [`UNKNOWN_REORG_MARGIN`] blocks deep (and the node does not have this one).
    ///
    /// Until then every submission is refused with the status and the height at which it clears.
    /// The operator can clear it sooner with [`Wallet::clear_unknown_submission`] (the
    /// `clearunknownsubmission` RPC). Reaching the node clears the record and keeps the locks
    /// (the wallet then tracks the transaction itself).
    pub(crate) async fn resolve_unknown(&mut self, node: &dyn Node) -> Result<(), RpcError> {
        let Some(u) = self.st.unknown.clone() else {
            return Ok(());
        };
        let present = self.node_has(node, &u.txid).await;
        if present == Some(true) {
            self.st.unknown = None;
            self.persist_state()?;
            return Err(RpcError::new(
                code::WALLET_ERROR,
                format!("the earlier transaction {}, whose status was unknown, reached the node; nothing was sent now: send again only if this is a new payment", u.txid),
            ));
        }
        let tip = match node::block_count(node).await {
            Ok(h) => h,
            Err(_) => self.st.tip.as_ref().map_or(0, |t| t.height),
        };
        let clears_at =
            (u.expiry_height != 0).then(|| u.expiry_height.saturating_add(UNKNOWN_REORG_MARGIN));
        let dead = if clears_at.is_some_and(|h| tip >= h) {
            Some(format!(
                "expired at height {} without reaching the chain (the chain is at {tip})",
                u.expiry_height
            ))
        } else if present == Some(false) {
            self.conflicting_input(&u, tip).map(|op| {
                format!("can no longer be mined (its input {op} is spent by another transaction)")
            })
        } else {
            None
        };
        let Some(why) = dead else {
            let when = match clears_at {
                Some(h) => format!(
                    "until the chain reaches height {h} ({} blocks past its expiry height {}; the chain is at {tip})",
                    UNKNOWN_REORG_MARGIN, u.expiry_height
                ),
                None => "until one of its inputs is spent by another transaction (it has no expiry height)".to_string(),
            };
            return Err(RpcError::new(
                code::WALLET_ERROR,
                format!("an earlier transaction's status is still unknown, txid {}: its coins stay locked {when}; nothing was sent. Check before sending again; clearunknownsubmission {} releases them now if you are sure it reached no node", u.txid, u.txid),
            ));
        };
        self.release_unknown(&u)?;
        Err(RpcError::new(
            code::WALLET_ERROR,
            format!("the earlier transaction {}, whose status was unknown, {why}; its coins are released; nothing was sent now: send again", u.txid),
        ))
    }

    /// An input of `u` spent by another transaction the wallet has seen confirmed at least
    /// [`UNKNOWN_REORG_MARGIN`] blocks below `tip`.
    fn conflicting_input(&self, u: &crate::state::UnknownSubmit, tip: u32) -> Option<String> {
        for (id, w) in &self.st.wtx {
            if *id == u.txid {
                continue;
            }
            let Some(b) = &w.block else { continue };
            if tip.saturating_sub(b.height) + 1 < UNKNOWN_REORG_MARGIN {
                continue;
            }
            let Some((tx, _)) = hex::decode(&w.hex)
                .ok()
                .and_then(|raw| Transaction::parse(&raw).ok())
            else {
                continue;
            };
            if let Some(op) = tx
                .vin
                .iter()
                .map(|i| op_str(&i.prevout))
                .find(|op| u.inputs.contains(op))
            {
                return Some(op);
            }
        }
        None
    }

    fn release_unknown(&mut self, u: &crate::state::UnknownSubmit) -> Result<(), RpcError> {
        self.st.unknown = None;
        for k in &u.locked {
            self.st.locks.remove(k);
        }
        self.persist_state()
    }

    /// `clearunknownsubmission "txid"` (yewd's own RPC, review YEW-REVIEW-3 L1): the operator
    /// releases the inputs of a submission whose status is unknown before it is certainly dead.
    /// The txid must be the outstanding one's. **Risk:** if the transaction reached any node, it
    /// can still be mined until its expiry height; a payment sent again from the released coins
    /// may then go out twice. Needs no node.
    pub fn clear_unknown_submission(&mut self, p: &[Value]) -> Result<J, RpcError> {
        if p.len() != 1 {
            return Err(RpcError::new(code::MISC_ERROR, CLEAR_UNKNOWN_HELP));
        }
        let txid = p[0]
            .as_str()
            .ok_or_else(|| RpcError::new(code::INVALID_PARAMETER, "txid must be a string"))?;
        let Some(u) = self.st.unknown.clone() else {
            return Err(RpcError::new(
                code::INVALID_PARAMETER,
                "no submission of unknown status is outstanding",
            ));
        };
        if u.txid != txid {
            return Err(RpcError::new(
                code::INVALID_PARAMETER,
                format!("the submission of unknown status is {}, not {txid}", u.txid),
            ));
        }
        self.release_unknown(&u)?;
        eprintln!(
            "yewd: clearunknownsubmission released the inputs of {} ({} locks); it may still be mined until height {}",
            u.txid,
            u.locked.len(),
            u.expiry_height
        );
        Ok(J::obj()
            .with("txid", J::Str(u.txid.clone()))
            .with(
                "released",
                J::Arr(u.locked.iter().map(|k| J::Str(k.clone())).collect()),
            )
            .with("expiryheight", J::Int(u.expiry_height as i64)))
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
        let hexs = hex::encode(&raw);
        self.submit(node, &hexs, serde_json::json!([hexs, true]), RpcError::new)
            .await
    }

    /// `LockOwn` (H5): the YED outputs of a transaction this wallet just committed that pay it
    /// (a MINT's token, a TRANSFER's or REDEEM's assigned outputs) are locked at once, so plain
    /// YEC selection never spends them.
    pub(crate) fn lock_own_yed(&mut self, tx: &Transaction, txid: &str) {
        let Some(fp) = yew_core::payload::find_payload(tx) else {
            return;
        };
        let mut held = false;
        let mut vouts: Vec<u32> = fp
            .payload
            .assignments()
            .iter()
            .map(|a| a.vout as u32)
            .collect();
        if fp.payload.payload_type() == yew_core::payload::PayloadType::Mint {
            vouts.push(1);
        }
        for n in vouts {
            if let Some(o) = tx.vout.get(n as usize) {
                if self.book.owns_script(&o.script_pubkey).is_some() {
                    self.st.locks.insert(format!("{txid}:{n}"));
                    held = true;
                }
            }
        }
        if held {
            self.mark_yed_held();
        }
    }

    /// Set the write-once "has held YED" marker and write it out.
    pub(crate) fn mark_yed_held(&mut self) {
        if !self.st.yed_held {
            self.st.yed_held = true;
            if let Err(e) = self.persist_state() {
                eprintln!(
                    "yewd: could not save the has-held-YED marker ({}); it is kept in memory",
                    e.message
                );
            }
        }
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
