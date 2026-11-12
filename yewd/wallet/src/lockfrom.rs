// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! `vault_lock`'s funding address, `"from"` (beta2 decision D-3), as ycash-dd 97338f107 and ycash6
//! 554f07fc1 answer it (`src/rpc/vault.cpp` `ParseLockFrom`, `CheckLockFrom`, `FundFromAddress`,
//! `SaplingLockBuilder`; `doc/vault-rpc.md`). Without it (or with `""`) the lock is funded as
//! before, from the wallet's confirmed transparent P2PKH coins. With it, from that one address of
//! this wallet:
//!
//! - a transparent P2PKH address: its confirmed, unlocked coins, largest first; the fee from the
//!   signed size, max(10,000 zat, the relay fee, the ZIP-317 conventional fee); change back to it
//!   from 1,000 zat (less joins the fee);
//! - a post-quantum address: its confirmed, unlocked `TX_PQPKH` coins, largest first; the fee as a
//!   post-quantum spend prices it, max(min(max(10,000 zat, the plain PQ rate x the signed size),
//!   the cap), the conventional fee); change back to it above its post-quantum dust threshold;
//! - a Sapling address: its confirmed notes, largest first, at most 20; the fee max(10,000 zat,
//!   the conventional fee of the shape, the bundle padded to two outputs); change a note back to it.
//!
//! A transparent or post-quantum source never spends an output YED holds (`yed_reserved`, left
//! out as ycashd's coin lock leaves it out), and spends nothing while the node cannot answer for
//! its Yellowback index. Its coins are not locked: a refused lock leaves them free.

use serde_json::Value;
use yew_core::tx::{OutPoint, Transaction, TxIn, TxOut};
use yewd_proto::{GatePath, SaplingOut};

use crate::build::{money, node_coin, Next, VAULT_RPC_FEE, VAULT_RPC_MIN_CHANGE};
use crate::keys::Owner;
use crate::node::Node;
use crate::rpc::invalid;
use crate::{code, RpcError, Wallet};

/// `MAX_YEC_INPUTS` / `MAX_YEC_INPUT_BYTES` (`yellowback/txbuilder.h`): the YED builders' caps.
const MAX_YEC_INPUTS: usize = 400;
const MAX_YEC_INPUT_BYTES: usize = 75_000;
/// `MAX_SAPLING_SPENDS` of the C++ builders (`yellowback/txbuilder.cpp`).
const MAX_LOCK_SAPLING_SPENDS: usize = 20;
/// `MAX_TX_SIZE_BEFORE_SAPLING` and `MAX_STANDARD_TX_SIGOPS`: the backstop of `FundFromAddress`.
const MAX_LOCK_SIZE: usize = 100_000;
const MAX_LOCK_SIGOPS: usize = 4_000;

/// The parsed `"from"` of `vault_lock`.
#[derive(Clone, Debug)]
pub(crate) enum LockFrom {
    /// A transparent P2PKH or post-quantum address of this wallet: its text and script.
    Coins { text: String, script: Vec<u8> },
    /// A Sapling address of this wallet.
    Sapling(String),
}

/// A funded and signed lock: a transparent transaction, or one with a Sapling part (hex).
pub(crate) enum Funded {
    Coins(Transaction),
    Sapling(String),
}

impl Wallet {
    /// `ParseLockFrom` + `CheckLockFrom`: `None` for the default funding (absent or `""`).
    pub(crate) fn parse_lock_from(&self, v: &Value) -> Result<Option<LockFrom>, RpcError> {
        let s = match v {
            Value::Null => return Ok(None),
            Value::String(s) if s.is_empty() => return Ok(None),
            Value::String(s) => s.as_str(),
            _ => return Err(invalid("from must be an address string")),
        };
        // vault.cpp CheckLockFrom: RPC_INVALID_ADDRESS_OR_KEY (-5) for another wallet's address and
        // for a scheme-2 address before Falcon, as z_sendmany answers the same conditions (beta2
        // audit L-5; doc/vault-rpc-contract.json). yewd holds no watch-only address, so the -4
        // "from: a watch-only address of this wallet" row has no yewd source.
        let not_ours = || {
            RpcError::new(
                code::INVALID_ADDRESS_OR_KEY,
                "from: not an address of this wallet",
            )
        };
        if self.is_sapling(s) {
            if self.view.owns_address(s).is_none() {
                return Err(not_ours());
            }
            return Ok(Some(LockFrom::Sapling(s.to_string())));
        }
        if let Ok(id) = yew_core::keys::parse_pq_yec_address(self.network, s) {
            if id.scheme == yew_core::pq::SCHEME_FN_DSA_512 && !self.falcon_next() {
                return Err(RpcError::new(
                    code::INVALID_ADDRESS_OR_KEY,
                    "from: an FN-DSA-512 (scheme 2) address cannot be spent before Falcon is active at the next block",
                ));
            }
            if self.book.pq_by_id(&id).is_none() {
                return Err(not_ours());
            }
            let script = yew_core::pq::pqpkh_script(&id).ok_or_else(not_ours)?;
            return Ok(Some(LockFrom::Coins {
                text: s.to_string(),
                script,
            }));
        }
        if let Some(script) = crate::rpc::parse_taddr_script(self.network, s) {
            if yew_core::script::p2pkh_hash(&script).is_some() {
                if !matches!(self.book.owns_script(&script), Some(Owner::T(..))) {
                    return Err(not_ours());
                }
                return Ok(Some(LockFrom::Coins {
                    text: s.to_string(),
                    script,
                }));
            }
        }
        // yellowback::ParseAddressChoice (txbuilder.cpp): a Sprout address of this network is named
        let what = if is_sprout_address(self.network, s) {
            "bad-address: from: Sprout addresses are not supported"
        } else {
            "bad-address: from: not a transparent P2PKH, post-quantum or Sapling address of this network"
        };
        Err(RpcError::new(code::INVALID_ADDRESS_OR_KEY, what))
    }

    /// Fund and sign `tx` (its one output, the V, set; no input) from `from`.
    pub(crate) async fn fund_lock_from(
        &mut self,
        node: &dyn Node,
        tx: &Transaction,
        from: &LockFrom,
        next: Next,
    ) -> Result<Funded, RpcError> {
        match from {
            LockFrom::Coins { text, script } => {
                self.fund_from_coins(node, tx, text, script, next).await
            }
            LockFrom::Sapling(z) => self.fund_from_sapling(node, tx, z, next).await,
        }
    }

    /// `FundFromAddress` and the one signing after it (`SignLockFromInputs`).
    async fn fund_from_coins(
        &mut self,
        node: &dyn Node,
        tx0: &Transaction,
        text: &str,
        only: &[u8],
        next: Next,
    ) -> Result<Funded, RpcError> {
        let pq = yew_core::pq::pqpkh_of(only).is_some();
        let reserved = self
            .yed_reserved(node)
            .await
            .map_err(|e| RpcError::new(e.code, format!("from: {}", e.message)))?;
        let shield_coinbase = self.network != yew_core::params::Network::Regtest;
        let spent = self.mempool_spent();
        let mut eligible: Vec<(OutPoint, i64)> = Vec::new();
        let mut coinbase_value = 0i64;
        // the coins at the address left out because YED holds them, named if the address cannot
        // fund the lock without them (vault.cpp FundFromAddress, review L6)
        let mut refused: Vec<String> = Vec::new();
        for (c, d) in self.available_coins(None) {
            if c.script != only || d < 1 || spent.contains(&(c.txid.clone(), c.vout)) {
                continue;
            }
            if reserved.contains(&(c.txid.clone(), c.vout)) {
                refused.push(format!("{}:{}", c.txid, c.vout));
                continue;
            }
            let op = OutPoint {
                txid: yew_core::tx::txid_from_hex(&c.txid)
                    .map_err(|e| RpcError::new(code::MISC_ERROR, e))?,
                n: c.vout,
            };
            // unspent and confirmed in the node's view
            match node_coin(node, &op).await? {
                Some(n) if n.height.is_some() && n.value == c.value && n.script == c.script => {}
                _ => continue,
            }
            if c.coinbase && shield_coinbase {
                coinbase_value += c.value;
                continue;
            }
            eligible.push((op, c.value));
        }
        eligible.sort_by(|a, b| {
            b.1.cmp(&a.1)
                .then((a.0.txid, a.0.n).cmp(&(b.0.txid, b.0.n)))
        });
        let sig_size = crate::send::script_sig_size(only);
        let compact = |n: usize| if n <= 252 { 1 } else { 3 };
        let input_bytes = 36 + compact(sig_size) + sig_size + 4;
        let out: i64 = tx0.output_total();
        let (rate, pq_cap) = crate::send::pq_fee_params(node).await;
        let mut fee = VAULT_RPC_FEE;
        let mut pass = 0;
        let (tx, paid) = loop {
            if pass == 8 {
                return Err(RpcError::new(
                    code::WALLET_ERROR,
                    "from: the funding fee did not settle",
                ));
            }
            pass += 1;
            let mut tx = tx0.clone();
            let needed = out + fee;
            let mut got = 0i64;
            for (op, v) in &eligible {
                if got >= needed {
                    break;
                }
                if tx.vin.len() + 1 > MAX_YEC_INPUTS
                    || (tx.vin.len() + 1) * input_bytes > MAX_YEC_INPUT_BYTES
                {
                    return Err(RpcError::new(code::WALLET_ERROR, format!(
                        "from: too-many-coins: covering {} at {text} would take more than {MAX_YEC_INPUTS} coins or {MAX_YEC_INPUT_BYTES} bytes of inputs; consolidate the address's coins first, then retry",
                        money(needed)
                    )));
                }
                tx.vin.push(TxIn::new(*op));
                got += v;
            }
            if got < needed {
                if !refused.is_empty() {
                    return Err(RpcError::new(code::WALLET_ERROR, format!(
                        "from: refusing to spend a Yellowback outpoint as plain YEC: {} (its YED would burn; lock it again with yed_lockcoins)",
                        refused.join(", ")
                    )));
                }
                let shielded = if coinbase_value > 0 {
                    format!(
                        " (its {} of coinbase outputs must be shielded first: z_shieldcoinbase)",
                        money(coinbase_value)
                    )
                } else {
                    String::new()
                };
                return Err(RpcError::new(
                    code::WALLET_INSUFFICIENT_FUNDS,
                    format!(
                        "insufficient confirmed funds at {text}: need {} more{shielded}",
                        money(needed - got)
                    ),
                ));
            }
            let change = got - needed;
            let keep = if pq {
                change > 0 && change >= crate::send::dust_threshold(only)
            } else {
                change >= VAULT_RPC_MIN_CHANGE
            };
            if keep {
                tx.vout.push(TxOut {
                    value: change,
                    script_pubkey: only.to_vec(),
                });
            }
            let sizes = vec![sig_size; tx.vin.len()];
            let (size, required) = lock_fee(&tx, &sizes, pq, rate, pq_cap)?;
            let sigops = if pq { tx.vin.len() * 20 } else { 0 }
                + tx.vout
                    .iter()
                    .filter(|o| yew_core::script::p2pkh_hash(&o.script_pubkey).is_some())
                    .count();
            if size > MAX_LOCK_SIZE || sigops > MAX_LOCK_SIGOPS {
                return Err(RpcError::new(code::WALLET_ERROR, format!(
                    "from: the lock would be {size} bytes with {sigops} sigops (limits {MAX_LOCK_SIZE}, {MAX_LOCK_SIGOPS}); consolidate the address's coins first"
                )));
            }
            let paid = got - tx.output_total();
            if paid >= required {
                break (tx, paid);
            }
            fee = required.max(fee + 1);
        };
        // signed once; the signed size re-checked against the fee priced
        let signed = self
            .sign_wallet_inputs(node, &tx, GatePath::Vault, out + paid, next)
            .await?;
        let sizes: Vec<usize> = signed.vin.iter().map(|i| i.script_sig.len()).collect();
        let (size, required) = lock_fee(&signed, &sizes, pq, rate, pq_cap)?;
        if required > paid {
            return Err(RpcError::new(
                code::WALLET_ERROR,
                format!(
                    "from: the signed lock ({size} bytes) needs a fee of {}, more than the {} priced; nothing was sent",
                    money(required),
                    money(paid)
                ),
            ));
        }
        Ok(Funded::Coins(signed))
    }

    /// `SaplingLockBuilder`: the V paid from the notes of a Sapling `from`, change a note back to
    /// it; the signer proves and authorizes the Sapling part with the transparent one.
    async fn fund_from_sapling(
        &mut self,
        node: &dyn Node,
        tx: &Transaction,
        zaddr: &str,
        next: Next,
    ) -> Result<Funded, RpcError> {
        let out = tx.output_total();
        let mut fee = VAULT_RPC_FEE;
        let mut pass = 0;
        loop {
            if pass == 25 {
                return Err(RpcError::new(
                    code::WALLET_ERROR,
                    "from: the Sapling funding fee did not settle",
                ));
            }
            pass += 1;
            let (spends, anchor, sum) = self
                .z_select(
                    node,
                    zaddr,
                    out + fee,
                    "transaction",
                    MAX_LOCK_SAPLING_SPENDS,
                )
                .await
                .map_err(|e| {
                    let c = if e.message.starts_with("insufficient-yec")
                        || e.message.starts_with("too-many-notes")
                    {
                        code::WALLET_INSUFFICIENT_FUNDS
                    } else {
                        code::WALLET_ERROR
                    };
                    RpcError::new(c, e.message)
                })?;
            if spends.len() > MAX_LOCK_SAPLING_SPENDS {
                return Err(RpcError::new(code::WALLET_INSUFFICIENT_FUNDS, format!(
                    "too-many-notes: the transaction would spend {} Sapling notes (limit {MAX_LOCK_SAPLING_SPENDS}); consolidate with z_mergetoaddress first",
                    spends.len()
                )));
            }
            // the change note (padded with a dummy to two outputs)
            let conventional = Self::hybrid_fee(tx, &[], spends.len(), 1)?;
            if conventional > fee {
                fee = conventional;
                continue;
            }
            let change = sum - out - fee;
            let outputs: Vec<SaplingOut> = if change > 0 {
                vec![self.sapling_out(zaddr, change)]
            } else {
                Vec::new()
            };
            let part = self.sapling_part(next.height, spends, anchor, outputs);
            let hex = self
                .sign_inputs_hex(
                    tx,
                    &[],
                    &[],
                    &[],
                    GatePath::Vault,
                    out + fee,
                    next.branch,
                    Some(part),
                )
                .await?;
            return Ok(Funded::Sapling(hex));
        }
    }
}

/// A Sprout payment address of `network` as `KeyIO::DecodePaymentAddress` takes one: Base58Check of
/// the `ZCPAYMENT_ADDRESS` prefix (`chainparams.cpp`: mainnet `{0x16,0x36}`, testnet and regtest
/// `{0x16,0x52}`) and the 64-byte serialized address. The legacy `zc…` prefix is not taken there.
fn is_sprout_address(network: yew_core::params::Network, s: &str) -> bool {
    let prefix: [u8; 2] = match network {
        yew_core::params::Network::Mainnet => [0x16, 0x36],
        _ => [0x16, 0x52],
    };
    yew_core::keys::base58check_decode(s).is_ok_and(|p| p.len() == 2 + 64 && p[..2] == prefix)
}

/// The size of `tx` with scriptSigs of `sizes` and the fee a lock from coins pays at it: for a
/// post-quantum source max(min(max(VAULT_RPC_FEE, the plain PQ rate x size), the cap), the
/// conventional fee); else max(VAULT_RPC_FEE, the relay fee, the conventional fee).
fn lock_fee(
    tx: &Transaction,
    sizes: &[usize],
    pq: bool,
    rate: i64,
    pq_cap: i64,
) -> Result<(usize, i64), RpcError> {
    let compact = |n: usize| if n <= 252 { 1 } else { 3 };
    let unsigned = tx
        .serialize()
        .map_err(|e| RpcError::new(code::INTERNAL_ERROR, e.to_string()))?
        .len();
    // each scriptSig at its size (with its length prefix) in place of the one it has
    let have: usize = tx
        .vin
        .iter()
        .map(|i| i.script_sig.len() + compact(i.script_sig.len()))
        .sum();
    let want: usize = sizes.iter().map(|n| n + compact(*n)).sum();
    let size = unsigned + want - have;
    let conventional = tx
        .zip317_conventional_fee(sizes)
        .map_err(|e| RpcError::new(code::INTERNAL_ERROR, e.to_string()))?;
    let relay = crate::pq_fee_rate() * size as i64 / 1000;
    let required = if pq {
        VAULT_RPC_FEE
            .max(rate * size as i64 / 1000)
            .min(pq_cap)
            .max(conventional)
    } else {
        VAULT_RPC_FEE.max(relay).max(conventional)
    };
    Ok((size, required))
}
