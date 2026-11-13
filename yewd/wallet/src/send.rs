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

/// `GetPQDustThreshold` at `ONE_THIRD_DUST_THRESHOLD_RATE` (100 zat/kB): 3 × the fee of the output
/// plus the input that spends it, the input a post-quantum spend for `TX_PQPKH`, 148 bytes otherwise
/// (`CTxOut::GetDustThreshold`: 54 zat for P2PKH).
pub(crate) fn dust_threshold(script: &[u8]) -> i64 {
    yew_core::build::any_to_any::dust_threshold(script)
}

/// The scriptSig a wallet coin's input will carry: a post-quantum signature's pushes for
/// `TX_PQPKH`, the P2PKH maximum otherwise (the YEW core's, one implementation with the app).
pub(crate) fn script_sig_size(script: &[u8]) -> usize {
    yew_core::build::any_to_any::script_sig_size(script)
}

/// The refusal of a coin-selecting send whose ordinary (ECC) coins fall short while the wallet holds
/// post-quantum coins `z_sendmany` would spend (ycash6 `CWallet::CreateTransaction`, beta2 audit M-1;
/// the text and the amount's format are the C++ lines').
pub(crate) fn pq_refusal(pq: i64) -> String {
    format!(
        "Insufficient funds in ordinary transparent addresses; this wallet also holds {} YEC at post-quantum addresses: send from one with z_sendmany, which returns the change to it",
        crate::rpc::format_money(pq)
    )
}

/// `YellowbackInputRefusal`'s text for the outpoints `list` (`txid:n, …`): live, the index's
/// refusal; not live, what the outputs' own payloads assign (ycash6 `src/wallet/wallet.cpp`).
pub(crate) fn yed_input_refusal(live: bool, list: &str) -> String {
    if live {
        format!("refusing to spend a Yellowback outpoint as plain YEC: {list} (its YED would burn; lock it again with yed_lockcoins)")
    } else {
        format!("refusing to spend an output that carries YED as plain YEC while Yellowback is not live: {list} (its YED would burn; to destroy it deliberately, name the outpoint in a raw transaction)")
    }
}

/// `SelectCoins`' coinbase flags over the ECC candidates: `(fOnlyCoinbaseCoins,
/// fNeedCoinbaseCoins)` for `target`, where coinbase must be shielded when `shield`.
pub(crate) fn coinbase_flags(
    candidates: &[(OutPoint, i64, Vec<u8>, bool)],
    target: i64,
    shield: bool,
) -> (bool, bool) {
    let no_cb: Vec<i64> = candidates.iter().filter(|c| !c.3).map(|c| c.1).collect();
    let only = no_cb.is_empty() && !candidates.is_empty();
    let mut need = false;
    if shield && candidates.len() > no_cb.len() && no_cb.iter().sum::<i64>() <= target {
        need = candidates.iter().map(|c| c.1).sum::<i64>() >= target;
    }
    (only && shield, need)
}

/// The text of `CreateTransaction`'s refusal when `SelectCoins` fails (ycash6
/// `src/wallet/wallet.cpp`): `pq` the post-quantum value left out, `yed_refusal` the YED refusal
/// when that is 0, `(only, need)` the coinbase flags (`only` already requires shielding).
pub(crate) fn select_fail_text(pq: i64, yed_refusal: &str, (only, need): (bool, bool)) -> String {
    let coinbase = only || need;
    if pq > 0 {
        let mut s = pq_refusal(pq);
        if coinbase {
            s += "; its coinbase funds can only be spent after they have been sent to a zaddr";
        }
        s
    } else if !yed_refusal.is_empty() && !coinbase {
        yed_refusal.to_string()
    } else if only {
        "Coinbase funds can only be sent to a zaddr".to_string()
    } else if need {
        "Insufficient funds, coinbase funds can only be spent after they have been sent to a zaddr"
            .to_string()
    } else {
        "Insufficient funds".to_string()
    }
}

/// `DisplayMoney`: the amount with the unit (ycash6 `src/util/moneystr.cpp`).
pub(crate) fn display_money(z: i64) -> String {
    format!("{} YEC", crate::rpc::format_money(z))
}

/// The stock call a coin-selecting send answers for: the refusal's code is that call's (ycash6
/// `SendMoney` answers `RPC_WALLET_ERROR` after its own fee check, `sendmany`
/// `RPC_WALLET_INSUFFICIENT_FUNDS`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Caller {
    SendToAddress,
    SendMany,
}

/// The plain fee rate (zat/kB) and the post-quantum fee cap (`PQMaxTxFee`) the node reports
/// (`yed_getinfo.params.fees.network`: `plain.zatPerKB`, `yellowback.maxTxFeeZat`); without a live
/// Yellowback the -pqfeerate default (the relay floor, 100 zat/kB) and -maxtxfee's 0.1 YEC.
pub(crate) async fn pq_fee_params(node: &dyn Node) -> (i64, i64) {
    match node::call(node, "yed_getinfo", serde_json::json!([])).await {
        Ok(v) => {
            let n = &v["params"]["fees"]["network"];
            (
                n["plain"]["zatPerKB"]
                    .as_i64()
                    .unwrap_or_else(crate::pq_fee_rate),
                n["yellowback"]["maxTxFeeZat"]
                    .as_i64()
                    .unwrap_or(10_000_000),
            )
        }
        // -pqfeerate's default, the relay floor (DEFAULT_MIN_RELAY_TX_FEE), and -maxtxfee's
        Err(_) => (crate::pq_fee_rate(), 10_000_000),
    }
}

impl Wallet {
    /// ycashd's `EnsurePQRecipientPayable` (`wallet/rpcwallet.cpp`): a post-quantum recipient only
    /// once the vault upgrade, and for FN-DSA-512 Falcon, is active at the next block.
    pub(crate) fn ensure_pq_payable(&self, script: &[u8]) -> Result<(), RpcError> {
        let Some(id) = yew_core::pq::pqpkh_of(script) else {
            return Ok(());
        };
        if !self.vault_active_next() {
            return Err(RpcError::new(
                code::INVALID_ADDRESS_OR_KEY,
                "post-quantum addresses can be paid only once the vault upgrade is active at the next block",
            ));
        }
        if id.scheme == 2 && !self.falcon_next() {
            return Err(RpcError::new(
                code::INVALID_ADDRESS_OR_KEY,
                "an FN-DSA-512 (scheme 2) post-quantum address can be paid only once Falcon is active at the next block",
            ));
        }
        Ok(())
    }

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
    /// Ordinary (ECC) coins only (beta2 audit M-1, review LOW-1, as ycash6 `SelectCoins`): a
    /// post-quantum coin is spent by naming its address in `z_sendmany`, which returns the change
    /// to it; [`Wallet::pq_selectable`] names what is left out when the ECC coins fall short.
    async fn spendable_yec(
        &self,
        node: &dyn Node,
        min_depth: i64,
    ) -> Result<Vec<(OutPoint, i64, Vec<u8>)>, RpcError> {
        // SelectCoins: coinbase coins are left out where coinbase must be shielded
        let shield = self.shield_coinbase();
        Ok(self
            .ecc_candidates(node, min_depth)
            .await?
            .into_iter()
            .filter(|c| !(c.3 && shield))
            .map(|(op, value, s, _)| (op, value, s))
            .collect())
    }

    /// Whether coinbase must be shielded (`fCoinbaseMustBeShielded`): every network but regtest.
    pub(crate) fn shield_coinbase(&self) -> bool {
        self.network != yew_core::params::Network::Regtest
    }

    /// The coins of [`Wallet::spendable_yec`] with the coinbase ones, each with its coinbase flag
    /// (`AvailableCoins` with and without coinbase, for `SelectCoins`' coinbase flags).
    async fn ecc_candidates(
        &self,
        node: &dyn Node,
        min_depth: i64,
    ) -> Result<Vec<(OutPoint, i64, Vec<u8>, bool)>, RpcError> {
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
            v.push((d == 0, op, c.value, c.script.clone(), c.coinbase));
        }
        // SelectCoins' passes: confirmed coins first (nConfMine = 1), the trusted mempool change
        // only when they do not cover the payment; largest first within each
        v.sort_by(|a, b| {
            a.0.cmp(&b.0)
                .then(b.2.cmp(&a.2))
                .then((a.1.txid, a.1.n).cmp(&(b.1.txid, b.1.n)))
        });
        Ok(v.into_iter()
            .map(|(_, op, value, s, cb)| (op, value, s, cb))
            .collect())
    }

    /// ycash6 `CWallet::PQSelectableValue` (beta2 review LOW-2): the post-quantum coins a
    /// coin-selecting send leaves out, counted only where `z_sendmany` from their address would
    /// spend them (`run_pq_source`): once the vault upgrade is active at the next block, confirmed
    /// (its default minconf 1), not coinbase, unlocked, not spent by a mempool transaction of this
    /// wallet, never an output YED holds ([`Wallet::yed_reserved`]), and FN-DSA-512 only once
    /// Falcon is active at the next block.
    ///
    /// With it, when it is 0 because every such coin is an output YED holds, the refusal
    /// `z_sendmany` would give for them (`PQSelectableValue(&yedRefusal)`,
    /// `YellowbackInputRefusal`; empty otherwise).
    async fn pq_selectable(&self, node: &dyn Node) -> Result<(i64, String), RpcError> {
        if !self.vault_active_next() {
            return Ok((0, String::new()));
        }
        let falcon = self.falcon_next();
        let spent = self.mempool_spent();
        let reserved = self.yed_reserved(node).await?;
        let mut value = 0i64;
        let mut refused: Vec<([u8; 32], u32, String)> = Vec::new();
        for (c, d) in self.available_coins(None) {
            let Owner::Pq(scheme, _) = c.owner else {
                continue;
            };
            if d < 1
                || c.coinbase
                || (scheme == yew_core::pq::SCHEME_FN_DSA_512 && !falcon)
                || spent.contains(&(c.txid.clone(), c.vout))
            {
                continue;
            }
            if reserved.contains(&(c.txid.clone(), c.vout)) {
                let key = yew_core::tx::txid_from_hex(&c.txid).unwrap_or([0; 32]);
                refused.push((key, c.vout, format!("{}:{}", c.txid, c.vout)));
            } else {
                value += c.value;
            }
        }
        if value > 0 || refused.is_empty() {
            return Ok((value, String::new()));
        }
        // the node's order: its wallet's map, by txid (uint256 order), then the output index
        refused.sort();
        let list = refused
            .into_iter()
            .map(|(_, _, s)| s)
            .collect::<Vec<_>>()
            .join(", ");
        let live = !matches!(
            node::call(node, "yed_getinfo", serde_json::json!([])).await,
            Err(NodeError::Rpc { code: c, .. }) if c == code::METHOD_NOT_FOUND
        );
        Ok((0, yed_input_refusal(live, &list)))
    }

    /// `CreateTransaction`'s `strFailReason` when `SelectCoins` falls short of `target` (ycash6
    /// `src/wallet/wallet.cpp`, beta2 review LOW-3): the post-quantum coins left out are named,
    /// with the coinbase tail when coinbase coins were left out too; else the YED refusal; else the
    /// coinbase reasons; else "Insufficient funds". `candidates` are the ECC coins the selection
    /// could use, coinbase ones included and flagged.
    async fn select_fail_reason(
        &self,
        node: &dyn Node,
        candidates: &[(OutPoint, i64, Vec<u8>, bool)],
        target: i64,
    ) -> Result<String, RpcError> {
        let (pq, yed_refusal) = self.pq_selectable(node).await?;
        Ok(select_fail_text(
            pq,
            &yed_refusal,
            coinbase_flags(candidates, target, self.shield_coinbase()),
        ))
    }

    /// `CreateTransaction` + `CommitTransaction` for plain YEC recipients: largest-first ECC
    /// coins, the ZIP-317 conventional fee, change to a new change key.
    async fn send_yec(
        &mut self,
        node: &dyn Node,
        recipients: &[(Vec<u8>, i64, bool)],
        min_depth: i64,
        caller: Caller,
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
                }
                // CreateTransaction: a recipient below its dust threshold (a TX_PQPKH one priced
                // with its real spend size, GetPQDustThreshold) is refused
                if v < dust_threshold(s) {
                    return Err(RpcError::new(
                        code::WALLET_ERROR,
                        if !*sub {
                            "Transaction amount too small"
                        } else if v < 0 {
                            "The transaction amount is too small to pay the fee"
                        } else {
                            "The transaction amount is too small to send after the fee has been deducted"
                        },
                    ));
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
                let candidates = self.ecc_candidates(node, min_depth).await?;
                let (pq, yed_refusal) = self.pq_selectable(node).await?;
                let reason = select_fail_text(
                    pq,
                    &yed_refusal,
                    coinbase_flags(&candidates, need, self.shield_coinbase()),
                );
                if pq > 0 {
                    // SendMoney's own check comes first: the payment is covered by the ECC
                    // coins, but the fee is not, and not by the whole balance either
                    let balance = self.balance(None, 0);
                    if caller == Caller::SendToAddress
                        && subtract == 0
                        && total <= available
                        && total + fee > balance
                    {
                        return Err(RpcError::new(
                            code::WALLET_INSUFFICIENT_FUNDS,
                            format!(
                                "Error: Insufficient funds to pay the fee. This transaction needs to spend {} plus a fee of at least {}, but only {} is available",
                                display_money(total),
                                display_money(fee),
                                display_money(balance)
                            ),
                        ));
                    }
                    return Err(RpcError::new(
                        match caller {
                            Caller::SendToAddress => code::WALLET_ERROR,
                            Caller::SendMany => code::WALLET_INSUFFICIENT_FUNDS,
                        },
                        reason,
                    ));
                }
                if subtract == 0 && total <= available {
                    return Err(RpcError::new(
                        code::WALLET_INSUFFICIENT_FUNDS,
                        format!(
                            "Error: Insufficient funds to pay the fee. This transaction needs to spend {} plus a fee of at least {}, but only {} is available",
                            display_money(total),
                            display_money(fee),
                            display_money(available)
                        ),
                    ));
                }
                return Err(RpcError::new(code::WALLET_INSUFFICIENT_FUNDS, reason));
            }
            for c in &chosen {
                tx.vin.push(TxIn::new(c.0));
            }
            let change = got - need;
            if change > 0 {
                // -sendchangeback: the largest input's address (ycashd 31bacc765); else a new key
                let back = self
                    .opts
                    .send_change_back
                    .then(|| chosen.iter().max_by_key(|c| c.1).map(|c| c.2.clone()))
                    .flatten();
                let s = match back {
                    Some(s) => s,
                    None => self.new_change()?,
                };
                // review B-4: the change's dust at its real spend size (TX_PQPKH); with
                // subtractfeefromamount the change is raised to it from the first such recipient
                let dust = dust_threshold(&s);
                let mut value = change;
                if subtract > 0 && value < dust {
                    let raise = dust - value;
                    value = dust;
                    let i = recipients.iter().position(|r| r.2).unwrap_or(0);
                    tx.vout[i].value -= raise;
                    if tx.vout[i].value < dust_threshold(&recipients[i].0) {
                        return Err(RpcError::new(code::WALLET_ERROR, "The transaction amount is too small to send after the fee has been deducted"));
                    }
                }
                if value >= dust.max(DUST + 1) {
                    tx.vout.push(TxOut {
                        value,
                        script_pubkey: s,
                    });
                }
            }
            let sizes: Vec<usize> = chosen.iter().map(|c| script_sig_size(&c.2)).collect();
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
        self.ensure_pq_payable(&script)?;
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
            self.send_yec(node, &[(script, amount, sub)], 0, Caller::SendToAddress)
                .await?,
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
            self.ensure_pq_payable(&script)?;
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
        Ok(J::Str(
            self.send_yec(node, &recipients, min, Caller::SendMany)
                .await?,
        ))
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
            // the caller's keys (never the wallet's): the node signs when it has the method
            // (ycash6); kogany has none (F-S2-7), so the façade signs with the given keys here
            return match node::call(node, "signrawtransaction", Value::Array(p.to_vec())).await {
                Ok(v) => Ok(J::Raw(v.to_string())),
                Err(NodeError::Rpc { code: -32601, .. }) => {
                    self.sign_with_given_keys(node, p).await
                }
                Err(NodeError::Rpc { code, message }) => Err(RpcError::new(code, message)),
                Err(e) => Err(e.into()),
            };
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
                let v = match node::call(
                    node,
                    "yed_validaterawtransaction",
                    serde_json::json!([signed_hex]),
                )
                .await
                {
                    Ok(v) => v,
                    // kogany verifies scripts only through yed_validaterawtransaction, which it
                    // answers only while Yellowback is live and once W7-b serves it (finding
                    // F-S5-2): the façade's own completeness (every input carries a scriptSig;
                    // the ones it signed are its signer's) stands in
                    Err(NodeError::Rpc { .. }) => return Ok(local_completeness(&out, signed_hex)),
                    Err(e) => return Err(e.into()),
                };
                // ycashd's signrawtransaction checks scripts, not sequence locks: an unaged
                // RELEASE is complete there, so kogany's BIP68 answers count as complete
                let complete = v["valid"].as_bool().unwrap_or(false)
                    || matches!(
                        v["invalidReason"].as_str(),
                        Some("non-BIP68-final" | "bad-txns-vault-timelock")
                    );
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

/// `signrawtransaction`'s answer when the node has no verifier (F-S5-2): `complete` when every
/// input carries a scriptSig, and ycashd's error object (`TxInErrorToJSON`) for each that does not,
/// with the text ycashd's interpreter gives an empty scriptSig.
fn local_completeness(tx: &Transaction, signed_hex: String) -> J {
    let mut errors = Vec::new();
    for i in &tx.vin {
        if i.script_sig.is_empty() {
            errors.push(
                J::obj()
                    .with("txid", yew_core::tx::txid_hex(&i.prevout.txid))
                    .with("vout", i.prevout.n as i64)
                    .with("scriptSig", String::new())
                    .with("sequence", i.sequence as i64)
                    .with(
                        "error",
                        "Operation not valid with the current stack size".to_string(),
                    ),
            );
        }
    }
    let mut o = J::obj()
        .with("hex", signed_hex)
        .with("complete", errors.is_empty());
    if !errors.is_empty() {
        o.push("errors", J::Arr(errors));
    }
    o
}

impl Wallet {
    /// `fundrawtransaction "hexstring" ( includeWatching )` (`CWallet::FundTransaction`): the
    /// transaction's outputs paid from its own inputs plus this wallet's coins, a change output
    /// appended, the ZIP-317 conventional fee; nothing is signed. The coins added are ordinary
    /// (ECC) coins only (review LOW-1): a post-quantum input stays only when the transaction names it.
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
        // each named input's scriptSig size: a post-quantum (`TX_PQPKH`) coin's real signature
        // pushes, as ycashd's dummy signatures size it (YEWD-PARITY gap 2)
        let mut preset_sizes = Vec::with_capacity(base.vin.len());
        for i in &base.vin {
            match node_coin(node, &i.prevout).await? {
                Some(c) => {
                    preset += c.value;
                    preset_sizes.push(
                        yew_core::pq::pqpkh_of(&c.script)
                            .and_then(|id| yew_core::pq::pq_sig_pushes_size(id.scheme))
                            .unwrap_or(MAX_P2PKH_SCRIPT_SIG),
                    );
                }
                None => return Err(RpcError::new(code::INTERNAL_ERROR, "Insufficient funds")),
            }
        }
        let pq_input = base
            .vin
            .iter()
            .zip(&preset_sizes)
            .any(|(_, s)| *s != MAX_P2PKH_SCRIPT_SIG);
        let pq_terms = if pq_input {
            Some(pq_fee_params(node).await)
        } else {
            None
        };
        let used: BTreeSet<(String, u32)> = base
            .vin
            .iter()
            .map(|i| (txid_hex(&i.prevout.txid), i.prevout.n))
            .collect();
        let candidates: Vec<_> = self
            .ecc_candidates(node, 0)
            .await?
            .into_iter()
            .filter(|c| !used.contains(&(txid_hex(&c.0.txid), c.0.n)))
            .collect();
        let shield = self.shield_coinbase();
        let coins: Vec<_> = candidates
            .iter()
            .filter(|c| !(c.3 && shield))
            .map(|(op, value, s, _)| (*op, *value, s.clone()))
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
                // the post-quantum coins left out are named (ycash6 FundTransaction, review LOW-1),
                // with the C++ coinbase and YED tails (review LOW-3)
                let reason = self.select_fail_reason(node, &candidates, need).await?;
                return Err(RpcError::new(code::INTERNAL_ERROR, reason));
            }
            // the named inputs may cover more than the outputs and the fee: the excess is change too
            let change = got - need;
            let mut changepos = -1i64;
            if change > DUST {
                let sc = self.new_change()?;
                tx.vout.push(TxOut {
                    value: change,
                    script_pubkey: sc,
                });
                changepos = tx.vout.len() as i64 - 1;
            }
            let mut sizes = preset_sizes.clone();
            sizes.resize(tx.vin.len(), MAX_P2PKH_SCRIPT_SIG);
            let conventional = tx
                .zip317_conventional_fee(&sizes)
                .map_err(|e| RpcError::new(code::INTERNAL_ERROR, e.to_string()))?;
            // ycashd CreateTransaction with a post-quantum input: max(min(max(fee, the plain PQ
            // rate x size), PQMaxTxFee()), the ZIP-317 conventional fee), the size with the
            // inputs' dummy signatures (quantum plan §4.5)
            let want = match pq_terms {
                Some((rate, cap)) => {
                    let bytes = tx
                        .size_with_script_sigs(&sizes)
                        .map_err(|e| RpcError::new(code::INTERNAL_ERROR, e.to_string()))?;
                    yew_core::build::any_to_any::pq_builder_fee(
                        conventional,
                        bytes,
                        conventional,
                        rate,
                        cap,
                    )
                }
                None => conventional,
            };
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

/// `PayloadYedOutputs` (ycash6 `src/yellowback/wallet.cpp`): the outputs to which `tx`'s own
/// Yellowback payload may give YED, read from the transaction alone (no index):
/// - MINT: vout 0, the vault, and vout 1, the token;
/// - TRANSFER and REDEEM: the payload's assignments;
/// - CANCEL_COSIGN, a claim cancel (CAN-1): vout 0, the re-created vault, and every output at
///   index >= 1 that is not the `OP_RETURN`, pays a non-zero value and is the first to pay its
///   script (the refund's holder is an index record, not in the transaction);
/// - a coinbase: none (TX-0).
///
/// `None` (fail closed) when the transaction carries a Yellowback payload this build cannot read
/// ([`yew_core::payload::unknown_yellowback`]): any of its outputs may hold YED.
pub(crate) fn payload_yed_outputs(tx: &Transaction, coinbase: bool) -> Option<BTreeSet<u32>> {
    use yew_core::payload::Payload;
    let mut out = BTreeSet::new();
    if coinbase {
        return Some(out);
    }
    if yew_core::payload::unknown_yellowback(tx) {
        return None;
    }
    let Some(f) = yew_core::payload::find_payload(tx) else {
        return Some(out);
    };
    let op_return = f.op_return_index as u32;
    match &f.payload {
        Payload::Mint { .. } => {
            for n in [0u32, 1] {
                if (n as usize) < tx.vout.len() && n != op_return {
                    out.insert(n);
                }
            }
        }
        Payload::Transfer { .. } | Payload::Redeem { .. } => {
            out.extend(f.payload.assignments().iter().map(|a| a.vout as u32));
        }
        Payload::CancelCosign => {
            if !tx.vout.is_empty() && op_return != 0 {
                out.insert(0);
            }
            let mut paid: BTreeSet<&[u8]> = BTreeSet::new();
            for (n, o) in tx.vout.iter().enumerate().skip(1) {
                if n as u32 == op_return || o.value <= 0 {
                    continue;
                }
                if paid.insert(o.script_pubkey.as_slice()) {
                    out.insert(n as u32);
                }
            }
        }
        _ => {}
    }
    Some(out)
}

/// The cents `tx`'s payload states for its output `n` (ycash6 `YedBurnedByRawTransaction`): a
/// MINT's token (vout 1), or a TRANSFER's or REDEEM's assignment to `n`. `None` where the payload
/// states none: a claim cancel's refund, whose amount is known only once its block is judged.
fn stated_cents(tx: &Transaction, n: u32) -> Option<i64> {
    use yew_core::payload::Payload;
    let f = yew_core::payload::find_payload(tx)?;
    match &f.payload {
        Payload::Mint { cents, .. } if n == 1 => Some(*cents as i64),
        Payload::Transfer { .. } | Payload::Redeem { .. } => f
            .payload
            .assignments()
            .iter()
            .find(|a| a.vout as u32 == n)
            .map(|a| a.cents as i64),
        _ => None,
    }
}

impl Wallet {
    /// `YedBurnedByRawTransaction` (H7, ycash6 `src/yellowback/wallet.cpp`): a raw transaction that
    /// destroys YED of this wallet is refused (`-4 yed-burn-refused`) unless the caller passes
    /// `allowyedburn`. It spends YED of this wallet when an input is
    /// - a token the node's index lists at one of this wallet's scripts (`yed_listtokens`), or
    /// - an output of this wallet whose transaction the index has not judged (`IndexJudged`: in the
    ///   mempool, including one this wallet just broadcast, or mined above the index's height; every
    ///   transaction while the index is unhealthy or cannot be read) and to which that
    ///   transaction's payload may give YED ([`payload_yed_outputs`]; review 3 MEDIUM-2), counted
    ///   at the payload's figure, or as unknown where the payload states none (a claim cancel's
    ///   refund) or this build cannot read it.
    ///
    /// An unknown amount refuses outright; otherwise the transaction is refused when its own
    /// payload reassigns fewer cents than it spends. A REDEEM spending a vault is MP-1's, never
    /// this guard's. Where Yellowback is not live (`yed_getinfo` answers `-32601`) there is no
    /// index and no guard, as ycashd without one: the raw transaction is the explicit path.
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
        // IndexJudged's facts: whether the index is healthy, and the height it has judged to
        let (mut healthy, index_height) =
            match node::call(node, "yed_getinfo", serde_json::json!([])).await {
                // no Yellowback index: no guard (ycashd's without one)
                Err(NodeError::Rpc { code: c, .. }) if c == code::METHOD_NOT_FOUND => return Ok(()),
                // fail closed: every input of this wallet is read by its transaction's payload
                Err(_) => (false, -1),
                Ok(v) => (
                    v["healthy"].as_bool() == Some(true),
                    v["height"].as_i64().unwrap_or(-1),
                ),
            };
        let tokens = if healthy {
            match self.tokens(node).await {
                Ok(t) => t,
                Err(_) => {
                    healthy = false; // the tokens cannot be read: judge by payloads (fail closed)
                    Vec::new()
                }
            }
        } else {
            Vec::new()
        };
        let judged =
            |height: Option<u32>| healthy && height.is_some_and(|h| h as i64 <= index_height);
        let mut cents = 0i64;
        let mut outpoints = Vec::new();
        let mut unknown = Vec::new();
        for i in &tx.vin {
            let (t, n) = (txid_hex(&i.prevout.txid), i.prevout.n);
            let op = format!("{t}:{n}");
            if healthy {
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
                    outpoints.push(op);
                    continue;
                }
            }
            // review 3 MEDIUM-2: an output of this wallet the index has not judged is read by its
            // transaction's payload. The wallet has synced to the node's mempool, so its own
            // transactions (just broadcast ones included) are here; an input it does not know is
            // read from the node, and one the node cannot show either refuses (fail closed).
            let (prev, height, coinbase) = match self.parsed(&t) {
                Some(pp) => (
                    pp.tx.clone(),
                    self.st
                        .wtx
                        .get(&t)
                        .and_then(|w| w.block.as_ref().map(|b| b.height)),
                    pp.coinbase,
                ),
                None => {
                    let Some(c) = node_coin(node, &i.prevout).await? else {
                        continue; // spent or unknown: the node refuses the transaction
                    };
                    if self.book.owns_script(&c.script).is_none() || judged(c.height) {
                        continue;
                    }
                    match node::raw_tx(node, &t)
                        .await
                        .ok()
                        .flatten()
                        .and_then(|b| Transaction::parse(&b).ok())
                    {
                        Some((x, _)) => (x, c.height, c.coinbase),
                        None => {
                            unknown.push(op);
                            continue;
                        }
                    }
                }
            };
            if judged(height) {
                continue;
            }
            let Some(out) = prev.vout.get(n as usize) else {
                continue;
            };
            if self.book.owns_script(&out.script_pubkey).is_none() {
                continue;
            }
            match payload_yed_outputs(&prev, coinbase) {
                Some(s) if !s.contains(&n) => {}
                Some(_) => match stated_cents(&prev, n) {
                    Some(c) => {
                        cents += c;
                        outpoints.push(format!("{op} (not judged yet)"));
                    }
                    None => unknown.push(op),
                },
                None => unknown.push(op),
            }
        }
        if !unknown.is_empty() {
            return Err(RpcError::new(
                code::WALLET_ERROR,
                format!(
                    "yed-burn-refused: this transaction spends output(s) of this wallet whose transaction the Yellowback index has not judged yet and whose payload may give them YED ({}); whatever YED they carry would be destroyed. Pass allowyedburn = true to send it anyway.",
                    unknown.join(", ")
                ),
            ));
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

impl Wallet {
    /// `signrawtransaction hex prevtxs privatekeys ( sighashtype )` against a backend that has no
    /// `signrawtransaction` (kogany, F-S2-7): the P2PKH inputs whose key the caller gives are
    /// signed here (ZIP-243 `SIGHASH_ALL` under the next block's branch), the rest are left as
    /// they are; `complete` and `errors` come from the node's dry run
    /// (`yed_validaterawtransaction`). With no keys (`[]`) it only verifies (x402's call).
    async fn sign_with_given_keys(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        let hexs = p[0]
            .as_str()
            .ok_or_else(|| RpcError::new(code::TYPE_ERROR, "Expected type string"))?;
        let raw =
            hex::decode(hexs).map_err(|_| invalid("argument 1 must be hexadecimal string"))?;
        let (mut tx, _) = Transaction::parse(&raw)
            .map_err(|_| RpcError::new(code::DESERIALIZATION_ERROR, "TX decode failed"))?;
        if let Some(t) = param(p, 3).and_then(|v| v.as_str()) {
            if t != "ALL" {
                return Err(invalid(format!(
                    "yewd: sighash type {t} is not signed here (ALL only)"
                )));
            }
        }
        let mut keys: Vec<(secp256k1::SecretKey, [u8; 20])> = Vec::new();
        for k in param(p, 2)
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
        {
            let w = k.as_str().unwrap_or("");
            let key = yew_core::keys::decode_wif(self.network, w)
                .map_err(|_| RpcError::new(code::INVALID_ADDRESS_OR_KEY, "Invalid private key"))?;
            keys.push((key.secret, key.hash160));
        }
        let given: Vec<Value> = param(p, 1)
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let next = next_block(node).await?;
        for i in 0..tx.vin.len() {
            let prev = tx.vin[i].prevout;
            let from_given = given.iter().find(|o| {
                o["txid"]
                    .as_str()
                    .and_then(|t| yew_core::tx::txid_from_hex(t).ok())
                    == Some(prev.txid)
                    && o["vout"].as_u64() == Some(prev.n as u64)
            });
            let (script, amount) = match from_given {
                Some(o) => (
                    hex::decode(o["scriptPubKey"].as_str().unwrap_or("")).unwrap_or_default(),
                    o.get("amount")
                        .filter(|v| !v.is_null())
                        .map(amount_param)
                        .transpose()?
                        .unwrap_or(0),
                ),
                None => match node_coin(node, &prev).await? {
                    Some(c) => (c.script, c.value),
                    None => continue,
                },
            };
            let Some(h) = yew_core::script::p2pkh_hash(&script) else {
                continue;
            };
            if let Some((sk, _)) = keys.iter().find(|(_, kh)| *kh == h) {
                tx.sign_p2pkh_input(i, sk, &script, amount, next.branch)
                    .map_err(|e| RpcError::new(code::INTERNAL_ERROR, e.to_string()))?;
            }
        }
        let signed_hex = tx_hex(&tx)?;
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
}

#[cfg(test)]
mod tests {
    use super::*;

    const COIN: i64 = 100_000_000;

    fn coin(value: i64, coinbase: bool) -> (OutPoint, i64, Vec<u8>, bool) {
        (
            OutPoint {
                txid: [1; 32],
                n: 0,
            },
            value,
            Vec::new(),
            coinbase,
        )
    }

    /// Review LOW-3: `SelectCoins`' coinbase flags, as ycash6 sets them.
    #[test]
    fn coinbase_flags_follow_select_coins() {
        // only coinbase coins: "only" where coinbase must be shielded, never on regtest
        assert_eq!(
            coinbase_flags(&[coin(COIN, true)], 2 * COIN, true),
            (true, false)
        );
        assert_eq!(
            coinbase_flags(&[coin(COIN, true)], 2 * COIN, false),
            (false, false)
        );
        // ordinary coins short, coinbase would cover: "need"
        let c = [coin(COIN, false), coin(COIN, true)];
        assert_eq!(coinbase_flags(&c, 2 * COIN, true), (false, true));
        // not even with coinbase: no flag
        assert_eq!(coinbase_flags(&c, 2 * COIN + 1, true), (false, false));
        // ordinary coins above the target (the failure is elsewhere): no flag
        assert_eq!(coinbase_flags(&c, COIN / 2, true), (false, false));
        assert_eq!(coinbase_flags(&[], COIN, true), (false, false));
    }

    /// Review LOW-3: `CreateTransaction`'s refusal texts, byte for byte the C++ lines'
    /// (ycash6 `src/wallet/wallet.cpp`, `YellowbackInputRefusal`).
    #[test]
    fn select_fail_texts_are_the_cpp_lines() {
        let pq = "Insufficient funds in ordinary transparent addresses; this wallet also holds 5.00 YEC at post-quantum addresses: send from one with z_sendmany, which returns the change to it";
        let tail = "; its coinbase funds can only be spent after they have been sent to a zaddr";
        assert_eq!(select_fail_text(5 * COIN, "", (false, false)), pq);
        assert_eq!(
            select_fail_text(5 * COIN, "", (true, false)),
            format!("{pq}{tail}")
        );
        assert_eq!(
            select_fail_text(5 * COIN, "", (false, true)),
            format!("{pq}{tail}")
        );
        let live = yed_input_refusal(true, "aa:1, bb:0");
        assert_eq!(live, "refusing to spend a Yellowback outpoint as plain YEC: aa:1, bb:0 (its YED would burn; lock it again with yed_lockcoins)");
        assert_eq!(
            yed_input_refusal(false, "aa:1"),
            "refusing to spend an output that carries YED as plain YEC while Yellowback is not live: aa:1 (its YED would burn; to destroy it deliberately, name the outpoint in a raw transaction)"
        );
        assert_eq!(select_fail_text(0, &live, (false, false)), live);
        // the coinbase reasons win over the YED refusal
        assert_eq!(
            select_fail_text(0, &live, (true, false)),
            "Coinbase funds can only be sent to a zaddr"
        );
        assert_eq!(
            select_fail_text(0, &live, (false, true)),
            "Insufficient funds, coinbase funds can only be spent after they have been sent to a zaddr"
        );
        assert_eq!(
            select_fail_text(0, "", (false, false)),
            "Insufficient funds"
        );
        // DisplayMoney: the amount and the unit
        assert_eq!(display_money(COIN), "1.00 YEC");
        assert_eq!(display_money(10_000), "0.0001 YEC");
    }
}
