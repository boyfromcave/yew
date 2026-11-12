// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! `yed_mint` and `yed_sweepcarriers` (R6; ycash6 `src/rpc/yellowbackwallet.cpp` `yed_mint`,
//! `CompleteMint`, `yed_sweepcarriers`; `src/yellowback/txbuilder.cpp` `PreflightMint`,
//! `BuildCarrier`, `BuildMint`, `MintOutputs`, `BuildSweepCarriers`): the v3 two-step flow (W7).
//!
//! **Preflight** at `R = tip − REF_LAG` from the node (`yed_estimatecollateral`: MINTPOL-1 as
//! `mintBlocked`, MINT-5's collateral, the combined `pMint`, the arming state; `yed_buildbundle` for
//! the pool's bundle while armed). **Carrier**: a fresh key's `P2SH(carrierScript(pk,
//! SHA256(bundle)))` of `CARRIER_VALUE`, funded and broadcast, recorded in the wallet state. **MINT**
//! once the carrier confirms (`wait`, or the wallet's poll for `wait = false`): the vault (a fresh
//! SLH-DSA owner), the token (a fresh holder), the payload, the pool fee, the YEC funding, the
//! carrier as `vin[last]`; dry-run by the node (`yed_validaterawtransaction`: MINT-1..10) before it
//! is committed. Every signature is the signer's.

use serde_json::Value;
use yew_core::params::{CARRIER_VALUE, TOKEN_VALUE};
use yew_core::payload::{self, Payload, FEE_VOUT_NONE};
use yew_core::tx::{OutPoint, Transaction, TxIn, TxOut};
use yewd_proto::{GatePath, KeyRef};

use crate::build::{next_block, node_coin, op_str, tx_hex, NodeCoin};
use crate::json::J;
use crate::node::{self, Node, NodeError};
use crate::rpc::invalid;
use crate::state::CarrierRec;
use crate::{code, txid_hex, RpcError, Wallet};

pub const SERVED: &[&str] = &["yed_mint", "yed_sweepcarriers"];

/// How long `wait = true` waits for the carrier's confirmation.
const CARRIER_WAIT_SECS: u64 = 300;

/// A mint between its carrier and its MINT (ycashd keeps it in memory only, as here).
#[derive(Clone, Debug)]
pub struct PendingMint {
    /// `None` for a mint; the claim's arguments for a claim.
    pub claim: Option<crate::claim::ClaimArgs>,
    /// An equivocation report's two attestations (hex), S3's `yed_reportequivocation`.
    pub equivocation: Option<(String, String)>,
    /// A claim notice's vault txid (`yed_claimnotice`, S4).
    pub notice: Option<String>,
    pub carrier: OutPoint,
    pub cents: i64,
    pub lock_blocks: i64,
    pub from: String,
    pub max_collateral: i64,
    pub est: Value,
    /// The bundle facts at the carrier's `R` (`BundleAt`; empty while unarmed).
    pub facts: crate::armed::BundleFacts,
}

/// `CombineMint`'s source: the estimate's, or `"x"` when the estimate names none (unarmed:
/// `yed_estimatecollateral` leaves it empty, a MINT's pMint is then xMint).
fn mint_source(est: &Value) -> String {
    match est["source"].as_str() {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => "x".to_string(),
    }
}

/// MINT-10: `|fast − a| · 10⁴ > max(0, bps) · min(fast, a)`.
pub fn mint10_diverged(fast: i64, a: i64, bps: i64) -> bool {
    let diff = (fast as i128 - a as i128).unsigned_abs();
    diff * yew_core::params::BPS as u128 > bps.max(0) as u128 * fast.min(a).max(0) as u128
}

/// ycashd's code for a build refusal (`ThrowBuildError`).
/// `TX_EXPIRING_SOON_THRESHOLD`.
const EXPIRING_SOON: i64 = 3;

pub fn build_error(msg: String) -> RpcError {
    const RULE: &[&str] = &[
        "mintpol-",
        "mint-unsatisfiable",
        "vault-locked",
        "claim-not-yet",
        "claim-not-underwater",
        "mempool-check-failed",
        "intent-",
        "yed-template-",
        "bundle-insufficient",
        "mint9-",
        "mint10-",
        "red1-",
        "red5-",
        "afee1-",
        "notice-standing",
        "notice-not-underwater",
        "carrier-lapsed",
        "carrier-unconfirmed",
        "bad-mint-",
        "vault-spend-",
        "vault-claim-",
        "mint-not-active",
        "mint-halted-",
        "mint-supply-cap",
        "mint-vault-share",
        "mint-dry-run",
        "liveness-",
        // the attestor role (S3)
        "bond-below-min",
        "lock-below-min",
        "bond-locked",
        "bond-spent",
        "not-dormant",
        "not-equivocation",
        "attest-unknown-seq",
        "attest-key-not-held",
        "attest-range",
        "attest-stale",
        "equivocation-guard",
        "register-refused",
    ];
    const PARAM: &[&str] = &[
        "mint-bad-lock",
        "bad-mint-amount",
        "bad-xfer-amount",
        "vault-not-found",
        "vault-not-active",
        "vault-not-owned",
        "not-a-yellowback-address",
        "bad-address",
        "bundle-malformed",
        "attest-malformed",
        "carrier-selector",
    ];
    if RULE.iter().any(|p| msg.starts_with(p)) {
        RpcError::new(code::TRANSACTION_REJECTED, msg)
    } else if PARAM.iter().any(|p| msg.starts_with(p)) {
        RpcError::new(code::INVALID_PARAMETER, msg)
    } else {
        RpcError::new(code::WALLET_ERROR, msg)
    }
}

fn node_build_error(e: NodeError) -> RpcError {
    match e {
        NodeError::Rpc { message, .. } => build_error(message),
        other => other.into(),
    }
}

/// `ParseAddressChoice` for `from`: `""` (any coin), an `s1…` address (its coins only), a Sapling
/// address of this wallet (`None` here: its notes fund the carrier and the mint, `zfund.rs`).
fn from_script(w: &Wallet, from: &str) -> Result<Option<Vec<u8>>, RpcError> {
    if from.is_empty() {
        return Ok(None);
    }
    if let Some(s) = crate::rpc::parse_taddr_script(w.network, from)
        .filter(|s| yew_core::script::p2pkh_hash(s).is_some())
    {
        return Ok(Some(s));
    }
    if w.is_sapling(from) {
        // the Sapling source (F-S2-8): its notes fund the carrier and the mint
        if w.view.owns_address(from).is_none() {
            return Err(build_error(format!(
                "bad-address: no spending key for {from} in this wallet"
            )));
        }
        return Ok(None);
    }
    Err(build_error(
        "bad-address: from: not a transparent (s1…) or Sapling (ys1…) address of this network"
            .into(),
    ))
}

impl Wallet {
    pub async fn mint_call(
        &mut self,
        node: &dyn Node,
        method: &str,
        p: &[Value],
    ) -> Result<J, RpcError> {
        match method {
            "yed_mint" => self.yed_mint(node, p).await,
            "yed_sweepcarriers" => self.yed_sweepcarriers(node, p).await,
            _ => Err(RpcError::new(code::METHOD_NOT_FOUND, "Method not found")),
        }
    }

    /// Plain YEC coins for a Yellowback build, optionally only those paying `only`: confirmed,
    /// smallest first (`PickYecCoins` without the fee follower: P2PKH inputs only here).
    async fn yec_for(
        &self,
        node: &dyn Node,
        needed: i64,
        only: Option<&[u8]>,
    ) -> Result<Vec<(OutPoint, i64, Vec<u8>)>, RpcError> {
        if needed <= 0 {
            return Ok(vec![]);
        }
        let mut cand: Vec<(OutPoint, i64, Vec<u8>)> = self
            .eligible(node, &Default::default())
            .await?
            .into_iter()
            .filter(|c| only.is_none_or(|o| c.script == o))
            .map(|c| (c.outpoint, c.value, c.script))
            .collect();
        cand.sort_by_key(|c| c.1);
        let mut got = 0;
        let mut out = Vec::new();
        for c in cand {
            if got >= needed {
                break;
            }
            got += c.1;
            out.push(c);
        }
        if got < needed {
            return Err(build_error(format!(
                "insufficient-yec: need {}, have {} confirmed and unlocked",
                crate::rpc::format_money(needed),
                crate::rpc::format_money(got)
            )));
        }
        Ok(out)
    }

    /// Fund `tx` (outputs already set; `input_value` from its other inputs) with plain YEC at the
    /// flat fee raised to the ZIP-317 conventional fee of the shape (P-2), change to a change key;
    /// `extra` inputs (a carrier) are appended after the funding. Returns the funding coins.
    pub(crate) async fn fund_yed(
        &mut self,
        node: &dyn Node,
        base: &Transaction,
        input_value: i64,
        flat: i64,
        only: Option<&[u8]>,
        extra: &[(OutPoint, usize)],
    ) -> Result<(Transaction, Vec<(OutPoint, i64, Vec<u8>)>), RpcError> {
        let change_script = match only {
            Some(o) => o.to_vec(),
            None => self.new_change()?,
        };
        let mut fee = flat;
        for _ in 0..6 {
            let mut tx = base.clone();
            let needed = tx.output_total() + fee - input_value;
            let coins = self.yec_for(node, needed, only).await?;
            for c in &coins {
                tx.vin.push(TxIn::new(c.0));
            }
            for (o, _) in extra {
                tx.vin.push(TxIn::new(*o));
            }
            let got: i64 = coins.iter().map(|c| c.1).sum();
            let change = got - needed.max(0);
            if change > 0 {
                tx.vout.push(TxOut {
                    value: change,
                    script_pubkey: change_script.clone(),
                });
            }
            let mut sizes: Vec<usize> = coins
                .iter()
                .map(|c| yew_core::tx::script_sig_size_bound(&c.2))
                .collect();
            sizes.extend(extra.iter().map(|(_, n)| *n));
            let conventional = tx.zip317_conventional_fee(&sizes).unwrap_or(fee);
            if conventional > fee {
                fee = conventional;
                continue;
            }
            return Ok((tx, coins));
        }
        Err(RpcError::new(
            code::WALLET_ERROR,
            "the fee did not converge",
        ))
    }

    /// The mint's preflight estimate at `R` (ycashd `PreflightMint`: `MintGate`, then `BundleAt`
    /// with **the caller's bundle** when `bundleHex` is given, then `CombineMint`). Without a
    /// bundle the node's `yed_estimatecollateral` is the whole answer (it builds the pool's
    /// bundle). With one, the node is asked at a price override (which skips its pool bundle and
    /// still reports `xMint` and the MINTPOL-1 gate at `R`), the bundle is read here, and the
    /// estimate is taken again at the combined `pMint = min(xMint, aMint)`: on an armed snapshot
    /// with an empty pool the plain estimate refuses `bundle-insufficient` although the caller's
    /// bundle suffices (yellowback_cancel_limit, yellowback_mint_armed).
    async fn mint_estimate(
        &self,
        node: &dyn Node,
        cents: i64,
        lock_blocks: i64,
        bundle: &[u8],
    ) -> Result<Value, RpcError> {
        let estimate = |price: Option<i64>| {
            let params = match price {
                Some(p) => serde_json::json!([cents, lock_blocks, p]),
                None => serde_json::json!([cents, lock_blocks]),
            };
            async move {
                node::call(node, "yed_estimatecollateral", params)
                    .await
                    .map_err(node_build_error)
            }
        };
        if bundle.is_empty() {
            return estimate(None).await;
        }
        let probe = estimate(Some(yewd_proto::attest::PRICE_MIN)).await?;
        let r = probe["refHeight"].as_i64().unwrap_or(0);
        let facts = self.bundle_at(node, r, "", bundle).await?;
        if !facts.armed {
            return estimate(None).await;
        }
        let x_mint = probe["xMint"].as_i64();
        // MINT-10 (`CombineMint`, W17): the caller's bundle against the pools' fast median at R
        if let (Some(x), Some(a)) = (x_mint, facts.a_mint) {
            let px = node::call(node, "yed_getprice", serde_json::json!([r]))
                .await
                .map_err(node_build_error)?;
            let fast = px["pFast"].as_i64().unwrap_or(x);
            let info = node::call(node, "yed_getinfo", serde_json::json!([])).await?;
            let bps = info["params"]["attest"]["divergeBpsAttest"]
                .as_i64()
                .unwrap_or(0);
            if mint10_diverged(fast, a, bps) {
                return Err(build_error(format!("mint10-diverged: the pools' fast median {fast} and the attestors' {a} micro-USD differ by more than {} bps, so minting is paused until they agree", bps.max(0))));
            }
        }
        let p_mint = crate::armed::mint_price(x_mint, &facts).ok_or_else(|| {
            build_error("mintpol-no-price: no price the network can mint at".into())
        })?;
        let mut est = estimate(Some(p_mint)).await?;
        if let Some(o) = est.as_object_mut() {
            let a = facts.a_mint;
            o.insert("aMint".into(), a.map(Value::from).unwrap_or(Value::Null));
            let source = match (x_mint, a) {
                (Some(x), Some(a)) if p_mint == a && a < x => "a",
                _ => "x",
            };
            o.insert("source".into(), Value::from(source));
            o.insert(
                "bundleSeqs".into(),
                Value::from(facts.seqs.iter().map(|s| *s as i64).collect::<Vec<_>>()),
            );
        }
        Ok(est)
    }

    /// `yed_mint cents lockBlocks ( "from" "bundleHex" wait maxCollateralZat )`.
    async fn yed_mint(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        if p.len() < 2 || p.len() > 6 {
            return Err(RpcError::new(
                code::MISC_ERROR,
                "yed_mint cents lockBlocks ( \"from\" \"bundleHex\" wait maxCollateralZat )",
            ));
        }
        let cents = p[0]
            .as_i64()
            .ok_or_else(|| RpcError::new(code::TYPE_ERROR, "Expected type number"))?;
        let lock_blocks = p[1]
            .as_i64()
            .ok_or_else(|| RpcError::new(code::TYPE_ERROR, "Expected type number"))?;
        let from = p.get(2).and_then(|v| v.as_str()).unwrap_or("").to_string();
        let bundle_arg = p.get(3).and_then(|v| v.as_str()).unwrap_or("").to_string();
        let wait = p.get(4).and_then(|v| v.as_bool()).unwrap_or(true);
        let max_collateral = match p.get(5) {
            None | Some(Value::Null) => 0,
            Some(v) => v
                .as_i64()
                .filter(|n| *n >= 0)
                .ok_or_else(|| invalid("maxCollateralZat must be a non-negative number"))?,
        };
        let only = from_script(self, &from)?;
        // preflight at R (MINTPOL-1, the bundle, MINT-10, the collateral bound), before any transaction
        crate::yed::yed_info(node).await?;
        let info = node::call(node, "yed_getinfo", serde_json::json!([])).await?;
        let prm = &info["params"];
        let (min_mint, max_mint) = (
            prm["minMintCents"].as_i64().unwrap_or(100),
            prm["maxMintCents"].as_i64().unwrap_or(10_000_000),
        );
        if cents < min_mint || cents > max_mint {
            return Err(build_error(format!(
                "bad-mint-amount: cents must be between {min_mint} and {max_mint}"
            )));
        }
        let bundle_bytes = if bundle_arg.is_empty() {
            Vec::new()
        } else {
            hex::decode(&bundle_arg)
                .map_err(|_| build_error("bundle-malformed: bundleHex is not hex".into()))?
        };
        let est = self
            .mint_estimate(node, cents, lock_blocks, &bundle_bytes)
            .await?;
        if est["mintBlocked"].as_bool() == Some(true) {
            return Err(build_error(
                est["mintBlockedReason"]
                    .as_str()
                    .unwrap_or("mintpol-")
                    .to_string(),
            ));
        }
        let collateral = est["requiredZatFloored"]
            .as_i64()
            .or_else(|| est["requiredZat"].as_i64())
            .ok_or_else(|| {
                build_error("mintpol-no-price: no price the network can mint at".into())
            })?;
        if max_collateral > 0 && collateral > max_collateral {
            return Err(RpcError::new(code::WALLET_ERROR, format!("collateral-above-max: the mint needs {collateral} zat of collateral, above the maxCollateralZat of {max_collateral}")));
        }
        // the whole mint must be coverable before the carrier is broadcast (real-stack run
        // YEW-REAL finding 5): the MINT's collateral and the carrier's flat fee at least, from the
        // same plain coins the MINT is funded from (`yec_for`: confirmed, unlocked, `from` only when
        // named); a Sapling source stages its collateral in the carrier itself (zfund's check)
        if !self.is_sapling(&from) {
            let flat = prm["feeZat"].as_i64().unwrap_or(10_000);
            self.yec_for(node, mint_funds_floor(collateral, flat), only.as_deref())
                .await?;
        }
        let r = est["refHeight"].as_i64().unwrap_or(0);
        // BundleAt (the pool's bundle, or bundleHex) and, while armed, AFEE-W at completion (F-S2-4)
        let facts = self.bundle_at(node, r, "", &bundle_bytes).await?;
        let bundle = facts.bundle.clone();
        // the carrier
        let z_from = self.is_sapling(&from).then(|| from.clone());
        let carrier = self
            .build_carrier_from(node, &bundle, r, "", only.as_deref(), z_from.as_deref())
            .await?;
        let pending = PendingMint {
            claim: None,
            equivocation: None,
            notice: None,
            carrier,
            cents,
            lock_blocks,
            from: from.clone(),
            max_collateral,
            est: est.clone(),
            facts: facts.clone(),
        };
        if !wait {
            self.pending.push(pending);
            return Ok(J::obj()
                .with("txid", "")
                .with("vault", "")
                .with("ownerAddress", "")
                .with("termClass", "")
                .with("lockHeight", 0i64)
                .with("claimHeight", 0i64)
                .with("collateralZat", 0i64)
                .with("feeZat", 0i64)
                .with("payee", J::Null)
                .with("fundedFrom", "")
                .with("warning", "")
                .with("carrierTxid", txid_hex(&carrier.txid))
                .with("pending", true)
                .with("refHeight", r)
                .with("xMint", raw_or_null(&est["xMint"]))
                .with("aMint", raw_or_null(&est["aMint"]))
                .with("pMint", raw_or_null(&est["pMint"]))
                .with("source", mint_source(&est))
                .with("bundleSeqs", raw_or_null(&est["bundleSeqs"]))
                .with("attestFeeZat", 0i64)
                .with("attestPayee", J::Null));
        }
        self.wait_or_park(node, pending).await
    }

    /// `wait=true`: park the completion when the caller waits without the wallet
    /// ([`Wallet::defer_wait`]), else wait here and complete.
    pub(crate) async fn wait_or_park(
        &mut self,
        node: &dyn Node,
        pm: PendingMint,
    ) -> Result<J, RpcError> {
        if self.defer_wait {
            let k = op_str(&pm.carrier);
            self.parked.insert(k.clone(), pm);
            return Err(RpcError::new(code::CARRIER_PARKED, k));
        }
        self.wait_carrier(node, &pm.carrier).await?;
        self.complete_one(node, &pm).await
    }

    /// A parked completion, once its carrier confirmed (`confirmed`), else its refusal.
    pub async fn resume_parked(
        &mut self,
        node: &dyn Node,
        carrier: &str,
        confirmed: Result<(), RpcError>,
    ) -> Result<J, RpcError> {
        let pm = self.parked.remove(carrier).ok_or_else(|| {
            RpcError::new(code::INTERNAL_ERROR, "yewd: the parked completion is gone")
        })?;
        confirmed?;
        self.sync(node).await?;
        self.complete_one(node, &pm).await
    }

    /// Whether a carrier confirmed (`Ok(true)`), is still unconfirmed (`Ok(false)`), or is not an
    /// unspent output (the refusal `WaitForCarrier` gives).
    pub async fn carrier_confirmed(node: &dyn Node, carrier: &str) -> Result<bool, RpcError> {
        let op = crate::build::outpoint_param(&Value::String(carrier.to_string()), "carrier")?;
        match node_coin(node, &op).await? {
            Some(c) => Ok(c.height.is_some()),
            None => Err(build_error(format!(
                "carrier-unconfirmed: the carrier {carrier} is not an unspent output"
            ))),
        }
    }

    /// The completion of one pending transaction on its confirmed carrier.
    async fn complete_one(&mut self, node: &dyn Node, pm: &PendingMint) -> Result<J, RpcError> {
        if let Some(t) = &pm.notice {
            return self.complete_notice(node, t, pm).await;
        }
        match (&pm.claim, &pm.equivocation) {
            (Some(a), _) => self.complete_claim(node, a, pm).await,
            (None, Some((a, b))) => {
                let dec = |h: &str| {
                    hex::decode(h)
                        .ok()
                        .and_then(|b| yew_core::bundle::Attestation::decode(&b))
                };
                match (dec(a), dec(b)) {
                    (Some(a), Some(b)) => {
                        self.complete_equivocation(node, &a, &b, &pm.carrier).await
                    }
                    _ => Err(RpcError::new(
                        code::INTERNAL_ERROR,
                        "a pending report's attestations",
                    )),
                }
            }
            (None, None) => self.complete_mint(node, pm).await,
        }
    }

    /// Wait until the carrier confirms (`WaitForCarrier`), following the node meanwhile.
    pub(crate) async fn wait_carrier(
        &mut self,
        node: &dyn Node,
        carrier: &OutPoint,
    ) -> Result<(), RpcError> {
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(CARRIER_WAIT_SECS);
        loop {
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
            if std::time::Instant::now() > deadline {
                return Err(RpcError::new(code::WALLET_ERROR, "carrier-wait-timeout: the carrier did not confirm; call again (yed_sweepcarriers reclaims it once it lapses)"));
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
    }

    /// `BuildCarrier` (transparent): the carrier output of a fresh key, funded, signed, sent, and
    /// recorded.
    pub(crate) async fn build_carrier(
        &mut self,
        node: &dyn Node,
        bundle: &[u8],
        r: i64,
        selector: &str,
        only: Option<&[u8]>,
    ) -> Result<OutPoint, RpcError> {
        self.build_carrier_from(node, bundle, r, selector, only, None)
            .await
    }

    /// [`Wallet::build_carrier`], funded from the Sapling notes of `z_from` when given (the
    /// carrier step of a mint from a Sapling address: no transparent input).
    pub(crate) async fn build_carrier_from(
        &mut self,
        node: &dyn Node,
        bundle: &[u8],
        r: i64,
        selector: &str,
        only: Option<&[u8]>,
        z_from: Option<&str>,
    ) -> Result<OutPoint, RpcError> {
        let info = node::call(node, "yed_getinfo", serde_json::json!([])).await?;
        let flat = info["params"]["feeZat"].as_i64().unwrap_or(10_000);
        let ref_window = info["params"]["refWindow"].as_i64().unwrap_or(40);
        let next = next_block(node).await?;
        let index = self.st.issued.external;
        let pk = self.new_wallet_key()?;
        let h = yew_core::keys::hash160(&pk);
        self.st.book.insert(
            yew_core::keys::encode_p2pkh(self.network, &h),
            crate::state::BookEntry {
                label: String::new(),
                purpose: "yellowback-carrier".into(),
            },
        );
        let redeem = yew_core::script::carrier_script(&pk, &yew_core::keys::sha256(bundle))
            .map_err(|e| RpcError::new(code::WALLET_ERROR, e.to_string()))?;
        let mut base = Transaction::new_v4();
        base.expiry_height = (r + ref_window) as u32;
        base.vout.push(TxOut {
            value: CARRIER_VALUE,
            script_pubkey: yew_core::script::p2sh_of(&redeem),
        });
        if let Some(z) = z_from {
            let (hexs, _) = self
                .z_fund_and_sign(
                    node,
                    &base,
                    &[],
                    &[],
                    0,
                    &[],
                    z,
                    flat,
                    GatePath::Yed,
                    &next,
                    "carrier",
                )
                .await?;
            let txid = self.broadcast_hex(node, &hexs).await?;
            let op = OutPoint {
                txid: yew_core::tx::txid_from_hex(&txid)
                    .map_err(|e| RpcError::new(code::INTERNAL_ERROR, e))?,
                n: 0,
            };
            self.st.carriers.insert(
                op_str(&op),
                CarrierRec {
                    index,
                    pk: hex::encode(pk),
                    bundle: hex::encode(bundle),
                    ref_height: r,
                    selector: selector.into(),
                    created_height: next.height as i64 - 1,
                },
            );
            self.persist_state()?;
            return Ok(op);
        }
        let (tx, coins) = self.fund_yed(node, &base, 0, flat, only, &[]).await?;
        let prevs: Vec<NodeCoin> = coins
            .iter()
            .map(|c| NodeCoin {
                value: c.1,
                script: c.2.clone(),
                height: None,
                coinbase: false,
            })
            .collect();
        let keys: Vec<KeyRef> = coins
            .iter()
            .map(|c| self.key_of_script(&c.2).unwrap_or(KeyRef::None))
            .collect();
        let fee: i64 = prevs.iter().map(|c| c.value).sum::<i64>() - tx.output_total();
        let signed = self
            .sign_inputs(
                &tx,
                &prevs,
                &keys,
                &[],
                GatePath::Yed,
                CARRIER_VALUE + fee,
                next.branch,
            )
            .await?;
        let txid = self.broadcast(node, &signed, None).await?;
        let op = OutPoint {
            txid: yew_core::tx::txid_from_hex(&txid)
                .map_err(|e| RpcError::new(code::INTERNAL_ERROR, e))?,
            n: 0,
        };
        self.st.carriers.insert(
            op_str(&op),
            CarrierRec {
                index,
                pk: hex::encode(pk),
                bundle: hex::encode(bundle),
                ref_height: r,
                selector: selector.into(),
                created_height: next.height as i64 - 1,
            },
        );
        self.persist_state()?;
        Ok(op)
    }

    /// The pending mints whose carrier confirmed, completed (the wallet's poll; `wait = false`).
    pub async fn complete_pending(&mut self, node: &dyn Node) {
        let mut keep = Vec::new();
        for pm in std::mem::take(&mut self.pending) {
            match node_coin(node, &pm.carrier).await {
                Ok(Some(c)) if c.height.is_some() => {
                    let r = self.complete_one(node, &pm).await;
                    if let Err(e) = r {
                        eprintln!(
                            "yewd: the pending transaction on carrier {} failed: {e}",
                            op_str(&pm.carrier)
                        );
                    }
                }
                Ok(Some(_)) => keep.push(pm),
                _ => {}
            }
        }
        self.pending.extend(keep);
    }

    /// `CompleteMint` / `BuildMint` on a confirmed carrier.
    async fn complete_mint(&mut self, node: &dyn Node, pm: &PendingMint) -> Result<J, RpcError> {
        let info = node::call(node, "yed_getinfo", serde_json::json!([])).await?;
        let prm = info["params"].clone();
        let flat = prm["feeZat"].as_i64().unwrap_or(10_000);
        let ref_window = prm["refWindow"].as_i64().unwrap_or(40);
        let claim_delay = prm["claimDelay"].as_i64().unwrap_or(0);
        let attestor_set = yew_core::tx::txid_from_hex(prm["attestorSetId"].as_str().unwrap_or(""))
            .map_err(|e| RpcError::new(code::MISC_ERROR, format!("yewd: attestorSetId: {e}")))?;
        let next = next_block(node).await?;
        let rec = self
            .st
            .carriers
            .get(&op_str(&pm.carrier))
            .cloned()
            .ok_or_else(|| {
                RpcError::new(
                    code::WALLET_ERROR,
                    "carrier-key-missing: the carrier is not this wallet's",
                )
            })?;
        // CheckCarrier
        match node_coin(node, &pm.carrier).await? {
            Some(c) if c.height.is_some() => {}
            _ => {
                return Err(build_error(format!(
                    "carrier-unconfirmed: the carrier {} is not a confirmed unspent output",
                    op_str(&pm.carrier)
                )))
            }
        }
        let r = rec.ref_height;
        // ycashd's CheckExpiry (yellowback/txbuilder.cpp:594): the mint expires at r + refWindow
        if r + ref_window < next.height as i64 + EXPIRING_SOON {
            return Err(build_error("expiring-too-soon: the transaction would expire too soon; the index is too far behind the chain".to_string()));
        }
        if next.height as i64 - ref_window > r {
            return Err(build_error(format!(
                "carrier-lapsed: the carrier's reference height {r} is outside the window at height {}; yed_sweepcarriers reclaims it",
                next.height
            )));
        }
        let est = &pm.est;
        let collateral = est["requiredZatFloored"]
            .as_i64()
            .or_else(|| est["requiredZat"].as_i64())
            .unwrap_or(0);
        if pm.max_collateral > 0 && collateral > pm.max_collateral {
            return Err(RpcError::new(code::WALLET_ERROR, format!("collateral-above-max: the mint needs {collateral} zat of collateral, above the maxCollateralZat of {}", pm.max_collateral)));
        }
        // pMint = min(xMint, aMint) while armed (CombineMint); the estimate's for the pool's bundle
        let p_mint = if pm.facts.armed && pm.facts.a_mint.is_some() {
            crate::armed::mint_price(est["xMint"].as_i64(), &pm.facts)
                .unwrap_or_else(|| est["pMint"].as_i64().unwrap_or(0))
        } else {
            est["pMint"].as_i64().unwrap_or(0)
        };
        let term_class = est["termClass"].as_str().unwrap_or("A").to_string();
        let class_idx = "ABC".find(&term_class).unwrap_or(0) as u8;
        let lock_height = r + pm.lock_blocks;
        let claim_height = est["claimHeight"].as_i64().unwrap_or(lock_height);
        // the owner: a fresh SLH-DSA key; the token: a fresh holder (P2PKH, Falcon from its height)
        let owner = self.new_pq(1)?;
        self.st.owners.insert(crate::keys::pqkeyid_hex(&owner));
        let token_script = if self.falcon_next() {
            let id = self.new_pq(2)?;
            yew_core::pq::pqpkh_script(&id).unwrap_or_default()
        } else {
            let pk = self.new_wallet_key()?;
            let h = yew_core::keys::hash160(&pk);
            self.st.book.insert(
                yew_core::keys::encode_p2pkh(self.network, &h),
                crate::state::BookEntry {
                    label: String::new(),
                    purpose: "yellowback-vault".into(),
                },
            );
            yew_core::script::p2pkh_script(&h)
        };
        let owner_bytes = owner.to_bytes();
        let payee = match node::call(
            node,
            "yed_getfeepayee",
            serde_json::json!([r, hex::encode(owner_bytes)]),
        )
        .await
        {
            Ok(v) => v["preferred"]
                .as_str()
                .or_else(|| v["default"]["payoutAddress"].as_str())
                .map(str::to_string),
            Err(NodeError::Rpc { message, .. }) if message.contains("fee-no-eligible-payee") => {
                None
            }
            Err(e) => return Err(e.into()),
        };
        let protocol_fee =
            yew_core::params::protocol_fee_zat(pm.cents as u64, p_mint).ok_or_else(|| {
                build_error("mint-unsatisfiable: no protocol fee at this price".into())
            })?;
        let fee_zat = if payee.is_some() { protocol_fee } else { 0 };
        // AFEE-W: the attestor fee of an armed mint (F-S2-4), selector empty
        let attest = self
            .attest_payee(node, r, &[], &pm.facts, protocol_fee)
            .await?;
        let vp =
            yew_core::vault::yed_mint_vault_params(&attestor_set, claim_delay, &owner, r as u32);
        let vault_script = yew_core::vault::build_vault(&vp)
            .ok_or_else(|| build_error("mint-bad-lock: cannot build the vault script".into()))?;
        let fee_vout = if payee.is_some() { 3u8 } else { FEE_VOUT_NONE };
        let pl = payload::encode(&Payload::Mint {
            term_class: class_idx,
            cents: pm.cents as u32,
            lock_height: lock_height as u32,
            ref_height: r as u32,
            owner,
            fee_vout,
            attest_fee_vout: match (&attest, payee.is_some()) {
                (None, _) => FEE_VOUT_NONE,
                (Some(_), true) => 4,
                (Some(_), false) => 3,
            },
        })
        .ok_or_else(|| RpcError::new(code::WALLET_ERROR, "cannot encode the mint payload"))?;
        let mut base = Transaction::new_v4();
        base.expiry_height = (r + ref_window) as u32;
        base.vout.push(TxOut {
            value: collateral,
            script_pubkey: vault_script,
        });
        base.vout.push(TxOut {
            value: TOKEN_VALUE,
            script_pubkey: token_script,
        });
        base.vout.push(TxOut {
            value: 0,
            script_pubkey: payload::payload_script(&pl),
        });
        if let Some(a) = &payee {
            let s = crate::rpc::parse_taddr_script(self.network, a).ok_or_else(|| {
                RpcError::new(
                    code::MISC_ERROR,
                    format!("yewd: the payee {a} is not an address"),
                )
            })?;
            base.vout.push(TxOut {
                value: fee_zat,
                script_pubkey: s,
            });
        }
        if let Some(a) = &attest {
            base.vout.push(TxOut {
                value: a.fee_zat,
                script_pubkey: a.script.clone(),
            });
        }
        let attest_fee = attest.as_ref().map(|a| a.fee_zat).unwrap_or(0);
        let only = from_script(self, &pm.from)?;
        let bundle = hex::decode(&rec.bundle).unwrap_or_default();
        let carrier_ss = 3 + bundle.len() + 74 + 73;
        let z_from = self.is_sapling(&pm.from).then(|| pm.from.clone());
        let pk: [u8; 33] = hex::decode(&rec.pk)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| RpcError::new(code::WALLET_ERROR, "carrier-key-missing"))?;
        let redeem = yew_core::script::carrier_script(&pk, &yew_core::keys::sha256(&bundle))
            .map_err(|e| RpcError::new(code::WALLET_ERROR, e.to_string()))?;
        let carrier_key = KeyRef::Carrier {
            chain: crate::keys::EXTERNAL,
            index: rec.index,
        };
        let carrier_coin = NodeCoin {
            value: CARRIER_VALUE,
            script: yew_core::script::p2sh_of(&redeem),
            height: None,
            coinbase: false,
        };
        // the Sapling shape (§4.6): the notes of `from` fund the outputs; the carrier is the one
        // transparent input (F-S2-8)
        let (signed_hex, funded_from) = if let Some(z) = &z_from {
            let mut tx = base.clone();
            tx.vin.push(TxIn::new(pm.carrier));
            let (h, _) = self
                .z_fund_and_sign(
                    node,
                    &tx,
                    std::slice::from_ref(&carrier_coin),
                    &[carrier_key],
                    CARRIER_VALUE,
                    &[carrier_ss],
                    z,
                    flat,
                    GatePath::Yed,
                    &next,
                    "mint",
                )
                .await?;
            (h, "sapling")
        } else {
            let (tx, coins) = self
                .fund_yed(
                    node,
                    &base,
                    CARRIER_VALUE,
                    flat,
                    only.as_deref(),
                    &[(pm.carrier, carrier_ss)],
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
            prevs.push(carrier_coin.clone());
            let mut keys: Vec<KeyRef> = coins
                .iter()
                .map(|c| self.key_of_script(&c.2).unwrap_or(KeyRef::None))
                .collect();
            keys.push(carrier_key);
            let outflow = collateral
                + TOKEN_VALUE
                + fee_zat
                + attest_fee
                + (prevs.iter().map(|c| c.value).sum::<i64>() - tx.output_total())
                + 1;
            let signed = self
                .sign_inputs(&tx, &prevs, &keys, &[], GatePath::Yed, outflow, next.branch)
                .await?;
            (tx_hex(&signed)?, "transparent")
        };
        // DryRunOrThrow: MINT-1..10 with the bundle, by the node
        let raw = signed_hex.clone();
        let v = node::call(node, "yed_validaterawtransaction", serde_json::json!([raw])).await?;
        let verdict = v["verdict"].as_str().unwrap_or("").to_string();
        if v["type"].as_str() != Some("mint") {
            return Err(build_error("mint-dry-run: the dry run saw no mint".into()));
        }
        if verdict != "ok" {
            return Err(build_error(format!(
                "{verdict}: the wallet's dry run of MINT-1..10 refused this mint at height {}",
                next.height
            )));
        }
        if !v["valid"].as_bool().unwrap_or(false) {
            return Err(RpcError::new(
                code::WALLET_ERROR,
                format!(
                    "yewd: the mint's scripts do not verify: {}",
                    v["invalidReason"].as_str().unwrap_or("")
                ),
            ));
        }
        let txid = self.broadcast_hex(node, &signed_hex).await?;
        self.st.carriers.remove(&op_str(&pm.carrier));
        self.persist_state()?;
        Ok(J::obj()
            .with("txid", txid.clone())
            .with("vault", format!("{txid}:0"))
            .with(
                "ownerAddress",
                yew_core::keys::encode_pq_yellowback(self.network, &owner).unwrap_or_default(),
            )
            .with("termClass", term_class)
            .with("lockHeight", lock_height)
            .with("claimHeight", claim_height)
            .with("collateralZat", collateral)
            .with("feeZat", fee_zat)
            .with("payee", payee.map(J::Str).unwrap_or(J::Null))
            .with("fundedFrom", funded_from)
            .with("warning", "")
            .with("carrierTxid", txid_hex(&pm.carrier.txid))
            .with("pending", false)
            .with("refHeight", r)
            .with("xMint", raw_or_null(&est["xMint"]))
            .with(
                "aMint",
                if pm.facts.armed {
                    crate::armed::opt(pm.facts.a_mint)
                } else {
                    J::Null
                },
            )
            .with("pMint", p_mint)
            .with(
                "source",
                match (pm.facts.armed, pm.facts.a_mint, est["xMint"].as_i64()) {
                    (true, Some(a), Some(x)) => (if a < x { "a" } else { "x" }).to_string(),
                    _ => mint_source(est),
                },
            )
            .with("bundleSeqs", pm.facts.seqs_json())
            .with("attestFeeZat", attest_fee)
            .with(
                "attestPayee",
                attest.map(|a| J::Str(a.address)).unwrap_or(J::Null),
            ))
    }

    /// `yed_sweepcarriers`: every carrier of this wallet whose window lapsed (`R + REF_WINDOW` below
    /// the next height), spent back to the wallet in one transaction.
    async fn yed_sweepcarriers(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        if !p.is_empty() {
            return Err(RpcError::new(code::MISC_ERROR, "yed_sweepcarriers"));
        }
        let info = node::call(node, "yed_getinfo", serde_json::json!([])).await?;
        let ref_window = info["params"]["refWindow"].as_i64().unwrap_or(40);
        let flat = info["params"]["feeZat"].as_i64().unwrap_or(10_000);
        let next = next_block(node).await?;
        let mut lapsed = Vec::new();
        let mut gone = Vec::new();
        for (k, rec) in self.st.carriers.clone() {
            let op = crate::build::outpoint_param(&Value::String(k.clone()), "carrier")?;
            match node_coin(node, &op).await? {
                None => gone.push(k),
                Some(c)
                    if c.height.is_some() && next.height as i64 - ref_window > rec.ref_height =>
                {
                    lapsed.push((op, rec))
                }
                _ => {}
            }
        }
        for k in gone {
            self.st.carriers.remove(&k);
        }
        if lapsed.is_empty() {
            self.persist_state()?;
            return Ok(J::obj()
                .with("txid", "")
                .with("count", 0i64)
                .with("reclaimedZat", 0i64)
                .with("outstanding", self.st.carriers.len() as i64));
        }
        self.ensure_unlocked()?;
        let mut tx = Transaction::new_v4();
        tx.expiry_height = next.height + crate::build::TX_EXPIRY_DELTA;
        let mut prevs = Vec::new();
        let mut keys = Vec::new();
        let mut sizes = Vec::new();
        for (op, rec) in &lapsed {
            tx.vin.push(TxIn::new(*op));
            let pk: [u8; 33] = hex::decode(&rec.pk)
                .ok()
                .and_then(|b| b.try_into().ok())
                .unwrap_or([0; 33]);
            let bundle = hex::decode(&rec.bundle).unwrap_or_default();
            let redeem = yew_core::script::carrier_script(&pk, &yew_core::keys::sha256(&bundle))
                .map_err(|e| RpcError::new(code::WALLET_ERROR, e.to_string()))?;
            // P-2: the scriptSig with its signature at the maximum DER size and hashtype
            sizes.push(
                yew_core::script::carrier_script_sig(&bundle, &[0u8; 73], &redeem)
                    .map(|x| x.len())
                    .unwrap_or(0),
            );
            prevs.push(NodeCoin {
                value: CARRIER_VALUE,
                script: yew_core::script::p2sh_of(&redeem),
                height: None,
                coinbase: false,
            });
            keys.push(KeyRef::Carrier {
                chain: crate::keys::EXTERNAL,
                index: rec.index,
            });
        }
        let total = lapsed.len() as i64 * CARRIER_VALUE;
        let dest = self.new_change()?;
        tx.vout.push(TxOut {
            value: 0,
            script_pubkey: dest,
        });
        // NetworkFee: max(the flat fee, the ZIP-317 conventional fee of the shape)
        let fee = flat
            .max(tx.zip317_conventional_fee(&sizes).unwrap_or(flat))
            .min(total - 1);
        tx.vout[0].value = total - fee;
        let signed = self
            .sign_inputs(&tx, &prevs, &keys, &[], GatePath::Yed, fee + 1, next.branch)
            .await?;
        let txid = self.broadcast(node, &signed, None).await?;
        for (op, _) in &lapsed {
            self.st.carriers.remove(&op_str(op));
        }
        self.persist_state()?;
        Ok(J::obj()
            .with("txid", txid)
            .with("count", lapsed.len() as i64)
            .with("reclaimedZat", total - fee)
            .with("outstanding", self.st.carriers.len() as i64))
    }
}

fn raw_or_null(v: &Value) -> J {
    if v.is_null() {
        J::Null
    } else {
        J::Raw(v.to_string())
    }
}

/// The least plain YEC a mint funded from ECC coins needs before its carrier is broadcast: the
/// collateral and one flat fee (the carrier's). A lower bound: the carrier's value returns as a
/// MINT input, the MINT's own fees come on top, so a mint this refuses could never complete and
/// one it admits is still checked in full when the MINT is built.
pub(crate) fn mint_funds_floor(collateral: i64, flat: i64) -> i64 {
    collateral.saturating_add(flat)
}

#[cfg(test)]
mod tests {
    /// YEW-REAL finding 5: the floor is the collateral plus the carrier's flat fee.
    #[test]
    fn mint_funds_floor_is_collateral_plus_the_carrier_fee() {
        assert_eq!(super::mint_funds_floor(600_000_000, 10_000), 600_010_000);
        assert_eq!(super::mint_funds_floor(i64::MAX, 10_000), i64::MAX);
    }
    #[test]
    fn mint10_divergence() {
        // 500 bps: 0.50 vs 0.525 is exactly 500 bps of the lower, not diverged; one more is
        assert!(!super::mint10_diverged(500_000, 525_000, 500));
        assert!(super::mint10_diverged(500_000, 525_001, 500));
        assert!(super::mint10_diverged(1_000_000, 2_000_000, 500));
        assert!(!super::mint10_diverged(1_000_000, 1_000_000, 0));
    }
}
