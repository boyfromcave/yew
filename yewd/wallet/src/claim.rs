// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! `yed_claim` and `yed_claimnotice` (R6; ycash6 `src/rpc/yellowbackwallet.cpp` `yed_claim`,
//! `CompleteClaim`, `yed_claimnotice`; `src/yellowback/txbuilder.cpp` `PreflightClaim`,
//! `BuildClaim`, `ClaimAt`, `BuildVaultSpend`'s claim branch): the claim of another wallet's
//! underwater vault in the v3 two-step flow (carrier first, the CLAIM on the confirmed carrier).
//!
//! The claim facts at `R` (the index tip at preflight: `claimable`, `claimPath`, `residualZat`,
//! `pClaim`) are the node's `yed_listclaimable` row for the vault; the CLAIM's shape is yew-core's
//! `build::claim::plan_claim` (the node's `PlanVaultSpend` claim branch, verbatim); the node
//! dry-runs RED-1..5 (`yed_validaterawtransaction`) before it is committed.

use serde_json::Value;
use yew_core::coinselect;
use yew_core::params::{CARRIER_VALUE, MAX_INPUTS, MIN_OUTPUT_CENTS, TOKEN_VALUE};
use yew_core::tx::{OutPoint, Transaction};
use yewd_proto::{GatePath, KeyRef};

use crate::build::{next_block, node_coin, op_str, tx_hex, NodeCoin};
use crate::json::J;
use crate::mint::{build_error, PendingMint};
use crate::node::{self, Node};
use crate::rpc::invalid;
use crate::{code, txid_hex, RpcError, Wallet};

pub const SERVED: &[&str] = &["yed_claim", "yed_claimnotice"];

/// A claim's arguments, kept with its carrier until the CLAIM is built.
#[derive(Clone, Debug)]
pub struct ClaimArgs {
    pub vault_txid: String,
    pub to: String,
    pub min_out: i64,
    pub max_burn: i64,
    /// The `yed_listclaimable` row at `R`.
    pub row: Value,
}

fn selector_hex(op: &OutPoint) -> String {
    let mut s = op.txid.to_vec();
    s.extend_from_slice(&op.n.to_le_bytes());
    hex::encode(s)
}

impl Wallet {
    pub async fn claim_call(&mut self, node: &dyn Node, method: &str, p: &[Value]) -> Result<J, RpcError> {
        match method {
            "yed_claim" => self.yed_claim(node, p).await,
            "yed_claimnotice" => self.yed_claimnotice(node, p).await,
            _ => Err(RpcError::new(code::METHOD_NOT_FOUND, "Method not found")),
        }
    }

    /// The `yed_listclaimable` row of `vault` (`txid:0`).
    async fn claimable_row(node: &dyn Node, vault: &str) -> Result<Option<Value>, RpcError> {
        let rows = node::call(node, "yed_listclaimable", serde_json::json!([])).await?;
        Ok(rows.as_array().and_then(|a| a.iter().find(|r| r["vault"].as_str() == Some(vault)).cloned()))
    }

    /// `yed_claim "vaultTxid" ( "to" "bundleHex" wait minOutZat maxBurnCents )`.
    async fn yed_claim(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        if p.is_empty() || p.len() > 6 {
            return Err(RpcError::new(code::MISC_ERROR, "yed_claim \"vaultTxid\" ( \"to\" \"bundleHex\" wait minOutZat maxBurnCents )"));
        }
        let txid_s = p[0].as_str().unwrap_or("").to_lowercase();
        let txid = yew_core::tx::txid_from_hex(&txid_s).map_err(|_| invalid("vaultTxid must be hexadecimal string of length 64"))?;
        let op = OutPoint { txid, n: 0 };
        let to = p.get(1).and_then(|v| v.as_str()).unwrap_or("").to_string();
        let bundle_arg = p.get(2).and_then(|v| v.as_str()).unwrap_or("").to_string();
        let wait = p.get(3).and_then(|v| v.as_bool()).unwrap_or(true);
        let bound = |i: usize, name: &str| -> Result<i64, RpcError> {
            match p.get(i) {
                None | Some(Value::Null) => Ok(0),
                Some(v) => v.as_i64().filter(|n| *n >= 0).ok_or_else(|| invalid(format!("{name} must be a non-negative number"))),
            }
        };
        let min_out = bound(4, "minOutZat")?;
        let max_burn = bound(5, "maxBurnCents")?;
        if let Some(sp) = Self::mempool_spender(node, &op).await? {
            return Err(RpcError::new(code::WALLET_ERROR, format!("vault-spend-pending: the vault {txid_s}:0 already has a spend in the mempool ({sp}); wait for it to confirm or expire")));
        }
        // PreflightClaim
        let v = Self::yed_vault(node, &txid_s).await?;
        let status = v["status"].as_str().unwrap_or("").to_string();
        if status != "ACTIVE" {
            return Err(build_error(format!("vault-not-active: the vault is {status}")));
        }
        let info = crate::yed::yed_info(node).await?;
        let r = info.index_height;
        let script = hex::decode(v["scriptPubKey"].as_str().unwrap_or("")).unwrap_or_default();
        let vp = yew_core::vault::parse_vault(&script).ok_or_else(|| build_error("vault-not-found: cannot reconstruct the vault script".into()))?;
        if r < vp.app_height {
            return Err(build_error(format!("claim-not-yet: the claim path opens at height {} (tip {r})", vp.app_height)));
        }
        let vault = format!("{txid_s}:0");
        let row = Self::claimable_row(node, &vault).await?.unwrap_or(Value::Null);
        if row["claimable"].as_bool() != Some(true) {
            let pc = row["pClaim"].as_i64().map(|x| x.to_string()).unwrap_or_else(|| "undefined".into());
            return Err(build_error(format!(
                "claim-not-underwater: the vault is not underwater at the reference height {r} by either clause (pClaim {pc}, pEmerg undefined, notice none)"
            )));
        }
        let minted = v["mintedCents"].as_i64().unwrap_or(0);
        if max_burn > 0 && minted > max_burn {
            return Err(RpcError::new(code::WALLET_ERROR, format!("claim-burn-above-max: the claim would burn {minted} cents of YED, above the maxBurnCents of {max_burn}")));
        }
        let residual = row["residualZat"].as_i64().unwrap_or(0);
        let collateral = v["collateralZat"].as_i64().unwrap_or(0);
        if min_out > 0 && collateral - residual < min_out {
            return Err(RpcError::new(code::WALLET_ERROR, format!("claim-out-below-min: the claim would pay {} zat to the destination, below the minOutZat of {min_out}", collateral - residual)));
        }
        let armed = node::call(node, "yed_getprice", serde_json::json!([r])).await.ok().and_then(|x| x["armed"].as_bool()).unwrap_or(false);
        let selector = selector_hex(&op);
        let bundle = if !bundle_arg.is_empty() {
            hex::decode(&bundle_arg).map_err(|_| build_error("bundle-malformed: bundleHex is not hex".into()))?
        } else if armed {
            let b = node::call(node, "yed_buildbundle", serde_json::json!([r, selector])).await.map_err(|e| match e {
                crate::node::NodeError::Rpc { message, .. } => build_error(message),
                other => other.into(),
            })?;
            hex::decode(b["hex"].as_str().unwrap_or("")).unwrap_or_default()
        } else {
            Vec::new()
        };
        if armed && row["attestFeeZat"].as_i64().unwrap_or(0) > 0 {
            return Err(RpcError::new(code::WALLET_ERROR, "yewd: an armed claim's attestor fee payee (AFEE-W) is not served yet; finding F-S2-4"));
        }
        let carrier = self.build_carrier(node, &bundle, r, &selector, None).await?;
        let args = ClaimArgs { vault_txid: txid_s.clone(), to: to.clone(), min_out, max_burn, row: row.clone() };
        let pending = PendingMint { claim: Some(args.clone()), carrier, cents: minted, lock_blocks: 0, from: String::new(), max_collateral: 0, est: Value::Null };
        if !wait {
            self.pending.push(pending);
            return Ok(J::obj()
                .with("txid", "")
                .with("burnedCents", 0i64)
                .with("feeZat", 0i64)
                .with("payee", J::Null)
                .with("collateralOut", 0i64)
                .with("to", to)
                .with("extraBurnCents", 0i64)
                .with("carrierTxid", txid_hex(&carrier.txid))
                .with("pending", true)
                .with("refHeight", r)
                .with("xClaim", raw(&row["pClaim"]))
                .with("aClaim", J::Null)
                .with("pClaim", raw(&row["pClaim"]))
                .with("pEmerg", J::Null)
                .with("claimPath", row["claimPath"].as_str().unwrap_or("").to_string())
                .with("bundleSeqs", J::Arr(vec![]))
                .with("attestFeeZat", 0i64)
                .with("attestPayee", J::Null)
                .with("residualZat", residual));
        }
        self.wait_carrier(node, &carrier).await?;
        self.complete_claim(node, &args, &pending).await
    }

    /// `CompleteClaim` / `BuildClaim` on a confirmed carrier.
    pub(crate) async fn complete_claim(&mut self, node: &dyn Node, a: &ClaimArgs, pm: &PendingMint) -> Result<J, RpcError> {
        let txid = yew_core::tx::txid_from_hex(&a.vault_txid).map_err(|e| RpcError::new(code::MISC_ERROR, e))?;
        let op = OutPoint { txid, n: 0 };
        if let Some(sp) = Self::mempool_spender(node, &op).await? {
            return Err(RpcError::new(code::WALLET_ERROR, format!("vault-spend-pending: the vault {}:0 already has a spend in the mempool ({sp}); wait for it to confirm or expire", a.vault_txid)));
        }
        let v = Self::yed_vault(node, &a.vault_txid).await?;
        if v["status"].as_str() != Some("ACTIVE") {
            return Err(build_error(format!("vault-not-active: the vault is {}", v["status"].as_str().unwrap_or(""))));
        }
        let info = crate::yed::yed_info(node).await?;
        let next = next_block(node).await?;
        let rec = self.st.carriers.get(&op_str(&pm.carrier)).cloned().ok_or_else(|| RpcError::new(code::WALLET_ERROR, "carrier-key-missing: the carrier is not this wallet's"))?;
        match node_coin(node, &pm.carrier).await? {
            Some(c) if c.height.is_some() => {}
            _ => return Err(build_error(format!("carrier-unconfirmed: the carrier {} is not a confirmed unspent output", op_str(&pm.carrier)))),
        }
        let r = rec.ref_height;
        if next.height as i64 - info.ref_window > r {
            return Err(build_error(format!("carrier-lapsed: the carrier's reference height {r} is outside the window at height {}; yed_sweepcarriers reclaims it", next.height)));
        }
        if rec.selector != selector_hex(&op) {
            return Err(build_error("carrier-selector: the carrier was built for another selector".into()));
        }
        let script = hex::decode(v["scriptPubKey"].as_str().unwrap_or("")).unwrap_or_default();
        let vp = yew_core::vault::parse_vault(&script).ok_or_else(|| build_error("vault-not-found: cannot reconstruct the vault script".into()))?;
        let minted = v["mintedCents"].as_i64().unwrap_or(0);
        let collateral = v["collateralZat"].as_i64().unwrap_or(0);
        // the YED burned: the debt, a sub-dollar remainder burned with it (H4)
        let coins = self.ranked_coins(node).await?;
        let cents: Vec<i64> = coins.iter().map(|c| c.cents).collect();
        let have: i64 = cents.iter().sum();
        let s = coinselect::select_floor_aware(&cents, minted, MIN_OUTPUT_CENTS as i64, MAX_INPUTS, true);
        if !s.ok {
            if s.insufficient {
                return Err(build_error(format!("insufficient-yed: need {minted} cents, have {have} confirmed and spendable")));
            }
            return Err(build_error(format!("too-many-inputs: more than {MAX_INPUTS} YED inputs would be needed; consolidate first")));
        }
        let mut sel: Vec<_> = s.inputs.iter().map(|&i| coins[i].clone()).collect();
        // CAN-1: a plain holder script first (the cancel refunds the burn to the lowest-index YED input's holder)
        sel.sort_by_key(|c| !(c.script.len() == 25 || c.script.len() == 35));
        if a.max_burn > 0 && minted + s.extra_burn > a.max_burn {
            return Err(RpcError::new(code::WALLET_ERROR, format!("claim-burn-above-max: the claim would burn {} cents of YED, above the maxBurnCents of {}", minted + s.extra_burn, a.max_burn)));
        }
        let change_script = if s.change > 0 { self.fresh_holder()? } else { Vec::new() };
        let payee = Self::spend_payee(node, r, &op).await?;
        let fee_zat = match &payee {
            Some(py) => yew_core::build::terms::protocol_fee(minted as u64, v["pMint"].as_i64().unwrap_or(0), py).map_err(|e| build_error(e.to_string()))?,
            None => 0,
        };
        let payee_script = match &payee {
            Some(x) => Some(crate::rpc::parse_taddr_script(self.network, x).ok_or_else(|| build_error(format!("the payee {x} is not an address")))?),
            None => None,
        };
        let claimant_script = if a.to.is_empty() {
            let pk = self.new_wallet_key()?;
            yew_core::script::p2pkh_script(&yew_core::keys::hash160(&pk))
        } else {
            crate::rpc::parse_taddr_script(self.network, &a.to)
                .filter(|sc| yew_core::script::p2pkh_hash(sc).is_some())
                .ok_or_else(|| build_error("bad-address: a claim pays an intent, whose recipient is a transparent script; pass a transparent address".into()))?
        };
        let owner = yew_core::pq::PqKeyId {
            scheme: v["ownerScheme"].as_u64().unwrap_or(0) as u8,
            hash: hex::decode(v["ownerHash"].as_str().unwrap_or("")).ok().and_then(|b| b.try_into().ok()).unwrap_or([0; 32]),
        };
        let residual = a.row["residualZat"].as_i64().unwrap_or(0);
        let utxo = |c: &crate::yed::YedCoin| yew_core::coins::Utxo {
            outpoint: c.outpoint,
            address: String::new(),
            script: c.script.clone(),
            value: c.value,
            height: 0,
            class: yew_core::coins::UtxoClass::Token,
            cents: c.cents as u64,
        };
        let yed_inputs: Vec<yew_core::coins::Utxo> = sel.iter().map(utxo).collect();
        let yed_value: i64 = sel.iter().map(|c| c.value).sum();
        let yed_scripts: Vec<Vec<u8>> = sel.iter().map(|c| c.script.clone()).collect();
        let funding_change_script = self.new_change()?;
        let mut network_fee = {
            let sc: Vec<&[u8]> = yed_scripts.iter().map(|s| s.as_slice()).collect();
            info.network_fee(&sc)
        };
        let expiry = (r + info.ref_window) as u32;
        let bundle = hex::decode(&rec.bundle).unwrap_or_default();
        let pk: [u8; 33] = hex::decode(&rec.pk).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| RpcError::new(code::WALLET_ERROR, "carrier-key-missing"))?;
        let redeem = yew_core::script::carrier_script(&pk, &yew_core::keys::sha256(&bundle)).map_err(|e| RpcError::new(code::WALLET_ERROR, e.to_string()))?;
        let mut last_err = None;
        for _pass in 0..6 {
            let needed = network_fee + fee_zat + if s.change > 0 { TOKEN_VALUE } else { 0 } - CARRIER_VALUE - yed_value;
            let (funding, fee_after) = self.pick_yec(node, needed.max(0), &info, &yed_scripts, network_fee).await?;
            network_fee = network_fee.max(fee_after);
            let shape = yew_core::build::claim::ClaimShape {
                vault_out: op,
                vault: vp.clone(),
                vault_script: script.clone(),
                vault_value: collateral,
                ref_height: r as u32,
                yed_inputs: yed_inputs.clone(),
                change_cents: s.change as u64,
                change_script: change_script.clone(),
                payee_script: payee_script.clone(),
                fee_zat,
                attest_script: None,
                attest_fee_zat: 0,
                residual_zat: residual,
                owner_script: yew_core::pq::pqpkh_script(&owner).unwrap_or_default(),
                claimant_script: claimant_script.clone(),
                funding: funding
                    .iter()
                    .map(|f| yew_core::coins::Utxo {
                        outpoint: f.0,
                        address: String::new(),
                        script: f.2.clone(),
                        value: f.1,
                        height: 0,
                        class: yew_core::coins::UtxoClass::Yec,
                        cents: 0,
                    })
                    .collect(),
                funding_change_script: funding_change_script.clone(),
                carrier: pm.carrier,
                network_fee,
            };
            let plan = match yew_core::build::claim::plan_claim(&shape) {
                Ok(p) => p,
                Err(e) => {
                    let m = e.to_string();
                    if m.starts_with("insufficient-yec") {
                        network_fee += 1_000;
                        last_err = Some(m);
                        continue;
                    }
                    return Err(build_error(m));
                }
            };
            let mut tx = Transaction::new_v4();
            tx.lock_time = plan.lock_time;
            tx.expiry_height = expiry;
            tx.vin = plan.vin.clone();
            tx.vout = plan.vout.clone();
            let mut prevs = vec![NodeCoin { value: collateral, script: script.clone(), height: None, coinbase: false }];
            prevs.extend(sel.iter().map(|c| NodeCoin { value: c.value, script: c.script.clone(), height: None, coinbase: false }));
            prevs.extend(funding.iter().map(|f| NodeCoin { value: f.1, script: f.2.clone(), height: None, coinbase: false }));
            prevs.push(NodeCoin { value: CARRIER_VALUE, script: yew_core::script::p2sh_of(&redeem), height: None, coinbase: false });
            let mut keys = vec![KeyRef::None];
            keys.extend(sel.iter().map(|c| self.key_of_script(&c.script).unwrap_or(KeyRef::None)));
            keys.extend(funding.iter().map(|f| self.key_of_script(&f.2).unwrap_or(KeyRef::None)));
            keys.push(KeyRef::Carrier { chain: crate::keys::EXTERNAL, index: rec.index });
            let cap = yed_value + funding.iter().map(|f| f.1).sum::<i64>() + CARRIER_VALUE + 1;
            let signed = self.sign_inputs(&tx, &prevs, &keys, &[], GatePath::Yed, cap, next.branch).await?;
            // P-2: never below the ZIP-317 conventional fee of the signed shape
            let sizes: Vec<usize> = signed.vin.iter().map(|i| i.script_sig.len()).collect();
            let conventional = signed.zip317_conventional_fee(&sizes).unwrap_or(0);
            let paid: i64 = prevs.iter().map(|p| p.value).sum::<i64>() - signed.output_total();
            if conventional > paid {
                network_fee = network_fee.max(conventional);
                continue;
            }
            // DryRunOrThrow (RED-1..5) and MP-1
            let hexs = tx_hex(&signed)?;
            let val = node::call(node, "yed_validaterawtransaction", serde_json::json!([hexs])).await?;
            if val["type"].as_str() != Some("redeem") {
                return Err(build_error("vault-spend-malformed: the dry run saw no vault spend".into()));
            }
            let verdict = val["verdict"].as_str().unwrap_or("").to_string();
            if verdict != "ok" {
                return Err(build_error(format!("{verdict}: the wallet's dry run of RED-1..5 refused this spend at height {}", next.height)));
            }
            if val["wouldBeRejected"].as_bool() == Some(true) {
                return Err(RpcError::new(code::TRANSACTION_REJECTED, format!("mempool-check-failed:{verdict}: an enforcing miner would refuse this vault spend (MP-1)")));
            }
            if a.min_out > 0 && plan.claimant_value < a.min_out {
                return Err(RpcError::new(code::WALLET_ERROR, format!("claim-out-below-min: the claim would pay {} zat to the destination, below the minOutZat of {}", plan.claimant_value, a.min_out)));
            }
            let txid = self.broadcast(node, &signed, None).await?;
            self.st.carriers.remove(&op_str(&pm.carrier));
            self.persist_state()?;
            let to_text = crate::keys::script_address(self.network, &claimant_script).unwrap_or_default();
            return Ok(J::obj()
                .with("txid", txid)
                .with("burnedCents", (plan.burn_cents - s.extra_burn).max(0))
                .with("feeZat", fee_zat)
                .with("earlyRedeemFeeZat", 0i64)
                .with("payee", payee.map(J::Str).unwrap_or(J::Null))
                .with("collateralOut", plan.claimant_value)
                .with("to", to_text)
                .with("extraBurnCents", s.extra_burn)
                .with("carrierTxid", txid_hex(&pm.carrier.txid))
                .with("pending", false)
                .with("refHeight", r)
                .with("xClaim", raw(&a.row["pClaim"]))
                .with("aClaim", J::Null)
                .with("pClaim", raw(&a.row["pClaim"]))
                .with("pEmerg", J::Null)
                .with("claimPath", a.row["claimPath"].as_str().unwrap_or("").to_string())
                .with("bundleSeqs", J::Arr(vec![]))
                .with("attestFeeZat", 0i64)
                .with("attestPayee", J::Null)
                .with("residualZat", residual));
        }
        Err(build_error(last_err.unwrap_or_else(|| "the fee did not converge".into())))
    }

    /// `yed_claimnotice "vaultTxid" ( "bundleHex" wait )`: NOT-1's preconditions; a notice is
    /// meaningful only while armed (`notice-not-underwater` otherwise, as ycashd). The armed notice
    /// itself needs the bundle statistics (`pEmerg`), finding F-S2-4.
    async fn yed_claimnotice(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        if p.is_empty() || p.len() > 3 {
            return Err(RpcError::new(code::MISC_ERROR, "yed_claimnotice \"vaultTxid\" ( \"bundleHex\" wait )"));
        }
        let txid_s = p[0].as_str().unwrap_or("").to_lowercase();
        yew_core::tx::txid_from_hex(&txid_s).map_err(|_| invalid("vaultTxid must be hexadecimal string of length 64"))?;
        let v = Self::yed_vault(node, &txid_s).await?;
        if v["status"].as_str() != Some("ACTIVE") {
            return Err(build_error(format!("vault-not-active: the vault is {}", v["status"].as_str().unwrap_or(""))));
        }
        let info = crate::yed::yed_info(node).await?;
        let r = info.index_height;
        let armed = node::call(node, "yed_getprice", serde_json::json!([r])).await.ok().and_then(|x| x["armed"].as_bool()).unwrap_or(false);
        if !armed {
            return Err(build_error(format!("notice-not-underwater: the snapshot at {r} is not armed; a notice is meaningless before arming")));
        }
        Err(RpcError::new(code::WALLET_ERROR, "yewd: an armed claim notice (NOT-1 at pEmerg) is not served yet; finding F-S2-4"))
    }
}

fn raw(v: &Value) -> J {
    if v.is_null() {
        J::Null
    } else {
        J::Raw(v.to_string())
    }
}
