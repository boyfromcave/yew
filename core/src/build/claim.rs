// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The two-step CLAIM of another wallet's vault (plan §4 rule 6, §5.3 "Claimable"; v3 spec
//! §3.5 "CLAIM"): the vault must be in `ListClaimable`; `R` = the index tip; the bundle is
//! `BuildBundle(R, outpointSelector(vault))`, verified against `ListAttestors` (rule 6); the
//! carrier step is the mint's (`build::mint::carrier_step`); after one confirmation the CLAIM
//! spends the vault at `vin[0]` with `OP_0 <vaultScript>` and `nLockTime = claimHeight`, own
//! YED inputs covering `mintedCents` (BURN stage allowed), the carrier at `vin[last]`, and
//! outputs collateral → fee → YED change → attestor fee → residual to the owner (RED-5) →
//! payload, in the node's slot order.
//!
//! Translation source (plan §3.6): `ycash-dd/src/yellowback/txbuilder.cpp` — `BuildClaim`
//! `:1301-1330`, `ClaimAt` `:845-884` (the residual; the client takes `residualZat`,
//! `claimPath`, `feeZat` and `attestFeeZat` from `ListClaimable`, which the node computes at
//! its tip with the same bundle its pool builds), `BuildVaultSpend` `:573-716` with
//! `ClaimExtras`, `SignVaultSpend` `:136-162` (the claim scriptSig `:152`, the carrier
//! `:159`); the Python reference `armed_raw_claim` (`yellowback_attest.py:1187-1205`).

use crate::bundle;
use crate::coins::{self, Utxo, UtxoClass};
use crate::gate::{self, Validator};
use crate::keys::{self, unhex};
use crate::net::{CompactClient, YellowbackClient};
use crate::params::{Network, CARRIER_VALUE, FEE_ZAT, SEQUENCE_LOCKTIME, TOKEN_VALUE};
use crate::payload::{self, Assignment, Payload, FEE_VOUT_NONE};
use crate::script;
use crate::store::{HistoryRow, IntentRow, IntentState, MintKind, MintRow, MintState};
use crate::tx::{txid_hex, OutPoint, Transaction, TxIn, TxOut};
use crate::wallet::{dollars, Wallet, WalletError};

use super::mint::{self, Finished, MintError};
use super::redeem;
use super::terms;
use super::yec_send::MIN_CHANGE;

/// One entry of `ListClaimable` as the Claimable screen shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claimable {
    /// The vault's mint txid (display form).
    pub vault_txid: String,
    /// The vault's owner (`ye…`).
    pub owner_address: String,
    /// The debt to burn, cents.
    pub minted_cents: u64,
    /// The collateral, zat.
    pub collateral_zat: i64,
    /// `claimHeight`.
    pub claim_height: u32,
    /// `"a"` (underwater at `pClaim`) or `"b"` (notice + emergency price).
    pub claim_path: String,
    /// `pClaim` at the node's tip.
    pub p_claim: i64,
    /// The enforcement fee.
    pub fee_zat: i64,
    /// The attestor fee.
    pub attest_fee_zat: i64,
    /// RED-5's residual to the owner.
    pub residual_zat: i64,
    /// What the claimant keeps: collateral − fees − residual − network fee (+ the carrier).
    pub claimant_zat: i64,
    /// The enforcement fee payee for `(R, vault)` (`s…`), empty under FEE-0 (audit G-2).
    pub payee: String,
}

/// `claimable` (plan §3.4): `ListClaimable` mapped for the screen. The fee is FEE-1 computed
/// locally and the attestor fee AFEE-1 (audit G-2): a server quoting another figure is
/// refused; the payee comes from `GetFeePayee` for the vault's selector at the index tip. The
/// residual is RED-5 recomputed from the row's `pClaim` (`terms::check_claimable`, H-9.3),
/// and the server's parameter set must be the network's (`terms::check_server_params`).
pub async fn claimable(
    network: Network,
    yb: &mut YellowbackClient,
) -> Result<Vec<Claimable>, WalletError> {
    let info = yb.info().await?;
    terms::check_server_params(network, info.params.as_ref())?;
    let r = info.height as u32;
    let mut out = Vec::new();
    for c in yb.list_claimable().await? {
        let vault_txid = c.vault.split(':').next().unwrap_or("").to_string();
        let txid = crate::tx::txid_from_hex(&vault_txid)
            .map_err(|e| MintError::Relay(format!("claimable vault {:?}: {e}", c.vault)))?;
        let vout: u32 = c
            .vault
            .split(':')
            .nth(1)
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let selector = bundle::outpoint_selector(&txid, vout);
        let residual_zat = terms::check_claimable(&c)?;
        let (fee_zat, payee) = mint::fee_payee(network, yb, r, c.collateral_zat, &selector).await?;
        if !payee.is_empty() && c.fee_zat != fee_zat {
            return Err(MintError::Inconsistent {
                what: format!(
                    "ListClaimable feeZat {} for collateral {} (FEE-1 gives {fee_zat})",
                    c.fee_zat, c.collateral_zat
                ),
            }
            .into());
        }
        let attest_fee_zat = if c.attest_fee_zat == 0 {
            0
        } else {
            let local = crate::params::attest_fee_zat_for(network, fee_zat);
            if c.attest_fee_zat != local {
                return Err(MintError::Inconsistent {
                    what: format!(
                        "ListClaimable attestFeeZat {} (AFEE-1 gives {local})",
                        c.attest_fee_zat
                    ),
                }
                .into());
            }
            local
        };
        out.push(Claimable {
            vault_txid,
            owner_address: c.owner_address,
            minted_cents: c.minted_cents.max(0) as u64,
            collateral_zat: c.collateral_zat,
            claim_height: c.claim_height as u32,
            claim_path: c.claim_path,
            p_claim: c.p_claim,
            fee_zat,
            attest_fee_zat,
            residual_zat,
            claimant_zat: terms::claimant_take(
                c.collateral_zat,
                fee_zat,
                attest_fee_zat,
                residual_zat,
            ),
            payee,
        });
    }
    Ok(out)
}

/// `claim` (plan §3.4; `BuildClaim`'s preflight and carrier step): start the two-step claim
/// of `vault_txid`. Returns the `mints` row id; `mint_finish(id)` sends the CLAIM once the
/// carrier is confirmed. With `bounds` (what the Claimable screen showed), the debt to burn
/// and the YEC the claimant takes are checked against them before the carrier is funded, and
/// again before the CLAIM is signed (`yed_claim`'s `maxBurnCents` / `minOutZat`, H-9.3).
pub async fn start(
    wallet: &Wallet,
    client: &mut CompactClient,
    validator: &mut Validator,
    vault_txid: &[u8; 32],
    bounds: Option<&terms::ClaimBounds>,
    tip: u64,
    branch_id: u32,
) -> Result<i64, WalletError> {
    let yb = validator
        .client_mut()
        .ok_or(gate::GateError::YellowbackAbsent)?;
    let txid_str = txid_hex(vault_txid);
    let entry = claimable(wallet.network, yb)
        .await?
        .into_iter()
        .find(|c| c.vault_txid == txid_str)
        .ok_or_else(|| {
            WalletError::Other(format!(
                "claim-not-underwater: vault {txid_str} is not in ListClaimable"
            ))
        })?;
    let v = yb.vault(&txid_str).await?;
    if v.status != "ACTIVE" {
        return Err(WalletError::Other(format!(
            "vault-not-active: the vault is {}",
            v.status
        )));
    }
    // The vault's script terms and debt, as the node reports them, checked (audit G-1); its V
    // script must be the YED vault this wallet rebuilds (U-23) — the one the claim spends.
    terms::check_vault(wallet.network, &v)?;
    let vt = mint::vault_terms_now(wallet, yb).await?;
    terms::check_vault_script(&vt, &v)?;
    if v.minted_cents.max(0) as u64 != entry.minted_cents
        || v.collateral_zat != entry.collateral_zat
    {
        return Err(MintError::Inconsistent {
            what: format!(
                "GetVault ({} cents, {} zat) disagrees with ListClaimable ({} cents, {} zat)",
                v.minted_cents, v.collateral_zat, entry.minted_cents, entry.collateral_zat
            ),
        }
        .into());
    }
    let info = yb.info().await?;
    let r = info.height as u32;
    if tip < v.claim_height as u64 || (r as u64) < v.claim_height as u64 {
        return Err(WalletError::Other(format!(
            "claim-not-yet: the claim path opens at height {} (tip {tip}, index {r})",
            v.claim_height
        )));
    }
    let owner_pubkey: [u8; 33] = unhex(&v.owner_pub_key)
        .ok()
        .and_then(|b| b.as_slice().try_into().ok())
        .ok_or_else(|| MintError::Relay("vault ownerPubKey".into()))?;
    // The YED to burn must be there before the carrier is funded, and (U-23: the vault's value
    // goes into intents) the YEC for the carrier and for the claim's fees.
    let (yed, change_cents, _, _) = redeem::select_yed_burn(wallet, entry.minted_cents)?;
    let yed_value: i64 = yed.iter().map(|u| u.value).sum();
    let fees_needed = claim_funding_needed(
        if entry.payee.is_empty() {
            0
        } else {
            entry.fee_zat
        },
        entry.attest_fee_zat,
        change_cents > 0,
        yed_value,
    )
    .max(0);
    coins::select_yec(
        &wallet.spendable_utxos()?,
        CARRIER_VALUE + FEE_ZAT + fees_needed,
        true,
    )?;
    let selector = bundle::outpoint_selector(vault_txid, v.vout);
    let b = yb.build_bundle(r, &keys::hex(&selector)).await?;
    let bundle_bytes = unhex(&b.hex).map_err(|e| MintError::Relay(format!("bundle hex: {e}")))?;
    let seqs = mint::verify_bundle(client, yb, &bundle_bytes).await?;
    // FEE-1 locally (audit G-2); the payee must be the one the Claimable screen showed.
    let (fee_zat, payee) =
        mint::fee_payee(wallet.network, yb, r, v.collateral_zat, &selector).await?;
    if payee != entry.payee {
        return Err(MintError::TermsChanged {
            what: "fee payee",
            was: entry.payee.clone(),
            now: payee,
        }
        .into());
    }
    let (attest_payee, attest_fee_zat) =
        mint::attest_payee(wallet.network, client, yb, r, &selector, &seqs, fee_zat).await?;
    // H-9.3: the numbers about to be committed against what the user confirmed.
    if let Some(b) = bounds {
        terms::check_claim_bounds(
            b,
            entry.minted_cents,
            terms::claimant_take(
                v.collateral_zat,
                fee_zat,
                attest_fee_zat,
                entry.residual_zat,
            ),
        )?;
    }
    let step =
        mint::carrier_step(wallet, client, validator, &bundle_bytes, r, tip, branch_id).await?;
    let row = MintRow {
        id: 0,
        kind: MintKind::Claim,
        state: MintState::CarrierSent,
        created_height: tip,
        cents: entry.minted_cents,
        lock_blocks: 0,
        term_class: v.term_class,
        ref_height: r,
        lock_height: v.lock_height as u32,
        claim_height: v.claim_height as u32,
        collateral_zat: v.collateral_zat,
        fee_zat,
        payee,
        attest_fee_zat,
        attest_payee,
        residual_zat: entry.residual_zat,
        bundle: bundle_bytes,
        bundle_seqs: seqs
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join(","),
        carrier_hash160: step.carrier_hash160,
        owner_hash160: keys::hash160(&owner_pubkey),
        carrier_txid: step.txid,
        carrier_vout: 0,
        main_txid: [0; 32],
        sweep_txid: [0; 32],
        expiry_height: step.expiry_height,
        vault_txid: *vault_txid,
        owner_pubkey: owner_pubkey.to_vec(),
        note: format!("clause {}", entry.claim_path),
    };
    let id = wallet.store.insert_mint(&row)?;
    if let Some(b) = bounds {
        wallet
            .store
            .set_claim_bounds(id, b.max_burn_cents, b.min_out_zat)?;
    }
    Ok(id)
}

/// The CLAIM's shape under the vault upgrade (U-23; `PlanVaultSpend`'s claim branch,
/// `ycash-dd/src/yellowback/txbuilder.cpp`, branch `upgrade/vault`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimShape {
    /// The vault outpoint.
    pub vault_out: OutPoint,
    /// The vault's V parameters and scriptPubKey.
    pub vault: crate::vault::VaultParams,
    /// `BuildVault(vault)`.
    pub vault_script: Vec<u8>,
    /// The vault's `nValue`.
    pub vault_value: i64,
    /// `R`.
    pub ref_height: u32,
    /// The YED inputs burned.
    pub yed_inputs: Vec<Utxo>,
    /// YED change in cents (0 = none).
    pub change_cents: u64,
    /// The change token's script.
    pub change_script: Vec<u8>,
    /// The fee payee's script (`None` under FEE-0).
    pub payee_script: Option<Vec<u8>>,
    /// The enforcement fee.
    pub fee_zat: i64,
    /// The attestor payee's script (`None` under AFEE-0).
    pub attest_script: Option<Vec<u8>>,
    /// The attestor fee.
    pub attest_fee_zat: i64,
    /// RED-5's residual (0 = none): an intent paying `P2PKH(owner)`.
    pub residual_zat: i64,
    /// `P2PKH(ownerPubKey)`, the residual intent's recipient.
    pub owner_script: Vec<u8>,
    /// The claimant intent's recipient (an own fresh P2PKH).
    pub claimant_script: Vec<u8>,
    /// The YEC inputs paying the fees (after the YED inputs, before the carrier).
    pub funding: Vec<Utxo>,
    /// Where the fee inputs' change goes.
    pub funding_change_script: Vec<u8>,
    /// The carrier outpoint (`vin[last]`), whose `CARRIER_VALUE` joins the inputs.
    pub carrier: OutPoint,
}

/// The planned CLAIM.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimPlan {
    /// `nLockTime` = the V's `appHeight` (`claimHeight`).
    pub lock_time: u32,
    /// vault, YED inputs, fee inputs, carrier.
    pub vin: Vec<TxIn>,
    /// The outputs in slot order.
    pub vout: Vec<TxOut>,
    /// The claimant intent's value: `vaultValue − residual`.
    pub claimant_value: i64,
    /// The claimant intent's scriptPubKey.
    pub claimant_intent: Vec<u8>,
    /// The owner's residual intent's scriptPubKey (empty without a residual).
    pub residual_intent: Vec<u8>,
    /// The cents burned.
    pub burn_cents: i64,
    /// Output indexes, −1 = none.
    pub fee_vout: i32,
    /// See [`ClaimPlan::fee_vout`].
    pub change_vout: i32,
    /// See [`ClaimPlan::fee_vout`].
    pub attest_fee_vout: i32,
    /// See [`ClaimPlan::fee_vout`].
    pub residual_vout: i32,
    /// See [`ClaimPlan::fee_vout`].
    pub funding_change_vout: i32,
    /// The fee inputs' change, zat (0 = none; it joined the network fee).
    pub funding_change: i64,
    /// The REDEEM payload.
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Slot {
    Intent,
    Fee,
    Change,
    Attest,
    Residual,
    Payload,
    FundChange,
}

/// YEC the fee side of a claim needs from the claimant's own coins (U-23): the network fee, the
/// pool and attestor fees and the YED change's `TOKEN_VALUE`, less what the carrier and the YED
/// inputs already bring. ≤ 0 = nothing.
pub fn claim_funding_needed(
    fee_zat: i64,
    attest_fee_zat: i64,
    change: bool,
    yed_value: i64,
) -> i64 {
    FEE_ZAT + fee_zat + attest_fee_zat + if change { TOKEN_VALUE } else { 0 }
        - CARRIER_VALUE
        - yed_value
}

/// `PlanVaultSpend` for a CLAIM (U-23): `vout[0]` the claimant intent of `vaultValue − residual`,
/// [fee], [YED change], [attestor fee], [the owner's residual intent], the REDEEM payload, [the
/// fee inputs' change]; `nLockTime = appHeight`. The vault's value never leaves to ordinary
/// outputs (S-2); everything else is paid by the carrier, YED and fee inputs. A spare of at least
/// `MIN_CHANGE` goes back to the claimant (the node's builder only returns it from fee inputs and
/// at ≥ 1,000 zat; an ordinary extra output is allowed by S-2), never as exactly `TOKEN_VALUE`.
pub fn plan_claim(s: &ClaimShape) -> Result<ClaimPlan, WalletError> {
    let v = &s.vault;
    if crate::vault::build_vault(v).as_deref() != Some(&s.vault_script[..]) {
        return Err(WalletError::Other(
            "vault-not-found: the vault script does not match its parameters".into(),
        ));
    }
    if v.app_height <= 0 {
        return Err(WalletError::Other(
            "vault-not-found: the vault has no APP branch (S-4)".into(),
        ));
    }
    let mut vin = vec![TxIn {
        prevout: s.vault_out,
        script_sig: crate::vault::vault_app_script_sig(),
        sequence: SEQUENCE_LOCKTIME,
    }];
    let mut yed_value = 0i64;
    let mut yed_in = 0i64;
    for c in &s.yed_inputs {
        vin.push(TxIn::new(c.outpoint));
        yed_value += c.value;
        yed_in += c.cents as i64;
    }
    let mut fund_value = 0i64;
    for f in &s.funding {
        vin.push(TxIn::new(f.outpoint));
        fund_value += f.value;
    }
    vin.push(TxIn::new(s.carrier));
    let change = s.change_cents > 0;
    let fee = s.payee_script.is_some();
    let attest = s.attest_script.is_some();
    let residual = s.residual_zat > 0;
    let claimant_value = s.vault_value - if residual { s.residual_zat } else { 0 };
    if claimant_value <= 0 {
        return Err(WalletError::Other(
            "vault-value-too-small: the residual takes the whole vault".into(),
        ));
    }
    let spare = CARRIER_VALUE + yed_value + fund_value
        - FEE_ZAT
        - if fee { s.fee_zat } else { 0 }
        - if attest { s.attest_fee_zat } else { 0 }
        - if change { TOKEN_VALUE } else { 0 };
    if spare < 0 {
        return Err(WalletError::Other(format!(
            "insufficient-yec: the claim's fees need {} zat more",
            -spare
        )));
    }
    let mut funding_change = if spare >= MIN_CHANGE && !s.funding_change_script.is_empty() {
        spare
    } else {
        0
    };
    if funding_change == TOKEN_VALUE {
        funding_change -= 1; // never an output that looks like a token
    }
    let mut order = vec![Slot::Intent];
    if fee {
        order.push(Slot::Fee);
    }
    if change {
        order.push(Slot::Change);
    }
    if attest && !fee && !change {
        order.push(Slot::Payload); // AFEE-1 excludes vout[1]: the payload takes it
    }
    if attest {
        order.push(Slot::Attest);
    }
    if residual {
        order.push(Slot::Residual);
    }
    if !order.contains(&Slot::Payload) {
        order.push(Slot::Payload);
    }
    if funding_change > 0 {
        order.push(Slot::FundChange);
    }
    let claimant_intent = crate::vault::build_intent(&crate::vault::intent_for(
        v,
        &s.vault_script,
        &s.claimant_script,
    ))
    .ok_or_else(|| WalletError::Other("cannot build the claimant intent".into()))?;
    let residual_intent = if residual {
        crate::vault::build_intent(&crate::vault::intent_for(
            v,
            &s.vault_script,
            &s.owner_script,
        ))
        .ok_or_else(|| WalletError::Other("cannot build the residual intent".into()))?
    } else {
        Vec::new()
    };
    let mut plan = ClaimPlan {
        lock_time: v.app_height as u32,
        vin,
        vout: Vec::new(),
        claimant_value,
        claimant_intent,
        residual_intent,
        burn_cents: yed_in - s.change_cents as i64,
        fee_vout: -1,
        change_vout: -1,
        attest_fee_vout: -1,
        residual_vout: -1,
        funding_change_vout: -1,
        funding_change,
        payload: Vec::new(),
    };
    let mut assignments = Vec::new();
    for (i, slot) in order.iter().enumerate() {
        match slot {
            Slot::Fee => plan.fee_vout = i as i32,
            Slot::Change => {
                plan.change_vout = i as i32;
                assignments.push(Assignment {
                    vout: i as u8,
                    cents: s.change_cents as u32,
                });
            }
            Slot::Attest => plan.attest_fee_vout = i as i32,
            Slot::Residual => plan.residual_vout = i as i32,
            Slot::FundChange => plan.funding_change_vout = i as i32,
            _ => {}
        }
    }
    let vout_or_none = |v: i32| if v < 0 { FEE_VOUT_NONE } else { v as u8 };
    plan.payload = payload::encode(&Payload::Redeem {
        ref_height: s.ref_height,
        fee_vout: vout_or_none(plan.fee_vout),
        attest_fee_vout: vout_or_none(plan.attest_fee_vout),
        assignments,
    })
    .ok_or_else(|| WalletError::Other("cannot encode the redeem payload".into()))?;
    for slot in order {
        plan.vout.push(match slot {
            Slot::Intent => TxOut {
                value: claimant_value,
                script_pubkey: plan.claimant_intent.clone(),
            },
            Slot::Fee => TxOut {
                value: s.fee_zat,
                script_pubkey: s.payee_script.clone().unwrap_or_default(),
            },
            Slot::Change => TxOut {
                value: TOKEN_VALUE,
                script_pubkey: s.change_script.clone(),
            },
            Slot::Attest => TxOut {
                value: s.attest_fee_zat,
                script_pubkey: s.attest_script.clone().unwrap_or_default(),
            },
            Slot::Residual => TxOut {
                value: s.residual_zat,
                script_pubkey: plan.residual_intent.clone(),
            },
            Slot::Payload => TxOut {
                value: 0,
                script_pubkey: payload::payload_script(&plan.payload),
            },
            Slot::FundChange => TxOut {
                value: funding_change,
                script_pubkey: s.funding_change_script.clone(),
            },
        });
    }
    Ok(plan)
}

/// The CLAIM over a confirmed carrier (`BuildClaim` → `BuildVaultSpend`, branch
/// `upgrade/vault`), called by `build::mint::finish` for a row of kind `Claim`: the vault spent
/// with selector 4 (`OP_4`, the APP branch) into the claimant intent (and the owner's residual
/// intent), the fees from the claimant's YEC; the intent is released after `CLAIM_DELAY`
/// ([`super::release`]) unless one attestor cancels it first.
pub async fn finish(
    wallet: &Wallet,
    client: &mut CompactClient,
    validator: &mut Validator,
    m: &MintRow,
    branch_id: u32,
) -> Result<Finished, WalletError> {
    let owner_pubkey: [u8; 33] = m
        .owner_pubkey
        .as_slice()
        .try_into()
        .map_err(|_| WalletError::Other("owner pubkey length".into()))?;
    let vt = {
        let yb = validator
            .client_mut()
            .ok_or(gate::GateError::YellowbackAbsent)?;
        mint::vault_terms_now(wallet, yb).await?
    };
    if m.claim_height != m.lock_height + vt.grace {
        return Err(MintError::Inconsistent {
            what: format!(
                "claimHeight {} is not lockHeight {} + GRACE",
                m.claim_height, m.lock_height
            ),
        }
        .into());
    }
    let vault = vt.vault_params(&owner_pubkey, m.lock_height);
    let vault_script = vt.vault_script(&owner_pubkey, m.lock_height)?;
    let vault_out = OutPoint {
        txid: m.vault_txid,
        n: 0,
    };
    let (carrier_op, redeem_script, carrier_key) = mint::carrier_of(wallet, m)?;
    let (yed_inputs, change_cents, extra_burn, _stage) = redeem::select_yed_burn(wallet, m.cents)?;
    let yed_value: i64 = yed_inputs.iter().map(|u| u.value).sum();
    let needed = claim_funding_needed(
        if m.payee.is_empty() { 0 } else { m.fee_zat },
        if m.attest_payee.is_empty() {
            0
        } else {
            m.attest_fee_zat
        },
        change_cents > 0,
        yed_value,
    );
    let funding = if needed > 0 {
        coins::select_yec(&wallet.spendable_utxos()?, needed, true)?
    } else {
        Vec::new()
    };
    let dest = mint::fresh_external(wallet)?;
    let change_row = if change_cents > 0 {
        Some(mint::fresh_external(wallet)?)
    } else {
        None
    };
    // Peeked, not taken: the key is marked used only if the plan returns change to it.
    let fund_change_row = wallet.change_address()?;
    let shape = ClaimShape {
        vault_out,
        vault: vault.clone(),
        vault_script: vault_script.clone(),
        vault_value: m.collateral_zat,
        ref_height: m.ref_height,
        yed_inputs: yed_inputs.clone(),
        change_cents,
        change_script: change_row
            .as_ref()
            .map(|c| script::p2pkh_script(&c.hash160))
            .unwrap_or_default(),
        payee_script: if m.payee.is_empty() {
            None
        } else {
            Some(mint::p2pkh_of_address(wallet, &m.payee)?)
        },
        fee_zat: m.fee_zat,
        attest_script: if m.attest_payee.is_empty() {
            None
        } else {
            Some(mint::p2pkh_of_address(wallet, &m.attest_payee)?)
        },
        attest_fee_zat: m.attest_fee_zat,
        residual_zat: m.residual_zat,
        owner_script: script::p2pkh_script(&keys::hash160(&owner_pubkey)),
        claimant_script: script::p2pkh_script(&dest.hash160),
        funding: funding.clone(),
        funding_change_script: script::p2pkh_script(&fund_change_row.hash160),
        carrier: carrier_op,
    };
    let plan = plan_claim(&shape)?;
    // H-9.3: refuse to sign a CLAIM whose debt or take moved past what the user confirmed
    // (the row holds the checked figures; the burn's own remainder is the wallet's, not the
    // server's, and is not bounded here).
    if let Some((max_burn_cents, min_out_zat)) = wallet.store.claim_bounds(m.id)? {
        let debt = (plan.burn_cents.max(0) as u64).saturating_sub(extra_burn);
        terms::check_claim_bounds(
            &terms::ClaimBounds {
                max_burn_cents,
                min_out_zat,
            },
            debt,
            terms::claimant_take(
                m.collateral_zat,
                m.fee_zat,
                m.attest_fee_zat,
                m.residual_zat,
            ),
        )?;
    }
    let mut tx = Transaction::new_v4();
    tx.lock_time = plan.lock_time;
    tx.expiry_height = m.expiry_height;
    tx.vin = plan.vin.clone();
    tx.vout = plan.vout.clone();
    let carrier_vin = tx.vin.len() - 1;
    mint::sign_p2pkh_inputs(wallet, &mut tx, &yed_inputs, 1, branch_id)?;
    mint::sign_p2pkh_inputs(wallet, &mut tx, &funding, 1 + yed_inputs.len(), branch_id)?;
    mint::sign_carrier_input(
        &mut tx,
        carrier_vin,
        &carrier_key,
        &redeem_script,
        &m.bundle,
        branch_id,
    )?;
    let raw = tx.serialize()?;
    let txid = tx.txid()?;
    let (_, validation) = gate::confirm_burning(
        validator,
        gate::Path::Claim(vault_out),
        &raw,
        |op| wallet.store.utxo_class(op).ok().flatten(),
        plan.burn_cents,
    )
    .await?;
    let validation = validation.ok_or(gate::GateError::YellowbackAbsent)?;
    mint::send(client, &raw, &txid).await?;
    let mut locked = yed_inputs.clone();
    locked.extend(funding.iter().cloned());
    locked.push(Utxo {
        outpoint: carrier_op,
        address: String::new(),
        script: script::p2sh_of(&redeem_script),
        value: CARRIER_VALUE,
        height: 0,
        class: UtxoClass::Carrier,
        cents: 0,
    });
    mint::record_broadcast(wallet, &txid, &raw, m.expiry_height, &locked)?;
    for u in &yed_inputs {
        wallet
            .store
            .insert_spent_token(&txid, &u.outpoint, u.cents)?;
    }
    if let Some(row) = &change_row {
        let n = plan.change_vout as u32;
        wallet.store.upsert_utxo(&Utxo {
            outpoint: OutPoint { txid, n },
            address: row.address_s.clone(),
            script: script::p2pkh_script(&row.hash160),
            value: TOKEN_VALUE,
            height: 0,
            class: UtxoClass::PendingToken,
            cents: change_cents,
        })?;
        wallet
            .store
            .insert_own_output(&OutPoint { txid, n }, TOKEN_VALUE, &row.hash160)?;
    }
    if plan.funding_change_vout >= 0 {
        wallet.store.mark_used(&fund_change_row.hash160)?;
        wallet.ensure_gap()?;
        wallet.store.insert_own_output(
            &OutPoint {
                txid,
                n: plan.funding_change_vout as u32,
            },
            plan.funding_change,
            &fund_change_row.hash160,
        )?;
    }
    // The claimant intent: released after CLAIM_DELAY (build::release), or cancelled.
    wallet.store.upsert_intent(&IntentRow {
        outpoint: OutPoint { txid, n: 0 },
        vault_txid: m.vault_txid,
        role: ROLE_CLAIMANT.into(),
        value: plan.claimant_value,
        recipient_script: shape.claimant_script.clone(),
        intent_script: plan.claimant_intent.clone(),
        delay: vault.delay,
        height: 0,
        state: IntentState::Pending,
        spend_txid: [0; 32],
        note: format!(
            "claim of vault {}: released {} blocks after it confirms unless an attestor cancels it",
            &txid_hex(&m.vault_txid)[..8],
            vault.delay
        ),
    })?;
    let yed_spent: i64 = yed_inputs.iter().map(|u| u.value).sum();
    let fund_spent: i64 = funding.iter().map(|u| u.value).sum();
    wallet.store.upsert_history(&HistoryRow {
        txid,
        height: 0,
        yec_delta: plan.funding_change + if change_cents > 0 { TOKEN_VALUE } else { 0 }
            - yed_spent
            - fund_spent
            - CARRIER_VALUE,
        has_payload: true,
        pending: true,
        shielded: false,
        yed_delta: -plan.burn_cents,
        kind: "claim".into(),
        verdict: String::new(),
        label: format!(
            "claiming vault {}, burning {}{}; {} YEC pending release",
            &txid_hex(&m.vault_txid)[..8],
            dollars(plan.burn_cents),
            if extra_burn > 0 {
                format!(" (incl. {} remainder)", dollars(extra_burn as i64))
            } else {
                String::new()
            },
            crate::wallet::yec(plan.claimant_value)
        ),
        labelled: false,
    })?;
    wallet
        .store
        .set_mint_state(m.id, MintState::MainSent, Some(&txid), None, &m.note)?;
    Ok(Finished {
        txid: txid_hex(&txid),
        validation,
        raw,
    })
}

/// The claimant's intent (`yed_getvault.intents[].role`).
pub const ROLE_CLAIMANT: &str = "claimant";
/// The owner's RED-5 residual intent.
pub const ROLE_RESIDUAL: &str = "residual";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::unhex;
    use crate::vault::{self, Kind};

    fn vectors() -> serde_json::Value {
        let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/vectors/vault_vectors.json");
        serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
    }

    fn named<'a>(v: &'a serde_json::Value, list: &str, name: &str) -> &'a serde_json::Value {
        v[list]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["name"] == name)
            .unwrap()
    }

    fn utxo(n: u8, value: i64, cents: u64, class: UtxoClass) -> Utxo {
        Utxo {
            outpoint: OutPoint {
                txid: [n; 32],
                n: 1,
            },
            address: String::new(),
            script: script::p2pkh_script(&[n; 20]),
            value,
            height: 1,
            class,
            cents,
        }
    }

    /// The golden vector's YED-tagged (`app-enabled`) vault, claimed into the vector's
    /// `app-enabled` intent: the CLAIM's template bytes are the node's.
    fn shape(residual: i64, fee: bool, attest: bool, change: u64, funding: i64) -> ClaimShape {
        let v = vectors();
        let vspk = unhex(
            named(&v, "vaults", "app-enabled")["script"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let ie = named(&v, "intents", "app-enabled");
        let recipient = unhex(ie["recipientScript"].as_str().unwrap()).unwrap();
        ClaimShape {
            vault_out: OutPoint {
                txid: [9; 32],
                n: 0,
            },
            vault: vault::parse_vault(&vspk).unwrap(),
            vault_script: vspk,
            vault_value: 2_500_000_000,
            ref_height: 1_290,
            yed_inputs: vec![
                utxo(1, TOKEN_VALUE, 6_000, UtxoClass::Token),
                utxo(2, TOKEN_VALUE, 6_000, UtxoClass::Token),
            ],
            change_cents: change,
            change_script: script::p2pkh_script(&[5; 20]),
            payee_script: fee.then(|| script::p2pkh_script(&[6; 20])),
            fee_zat: 50_000_000,
            attest_script: attest.then(|| script::p2pkh_script(&[7; 20])),
            attest_fee_zat: 12_500_000,
            residual_zat: residual,
            owner_script: script::p2pkh_script(&[8; 20]),
            claimant_script: recipient,
            funding: if funding > 0 {
                vec![utxo(3, funding, 0, UtxoClass::Yec)]
            } else {
                Vec::new()
            },
            funding_change_script: script::p2pkh_script(&[4; 20]),
            carrier: OutPoint {
                txid: [0xca; 32],
                n: 0,
            },
        }
    }

    #[test]
    fn claim_reproduces_the_vector_templates_and_the_node_slot_order() {
        let v = vectors();
        let intent = unhex(
            named(&v, "intents", "app-enabled")["script"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let s = shape(0, true, true, 0, 100_000_000);
        let p = plan_claim(&s).unwrap();
        // vin[0]: the vault with OP_4 (the selector vector), nSequence 0xFFFFFFFE (CLTV); the fee
        // inputs after the YED ones; the carrier last. nLockTime = appHeight.
        assert_eq!(p.vin[0].prevout, s.vault_out);
        assert_eq!(p.vin[0].script_sig, unhex("54").unwrap());
        assert_eq!(
            vault::parse_selector(Kind::Vault, &p.vin[0].script_sig).map(|x| x.0),
            Some(vault::SEL_APP)
        );
        assert_eq!(p.vin[0].sequence, SEQUENCE_LOCKTIME);
        assert_eq!(p.lock_time, 1_288);
        assert_eq!(p.vin.len(), 5);
        assert_eq!(p.vin[3].prevout, s.funding[0].outpoint);
        assert_eq!(p.vin[4].prevout, s.carrier);
        // vout[0]: the claimant intent, byte for byte the vector's IntentFor(vault, recipient).
        assert_eq!(p.vout[0].script_pubkey, intent);
        assert_eq!(p.vout[0].value, 2_500_000_000);
        // fee, attestor fee, payload, the fee inputs' change.
        assert_eq!(
            (
                p.fee_vout,
                p.attest_fee_vout,
                p.change_vout,
                p.residual_vout
            ),
            (1, 2, -1, -1)
        );
        assert!(script::is_op_return(&p.vout[3].script_pubkey));
        assert_eq!(p.funding_change_vout, 4);
        let spare =
            CARRIER_VALUE + 2 * TOKEN_VALUE + 100_000_000 - FEE_ZAT - 50_000_000 - 12_500_000;
        assert_eq!(p.vout[4].value, spare);
        assert_eq!(p.burn_cents, 12_000);
        // S-2: Σ intents ≥ the vault's value; nothing of it leaves to an ordinary output.
        let intents: i64 = p
            .vout
            .iter()
            .filter(|o| vault::parse_intent(&o.script_pubkey).is_some())
            .map(|o| o.value)
            .sum();
        assert_eq!(intents, s.vault_value);
        let inputs = s.vault_value + CARRIER_VALUE + 2 * TOKEN_VALUE + 100_000_000;
        let outputs: i64 = p.vout.iter().map(|o| o.value).sum();
        assert_eq!(inputs - outputs, FEE_ZAT);
    }

    #[test]
    fn claim_residual_intent_pays_the_owner_and_change_and_payload_slots() {
        let s = shape(300_000, false, true, 2_000, 100_000_000);
        let p = plan_claim(&s).unwrap();
        assert_eq!(p.vout[0].value, s.vault_value - 300_000);
        // Change at vout[1] (assigned), then attest, then the residual intent, then the payload.
        assert_eq!(
            (
                p.fee_vout,
                p.change_vout,
                p.attest_fee_vout,
                p.residual_vout
            ),
            (-1, 1, 2, 3)
        );
        let r = vault::parse_intent(&p.vout[3].script_pubkey).unwrap();
        assert_eq!(r.recipient_hash, vault::script_hash256(&s.owner_script));
        assert_eq!(r.vault_hash, vault::script_hash256(&s.vault_script));
        assert_eq!(
            (r.delay, r.cancel_set_id, r.tag),
            (s.vault.delay, s.vault.cancel_set_id, vault::YED_TAG)
        );
        assert_eq!(p.vout[3].value, 300_000);
        assert!(script::is_op_return(&p.vout[4].script_pubkey));
        assert_eq!(
            payload::decode(&p.payload).unwrap().assignments(),
            &[Assignment {
                vout: 1,
                cents: 2_000
            }]
        );
        // Attest alone (no fee, no change): the payload takes vout[1] (AFEE-1 excludes it).
        let p = plan_claim(&shape(0, false, true, 0, 100_000_000)).unwrap();
        assert!(script::is_op_return(&p.vout[1].script_pubkey));
        assert_eq!(p.attest_fee_vout, 2);
    }

    #[test]
    fn claim_needs_yec_for_its_fees() {
        // Two tokens and the carrier bring 30,000 zat; a 0.5 YEC fee needs funding.
        assert_eq!(
            claim_funding_needed(50_000_000, 0, false, 2 * TOKEN_VALUE),
            FEE_ZAT + 50_000_000 - CARRIER_VALUE - 2 * TOKEN_VALUE
        );
        assert!(claim_funding_needed(0, 0, false, TOKEN_VALUE) < 0);
        assert!(plan_claim(&shape(0, true, false, 0, 0)).is_err());
        // Without a fee the spare is change back to the claimant, never TOKEN_VALUE exactly.
        let mut s = shape(0, false, false, 0, 0);
        s.yed_inputs.truncate(1);
        let p = plan_claim(&s).unwrap();
        assert_eq!(p.funding_change, CARRIER_VALUE + TOKEN_VALUE - FEE_ZAT);
        let mut s = shape(0, false, false, 0, 0);
        s.yed_inputs = vec![utxo(1, FEE_ZAT, 100, UtxoClass::Token)];
        let p = plan_claim(&s).unwrap();
        assert_eq!(p.funding_change, TOKEN_VALUE - 1);
        // A residual that takes the whole vault is refused.
        assert!(plan_claim(&shape(2_500_000_000, true, false, 0, 100_000_000)).is_err());
        // A vault script that is not its parameters' is refused.
        let mut s = shape(0, true, false, 0, 100_000_000);
        s.vault_script.push(0x51);
        assert!(plan_claim(&s).is_err());
    }
}
