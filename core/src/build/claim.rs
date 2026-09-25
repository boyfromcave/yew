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
use crate::coins::{Utxo, UtxoClass};
use crate::gate::{self, Validator};
use crate::keys::{self, unhex};
use crate::net::{CompactClient, YellowbackClient};
use crate::params::{CARRIER_VALUE, TOKEN_VALUE};
use crate::script;
use crate::store::{HistoryRow, MintKind, MintRow, MintState};
use crate::tx::{txid_hex, OutPoint, Transaction, TxIn};
use crate::wallet::{dollars, Wallet, WalletError};

use super::mint::{self, Finished, MintError};
use super::redeem::{self, VaultSpendShape};

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
}

/// `claimable` (plan §3.4): `ListClaimable` mapped for the screen.
pub async fn claimable(yb: &mut YellowbackClient) -> Result<Vec<Claimable>, WalletError> {
    Ok(yb
        .list_claimable()
        .await?
        .into_iter()
        .map(|c| Claimable {
            vault_txid: c.vault.split(':').next().unwrap_or("").to_string(),
            owner_address: c.owner_address,
            minted_cents: c.minted_cents.max(0) as u64,
            collateral_zat: c.collateral_zat,
            claim_height: c.claim_height as u32,
            claim_path: c.claim_path,
            p_claim: c.p_claim,
            fee_zat: c.fee_zat,
            attest_fee_zat: c.attest_fee_zat,
            residual_zat: c.residual_zat,
            claimant_zat: c.collateral_zat
                - c.fee_zat
                - c.attest_fee_zat
                - c.residual_zat
                - crate::params::FEE_ZAT,
        })
        .collect())
}

/// `claim` (plan §3.4; `BuildClaim`'s preflight and carrier step): start the two-step claim
/// of `vault_txid`. Returns the `mints` row id; `mint_finish(id)` sends the CLAIM once the
/// carrier is confirmed.
pub async fn start(
    wallet: &Wallet,
    client: &mut CompactClient,
    validator: &mut Validator,
    vault_txid: &[u8; 32],
    tip: u64,
    branch_id: u32,
) -> Result<i64, WalletError> {
    let yb = validator
        .client_mut()
        .ok_or(gate::GateError::YellowbackAbsent)?;
    let txid_str = txid_hex(vault_txid);
    let entry = claimable(yb)
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
    // The YED to burn must be there before the carrier is funded.
    let (yed, _, _, _) = redeem::select_yed_burn(wallet, entry.minted_cents)?;
    let _ = yed;
    let selector = bundle::outpoint_selector(vault_txid, v.vout);
    let b = yb.build_bundle(r, &keys::hex(&selector)).await?;
    let bundle_bytes = unhex(&b.hex).map_err(|e| MintError::Relay(format!("bundle hex: {e}")))?;
    let seqs = mint::verify_bundle(client, yb, &bundle_bytes).await?;
    let p = yb
        .fee_payee(r, v.collateral_zat, &keys::hex(&selector))
        .await?;
    let payee = if !p.preferred.is_empty() {
        p.preferred
    } else if let Some(d) = p.default {
        d.payout_address
    } else {
        String::new()
    };
    let attest_fee_bps = yb
        .info()
        .await?
        .params
        .and_then(|p| p.attest)
        .map(|a| a.attest_fee_bps)
        .unwrap_or(0);
    let (attest_payee, attest_fee_zat) =
        mint::attest_payee(client, yb, r, &selector, &seqs, p.fee_zat, attest_fee_bps).await?;
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
        fee_zat: if payee.is_empty() { 0 } else { p.fee_zat },
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
    Ok(wallet.store.insert_mint(&row)?)
}

/// The CLAIM over a confirmed carrier (`BuildClaim` → `BuildVaultSpend` with `ClaimExtras`),
/// called by `build::mint::finish` for a row of kind `Claim`.
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
    let vault_script = script::vault_script(m.lock_height, &owner_pubkey, m.claim_height)
        .map_err(MintError::Script)?;
    let vault_out = OutPoint {
        txid: m.vault_txid,
        n: 0,
    };
    let (carrier_op, redeem_script, carrier_key) = mint::carrier_of(wallet, m)?;
    let (yed_inputs, change_cents, extra_burn, _stage) = redeem::select_yed_burn(wallet, m.cents)?;
    let dest = mint::fresh_external(wallet)?;
    let change_row = if change_cents > 0 {
        Some(mint::fresh_external(wallet)?)
    } else {
        None
    };
    let shape = VaultSpendShape {
        vault_out,
        vault_value: m.collateral_zat,
        lock_height: m.lock_height,
        claim_height: m.claim_height,
        owner_path: false,
        with_payload: true,
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
        owner_script: script::p2pkh_script(&m.owner_hash160),
        carrier_value: CARRIER_VALUE,
        collateral_script: script::p2pkh_script(&dest.hash160),
    };
    let plan = redeem::plan_vault_spend(&shape)?;
    let mut tx = Transaction::new_v4();
    tx.lock_time = plan.lock_time;
    tx.expiry_height = m.expiry_height;
    tx.vin = plan.vin.clone();
    tx.vin.push(TxIn::new(carrier_op)); // never vin[0] (§3.5)
    let carrier_vin = tx.vin.len() - 1;
    tx.vout = plan.vout.clone();
    tx.vin[0].script_sig = script::claim_script_sig(&vault_script);
    mint::sign_p2pkh_inputs(wallet, &mut tx, &yed_inputs, 1, branch_id)?;
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
    wallet
        .store
        .insert_own_output(&OutPoint { txid, n: 0 }, plan.collateral_out, &dest.hash160)?;
    let yed_spent: i64 = yed_inputs.iter().map(|u| u.value).sum();
    wallet.store.upsert_history(&HistoryRow {
        txid,
        height: 0,
        yec_delta: plan.collateral_out + if change_cents > 0 { TOKEN_VALUE } else { 0 }
            - yed_spent
            - CARRIER_VALUE,
        has_payload: true,
        pending: true,
        shielded: false,
        yed_delta: -plan.burn_cents,
        kind: "claim".into(),
        verdict: String::new(),
        label: format!(
            "claiming vault {}, burning {}{}",
            &txid_hex(&m.vault_txid)[..8],
            dollars(plan.burn_cents),
            if extra_burn > 0 {
                format!(" (incl. {} remainder)", dollars(extra_burn as i64))
            } else {
                String::new()
            }
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
