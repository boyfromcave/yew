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
use crate::coins::{Utxo, UtxoClass};
use crate::gate::{self, Validator};
use crate::keys::{self, unhex};
use crate::net::{CompactClient, YellowbackClient};
use crate::params::{Network, CARRIER_VALUE, TOKEN_VALUE};
use crate::script;
use crate::store::{HistoryRow, MintKind, MintRow, MintState};
use crate::tx::{txid_hex, OutPoint, Transaction, TxIn};
use crate::wallet::{dollars, Wallet, WalletError};

use super::mint::{self, Finished, MintError};
use super::redeem::{self, VaultSpendShape};
use super::terms;

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
    // The vault's script terms and debt, as the node reports them, checked (audit G-1).
    terms::check_vault(wallet.network, &v)?;
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
    // The YED to burn must be there before the carrier is funded.
    let (yed, _, _, _) = redeem::select_yed_burn(wallet, entry.minted_cents)?;
    let _ = yed;
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
