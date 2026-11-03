// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The Sapling side of the YED builders (S4, F-S2-8): a mint funded from a Sapling address (its
//! carrier step too), a redemption or a bond withdrawal paying one. ycash6
//! `src/yellowback/txbuilder.cpp` `ParseAddressChoice`, `Context::SelectSapling` (largest notes
//! first, `insufficient-yec: … in confirmed Sapling notes at …`), and the Sapling shapes of
//! `BuildMint`, `BuildVaultSpend`, `BuildWithdrawBond`. The notes and their Merkle paths are the
//! façade's (`zsend.rs`); the signer builds, proves and authorizes the Sapling part with the
//! transparent one ([`yewd_proto::SaplingPart`]).

use yewd_proto::{SaplingOut, SaplingPart, SaplingSpend};

use crate::node::Node;
use crate::{code, RpcError, Wallet};

/// `MAX_SAPLING_SPENDS` of the overlay's builders.
pub const MAX_SAPLING_SPENDS: usize = 50;

impl Wallet {
    /// A Sapling address of this network (any wallet's).
    pub(crate) fn is_sapling(&self, a: &str) -> bool {
        yew_core::shielded_keys::is_sapling_address(self.network, a)
    }

    /// `SelectSapling(addr, needed)`: the notes of `zaddr` (this account's, confirmed), largest
    /// first, covering `needed`; with their paths at the tip and the anchor.
    pub(crate) async fn z_select(
        &self,
        node: &dyn Node,
        zaddr: &str,
        needed: i64,
        what: &str,
    ) -> Result<(Vec<SaplingSpend>, String, i64), RpcError> {
        if self.view.owns_address(zaddr).is_none() {
            return Err(crate::mint::build_error(format!(
                "bad-address: no spending key for {zaddr} in this wallet"
            )));
        }
        let mut notes: Vec<crate::NoteRow> = self
            .notes
            .iter()
            .filter(|n| {
                !n.spent && n.address == zaddr && self.depth(n.height) >= 1 && n.position.is_some()
            })
            .cloned()
            .collect();
        notes.sort_by(|a, b| b.value.cmp(&a.value));
        let available: i64 = notes.iter().map(|n| n.value as i64).sum();
        let mut sel = Vec::new();
        let mut sum = 0i64;
        for n in notes {
            if sum >= needed {
                break;
            }
            sum += n.value as i64;
            sel.push(n);
        }
        if sum < needed {
            return Err(crate::mint::build_error(format!(
                "insufficient-yec: need {}, have {} in confirmed Sapling notes at {zaddr}",
                crate::rpc::format_money(needed),
                crate::rpc::format_money(available)
            )));
        }
        if sel.len() > MAX_SAPLING_SPENDS {
            return Err(crate::mint::build_error(format!(
                "too-many-notes: the {what} would spend {} Sapling notes (limit {MAX_SAPLING_SPENDS}); consolidate with z_mergetoaddress first",
                sel.len()
            )));
        }
        let (anchor, paths) = self.sapling_paths(node, &sel, self.tip_height()).await?;
        let spends = sel
            .iter()
            .zip(paths)
            .map(|(n, (pos, path))| {
                let (rseed, after) = match n.note.rseed() {
                    sapling_crypto::Rseed::AfterZip212(r) => (hex::encode(r), true),
                    sapling_crypto::Rseed::BeforeZip212(r) => (hex::encode(r.to_bytes()), false),
                };
                SaplingSpend {
                    recipient: hex::encode(n.note.recipient().to_bytes()),
                    value: n.value,
                    rseed,
                    after_zip212: after,
                    internal: n.internal,
                    position: pos,
                    path,
                }
            })
            .collect();
        Ok((spends, anchor, sum))
    }

    /// The Sapling part of a builder's transaction at `target_height`.
    pub(crate) fn sapling_part(
        &self,
        target_height: u32,
        spends: Vec<SaplingSpend>,
        anchor: String,
        outputs: Vec<SaplingOut>,
    ) -> SaplingPart {
        SaplingPart {
            target_height,
            vault_height: self.chain.vault_activation,
            spends,
            outputs,
            anchor,
            params_dir: self.params_dir(),
        }
    }

    /// A Sapling output of `value` to `zaddr` (a change back to a source counts as the wallet's).
    pub(crate) fn sapling_out(&self, zaddr: &str, value: i64) -> SaplingOut {
        SaplingOut::Shielded {
            address: zaddr.to_string(),
            value,
            memo: String::new(),
            own: self.view.owns_address(zaddr).is_some(),
        }
    }

    /// ZIP-317's conventional fee of a transparent part (its scriptSig sizes) with `spends`
    /// Sapling spends and `outputs` Sapling outputs (padded to two).
    pub(crate) fn hybrid_fee(
        tx: &yew_core::tx::Transaction,
        script_sig_sizes: &[usize],
        spends: usize,
        outputs: usize,
    ) -> Result<i64, RpcError> {
        let mut t = tx.clone();
        t.shielded.spends = spends;
        t.shielded.outputs = if spends + outputs > 0 {
            outputs.max(2)
        } else {
            0
        };
        t.zip317_conventional_fee(script_sig_sizes)
            .map_err(|e| RpcError::new(code::INTERNAL_ERROR, e.to_string()))
    }
}

/// The Sapling destination's outputs of a vault spend (`PlanVaultSpend`'s Sapling branch, M13,
/// S11): change, payload, fee, attestor fee, residual — the collateral is the Sapling note. From
/// the transparent plan's amounts; the payload's vout indices follow this order.
pub(crate) fn sapling_spend_vout(
    shape: &yew_core::build::redeem::VaultSpendShape,
    plan: &yew_core::build::redeem::VaultSpendPlan,
) -> Result<Vec<yew_core::tx::TxOut>, RpcError> {
    use yew_core::payload::{self, Assignment, Payload, FEE_VOUT_NONE};
    use yew_core::tx::TxOut;
    if !shape.with_payload {
        return Ok(Vec::new());
    }
    #[derive(PartialEq)]
    enum Slot {
        Change,
        Payload,
        Fee,
        Attest,
        Residual,
    }
    let change = plan.change_vout >= 0;
    let fee = plan.fee_vout >= 0;
    let attest = plan.attest_fee_vout >= 0;
    let residual = plan.residual_vout >= 0;
    let mut order = Vec::new();
    if change {
        order.push(Slot::Change);
    }
    order.push(Slot::Payload);
    if fee {
        order.push(Slot::Fee);
    }
    if attest && !fee && !change {
        if !residual {
            return Err(crate::mint::build_error("attest-fee-shape: a Sapling-paid claim with no pool fee, no YED change and no residual cannot place the attestor fee; pass a transparent destination".into()));
        }
        order.push(Slot::Residual);
        order.push(Slot::Attest);
    } else {
        if attest {
            order.push(Slot::Attest);
        }
        if residual {
            order.push(Slot::Residual);
        }
    }
    let (mut fee_vout, mut attest_vout) = (FEE_VOUT_NONE, FEE_VOUT_NONE);
    let mut assignments = Vec::new();
    for (i, s) in order.iter().enumerate() {
        match s {
            Slot::Fee => fee_vout = i as u8,
            Slot::Attest => attest_vout = i as u8,
            Slot::Change => assignments.push(Assignment {
                vout: i as u8,
                cents: shape.change_cents as u32,
            }),
            _ => {}
        }
    }
    let pl = payload::encode(&Payload::Redeem {
        ref_height: shape.ref_height,
        fee_vout,
        attest_fee_vout: attest_vout,
        assignments,
    })
    .ok_or_else(|| RpcError::new(code::INTERNAL_ERROR, "cannot encode the redeem payload"))?;
    Ok(order
        .into_iter()
        .map(|s| match s {
            Slot::Change => TxOut {
                value: yew_core::params::TOKEN_VALUE,
                script_pubkey: shape.change_script.clone(),
            },
            Slot::Payload => TxOut {
                value: 0,
                script_pubkey: payload::payload_script(&pl),
            },
            Slot::Fee => TxOut {
                value: shape.fee_zat,
                script_pubkey: shape.payee_script.clone().unwrap_or_default(),
            },
            Slot::Attest => TxOut {
                value: shape.attest_fee_zat,
                script_pubkey: shape.attest_script.clone().unwrap_or_default(),
            },
            Slot::Residual => TxOut {
                value: shape.residual_zat,
                script_pubkey: shape.owner_script.clone(),
            },
        })
        .collect())
}

impl Wallet {
    /// Fund `base` (its transparent inputs, worth `input_value`, already in `vin` with `prevs` and
    /// `keys`) from the Sapling notes of `zaddr`, change back to `zaddr`, at
    /// `max(flat, the ZIP-317 conventional fee)` of the whole shape (`script_sig_sizes` for its
    /// transparent inputs); the signer builds, proves and signs it. Returns the transaction's hex
    /// and the network fee.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn z_fund_and_sign(
        &mut self,
        node: &dyn Node,
        base: &yew_core::tx::Transaction,
        prevs: &[crate::build::NodeCoin],
        keys: &[yewd_proto::KeyRef],
        input_value: i64,
        script_sig_sizes: &[usize],
        zaddr: &str,
        flat: i64,
        gate: yewd_proto::GatePath,
        next: &crate::build::Next,
        what: &str,
    ) -> Result<(String, i64), RpcError> {
        let mut fee = flat;
        for _ in 0..6 {
            let need = base.output_total() + fee - input_value;
            let (spends, anchor, sum) = self.z_select(node, zaddr, need.max(0), what).await?;
            let change = sum - need.max(0);
            let outputs = if change > 0 {
                vec![self.sapling_out(zaddr, change)]
            } else {
                Vec::new()
            };
            let conventional =
                Wallet::hybrid_fee(base, script_sig_sizes, spends.len(), outputs.len())?.max(flat);
            if conventional > fee {
                fee = conventional;
                continue;
            }
            let part = self.sapling_part(next.height, spends, anchor, outputs);
            let cap = input_value + sum + 1;
            let hexs = self
                .sign_inputs_hex(base, prevs, keys, &[], gate, cap, next.branch, Some(part))
                .await?;
            return Ok((hexs, fee));
        }
        Err(crate::mint::build_error("the fee did not converge".into()))
    }
}
