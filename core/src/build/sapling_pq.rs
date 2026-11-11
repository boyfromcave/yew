// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! A plain YEC send **from the private (Sapling) balance to a post-quantum address** (`sqf…` /
//! `sqs…`; beta2 D-2, D-5, D-8): the shape yewd's `z_sendmany` builds for a Sapling source and a
//! `TX_PQPKH` recipient (`yewd/wallet/src/zsend.rs` `run_sendmany`, the `n_pq_out > 0` arm).
//!
//! - **Notes and paths** from the light client's own store ([`Shielded::select_spends`]: the
//!   store's note selection and its commitment tree's paths at the anchor, as the private send's
//!   `create_proposed_transactions` takes them). No witness store of YEW's own.
//! - **The transaction**: no transparent input; one transparent output, the recipient's
//!   `TX_PQPKH`; the Sapling part spends the notes with the change back to the account's internal
//!   (change) address (D-4: Sapling-source change stays a Sapling note). Proven and authorized by
//!   the hybrid builder (`build::hybrid::sapling_prepare`, `sign_hybrid` with no transparent input
//!   to sign); nothing in it is new signing code.
//! - **Fee**: the ZIP-317 conventional fee of the shape (ycash6's `CalcZIP317Fee` with the
//!   post-quantum output's longer script; no post-quantum input, so `PQBuilderFee` does not apply),
//!   re-checked on the signed bytes, bounded by [`params::pq_send_fee_limit`], and passed through
//!   the fee guard ([`terms::guard_fee`]: an unusual fee needs its own acknowledgement at confirm).
//!   No server-quoted rate enters it.
//! - **Gate**: [`gate::Path::SaplingToPq`] (no transparent input, at least one Sapling spend,
//!   exactly one transparent output paying the named key, not `TOKEN_VALUE`) on the final bytes at
//!   build and again at confirm, where the node's dry run is mandatory (a server without Yellowback
//!   refuses the send).
//! - **Privacy (D-5)**: the amount and the recipient are visible on the chain; the preview says so
//!   (`reveals_shielded`), in the words the private → public send uses.
//!
//! Native only: the browser build has no prover.

use crate::gate::{self, Validator};
use crate::keys::{self, YecDestination};
use crate::net::{CompactClient, Validation};
use crate::params::{self, TOKEN_VALUE, TX_EXPIRY_DELTA, VAULT_BRANCH_ID};
use crate::tx::{txid_hex, Transaction, TxOut};
use crate::wallet::{Wallet, WalletError};

use super::any_to_any as plan;
use super::mint;
use super::pq_send::SaplingSide;
use super::terms;

/// A planned, proven and authorized Sapling -> post-quantum send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SaplingPqPreview {
    /// The recipient as given.
    pub to: String,
    /// The recipient's key.
    pub id: crate::pq::PqKeyId,
    /// The amount paid to it, zat (after the `TOKEN_VALUE` bump, if any).
    pub amount: i64,
    /// True when the amount was bumped from exactly `TOKEN_VALUE`.
    pub amount_bumped: bool,
    /// The fee, zat.
    pub fee: i64,
    /// The Sapling change back to the wallet, zat (0 = none).
    pub change: i64,
    /// The notes spent.
    pub notes: u32,
    /// `nExpiryHeight`.
    pub expiry_height: u32,
    /// The finished transaction.
    pub raw: Vec<u8>,
    /// Its txid (internal order).
    pub txid: [u8; 32],
    /// The branch ID it was built under (the next block's).
    pub branch_id: u32,
    /// Milliseconds spent proving and authorizing.
    pub prove_millis: Option<u64>,
    /// Set when the fee is unusual ([`terms::guard_fee`]).
    pub fee_note: Option<String>,
    /// The fee guard: [`broadcast`] refuses a flagged fee without its acknowledgement.
    pub fee_guard: terms::FeeGuard,
    /// [`gate::Path::SaplingToPq`] of the recipient: what both gate layers check.
    pub path: gate::Path,
}

fn other(m: impl Into<String>) -> WalletError {
    WalletError::Other(m.into())
}

/// The ZIP-317 conventional fee of the shape with `notes` Sapling spends, one transparent output
/// of `script` and the Sapling outputs padded to two (the change, or none).
pub fn shape_fee(script: &[u8], notes: usize) -> i64 {
    let out = 8 + plan::compact(script.len()) + script.len();
    let extra = out.saturating_sub(params::ZIP317_OUTPUT_SIZE);
    plan::conventional_fee_bytes(0, 1, extra, notes, 1)
}

/// A planned Sapling -> post-quantum send: the recipient checked, the notes selected with their
/// paths. Next: fetch the notes' transactions ([`fetch_note_txs`]), then [`build_sapling_to_pq`].
#[derive(Clone, Debug)]
pub struct SaplingPqPlan {
    to: String,
    id: crate::pq::PqKeyId,
    script: Vec<u8>,
    amount: i64,
    amount_bumped: bool,
    picked: crate::shielded::NoteSpends,
    tip: u64,
    branch_id: u32,
}

impl SaplingPqPlan {
    /// The transactions that created the selected notes (internal order), to fetch.
    pub fn note_txids(&self) -> Vec<[u8; 32]> {
        let mut v: Vec<[u8; 32]> = self.picked.notes.iter().map(|n| n.txid).collect();
        v.sort();
        v.dedup();
        v
    }
}

/// Check the recipient and select the notes (from the store, with their paths) for a send of
/// `amount` zat from the private balance to the post-quantum address `to`, at `tip` under the
/// next block's `branch_id`. Nothing is built, stored or locked.
pub fn plan_sapling_to_pq(
    wallet: &mut Wallet,
    to: &str,
    amount: i64,
    tip: u64,
    branch_id: u32,
) -> Result<SaplingPqPlan, WalletError> {
    if amount <= 0 {
        return Err(other("amount must be positive"));
    }
    let to = to.trim();
    let id = match keys::parse_yec_destination(wallet.network, to)? {
        YecDestination::Pq(id) => id,
        _ => {
            return Err(other(
                "From your private balance this send pays a post-quantum address (sqf… or sqs…); other addresses use the automatic funding.",
            ))
        }
    };
    // ycash6 EnsurePQRecipientPayable
    if branch_id != VAULT_BRANCH_ID {
        return Err(other(
            "post-quantum addresses can be paid only once the vault upgrade is active at the next block",
        ));
    }
    if id.scheme == crate::pq::SCHEME_FN_DSA_512 && !wallet.pq_terms().falcon_at(tip + 1) {
        return Err(other(
            "an FN-DSA-512 (scheme 2) post-quantum address can be paid only once Falcon is active at the next block",
        ));
    }
    // never a YEC output that looks like a token
    let (amount, amount_bumped) = if amount == TOKEN_VALUE {
        (amount + 1, true)
    } else {
        (amount, false)
    };
    let script = crate::pq::pqpkh_script(&id)
        .ok_or_else(|| other("the address's scheme is not registered"))?;
    let picked = wallet
        .shielded_mut()?
        .select_spends(amount as u64, |n| shape_fee(&script, n) as u64)?;
    Ok(SaplingPqPlan {
        to: to.to_string(),
        id,
        script,
        amount,
        amount_bumped,
        picked,
        tip,
        branch_id,
    })
}

/// Fetch the transactions that created the plan's notes (`GetTransaction`), by txid.
pub async fn fetch_note_txs(
    client: &mut CompactClient,
    plan: &SaplingPqPlan,
) -> Result<std::collections::HashMap<[u8; 32], Vec<u8>>, WalletError> {
    let mut out = std::collections::HashMap::new();
    for txid in plan.note_txids() {
        let (raw, _) = client.get_transaction(&txid).await?.ok_or_else(|| {
            other(format!(
                "the server does not know transaction {}, which created a note being spent",
                txid_hex(&txid)
            ))
        })?;
        out.insert(txid, raw);
    }
    Ok(out)
}

/// Each selected note as the hybrid builder spends it: the note plaintext decrypted again from
/// its creating transaction (`fetched`, by txid) with the account's incoming viewing key of the
/// note's scope, and bound to the store's note: the fetched bytes must hash to the txid, the
/// output must decrypt, its commitment must equal the store's (so value, recipient and `rcm` are
/// the store's), and it must be a ZIP-212 note (its `rseed`). The paths are the store's.
pub fn note_spends(
    extsk: &sapling_crypto::zip32::ExtendedSpendingKey,
    notes: &[crate::shielded::SelectedNote],
    fetched: &std::collections::HashMap<[u8; 32], Vec<u8>>,
) -> Result<Vec<crate::sapling_part::SaplingSpend>, WalletError> {
    use sapling_crypto::note_encryption::{
        try_sapling_note_decryption, PreparedIncomingViewingKey, Zip212Enforcement,
    };
    let dfvk = extsk.to_diversifiable_full_viewing_key();
    let branch = zcash_protocol::consensus::BranchId::try_from(VAULT_BRANCH_ID)
        .map_err(|_| other("the vault branch id"))?;
    let mut out = Vec::with_capacity(notes.len());
    for n in notes {
        let t = txid_hex(&n.txid);
        let raw = fetched
            .get(&n.txid)
            .ok_or_else(|| other(format!("transaction {t} was not fetched")))?;
        // a v4 transaction reads the same under any branch id; the txid does not depend on it
        let tx = zcash_primitives::transaction::Transaction::read(&raw[..], branch)
            .map_err(|e| other(format!("transaction {t} does not parse: {e}")))?;
        if tx.txid().as_ref() != &n.txid {
            return Err(other(format!(
                "the server answered another transaction for {t}"
            )));
        }
        let o = tx
            .sapling_bundle()
            .and_then(|b| b.shielded_outputs().get(n.output_index as usize))
            .ok_or_else(|| {
                other(format!(
                    "transaction {t} has no Sapling output {}",
                    n.output_index
                ))
            })?;
        let scope = if n.internal {
            zip32::Scope::Internal
        } else {
            zip32::Scope::External
        };
        let ivk = PreparedIncomingViewingKey::new(&dfvk.to_ivk(scope));
        let (note, addr, _) = try_sapling_note_decryption(&ivk, o, Zip212Enforcement::GracePeriod)
            .ok_or_else(|| {
                other(format!(
                    "output {} of transaction {t} does not decrypt to this wallet",
                    n.output_index
                ))
            })?;
        if note.cmu().to_bytes() != n.cmu || note.value().inner() != n.value {
            return Err(other(format!(
                "output {} of transaction {t} is not the note the private wallet holds",
                n.output_index
            )));
        }
        let rseed = match note.rseed() {
            sapling_crypto::Rseed::AfterZip212(r) => *r,
            sapling_crypto::Rseed::BeforeZip212(_) => return Err(other(
                "a note from before ZIP-212 cannot be spent by this app; move it with a full node",
            )),
        };
        out.push(crate::sapling_part::SaplingSpend {
            recipient: hex::encode(addr.to_bytes()),
            value: n.value,
            rseed: hex::encode(rseed),
            after_zip212: true,
            internal: n.internal,
            position: n.position,
            path: n.path.clone(),
        });
    }
    Ok(out)
}

/// Prove and authorize the planned send with the notes' `fetched` transactions
/// ([`fetch_note_txs`]). Nothing is broadcast, stored or locked.
pub fn build_sapling_to_pq(
    wallet: &Wallet,
    side: &SaplingSide,
    plan: SaplingPqPlan,
    fetched: &std::collections::HashMap<[u8; 32], Vec<u8>>,
) -> Result<SaplingPqPreview, WalletError> {
    use crate::build::hybrid;
    use crate::sapling_part::{SaplingOut, SaplingPart};
    let SaplingPqPlan {
        to,
        id,
        script,
        amount,
        amount_bumped,
        picked,
        tip,
        branch_id,
    } = plan;
    let spends = note_spends(&side.extsk, &picked.notes, fetched)?;
    let fee = picked.fee_zat as i64;
    let change = picked.total_zat as i64 - amount - fee;
    if change < 0 {
        return Err(other(
            "the selected notes do not cover the amount and the fee",
        ));
    }
    let n_notes = spends.len();
    let mut tx = Transaction::new_v4();
    tx.expiry_height = (tip as u32).saturating_add(TX_EXPIRY_DELTA);
    tx.vout.push(TxOut {
        value: amount,
        script_pubkey: script.clone(),
    });
    let part = SaplingPart {
        target_height: (tip as u32).saturating_add(1),
        vault_height: None,
        spends,
        outputs: if change > 0 {
            vec![SaplingOut::Change { value: change }]
        } else {
            Vec::new()
        },
        anchor: picked.anchor,
        params_dir: side.params_dir.display().to_string(),
    };
    let started = std::time::Instant::now();
    let h = hybrid::sapling_prepare(
        side.extsk.clone(),
        wallet.network,
        &part,
        &tx,
        branch_id,
        rand_core::OsRng,
    )
    .map_err(|r| other(format!("{}: {}", r.0, r.1)))?;
    let (_, raw) = hybrid::sign_hybrid(h, tx, &[], branch_id, rand_core::OsRng)
        .map_err(|r| other(format!("{}: {}", r.0, r.1)))?;
    let prove_millis = Some(started.elapsed().as_millis() as u64);
    // the final bytes, parsed: exactly what the preview shows
    let (signed, txid) = Transaction::parse(&raw)?;
    if !signed.vin.is_empty()
        || signed.vout.len() != 1
        || signed.vout[0].script_pubkey != script
        || signed.vout[0].value != amount
    {
        return Err(other(
            "the built transaction does not pay exactly the recipient the preview shows",
        ));
    }
    if signed.shielded.spends != n_notes || signed.shielded.value_balance != amount + fee {
        return Err(other(format!(
            "the built transaction takes {} zat out of the private balance, not the {} zat the preview shows",
            signed.shielded.value_balance,
            amount + fee
        )));
    }
    let conventional = signed.zip317_conventional_fee(&[])?;
    if fee < conventional {
        return Err(other(format!(
            "the fee {} YEC is below the {} YEC this transaction needs",
            plan::format_money(fee),
            plan::format_money(conventional)
        )));
    }
    let limit = params::pq_send_fee_limit(raw.len(), conventional);
    if fee > limit {
        return Err(other(format!(
            "Fee {} YEC is above this app's limit of {} YEC for this send. Nothing was sent.",
            plan::format_money(fee),
            plan::format_money(limit)
        )));
    }
    let fee_guard = wallet.guard_fee(
        terms::FeeKind::Plain,
        fee,
        raw.len(),
        conventional,
        &txid_hex(&txid),
    )?;
    let fee_note = fee_guard.note.clone();
    let path = gate::Path::SaplingToPq(id);
    gate::check(path, &raw, |op| wallet.store.utxo_class(op).ok().flatten())?;
    Ok(SaplingPqPreview {
        to,
        id,
        amount,
        amount_bumped,
        fee,
        change,
        notes: n_notes as u32,
        expiry_height: signed.expiry_height,
        raw,
        txid,
        branch_id,
        prove_millis,
        fee_note,
        fee_guard,
        path,
    })
}

/// Both gate layers on the preview ([`gate::Path::SaplingToPq`]: the node must say `ok, burned
/// 0`; a server without Yellowback refuses it), then `SendTransaction`. The send has no
/// transparent input, so there is nothing for layer 3 (provenance) to fetch and nothing to lock
/// in the transparent store; once the server has it (or its fate is unknown) the private store
/// records it ([`crate::shielded::Shielded::record_sent`]), so its notes count as spent until it
/// is mined or expires. A send the server certainly refused records nothing and returns its error;
/// any other failure says `…; status unknown, txid <txid>: check before sending again`.
pub async fn broadcast(
    wallet: &mut Wallet,
    client: &mut CompactClient,
    validator: &mut Validator,
    p: &SaplingPqPreview,
    accept_unusual_fee: Option<&str>,
) -> Result<(String, Validation), WalletError> {
    terms::require_ack(&p.fee_guard, accept_unusual_fee)?;
    let (_, validation) = gate::confirm(validator, p.path, &p.raw, |op| {
        wallet.store.utxo_class(op).ok().flatten()
    })
    .await?;
    let validation = validation.ok_or(gate::GateError::NoDryRunForPqSend)?;
    if validation.fee_zat != 0 {
        return Err(other(format!(
            "the node's dry run reports a Yellowback fee of {} zat on a plain YEC send; nothing was sent",
            validation.fee_zat
        )));
    }
    let txid = txid_hex(&p.txid);
    match mint::send(client, &p.raw, &p.txid).await {
        Ok(()) => {
            wallet.shielded_mut()?.record_sent(&p.raw, p.branch_id)?;
            Ok((txid, validation))
        }
        Err(e) if mint::send_refused(&e) => Err(e),
        Err(e) => {
            let recorded = wallet.shielded_mut()?.record_sent(&p.raw, p.branch_id);
            let also = match recorded {
                Ok(()) => String::new(),
                Err(r) => format!(" (recording it in the private wallet failed: {r})"),
            };
            Err(other(format!(
                "{e}; status unknown, txid {txid}: check before sending again{also}"
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fee of the shape: one `TX_PQPKH` output (35-byte script, 44 bytes: two ZIP-317
    /// transparent actions) and two padded Sapling outputs; more spends cost more above two (Ycash's
    /// ZIP-317 marginal fee is 500 zat).
    #[test]
    fn shape_fee_counts_the_longer_output() {
        let id = crate::pq::PqKeyId {
            scheme: crate::pq::SCHEME_FN_DSA_512,
            hash: [1; 32],
        };
        let s = crate::pq::pqpkh_script(&id).unwrap();
        assert_eq!(
            shape_fee(&s, 1),
            plan::conventional_fee_bytes(0, 1, 10, 1, 1)
        );
        assert_eq!(shape_fee(&s, 1), 2_000);
        assert_eq!(shape_fee(&s, 3), 2_500);
        let p2pkh = crate::script::p2pkh_script(&[2; 20]);
        assert_eq!(shape_fee(&p2pkh, 1), 1_500);
    }

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn params_dir() -> std::path::PathBuf {
        if let Ok(d) = std::env::var("YEW_SAPLING_PARAMS") {
            return d.into();
        }
        let home = std::env::var("HOME").unwrap_or_default();
        if cfg!(target_os = "macos") {
            format!("{home}/Library/Application Support/ZcashParams").into()
        } else {
            format!("{home}/.zcash-params").into()
        }
    }

    /// A wallet whose private store holds notes of `values` (scanned by the store's own scanner,
    /// [`crate::shielded::Shielded::receive_for_test`]) at a tip of 120, the vault upgrade active.
    fn wallet_with_notes(name: &str, values: &[u64]) -> (Wallet, std::path::PathBuf, Fetched) {
        let dir = std::env::temp_dir().join(format!("yew-saplingpq-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("w.sqlite");
        let mut w = Wallet::open(
            path.to_str().unwrap(),
            crate::params::Network::Regtest,
            PHRASE,
            "",
            Some(100),
        )
        .unwrap();
        w.set_vault_activation(Some(1)).unwrap();
        let raw = w
            .shielded_mut()
            .unwrap()
            .receive_for_test(100, 120, values, &params_dir());
        let (_, txid) = Transaction::parse(&raw).unwrap();
        let fetched = [(txid, raw)].into_iter().collect();
        (w, dir, fetched)
    }

    type Fetched = std::collections::HashMap<[u8; 32], Vec<u8>>;

    /// The refusal's text (a built preview is too large to print).
    fn err(r: Result<SaplingPqPreview, WalletError>) -> String {
        match r {
            Ok(p) => panic!("built, fee {} change {}", p.fee, p.change),
            Err(e) => e.to_string(),
        }
    }

    /// Plan then build, as the API does (the fetch answered by `fetched`).
    fn build(
        w: &mut Wallet,
        side: &SaplingSide,
        to: &str,
        amount: i64,
        branch_id: u32,
        fetched: &Fetched,
    ) -> Result<SaplingPqPreview, WalletError> {
        let plan = plan_sapling_to_pq(w, to, amount, 120, branch_id)?;
        build_sapling_to_pq(w, side, plan, fetched)
    }

    /// Item 1 end to end through the builder the app calls: notes and paths from the store, the
    /// one `TX_PQPKH` output, Sapling change back to the account's internal address, the fee of
    /// the shape, `valueBalance` = amount + fee; the bytes parse under the Vault branch, the
    /// Sapling bundle verifies (proofs, spend authorizations, binding signature over the shielded
    /// sighash recomputed from the bytes), the change decrypts to the internal key; the gate's
    /// SaplingToPq path admits it for the named key only and every other path refuses it; once
    /// recorded, its notes are spent in the store.
    #[test]
    fn sapling_to_pq_end_to_end() {
        use zcash_primitives::transaction::sighash::SignableInput;
        use zcash_primitives::transaction::sighash_v4::v4_signature_hash;
        let (mut w, dir, f) = wallet_with_notes("e2e", &[2_000_000, 500_000]);
        let b = w.shielded().unwrap().balance().unwrap();
        assert!(b.sendable, "{b:?}");
        assert_eq!(b.spendable_zat, 2_500_000);
        let id = crate::pq::PqKeyId {
            scheme: crate::pq::SCHEME_SLH_DSA_SHA2_128S,
            hash: [0x5a; 32],
        };
        let to = keys::encode_pq_yec(w.network, &id).unwrap();
        let side = SaplingSide::of(&w, &params_dir()).unwrap();
        // not before the vault upgrade; not to a non-PQ recipient
        let e = err(build(&mut w, &side, &to, 1_000_000, 0x4dec4df0, &f));
        assert!(e.contains("vault upgrade is active"), "{e}");
        let ecc = keys::encode_p2pkh(w.network, &[3; 20]);
        let e = err(build(&mut w, &side, &ecc, 1_000_000, VAULT_BRANCH_ID, &f));
        assert!(e.contains("post-quantum address"), "{e}");
        let e = err(build(&mut w, &side, &to, 2_499_000, VAULT_BRANCH_ID, &f));
        assert!(e.starts_with("Not enough private YEC"), "{e}");

        // the notes' transactions must be fetched and be exactly the txid's bytes
        let empty = Fetched::new();
        let e = err(build(
            &mut w,
            &side,
            &to,
            1_000_000,
            VAULT_BRANCH_ID,
            &empty,
        ));
        assert!(e.contains("was not fetched"), "{e}");
        let mut tampered = f.clone();
        for raw in tampered.values_mut() {
            raw[14] ^= 1; // nExpiryHeight
        }
        let e = err(build(
            &mut w,
            &side,
            &to,
            1_000_000,
            VAULT_BRANCH_ID,
            &tampered,
        ));
        assert!(e.contains("another transaction"), "{e}");
        // more than either note: the store's selection (its order is not fixed) takes both
        let p = build(&mut w, &side, &to, 2_200_000, VAULT_BRANCH_ID, &f).unwrap();
        assert_eq!(p.path, gate::Path::SaplingToPq(id));
        let script = crate::pq::pqpkh_script(&id).unwrap();
        assert_eq!(p.notes, 2);
        assert_eq!(p.fee, shape_fee(&script, 2));
        assert_eq!(p.amount + p.fee + p.change, 2_500_000);
        assert_eq!(p.expiry_height, 120 + TX_EXPIRY_DELTA);
        let (tx, txid) = Transaction::parse(&p.raw).unwrap();
        assert_eq!(txid, p.txid);
        assert!(tx.vin.is_empty());
        assert_eq!(tx.vout.len(), 1);
        assert_eq!(tx.vout[0].script_pubkey, script);
        assert_eq!(tx.vout[0].value, 2_200_000);
        assert_eq!(tx.shielded.spends, 2);
        assert_eq!(tx.shielded.value_balance, 2_200_000 + p.fee);
        // the verifying path
        let branch = zcash_protocol::consensus::BranchId::try_from(VAULT_BRANCH_ID).unwrap();
        let ztx = zcash_primitives::transaction::Transaction::read(&p.raw[..], branch).unwrap();
        let shielded: [u8; 32] = v4_signature_hash(&ztx, &SignableInput::Shielded)
            .as_ref()
            .try_into()
            .unwrap();
        let sb = ztx.sapling_bundle().cloned().unwrap();
        let dfvk = side.extsk.to_diversifiable_full_viewing_key();
        let ivk = sapling_crypto::note_encryption::PreparedIncomingViewingKey::new(
            &dfvk.to_ivk(zip32::Scope::Internal),
        );
        let change: Vec<_> = sb
            .shielded_outputs()
            .iter()
            .filter_map(|o| {
                sapling_crypto::note_encryption::try_sapling_note_decryption(
                    &ivk,
                    o,
                    sapling_crypto::note_encryption::Zip212Enforcement::On,
                )
            })
            .collect();
        assert_eq!(change.len(), 1, "one change note to the internal address");
        assert_eq!(change[0].0.value().inner() as i64, p.change);
        let dir_p = params_dir();
        let params = zcash_proofs::load_parameters(
            &dir_p.join(crate::sapling_params::SPEND.name),
            &dir_p.join(crate::sapling_params::OUTPUT.name),
            None,
        );
        let mut bv = sapling_crypto::BatchValidator::new();
        assert!(bv.check_bundle(sb, shielded));
        assert!(bv.validate(
            &params.spend_params.verifying_key(),
            &params.output_params.verifying_key(),
            rand_core::OsRng
        ));
        // the gate: this path for this key only
        let none = |_: &crate::tx::OutPoint| None;
        assert!(gate::check(gate::Path::SaplingToPq(id), &p.raw, none).is_ok());
        let other_id = crate::pq::PqKeyId {
            scheme: id.scheme,
            hash: [0x77; 32],
        };
        assert!(gate::check(gate::Path::SaplingToPq(other_id), &p.raw, none).is_err());
        assert!(gate::check(gate::Path::Shielded, &p.raw, none).is_err());
        assert!(gate::check(gate::Path::Yec, &p.raw, none).is_err());
        assert!(gate::check(gate::Path::PqSpend, &p.raw, none).is_err());
        // recorded (as broadcast does): its notes are spent in the store, the change is pending
        w.shielded_mut()
            .unwrap()
            .record_sent(&p.raw, VAULT_BRANCH_ID)
            .unwrap();
        let after = w.shielded().unwrap().balance().unwrap();
        assert_eq!(after.spendable_zat, 0, "{after:?}");
        let e = err(build(&mut w, &side, &to, 100_000, VAULT_BRANCH_ID, &f));
        assert!(e.starts_with("Not enough private YEC"), "{e}");
        drop(w);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Exactly TOKEN_VALUE is raised by one zat; an amount needing both notes spends both, with
    /// the fee of two spends.
    #[test]
    fn token_value_bump_and_two_notes() {
        let (mut w, dir, f) = wallet_with_notes("two", &[300_000, 300_000]);
        let id = crate::pq::PqKeyId {
            scheme: crate::pq::SCHEME_SLH_DSA_SHA2_128S,
            hash: [0x5b; 32],
        };
        let to = keys::encode_pq_yec(w.network, &id).unwrap();
        let side = SaplingSide::of(&w, &params_dir()).unwrap();
        let p = build(&mut w, &side, &to, TOKEN_VALUE, VAULT_BRANCH_ID, &f).unwrap();
        assert!(p.amount_bumped);
        assert_eq!(p.amount, TOKEN_VALUE + 1);
        let p = build(&mut w, &side, &to, 500_000, VAULT_BRANCH_ID, &f).unwrap();
        let script = crate::pq::pqpkh_script(&id).unwrap();
        assert_eq!(p.notes, 2);
        assert_eq!(p.fee, shape_fee(&script, 2));
        assert_eq!(p.amount + p.fee + p.change, 600_000);
        drop(w);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
