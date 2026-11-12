// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! Move YEC between the wallet's own public and private balances (yew-shielded plan S4): one
//! explicit action, two directions, the same preview / gate / confirm as a send.
//!
//! - **To private (shield, t→z):** transparent `YEC` coins only — `coins::select_yec` without
//!   the reserve, so the fee reserve and every YED-bearing, locked, pending or held output stay
//!   where they are — into one Sapling output to the wallet's own default `ys1…` address, with
//!   transparent change back to the next change address. Built by the librustzcash6 builder
//!   (`Shielded::build_shield`, ZIP-317 fee): YEW's own serializer makes no Sapling outputs,
//!   and the light library's shielding (`zcash_client_backend` transparent support) would pick
//!   coins from its own UTXO table by its own rules, blind to YEW's coin classes. Gate path
//!   [`GatePath::Shield`] (inputs class `YEC` only).
//! - **To public (unshield, z→t):** a private spend to the wallet's own current public `s…`
//!   address through the existing private send path (`Shielded::plan`, gate path `Shielded`).
//!   The amount becomes visible on the chain, so the plan says `reveals_shielded`.
//!
//! "All" moves everything the direction can: every `YEC` coin less the fee, or every spendable
//! note less the fee.

use std::path::Path;

use crate::build::yec_private::{Confirmed, Funding, YecSendPlan};
use crate::build::yec_send::MIN_CHANGE;
use crate::coins::{self, Utxo};
use crate::gate::{self, Path as GatePath, Validator};
use crate::net::CompactClient;
use crate::params::{MAX_INPUTS, TOKEN_VALUE, TX_EXPIRY_DELTA};
use crate::script;
use crate::shielded::{ShieldInput, ShieldTo, ShieldedError};
use crate::store::HistoryRow;
use crate::tx::{txid_hex, OutPoint};
use crate::wallet::{Wallet, WalletError};

/// Which way a move goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Public (transparent) YEC into the private (Sapling) balance.
    ToPrivate,
    /// Private YEC out to the wallet's own public address.
    ToPublic,
}

/// A planned shield: what the preview shows and what confirm proves and signs.
#[derive(Clone, Debug)]
pub struct ShieldPlan {
    /// The Sapling address paid: the wallet's own default one (a move), or another wallet's
    /// ([`plan_shield_to`]).
    pub to: String,
    /// The output's destination as the builder takes it (and the fee rule that goes with it).
    pub dest: ShieldTo,
    /// The memo of a shield to another wallet.
    pub memo: Option<String>,
    /// Into the private balance, zat.
    pub amount: i64,
    /// The amount was raised to absorb a change of exactly `TOKEN_VALUE` or of dust.
    pub amount_bumped: bool,
    /// The ZIP-317 fee, zat.
    pub fee: i64,
    /// Transparent change, zat (0 = none).
    pub change: i64,
    /// The change address (`s…`) and its key hash when `change > 0`.
    pub change_address: Option<(String, [u8; 20])>,
    /// The coins spent (class `YEC` only).
    pub inputs: Vec<Utxo>,
    /// The same coins as the builder takes them.
    pub shield_inputs: Vec<ShieldInput>,
    /// The height the transaction is built for (the tip + 1).
    pub target: u32,
    /// `nExpiryHeight` (target + 40).
    pub expiry_height: u32,
}

/// Plan a move of `amount` zat (`None`: everything the direction can move) after a sync at
/// `tip`. Nothing is signed, proved or locked. To private, the coins come from one public
/// address unless `allow_linking` (the user's go-ahead after
/// [`coins::CoinError::LinkingNeeded`]; beta2 D-5: ycashd's `z_sendmany` asks for
/// `AllowLinkingAccountAddresses` before it shields coins of several addresses together).
pub fn plan_move(
    wallet: &mut Wallet,
    direction: Direction,
    amount: Option<i64>,
    allow_linking: bool,
    tip: u64,
) -> Result<YecSendPlan, WalletError> {
    if matches!(amount, Some(a) if a <= 0) {
        return Err(WalletError::Other("amount must be positive".into()));
    }
    match direction {
        Direction::ToPrivate => {
            let p = plan_shield(wallet, amount, allow_linking, tip)?;
            Ok(YecSendPlan {
                funding: Funding::Shield(Box::new(p)),
                reveals_shielded: false,
            })
        }
        Direction::ToPublic => {
            let to = wallet.receive_address(false)?.address_s;
            let sh = wallet.shielded_mut()?;
            let plan = match amount {
                Some(a) => sh.plan(&to, a as u64, None)?,
                None => {
                    // Everything spendable less the fee, which depends on the notes spent: ask
                    // for the balance less a first guess and correct by what the proposal says
                    // it needs (at most a few rounds; the fee only grows with note count).
                    let b = sh.balance()?;
                    if !b.sendable {
                        return Err(ShieldedError::NotSynced {
                            scanned: b.scanned_height,
                            tip: b.tip_height,
                        }
                        .into());
                    }
                    let mut fee = 15_000u64;
                    let mut out = None;
                    for _ in 0..8 {
                        let want = b.spendable_zat.checked_sub(fee).filter(|w| *w > 0).ok_or(
                            ShieldedError::Insufficient {
                                available: b.spendable_zat,
                                required: fee + 1,
                            },
                        )?;
                        match sh.plan(&to, want, None) {
                            Ok(p) if p.amount_zat + p.fee_zat + p.change_zat == b.spendable_zat => {
                                out = Some(p);
                                break;
                            }
                            // Over-estimated: the change is the slack; take it next round.
                            Ok(p) => fee = p.fee_zat,
                            Err(ShieldedError::Insufficient { required, .. }) => {
                                fee = required - want;
                            }
                            Err(e) => return Err(e.into()),
                        }
                    }
                    out.ok_or_else(|| {
                        WalletError::Other("could not settle the fee for moving everything".into())
                    })?
                }
            };
            Ok(YecSendPlan {
                funding: Funding::Shielded(Box::new(plan)),
                reveals_shielded: true,
            })
        }
    }
}

fn plan_shield(
    wallet: &Wallet,
    amount: Option<i64>,
    allow_linking: bool,
    tip: u64,
) -> Result<ShieldPlan, WalletError> {
    let sh = wallet.shielded()?;
    let to = sh.default_address().1;
    let target = (tip as u32).saturating_add(1);
    let spendable = wallet.spendable_utxos()?;
    let change_row = wallet.change_address()?;
    let change_h = change_row.hash160;

    // The coins: class YEC only (no reserve override exists on this path).
    let (inputs, mut amount_zat, mut change, fee) = match amount {
        None => {
            let mut all: Vec<Utxo> = spendable
                .iter()
                .filter(|u| u.class == coins::UtxoClass::Yec)
                .cloned()
                .collect();
            all.sort_by_key(|u| std::cmp::Reverse(u.value));
            all.truncate(MAX_INPUTS);
            if all.is_empty() {
                return Err(coins::CoinError::Insufficient { need: 1, have: 0 }.into());
            }
            // "All" spends every address's coins: without the go-ahead only when there is one.
            if !allow_linking && coins::distinct_addresses(&all) > 1 {
                let mut per: std::collections::BTreeMap<&[u8], i64> = Default::default();
                for u in &all {
                    *per.entry(u.script.as_slice()).or_default() += u.value;
                }
                return Err(coins::CoinError::LinkingNeeded {
                    need: all.iter().map(|u| u.value).sum(),
                    best_one: per.values().copied().max().unwrap_or(0),
                }
                .into());
            }
            let si = shield_inputs(wallet, &all)?;
            let total: i64 = all.iter().map(|u| u.value).sum();
            let fee = sh.shield_fee(target, &si, &ShieldTo::Own, total as u64, None)? as i64;
            if total <= fee {
                return Err(coins::CoinError::Insufficient {
                    need: fee + 1,
                    have: total,
                }
                .into());
            }
            (all, total - fee, 0, fee)
        }
        Some(a) => {
            // The fee depends on how many coins are spent: select for amount + fee, recompute
            // the fee for that selection, repeat until it holds (it only grows with inputs).
            let mut fee = 10_000i64;
            loop {
                let sel = coins::select_yec_linking(&spendable, a + fee, false, allow_linking)?;
                let si = shield_inputs(wallet, &sel)?;
                let f =
                    sh.shield_fee(target, &si, &ShieldTo::Own, a as u64, Some(change_h))? as i64;
                let total: i64 = sel.iter().map(|u| u.value).sum();
                if total >= a + f {
                    break (sel, a, total - a - f, f);
                }
                fee = f;
            }
        }
    };
    // No transparent output may look like a token, and dust change is not worth an output:
    // either goes into the private amount instead (the fee does not change — with at least
    // one input, ZIP-317 counts max(inputs, outputs) transparent actions).
    let mut amount_bumped = false;
    if change == TOKEN_VALUE {
        change -= 1;
        amount_zat += 1;
        amount_bumped = true;
    }
    if change > 0 && change < MIN_CHANGE {
        amount_zat += change;
        change = 0;
        amount_bumped = true;
    }
    let shield_inputs = shield_inputs(wallet, &inputs)?;
    Ok(ShieldPlan {
        to,
        dest: ShieldTo::Own,
        memo: None,
        amount: amount_zat,
        amount_bumped,
        fee,
        change,
        change_address: (change > 0).then(|| (change_row.address_s.clone(), change_h)),
        inputs,
        shield_inputs,
        target,
        expiry_height: target.saturating_add(TX_EXPIRY_DELTA),
    })
}

/// Plan a send of `amount` zat from the public balance to another wallet's Sapling address `to`
/// (real-stack run WEB-REAL MEDIUM-4: before, a Sapling recipient was paid from private notes
/// only). The shape of ycash6's `z_sendmany` from transparent addresses to a Sapling address:
/// transparent `YEC` coins only (`coins::select_yec_linking` without the reserve, so the fee reserve and
/// every YED-bearing, locked, pending or held output stay where they are), one Sapling output to
/// `to` with the optional `memo`, transparent change to a fresh change address of this wallet (as
/// the node's change from transparent addresses, and as every other public-balance send here),
/// and the node's fee for that shape ([`ShieldTo::fixed_fee`], 1,000 zat). The recipient gets
/// exactly `amount`: a change of dust goes to the fee, and a change of exactly `TOKEN_VALUE` is one
/// zat less (that zat to the fee), never to the recipient. Confirm is [`confirm_shield`] (gate path [`GatePath::Shield`], the held-YED guard,
/// the provenance layer, the built fee equal to the previewed one).
///
/// The coins come from one public address, as every other public-balance send (beta2 D-5,
/// [`coins::select_yec_linking`]): when only several addresses together cover the send the
/// answer is [`coins::CoinError::LinkingNeeded`], and `allow_linking` (the user's go-ahead after
/// that question) combines them. A shell with no go-ahead step (the browser) passes `false` and
/// shows the refusal.
pub fn plan_shield_to(
    wallet: &Wallet,
    to: &str,
    memo: Option<&str>,
    amount: i64,
    allow_linking: bool,
    tip: u64,
) -> Result<ShieldPlan, WalletError> {
    if amount <= 0 {
        return Err(WalletError::Other("amount must be positive".into()));
    }
    let sh = wallet.shielded()?;
    let to = to.trim();
    sh.sapling_recipient(to)?;
    let memo = memo
        .map(str::trim_end)
        .filter(|m| !m.is_empty())
        .map(str::to_string);
    if let Some(m) = &memo {
        crate::shielded::memo_to_bytes(m)?;
    }
    let base_fee = ShieldTo::node_fee() as i64;
    let target = (tip as u32).saturating_add(1);
    let spendable = wallet.spendable_utxos()?;
    let inputs = coins::select_yec_linking(&spendable, amount + base_fee, false, allow_linking)?;
    let total: i64 = inputs.iter().map(|u| u.value).sum();
    let mut change = total - amount - base_fee;
    let mut fee = base_fee;
    if change == TOKEN_VALUE {
        // never an output that looks like a token: one zat less change, as the public send does
        change -= 1;
        fee += 1;
    } else if change > 0 && change < MIN_CHANGE {
        fee += change;
        change = 0;
    }
    let dest = ShieldTo::Recipient {
        address: to.to_string(),
        memo: memo.clone(),
        fee: fee as u64,
    };
    let change_row = wallet.change_address()?;
    let shield_inputs = shield_inputs(wallet, &inputs)?;
    // the builder takes the shape (recipient, memo, change) before anything is signed
    let f = sh.shield_fee(
        target,
        &shield_inputs,
        &dest,
        amount as u64,
        (change > 0).then_some(change_row.hash160),
    )? as i64;
    debug_assert_eq!(f, fee);
    Ok(ShieldPlan {
        to: to.to_string(),
        dest,
        memo,
        amount,
        amount_bumped: false,
        fee,
        change,
        change_address: (change > 0).then(|| (change_row.address_s.clone(), change_row.hash160)),
        inputs,
        shield_inputs,
        target,
        expiry_height: target.saturating_add(TX_EXPIRY_DELTA),
    })
}

/// The builder's view of `coins`: P2PKH outputs of own keys (public keys only; the secrets are
/// fetched at confirm).
fn shield_inputs(wallet: &Wallet, coins: &[Utxo]) -> Result<Vec<ShieldInput>, WalletError> {
    coins
        .iter()
        .map(|u| {
            let h = script::p2pkh_hash(&u.script).ok_or_else(|| {
                WalletError::Other(format!("input {} is not P2PKH", u.outpoint.display()))
            })?;
            let key = wallet.key_for_hash(&h)?.ok_or_else(|| {
                WalletError::Other(format!("no key for input {}", u.outpoint.display()))
            })?;
            Ok(ShieldInput {
                txid: u.outpoint.txid,
                n: u.outpoint.n,
                value: u.value as u64,
                pubkey: key.pubkey,
                hash160: h,
            })
        })
        .collect()
}

/// Confirm a shield: check the server's branch id, prove and sign (keys fetched for this call
/// only), both gate layers on [`GatePath::Shield`], broadcast, then the bookkeeping a
/// transparent send does (locks, pending record, history row, own change output).
pub async fn confirm_shield(
    wallet: &mut Wallet,
    client: &mut CompactClient,
    validator: &mut Validator,
    plan: &ShieldPlan,
    params_dir: &Path,
) -> Result<Confirmed, WalletError> {
    let chain = match validator.client_mut() {
        Some(yb) => yb.chain_info_vault().await?,
        None => None,
    };
    let network = wallet.network;
    // The vault upgrade's activation height (regtest) comes with the same answer.
    if let Some((_, _, vault)) = chain {
        wallet.set_vault_activation(vault)?;
    }
    let chain = chain.map(|(h, id, _)| (h, id));
    let mut secrets = Vec::with_capacity(plan.inputs.len());
    for i in &plan.shield_inputs {
        let key = wallet
            .key_for_hash(&i.hash160)?
            .ok_or_else(|| WalletError::Other("no key for a shield input".into()))?;
        secrets.push(key.secret.to_secret_bytes());
    }
    let info = match chain {
        Some(c) => Ok(c),
        None => client
            .lightd_info_for(network)
            .await
            .map(|i| (i.block_height, i.branch_id)),
    };
    let sh = wallet.shielded_mut()?;
    let built = match info {
        Ok((height, id)) => sh
            .check_branch_at(height, id, chain.is_some(), Some(plan.target))
            .and_then(|_| {
                sh.build_shield(
                    plan.target,
                    &plan.shield_inputs,
                    &secrets,
                    &plan.dest,
                    plan.amount as u64,
                    plan.change_address
                        .as_ref()
                        .map(|(_, h)| (*h, plan.change as u64)),
                    params_dir,
                )
            }),
        Err(e) => Err(e.into()),
    };
    for s in secrets.iter_mut() {
        crate::keys::wipe(s);
    }
    let built = built?;
    if built.fee_zat != plan.fee as u64 {
        return Err(WalletError::Other(format!(
            "the built fee {} differs from the previewed {}",
            built.fee_zat, plan.fee
        )));
    }
    // the has-held-YED guard (beta2 item 32): a wallet that held YED spends transparent YEC
    // only where Yellowback tells its YED outputs apart
    gate::refuse_held_absent(validator, GatePath::Shield, wallet.has_held_yed()?)?;
    gate::confirm(validator, GatePath::Shield, &built.raw, |op| {
        wallet.store.utxo_class(op).ok().flatten()
    })
    .await?;
    // layer 3: no input carries YED by its creating transaction (review YEW-REVIEW-3)
    gate::confirm_provenance(
        client,
        GatePath::Shield,
        &built.raw,
        |op| wallet.store.utxo_class(op).ok().flatten(),
        |op| wallet.store.utxo_txout(op).ok().flatten(),
    )
    .await?;
    let reply = client.send_transaction(built.raw.clone()).await?;
    let txid = txid_hex(&built.txid);
    if !reply.is_empty() && reply != txid {
        return Err(WalletError::Other(format!(
            "server replied {reply} for txid {txid}"
        )));
    }
    let reason = format!("spent-by:{txid}");
    for u in &plan.inputs {
        wallet
            .store
            .lock(&u.outpoint, &reason, built.expiry_height as u64)?;
    }
    wallet
        .store
        .insert_pending_tx(&built.txid, &built.raw, built.expiry_height as u64)?;
    let spent: i64 = plan.inputs.iter().map(|u| u.value).sum();
    wallet.store.upsert_history(&HistoryRow {
        txid: built.txid,
        height: 0,
        yec_delta: plan.change - spent,
        has_payload: false,
        pending: true,
        shielded: true,
        yed_delta: 0,
        kind: String::new(),
        verdict: String::new(),
        label: String::new(),
        labelled: true,
    })?;
    if let Some((_, h)) = &plan.change_address {
        wallet.store.mark_used(h)?;
        // The builder writes the one transparent output (the change) at index 0.
        wallet.store.insert_own_output(
            &OutPoint {
                txid: built.txid,
                n: 0,
            },
            plan.change,
            h,
        )?;
    }
    Ok(Confirmed {
        txid,
        params_millis: built.params_millis,
        prove_millis: built.prove_millis,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coins::UtxoClass;
    use crate::keys;
    use crate::params::Network;

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    /// A wallet with a private store and the given transparent coins on its first addresses.
    fn wallet_with(name: &str, values: &[(i64, UtxoClass)]) -> (Wallet, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("yew-move-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("w.sqlite");
        let mut w = Wallet::open(
            path.to_str().unwrap(),
            Network::Regtest,
            PHRASE,
            "",
            Some(5),
        )
        .unwrap();
        let rows = w.addresses().unwrap();
        let utxos: Vec<Utxo> = values
            .iter()
            .enumerate()
            .map(|(i, (v, c))| {
                let row = &rows[i % rows.len()];
                Utxo {
                    outpoint: OutPoint {
                        txid: [i as u8 + 1; 32],
                        n: 0,
                    },
                    address: row.address_s.clone(),
                    script: script::p2pkh_script(&row.hash160),
                    value: *v,
                    height: 10,
                    class: *c,
                    cents: 0,
                }
            })
            .collect();
        w.store.replace_utxos(&utxos).unwrap();
        (w, dir)
    }

    fn shield(p: &YecSendPlan) -> &ShieldPlan {
        match &p.funding {
            Funding::Shield(s) => s,
            other => panic!("not a shield: {other:?}"),
        }
    }

    #[test]
    fn shield_spends_plain_yec_only_and_keeps_the_reserve() {
        let (mut w, dir) = wallet_with(
            "only",
            &[
                (100_000_000, UtxoClass::Yec),
                (50_000_000, UtxoClass::Yec),
                (105_000, UtxoClass::FeeReserve),
                (TOKEN_VALUE, UtxoClass::Token),
                (TOKEN_VALUE, UtxoClass::Held),
                (7_000_000, UtxoClass::Vault),
            ],
        );
        let own_z = w.shielded().unwrap().default_address().1;
        // 1 YEC: the smallest coin that covers it, one input + change + two padded Sapling
        // outputs = three logical actions = 15,000 zat; change back to a change address.
        let p = plan_move(&mut w, Direction::ToPrivate, Some(40_000_000), false, 100).unwrap();
        assert!(!p.reveals_shielded);
        let s = shield(&p);
        assert_eq!(s.to, own_z);
        assert_eq!((s.amount, s.fee, s.inputs.len()), (40_000_000, 15_000, 1));
        assert_eq!(s.inputs[0].value, 50_000_000);
        assert_eq!(s.change, 50_000_000 - 40_000_000 - 15_000);
        assert!(s.change_address.is_some());
        assert_eq!((s.target, s.expiry_height), (101, 141));
        assert_eq!(p.amount_zat(), 40_000_000);
        assert_eq!(p.fee_zat(), 15_000);
        // Two inputs, from two public addresses: only with the go-ahead (beta2 D-5), which the
        // refusal asks for; then four logical actions.
        let e = plan_move(&mut w, Direction::ToPrivate, Some(120_000_000), false, 100).unwrap_err();
        assert!(
            matches!(
                e,
                WalletError::Coins(coins::CoinError::LinkingNeeded {
                    best_one: 100_000_000,
                    ..
                })
            ),
            "{e}"
        );
        let p = plan_move(&mut w, Direction::ToPrivate, Some(120_000_000), true, 100).unwrap();
        assert_eq!((shield(&p).inputs.len(), shield(&p).fee), (2, 20_000));
        // All: every YEC coin, never the reserve or anything YED, no change; two addresses, so
        // only with the go-ahead.
        let e = plan_move(&mut w, Direction::ToPrivate, None, false, 100).unwrap_err();
        assert!(
            matches!(
                e,
                WalletError::Coins(coins::CoinError::LinkingNeeded {
                    need: 150_000_000,
                    best_one: 100_000_000
                })
            ),
            "{e}"
        );
        let p = plan_move(&mut w, Direction::ToPrivate, None, true, 100).unwrap();
        let s = shield(&p);
        assert!(s.inputs.iter().all(|u| u.class == UtxoClass::Yec));
        assert_eq!(s.inputs.len(), 2);
        assert_eq!(
            (s.amount, s.change, s.fee),
            (150_000_000 - 20_000, 0, 20_000)
        );
        assert!(s.change_address.is_none());
        // More than the plain YEC: refused (the reserve is not an override here).
        let e = plan_move(&mut w, Direction::ToPrivate, Some(150_000_000), false, 100).unwrap_err();
        assert!(matches!(e, WalletError::Coins(_)), "{e}");
        assert!(plan_move(&mut w, Direction::ToPrivate, Some(0), false, 100).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn shield_change_never_looks_like_a_token_or_dust() {
        let (mut w, dir) = wallet_with("change", &[(1_000_000, UtxoClass::Yec)]);
        let fee = 15_000;
        let p = plan_move(
            &mut w,
            Direction::ToPrivate,
            Some(1_000_000 - fee - TOKEN_VALUE),
            false,
            7,
        )
        .unwrap();
        let s = shield(&p);
        assert_eq!((s.change, s.amount_bumped), (TOKEN_VALUE - 1, true));
        assert_eq!(s.amount + s.change + s.fee, 1_000_000);
        let p = plan_move(
            &mut w,
            Direction::ToPrivate,
            Some(1_000_000 - fee - 40),
            false,
            7,
        )
        .unwrap();
        let s = shield(&p);
        assert_eq!(
            (s.change, s.amount, s.amount_bumped),
            (0, 1_000_000 - fee, true)
        );
        assert!(s.change_address.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unshield_goes_to_the_own_public_address_and_needs_a_scan() {
        let (mut w, dir) = wallet_with("unshield", &[]);
        // No scan yet: the private side says so, it never falls back to anything else.
        for amount in [Some(1_000), None] {
            let e = plan_move(&mut w, Direction::ToPublic, amount, false, 100).unwrap_err();
            assert!(
                matches!(e, WalletError::Shielded(ShieldedError::NotSynced { .. })),
                "{e}"
            );
        }
        // An empty wallet cannot shield either.
        let e = plan_move(&mut w, Direction::ToPrivate, None, false, 100).unwrap_err();
        assert!(matches!(e, WalletError::Coins(_)), "{e}");
        assert!(keys::parse_address(
            Network::Regtest,
            &w.receive_address(false).unwrap().address_s
        )
        .is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

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

    /// WEB-REAL MEDIUM-4: public YEC pays ANOTHER wallet's Sapling address. Through the send
    /// dispatch (`plan_yec_send`, the app's and the browser's path) with too little private YEC:
    /// the public balance pays by a shield to the recipient. Only plain `YEC` coins (never the
    /// reserve, a token, a held or a vault output); one Sapling output that decrypts with the
    /// RECIPIENT's viewing key to the amount and the memo; no Sapling spend, valueBalance =
    /// -amount; the change to a fresh change key of this wallet; the fee = ycash6 z_sendmany's
    /// for the shape (peroutput, 1,000 zat) = inputs - outputs; the gate's Shield path admits it.
    /// A dust or TOKEN_VALUE change goes to the fee, never to the recipient; a public balance
    /// too small is the private shortfall error.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn public_yec_pays_another_wallets_sapling_address() {
        use crate::build::yec_private::plan_yec_send;
        use crate::tx::Transaction;
        let (mut w, dir) = wallet_with(
            "third",
            &[
                (3_000_000, UtxoClass::Yec),
                (105_000, UtxoClass::FeeReserve),
                (TOKEN_VALUE, UtxoClass::Token),
                (90_000_000, UtxoClass::Held),
                (70_000_000, UtxoClass::Vault),
            ],
        );
        w.set_vault_activation(Some(1)).unwrap();
        // a synced private balance of 0.0005 YEC: too little for the send
        w.shielded_mut()
            .unwrap()
            .receive_for_test(100, 120, &[50_000], &params_dir());
        let other = crate::shielded_keys::SaplingAccount::from_mnemonic(
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
            "",
            Network::Regtest,
        )
        .unwrap();
        let (_, to) = other.default_address();
        assert_ne!(to, w.shielded().unwrap().default_address().1);
        let p = plan_yec_send(
            &mut w,
            &to,
            1_000_000,
            false,
            false,
            Some("for you"),
            120,
            1,
        )
        .unwrap();
        assert!(!p.reveals_shielded);
        let s = shield(&p);
        assert_eq!(s.to, to);
        assert_eq!(s.memo.as_deref(), Some("for you"));
        assert_eq!((s.amount, s.fee), (1_000_000, 1_000));
        assert_eq!(s.fee, ShieldTo::node_fee() as i64);
        assert_eq!(s.inputs.len(), 1);
        assert!(s.inputs.iter().all(|u| u.class == UtxoClass::Yec));
        assert_eq!(s.change, 3_000_000 - 1_000_000 - 1_000);
        let (change_addr, change_h) = s.change_address.clone().unwrap();
        assert!(change_addr.starts_with('s') || change_addr.starts_with('t'));
        assert_eq!((s.target, s.expiry_height), (121, 161));
        // built: the vector
        let secrets: Vec<[u8; 32]> = s
            .shield_inputs
            .iter()
            .map(|i| {
                w.key_for_hash(&i.hash160)
                    .unwrap()
                    .unwrap()
                    .secret
                    .to_secret_bytes()
            })
            .collect();
        let built = w
            .shielded_mut()
            .unwrap()
            .build_shield(
                s.target,
                &s.shield_inputs,
                &secrets,
                &s.dest,
                s.amount as u64,
                Some((change_h, s.change as u64)),
                &params_dir(),
            )
            .unwrap();
        assert_eq!(built.fee_zat, 1_000);
        let (tx, txid) = Transaction::parse(&built.raw).unwrap();
        assert_eq!(txid, built.txid);
        assert_eq!(tx.shielded.spends, 0);
        assert_eq!(tx.shielded.outputs, 2, "one output, padded to two");
        assert_eq!(tx.shielded.value_balance, -1_000_000);
        assert_eq!(tx.vin.len(), 1);
        assert_eq!(tx.vout.len(), 1);
        assert_eq!(tx.vout[0].value, s.change);
        assert_eq!(tx.vout[0].script_pubkey, script::p2pkh_script(&change_h));
        assert_eq!(
            3_000_000 - tx.vout[0].value + tx.shielded.value_balance,
            1_000,
            "inputs - outputs = the node's fee"
        );
        let branch =
            zcash_protocol::consensus::BranchId::try_from(crate::params::VAULT_BRANCH_ID).unwrap();
        let ztx = zcash_primitives::transaction::Transaction::read(&built.raw[..], branch).unwrap();
        let sb = ztx.sapling_bundle().cloned().unwrap();
        let ivk = |a: &crate::shielded_keys::SaplingAccount| {
            sapling_crypto::note_encryption::PreparedIncomingViewingKey::new(
                &a.extended_spending_key()
                    .to_diversifiable_full_viewing_key()
                    .to_ivk(zip32::Scope::External),
            )
        };
        let decrypt = |k: &sapling_crypto::note_encryption::PreparedIncomingViewingKey| {
            sb.shielded_outputs()
                .iter()
                .filter_map(|o| {
                    sapling_crypto::note_encryption::try_sapling_note_decryption(
                        k,
                        o,
                        sapling_crypto::note_encryption::Zip212Enforcement::On,
                    )
                })
                .collect::<Vec<_>>()
        };
        let paid = decrypt(&ivk(&other));
        assert_eq!(paid.len(), 1, "the recipient reads one output");
        assert_eq!(paid[0].0.value().inner(), 1_000_000);
        assert_eq!(
            zcash_keys::encoding::encode_payment_address(
                Network::Regtest.sapling_address_hrp(),
                &paid[0].1
            ),
            to
        );
        let memo = zcash_protocol::memo::Memo::from_bytes(paid[0].2.as_slice()).unwrap();
        assert_eq!(
            memo,
            "for you".parse::<zcash_protocol::memo::Memo>().unwrap()
        );
        let mine =
            crate::shielded_keys::SaplingAccount::from_mnemonic(PHRASE, "", Network::Regtest)
                .unwrap();
        assert!(decrypt(&ivk(&mine)).is_empty(), "nothing to this wallet");
        // the gate's local layer: the Shield path admits it with the coin's class
        let class = |op: &OutPoint| w.store.utxo_class(op).ok().flatten();
        assert!(gate::check(GatePath::Shield, &built.raw, class).is_ok());

        // dust change (< MIN_CHANGE) goes to the fee, not to the recipient
        let p = plan_yec_send(
            &mut w,
            &to,
            3_000_000 - 1_000 - 50,
            false,
            false,
            None,
            120,
            1,
        )
        .unwrap();
        let s = shield(&p);
        assert_eq!((s.amount, s.fee, s.change), (3_000_000 - 1_050, 1_050, 0));
        assert!(s.change_address.is_none());
        // a change of exactly TOKEN_VALUE: one zat less, that zat to the fee
        let p = plan_yec_send(
            &mut w,
            &to,
            3_000_000 - 1_000 - TOKEN_VALUE,
            false,
            false,
            None,
            120,
            1,
        )
        .unwrap();
        assert_eq!(
            (shield(&p).fee, shield(&p).change),
            (1_001, TOKEN_VALUE - 1)
        );
        // more than the public plain YEC: the private shortfall error, as before
        let e = plan_yec_send(&mut w, &to, 3_000_000, false, false, None, 120, 1).unwrap_err();
        assert!(e.to_string().contains("Not enough private YEC"), "{e}");
        // the private balance still pays when it can (privacy first)
        let p = plan_yec_send(&mut w, &to, 20_000, false, false, None, 120, 1).unwrap();
        assert!(matches!(p.funding, Funding::Shielded(_)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The merge of WEB-REAL MEDIUM-4 with beta2 D-5: the shield to another wallet's Sapling
    /// address takes one public address's coins, as every other public-balance send. Two
    /// addresses that only together cover the send: the linking question (the app asks; the
    /// browser, with no go-ahead step, shows it as the refusal, kind `linking`), never a silent
    /// combination and never the private shortfall; with the go-ahead both coins are spent at
    /// the node's fee. One address that covers it alone is taken without asking.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn public_yec_to_sapling_keeps_addresses_apart_unless_allowed() {
        use crate::api::{ErrorKind, YewError};
        use crate::build::yec_private::plan_yec_send;
        let (mut w, dir) = wallet_with(
            "third-link",
            &[(1_000_000, UtxoClass::Yec), (1_000_000, UtxoClass::Yec)],
        );
        assert_eq!(coins::distinct_addresses(&w.spendable_utxos().unwrap()), 2);
        w.shielded_mut()
            .unwrap()
            .receive_for_test(100, 120, &[50_000], &params_dir());
        let other = crate::shielded_keys::SaplingAccount::from_mnemonic(
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
            "",
            Network::Regtest,
        )
        .unwrap();
        let (_, to) = other.default_address();
        // one address covers it: no question, one input
        let p = plan_yec_send(&mut w, &to, 900_000, false, false, None, 120, 1).unwrap();
        assert_eq!((shield(&p).inputs.len(), shield(&p).fee), (1, 1_000));
        // only both together cover it: the question, without the go-ahead
        let e = plan_yec_send(&mut w, &to, 1_500_000, false, false, None, 120, 1).unwrap_err();
        assert!(
            matches!(
                e,
                WalletError::Coins(coins::CoinError::LinkingNeeded {
                    need: 1_501_000,
                    best_one: 1_000_000
                })
            ),
            "{e}"
        );
        let text = e.to_string();
        assert!(!text.contains("Not enough private YEC"), "{text}");
        let api = YewError::from(e);
        assert_eq!(api.kind, ErrorKind::AddressLinkingNeeded);
        assert_eq!(api.message, text);
        // with the go-ahead: both coins, the node's fee, change to a fresh own change key
        let p = plan_yec_send(&mut w, &to, 1_500_000, false, true, None, 120, 1).unwrap();
        let s = shield(&p);
        assert_eq!((s.inputs.len(), s.amount, s.fee), (2, 1_500_000, 1_000));
        assert_eq!(s.change, 2_000_000 - 1_500_000 - 1_000);
        let (_, change_h) = s.change_address.clone().unwrap();
        assert!(s
            .inputs
            .iter()
            .all(|u| u.script != script::p2pkh_script(&change_h)));
        // more than both: the private shortfall, as before (the go-ahead changes nothing)
        for allow in [false, true] {
            let e = plan_yec_send(&mut w, &to, 2_000_000, false, allow, None, 120, 1).unwrap_err();
            assert!(e.to_string().contains("Not enough private YEC"), "{e}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
