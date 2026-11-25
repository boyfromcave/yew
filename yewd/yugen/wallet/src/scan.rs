// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! Finding incoming notes in node data (M1: direct scan of `yugen_getblockdata`, the stand-in
//! for the mailbox, addendum W-5). For each applied transfer, in block order: own nullifiers are
//! marked spent; `cm_1`, `cm_2` are appended to the note tree (spec §8); each output is tried as
//! change (outgoing tag, spec §7.4), as a payment to an issued request (§9.3) and as an on-chain
//! package to static address 0 (§10.3). A found note is credited only when its membership path
//! recomputes the tree root after the block (`yugen_ref::wallet::is_applied`, §7.7).

use serde_json::Value;
use yugen_ref::keys::AddrId;
use yugen_ref::note;
use yugen_ref::params::*;
use yugen_ref::transfer::{self, Transfer};
use yugen_ref::wallet::is_applied;

use crate::account::Account;
use crate::store::{addr_hex, h, hx, NoteRec, Store};
use crate::B48;

#[derive(Clone, Debug)]
pub struct BlockData {
    pub height: u32,
    pub transfers: Vec<(String, Transfer)>,
    /// The node's note-tree root after the block, if it reports one.
    pub root_after: Option<B48>,
    pub tree_size_before: Option<u64>,
}

impl BlockData {
    /// Parses the W-RPC-2 shape (yewd/yugen/docs/node-interface.md).
    pub fn from_json(v: &Value) -> Result<Self, String> {
        let height = v["height"].as_u64().ok_or("height")? as u32;
        let mut transfers = Vec::new();
        for t in v["transfers"].as_array().cloned().unwrap_or_default() {
            let bytes = hex::decode(t["transfer"].as_str().ok_or("transfer")?).map_err(|e| e.to_string())?;
            let tr = Transfer::decode(&bytes).map_err(|e| format!("transfer decode: {e:?}"))?;
            transfers.push((t["txid"].as_str().unwrap_or("").to_string(), tr));
        }
        let root_after = v["root_after"].as_str().map(h::<48>);
        let tree_size_before = v["tree_size_before"].as_u64();
        Ok(BlockData { height, transfers, root_after, tree_size_before })
    }
}

/// The anchor height a slot denotes in a block at `h` (spec §8.1), with the activation height
/// of the network the node reports (the reference's `resolve_anchor` uses the constant
/// `ACTIVATION_HEIGHT`; regtest activates by `-nuparams`).
pub fn resolve_anchor(slot: u8, h: u32, activation: u32) -> Option<u32> {
    let mut ha = h.checked_sub(1)? / ANCHOR_GRID * ANCHOR_GRID;
    while ha >= activation && h - ha <= ANCHOR_WINDOW {
        if transfer::anchor_slot(ha) == slot {
            return Some(ha);
        }
        ha = ha.checked_sub(ANCHOR_GRID)?;
    }
    None
}

/// Applies one block to the store. Returns the number of notes credited.
pub fn apply_block(st: &mut Store, acct: &Account, b: &BlockData, activation: u32, branch_id: u32) -> Result<usize, String> {
    if let Some(n) = b.tree_size_before {
        if n != st.leaves.len() as u64 {
            return Err(format!("block {}: node tree size {n}, wallet {}", b.height, st.leaves.len()));
        }
    }
    // Spec §13.2: the canary commitment cm* is leaf 0, appended in the activation block.
    if b.height == activation && st.leaves.is_empty() {
        st.leaves.push(hx(&yugen_ref::tree::canary_nullifier().1));
    }
    let w = &acct.wallet;
    let mut found = Vec::new();
    for (txid, t) in &b.transfers {
        for nf in &t.nf {
            let nfh = hx(nf);
            for n in st.notes.iter_mut().filter(|n| n.nf == nfh) {
                n.spent_in = Some(txid.clone());
                n.pending = None;
            }
        }
        let ha = resolve_anchor(t.anchor_slot, b.height, activation).unwrap_or(b.height.saturating_sub(1) / ANCHOR_GRID * ANCHOR_GRID);
        let epoch = transfer::otag_epoch(ha);
        for j in 1..=2u8 {
            let i = (j - 1) as usize;
            let pos = st.leaves.len() as u64;
            st.leaves.push(hx(&t.cm[i]));
            let mut hit: Option<(AddrId, note::Note)> = None;
            let mut memo = None;
            let top = st.otag_counters.get(&epoch).copied().unwrap_or(0) + OTAG_GAP;
            for c in 0..top {
                if let Some((n, nt)) = w.recover_change(t, j, epoch, c) {
                    hit = Some((AddrId::internal(n), nt));
                    break;
                }
            }
            if hit.is_none() {
                for &(day, c) in &st.requests {
                    if let Some(nt) = w.request(day, c).recover(t, j) {
                        hit = Some((AddrId::req(day, c), nt));
                        break;
                    }
                }
            }
            if hit.is_none() && t.pkg[i].is_some() && !acct.by_hosts {
                if let Some((nt, m)) = w.recover_static(t, j, 0, branch_id) {
                    hit = Some((AddrId::stat(0), nt));
                    memo = (!m.is_empty()).then(|| hx(&m));
                }
            }
            if let Some((d, nt)) = hit {
                let nf = note::nullifier(&acct.nk_d(d), &nt.rho, &nt.cm());
                found.push(NoteRec {
                    d: addr_hex(d),
                    v: nt.v,
                    auth: hx(&nt.auth),
                    nkc: hx(&nt.nkc),
                    rho: hx(&nt.rho),
                    rcm: hx(&nt.rcm),
                    pos,
                    height: b.height,
                    txid: txid.clone(),
                    nf: hx(&nf),
                    spent_in: None,
                    pending: None,
                    applied: false,
                    memo,
                });
            }
        }
    }
    st.sizes.insert(b.height, st.leaves.len() as u64);
    st.scanned = Some(b.height);
    let n = found.len();
    if n > 0 {
        let tree = st.tree_at(b.height);
        let root = tree.root();
        if let Some(r) = b.root_after {
            if r != root {
                return Err(format!("block {}: node root differs from the wallet's", b.height));
            }
        }
        for mut f in found {
            f.applied = is_applied(&f.note(), f.pos, &tree.path(f.pos), &root);
            st.notes.retain(|x| x.nf != f.nf);
            st.notes.push(f);
        }
    }
    Ok(n)
}
