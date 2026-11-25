// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The wallet side of the two-host mailbox / retrieval pair (spec 0.5.2 §17; addendum W-7, L-4).
//! Every answer is checked against the per-sync roots both hosts publish (§17.5, §17.8 item 3):
//! the address root `aroot_h` (with the counts and the locator chain, S-7) and the note-tree root
//! at the boundary, which the wallet also compares with the node's `root_after`. A disagreement or
//! a failed check is a host fault; nothing found through a faulty answer is credited.
//!
//! Devnet cut (recorded in docs/decisions.md Y-W8): a session runs when the wallet syncs or pays a
//! short address, not on the fixed 16-block schedule of §17.8 item 1; no hybrid transport (§17.7);
//! path records (§17.3) are replaced by a full membership path beside each package entry, served
//! with the bucket (public data downloaded whole).

use serde_json::{json, Value};
use yugen_ref::address::{self, FullAddress};
use yugen_ref::hostidx::{addr_catch_up, addr_outcome, addr_query_indices, check_addr_answer, AddrOutcome};
use yugen_ref::keys::{self, AddrId};
use yugen_ref::note::{self, Note};
use yugen_ref::package;
use yugen_ref::params::*;
use yugen_ref::tree::{leaf_hash, root_from_path, Path as TPath};

use crate::account::Account;
use crate::dpf;
use crate::node::Rpc;
use crate::store::{addr_hex, hx, NoteRec};
use crate::{B32, B48};

/// What a sync session learned about one short address.
#[derive(Clone, Debug)]
pub enum Resolution {
    Resolved(FullAddress),
    /// No record listed yet (it is served from the boundary after it is written), or no real
    /// query for it this session: asked again at the next sync.
    NoRecord,
    /// Both hosts committed to a record that fails §12.3's client rule: the need is closed.
    Invalid,
}

pub struct Pair {
    pub names: Vec<String>,
    pub a: Rpc,
    pub b: Rpc,
}

#[derive(Clone, Debug)]
pub struct Roots {
    pub h: u32,
    pub n: u32,
    pub aroot: B32,
    pub note_root: B48,
    pub counts: Vec<u32>,
}

fn e<E: std::fmt::Display>(x: E) -> String {
    x.to_string()
}
fn unhex<const N: usize>(v: &Value) -> Result<[u8; N], String> {
    hex::decode(v.as_str().unwrap_or("")).ok().and_then(|x| x.try_into().ok()).ok_or_else(|| "host fault: malformed answer".to_string())
}
fn draw() -> u64 {
    let mut b = [0u8; 8];
    getrandom::getrandom(&mut b).expect("os random");
    u64::from_le_bytes(b)
}

impl Pair {
    /// `-yugenhosts=host1,host2` (host:port each).
    pub fn new(spec: &str) -> Result<Pair, String> {
        let names: Vec<String> = spec.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        if names.len() != 2 {
            return Err("-yugenhosts needs exactly two hosts (spec §17.6: a pair that does not collude)".into());
        }
        Ok(Pair { a: Rpc::new(&names[0], "", ""), b: Rpc::new(&names[1], "", ""), names })
    }

    /// The deletion token of this wallet's records (R-27), derived from the seed so a restore can
    /// replace its own record.
    pub fn del_token(seed: &[u8]) -> B32 {
        let h = blake2b_simd::Params::new().hash_length(32).personal(b"YugenDelToken\0\0\0").hash(seed);
        h.as_bytes().try_into().unwrap()
    }

    /// Writes the record of `addr` (§12.3) to both hosts. Byte-identical rewrites are accepted.
    pub fn publish(&self, addr: &FullAddress, del_token: &B32) -> Result<(), String> {
        let (loc, rec) = address::record_seal(addr, &address::del_hash(del_token));
        for h in [&self.a, &self.b] {
            let r = h.call("yh_putrecord", json!([hx(&loc), hx(&rec)])).map_err(e)?;
            if r["accepted"] != json!(true) {
                return Err(format!("host {} refused the address record (a different record holds this locator)", h.addr));
            }
        }
        Ok(())
    }

    /// Both hosts' per-sync roots; they must agree (§17.5).
    pub fn roots(&self) -> Result<Roots, String> {
        let ra = self.a.call("yh_getsyncroots", json!([])).map_err(e)?;
        let rb = self.b.call("yh_getsyncroots", json!([])).map_err(e)?;
        for k in ["h", "aroot", "n", "counts", "note_root"] {
            if ra[k] != rb[k] {
                return Err(format!("host fault: the two hosts disagree on {k}"));
            }
        }
        Ok(Roots {
            h: ra["h"].as_u64().ok_or("host fault: h")? as u32,
            n: ra["n"].as_u64().ok_or("host fault: n")? as u32,
            aroot: unhex(&ra["aroot"])?,
            note_root: unhex(&ra["note_root"])?,
            counts: ra["counts"].as_array().cloned().unwrap_or_default().iter().map(|c| c["n"].as_u64().unwrap_or(0) as u32).collect(),
        })
    }

    /// One sync session's address queries (§17.8 item 3): exactly `SYNC_ADDR_QUERIES` to each
    /// host (none while `n_h = 0`), the oldest needs first, then covers drawn from `[0, n)`, every
    /// answer checked against `aroot_h` (§17.5), a real one opened under §12.3's client rule.
    /// Returns one outcome per need, in order; `Err` is a host fault (one reaction, §17.8 item 3).
    pub fn resolve_session(&self, network: u8, needs: &[(u8, B32)]) -> Result<Vec<Resolution>, String> {
        let r = self.roots()?;
        let mut out = vec![Resolution::NoRecord; needs.len()];
        if r.n == 0 {
            return Ok(out); // SPEC-200: no address query, real or cover, while n_h = 0
        }
        // locators from one host, counts from both (a first sync: from activation, S-7)
        let locators: Vec<B32> = self.a.call("yh_getlocators", json!([0, r.h])).map_err(e)?.as_array().cloned().unwrap_or_default().iter().map(unhex::<32>).collect::<Result<_, _>>()?;
        let chain = addr_catch_up(&[0u8; 32], 0, &r.counts, &r.counts, &locators).ok_or("host fault: counts do not account for the locators")?;
        let locs = *chain.last().unwrap();
        // the needs with a listed locator, oldest first; the rest have no record yet
        let wants: Vec<B32> = needs.iter().map(|(_, sa)| address::locator(sa)).collect();
        let listed: Vec<(usize, u64)> =
            wants.iter().enumerate().filter_map(|(k, w)| locators.iter().position(|l| l == w).map(|i| (k, i as u64))).collect();
        let pending: Vec<u64> = listed.iter().map(|(_, i)| *i).collect();
        let draws: Vec<u64> = (0..SYNC_ADDR_QUERIES).map(|_| draw()).collect();
        let indices = addr_query_indices(r.n, &pending, &draws);
        // sync_queries puts the real queries first: the distinct pending indices, oldest first
        let n_real = { let mut d: Vec<u64> = Vec::new(); for p in &pending { if !d.contains(p) { d.push(*p); } } d.len() }.min(SYNC_ADDR_QUERIES);
        let mut fault = false;
        for (q, &i) in indices.iter().enumerate() {
            let (ka, kb) = dpf::gen_random(i, ADDR_TREE_DEPTH);
            let aa = hex::decode(self.a.call("yh_addrquery", json!([r.h, hx(&ka.encode())])).map_err(e)?.as_str().unwrap_or("")).map_err(e)?;
            let ab = hex::decode(self.b.call("yh_addrquery", json!([r.h, hx(&kb.encode())])).map_err(e)?.as_str().unwrap_or("")).map_err(e)?;
            if aa.len() != ab.len() {
                fault = true;
                continue;
            }
            let x: Vec<u8> = aa.iter().zip(&ab).map(|(p, q)| p ^ q).collect();
            let passed = check_addr_answer(&x, i as u32, r.h, r.n, &locs, &r.aroot);
            // a real query: one of the listed needs whose index this is (duplicates merged)
            let need = (q < n_real).then(|| listed.iter().find(|(_, li)| *li == i).map(|(k, _)| *k)).flatten();
            let opened = std::cell::RefCell::new(None);
            let (flags, sa) = need.map(|k| needs[k]).unwrap_or((0, [0u8; 32]));
            let want = need.map(|k| wants[k]);
            match addr_outcome(passed.as_ref(), want.as_ref(), |rec| {
                *opened.borrow_mut() = address::record_open(network, flags, &sa, rec);
                opened.borrow().is_some()
            }) {
                AddrOutcome::Fault => fault = true,
                AddrOutcome::Discarded => {}
                AddrOutcome::Resolved => {
                    if let (Some(k), Some(a)) = (need, opened.into_inner()) {
                        for (m, w) in wants.iter().enumerate() {
                            if *w == wants[k] {
                                out[m] = Resolution::Resolved(a.clone());
                            }
                        }
                    }
                }
                AddrOutcome::RecordInvalid => {
                    if let Some(k) = need {
                        out[k] = Resolution::Invalid;
                    }
                }
            }
        }
        if fault {
            // one reaction whatever failed (§17.8 item 3): report, no retry in this session
            return Err("host fault: an answer failed its check against the hosts' roots; try the other host next sync".into());
        }
        Ok(out)
    }

    /// Finds on-chain packages to static address 0 (§17.4) through the hosts only: per epoch, the
    /// fixed lists of `SYNC_ADDR_SLOTS` keys (own first, then covers), each list the
    /// `PKG_BUCKET_BITS + 1` widths; every entry's path checked against the agreed note root.
    pub fn find_packages(&self, acct: &Account, node_root: &dyn Fn(u32) -> Option<B48>, from: u32, to: u32, branch_id: u32) -> Result<Vec<NoteRec>, String> {
        let r = self.roots()?;
        if let Some(nr) = node_root(r.h) {
            if nr != r.note_root {
                return Err("host fault: the hosts' note root differs from the node's".into());
            }
        }
        let d = AddrId::stat(0);
        let ak = acct.wallet.address_keys(d);
        let (dk, ek) = keys::kem_keypair(&ak.kem_d, &ak.kem_z);
        let lists = |full: u16| -> Vec<u16> {
            let mut v: Vec<u16> = (0..=PKG_BUCKET_BITS).map(|b| (((full as u32) >> (PKG_BUCKET_BITS - b)) << (PKG_BUCKET_BITS - b)) as u16).collect();
            v.sort_unstable();
            v.dedup();
            v
        };
        let mut out = Vec::new();
        for epoch in from / MAILBOX_EPOCH_BLOCKS..=to / MAILBOX_EPOCH_BLOCKS {
            let mut keys_of_epoch = vec![address::pkg_fetch_buckets(&ek, epoch)];
            while keys_of_epoch.len() < SYNC_ADDR_SLOTS {
                keys_of_epoch.push(lists((draw() % (1 << PKG_BUCKET_BITS)) as u16));
            }
            for (slot, list) in keys_of_epoch.iter().enumerate() {
                for &bucket in list {
                    let items = self.a.call("yh_getpackages", json!([epoch, bucket, r.h])).map_err(e)?;
                    if slot != 0 {
                        continue; // cover list: downloaded like the own list, then discarded
                    }
                    for it in items.as_array().cloned().unwrap_or_default() {
                        let entry = hex::decode(it["entry"].as_str().unwrap_or("")).map_err(e)?;
                        let path_b = hex::decode(it["path"].as_str().unwrap_or("")).map_err(e)?;
                        if entry.len() < 54 || path_b.len() != TREE_DEPTH * 3 * 48 {
                            return Err("host fault: malformed package entry".into());
                        }
                        let cm: B48 = entry[..48].try_into().unwrap();
                        let j = entry[48];
                        let pos = u64::from_le_bytes([entry[49], entry[50], entry[51], entry[52], entry[53], 0, 0, 0]);
                        let mut path: TPath = [[[0u8; 48]; 3]; TREE_DEPTH];
                        for (k, c) in path_b.chunks(48).enumerate() {
                            path[k / 3][k % 3] = c.try_into().unwrap();
                        }
                        if root_from_path(&leaf_hash(&cm), pos, &path) != r.note_root {
                            return Err("host fault: a package entry's path does not reach the agreed note root".into());
                        }
                        if !(1..=2).contains(&j) {
                            continue;
                        }
                        let nf1: B32 = unhex(&it["nf1"])?;
                        let Some(plain) = package::open(&dk, &cm, j, branch_id, acct.network(), &entry[54..]) else { continue };
                        let nt = Note { asset: ASSET_YEC, v: plain.v, auth: acct.wallet.auth(d), nkc: ak.nkc_d, rho: plain.rho, rcm: note::rcm_static(&plain.rseed) };
                        if plain.rho != note::rho_out(&nf1, j) || nt.cm() != cm {
                            continue;
                        }
                        let nf = note::nullifier(&acct.nk_d(d), &nt.rho, &nt.cm());
                        out.push(NoteRec {
                            d: addr_hex(d),
                            v: nt.v,
                            auth: hx(&nt.auth),
                            nkc: hx(&nt.nkc),
                            rho: hx(&nt.rho),
                            rcm: hx(&nt.rcm),
                            pos,
                            height: it["height"].as_u64().unwrap_or(0) as u32,
                            txid: it["txid"].as_str().unwrap_or("").to_string(),
                            nf: hx(&nf),
                            spent_in: None,
                            pending: None,
                            applied: true,
                            memo: (!plain.memo.is_empty()).then(|| hx(&plain.memo)),
                        });
                    }
                }
            }
        }
        Ok(out)
    }
}
