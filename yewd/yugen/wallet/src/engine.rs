//! The wallet operations behind the `yugen_*` RPCs (clones/INTERFACES.md, section W final).

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{json, Value};
use yugen_ref::address::FullAddress;
use yugen_ref::keys::AddrId;
use yugen_ref::params::*;
use yugen_ref::registry::Registry;
use yugen_ref::request::{issue_day, PaymentRequest};
use yugen_ref::transfer::{self, FLAG_LEAFFEE};
use yugen_ref::tree::Path as TPath;
use yugen_ref::vectors::{public_json, witness_json};
use yugen_ref::wallet::{BuildParams, Built, Output, Spend};

use zeroize::Zeroizing;

use crate::account::Account;
use crate::build::BuildExt;
use crate::node::Rpc;
use crate::scan::{apply_block, BlockData};
use crate::store::{h, NoteRec, PendingSend, Store};
use crate::tx::{self, TxIn, TxOut, YugenTx};
use crate::yaddr::{self, Choice, Static, YugenAddress};
use crate::{coins, zats};

/// Pads a memo to 512 bytes (§10.1); empty for none.
fn memo_pad(memo: Option<&str>) -> Result<Vec<u8>, String> {
    Ok(match memo.filter(|m| !m.is_empty()) {
        None => Vec::new(),
        Some(m) => {
            if m.len() > MEMO_LEN {
                return Err(format!("memo longer than {MEMO_LEN} bytes"));
            }
            let mut b = m.as_bytes().to_vec();
            b.resize(MEMO_LEN, 0);
            b
        }
    })
}

pub struct Engine {
    pub dir: PathBuf,
    pub node: Rpc,
    pub st: Store,
    pub acct: Account,
    /// The account seed of this call (never stored; wiped on drop).
    seed: Zeroizing<Vec<u8>>,
    /// The prover binary (this executable), run as `prove a|b`.
    pub prover: PathBuf,
    /// The mailbox host pair (M3), from `-yugenhosts`.
    pub hosts: Option<crate::hosts::Pair>,
}

pub struct Info {
    pub activation: u32,
    pub branch_id: u32,
    pub tip: u32,
}

fn err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

impl Engine {
    /// Opens `dir` with the account seed, creating the wallet state on first use. The seed is
    /// never written: the state keeps its fingerprint and a call with another seed is refused. A
    /// state file from before that rule (a `seed` field) opens only with that same seed, and the
    /// next save rewrites it without the seed (the caller has stored the seed safely first).
    pub fn open(dir: &Path, node: Rpc, network: u8, seed: Option<Zeroizing<Vec<u8>>>) -> Result<Self, String> {
        let seed = seed.ok_or("the Yugen account seed was not supplied (the wallet is locked)")?;
        let fp = crate::store::seed_fingerprint(&seed);
        let mut st = match Store::load(dir) {
            Some(s) => s,
            None => Store { network, ..Default::default() },
        };
        if !st.legacy_seed.is_empty() {
            let legacy = Zeroizing::new(hex::decode(&st.legacy_seed.0).map_err(|_| "the wallet state holds a malformed seed".to_string())?);
            if !crate::store::ct_eq(legacy.as_slice(), seed.as_slice()) {
                return Err("the wallet state holds another seed".into());
            }
        }
        if st.seed_fp.is_empty() {
            st.seed_fp = fp;
        } else if st.seed_fp != fp {
            return Err("the supplied seed is not this Yugen account's seed".into());
        }
        let migrate = !st.legacy_seed.is_empty() || !Store::path(dir).exists();
        let acct = Account::from_seed(&seed, st.network).ok_or("seed refused (spec §4)")?;
        let mut e = Engine { dir: dir.into(), node, st, acct, seed, prover: std::env::current_exe().map_err(err)?, hosts: None };
        if migrate {
            e.save()?;
            e.st.legacy_seed.clear();
        }
        Ok(e)
    }
    /// Uses the host pair: static address 0 names the two hosts, and static-address payments are
    /// found only through them.
    pub fn set_hosts(&mut self, p: crate::hosts::Pair) {
        self.acct.by_hosts = true;
        self.hosts = Some(p);
    }
    /// Static address 0: with hosts, the address naming them (its short form is what users see).
    pub fn my_static(&self) -> FullAddress {
        match &self.hosts {
            Some(p) => self.acct.static_address_hosts(0, &p.names),
            None => self.acct.static_address(0),
        }
    }
    /// A short address resolved through the hosts (§12.3), or an error naming what is missing.
    /// A short address this wallet has resolved at an earlier sync session; resolving a new one
    /// waits for the next session (§17.8: no host query outside the schedule).
    fn resolve_short(&self, flags: u8, sa: &[u8; 32]) -> Result<FullAddress, String> {
        if self.hosts.is_none() {
            return Err("this Yugen address needs its record from a mailbox host (spec §12.3): start with -yugenhosts".into());
        }
        self.cached(flags, sa).ok_or_else(|| "this Yugen address is resolved at the next scheduled sync (spec §17.8): send it with yugen_send, which queues it".into())
    }
    pub fn save(&self) -> Result<(), String> {
        self.st.save(&self.dir).map_err(err)
    }

    pub fn info(&self) -> Result<Info, String> {
        let v = self.node.call("yugen_getinfo", json!([])).map_err(err)?;
        Ok(Info {
            activation: v["activation_height"].as_u64().ok_or("yugen_getinfo: activation_height")? as u32,
            branch_id: v["branch_id"].as_u64().unwrap_or(BRANCH_ID as u64) as u32,
            tip: v["tip_height"].as_u64().ok_or("yugen_getinfo: tip_height")? as u32,
        })
    }

    /// Scans the node's blocks from activation (or the last scanned) to the tip: the wallet's own
    /// node, not a host, so this runs on every call (on-chain request payments, change, spends).
    pub fn chain_scan(&mut self) -> Result<Info, String> {
        let i = self.info()?;
        let from = self.st.scanned.map(|h| h + 1).unwrap_or(i.activation);
        for hgt in from..=i.tip {
            let v = self.node.call("yugen_getblockdata", json!([hgt])).map_err(err)?;
            let b = BlockData::from_json(&v)?;
            apply_block(&mut self.st, &self.acct, &b, i.activation, i.branch_id)?;
        }
        self.save()?;
        Ok(i)
    }

    /// The status of the fixed sync schedule and the balances (no host session).
    pub fn sync_status(&mut self) -> Result<Value, String> {
        let i = self.chain_scan()?;
        Ok(json!({"tip": i.tip, "scanned": self.st.scanned, "hosts": self.hosts.is_some(),
                  "last_sync": self.st.host_synced, "next_sync": crate::schedule::next_boundary(i.tip.max(self.st.host_synced.unwrap_or(0))),
                  "pending_sends": self.pending_json()}))
    }

    /// The scheduled sync (spec §17.8; ruling 16). Run by yewd's scheduler only, never on a
    /// user's request. Without hosts it is the chain scan. With hosts, at most one session per
    /// 16-block boundary: first the address queries (exactly `SYNC_ADDR_QUERIES` to each host,
    /// real ones for the oldest queued payments to short addresses, the rest cover), then the
    /// package buckets of every epoch since the last session (the fixed four lists per epoch);
    /// then the queued payments whose addresses resolved are built and submitted.
    pub fn sync(&mut self) -> Result<Value, String> {
        let i = self.chain_scan()?;
        let Some(p) = &self.hosts else {
            return Ok(json!({"tip": i.tip, "session": false}));
        };
        let Some(target) = crate::schedule::due(self.st.host_synced, i.tip, i.activation) else {
            return Ok(json!({"tip": i.tip, "session": false, "last_sync": self.st.host_synced, "next_sync": crate::schedule::next_boundary(i.tip)}));
        };
        // the hosts serve the snapshot of `target` only once they have taken it (§17.5): until
        // then the session waits (the same for every wallet), and the scheduler asks again
        if p.roots()?.h < target {
            return Ok(json!({"tip": i.tip, "session": false, "retry": true, "boundary": target}));
        }
        // 1. address queries for the oldest waiting payments (needs beyond the count wait)
        let mut needs: Vec<(u32, u8, [u8; 32])> = Vec::new();
        for ps in self.st.pending_sends.iter().filter(|x| x.state == "waiting") {
            if let Ok(YugenAddress { stat: Static::Short(f, sa), .. }) = YugenAddress::decode(&ps.to, self.st.network) {
                if !self.st.resolved.contains_key(&short_key(f, &sa)) {
                    needs.push((ps.id, f, sa));
                }
            }
        }
        let asks: Vec<(u8, [u8; 32])> = needs.iter().map(|(_, f, sa)| (*f, *sa)).collect();
        let outcomes = p.resolve_session(self.st.network, &asks)?;
        let mut invalid = Vec::new();
        for ((id, f, sa), o) in needs.iter().zip(outcomes) {
            match o {
                crate::hosts::Resolution::Resolved(a) if a.valid() && a.network == self.st.network => {
                    self.st.resolved.insert(short_key(*f, sa), hex::encode(a.to_bytes()));
                }
                crate::hosts::Resolution::Invalid => invalid.push(*id),
                _ => {}
            }
        }
        // 2. package buckets for the epochs since the last session
        let from = self.st.host_synced.unwrap_or(i.activation);
        let node = self.node.clone();
        let node_root = move |h: u32| node.call("yugen_getblockdata", json!([h])).ok().and_then(|v| v["root_after"].as_str().map(h48));
        let mut via_hosts = 0;
        match p.find_packages(&self.acct, &node_root, from, target, i.branch_id) {
            Ok(found) => {
                for f in found {
                    if !self.st.notes.iter().any(|n| n.nf == f.nf) {
                        via_hosts += 1;
                        self.st.notes.push(f);
                    }
                }
            }
            Err(e) if e.contains("no boundary yet") => {}
            Err(e) => return Err(e),
        }
        self.st.host_synced = Some(target);
        for ps in self.st.pending_sends.iter_mut().filter(|x| invalid.contains(&x.id)) {
            ps.state = "invalid-record".into();
            ps.error = Some("this Yugen address has an invalid record at its hosts".into());
        }
        self.save()?;
        // 3. the payments whose addresses are now known
        let ready: Vec<PendingSend> = self
            .st
            .pending_sends
            .iter()
            .filter(|x| x.state == "waiting" && self.cached_short(&x.to).is_some())
            .cloned()
            .collect();
        let mut sent = Vec::new();
        for ps in ready {
            let r = self.send(&ps.to, ps.amount, ps.memo.as_deref());
            let e = self.st.pending_sends.iter_mut().find(|x| x.id == ps.id).expect("queued");
            match r {
                Ok(v) => {
                    e.state = "sent".into();
                    e.txid = v["txid"].as_str().map(String::from);
                    sent.push(v);
                }
                Err(m) => {
                    e.state = "failed".into();
                    e.error = Some(m);
                }
            }
            self.save()?;
        }
        Ok(json!({"tip": i.tip, "session": true, "boundary": target, "via_hosts": via_hosts, "sent": sent,
                  "pending_sends": self.pending_json()}))
    }

    fn pending_json(&self) -> Value {
        json!(self.st.pending_sends.iter().map(|p| json!({"id": p.id, "to": p.to, "amount": coins(p.amount), "state": p.state,
            "queued": p.queued, "txid": p.txid, "error": p.error})).collect::<Vec<_>>())
    }

    /// The full address of a short Yugen address this wallet has resolved before.
    fn cached_short(&self, to: &str) -> Option<FullAddress> {
        match YugenAddress::decode(to, self.st.network).ok()?.stat {
            Static::Short(f, sa) => self.cached(f, &sa),
            Static::Full(a) => Some(a),
        }
    }
    fn cached(&self, f: u8, sa: &[u8; 32]) -> Option<FullAddress> {
        let b = hex::decode(self.st.resolved.get(&short_key(f, sa))?).ok()?;
        FullAddress::from_bytes(&b)
    }

    /// Balances (ruling 16): `spendable` (found, under the wallet's anchor, unspent); `pending`
    /// (found but not yet under an anchor, or spent in a transfer not yet mined: change);
    /// `outgoing_pending` (payments to short addresses waiting for the next sync). A payment to
    /// this wallet's short address is found only by the sync session after it is mined, so it
    /// appears at that session, as pending first if it is not yet anchored.
    pub fn balances(&mut self) -> Result<Value, String> {
        let i = self.chain_scan()?;
        let ha = transfer::wallet_anchor(i.tip);
        let size = if ha >= i.activation { self.st.size_at(ha) } else { 0 };
        let mut spendable = 0;
        let mut pending = 0;
        for n in self.st.notes.iter().filter(|n| n.spent_in.is_none() && n.v > 0) {
            if n.applied && n.pending.is_none() && n.pos < size {
                spendable += n.v;
            } else if n.pending.is_none() {
                pending += n.v;
            }
        }
        let out: u64 = self.st.pending_sends.iter().filter(|p| p.state == "waiting").map(|p| p.amount).sum();
        Ok(json!({"spendable": coins(spendable), "pending": coins(pending), "outgoing_pending": coins(out),
                  "last_sync": self.st.host_synced, "next_sync": crate::schedule::next_boundary(i.tip)}))
    }

    pub fn new_request(&mut self) -> Result<String, String> {
        let tip = self.node.call("getblockcount", json!([])).map_err(err)?.as_u64().unwrap_or(0) as u32;
        let day = issue_day(tip);
        let c = self.st.requests.iter().filter(|(d, _)| *d == day).count() as u16;
        self.st.requests.push((day, c));
        self.save()?;
        Ok(self.acct.request(day, c).to_string())
    }

    pub fn deposit_address(&self) -> String {
        tx::taddr(&tx::deposit_key(&self.seed), self.st.network)
    }

    pub fn balance(&self) -> f64 {
        coins(self.st.balance())
    }

    pub fn list_received(&self) -> Value {
        json!(self
            .st
            .notes
            .iter()
            .map(|n| json!({"txid": n.txid, "height": n.height, "amount": coins(n.v), "pos": n.pos, "applied": n.applied,
                            "spent": n.spent_in.is_some(), "nf": n.nf, "memo": n.memo_text()}))
            .collect::<Vec<_>>())
    }

    fn anchor(&self, i: &Info) -> Result<(u32, [u8; 32]), String> {
        let ha = transfer::wallet_anchor(i.tip);
        if ha < i.activation {
            return Err(format!("no anchor yet: tip {} gives anchor {ha} below activation {}", i.tip, i.activation));
        }
        let hash = self.node.call("getblockhash", json!([ha])).map_err(err)?;
        let mut b = hex::decode(hash.as_str().ok_or("getblockhash")?).map_err(err)?;
        b.reverse(); // internal byte order (W-RPC-3)
        Ok((ha, b.try_into().map_err(|_| "block hash length")?))
    }

    /// A dummy spend at anchor `ha` (spec §5.6): `c` is the smallest counter not yet used with
    /// that anchor height. "Used" is read from the chain, not only from this wallet's state: a
    /// wallet restored from its seed alone has no counter record, so each candidate's nullifier
    /// is looked up on the node (`gettransferstatus`, which matches either spend of a pending
    /// transfer) and a counter whose nullifier is already mined or pending is skipped.
    ///
    /// The lookup sends candidate nullifiers, which are linkable to this wallet's next transfer,
    /// so it is made only when the node is on a loopback address (`Rpc::is_loopback`). With a
    /// remote backend the wallet keeps to its own record for the anchor height, and with no record
    /// (the first dummy at that height in this state, e.g. after a restore) starts at a counter
    /// drawn uniformly from [2^31, 2^32 - 2^20): a value a wallet that kept its record never
    /// reaches (it starts at 0). Two restores without a record, each making a transfer (at most two
    /// dummy counters) at the same anchor height, share a counter with probability about
    /// 3·2^-31 per transfer pair; the outcome is a refused transfer, no funds at risk (SPEC-215,
    /// `yugen-spec` `spec/decisions.md`). The nullifier stays a function of the seed, the anchor height and `c`
    /// (§7.7: `c` is wallet state, not a free byte; this wallet is its own signer and keeps the
    /// record of §7.7's signer rule).
    pub fn dummy(&mut self, ha: u32) -> Result<Spend, String> {
        let probe = self.node.is_loopback();
        let mut c = match self.st.dummy_next.get(&ha) {
            Some(n) => *n,
            None if probe => 0,
            None => random_dummy_start(),
        };
        while probe {
            let dx = yugen_ref::note::dummy_preimage(&self.acct.wallet.keys.rsk, &self.acct.wallet.keys.nk, ha, c);
            let nf = yugen_ref::note::nullifier_dummy(&dx);
            let st = self.node.call("gettransferstatus", json!([hex::encode(nf)])).map_err(err)?;
            if st["state"].as_str() == Some("unknown") {
                break;
            }
            c = c.checked_add(1).ok_or("dummy counter exhausted")?;
        }
        self.st.dummy_next.insert(ha, c.checked_add(1).ok_or("dummy counter exhausted")?);
        // anchors leave the window: keep the record of the recent ones only
        let keep = ha.saturating_sub(4096);
        self.st.dummy_next.retain(|h, _| *h >= keep);
        Ok(Spend::Dummy { c })
    }

    /// Builds, proves (both systems, in two child processes) and returns the transaction.
    fn make(&mut self, i: &Info, spends: [Spend; 2], outputs: [Output; 2], ha: u32, abh: [u8; 32], vb: i64, vout: Vec<TxOut>, vin: Vec<TxIn>) -> Result<(Built, YugenTx), String> {
        let tree = self.st.tree_at(ha);
        let epoch = transfer::otag_epoch(ha);
        let oc = [self.st.next_otag(epoch), self.st.next_otag(epoch)];
        let bp = BuildParams {
            branch_id: i.branch_id,
            fee_class: 0,
            anchor_height: ha,
            anchor_root: tree.root(),
            anchor_block_hash: abh,
            value_balance: vb,
            vout: tx::vout_bytes(&vout),
            otag_counter: oc,
            auth_mode: 0,
            registry: Registry::default(),
        };
        let built = self.acct.wallet.build_flags(&mut self.acct.signer, &spends, &outputs, &bp, FLAG_LEAFFEE);
        yugen_ref::statement::check_statement(&built.public, &built.witness).map_err(|v| format!("statement refused: {v:?}"))?;
        let stmt = json!({"public": public_json(&built.public), "witness": witness_json(&built.witness)});
        let (pa, pb) = prove_both(&self.prover, &stmt)?;
        let mut t = YugenTx { vin, vout, expiry: transfer::expiry_height(ha), transfer: built.transfer.encode(), proof_a: pa, proof_b: pb };
        if !t.vin.is_empty() {
            t.sign_all(&tx::deposit_key(&self.seed), i.branch_id);
        }
        Ok((built, t))
    }

    fn submit(&self, t: &YugenTx) -> Result<String, String> {
        let hexs = hex::encode(t.serialize());
        match self.node.call("submittransfer", json!([{"tx": hexs, "route": "leaf"}])) {
            Ok(v) => Ok(v["txid"].as_str().map(String::from).unwrap_or_else(|| t.txid())),
            Err(e) if e.code == -32601 => self.node.call("sendrawtransaction", json!([hexs])).map(|v| v.as_str().unwrap_or("").to_string()).map_err(err),
            Err(e) => Err(err(e)),
        }
    }

    /// Deposit: spends the outputs of `fund_txid` that pay the deposit address into a change
    /// note of this wallet (`vb_in = amount`; the note holds amount minus the transfer fee).
    pub fn shield(&mut self, fund_txid: &str) -> Result<Value, String> {
        self.shield_to(fund_txid, None, None)
    }

    /// Deposit to a static full address (hex, §12.1) with an optional memo, or with `to = None`
    /// to this wallet's change. The note goes straight to the recipient's static address in the
    /// deposit transfer (shape: dummy + dummy, negative value balance).
    pub fn shield_to(&mut self, fund_txid: &str, to: Option<&str>, memo: Option<&str>) -> Result<Value, String> {
        let dest = match to {
            None => {
                if memo.map_or(false, |m| !m.is_empty()) {
                    return Err("memo refused: a deposit to this wallet's change carries no memo; give a static address".into());
                }
                None
            }
            // this wallet's own Yugen address (or a request): own change, as `None`
            Some(a) if self.is_own(a) => {
                if memo.map_or(false, |m| !m.is_empty()) {
                    return Err("memo refused: a deposit to this wallet's change carries no memo; give a static address".into());
                }
                None
            }
            Some(a) => Some(self.static_output(a, memo)?),
        };
        self.chain_scan()?;
        let i = self.info()?;
        let key = tx::deposit_key(&self.seed);
        let script = tx::p2pkh_script(&key);
        let raw = self.node.call("getrawtransaction", json!([fund_txid, 1])).map_err(err)?;
        let mut vin = Vec::new();
        let mut total = 0u64;
        let mut prev: [u8; 32] = h(fund_txid);
        prev.reverse();
        for o in raw["vout"].as_array().cloned().unwrap_or_default() {
            let spk = hex::decode(o["scriptPubKey"]["hex"].as_str().unwrap_or("")).unwrap_or_default();
            if spk == script {
                let value = o["valueZat"].as_u64().unwrap_or_else(|| zats(o["value"].as_f64().unwrap_or(0.0)));
                total += value;
                vin.push(TxIn { prev, vout: o["n"].as_u64().unwrap_or(0) as u32, value, script_pubkey: script.clone(), script_sig: vec![] });
            }
        }
        if vin.is_empty() {
            return Err(format!("{fund_txid} pays nothing to the deposit address"));
        }
        let fee = (BASE_FEE) + LEAF_PROOF_FEE;
        if total <= fee {
            return Err("deposit below the transfer fee".into());
        }
        let (ha, abh) = self.anchor(&i)?;
        let n0 = self.st.next_change;
        self.st.next_change += 2;
        let spends = [self.dummy(ha)?, self.dummy(ha)?];
        let first = match dest {
            None => Output::Change { n: n0, v: total - fee },
            Some((addr, memo)) => Output::Static { addr, v: total - fee, memo },
        };
        let outputs = [first, Output::Change { n: n0 + 1, v: 0 }];
        let (built, t) = self.make(&i, spends, outputs, ha, abh, -(total as i64), vec![], vin)?;
        let txid = self.submit(&t)?;
        self.save()?;
        Ok(json!({"txid": txid, "nf1": hex::encode(built.transfer.nf[0]), "amount": coins(total - fee), "fee": coins(fee)}))
    }

    /// Picks up to two applied notes at anchor `ha` covering `need`. Returns (notes, sum).
    fn select(&self, ha: u32, need: u64) -> Result<(Vec<NoteRec>, u64), String> {
        let size = self.st.size_at(ha);
        let mut cand: Vec<_> = self.st.spendable().into_iter().filter(|n| n.pos < size).cloned().collect();
        cand.sort_by(|a, b| b.v.cmp(&a.v));
        let mut picked = Vec::new();
        let mut sum = 0;
        for n in cand {
            if sum >= need || picked.len() == 2 {
                break;
            }
            sum += n.v;
            picked.push(n);
        }
        if sum < need {
            return Err(format!("insufficient applied funds at anchor {ha}: {} < {}", coins(sum), coins(need)));
        }
        Ok((picked, sum))
    }

    fn spends_of(&mut self, ha: u32, picked: &[NoteRec]) -> Result<[Spend; 2], String> {
        let tree = self.st.tree_at(ha);
        let mut sp: Vec<Spend> = picked
            .iter()
            .map(|n| Spend::Note { d: n.addr(), note: n.note(), pos: n.pos, path: Box::new(tree.path(n.pos) as TPath) })
            .collect();
        while sp.len() < 2 {
            let d = self.dummy(ha)?;
            sp.push(d);
        }
        Ok(sp.try_into().unwrap_or_else(|_| unreachable!()))
    }

    fn mark_pending(&mut self, picked: &[NoteRec], txid: &str) {
        for p in picked {
            if let Some(n) = self.st.notes.iter_mut().find(|x| x.nf == p.nf) {
                n.pending = Some(txid.to_string());
            }
        }
    }

    /// Static address 0 (spec §12.1, flag ONCHAIN, no hosts): the full address as hex (the M1
    /// text form; spec 0.5.2 gives a full address no text form of its own) and its short string (§12.2).
    pub fn static_address(&self) -> Value {
        let a = self.my_static();
        json!({"address": hex::encode(a.to_bytes()), "short": a.short_string()})
    }

    /// Parses a static full address (hex, §12.1) and pads a memo to 512 bytes (§10.1).
    fn static_output(&self, to: &str, memo: Option<&str>) -> Result<(FullAddress, Vec<u8>), String> {
        if let Ok(y) = YugenAddress::decode(to, self.st.network) {
            return match y.stat {
                Static::Full(a) => Ok((a, memo_pad(memo)?)),
                Static::Short(f, sa) => Ok((self.resolve_short(f, &sa)?, memo_pad(memo)?)),
            };
        }
        let b = hex::decode(to.trim()).map_err(|_| "not a Yugen address")?;
        let a = FullAddress::from_bytes(&b).ok_or("static full address refused (spec §12.1)")?;
        if !a.valid() || a.network != self.st.network {
            return Err("static full address refused (spec §12.1: network, flags or encapsulation key)".into());
        }
        Ok((a, memo_pad(memo)?))
    }

    /// True for this wallet's own Yugen address (static address 0), or any payment request string.
    fn is_own(&self, to: &str) -> bool {
        match YugenAddress::decode(to, self.st.network) {
            Ok(y) => {
                let m = self.my_static();
                y.stat == Static::Short(m.flags, m.short()) || y.stat == Static::Full(m)
            }
            Err(_) => false,
        }
    }

    /// The Yugen address (ruling 15): by default static address 0 alone, in its 66-character
    /// short form when the wallet has hosts (the full form without); with `onetime` the same plus
    /// a fresh single-payer payment request (new `(day, c)`; about 262 characters), which a sender
    /// pays at once with no host lookup.
    pub fn get_address(&mut self, onetime: bool) -> Result<Value, String> {
        let reusable = !onetime;
        let stat = match &self.hosts {
            // M3 (ruling 11): the short form, its record published at both hosts
            Some(p) => {
                let a = self.my_static();
                p.publish(&a, &crate::hosts::Pair::del_token(&self.seed))?;
                Static::Short(a.flags, a.short())
            }
            None => Static::Full(self.my_static()),
        };
        let request = if reusable {
            None
        } else {
            let tip = self.node.call("getblockcount", json!([])).map_err(err)?.as_u64().unwrap_or(0) as u32;
            let day = issue_day(tip);
            let c = self.st.requests.iter().filter(|(d, _)| *d == day).count() as u16;
            self.st.requests.push((day, c));
            self.save()?;
            Some(self.acct.request(day, c))
        };
        Ok(YugenAddress { network: self.st.network, stat, request }.encode().into())
    }

    /// Leaf-route send to a payment request (§9.2) or to a static full address (§12.1, with an
    /// on-chain note package, §10). A memo is refused for a request (§9.2: "A memo needs a static
    /// address"), never dropped.
    pub fn send(&mut self, to: &str, amount: u64, memo: Option<&str>) -> Result<Value, String> {
        let memo = memo.filter(|m| !m.is_empty());
        // `to`: the Yugen address (UX-1); a §12.1 full address in hex stays accepted for tests. The
        // 0.5.2 strings `yug1…` and `yugreq1…` are refused (ruling 13).
        if yaddr::is_legacy(to) {
            return Err(yaddr::LEGACY_REFUSED.into());
        }
        let ya = match YugenAddress::decode(to, self.st.network) {
            Ok(a) => Some(a),
            Err(e) if yaddr::looks_like(to) => return Err(e.into()),
            Err(_) => None,
        };
        let legacy_req: Option<PaymentRequest> = None;
        if legacy_req.is_some() && memo.is_some() {
            return Err("memo refused: a Yugen payment request carries no memo (spec §9.2: a memo needs a static address)".into());
        }
        self.chain_scan()?;
        let i = self.info()?;
        let fee = BASE_FEE + LEAF_PROOF_FEE;
        let (ha, abh) = self.anchor(&i)?;
        let choice = match (&ya, legacy_req) {
            (Some(a), _) => {
                let paid = |r: &PaymentRequest| self.st.paid_requests.contains(&hex::encode(r.k));
                match yaddr::choose(a, memo.is_some(), ha, paid) {
                    Ok(c) => c,
                    Err(_) if matches!(a.stat, Static::Short(..)) => match &a.stat {
                        Static::Short(f, sa) => match self.cached(*f, sa) {
                            Some(full) => Choice::Static(full),
                            None if self.hosts.is_some() => return self.queue_send(to, amount, memo, i.tip),
                            None => return Err(self.resolve_short(*f, sa).unwrap_err()),
                        },
                        _ => unreachable!(),
                    },
                    Err(e) => return Err(e),
                }
            }
            (None, Some(r)) => Choice::Request(r),
            (None, None) => Choice::Static(self.static_output(to, None)?.0),
        };
        let memo_bytes = match &choice {
            Choice::Static(_) => memo_pad(memo)?,
            Choice::Request(_) => Vec::new(),
        };
        let paid_k = match &choice {
            Choice::Request(r) => Some(hex::encode(r.k)),
            _ => None,
        };
        let (picked, sum) = self.select(ha, amount + fee)?;
        let spends = self.spends_of(ha, &picked)?;
        let n0 = self.st.next_change;
        self.st.next_change += 1;
        let route = if paid_k.is_some() { "request" } else { "static" };
        let first = match choice {
            Choice::Request(req) => Output::Request { req, v: amount },
            Choice::Static(addr) => Output::Static { addr, v: amount, memo: memo_bytes },
        };
        let outputs = [first, Output::Change { n: n0, v: sum - amount - fee }];
        let (built, t) = self.make(&i, spends, outputs, ha, abh, 0, vec![], vec![])?;
        let txid = self.submit(&t)?;
        self.mark_pending(&picked, &txid);
        if let Some(k) = paid_k {
            self.st.paid_requests.push(k);
        }
        self.save()?;
        Ok(json!({"txid": txid, "nf1": hex::encode(built.transfer.nf[0]), "fee": coins(fee), "route": route}))
    }

    /// Queues a payment to a short address until the scheduled sync that resolves it (ruling
    /// 16): nothing is sent to a host now. Checks the funds first, so a payment that cannot be
    /// made is refused at once.
    fn queue_send(&mut self, to: &str, amount: u64, memo: Option<&str>, tip: u32) -> Result<Value, String> {
        let fee = BASE_FEE + LEAF_PROOF_FEE;
        let have = self.st.balance();
        let queued: u64 = self.st.pending_sends.iter().filter(|p| p.state == "waiting").map(|p| p.amount + fee).sum();
        if have < queued + amount + fee {
            return Err(format!("insufficient funds: {} spendable, {} already queued, {} needed", coins(have), coins(queued), coins(amount + fee)));
        }
        memo_pad(memo)?;
        let id = self.st.pending_sends.iter().map(|p| p.id + 1).max().unwrap_or(0);
        self.st.pending_sends.push(PendingSend {
            id,
            to: to.to_string(),
            amount,
            memo: memo.map(String::from),
            queued: tip,
            state: "waiting".into(),
            txid: None,
            error: None,
        });
        self.save()?;
        let next = crate::schedule::next_boundary(tip);
        Ok(json!({"txid": null, "status": "pending", "id": id, "next_sync": next,
                  "message": format!("queued: the address is resolved at the next scheduled sync (block {next}), then paid")}))
    }

    /// Withdrawal (spec §7.9 rule 4): spends notes into one transparent output (any script:
    /// P2PKH, or a post-quantum SLH-DSA / FN-DSA-512 script) with a positive `value_balance`
    /// (§7.1: positive when value leaves the pool), the change back to this wallet. The address is
    /// resolved to its script by the node's `validateaddress`. A Sapling address is refused: a
    /// Yugen transaction has no Sapling part (W-TX), so Yugen to Sapling is two steps through a
    /// transparent address.
    pub fn withdraw(&mut self, to: &str, amount: u64, memo: Option<&str>) -> Result<Value, String> {
        if memo.map_or(false, |m| !m.is_empty()) {
            return Err("memo refused: a transparent output carries no memo (a memo needs a static Yugen address or a Sapling address)".into());
        }
        let va = self.node.call("validateaddress", json!([to])).map_err(err)?;
        let script = match va["scriptPubKey"].as_str() {
            Some(s) if va["isvalid"].as_bool() == Some(true) => hex::decode(s).map_err(err)?,
            _ => {
                let z = self.node.call("z_validateaddress", json!([to])).ok();
                if z.as_ref().and_then(|z| z["isvalid"].as_bool()) == Some(true) {
                    return Err("withdrawal to a shielded (Sapling) address refused: a Yugen transaction has no Sapling part; withdraw to a transparent address, then send it on (two steps)".into());
                }
                return Err(format!("not a transparent address: {to}"));
            }
        };
        if amount == 0 {
            return Err("amount must be positive".into());
        }
        self.chain_scan()?;
        let i = self.info()?;
        let fee = BASE_FEE + LEAF_PROOF_FEE;
        let (ha, abh) = self.anchor(&i)?;
        let (picked, sum) = self.select(ha, amount + fee)?;
        let spends = self.spends_of(ha, &picked)?;
        let n0 = self.st.next_change;
        self.st.next_change += 2;
        let outputs = [Output::Change { n: n0, v: sum - amount - fee }, Output::Change { n: n0 + 1, v: 0 }];
        let vout = vec![TxOut { value: amount, script }];
        let (built, t) = self.make(&i, spends, outputs, ha, abh, amount as i64, vout, vec![])?;
        let txid = self.submit(&t)?;
        self.mark_pending(&picked, &txid);
        self.save()?;
        Ok(json!({"txid": txid, "nf1": hex::encode(built.transfer.nf[0]), "fee": coins(fee), "script": hex::encode(&t.vout[0].script)}))
    }
}

/// Runs `prove a` and `prove b` as two child processes in parallel (each verifies its own
/// proof before printing it). Returns (proof A, proof B).
pub fn prove_both(prover: &Path, stmt: &Value) -> Result<(Vec<u8>, Vec<u8>), String> {
    let spawn = |sys: &str| -> Result<std::process::Child, String> {
        use std::io::Write;
        let mut c = Command::new(prover).args(["prove", sys]).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().map_err(err)?;
        c.stdin.take().unwrap().write_all(stmt.to_string().as_bytes()).map_err(err)?;
        Ok(c)
    };
    let (ca, cb) = (spawn("a")?, spawn("b")?);
    let out = |c: std::process::Child, sys: &str| -> Result<Vec<u8>, String> {
        let o = c.wait_with_output().map_err(err)?;
        if !o.status.success() {
            return Err(format!("prover {sys}: {}", String::from_utf8_lossy(&o.stderr)));
        }
        hex::decode(String::from_utf8_lossy(&o.stdout).trim()).map_err(err)
    };
    Ok((out(ca, "a")?, out(cb, "b")?))
}

pub fn addr_of(d: AddrId) -> String {
    hex::encode(d.to_bytes())
}

/// The cache key of a short address: hex `flags || short`.
fn short_key(f: u8, sa: &[u8; 32]) -> String {
    let mut b = vec![f];
    b.extend_from_slice(sa);
    hex::encode(b)
}

fn h48(s: &str) -> [u8; 48] {
    h::<48>(s)
}

/// A dummy counter start for a remote backend with no record (see `Engine::dummy`).
fn random_dummy_start() -> u32 {
    let mut b = [0u8; 4];
    getrandom::getrandom(&mut b).expect("the system random source");
    (1u32 << 31) + u32::from_le_bytes(b) % ((1u32 << 31) - (1u32 << 20))
}
