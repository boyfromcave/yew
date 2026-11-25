// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! Copied from lightwalletd-dd yugen/hostd/src/dpf.rs (yugen/mailbox 2a67449); keep the two identical.
//! Two-server point function over a domain of `2^depth` indices (spec §17.6).
//!
//! Provenance: the tree construction (seeds, control bits, one correction word per level) is
//! Published: Boyle, Gilboa, Ishai, "Function Secret Sharing" (BGI16), as `yugen-pir`
//! `docs/pir-selection.md` §3.1 describes it; the paper is not in the reference folder and was not
//! read (from memory through that document, as spec §17.6 states). The length-doubling PRG is the
//! spec's `G(s) = H_dpf-prg(s)` at 256-bit seeds (`yugen_ref::hostidx::dpf_prg`).
//! Adapted (changes: output group GF(2), the leaf control bit is the output, no final correction
//! word and no `Convert`/early termination): an answer is the XOR of the entries whose bit is 1, so
//! the XOR of the two answers is the entry at the queried index. Not the spec's early-termination
//! form; the client check (§17.5) is unchanged by the choice. Evaluation is limited to the used
//! prefix `[0, n)` of the domain (entries beyond `n` are all zero, so they add nothing).

use yugen_ref::hostidx::dpf_prg;

pub type B32 = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Key {
    pub party: u8,
    pub seed: B32,
    /// Per level: (seed correction, left bit correction, right bit correction).
    pub cw: Vec<(B32, u8, u8)>,
}

fn xor(a: &B32, b: &B32) -> B32 {
    let mut o = *a;
    for i in 0..32 {
        o[i] ^= b[i];
    }
    o
}

/// Keys for the point function at `alpha` over `2^depth` indices, from two 32-byte random seeds.
pub fn gen(alpha: u64, depth: usize, r0: B32, r1: B32) -> (Key, Key) {
    assert!(depth <= 63 && alpha >> depth == 0);
    let (mut s0, mut s1, mut t0, mut t1) = (r0, r1, 0u8, 1u8);
    let mut cw = Vec::with_capacity(depth);
    for l in 0..depth {
        let bit = ((alpha >> (depth - 1 - l)) & 1) as u8;
        let (a_l, a_r, at_l, at_r) = dpf_prg(&s0);
        let (b_l, b_r, bt_l, bt_r) = dpf_prg(&s1);
        let scw = if bit == 0 { xor(&a_r, &b_r) } else { xor(&a_l, &b_l) };
        let tl = at_l ^ bt_l ^ bit ^ 1;
        let tr = at_r ^ bt_r ^ bit;
        let (ka, kb, kta, ktb, tk) = if bit == 0 { (a_l, b_l, at_l, bt_l, tl) } else { (a_r, b_r, at_r, bt_r, tr) };
        s0 = if t0 == 1 { xor(&ka, &scw) } else { ka };
        s1 = if t1 == 1 { xor(&kb, &scw) } else { kb };
        let n0 = kta ^ (t0 & tk);
        let n1 = ktb ^ (t1 & tk);
        t0 = n0;
        t1 = n1;
        cw.push((scw, tl, tr));
    }
    (Key { party: 0, seed: r0, cw: cw.clone() }, Key { party: 1, seed: r1, cw })
}

/// Fresh keys from the OS random source.
pub fn gen_random(alpha: u64, depth: usize) -> (Key, Key) {
    let mut r = [0u8; 64];
    getrandom::getrandom(&mut r).expect("os random");
    gen(alpha, depth, r[..32].try_into().unwrap(), r[32..].try_into().unwrap())
}

impl Key {
    pub fn depth(&self) -> usize {
        self.cw.len()
    }
    /// `party(1) || seed(32) || depth(1) || depth × (cw(32) || tl(1) || tr(1))`.
    pub fn encode(&self) -> Vec<u8> {
        let mut o = vec![self.party];
        o.extend_from_slice(&self.seed);
        o.push(self.cw.len() as u8);
        for (s, l, r) in &self.cw {
            o.extend_from_slice(s);
            o.push(*l);
            o.push(*r);
        }
        o
    }
    pub fn decode(b: &[u8]) -> Option<Key> {
        let (&party, rest) = b.split_first()?;
        if party > 1 || rest.len() < 33 {
            return None;
        }
        let seed: B32 = rest[..32].try_into().ok()?;
        let d = rest[32] as usize;
        let body = &rest[33..];
        if d > 63 || body.len() != d * 34 {
            return None;
        }
        let mut cw = Vec::with_capacity(d);
        for c in body.chunks(34) {
            if c[32] > 1 || c[33] > 1 {
                return None;
            }
            cw.push((c[..32].try_into().unwrap(), c[32], c[33]));
        }
        Some(Key { party, seed, cw })
    }
    /// The output bit at every index of `[0, n)`.
    pub fn eval_prefix(&self, n: u64) -> Vec<u8> {
        let d = self.depth();
        let mut out = Vec::with_capacity(n as usize);
        // depth-first over the nodes whose subtree intersects [0, n)
        fn walk(k: &Key, level: usize, prefix: u64, s: B32, t: u8, n: u64, out: &mut Vec<u8>) {
            let d = k.cw.len();
            if level == d {
                out.push(t);
                return;
            }
            let (mut sl, mut sr, mut tl, mut tr) = dpf_prg(&s);
            if t == 1 {
                let (c, cl, cr) = &k.cw[level];
                sl = xor(&sl, c);
                sr = xor(&sr, c);
                tl ^= cl;
                tr ^= cr;
            }
            let span = 1u64 << (d - level - 1);
            let left = prefix << 1;
            if left * span < n {
                walk(k, level + 1, left, sl, tl, n, out);
            }
            if (left + 1) * span < n {
                walk(k, level + 1, left + 1, sr, tr, n, out);
            }
        }
        if n > 0 {
            walk(self, 0, 0, self.seed, self.party, n.min(1u64 << d), &mut out);
        }
        out
    }
}

/// A host's answer: the XOR of the entries whose output bit is 1 (`entries` all of one length).
pub fn answer(key: &Key, entries: &[Vec<u8>], len: usize) -> Vec<u8> {
    let bits = key.eval_prefix(entries.len() as u64);
    let mut acc = vec![0u8; len];
    for (e, b) in entries.iter().zip(bits) {
        if b == 1 {
            for (a, x) in acc.iter_mut().zip(e) {
                *a ^= x;
            }
        }
    }
    acc
}
