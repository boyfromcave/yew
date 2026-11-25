// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The Yugen address (proposal UX-1, yugen-spec branch `ux-address` 104cc0b,
//! `spec/decision-yugen-address.md`): one Bech32m string carrying the static address (full §12.1
//! or short §12.2) and an optional payment request (§9.1). Rules P-1 (encoding), P-2 (refusals),
//! P-3 (the sender's choice). Bech32m is BIP 350 without a length limit, written here because the
//! `bech32` crate caps a string at 1,023 characters and the full form is about 2,660.

use yugen_ref::address::FullAddress;
use yugen_ref::params::*;
use yugen_ref::request::PaymentRequest;

const CS: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32M: u32 = 0x2bc8_30a3;
pub const FORM_FULL: u8 = 0x01;
pub const FORM_REQ: u8 = 0x02;

fn polymod(v: &[u8]) -> u32 {
    const G: [u32; 5] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];
    let mut c = 1u32;
    for &x in v {
        let b = c >> 25;
        c = ((c & 0x1ff_ffff) << 5) ^ x as u32;
        for (i, g) in G.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                c ^= g;
            }
        }
    }
    c
}
fn hrp_expand(h: &str) -> Vec<u8> {
    let mut v: Vec<u8> = h.bytes().map(|x| x >> 5).collect();
    v.push(0);
    v.extend(h.bytes().map(|x| x & 31));
    v
}
fn convert(data: &[u8], from: u32, to: u32, pad: bool) -> Option<Vec<u8>> {
    let (mut acc, mut n, mut out) = (0u32, 0u32, Vec::new());
    for &x in data {
        acc = (acc << from) | x as u32;
        n += from;
        while n >= to {
            n -= to;
            out.push(((acc >> n) & ((1 << to) - 1)) as u8);
        }
        acc &= (1 << n) - 1;
    }
    if pad {
        if n > 0 {
            out.push(((acc << (to - n)) & ((1 << to) - 1)) as u8);
        }
    } else if n >= from || acc != 0 {
        return None;
    }
    Some(out)
}
pub fn bech32m_encode(hrp: &str, data: &[u8]) -> String {
    let d = convert(data, 8, 5, true).unwrap();
    let mut e = hrp_expand(hrp);
    e.extend(&d);
    e.extend([0u8; 6]);
    let p = polymod(&e) ^ BECH32M;
    let mut s = String::with_capacity(hrp.len() + 1 + d.len() + 6);
    s.push_str(hrp);
    s.push('1');
    s.extend(d.iter().map(|&x| CS[x as usize] as char));
    s.extend((0..6).map(|i| CS[((p >> (5 * (5 - i))) & 31) as usize] as char));
    s
}
pub fn bech32m_decode(s: &str) -> Option<(String, Vec<u8>)> {
    if s.to_lowercase() != s && s.to_uppercase() != s {
        return None;
    }
    let s = s.to_lowercase();
    let i = s.rfind('1')?;
    if i < 1 || s.len() - i < 7 {
        return None;
    }
    let d: Vec<u8> = s[i + 1..].bytes().map(|c| CS.iter().position(|&x| x == c).map(|p| p as u8)).collect::<Option<_>>()?;
    let mut e = hrp_expand(&s[..i]);
    e.extend(&d);
    if polymod(&e) != BECH32M {
        return None;
    }
    Some((s[..i].to_string(), convert(&d[..d.len() - 6], 5, 8, false)?))
}

/// HRP (lead architect's ruling 14): `yq`, the network letter on test/regtest, the scheme letter:
/// `yqf`/`yqtf`/`yqrf` (Falcon-512), `yqk`/`yqtk`/`yqrk` (Falcon-1024, refused until enabled).
pub fn hrp(network: u8, scheme2: bool) -> String {
    let n = match network {
        NET_MAIN => "",
        NET_TEST => "t",
        _ => "r",
    };
    format!("yq{n}{}", if scheme2 { 'k' } else { 'f' })
}

/// The 0.5.2 test strings (`yug1…` short address, `yugreq1…` request), refused everywhere (ruling 13).
pub fn is_legacy(s: &str) -> bool {
    let s = s.trim().to_lowercase();
    // spec 0.5.2 HRPs: yug / yugtest / yugregtest (§12.2), yugreq / yugreqtest / yugreqregtest (§9.1)
    ["yug1", "yugtest1", "yugregtest1", "yugreq1", "yugreqtest1", "yugreqregtest1"].iter().any(|p| s.starts_with(p))
}
pub const LEGACY_REFUSED: &str = "refused: yug1…/yugreq1… strings are withdrawn (ruling 13); use the Yugen address (yqf…/yqtf…/yqrf…)";

/// True if `s` carries one of the six Yugen address prefixes (then its decode error is reported).
pub fn looks_like(s: &str) -> bool {
    let s = s.trim().to_lowercase();
    ["yqf1", "yqtf1", "yqrf1", "yqk1", "yqtk1", "yqrk1"].iter().any(|p| s.starts_with(p) && s.len() > p.len())
}

/// The static part of a Yugen address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Static {
    Full(FullAddress),
    /// `(flags, short)` (§12.2); resolved through its record (§12.3).
    Short(u8, [u8; 32]),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct YugenAddress {
    pub network: u8,
    pub stat: Static,
    pub request: Option<PaymentRequest>,
}

impl YugenAddress {
    fn flags(&self) -> u8 {
        match &self.stat {
            Static::Full(a) => a.flags,
            Static::Short(f, _) => *f,
        }
    }
    /// The payload bytes and HRP (P-1).
    pub fn encode(&self) -> String {
        let mut p = vec![if matches!(self.stat, Static::Full(_)) { FORM_FULL } else { 0 } | if self.request.is_some() { FORM_REQ } else { 0 }];
        match &self.stat {
            Static::Full(a) => {
                let b = a.to_bytes();
                p.extend((b.len() as u16).to_le_bytes());
                p.extend(b);
            }
            Static::Short(f, s) => {
                p.extend([ADDR_VERSION, *f]);
                p.extend(s);
            }
        }
        if let Some(r) = &self.request {
            p.extend(r.to_bytes());
        }
        bech32m_encode(&hrp(self.network, self.flags() & ADDR_FLAG_SCHEME2 != 0), &p)
    }

    /// Parses and applies every refusal of P-2 for a wallet on `network`.
    pub fn decode(s: &str, network: u8) -> Result<Self, &'static str> {
        let (h, p) = bech32m_decode(s.trim()).ok_or("not a Yugen address (Bech32m)")?;
        let net = [NET_MAIN, NET_TEST, NET_REGTEST].into_iter().find(|n| h == hrp(*n, false) || h == hrp(*n, true)).ok_or("not a Yugen address (prefix)")?;
        if net != network {
            return Err("Yugen address of another network");
        }
        let sch = h.ends_with('k');
        let (&form, mut q) = p.split_first().ok_or("Yugen address: empty")?;
        if form & !(FORM_FULL | FORM_REQ) != 0 {
            return Err("Yugen address: unknown form");
        }
        let stat = if form & FORM_FULL != 0 {
            if q.len() < 2 {
                return Err("Yugen address: length");
            }
            let n = u16::from_le_bytes([q[0], q[1]]) as usize;
            let b = q.get(2..2 + n).ok_or("Yugen address: length")?;
            q = &q[2 + n..];
            let a = FullAddress::from_bytes(b).ok_or("Yugen address: static address refused (spec §12.1)")?;
            if a.network != net {
                return Err("Yugen address of another network");
            }
            Static::Full(a)
        } else {
            let b = q.get(..34).ok_or("Yugen address: length")?;
            q = &q[34..];
            if b[0] != ADDR_VERSION || b[1] & !yugen_ref::address::addr_flags_accepted() != 0 {
                return Err("Yugen address: short address refused (spec §12.2)");
            }
            Static::Short(b[1], b[2..].try_into().unwrap())
        };
        let a = YugenAddress { network: net, stat, request: None };
        if (a.flags() & ADDR_FLAG_SCHEME2 != 0) != sch {
            return Err("Yugen address: scheme letter disagrees with the address");
        }
        let request = if form & FORM_REQ != 0 {
            let b = q.get(..122).ok_or("Yugen address: length")?;
            q = &q[122..];
            let r = PaymentRequest::from_bytes(b).ok_or("Yugen address: request refused (spec §9.2)")?;
            if r.network != net || (b[0] & REQ_SCHEME2 != 0) != sch {
                return Err("Yugen address: request disagrees with the address");
            }
            Some(r)
        } else {
            None
        };
        if !q.is_empty() {
            return Err("Yugen address: trailing bytes");
        }
        let a = YugenAddress { request, ..a };
        if a.encode() != s.trim().to_lowercase() {
            return Err("Yugen address: not canonical");
        }
        Ok(a)
    }
}

/// What the sender pays (P-3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Choice {
    Request(PaymentRequest),
    Static(FullAddress),
}

/// P-3: the request if present, no memo, payable at `anchor_height` (§9.2), not paid before by
/// this wallet; otherwise the static address (the full part; a short part needs its record).
pub fn choose(a: &YugenAddress, memo: bool, anchor_height: u32, paid_before: impl Fn(&PaymentRequest) -> bool) -> Result<Choice, String> {
    if let Some(r) = &a.request {
        if !memo && r.payable(anchor_height) && !paid_before(r) {
            return Ok(Choice::Request(r.clone()));
        }
    }
    match &a.stat {
        Static::Full(f) => Ok(Choice::Static(f.clone())),
        Static::Short(..) => Err("this Yugen address needs its record from a mailbox host (spec §12.3), not available at M1".into()),
    }
}
