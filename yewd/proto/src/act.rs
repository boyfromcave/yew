// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The `YV` act codec and the two set messages (upgrade plan §15.5, §15.2 step 4), re-derived
//! from ycash6 `src/vault/act.cpp` at the revision `yewd/PIN` names and checked against
//! `vault_vectors.json` `acts[]` and `setSigMsgs[]` (plan §4.3 rule 1: pure codecs are re-derived
//! and checked against the vectors, never taken from a kogany crate).
//!
//! An act is an `OP_RETURN` output `OP_RETURN <P> <sig_1> … <sig_k>`: the payload
//! `P = "YV" ‖ 0x01 ‖ type ‖ body` (fixed body size per type) and up to 16 recoverable
//! signatures over `SHA256d("YcashSetAct" ‖ P ‖ vin[0].prevout)`, minimal pushes only.

use yew_core::keys::sha256d;
use yew_core::script;

pub const MAGIC: [u8; 2] = *b"YV";
pub const VERSION: u8 = 0x01;
pub const SET_CREATE: u8 = 0x01;
pub const SET_JOIN: u8 = 0x02;
pub const SET_HEARTBEAT: u8 = 0x03;
pub const SET_REMOVE: u8 = 0x04;
pub const SET_EQUIVOCATION: u8 = 0x05;
pub const SET_WINDDOWN: u8 = 0x06;
pub const SET_FLAG_OPEN: u8 = 0x01;
pub const MAX_SET_SEATS: u8 = 15;
pub const MAX_ACT_SIGS: usize = 1 + MAX_SET_SEATS as usize;
pub const MAX_SET_WINDOW: u32 = 1_048_576;
pub const MAX_RATE_BPS: u16 = 10_000;
pub const SIG_SIZE: usize = 65;

/// An outpoint in internal byte order (`txid` as hashed, not the display order).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct OutPoint {
    pub txid: [u8; 32],
    pub n: u32,
}

impl OutPoint {
    /// From `txid:n` (display txid).
    pub fn parse(s: &str) -> Option<OutPoint> {
        let (t, n) = s.rsplit_once(':')?;
        let txid = yew_core::tx::txid_from_hex(t).ok()?;
        Some(OutPoint {
            txid,
            n: n.parse().ok()?,
        })
    }

    pub fn display(&self) -> String {
        format!("{}:{}", yew_core::tx::txid_hex(&self.txid), self.n)
    }

    /// The 36 bytes `txid ‖ n_le`.
    pub fn bytes(&self) -> [u8; 36] {
        let mut b = [0u8; 36];
        b[..32].copy_from_slice(&self.txid);
        b[32..].copy_from_slice(&self.n.to_le_bytes());
        b
    }
}

impl From<yew_core::tx::OutPoint> for OutPoint {
    fn from(o: yew_core::tx::OutPoint) -> OutPoint {
        OutPoint {
            txid: o.txid,
            n: o.n,
        }
    }
}

/// `SET_CREATE`'s body (`SetCreateBody`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Create {
    pub seats: u8,
    pub unlock_threshold: u8,
    pub cancel_threshold: u8,
    pub slash_threshold: u8,
    pub flags: u8,
    pub rate_limit_bps: u16,
    pub rate_window: u32,
    pub liveness_window: u32,
    pub bond_min: i64,
    pub bond_lock_min: u32,
    pub maturity: u32,
    pub admit_key: [u8; 33],
}

impl Create {
    /// `SetCreateBody::Valid` (the key is checked for its `02`/`03` header only, as the node).
    pub fn valid(&self) -> bool {
        if self.seats < 1 || self.seats > MAX_SET_SEATS {
            return false;
        }
        for t in [
            self.unlock_threshold,
            self.cancel_threshold,
            self.slash_threshold,
        ] {
            if t < 1 || t > self.seats {
                return false;
            }
        }
        self.rate_limit_bps <= MAX_RATE_BPS
            && (1..=MAX_SET_WINDOW).contains(&self.rate_window)
            && (1..=MAX_SET_WINDOW).contains(&self.liveness_window)
            && self.bond_min >= 1
            && self.bond_min <= 21_000_000 * 100_000_000
            && script::is_compressed_key(&self.admit_key)
            && self.flags & !SET_FLAG_OPEN == 0
    }

    pub fn open(&self) -> bool {
        self.flags & SET_FLAG_OPEN != 0
    }
}

/// `SET_EQUIVOCATION`'s body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Equivocation {
    pub set_id: [u8; 32],
    pub prevout: OutPoint,
    pub role_a: u8,
    pub sighash_a: [u8; 32],
    pub sig_a: [u8; SIG_SIZE],
    pub role_b: u8,
    pub sighash_b: [u8; 32],
    pub sig_b: [u8; SIG_SIZE],
}

/// An act body. Set ids are the internal bytes of the create txid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Body {
    Create(Create),
    Join {
        set_id: [u8; 32],
        member_key: [u8; 33],
        bond_locktime: u32,
        bond_vout: u8,
    },
    Heartbeat {
        set_id: [u8; 32],
        member_key: [u8; 33],
    },
    Remove {
        set_id: [u8; 32],
        member_key: [u8; 33],
        burn: u8,
    },
    Equivocation(Box<Equivocation>),
    Winddown {
        set_id: [u8; 32],
    },
}

/// An act: the body and its signatures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Act {
    pub body: Body,
    pub sigs: Vec<[u8; SIG_SIZE]>,
}

/// `ActBodySize`.
pub fn body_size(t: u8) -> usize {
    match t {
        SET_CREATE => 64,
        SET_JOIN => 70,
        SET_HEARTBEAT => 65,
        SET_REMOVE => 66,
        SET_EQUIVOCATION => 264,
        SET_WINDDOWN => 32,
        _ => 0,
    }
}

impl Body {
    pub fn type_byte(&self) -> u8 {
        match self {
            Body::Create(_) => SET_CREATE,
            Body::Join { .. } => SET_JOIN,
            Body::Heartbeat { .. } => SET_HEARTBEAT,
            Body::Remove { .. } => SET_REMOVE,
            Body::Equivocation(_) => SET_EQUIVOCATION,
            Body::Winddown { .. } => SET_WINDDOWN,
        }
    }

    /// The `ActType` name of `doc/vault-rpc.md` (`ActTypeName`).
    pub fn type_name(&self) -> &'static str {
        type_name(self.type_byte())
    }

    /// The set the act names (`Act::TargetSet`; `None` for a create).
    pub fn target_set(&self) -> Option<[u8; 32]> {
        match self {
            Body::Create(_) => None,
            Body::Join { set_id, .. }
            | Body::Heartbeat { set_id, .. }
            | Body::Remove { set_id, .. }
            | Body::Winddown { set_id } => Some(*set_id),
            Body::Equivocation(e) => Some(e.set_id),
        }
    }
}

pub fn type_name(t: u8) -> &'static str {
    match t {
        SET_CREATE => "create",
        SET_JOIN => "join",
        SET_HEARTBEAT => "heartbeat",
        SET_REMOVE => "remove",
        SET_EQUIVOCATION => "equivocation",
        SET_WINDDOWN => "winddown",
        _ => "unknown",
    }
}

/// `ParseActType`.
pub fn type_of_name(s: &str) -> Option<u8> {
    Some(match s {
        "create" => SET_CREATE,
        "join" => SET_JOIN,
        "heartbeat" => SET_HEARTBEAT,
        "remove" => SET_REMOVE,
        "equivocation" => SET_EQUIVOCATION,
        "winddown" => SET_WINDDOWN,
        _ => return None,
    })
}

struct W(Vec<u8>);

impl W {
    fn u8(&mut self, v: u8) {
        self.0.push(v)
    }
    fn u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_le_bytes())
    }
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes())
    }
    fn i64(&mut self, v: i64) {
        self.0.extend_from_slice(&v.to_le_bytes())
    }
    fn b(&mut self, v: &[u8]) {
        self.0.extend_from_slice(v)
    }
}

/// `EncodePayload`.
pub fn encode_payload(b: &Body) -> Vec<u8> {
    let mut w = W(Vec::with_capacity(4 + body_size(b.type_byte())));
    w.b(&MAGIC);
    w.u8(VERSION);
    w.u8(b.type_byte());
    match b {
        Body::Create(c) => {
            w.u8(c.seats);
            w.u8(c.unlock_threshold);
            w.u8(c.cancel_threshold);
            w.u8(c.slash_threshold);
            w.u8(c.flags);
            w.u16(c.rate_limit_bps);
            w.u32(c.rate_window);
            w.u32(c.liveness_window);
            w.i64(c.bond_min);
            w.u32(c.bond_lock_min);
            w.u32(c.maturity);
            w.b(&c.admit_key);
        }
        Body::Join {
            set_id,
            member_key,
            bond_locktime,
            bond_vout,
        } => {
            w.b(set_id);
            w.b(member_key);
            w.u32(*bond_locktime);
            w.u8(*bond_vout);
        }
        Body::Heartbeat { set_id, member_key } => {
            w.b(set_id);
            w.b(member_key);
        }
        Body::Remove {
            set_id,
            member_key,
            burn,
        } => {
            w.b(set_id);
            w.b(member_key);
            w.u8(*burn);
        }
        Body::Equivocation(e) => {
            w.b(&e.set_id);
            w.b(&e.prevout.bytes());
            w.u8(e.role_a);
            w.b(&e.sighash_a);
            w.b(&e.sig_a);
            w.u8(e.role_b);
            w.b(&e.sighash_b);
            w.b(&e.sig_b);
        }
        Body::Winddown { set_id } => w.b(set_id),
    }
    w.0
}

/// `EncodeAct`: `OP_RETURN <P> <sig>…` with minimal pushes.
pub fn encode(a: &Act) -> Vec<u8> {
    let mut s = vec![script::op::OP_RETURN];
    script::push_data(&mut s, &encode_payload(&a.body));
    for sig in &a.sigs {
        script::push_data(&mut s, sig);
    }
    s
}

struct R<'a> {
    b: &'a [u8],
    p: usize,
}

impl R<'_> {
    fn take<const N: usize>(&mut self) -> Option<[u8; N]> {
        let v: [u8; N] = self.b.get(self.p..self.p + N)?.try_into().ok()?;
        self.p += N;
        Some(v)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take::<1>().map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take::<2>().map(u16::from_le_bytes)
    }
    fn u32(&mut self) -> Option<u32> {
        self.take::<4>().map(u32::from_le_bytes)
    }
    fn i64(&mut self) -> Option<i64> {
        self.take::<8>().map(i64::from_le_bytes)
    }
    fn outpoint(&mut self) -> Option<OutPoint> {
        Some(OutPoint {
            txid: self.take::<32>()?,
            n: self.u32()?,
        })
    }
}

/// `DecodePayload`: the node's error identifiers.
pub fn decode_payload(p: &[u8]) -> Result<Body, &'static str> {
    if p.len() < 4 || p[..2] != MAGIC {
        return Err("bad-vault-act-malformed");
    }
    if p[2] != VERSION {
        return Err("bad-vault-act-version");
    }
    let t = p[3];
    let size = body_size(t);
    if size == 0 {
        return Err("bad-vault-act-type");
    }
    if p.len() != 4 + size {
        return Err("bad-vault-act-malformed");
    }
    let mut r = R { b: p, p: 4 };
    let m = "bad-vault-act-malformed";
    let body = match t {
        SET_CREATE => Body::Create(Create {
            seats: r.u8().ok_or(m)?,
            unlock_threshold: r.u8().ok_or(m)?,
            cancel_threshold: r.u8().ok_or(m)?,
            slash_threshold: r.u8().ok_or(m)?,
            flags: r.u8().ok_or(m)?,
            rate_limit_bps: r.u16().ok_or(m)?,
            rate_window: r.u32().ok_or(m)?,
            liveness_window: r.u32().ok_or(m)?,
            bond_min: r.i64().ok_or(m)?,
            bond_lock_min: r.u32().ok_or(m)?,
            maturity: r.u32().ok_or(m)?,
            admit_key: r.take::<33>().ok_or(m)?,
        }),
        SET_JOIN => Body::Join {
            set_id: r.take::<32>().ok_or(m)?,
            member_key: r.take::<33>().ok_or(m)?,
            bond_locktime: r.u32().ok_or(m)?,
            bond_vout: r.u8().ok_or(m)?,
        },
        SET_HEARTBEAT => Body::Heartbeat {
            set_id: r.take::<32>().ok_or(m)?,
            member_key: r.take::<33>().ok_or(m)?,
        },
        SET_REMOVE => Body::Remove {
            set_id: r.take::<32>().ok_or(m)?,
            member_key: r.take::<33>().ok_or(m)?,
            burn: r.u8().ok_or(m)?,
        },
        SET_EQUIVOCATION => Body::Equivocation(Box::new(Equivocation {
            set_id: r.take::<32>().ok_or(m)?,
            prevout: r.outpoint().ok_or(m)?,
            role_a: r.u8().ok_or(m)?,
            sighash_a: r.take::<32>().ok_or(m)?,
            sig_a: r.take::<65>().ok_or(m)?,
            role_b: r.u8().ok_or(m)?,
            sighash_b: r.take::<32>().ok_or(m)?,
            sig_b: r.take::<65>().ok_or(m)?,
        })),
        _ => Body::Winddown {
            set_id: r.take::<32>().ok_or(m)?,
        },
    };
    if r.p != p.len() {
        return Err(m);
    }
    Ok(body)
}

/// The first operation of `s`: its opcode and pushed data (`CScript::GetOp`).
fn first_op(s: &[u8]) -> Option<(u8, &[u8])> {
    let op = *s.first()?;
    let (len, at) = match op {
        0x01..=0x4b => (op as usize, 1),
        script::op::OP_PUSHDATA1 => (*s.get(1)? as usize, 2),
        script::op::OP_PUSHDATA2 => (
            u16::from_le_bytes(s.get(1..3)?.try_into().ok()?) as usize,
            3,
        ),
        script::op::OP_PUSHDATA4 => (
            u32::from_le_bytes(s.get(1..5)?.try_into().ok()?) as usize,
            5,
        ),
        _ => (0, 1),
    };
    Some((op, s.get(at..at + len)?))
}

/// `IsActOutput`: `OP_RETURN` then a push whose data begins `YV`.
pub fn is_act_output(spk: &[u8]) -> bool {
    if spk.first() != Some(&script::op::OP_RETURN) {
        return false;
    }
    first_op(&spk[1..]).is_some_and(|(op, data)| {
        op <= script::op::OP_PUSHDATA4 && data.len() >= 2 && data[..2] == MAGIC
    })
}

/// `DecodeAct`: the act of an act output, canonical encoding only.
pub fn decode(spk: &[u8]) -> Result<Act, &'static str> {
    let m = "bad-vault-act-malformed";
    if spk.first() != Some(&script::op::OP_RETURN) {
        return Err(m);
    }
    let ops = script::ops(&spk[1..]).map_err(|_| m)?;
    let (first, rest) = ops.split_first().ok_or(m)?;
    if first.opcode > script::op::OP_PUSHDATA4 || !first.data.starts_with(&MAGIC) {
        return Err(m);
    }
    let body = decode_payload(&first.data)?;
    let mut sigs = Vec::new();
    for o in rest {
        if o.opcode > script::op::OP_PUSHDATA4 || o.data.len() != SIG_SIZE {
            return Err(m);
        }
        if sigs.len() >= MAX_ACT_SIGS {
            return Err("bad-vault-act-sigs");
        }
        sigs.push(o.data.as_slice().try_into().expect("65 bytes"));
    }
    let a = Act { body, sigs };
    if encode(&a) != spk {
        return Err(m);
    }
    Ok(a)
}

/// `ActMsg`: `SHA256d("YcashSetAct" ‖ P ‖ prevout)`, the 32 bytes the signatures sign.
pub fn act_msg(payload: &[u8], prevout: &OutPoint) -> [u8; 32] {
    let mut m = Vec::with_capacity(11 + payload.len() + 36);
    m.extend_from_slice(b"YcashSetAct");
    m.extend_from_slice(payload);
    m.extend_from_slice(&prevout.bytes());
    sha256d(&m)
}

/// `SetSigMsg`: `SHA256d("YcashSetSig" ‖ setId ‖ role ‖ prevout ‖ sighash)`.
pub fn set_sig_msg(
    set_id: &[u8; 32],
    role: u8,
    prevout: &OutPoint,
    sighash: &[u8; 32],
) -> [u8; 32] {
    let mut m = Vec::with_capacity(11 + 32 + 1 + 36 + 32);
    m.extend_from_slice(b"YcashSetSig");
    m.extend_from_slice(set_id);
    m.push(role);
    m.extend_from_slice(&prevout.bytes());
    m.extend_from_slice(sighash);
    sha256d(&m)
}

/// The bond redeem script `<locktime> CLTV DROP <memberkey> CHECKSIG` and its P2SH output
/// (`BondScriptPubKey`).
pub fn bond_redeem_script(locktime: u32, member_key: &[u8; 33]) -> Vec<u8> {
    let mut s = Vec::with_capacity(48);
    script::push_int(&mut s, locktime as i64);
    s.push(script::op::OP_CHECKLOCKTIMEVERIFY);
    s.push(script::op::OP_DROP);
    script::push_data(&mut s, member_key);
    s.push(script::op::OP_CHECKSIG);
    s
}

pub fn bond_script_pubkey(locktime: u32, member_key: &[u8; 33]) -> Vec<u8> {
    script::p2sh_of(&bond_redeem_script(locktime, member_key))
}

/// The low-S check of a recoverable signature (`RecoverSig`'s).
pub fn low_s(sig: &[u8; SIG_SIZE]) -> bool {
    const HALF: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b,
        0x20, 0xa0,
    ];
    sig[33..] <= HALF[..]
}

/// `ActFieldsValid`: the field rules a decoded act must also pass (signature headers 31..34, the
/// create parameters, compressed keys, the join locktime, the burn flag, the equivocation roles).
pub fn fields_valid(a: &Act) -> bool {
    let header = |s: &[u8; SIG_SIZE]| (31..=34).contains(&s[0]);
    if !a.sigs.iter().all(header) {
        return false;
    }
    let key = |k: &[u8; 33]| script::is_compressed_key(k);
    match &a.body {
        Body::Create(c) => c.valid(),
        Body::Join {
            member_key,
            bond_locktime,
            ..
        } => key(member_key) && *bond_locktime >= 1 && *bond_locktime < 500_000_000,
        Body::Heartbeat { member_key, .. } => key(member_key),
        Body::Remove {
            member_key, burn, ..
        } => key(member_key) && *burn <= 1,
        Body::Equivocation(e) => {
            matches!(e.role_a, 1 | 2)
                && matches!(e.role_b, 1 | 2)
                && header(&e.sig_a)
                && header(&e.sig_b)
        }
        Body::Winddown { .. } => true,
    }
}

/// `RecoverSig`: the compressed key a 65-byte recoverable signature (`header ‖ r ‖ s`, header
/// 31..34, low S) recovers to over `msg`, or `None`.
pub fn recover(msg: &[u8; 32], sig: &[u8; SIG_SIZE]) -> Option<[u8; 33]> {
    use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
    if !(31..=34).contains(&sig[0]) || !low_s(sig) {
        return None;
    }
    let rs = RecoverableSignature::from_compact(&sig[1..], RecoveryId::from_u8_masked(sig[0] - 31))
        .ok()?;
    let pk = rs
        .recover_ecdsa(secp256k1::Message::from_digest(*msg))
        .ok()?;
    Some(pk.serialize())
}

/// `SignRecoverable` (`CKey::SignCompact`, RFC 6979): `27 + 4 + recid ‖ r ‖ s`.
pub fn sign_recoverable(secret: &secp256k1::SecretKey, msg: &[u8; 32]) -> [u8; SIG_SIZE] {
    use secp256k1::ecdsa::RecoverableSignature;
    let rs =
        RecoverableSignature::sign_ecdsa_recoverable(secp256k1::Message::from_digest(*msg), secret);
    let (id, rs) = rs.serialize_compact();
    let mut out = [0u8; SIG_SIZE];
    out[0] = 31 + id.to_u8();
    out[1..].copy_from_slice(&rs);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_round_trips() {
        let c = Create {
            seats: 3,
            unlock_threshold: 2,
            cancel_threshold: 1,
            slash_threshold: 2,
            flags: 0,
            rate_limit_bps: 0,
            rate_window: 144,
            liveness_window: 1000,
            bond_min: 100_000_000,
            bond_lock_min: 0,
            maturity: 2,
            admit_key: [2u8; 33],
        };
        assert!(c.valid());
        let a = Act {
            body: Body::Create(c),
            sigs: vec![],
        };
        let spk = encode(&a);
        assert!(is_act_output(&spk));
        assert_eq!(decode(&spk).unwrap(), a);
        assert_eq!(encode_payload(&a.body).len(), 4 + 64);
    }
}
