//! The Yellowback payload codec, version 3: `"YB" ‖ 0x03 ‖ type ‖ body`, the data of a
//! transaction's only `OP_RETURN` output (spec §3.3; v3 §3.3).
//!
//! Translation source (plan §3.6): `ycash-dd/src/yellowback/payload.{h,cpp}`
//! (`feature/yellowback-price-attest`). The node's decoder is the parse the spec means, so this
//! file keeps its structure: a bounds-checked little-endian reader that never panics, one
//! body per type, `EncodePayload`/`DecodePayload`, `ExtractOpReturnData`, `FindOpReturn`,
//! `FindPayload`. Client contract rule 3: a decoded payload is for **display and for the
//! `PreLock` pending rule only**, never a verdict — verdicts come from `GetTxInfo`.
//!
//! Layout (`payload.h:19-40`): all multi-byte integers fixed-width little-endian, total 4..80
//! bytes, trailing bytes ⇒ malformed, unknown type or version ⇒ non-Yellowback (V23).
//!
//! | type | body | size |
//! |---|---|---|
//! | `0x01` MINT | `termClass u8, cents u32, lockHeight u32, refHeight u32, ownerPubKey 33, feeVout u8, attestFeeVout u8` | 52 |
//! | `0x02` TRANSFER | `count u8, count × (vout u8, cents u32)` | 5 + 5n, n ≤ 15 |
//! | `0x03` REDEEM | `refHeight u32, feeVout u8, attestFeeVout u8, count u8, count × (vout u8, cents u32)` | 11 + 5n, n ≤ 13 |
//! | `0x05` ATTESTOR_REGISTER | `attestorPubKey 33, bondPubKey 33, bondLocktime u32, flags u8` | 75 |
//! | `0x06` CLAIM_NOTICE | `vaultTxid 32, vaultVout u8, refHeight u32` | 41 |
//! | `0x07` EQUIVOCATION | (empty) | 4 |
//! | `0x08` ATTESTOR_REVIVE | `seq u16, priceMicroUsd u32, citedHeight u32, sig 64` | 78 |

use std::collections::HashSet;

use crate::script::{self, op};
use crate::tx::Transaction;

/// `PAYLOAD_MAGIC_0`, `PAYLOAD_MAGIC_1` (`ycash-dd/src/yellowback/params.h:43-44`): `"YB"`.
pub const MAGIC: [u8; 2] = [0x59, 0x42];
/// `PAYLOAD_VERSION` (`params.h:45`).
pub const VERSION: u8 = 0x03;
/// `MIN_PAYLOAD` (`params.h:50`): the four-byte header alone.
pub const MIN_PAYLOAD: usize = 4;
/// `MAX_PAYLOAD` (`params.h:49`): the `OP_RETURN` data cap.
pub const MAX_PAYLOAD: usize = 80;
/// `FEE_VOUT_NONE` (`params.h:86`): "no such fee output".
pub const FEE_VOUT_NONE: u8 = 0xFF;
/// `MAX_ASSIGNMENTS` (`payload.h:74`): TRANSFER, `5 + 5·count ≤ 80`.
pub const MAX_ASSIGNMENTS: usize = 15;
/// `MAX_REDEEM_ASSIGNMENTS` (`payload.h:76`): REDEEM, `11 + 5·count ≤ 80`.
pub const MAX_REDEEM_ASSIGNMENTS: usize = 13;
/// `COMPACT_SIG_SIZE` (`payload.h:78`).
pub const COMPACT_SIG_SIZE: usize = 64;

const KEY_SIZE: usize = 33;
const MINT_BODY_SIZE: usize = 1 + 4 + 4 + 4 + KEY_SIZE + 1 + 1; // 48 (payload.cpp:16)
const REDEEM_HEAD_SIZE: usize = 4 + 1 + 1 + 1; // payload.cpp:17
const REGISTER_BODY_SIZE: usize = KEY_SIZE + KEY_SIZE + 4 + 1; // 71
const NOTICE_BODY_SIZE: usize = 32 + 1 + 4; // 37
const REVIVE_BODY_SIZE: usize = 2 + 4 + 4 + COMPACT_SIG_SIZE; // 74

/// `PayloadType` (`payload.h:58-66`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PayloadType {
    /// `0x01`.
    Mint = 0x01,
    /// `0x02`.
    Transfer = 0x02,
    /// `0x03`.
    Redeem = 0x03,
    /// `0x05`.
    AttestorRegister = 0x05,
    /// `0x06`.
    ClaimNotice = 0x06,
    /// `0x07`.
    Equivocation = 0x07,
    /// `0x08`.
    AttestorRevive = 0x08,
}

impl PayloadType {
    /// `PayloadTypeName` (`payload.cpp:433-445`): the RPC's `type` strings.
    pub fn name(self) -> &'static str {
        match self {
            PayloadType::Mint => "mint",
            PayloadType::Transfer => "transfer",
            PayloadType::Redeem => "redeem",
            PayloadType::AttestorRegister => "register",
            PayloadType::ClaimNotice => "notice",
            PayloadType::Equivocation => "equivocation",
            PayloadType::AttestorRevive => "revive",
        }
    }

    fn from_byte(b: u8) -> Option<PayloadType> {
        Some(match b {
            0x01 => PayloadType::Mint,
            0x02 => PayloadType::Transfer,
            0x03 => PayloadType::Redeem,
            0x05 => PayloadType::AttestorRegister,
            0x06 => PayloadType::ClaimNotice,
            0x07 => PayloadType::Equivocation,
            0x08 => PayloadType::AttestorRevive,
            _ => return None, // 0x04, 0x09-0xFF: reserved, non-Yellowback
        })
    }
}

/// One `(vout, cents)` assignment of a TRANSFER or REDEEM body (`payload.h:69`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Assignment {
    /// The output index the cents are assigned to.
    pub vout: u8,
    /// The cents; never 0 in a valid payload.
    pub cents: u32,
}

/// A decoded (or to-be-encoded) payload. The node's `Payload` is one struct with every field;
/// here each type carries its own body so an impossible combination cannot be expressed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Payload {
    /// MINT (`Payload::Mint`, `payload.cpp:95`).
    Mint {
        /// `0` = A, `1` = B, `2` = C; any byte decodes, MINT-2 judges it.
        term_class: u8,
        /// The minted cents.
        cents: u32,
        /// The vault's lock height.
        lock_height: u32,
        /// The reference height.
        ref_height: u32,
        /// The 33 owner-key bytes verbatim (MINT-3 judges them).
        owner_key: [u8; 33],
        /// The enforcement-fee output, or `FEE_VOUT_NONE`.
        fee_vout: u8,
        /// The attestor-fee output, or `FEE_VOUT_NONE`.
        attest_fee_vout: u8,
    },
    /// TRANSFER (`Payload::Transfer`, `payload.cpp:170`).
    Transfer {
        /// The assignments, at most `MAX_ASSIGNMENTS`.
        assignments: Vec<Assignment>,
    },
    /// REDEEM (`Payload::Redeem`, `payload.cpp:110`).
    Redeem {
        /// The reference height (V11).
        ref_height: u32,
        /// The enforcement-fee output, or `FEE_VOUT_NONE`.
        fee_vout: u8,
        /// The attestor-fee output, or `FEE_VOUT_NONE`.
        attest_fee_vout: u8,
        /// YED change assignments, at most `MAX_REDEEM_ASSIGNMENTS` (empty allowed).
        assignments: Vec<Assignment>,
    },
    /// ATTESTOR_REGISTER (`payload.cpp:121`).
    AttestorRegister {
        /// The attestor key bytes.
        attestor_key: [u8; 33],
        /// The bond key bytes.
        bond_key: [u8; 33],
        /// The bond's locktime.
        bond_locktime: u32,
        /// Flags.
        flags: u8,
    },
    /// CLAIM_NOTICE (`payload.cpp:134`).
    ClaimNotice {
        /// The vault txid, internal byte order (the payload bytes verbatim).
        vault_txid: [u8; 32],
        /// The vault vout.
        vault_vout: u8,
        /// The reference height.
        ref_height: u32,
    },
    /// EQUIVOCATION (`payload.cpp:149`): empty body.
    Equivocation,
    /// ATTESTOR_REVIVE (`payload.cpp:156`).
    AttestorRevive {
        /// The attestor's seq.
        seq: u16,
        /// The attested price.
        price_micro_usd: u32,
        /// The cited height.
        cited_height: u32,
        /// The compact signature.
        sig: [u8; 64],
    },
}

impl Payload {
    /// The type byte.
    pub fn payload_type(&self) -> PayloadType {
        match self {
            Payload::Mint { .. } => PayloadType::Mint,
            Payload::Transfer { .. } => PayloadType::Transfer,
            Payload::Redeem { .. } => PayloadType::Redeem,
            Payload::AttestorRegister { .. } => PayloadType::AttestorRegister,
            Payload::ClaimNotice { .. } => PayloadType::ClaimNotice,
            Payload::Equivocation => PayloadType::Equivocation,
            Payload::AttestorRevive { .. } => PayloadType::AttestorRevive,
        }
    }

    /// The assignments of a TRANSFER or REDEEM; empty otherwise.
    pub fn assignments(&self) -> &[Assignment] {
        match self {
            Payload::Transfer { assignments } | Payload::Redeem { assignments, .. } => assignments,
            _ => &[],
        }
    }

    /// `AssignedCents` (`payload.cpp:177`): the sum of assigned cents (fits `i64`, 15 × 2³²).
    pub fn assigned_cents(&self) -> i64 {
        self.assignments().iter().map(|a| a.cents as i64).sum()
    }
}

/// A bounds-checked little-endian reader (`payload.cpp:22-67`). Never panics.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn u8(&mut self) -> Option<u8> {
        let v = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(v)
    }
    fn u16(&mut self) -> Option<u16> {
        let b = self.bytes(2)?;
        Some(u16::from_le_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Option<u32> {
        let b = self.bytes(4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }
    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.bytes(N)?);
        Some(out)
    }
    fn at_end(&self) -> bool {
        self.pos == self.data.len()
    }
}

/// `ValidAssignments` (`payload.cpp:89-98`): at most `max`, no `cents == 0`, no duplicate vout.
fn valid_assignments(assignments: &[Assignment], max: usize) -> bool {
    if assignments.len() > max {
        return false;
    }
    let mut seen = HashSet::new();
    assignments
        .iter()
        .all(|a| a.cents != 0 && seen.insert(a.vout))
}

fn read_assignments(r: &mut Reader<'_>, count: u8) -> Option<Vec<Assignment>> {
    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        out.push(Assignment {
            vout: r.u8()?,
            cents: r.u32()?,
        });
    }
    Some(out)
}

fn put_assignments(out: &mut Vec<u8>, assignments: &[Assignment]) {
    out.push(assignments.len() as u8);
    for a in assignments {
        out.push(a.vout);
        out.extend_from_slice(&a.cents.to_le_bytes());
    }
}

/// `EncodePayload` (`payload.cpp:341-398`): the bytes of the `OP_RETURN` data push, or `None`
/// when the payload is not encodable (bad assignments, over `MAX_PAYLOAD`).
pub fn encode(payload: &Payload) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(MAX_PAYLOAD);
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    out.push(payload.payload_type() as u8);
    match payload {
        Payload::Mint {
            term_class,
            cents,
            lock_height,
            ref_height,
            owner_key,
            fee_vout,
            attest_fee_vout,
        } => {
            out.push(*term_class);
            out.extend_from_slice(&cents.to_le_bytes());
            out.extend_from_slice(&lock_height.to_le_bytes());
            out.extend_from_slice(&ref_height.to_le_bytes());
            out.extend_from_slice(owner_key);
            out.push(*fee_vout);
            out.push(*attest_fee_vout);
        }
        Payload::Transfer { assignments } => {
            if !valid_assignments(assignments, MAX_ASSIGNMENTS) {
                return None;
            }
            put_assignments(&mut out, assignments);
        }
        Payload::Redeem {
            ref_height,
            fee_vout,
            attest_fee_vout,
            assignments,
        } => {
            if !valid_assignments(assignments, MAX_REDEEM_ASSIGNMENTS) {
                return None;
            }
            out.extend_from_slice(&ref_height.to_le_bytes());
            out.push(*fee_vout);
            out.push(*attest_fee_vout);
            put_assignments(&mut out, assignments);
        }
        Payload::AttestorRegister {
            attestor_key,
            bond_key,
            bond_locktime,
            flags,
        } => {
            out.extend_from_slice(attestor_key);
            out.extend_from_slice(bond_key);
            out.extend_from_slice(&bond_locktime.to_le_bytes());
            out.push(*flags);
        }
        Payload::ClaimNotice {
            vault_txid,
            vault_vout,
            ref_height,
        } => {
            out.extend_from_slice(vault_txid);
            out.push(*vault_vout);
            out.extend_from_slice(&ref_height.to_le_bytes());
        }
        Payload::Equivocation => {}
        Payload::AttestorRevive {
            seq,
            price_micro_usd,
            cited_height,
            sig,
        } => {
            out.extend_from_slice(&seq.to_le_bytes());
            out.extend_from_slice(&price_micro_usd.to_le_bytes());
            out.extend_from_slice(&cited_height.to_le_bytes());
            out.extend_from_slice(sig);
        }
    }
    if out.len() > MAX_PAYLOAD {
        return None;
    }
    Some(out)
}

/// `DecodeBodyV3` (`payload.cpp:248-320`): one body per type, size-checked.
fn decode_body_v3(r: &mut Reader<'_>, t: PayloadType, size: usize) -> Option<Payload> {
    Some(match t {
        PayloadType::Mint => {
            if size != 4 + MINT_BODY_SIZE {
                return None;
            }
            Payload::Mint {
                term_class: r.u8()?,
                cents: r.u32()?,
                lock_height: r.u32()?,
                ref_height: r.u32()?,
                owner_key: r.array::<33>()?,
                fee_vout: r.u8()?,
                attest_fee_vout: r.u8()?,
            }
        }
        PayloadType::Transfer => {
            let count = r.u8()?;
            if count as usize > MAX_ASSIGNMENTS || size != 5 + 5 * count as usize {
                return None;
            }
            let assignments = read_assignments(r, count)?;
            if !valid_assignments(&assignments, MAX_ASSIGNMENTS) {
                return None;
            }
            Payload::Transfer { assignments }
        }
        PayloadType::Redeem => {
            let ref_height = r.u32()?;
            let fee_vout = r.u8()?;
            let attest_fee_vout = r.u8()?;
            let count = r.u8()?;
            if count as usize > MAX_REDEEM_ASSIGNMENTS
                || size != 4 + REDEEM_HEAD_SIZE + 5 * count as usize
            {
                return None;
            }
            let assignments = read_assignments(r, count)?;
            if !valid_assignments(&assignments, MAX_REDEEM_ASSIGNMENTS) {
                return None;
            }
            Payload::Redeem {
                ref_height,
                fee_vout,
                attest_fee_vout,
                assignments,
            }
        }
        PayloadType::AttestorRegister => {
            if size != 4 + REGISTER_BODY_SIZE {
                return None;
            }
            Payload::AttestorRegister {
                attestor_key: r.array::<33>()?,
                bond_key: r.array::<33>()?,
                bond_locktime: r.u32()?,
                flags: r.u8()?,
            }
        }
        PayloadType::ClaimNotice => {
            if size != 4 + NOTICE_BODY_SIZE {
                return None;
            }
            Payload::ClaimNotice {
                vault_txid: r.array::<32>()?,
                vault_vout: r.u8()?,
                ref_height: r.u32()?,
            }
        }
        PayloadType::Equivocation => {
            if size != 4 {
                return None;
            }
            Payload::Equivocation
        }
        PayloadType::AttestorRevive => {
            if size != 4 + REVIVE_BODY_SIZE {
                return None;
            }
            Payload::AttestorRevive {
                seq: r.u16()?,
                price_micro_usd: r.u32()?,
                cited_height: r.u32()?,
                sig: r.array::<64>()?,
            }
        }
    })
}

/// `DecodePayload` (`payload.cpp:400-417`): `None` for every malformed case of spec §3.3 —
/// bad magic, version or type, short or long body, count over the cap, duplicate vout,
/// `cents == 0`, trailing bytes. Range checks that need the transaction are in [`find_payload`].
pub fn decode(data: &[u8]) -> Option<Payload> {
    if data.len() < MIN_PAYLOAD || data.len() > MAX_PAYLOAD {
        return None;
    }
    if data[0] != MAGIC[0] || data[1] != MAGIC[1] {
        return None;
    }
    let mut r = Reader { data, pos: 0 };
    let _magic0 = r.u8()?;
    let _magic1 = r.u8()?;
    let version = r.u8()?;
    let type_byte = r.u8()?;
    if version != VERSION {
        return None; // versions 1, 2 and every later version: non-Yellowback (V23)
    }
    let t = PayloadType::from_byte(type_byte)?;
    let p = decode_body_v3(&mut r, t, data.len())?;
    if !r.at_end() {
        return None;
    }
    Some(p)
}

/// `PayloadScript` (`payload.cpp:419`): `OP_RETURN <push>`.
pub fn payload_script(data: &[u8]) -> Vec<u8> {
    let mut s = Vec::with_capacity(2 + data.len());
    s.push(op::OP_RETURN);
    script::push_data(&mut s, data);
    s
}

/// `ExtractOpReturnData` (`payload.cpp:424-437`): the pushed bytes when `script` is exactly
/// `OP_RETURN <one data push of MIN..MAX bytes>`; `None` for any other shape (no push, two
/// pushes, an `OP_N`, trailing bytes).
pub fn extract_op_return_data(script_pubkey: &[u8]) -> Option<Vec<u8>> {
    if script_pubkey.first() != Some(&op::OP_RETURN) {
        return None;
    }
    let ops = script::ops(&script_pubkey[1..]).ok()?;
    if ops.len() != 1 {
        return None;
    }
    let o = &ops[0];
    // Only a real data push (a direct 1..75-byte push or OP_PUSHDATA*) qualifies.
    if o.opcode > op::OP_PUSHDATA4 || o.data.is_empty() {
        return None;
    }
    if o.data.len() < MIN_PAYLOAD || o.data.len() > MAX_PAYLOAD {
        return None;
    }
    Some(o.data.clone())
}

/// `FindOpReturn` (`payload.cpp:439-450`): the index of the transaction's `OP_RETURN` output
/// when it has exactly one; `None` for zero or more than one (spec §3.2).
pub fn find_op_return(tx: &Transaction) -> Option<usize> {
    let mut found = None;
    for (i, o) in tx.vout.iter().enumerate() {
        if script::is_op_return(&o.script_pubkey) {
            if found.is_some() {
                return None;
            }
            found = Some(i);
        }
    }
    found
}

/// What [`find_payload`] returns (`FoundPayload`, `payload.h:167`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoundPayload {
    /// The decoded payload.
    pub payload: Payload,
    /// The `OP_RETURN` output's index.
    pub op_return_index: usize,
}

/// `FindPayload` (`payload.cpp:452-466`): the transaction's Yellowback payload, if it has one —
/// exactly one `OP_RETURN` of the required shape that decodes, whose assigned vouts all exist
/// and none of which is the `OP_RETURN` itself. Otherwise `None`: non-Yellowback for outputs.
pub fn find_payload(tx: &Transaction) -> Option<FoundPayload> {
    let idx = find_op_return(tx)?;
    let data = extract_op_return_data(&tx.vout[idx].script_pubkey)?;
    let payload = decode(&data)?;
    for a in payload.assignments() {
        if a.vout as usize >= tx.vout.len() || a.vout as usize == idx {
            return None;
        }
    }
    Some(FoundPayload {
        payload,
        op_return_index: idx,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{hex, unhex};

    fn transfer(v: &[(u8, u32)]) -> Payload {
        Payload::Transfer {
            assignments: v
                .iter()
                .map(|&(vout, cents)| Assignment { vout, cents })
                .collect(),
        }
    }

    #[test]
    fn transfer_round_trip_and_limits() {
        let p = transfer(&[(0, 500), (1, 100)]);
        let bytes = encode(&p).unwrap();
        assert_eq!(hex(&bytes), "594203020200f40100000164000000");
        assert_eq!(decode(&bytes).unwrap(), p);
        assert_eq!(p.assigned_cents(), 600);
        // 15 assignments fit (80 bytes); 16 do not.
        let fifteen: Vec<(u8, u32)> = (0..15).map(|i| (i, 100)).collect();
        assert_eq!(encode(&transfer(&fifteen)).unwrap().len(), MAX_PAYLOAD);
        let sixteen: Vec<(u8, u32)> = (0..16).map(|i| (i, 100)).collect();
        assert!(encode(&transfer(&sixteen)).is_none());
        // cents == 0 and duplicate vouts are not encodable and not decodable.
        assert!(encode(&transfer(&[(0, 0)])).is_none());
        assert!(encode(&transfer(&[(0, 1), (0, 2)])).is_none());
        assert!(decode(&unhex("59420302010000000000").unwrap()).is_none());
        assert!(decode(&unhex("594203020200010000000002000000").unwrap()).is_none());
        // Trailing byte, short body, bad count/size, bad magic, bad version, unknown type.
        assert!(decode(&unhex("594203020100f401000000").unwrap()).is_none());
        assert!(decode(&unhex("594203020100f4").unwrap()).is_none());
        assert!(decode(&unhex("594203020200f4010000").unwrap()).is_none());
        assert!(decode(&unhex("594303020100f4010000").unwrap()).is_none());
        assert!(decode(&unhex("594202020100f4010000").unwrap()).is_none());
        assert!(decode(&unhex("594203040100f4010000").unwrap()).is_none());
        assert!(decode(&unhex("594203100100f4010000").unwrap()).is_none());
        assert!(decode(&unhex("5942").unwrap()).is_none());
        assert!(decode(&[0x59; 81]).is_none());
        assert_eq!(
            decode(&unhex("59420307").unwrap()),
            Some(Payload::Equivocation)
        );
        assert!(decode(&unhex("5942030700").unwrap()).is_none());
    }

    #[test]
    fn mint_and_redeem_round_trip() {
        let m = Payload::Mint {
            term_class: 1,
            cents: 12_345,
            lock_height: 1000,
            ref_height: 900,
            owner_key: [0x02; 33],
            fee_vout: 3,
            attest_fee_vout: FEE_VOUT_NONE,
        };
        let b = encode(&m).unwrap();
        assert_eq!(b.len(), 52);
        assert_eq!(decode(&b).unwrap(), m);
        assert!(decode(&b[..51]).is_none());
        let r = Payload::Redeem {
            ref_height: 431,
            fee_vout: 1,
            attest_fee_vout: FEE_VOUT_NONE,
            assignments: vec![Assignment {
                vout: 0,
                cents: 250,
            }],
        };
        let b = encode(&r).unwrap();
        assert_eq!(b.len(), 16);
        assert_eq!(decode(&b).unwrap(), r);
        let thirteen: Vec<Assignment> = (0..13)
            .map(|i| Assignment {
                vout: i,
                cents: 100,
            })
            .collect();
        assert_eq!(
            encode(&Payload::Redeem {
                ref_height: 1,
                fee_vout: 1,
                attest_fee_vout: 2,
                assignments: thirteen.clone()
            })
            .unwrap()
            .len(),
            76
        );
        let mut fourteen = thirteen;
        fourteen.push(Assignment {
            vout: 13,
            cents: 100,
        });
        assert!(encode(&Payload::Redeem {
            ref_height: 1,
            fee_vout: 1,
            attest_fee_vout: 2,
            assignments: fourteen
        })
        .is_none());
        let n = Payload::ClaimNotice {
            vault_txid: [7; 32],
            vault_vout: 0,
            ref_height: 5,
        };
        assert_eq!(decode(&encode(&n).unwrap()).unwrap(), n);
        let reg = Payload::AttestorRegister {
            attestor_key: [1; 33],
            bond_key: [2; 33],
            bond_locktime: 9,
            flags: 1,
        };
        assert_eq!(decode(&encode(&reg).unwrap()).unwrap(), reg);
        let rev = Payload::AttestorRevive {
            seq: 3,
            price_micro_usd: 50_000_000,
            cited_height: 400,
            sig: [9; 64],
        };
        let b = encode(&rev).unwrap();
        assert_eq!(b.len(), 78);
        assert_eq!(decode(&b).unwrap(), rev);
    }

    #[test]
    fn op_return_shape_rules() {
        let data = encode(&transfer(&[(0, 500)])).unwrap();
        let s = payload_script(&data);
        assert_eq!(s[0], op::OP_RETURN);
        assert_eq!(extract_op_return_data(&s).unwrap(), data);
        // Two pushes, an OP_N, an empty push, a non-OP_RETURN script, a bare OP_RETURN.
        let mut two = s.clone();
        two.push(0x01);
        two.push(0x00);
        assert!(extract_op_return_data(&two).is_none());
        assert!(extract_op_return_data(&[op::OP_RETURN, op::OP_1]).is_none());
        assert!(extract_op_return_data(&[op::OP_RETURN, op::OP_0]).is_none());
        assert!(extract_op_return_data(&[op::OP_RETURN]).is_none());
        assert!(extract_op_return_data(&script::p2pkh_script(&[1; 20])).is_none());
        // Below MIN_PAYLOAD and above MAX_PAYLOAD.
        assert!(extract_op_return_data(&payload_script(&[1, 2, 3])).is_none());
        assert!(extract_op_return_data(&payload_script(&[1; 81])).is_none());
        assert!(extract_op_return_data(&payload_script(&[1; 80])).is_some());
    }

    #[test]
    fn find_payload_range_checks() {
        use crate::tx::TxOut;
        let mut tx = Transaction::new_v4();
        tx.vout.push(TxOut {
            value: 10_000,
            script_pubkey: script::p2pkh_script(&[1; 20]),
        });
        tx.vout.push(TxOut {
            value: 0,
            script_pubkey: payload_script(&encode(&transfer(&[(0, 500)])).unwrap()),
        });
        let f = find_payload(&tx).unwrap();
        assert_eq!(f.op_return_index, 1);
        assert_eq!(f.payload, transfer(&[(0, 500)]));
        // A vout past the end, or the OP_RETURN itself: non-Yellowback.
        tx.vout[1].script_pubkey = payload_script(&encode(&transfer(&[(2, 500)])).unwrap());
        assert!(find_payload(&tx).is_none());
        tx.vout[1].script_pubkey = payload_script(&encode(&transfer(&[(1, 500)])).unwrap());
        assert!(find_payload(&tx).is_none());
        // Two OP_RETURNs: non-Yellowback.
        tx.vout[1].script_pubkey = payload_script(&encode(&transfer(&[(0, 500)])).unwrap());
        tx.vout.push(TxOut {
            value: 0,
            script_pubkey: vec![op::OP_RETURN],
        });
        assert!(find_op_return(&tx).is_none());
        assert!(find_payload(&tx).is_none());
    }
}
