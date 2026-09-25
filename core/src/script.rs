//! Scripts: the generic `CScript` push encoding, P2PKH and P2SH scriptPubKey / scriptSig
//! construction and recognition. The Yellowback `vaultScript` / `carrierScript` templates and
//! the `<bundle> <sig> <script>` scriptSig are Phase W4.
//!
//! Translation source (plan §3.6): `ycash-dd/src/yellowback/script.cpp` (`GetPushes`,
//! `StackElementFor`, the push-only iteration) over Ycash's `CScript`
//! (`ref/ycash/src/script/script.h:448-470` `operator<<(const std::vector<unsigned char>&)`,
//! `:513-560` `GetOp2`). Byte-identical to the node's encoding by construction.

use thiserror::Error;

/// Script errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ScriptError {
    /// A push ran past the end of the script.
    #[error("truncated push at offset {0}")]
    Truncated(usize),
}

/// Opcodes YEW needs (`ref/ycash/src/script/script.h`).
pub mod op {
    /// Push an empty vector.
    pub const OP_0: u8 = 0x00;
    /// The next byte is the push length.
    pub const OP_PUSHDATA1: u8 = 0x4c;
    /// The next two bytes (LE) are the push length.
    pub const OP_PUSHDATA2: u8 = 0x4d;
    /// The next four bytes (LE) are the push length.
    pub const OP_PUSHDATA4: u8 = 0x4e;
    /// Push −1.
    pub const OP_1NEGATE: u8 = 0x4f;
    /// Push 1.
    pub const OP_1: u8 = 0x51;
    /// Push 16.
    pub const OP_16: u8 = 0x60;
    /// OP_RETURN.
    pub const OP_RETURN: u8 = 0x6a;
    /// OP_DUP.
    pub const OP_DUP: u8 = 0x76;
    /// OP_EQUAL.
    pub const OP_EQUAL: u8 = 0x87;
    /// OP_EQUALVERIFY.
    pub const OP_EQUALVERIFY: u8 = 0x88;
    /// OP_HASH160.
    pub const OP_HASH160: u8 = 0xa9;
    /// OP_CHECKSIG.
    pub const OP_CHECKSIG: u8 = 0xac;
}

/// Append a data push exactly as `CScript::operator<<(const std::vector<unsigned char>&)`
/// does (`ref/ycash/src/script/script.h:448-470`): direct length byte below `OP_PUSHDATA1`
/// (76), else `OP_PUSHDATA1` up to 0xff, `OP_PUSHDATA2` up to 0xffff, `OP_PUSHDATA4` beyond.
/// Note that an empty vector is encoded as a zero-length direct push (`0x00`), which is the
/// same byte as `OP_0` — the node's `<< valtype()` and `<< OP_0` agree.
pub fn push_data(script: &mut Vec<u8>, data: &[u8]) {
    let n = data.len();
    if n < op::OP_PUSHDATA1 as usize {
        script.push(n as u8);
    } else if n <= 0xff {
        script.push(op::OP_PUSHDATA1);
        script.push(n as u8);
    } else if n <= 0xffff {
        script.push(op::OP_PUSHDATA2);
        script.extend_from_slice(&(n as u16).to_le_bytes());
    } else {
        script.push(op::OP_PUSHDATA4);
        script.extend_from_slice(&(n as u32).to_le_bytes());
    }
    script.extend_from_slice(data);
}

/// Append an integer push as `CScript::operator<<(int64_t)` does
/// (`ref/ycash/src/script/script.h:389-402` `push_int64`): `OP_0` for 0, `OP_1NEGATE` for −1,
/// `OP_1..OP_16` for 1..16, else a minimally encoded `CScriptNum` data push.
pub fn push_int(script: &mut Vec<u8>, n: i64) {
    match n {
        0 => script.push(op::OP_0),
        -1 => script.push(op::OP_1NEGATE),
        1..=16 => script.push(op::OP_1 + (n as u8 - 1)),
        _ => push_data(script, &script_num_encode(n)),
    }
}

/// `CScriptNum::serialize` (`ref/ycash/src/script/script.h:307-330`): little-endian magnitude,
/// sign in the top bit of the last byte, with an extra byte when that bit is taken.
pub fn script_num_encode(value: i64) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
    }
    let neg = value < 0;
    let mut abs = value.unsigned_abs();
    let mut out = Vec::new();
    while abs > 0 {
        out.push((abs & 0xff) as u8);
        abs >>= 8;
    }
    if out.last().map(|b| b & 0x80 != 0).unwrap_or(false) {
        out.push(if neg { 0x80 } else { 0 });
    } else if neg {
        let last = out.len() - 1;
        out[last] |= 0x80;
    }
    out
}

/// One element the push-only iterator yields: the opcode and, for a data push, its bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScriptOp {
    /// The opcode byte (for direct pushes, the length byte itself).
    pub opcode: u8,
    /// The pushed data; empty for non-push opcodes and `OP_0`.
    pub data: Vec<u8>,
}

/// Iterate a script like `CScript::GetOp2` (`ref/ycash/src/script/script.h:513-560`).
pub fn ops(script: &[u8]) -> Result<Vec<ScriptOp>, ScriptError> {
    let mut out = Vec::new();
    let mut pc = 0usize;
    while pc < script.len() {
        let opcode = script[pc];
        let start = pc;
        pc += 1;
        let mut data = Vec::new();
        if opcode <= op::OP_PUSHDATA4 {
            let n = if opcode < op::OP_PUSHDATA1 {
                opcode as usize
            } else if opcode == op::OP_PUSHDATA1 {
                let b = *script.get(pc).ok_or(ScriptError::Truncated(start))?;
                pc += 1;
                b as usize
            } else if opcode == op::OP_PUSHDATA2 {
                let b = script
                    .get(pc..pc + 2)
                    .ok_or(ScriptError::Truncated(start))?;
                pc += 2;
                u16::from_le_bytes([b[0], b[1]]) as usize
            } else {
                let b = script
                    .get(pc..pc + 4)
                    .ok_or(ScriptError::Truncated(start))?;
                pc += 4;
                u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize
            };
            data = script
                .get(pc..pc + n)
                .ok_or(ScriptError::Truncated(start))?
                .to_vec();
            pc += n;
        }
        out.push(ScriptOp { opcode, data });
    }
    Ok(out)
}

/// `GetPushes` (`ycash-dd/src/yellowback/script.cpp:16-29`): the pushes of a push-only
/// script; `None` on any non-push opcode.
pub fn pushes(script: &[u8]) -> Option<Vec<Vec<u8>>> {
    let ops = ops(script).ok()?;
    let mut out = Vec::with_capacity(ops.len());
    for o in ops {
        if o.opcode > op::OP_16 {
            return None;
        }
        out.push(o.data);
    }
    Some(out)
}

/// `OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG`.
pub fn p2pkh_script(hash: &[u8; 20]) -> Vec<u8> {
    let mut s = Vec::with_capacity(25);
    s.push(op::OP_DUP);
    s.push(op::OP_HASH160);
    push_data(&mut s, hash);
    s.push(op::OP_EQUALVERIFY);
    s.push(op::OP_CHECKSIG);
    s
}

/// `OP_HASH160 <20> OP_EQUAL`.
pub fn p2sh_script(hash: &[u8; 20]) -> Vec<u8> {
    let mut s = Vec::with_capacity(23);
    s.push(op::OP_HASH160);
    push_data(&mut s, hash);
    s.push(op::OP_EQUAL);
    s
}

/// The key hash if `script` is exactly P2PKH (`CScript::IsPayToPublicKeyHash`).
pub fn p2pkh_hash(script: &[u8]) -> Option<[u8; 20]> {
    if script.len() == 25
        && script[0] == op::OP_DUP
        && script[1] == op::OP_HASH160
        && script[2] == 20
        && script[23] == op::OP_EQUALVERIFY
        && script[24] == op::OP_CHECKSIG
    {
        let mut h = [0u8; 20];
        h.copy_from_slice(&script[3..23]);
        Some(h)
    } else {
        None
    }
}

/// The script hash if `script` is exactly P2SH (`CScript::IsPayToScriptHash`,
/// `ref/ycash/src/script/script.cpp`), the test `SelectYec` uses to skip every P2SH output
/// (`ycash-dd/src/yellowback/txbuilder.cpp:410`).
pub fn p2sh_hash(script: &[u8]) -> Option<[u8; 20]> {
    if script.len() == 23
        && script[0] == op::OP_HASH160
        && script[1] == 20
        && script[22] == op::OP_EQUAL
    {
        let mut h = [0u8; 20];
        h.copy_from_slice(&script[2..22]);
        Some(h)
    } else {
        None
    }
}

/// True for an `OP_RETURN` output (a payload carrier).
pub fn is_op_return(script: &[u8]) -> bool {
    script.first() == Some(&op::OP_RETURN)
}

/// The P2PKH scriptSig: `<sig ‖ hashtype> <pubkey>`.
pub fn p2pkh_script_sig(sig_with_hashtype: &[u8], pubkey: &[u8; 33]) -> Vec<u8> {
    let mut s = Vec::with_capacity(2 + sig_with_hashtype.len() + 34);
    push_data(&mut s, sig_with_hashtype);
    push_data(&mut s, pubkey);
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_boundaries_match_cscript() {
        let mut s = Vec::new();
        push_data(&mut s, &[]);
        assert_eq!(s, [0x00]);
        s.clear();
        push_data(&mut s, &[0xaa; 75]);
        assert_eq!(s[0], 75);
        s.clear();
        push_data(&mut s, &[0xaa; 76]);
        assert_eq!(&s[..2], &[op::OP_PUSHDATA1, 76]);
        s.clear();
        push_data(&mut s, &[0xaa; 255]);
        assert_eq!(&s[..2], &[op::OP_PUSHDATA1, 255]);
        s.clear();
        push_data(&mut s, &[0xaa; 256]);
        assert_eq!(&s[..3], &[op::OP_PUSHDATA2, 0x00, 0x01]);
        s.clear();
        push_data(&mut s, &[0xaa; 65536]);
        assert_eq!(&s[..5], &[op::OP_PUSHDATA4, 0, 0, 1, 0]);
    }

    #[test]
    fn ops_round_trip_every_push_form() {
        for n in [0usize, 1, 75, 76, 255, 256, 65535, 65536] {
            let data = vec![0x5a; n];
            let mut s = vec![op::OP_DUP];
            push_data(&mut s, &data);
            s.push(op::OP_CHECKSIG);
            let o = ops(&s).unwrap();
            assert_eq!(o.len(), 3);
            assert_eq!(o[1].data, data);
            assert_eq!(pushes(&s), None);
            let mut p = Vec::new();
            push_data(&mut p, &data);
            assert_eq!(pushes(&p).unwrap(), vec![data]);
        }
        assert_eq!(ops(&[0x05, 1, 2]), Err(ScriptError::Truncated(0)));
        assert_eq!(ops(&[op::OP_PUSHDATA2, 1]), Err(ScriptError::Truncated(0)));
    }

    #[test]
    fn script_num_matches_cscriptnum() {
        assert_eq!(script_num_encode(0), Vec::<u8>::new());
        assert_eq!(script_num_encode(1), vec![1]);
        assert_eq!(script_num_encode(127), vec![0x7f]);
        assert_eq!(script_num_encode(128), vec![0x80, 0x00]);
        assert_eq!(script_num_encode(-1), vec![0x81]);
        assert_eq!(script_num_encode(-128), vec![0x80, 0x80]);
        assert_eq!(script_num_encode(255), vec![0xff, 0x00]);
        assert_eq!(script_num_encode(256), vec![0x00, 0x01]);
        assert_eq!(script_num_encode(500_000), vec![0x20, 0xa1, 0x07]);
        let mut s = Vec::new();
        push_int(&mut s, 0);
        push_int(&mut s, 1);
        push_int(&mut s, 16);
        push_int(&mut s, 17);
        push_int(&mut s, -1);
        assert_eq!(s, vec![0x00, 0x51, 0x60, 0x01, 0x11, 0x4f]);
    }

    #[test]
    fn p2pkh_and_p2sh_recognition() {
        let h = [7u8; 20];
        let p = p2pkh_script(&h);
        assert_eq!(p.len(), 25);
        assert_eq!(p2pkh_hash(&p), Some(h));
        assert_eq!(p2sh_hash(&p), None);
        let q = p2sh_script(&h);
        assert_eq!(q.len(), 23);
        assert_eq!(p2sh_hash(&q), Some(h));
        assert_eq!(p2pkh_hash(&q), None);
        assert!(!is_op_return(&p));
        assert!(is_op_return(&[op::OP_RETURN, 0x02, 0x59, 0x42]));
        let sig = p2pkh_script_sig(&[0x30, 0x44, 0x01], &[2u8; 33]);
        assert_eq!(
            pushes(&sig).unwrap(),
            vec![vec![0x30, 0x44, 0x01], vec![2u8; 33]]
        );
    }
}
