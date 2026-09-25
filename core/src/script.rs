//! Scripts: the generic `CScript` push encoding, P2PKH and P2SH scriptPubKey / scriptSig
//! construction and recognition, and (W4) the Yellowback `vaultScript` / `carrierScript`
//! templates with their scriptSigs.
//!
//! Translation source (plan §3.6): `ycash-dd/src/yellowback/script.cpp` (`GetPushes` `:16-29`,
//! `ReadHeightPush` `:35-52`, `VaultScript` `:81-96`, `ParseVaultScript` `:98-127`,
//! `OwnerScriptSig` / `ClaimScriptSig` `:129-137`, `CarrierScript` `:160-168`, `IsCarrierScript`
//! `:170-189`, `CarrierScriptSig` `:191-194`, `ParseCarrierScriptSig` `:196-213`) over Ycash's
//! `CScript` (`ref/ycash/src/script/script.h:448-470` `operator<<(const std::vector<unsigned
//! char>&)`, `:513-560` `GetOp2`). Byte-identical to the node's encoding by construction, and
//! checked against the node-built templates in `tests/vectors.rs`.
//!
//! **Plan §8.7 (bundle push size).** The carrier scriptSig pushes the whole bundle as one
//! element. Consensus caps a stack element at `MAX_SCRIPT_ELEMENT_SIZE = 520` bytes
//! (`ref/ycash/src/script/script.h:24`); the largest bundle is `4 + 74 · BUNDLE_MAX(6) = 448`
//! bytes (`bundle.h:24-25`), so every valid bundle fits with 72 bytes to spare, and the push
//! form is `OP_PUSHDATA2` for a bundle over 255 bytes (four or more attestations),
//! `OP_PUSHDATA1` below. The node's `CScript << bundle` and [`push_data`] agree; the Python
//! reference asserts `len(bundle) <= MAX_SCRIPT_ELEMENT_SIZE` at the same place
//! (`qa/rpc-tests/test_framework/yellowback_attest.py:338-340`), and [`carrier_script_sig`]
//! refuses a larger element rather than emitting a scriptSig consensus would reject.

use thiserror::Error;

/// Script errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ScriptError {
    /// A push ran past the end of the script.
    #[error("truncated push at offset {0}")]
    Truncated(usize),
    /// A height outside `[1, LOCKTIME_THRESHOLD)` or `claimHeight <= lockHeight`.
    #[error("vault height out of range: lock {0}, claim {1}")]
    BadHeight(u32, u32),
    /// A public key that is not a 33-byte compressed encoding.
    #[error("public key is not compressed")]
    BadKey,
    /// The bundle push would exceed `MAX_SCRIPT_ELEMENT_SIZE` (plan §8.7).
    #[error("bundle of {0} bytes exceeds the {MAX_SCRIPT_ELEMENT_SIZE}-byte script element limit")]
    ElementTooLarge(usize),
}

/// `MAX_SCRIPT_ELEMENT_SIZE` (`ref/ycash/src/script/script.h:24`): the consensus cap on one
/// stack element, hence on the bundle push (plan §8.7).
pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;

/// `LOCKTIME_THRESHOLD` (`ref/ycash/src/script/script.h:33`): `nLockTime` values below it are
/// heights; a vault's `lockHeight` / `claimHeight` must be below it.
pub const LOCKTIME_THRESHOLD: u32 = 500_000_000;

/// `CARRIER_SCRIPT_SIZE` (`ycash-dd/src/yellowback/script.h:118`): 1+1+33+1+34+1.
pub const CARRIER_SCRIPT_SIZE: usize = 71;

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
    /// OP_TRUE (= OP_1).
    pub const OP_TRUE: u8 = 0x51;
    /// OP_IF.
    pub const OP_IF: u8 = 0x63;
    /// OP_ELSE.
    pub const OP_ELSE: u8 = 0x67;
    /// OP_ENDIF.
    pub const OP_ENDIF: u8 = 0x68;
    /// OP_RETURN.
    pub const OP_RETURN: u8 = 0x6a;
    /// OP_DROP.
    pub const OP_DROP: u8 = 0x75;
    /// OP_DUP.
    pub const OP_DUP: u8 = 0x76;
    /// OP_SWAP.
    pub const OP_SWAP: u8 = 0x7c;
    /// OP_EQUAL.
    pub const OP_EQUAL: u8 = 0x87;
    /// OP_EQUALVERIFY.
    pub const OP_EQUALVERIFY: u8 = 0x88;
    /// OP_SHA256.
    pub const OP_SHA256: u8 = 0xa8;
    /// OP_HASH160.
    pub const OP_HASH160: u8 = 0xa9;
    /// OP_CHECKSIG.
    pub const OP_CHECKSIG: u8 = 0xac;
    /// OP_CHECKLOCKTIMEVERIFY (= OP_NOP2).
    pub const OP_CHECKLOCKTIMEVERIFY: u8 = 0xb1;
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

/// `IsCompressedKey` (`script.cpp:263-266`): a 33-byte encoding with a `0x02`/`0x03` prefix
/// that parses as a point.
pub fn is_compressed_key(key: &[u8]) -> bool {
    key.len() == 33
        && (key[0] == 0x02 || key[0] == 0x03)
        && secp256k1::PublicKey::from_slice(key).is_ok()
}

/// `P2SHScript` (`script.cpp:268-271`): the P2SH scriptPubKey of a redeem script.
pub fn p2sh_of(redeem_script: &[u8]) -> Vec<u8> {
    p2sh_script(&crate::keys::hash160(redeem_script))
}

/// `VaultScript` (`script.cpp:81-96`; spec §3.4):
/// `OP_IF <lockHeight> OP_CHECKLOCKTIMEVERIFY OP_DROP <owner> OP_CHECKSIG OP_ELSE <claimHeight>
/// OP_CHECKLOCKTIMEVERIFY OP_DROP OP_TRUE OP_ENDIF`, heights as minimal `CScriptNum` pushes.
/// Refused when a height is outside `[1, LOCKTIME_THRESHOLD)`, `claimHeight <= lockHeight`, or
/// the key is not compressed — the node returns an empty script there.
pub fn vault_script(
    lock_height: u32,
    owner: &[u8; 33],
    claim_height: u32,
) -> Result<Vec<u8>, ScriptError> {
    if lock_height == 0
        || lock_height >= LOCKTIME_THRESHOLD
        || claim_height <= lock_height
        || claim_height >= LOCKTIME_THRESHOLD
    {
        return Err(ScriptError::BadHeight(lock_height, claim_height));
    }
    if !is_compressed_key(owner) {
        return Err(ScriptError::BadKey);
    }
    let mut s = Vec::with_capacity(53);
    s.push(op::OP_IF);
    push_int(&mut s, lock_height as i64);
    s.push(op::OP_CHECKLOCKTIMEVERIFY);
    s.push(op::OP_DROP);
    push_data(&mut s, owner);
    s.push(op::OP_CHECKSIG);
    s.push(op::OP_ELSE);
    push_int(&mut s, claim_height as i64);
    s.push(op::OP_CHECKLOCKTIMEVERIFY);
    s.push(op::OP_DROP);
    s.push(op::OP_TRUE);
    s.push(op::OP_ENDIF);
    Ok(s)
}

/// The parts of a vault script.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultParts {
    /// `lockHeight`.
    pub lock_height: u32,
    /// The owner's compressed public key.
    pub owner: [u8; 33],
    /// `claimHeight`.
    pub claim_height: u32,
}

/// `ReadHeightPush` (`script.cpp:35-52`): `OP_1..OP_16` or a `CScriptNum` of at most 5 bytes,
/// minimally encoded, in `(0, LOCKTIME_THRESHOLD)`.
fn read_height(o: &ScriptOp) -> Option<u32> {
    let h: i64 = if (op::OP_1..=op::OP_16).contains(&o.opcode) {
        (o.opcode - op::OP_1 + 1) as i64
    } else if o.opcode <= op::OP_PUSHDATA4 && !o.data.is_empty() && o.data.len() <= 5 {
        // CScriptNum(data, fRequireMinimal = true).
        let d = &o.data;
        let last = *d.last().unwrap();
        if last & 0x7f == 0 && (d.len() == 1 || d[d.len() - 2] & 0x80 == 0) {
            return None; // not minimal
        }
        let mut v: i64 = 0;
        for (i, b) in d.iter().enumerate() {
            v |= ((*b as i64) & if i == d.len() - 1 { 0x7f } else { 0xff }) << (8 * i);
        }
        if last & 0x80 != 0 {
            v = -v;
        }
        v
    } else {
        return None;
    };
    if h > 0 && h < LOCKTIME_THRESHOLD as i64 {
        Some(h as u32)
    } else {
        None
    }
}

/// `ParseVaultScript` (`script.cpp:98-127`): the parts, or `None` for anything but the exact
/// template with minimal pushes.
pub fn parse_vault_script(script: &[u8]) -> Option<VaultParts> {
    let o = ops(script).ok()?;
    if o.len() != 12 {
        return None;
    }
    if o[0].opcode != op::OP_IF {
        return None;
    }
    let lock_height = read_height(&o[1])?;
    if o[2].opcode != op::OP_CHECKLOCKTIMEVERIFY || o[3].opcode != op::OP_DROP {
        return None;
    }
    if o[4].opcode != 33 || !is_compressed_key(&o[4].data) {
        return None;
    }
    let mut owner = [0u8; 33];
    owner.copy_from_slice(&o[4].data);
    if o[5].opcode != op::OP_CHECKSIG || o[6].opcode != op::OP_ELSE {
        return None;
    }
    let claim_height = read_height(&o[7])?;
    if o[8].opcode != op::OP_CHECKLOCKTIMEVERIFY
        || o[9].opcode != op::OP_DROP
        || o[10].opcode != op::OP_TRUE
        || o[11].opcode != op::OP_ENDIF
    {
        return None;
    }
    if claim_height <= lock_height {
        return None;
    }
    Some(VaultParts {
        lock_height,
        owner,
        claim_height,
    })
}

/// `OwnerScriptSig` (`script.cpp:129-132`): `<ownerSig ‖ hashtype> OP_1 <vaultScript>`.
pub fn owner_script_sig(owner_sig: &[u8], vault_script: &[u8]) -> Vec<u8> {
    let mut s = Vec::with_capacity(owner_sig.len() + vault_script.len() + 4);
    push_data(&mut s, owner_sig);
    s.push(op::OP_1);
    push_data(&mut s, vault_script);
    s
}

/// `ClaimScriptSig` (`script.cpp:134-137`): `OP_0 <vaultScript>`.
pub fn claim_script_sig(vault_script: &[u8]) -> Vec<u8> {
    let mut s = Vec::with_capacity(vault_script.len() + 3);
    s.push(op::OP_0);
    push_data(&mut s, vault_script);
    s
}

/// `CarrierScript` (`script.cpp:160-168`; v3 spec §3.4):
/// `OP_SWAP OP_SHA256 <bundleHash 32> OP_EQUALVERIFY <pk 33> OP_CHECKSIG`, 71 bytes.
pub fn carrier_script(pk: &[u8; 33], bundle_hash: &[u8; 32]) -> Result<Vec<u8>, ScriptError> {
    if !is_compressed_key(pk) {
        return Err(ScriptError::BadKey);
    }
    let mut s = Vec::with_capacity(CARRIER_SCRIPT_SIZE);
    s.push(op::OP_SWAP);
    s.push(op::OP_SHA256);
    push_data(&mut s, bundle_hash);
    s.push(op::OP_EQUALVERIFY);
    push_data(&mut s, pk);
    s.push(op::OP_CHECKSIG);
    debug_assert_eq!(s.len(), CARRIER_SCRIPT_SIZE);
    Ok(s)
}

/// `IsCarrierScript` (`script.cpp:170-189`): `(pk, bundleHash)` for the exact 71-byte template.
pub fn parse_carrier_script(script: &[u8]) -> Option<([u8; 33], [u8; 32])> {
    if script.len() != CARRIER_SCRIPT_SIZE {
        return None;
    }
    let o = ops(script).ok()?;
    if o.len() != 6
        || o[0].opcode != op::OP_SWAP
        || o[1].opcode != op::OP_SHA256
        || o[2].opcode != 32
        || o[3].opcode != op::OP_EQUALVERIFY
        || o[4].opcode != 33
        || !is_compressed_key(&o[4].data)
        || o[5].opcode != op::OP_CHECKSIG
    {
        return None;
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&o[2].data);
    let mut pk = [0u8; 33];
    pk.copy_from_slice(&o[4].data);
    Some((pk, hash))
}

/// `CarrierScriptSig` (`script.cpp:191-194`): `<bundle> <sig ‖ hashtype> <carrierScript>`, three
/// data pushes; the bundle push is bounded by [`MAX_SCRIPT_ELEMENT_SIZE`] (plan §8.7).
pub fn carrier_script_sig(
    bundle: &[u8],
    sig: &[u8],
    carrier_script: &[u8],
) -> Result<Vec<u8>, ScriptError> {
    if bundle.len() > MAX_SCRIPT_ELEMENT_SIZE {
        return Err(ScriptError::ElementTooLarge(bundle.len()));
    }
    let mut s = Vec::with_capacity(bundle.len() + sig.len() + carrier_script.len() + 6);
    push_data(&mut s, bundle);
    push_data(&mut s, sig);
    push_data(&mut s, carrier_script);
    Ok(s)
}

/// A parsed carrier scriptSig (`CarrierSpend`, `script.h:127-134`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CarrierSpend {
    /// The bundle bytes (the first push).
    pub bundle: Vec<u8>,
    /// The DER signature with its hashtype byte (the second push).
    pub sig: Vec<u8>,
    /// The carrier key, from the redeem script.
    pub pk: [u8; 33],
    /// The bundle hash, from the redeem script.
    pub bundle_hash: [u8; 32],
    /// The redeem script (the third push).
    pub carrier_script: Vec<u8>,
}

/// `ParseCarrierScriptSig` (`script.cpp:196-213`): exactly three data pushes (never `OP_0` /
/// `OP_1..OP_16`), the third a carrier script.
pub fn parse_carrier_script_sig(script_sig: &[u8]) -> Option<CarrierSpend> {
    let o = ops(script_sig).ok()?;
    if o.len() != 3 || o.iter().any(|x| x.opcode > op::OP_PUSHDATA4) {
        return None;
    }
    let (pk, bundle_hash) = parse_carrier_script(&o[2].data)?;
    Some(CarrierSpend {
        bundle: o[0].data.clone(),
        sig: o[1].data.clone(),
        pk,
        bundle_hash,
        carrier_script: o[2].data.clone(),
    })
}

/// `ExtractRedeemScript` (`script.cpp:273-279`): the last push of a push-only scriptSig.
pub fn redeem_script_of(script_sig: &[u8]) -> Option<Vec<u8>> {
    pushes(script_sig)?.pop()
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

    #[test]
    fn vault_and_carrier_templates_round_trip() {
        let sk = secp256k1::SecretKey::from_secret_bytes([9u8; 32]).unwrap();
        let pk = secp256k1::PublicKey::from_secret_key(&sk).serialize();
        let v = vault_script(431, &pk, 455).unwrap();
        // 2-byte height pushes: 49 bytes (the spec's 51/53 are for 3- and 4-byte heights).
        assert_eq!(v.len(), 49);
        assert_eq!(v[0], op::OP_IF);
        assert_eq!(&v[1..4], &[0x02, 0xaf, 0x01]);
        assert_eq!(vault_script(40_000, &pk, 40_024).unwrap().len(), 51);
        assert_eq!(
            parse_vault_script(&v),
            Some(VaultParts {
                lock_height: 431,
                owner: pk,
                claim_height: 455
            })
        );
        // Small heights use OP_1..OP_16 and still parse.
        let small = vault_script(5, &pk, 16).unwrap();
        assert_eq!(small[1], op::OP_1 + 4);
        assert_eq!(parse_vault_script(&small).unwrap().claim_height, 16);
        // A non-minimal height push (a trailing zero byte) is refused.
        let mut bad = v.clone();
        bad[1] = 0x03;
        bad.insert(4, 0x00);
        assert_eq!(parse_vault_script(&bad), None);
        assert!(matches!(
            vault_script(455, &pk, 431),
            Err(ScriptError::BadHeight(455, 431))
        ));
        assert!(matches!(
            vault_script(0, &pk, 1),
            Err(ScriptError::BadHeight(0, 1))
        ));
        assert!(matches!(
            vault_script(1, &[4u8; 33], 2),
            Err(ScriptError::BadKey)
        ));
        let o = owner_script_sig(&[0x30, 0x01], &v);
        assert_eq!(
            pushes(&o).unwrap(),
            vec![vec![0x30, 0x01], vec![], v.clone()]
        );
        assert_eq!(o[3], op::OP_1);
        let c = claim_script_sig(&v);
        assert_eq!(c[0], op::OP_0);
        assert_eq!(redeem_script_of(&c), Some(v.clone()));

        let h = [0xab; 32];
        let cs = carrier_script(&pk, &h).unwrap();
        assert_eq!(cs.len(), CARRIER_SCRIPT_SIZE);
        assert_eq!(&cs[..2], &[op::OP_SWAP, op::OP_SHA256]);
        assert_eq!(parse_carrier_script(&cs), Some((pk, h)));
        assert_eq!(parse_carrier_script(&cs[..70]), None);
        let bundle = vec![0x59u8; 448];
        let sig = vec![0x30u8; 71];
        let ss = carrier_script_sig(&bundle, &sig, &cs).unwrap();
        // 448 bytes > 255: OP_PUSHDATA2 (plan §8.7).
        assert_eq!(&ss[..3], &[op::OP_PUSHDATA2, 0xc0, 0x01]);
        let spend = parse_carrier_script_sig(&ss).unwrap();
        assert_eq!(
            (spend.bundle, spend.sig, spend.pk, spend.bundle_hash),
            (bundle, sig, pk, h)
        );
        assert_eq!(spend.carrier_script, cs);
        assert!(matches!(
            carrier_script_sig(&[0u8; 521], &[1], &cs),
            Err(ScriptError::ElementTooLarge(521))
        ));
        // Two pushes are not a carrier scriptSig; an OP_1 "bundle" is not a data push. (OP_0 is
        // the empty data push, as the node's `opcode > OP_PUSHDATA4` test also admits it.)
        let mut two = Vec::new();
        push_data(&mut two, &[1]);
        push_data(&mut two, &cs);
        assert_eq!(parse_carrier_script_sig(&two), None);
        let mut one = vec![op::OP_1];
        push_data(&mut one, &[1]);
        push_data(&mut one, &cs);
        assert_eq!(parse_carrier_script_sig(&one), None);
        assert_eq!(p2sh_hash(&p2sh_of(&cs)), Some(crate::keys::hash160(&cs)));
    }
}
