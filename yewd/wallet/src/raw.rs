// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The raw-transaction helpers ycashd serves without a wallet and Zakura lacks (workspace plan
//! §3b, K-25: `createrawtransaction`, `decoderawtransaction`, `decodescript`), served by the
//! façade itself so kogany needs no change for them. ycash6 `src/rpc/rawtransaction.cpp`
//! (`createrawtransaction`, `decoderawtransaction`, `decodescript`, `TxToJSON`,
//! `ScriptPubKeyToJSON`), `src/core_write.cpp` (`ScriptToAsmStr`), `src/script/standard.cpp`
//! (`Solver`, `GetTxnOutputType`, `ExtractDestinations`), re-expressed over yew-core's script
//! helpers and librustzcash6's transaction parser.

use serde_json::Value;
use yew_core::params::Network;

use crate::json::J;
use crate::{code, RpcError};

/// `TX_EXPIRING_SOON_THRESHOLD`.
const EXPIRING_SOON: i64 = 3;
/// `TX_EXPIRY_HEIGHT_THRESHOLD`.
const EXPIRY_THRESHOLD: i64 = 500_000_000;
/// `DEFAULT_POST_BLOSSOM_TX_EXPIRY_DELTA`.
const EXPIRY_DELTA: u32 = 40;

fn op_name(op: u8) -> &'static str {
    match op {
        0x00 => "0",
        0x4c => "OP_PUSHDATA1",
        0x4d => "OP_PUSHDATA2",
        0x4e => "OP_PUSHDATA4",
        0x4f => "-1",
        0x50 => "OP_RESERVED",
        0x51 => "1",
        0x52 => "2",
        0x53 => "3",
        0x54 => "4",
        0x55 => "5",
        0x56 => "6",
        0x57 => "7",
        0x58 => "8",
        0x59 => "9",
        0x5a => "10",
        0x5b => "11",
        0x5c => "12",
        0x5d => "13",
        0x5e => "14",
        0x5f => "15",
        0x60 => "16",
        0x61 => "OP_NOP",
        0x62 => "OP_VER",
        0x63 => "OP_IF",
        0x64 => "OP_NOTIF",
        0x65 => "OP_VERIF",
        0x66 => "OP_VERNOTIF",
        0x67 => "OP_ELSE",
        0x68 => "OP_ENDIF",
        0x69 => "OP_VERIFY",
        0x6a => "OP_RETURN",
        0x6b => "OP_TOALTSTACK",
        0x6c => "OP_FROMALTSTACK",
        0x6d => "OP_2DROP",
        0x6e => "OP_2DUP",
        0x6f => "OP_3DUP",
        0x70 => "OP_2OVER",
        0x71 => "OP_2ROT",
        0x72 => "OP_2SWAP",
        0x73 => "OP_IFDUP",
        0x74 => "OP_DEPTH",
        0x75 => "OP_DROP",
        0x76 => "OP_DUP",
        0x77 => "OP_NIP",
        0x78 => "OP_OVER",
        0x79 => "OP_PICK",
        0x7a => "OP_ROLL",
        0x7b => "OP_ROT",
        0x7c => "OP_SWAP",
        0x7d => "OP_TUCK",
        0x7e => "OP_CAT",
        0x7f => "OP_SUBSTR",
        0x80 => "OP_LEFT",
        0x81 => "OP_RIGHT",
        0x82 => "OP_SIZE",
        0x83 => "OP_INVERT",
        0x84 => "OP_AND",
        0x85 => "OP_OR",
        0x86 => "OP_XOR",
        0x87 => "OP_EQUAL",
        0x88 => "OP_EQUALVERIFY",
        0x89 => "OP_RESERVED1",
        0x8a => "OP_RESERVED2",
        0x8b => "OP_1ADD",
        0x8c => "OP_1SUB",
        0x8d => "OP_2MUL",
        0x8e => "OP_2DIV",
        0x8f => "OP_NEGATE",
        0x90 => "OP_ABS",
        0x91 => "OP_NOT",
        0x92 => "OP_0NOTEQUAL",
        0x93 => "OP_ADD",
        0x94 => "OP_SUB",
        0x95 => "OP_MUL",
        0x96 => "OP_DIV",
        0x97 => "OP_MOD",
        0x98 => "OP_LSHIFT",
        0x99 => "OP_RSHIFT",
        0x9a => "OP_BOOLAND",
        0x9b => "OP_BOOLOR",
        0x9c => "OP_NUMEQUAL",
        0x9d => "OP_NUMEQUALVERIFY",
        0x9e => "OP_NUMNOTEQUAL",
        0x9f => "OP_LESSTHAN",
        0xa0 => "OP_GREATERTHAN",
        0xa1 => "OP_LESSTHANOREQUAL",
        0xa2 => "OP_GREATERTHANOREQUAL",
        0xa3 => "OP_MIN",
        0xa4 => "OP_MAX",
        0xa5 => "OP_WITHIN",
        0xa6 => "OP_RIPEMD160",
        0xa7 => "OP_SHA1",
        0xa8 => "OP_SHA256",
        0xa9 => "OP_HASH160",
        0xaa => "OP_HASH256",
        0xab => "OP_CODESEPARATOR",
        0xac => "OP_CHECKSIG",
        0xad => "OP_CHECKSIGVERIFY",
        0xae => "OP_CHECKMULTISIG",
        0xaf => "OP_CHECKMULTISIGVERIFY",
        0xb0 => "OP_NOP1",
        0xb1 => "OP_NOP2",
        0xb2 => "OP_NOP3",
        0xb3 => "OP_NOP4",
        0xb4 => "OP_NOP5",
        0xb5 => "OP_NOP6",
        0xb6 => "OP_NOP7",
        0xb7 => "OP_NOP8",
        0xb8 => "OP_NOP9",
        0xb9 => "OP_NOP10",
        0xc0 => "OP_CHECKSETSIG",
        0xc1 => "OP_CHECKSETDORMANT",
        0xc2 => "OP_CHECKPQSIG",
        0xff => "OP_INVALIDOPCODE",
        _ => "OP_UNKNOWN",
    }
}

/// One `GetOp` step: `(opcode, data)`, or `None` on a truncated push.
fn get_op(s: &[u8], pc: &mut usize) -> Option<(u8, Vec<u8>)> {
    let op = *s.get(*pc)?;
    *pc += 1;
    if op > 0x4e {
        return Some((op, Vec::new()));
    }
    let n = match op {
        0x4c => {
            let n = *s.get(*pc)? as usize;
            *pc += 1;
            n
        }
        0x4d => {
            let b = s.get(*pc..*pc + 2)?;
            *pc += 2;
            u16::from_le_bytes([b[0], b[1]]) as usize
        }
        0x4e => {
            let b = s.get(*pc..*pc + 4)?;
            *pc += 4;
            u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize
        }
        n => n as usize,
    };
    let d = s.get(*pc..pc.checked_add(n)?)?.to_vec();
    *pc += n;
    Some((op, d))
}

/// `CScriptNum(vch, false).getint()`.
fn script_num(v: &[u8]) -> i64 {
    if v.is_empty() {
        return 0;
    }
    let mut r: i64 = 0;
    for (i, b) in v.iter().enumerate() {
        r |= (*b as i64) << (8 * i);
    }
    let last = v[v.len() - 1];
    if last & 0x80 != 0 {
        -(r & !(0x80i64 << (8 * (v.len() - 1))))
    } else {
        r
    }
    .clamp(i32::MIN as i64, i32::MAX as i64)
}

/// BIP66's `IsValidSignatureEncoding` plus a defined hash type (`CheckSignatureEncoding` with
/// `SCRIPT_VERIFY_STRICTENC`).
fn is_strict_sig(sig: &[u8]) -> bool {
    if sig.is_empty() {
        return true;
    }
    let n = sig.len();
    if !(9..=73).contains(&n) || sig[0] != 0x30 || sig[1] as usize != n - 3 {
        return false;
    }
    let len_r = sig[3] as usize;
    if 5 + len_r >= n {
        return false;
    }
    let len_s = sig[5 + len_r] as usize;
    if len_r + len_s + 7 != n || sig[2] != 0x02 || len_r == 0 || sig[4] & 0x80 != 0 {
        return false;
    }
    if len_r > 1 && sig[4] == 0 && sig[5] & 0x80 == 0 {
        return false;
    }
    if sig[len_r + 4] != 0x02 || len_s == 0 || sig[len_r + 6] & 0x80 != 0 {
        return false;
    }
    if len_s > 1 && sig[len_r + 6] == 0 && sig[len_r + 7] & 0x80 == 0 {
        return false;
    }
    let ht = sig[n - 1] & !0x80;
    (1..=3).contains(&ht)
}

fn sighash_name(b: u8) -> Option<&'static str> {
    match b {
        0x01 => Some("ALL"),
        0x81 => Some("ALL|ANYONECANPAY"),
        0x02 => Some("NONE"),
        0x82 => Some("NONE|ANYONECANPAY"),
        0x03 => Some("SINGLE"),
        0x83 => Some("SINGLE|ANYONECANPAY"),
        _ => None,
    }
}

/// `ScriptToAsmStr(script, fAttemptSighashDecode)`.
pub fn script_asm(s: &[u8], sighash_decode: bool) -> String {
    let unspendable = s.first() == Some(&0x6a) || s.len() > 10_000;
    let mut out = String::new();
    let mut pc = 0;
    while pc < s.len() {
        if !out.is_empty() {
            out.push(' ');
        }
        let Some((op, d)) = get_op(s, &mut pc) else {
            out.push_str("[error]");
            return out;
        };
        if op <= 0x4e {
            if d.len() <= 4 {
                out.push_str(&script_num(&d).to_string());
            } else if sighash_decode && !unspendable && is_strict_sig(&d) {
                match sighash_name(d[d.len() - 1]) {
                    Some(n) => {
                        out.push_str(&hex::encode(&d[..d.len() - 1]));
                        out.push_str(&format!("[{n}]"));
                    }
                    None => out.push_str(&hex::encode(&d)),
                }
            } else {
                out.push_str(&hex::encode(&d));
            }
        } else {
            out.push_str(op_name(op));
        }
    }
    out
}

fn is_pubkey(b: &[u8]) -> bool {
    (b.len() == 33 && (b[0] == 2 || b[0] == 3)) || (b.len() == 65 && b[0] == 4)
}

/// `Solver` + `ExtractDestinations`: `(type, Some((reqSigs, addresses)))`.
pub fn solve(network: Network, s: &[u8]) -> (&'static str, Option<(i64, Vec<String>)>) {
    if let Some(h) = yew_core::script::p2sh_hash(s) {
        return (
            "scripthash",
            Some((1, vec![yew_core::keys::encode_p2sh(network, &h)])),
        );
    }
    if s.first() == Some(&0x6a) {
        let mut pc = 1;
        let mut push_only = true;
        while pc < s.len() {
            match get_op(s, &mut pc) {
                Some((op, _)) if op <= 0x60 => {}
                _ => {
                    push_only = false;
                    break;
                }
            }
        }
        if push_only {
            return ("nulldata", None);
        }
    }
    if (s.len() == 35 || s.len() == 67) && s[0] as usize == s.len() - 2 && s[s.len() - 1] == 0xac {
        let pk = &s[1..s.len() - 1];
        if is_pubkey(pk) {
            let h = yew_core::keys::hash160(pk);
            return (
                "pubkey",
                Some((1, vec![yew_core::keys::encode_p2pkh(network, &h)])),
            );
        }
    }
    if let Some(h) = yew_core::script::p2pkh_hash(s) {
        return (
            "pubkeyhash",
            Some((1, vec![yew_core::keys::encode_p2pkh(network, &h)])),
        );
    }
    // multisig: OP_m <pk>... OP_n OP_CHECKMULTISIG
    if s.len() >= 3 && s[s.len() - 1] == 0xae && (0x51..=0x60).contains(&s[0]) {
        let m = (s[0] - 0x50) as i64;
        let mut pc = 1;
        let mut keys = Vec::new();
        let mut ok = true;
        while pc < s.len() - 2 {
            match get_op(s, &mut pc) {
                Some((op, d)) if op <= 0x4e && is_pubkey(&d) => keys.push(d),
                _ => {
                    ok = false;
                    break;
                }
            }
        }
        let n_op = s[s.len() - 2];
        if ok
            && pc == s.len() - 2
            && (0x51..=0x60).contains(&n_op)
            && (n_op - 0x50) as usize == keys.len()
            && keys.len() as i64 >= m
        {
            let addrs: Vec<String> = keys
                .iter()
                .map(|k| yew_core::keys::encode_p2pkh(network, &yew_core::keys::hash160(k)))
                .collect();
            return ("multisig", Some((m, addrs)));
        }
    }
    if let Some(id) = yew_core::pq::pqpkh_of(s) {
        let a = yew_core::keys::encode_pq_yec(network, &id).unwrap_or_default();
        return ("pqpubkeyhash", Some((1, vec![a])));
    }
    if yew_core::vault::parse_vault(s).is_some() {
        return ("vault", None);
    }
    if yew_core::vault::parse_intent(s).is_some() {
        return ("vaultintent", None);
    }
    ("nonstandard", None)
}

/// `ScriptPubKeyToJSON`.
fn script_pubkey_json(network: Network, s: &[u8], include_hex: bool) -> J {
    let mut o = J::obj().with("asm", script_asm(s, false));
    if include_hex {
        o.push("hex", J::Str(hex::encode(s)));
    }
    let (typ, dest) = solve(network, s);
    match dest {
        None => {
            o.push("type", J::Str(typ.into()));
        }
        Some((req, addrs)) => {
            o.push("reqSigs", J::Int(req));
            o.push("type", J::Str(typ.into()));
            o.push("addresses", J::Arr(addrs.into_iter().map(J::Str).collect()));
        }
    }
    o
}

fn hash_hex(b: &[u8; 32]) -> String {
    let mut r = *b;
    r.reverse();
    hex::encode(r)
}

/// `decoderawtransaction "hexstring"`.
pub fn decoderawtransaction(network: Network, p: &[Value]) -> Result<J, RpcError> {
    let h = p.first().and_then(|v| v.as_str()).ok_or_else(|| {
        RpcError::new(
            code::TYPE_ERROR,
            format!("Expected type string, got {}", type_name(p.first())),
        )
    })?;
    let bytes = hex::decode(h).map_err(|_| {
        RpcError::new(
            code::DESERIALIZATION_ERROR,
            "TX decode failed: non-hex input",
        )
    })?;
    let tx = zcash_primitives::transaction::Transaction::read(
        &bytes[..],
        zcash_protocol::consensus::BranchId::Sapling,
    )
    .map_err(|e| {
        RpcError::new(
            code::DESERIALIZATION_ERROR,
            format!("TX decode failed: {e}"),
        )
    })?;
    let (ytx, txid) = yew_core::tx::Transaction::parse(&bytes).map_err(|e| {
        RpcError::new(
            code::DESERIALIZATION_ERROR,
            format!("TX decode failed: {e}"),
        )
    })?;
    Ok(tx_json(network, &bytes, &ytx, &txid, &tx))
}

fn type_name(v: Option<&Value>) -> &'static str {
    match v {
        None | Some(Value::Null) => "null",
        Some(Value::Bool(_)) => "bool",
        Some(Value::Number(_)) => "number",
        Some(Value::String(_)) => "string",
        Some(Value::Array(_)) => "array",
        Some(Value::Object(_)) => "object",
    }
}

/// `TxToJSON` without a block.
fn tx_json(
    network: Network,
    bytes: &[u8],
    ytx: &yew_core::tx::Transaction,
    txid: &[u8; 32],
    tx: &zcash_primitives::transaction::Transaction,
) -> J {
    let mut o = J::obj()
        .with("txid", hash_hex(txid))
        .with("authdigest", "f".repeat(64))
        .with("size", bytes.len())
        .with("overwintered", ytx.overwintered())
        .with("version", ytx.version() as i64);
    if ytx.overwintered() {
        o.push(
            "versiongroupid",
            J::Str(format!("{:08x}", ytx.version_group_id)),
        );
    }
    o.push("locktime", J::Int(ytx.lock_time as i64));
    if ytx.overwintered() {
        o.push("expiryheight", J::Int(ytx.expiry_height as i64));
    }
    o.push("hex", J::Str(hex::encode(bytes)));
    let coinbase = ytx.vin.len() == 1
        && ytx.vin[0].prevout.txid == [0u8; 32]
        && ytx.vin[0].prevout.n == u32::MAX;
    let vin: Vec<J> = ytx
        .vin
        .iter()
        .map(|i| {
            let mut x = J::obj();
            if coinbase {
                x.push("coinbase", J::Str(hex::encode(&i.script_sig)));
            } else {
                x.push("txid", J::Str(hash_hex(&i.prevout.txid)));
                x.push("vout", J::Int(i.prevout.n as i64));
                x.push(
                    "scriptSig",
                    J::obj()
                        .with("asm", script_asm(&i.script_sig, true))
                        .with("hex", hex::encode(&i.script_sig)),
                );
            }
            x.push("sequence", J::Int(i.sequence as i64));
            x
        })
        .collect();
    o.push("vin", J::Arr(vin));
    let vout: Vec<J> = ytx
        .vout
        .iter()
        .enumerate()
        .map(|(n, out)| {
            J::obj()
                .with("value", J::Amount(out.value))
                .with("valueZat", out.value)
                .with("valueSat", out.value)
                .with("n", n)
                .with(
                    "scriptPubKey",
                    script_pubkey_json(network, &out.script_pubkey, true),
                )
        })
        .collect();
    o.push("vout", J::Arr(vout));
    o.push("vjoinsplit", J::Arr(vec![]));
    if ytx.overwintered() && ytx.version() >= 4 {
        let (vb, spends, outs, binding) = match tx.sapling_bundle() {
            Some(b) => {
                let spends: Vec<J> = b
                    .shielded_spends()
                    .iter()
                    .map(|s| {
                        J::obj()
                            .with("cv", hash_hex(&s.cv().to_bytes()))
                            .with("anchor", hash_hex(&s.anchor().to_bytes()))
                            .with("nullifier", hash_hex(&s.nullifier().0))
                            .with("rk", hash_hex(&<[u8; 32]>::from(*s.rk())))
                            .with("proof", hex::encode(s.zkproof()))
                            .with(
                                "spendAuthSig",
                                hex::encode(<[u8; 64]>::from(*s.spend_auth_sig())),
                            )
                    })
                    .collect();
                let outs: Vec<J> = b
                    .shielded_outputs()
                    .iter()
                    .map(|x| {
                        J::obj()
                            .with("cv", hash_hex(&x.cv().to_bytes()))
                            .with("cmu", hash_hex(&x.cmu().to_bytes()))
                            .with("ephemeralKey", hash_hex(&x.ephemeral_key().0))
                            .with("encCiphertext", hex::encode(x.enc_ciphertext()))
                            .with("outCiphertext", hex::encode(x.out_ciphertext()))
                            .with("proof", hex::encode(x.zkproof()))
                    })
                    .collect();
                let binding = hex::encode(<[u8; 64]>::from(b.authorization().binding_sig));
                (i64::from(*b.value_balance()), spends, outs, Some(binding))
            }
            None => (0, Vec::new(), Vec::new(), None),
        };
        o.push("valueBalance", J::Amount(vb));
        o.push("valueBalanceZat", J::Int(vb));
        let any = !spends.is_empty() || !outs.is_empty();
        o.push("vShieldedSpend", J::Arr(spends));
        o.push("vShieldedOutput", J::Arr(outs));
        if any {
            if let Some(b) = binding {
                o.push("bindingSig", J::Str(b));
            }
        }
    }
    o
}

/// `decodescript "hex"`.
pub fn decodescript(network: Network, p: &[Value]) -> Result<J, RpcError> {
    let h = p.first().and_then(|v| v.as_str()).ok_or_else(|| {
        RpcError::new(
            code::TYPE_ERROR,
            format!("Expected type string, got {}", type_name(p.first())),
        )
    })?;
    let s = if h.is_empty() {
        Vec::new()
    } else {
        hex::decode(h).map_err(|_| {
            RpcError::new(
                code::INVALID_PARAMETER,
                format!("argument must be hexadecimal string (not '{h}')"),
            )
        })?
    };
    let mut o = script_pubkey_json(network, &s, false);
    o.push(
        "p2sh",
        J::Str(yew_core::keys::encode_p2sh(
            network,
            &yew_core::keys::hash160(&s),
        )),
    );
    Ok(o)
}

/// `createrawtransaction [{"txid","vout","sequence"},...] {"address":amount,...} ( locktime
/// expiryheight )`: a v4 (Sapling) transaction at `next_height`, as ycashd's
/// `CreateNewContextualCMutableTransaction` makes it for Ycash (the Vault epoch is v4-only).
pub fn createrawtransaction(
    network: Network,
    next_height: u32,
    p: &[Value],
) -> Result<J, RpcError> {
    // RPCTypeCheck(VARR, VOBJ, VNUM, VNUM), nulls allowed
    for (i, want) in ["array", "object", "number", "number"].iter().enumerate() {
        if let Some(v) = p.get(i).filter(|v| !v.is_null()) {
            let got = type_name(Some(v));
            if got != *want {
                return Err(RpcError::new(
                    code::TYPE_ERROR,
                    format!("Expected type {want}, got {got}"),
                ));
            }
        }
    }
    let (Some(Value::Array(inputs)), Some(Value::Object(send_to))) = (p.first(), p.get(1)) else {
        return Err(RpcError::new(
            code::INVALID_PARAMETER,
            "Invalid parameter, arguments 1 and 2 must be non-null",
        ));
    };
    let mut tx = yew_core::tx::Transaction::new_v4();
    tx.expiry_height = next_height + EXPIRY_DELTA;
    if let Some(v) = p.get(2).filter(|v| !v.is_null()) {
        let lt = v.as_i64().unwrap_or(-1);
        if !(0..=u32::MAX as i64).contains(&lt) {
            return Err(RpcError::new(
                code::INVALID_PARAMETER,
                "Invalid parameter, locktime out of range",
            ));
        }
        tx.lock_time = lt as u32;
    }
    if let Some(v) = p.get(3).filter(|v| !v.is_null()) {
        let e = v.as_i64().unwrap_or(-1);
        if !(0..EXPIRY_THRESHOLD).contains(&e) {
            return Err(RpcError::new(
                code::INVALID_PARAMETER,
                format!("Invalid parameter, expiryheight must be nonnegative and less than {EXPIRY_THRESHOLD}."),
            ));
        }
        if e != 0 && next_height as i64 + EXPIRING_SOON > e {
            return Err(RpcError::new(
                code::INVALID_PARAMETER,
                format!(
                    "Invalid parameter, expiryheight should be at least {} to avoid transaction expiring soon",
                    next_height as i64 + EXPIRING_SOON
                ),
            ));
        }
        tx.expiry_height = e as u32;
    }
    for i in inputs {
        let o = i.as_object().ok_or_else(|| {
            RpcError::new(code::MISC_ERROR, "JSON value is not an object as expected")
        })?;
        let txid_s = o.get("txid").and_then(|v| v.as_str()).ok_or_else(|| {
            RpcError::new(
                code::INVALID_PARAMETER,
                "txid must be hexadecimal string (not '')",
            )
        })?;
        let txid = yew_core::tx::txid_from_hex(txid_s)
            .ok()
            .filter(|_| txid_s.len() == 64)
            .ok_or_else(|| {
                RpcError::new(
                    code::INVALID_PARAMETER,
                    format!("txid must be hexadecimal string (not '{txid_s}')"),
                )
            })?;
        let vout = match o.get("vout") {
            Some(Value::Number(n)) => n.as_i64().unwrap_or(-1),
            _ => {
                return Err(RpcError::new(
                    code::INVALID_PARAMETER,
                    "Invalid parameter, missing vout key",
                ))
            }
        };
        if vout < 0 {
            return Err(RpcError::new(
                code::INVALID_PARAMETER,
                "Invalid parameter, vout must be positive",
            ));
        }
        let mut sequence = if tx.lock_time != 0 {
            u32::MAX - 1
        } else {
            u32::MAX
        };
        if let Some(Value::Number(n)) = o.get("sequence") {
            sequence = n.as_i64().unwrap_or(0) as u32;
        }
        let mut txin = yew_core::tx::TxIn::new(yew_core::tx::OutPoint {
            txid,
            n: vout as u32,
        });
        txin.sequence = sequence;
        tx.vin.push(txin);
    }
    let mut seen = std::collections::BTreeSet::new();
    for (name, v) in send_to {
        let script = crate::rpc::parse_taddr_script(network, name)
            .or_else(|| {
                yew_core::keys::parse_pq_address(network, name)
                    .ok()
                    .and_then(|id| yew_core::pq::pqpkh_script(&id))
            })
            .ok_or_else(|| {
                RpcError::new(
                    code::INVALID_ADDRESS_OR_KEY,
                    format!("Invalid Ycash address: {name}"),
                )
            })?;
        if !seen.insert(script.clone()) {
            return Err(RpcError::new(
                code::INVALID_PARAMETER,
                format!("Invalid parameter, duplicated address: {name}"),
            ));
        }
        let amount = crate::build::amount_param(v)?;
        tx.vout.push(yew_core::tx::TxOut {
            value: amount,
            script_pubkey: script,
        });
    }
    let raw = tx
        .serialize()
        .map_err(|e| RpcError::new(code::INTERNAL_ERROR, e.to_string()))?;
    Ok(J::Str(hex::encode(raw)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asm_and_types() {
        let pkh = hex::decode("76a914000102030405060708090a0b0c0d0e0f1011121388ac").unwrap();
        assert_eq!(
            script_asm(&pkh, false),
            "OP_DUP OP_HASH160 000102030405060708090a0b0c0d0e0f10111213 OP_EQUALVERIFY OP_CHECKSIG"
        );
        assert_eq!(solve(Network::Regtest, &pkh).0, "pubkeyhash");
        assert_eq!(
            script_asm(&[0x51, 0x02, 0xff, 0x00, 0x6a], false),
            "1 255 OP_RETURN"
        );
        assert_eq!(script_asm(&[0x4c], false), "[error]");
        assert_eq!(solve(Network::Regtest, &[0x6a, 0x01, 0x07]).0, "nulldata");
        assert_eq!(solve(Network::Regtest, &[0x51]).0, "nonstandard");
        assert_eq!(script_num(&[0x81]), -1);
        assert_eq!(script_num(&[0xff, 0x00]), 255);
    }
}
