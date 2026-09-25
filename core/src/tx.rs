//! Transactions: the v4 (Sapling, `fOverwintered`) transparent-only serializer, a parser that
//! also reads the transparent part of transactions with shielded components (history of funds
//! from shielded senders), the ZIP-243 sighash bound to `consensusBranchId`, and the signer
//! (D-W-3: hand-written, no `zcash_*` crates; RFC 6979 via libsecp256k1 so the node's
//! `signrawtransaction` produces the same DER bytes).
//!
//! Translation source: `ycash-dd/src/primitives/transaction.h:575-640` (`SerializationOp`),
//! `qa/rpc-tests/test_framework/script.py:829-935` (`SignatureHash`, the Python form of
//! `ref/ycash/src/script/interpreter.cpp` `SignatureHash`, ZIP-243 branch).
//! Verified byte-for-byte against the node-generated vectors in `tests/vectors/transparent.json`.

use secp256k1::{Message, SecretKey};
use thiserror::Error;

use crate::keys::sha256d;
use crate::params::{
    OVERWINTER_VERSION_GROUP_ID, SAPLING_VERSION_GROUP_ID, SEQUENCE_FINAL, SIGHASH_ALL,
    TX_HEADER_V4,
};
use crate::script;

/// Transaction errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TxError {
    /// The bytes ended before the structure did.
    #[error("truncated transaction at byte {0}")]
    Truncated(usize),
    /// A version / version group combination the node would reject.
    #[error("unsupported transaction version: header {0:#010x}, group {1:#010x}")]
    Version(u32, u32),
    /// Trailing bytes after a complete transaction.
    #[error("{0} trailing bytes")]
    Trailing(usize),
    /// The transaction carries shielded components and cannot be re-serialized here.
    #[error("transaction has shielded components; YEW only serializes transparent v4")]
    Shielded,
    /// The input index is out of range.
    #[error("input index {0} out of range")]
    InputIndex(usize),
}

/// A reference to an output.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OutPoint {
    /// The txid, in internal byte order (as serialized; reverse for display).
    pub txid: [u8; 32],
    /// The output index.
    pub n: u32,
}

impl OutPoint {
    /// The display form `hex(reversed txid):n`.
    pub fn display(&self) -> String {
        format!("{}:{}", txid_hex(&self.txid), self.n)
    }
}

/// The display form of a txid: the internal bytes reversed, in hex.
pub fn txid_hex(txid: &[u8; 32]) -> String {
    let mut r = *txid;
    r.reverse();
    crate::keys::hex(&r)
}

/// Parse a display-form txid back to internal byte order.
pub fn txid_from_hex(s: &str) -> Result<[u8; 32], String> {
    let v = crate::keys::unhex(s)?;
    if v.len() != 32 {
        return Err(format!("txid must be 32 bytes, got {}", v.len()));
    }
    let mut r = [0u8; 32];
    r.copy_from_slice(&v);
    r.reverse();
    Ok(r)
}

/// A transaction input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxIn {
    /// The spent output.
    pub prevout: OutPoint,
    /// The unlocking script (empty until signed).
    pub script_sig: Vec<u8>,
    /// `nSequence`.
    pub sequence: u32,
}

impl TxIn {
    /// An unsigned input with `SEQUENCE_FINAL`.
    pub fn new(prevout: OutPoint) -> TxIn {
        TxIn {
            prevout,
            script_sig: Vec::new(),
            sequence: SEQUENCE_FINAL,
        }
    }
}

/// A transaction output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOut {
    /// `nValue` in zatoshi.
    pub value: i64,
    /// The locking script.
    pub script_pubkey: Vec<u8>,
}

/// What a parsed transaction carried besides its transparent part. Never set on a
/// transaction YEW builds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ShieldedSummary {
    /// `vShieldedSpend.size()`.
    pub spends: usize,
    /// `vShieldedOutput.size()`.
    pub outputs: usize,
    /// `vJoinSplit.size()`.
    pub joinsplits: usize,
    /// `valueBalance` as parsed.
    pub value_balance: i64,
}

impl ShieldedSummary {
    /// True when any shielded component is present.
    pub fn any(&self) -> bool {
        self.spends > 0 || self.outputs > 0 || self.joinsplits > 0
    }
}

/// A transaction: the transparent fields YEW serializes, plus a summary of any shielded part
/// found while parsing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    /// The header word: `fOverwintered << 31 | nVersion` (`TX_HEADER_V4` when built here).
    pub header: u32,
    /// `nVersionGroupId` (0 for pre-Overwinter transactions).
    pub version_group_id: u32,
    /// Inputs.
    pub vin: Vec<TxIn>,
    /// Outputs.
    pub vout: Vec<TxOut>,
    /// `nLockTime`.
    pub lock_time: u32,
    /// `nExpiryHeight` (0 = never).
    pub expiry_height: u32,
    /// The shielded components seen while parsing (all zero for a built transaction).
    pub shielded: ShieldedSummary,
}

impl Default for Transaction {
    fn default() -> Self {
        Transaction::new_v4()
    }
}

/// Sizes of the shielded structures, for skipping them
/// (`ycash-dd/src/primitives/transaction.h:78-152`, `src/zcash/Zcash.h`).
const SPEND_DESCRIPTION_SIZE: usize = 32 + 32 + 32 + 32 + 192 + 64; // 384
const OUTPUT_DESCRIPTION_SIZE: usize = 32 + 32 + 32 + 580 + 80 + 192; // 948
const JOINSPLIT_GROTH_SIZE: usize = 1698;
const JOINSPLIT_PHGR_SIZE: usize = 1802;
const JOINSPLIT_PUBKEY_SIZE: usize = 32;
const JOINSPLIT_SIG_SIZE: usize = 64;
const BINDING_SIG_SIZE: usize = 64;

impl Transaction {
    /// An empty Sapling v4 transaction.
    pub fn new_v4() -> Transaction {
        Transaction {
            header: TX_HEADER_V4,
            version_group_id: SAPLING_VERSION_GROUP_ID,
            vin: Vec::new(),
            vout: Vec::new(),
            lock_time: 0,
            expiry_height: 0,
            shielded: ShieldedSummary::default(),
        }
    }

    /// `fOverwintered`.
    pub fn overwintered(&self) -> bool {
        self.header & 0x8000_0000 != 0
    }

    /// `nVersion` (the header without the Overwinter bit).
    pub fn version(&self) -> u32 {
        self.header & 0x7fff_ffff
    }

    fn is_sapling_v4(&self) -> bool {
        self.overwintered()
            && self.version_group_id == SAPLING_VERSION_GROUP_ID
            && self.version() == 4
    }

    fn is_overwinter_v3(&self) -> bool {
        self.overwintered()
            && self.version_group_id == OVERWINTER_VERSION_GROUP_ID
            && self.version() == 3
    }

    /// Serialize a transparent-only transaction
    /// (`ycash-dd/src/primitives/transaction.h:575-640`): header, `nVersionGroupId`, `vin`,
    /// `vout`, `nLockTime`, `nExpiryHeight`, `valueBalance = 0`, three empty vectors, and no
    /// `bindingSig` (it is only written when a shielded spend or output exists, `:634`).
    pub fn serialize(&self) -> Result<Vec<u8>, TxError> {
        if self.shielded.any() {
            return Err(TxError::Shielded);
        }
        if !(self.is_sapling_v4() || self.is_overwinter_v3()) {
            return Err(TxError::Version(self.header, self.version_group_id));
        }
        let mut w = Vec::with_capacity(64 + 150 * self.vin.len() + 34 * self.vout.len());
        w.extend_from_slice(&self.header.to_le_bytes());
        w.extend_from_slice(&self.version_group_id.to_le_bytes());
        write_compact_size(&mut w, self.vin.len() as u64);
        for i in &self.vin {
            write_txin(&mut w, i);
        }
        write_compact_size(&mut w, self.vout.len() as u64);
        for o in &self.vout {
            write_txout(&mut w, o);
        }
        w.extend_from_slice(&self.lock_time.to_le_bytes());
        w.extend_from_slice(&self.expiry_height.to_le_bytes());
        if self.is_sapling_v4() {
            w.extend_from_slice(&0i64.to_le_bytes()); // valueBalance
            write_compact_size(&mut w, 0); // vShieldedSpend
            write_compact_size(&mut w, 0); // vShieldedOutput
        }
        write_compact_size(&mut w, 0); // vJoinSplit (nVersion >= 2)
        Ok(w)
    }

    /// The txid: `SHA256d` of the serialization, internal byte order.
    pub fn txid(&self) -> Result<[u8; 32], TxError> {
        Ok(sha256d(&self.serialize()?))
    }

    /// Parse a transaction of any Ycash version, reading the transparent fields and skipping
    /// the shielded ones by their fixed sizes. Returns the transaction and its txid (computed
    /// over the bytes consumed, so it is right for shielded transactions too).
    pub fn parse(bytes: &[u8]) -> Result<(Transaction, [u8; 32]), TxError> {
        let mut r = Reader { b: bytes, pos: 0 };
        let header = r.u32()?;
        let overwintered = header & 0x8000_0000 != 0;
        let version = header & 0x7fff_ffff;
        let version_group_id = if overwintered { r.u32()? } else { 0 };
        let is_overwinter_v3 =
            overwintered && version_group_id == OVERWINTER_VERSION_GROUP_ID && version == 3;
        let is_sapling_v4 =
            overwintered && version_group_id == SAPLING_VERSION_GROUP_ID && version == 4;
        if overwintered && !(is_overwinter_v3 || is_sapling_v4) {
            return Err(TxError::Version(header, version_group_id));
        }
        let n = r.compact_size()?;
        let mut vin = Vec::with_capacity(n.min(1024) as usize);
        for _ in 0..n {
            let mut txid = [0u8; 32];
            txid.copy_from_slice(r.take(32)?);
            let idx = r.u32()?;
            let script_sig = r.var_bytes()?;
            let sequence = r.u32()?;
            vin.push(TxIn {
                prevout: OutPoint { txid, n: idx },
                script_sig,
                sequence,
            });
        }
        let n = r.compact_size()?;
        let mut vout = Vec::with_capacity(n.min(1024) as usize);
        for _ in 0..n {
            let value = r.u64()? as i64;
            let script_pubkey = r.var_bytes()?;
            vout.push(TxOut {
                value,
                script_pubkey,
            });
        }
        let lock_time = r.u32()?;
        let expiry_height = if overwintered { r.u32()? } else { 0 };
        let mut shielded = ShieldedSummary::default();
        if is_sapling_v4 {
            shielded.value_balance = r.u64()? as i64;
            shielded.spends = r.compact_size()? as usize;
            r.take(shielded.spends * SPEND_DESCRIPTION_SIZE)?;
            shielded.outputs = r.compact_size()? as usize;
            r.take(shielded.outputs * OUTPUT_DESCRIPTION_SIZE)?;
        }
        if version >= 2 {
            shielded.joinsplits = r.compact_size()? as usize;
            let js_size = if is_sapling_v4 {
                JOINSPLIT_GROTH_SIZE
            } else {
                JOINSPLIT_PHGR_SIZE
            };
            r.take(shielded.joinsplits * js_size)?;
            if shielded.joinsplits > 0 {
                r.take(JOINSPLIT_PUBKEY_SIZE + JOINSPLIT_SIG_SIZE)?;
            }
        }
        if is_sapling_v4 && (shielded.spends > 0 || shielded.outputs > 0) {
            r.take(BINDING_SIG_SIZE)?;
        }
        if r.pos != bytes.len() {
            return Err(TxError::Trailing(bytes.len() - r.pos));
        }
        let txid = sha256d(bytes);
        Ok((
            Transaction {
                header,
                version_group_id,
                vin,
                vout,
                lock_time,
                expiry_height,
                shielded,
            },
            txid,
        ))
    }

    /// The ZIP-243 signature hash of input `index` with `hash_type`, over `script_code` (the
    /// scriptPubKey being spent for P2PKH) and the spent `amount`, bound to `branch_id`
    /// (`qa/rpc-tests/test_framework/script.py:871-935`). Only the shielded-free case is
    /// needed (the three shielded hashes are zero).
    pub fn sighash(
        &self,
        index: usize,
        script_code: &[u8],
        amount: i64,
        hash_type: u32,
        branch_id: u32,
    ) -> Result<[u8; 32], TxError> {
        if index >= self.vin.len() {
            return Err(TxError::InputIndex(index));
        }
        if self.shielded.any() {
            return Err(TxError::Shielded);
        }
        const ANYONECANPAY: u32 = 0x80;
        const NONE: u32 = 2;
        const SINGLE: u32 = 3;
        let base = hash_type & 0x1f;
        let zero = [0u8; 32];

        let hash_prevouts = if hash_type & ANYONECANPAY == 0 {
            let mut b = Vec::with_capacity(36 * self.vin.len());
            for i in &self.vin {
                b.extend_from_slice(&i.prevout.txid);
                b.extend_from_slice(&i.prevout.n.to_le_bytes());
            }
            blake2b_256(b"ZcashPrevoutHash", &b)
        } else {
            zero
        };
        let hash_sequence = if hash_type & ANYONECANPAY == 0 && base != SINGLE && base != NONE {
            let mut b = Vec::with_capacity(4 * self.vin.len());
            for i in &self.vin {
                b.extend_from_slice(&i.sequence.to_le_bytes());
            }
            blake2b_256(b"ZcashSequencHash", &b)
        } else {
            zero
        };
        let hash_outputs = if base != SINGLE && base != NONE {
            let mut b = Vec::new();
            for o in &self.vout {
                write_txout(&mut b, o);
            }
            blake2b_256(b"ZcashOutputsHash", &b)
        } else if base == SINGLE && index < self.vout.len() {
            let mut b = Vec::new();
            write_txout(&mut b, &self.vout[index]);
            blake2b_256(b"ZcashOutputsHash", &b)
        } else {
            zero
        };

        let mut person = [0u8; 16];
        person[..12].copy_from_slice(b"ZcashSigHash");
        person[12..].copy_from_slice(&branch_id.to_le_bytes());
        let mut m = Vec::with_capacity(320);
        m.extend_from_slice(&self.header.to_le_bytes());
        m.extend_from_slice(&self.version_group_id.to_le_bytes());
        m.extend_from_slice(&hash_prevouts);
        m.extend_from_slice(&hash_sequence);
        m.extend_from_slice(&hash_outputs);
        m.extend_from_slice(&zero); // hashJoinSplits
        m.extend_from_slice(&zero); // hashShieldedSpends
        m.extend_from_slice(&zero); // hashShieldedOutputs
        m.extend_from_slice(&self.lock_time.to_le_bytes());
        m.extend_from_slice(&self.expiry_height.to_le_bytes());
        m.extend_from_slice(&0i64.to_le_bytes()); // valueBalance
        m.extend_from_slice(&hash_type.to_le_bytes());
        let i = &self.vin[index];
        m.extend_from_slice(&i.prevout.txid);
        m.extend_from_slice(&i.prevout.n.to_le_bytes());
        write_compact_size(&mut m, script_code.len() as u64);
        m.extend_from_slice(script_code);
        m.extend_from_slice(&(amount as u64).to_le_bytes());
        m.extend_from_slice(&i.sequence.to_le_bytes());
        Ok(blake2b_256(&person, &m))
    }

    /// Sign input `index` as P2PKH over `secret` (whose key hash the spent script must pay),
    /// `SIGHASH_ALL`, and set its scriptSig to `<DER sig ‖ 0x01> <pubkey>`. Returns the
    /// sighash that was signed, for diagnosis against the node's vectors.
    pub fn sign_p2pkh_input(
        &mut self,
        index: usize,
        secret: &SecretKey,
        script_pubkey: &[u8],
        amount: i64,
        branch_id: u32,
    ) -> Result<[u8; 32], TxError> {
        let digest = self.sighash(index, script_pubkey, amount, SIGHASH_ALL, branch_id)?;
        let sig = secp256k1::ecdsa::sign(Message::from_digest(digest), secret);
        let mut der = sig.serialize_der().to_vec();
        der.push(SIGHASH_ALL as u8);
        let pubkey = secp256k1::PublicKey::from_secret_key(secret).serialize();
        self.vin[index].script_sig = script::p2pkh_script_sig(&der, &pubkey);
        Ok(digest)
    }

    /// Sum of output values.
    pub fn output_total(&self) -> i64 {
        self.vout.iter().map(|o| o.value).sum()
    }
}

/// BLAKE2b-256 with a 16-byte personalization (ZIP-243).
pub fn blake2b_256(person: &[u8], data: &[u8]) -> [u8; 32] {
    let h = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(person)
        .hash(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_bytes());
    out
}

/// Bitcoin `CompactSize`.
pub fn write_compact_size(w: &mut Vec<u8>, n: u64) {
    if n < 253 {
        w.push(n as u8);
    } else if n <= 0xffff {
        w.push(253);
        w.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        w.push(254);
        w.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        w.push(255);
        w.extend_from_slice(&n.to_le_bytes());
    }
}

fn write_txin(w: &mut Vec<u8>, i: &TxIn) {
    w.extend_from_slice(&i.prevout.txid);
    w.extend_from_slice(&i.prevout.n.to_le_bytes());
    write_compact_size(w, i.script_sig.len() as u64);
    w.extend_from_slice(&i.script_sig);
    w.extend_from_slice(&i.sequence.to_le_bytes());
}

fn write_txout(w: &mut Vec<u8>, o: &TxOut) {
    w.extend_from_slice(&(o.value as u64).to_le_bytes());
    write_compact_size(w, o.script_pubkey.len() as u64);
    w.extend_from_slice(&o.script_pubkey);
}

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], TxError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(TxError::Truncated(self.pos))?;
        let s = self
            .b
            .get(self.pos..end)
            .ok_or(TxError::Truncated(self.pos))?;
        self.pos = end;
        Ok(s)
    }
    fn u32(&mut self) -> Result<u32, TxError> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn u64(&mut self) -> Result<u64, TxError> {
        let s = self.take(8)?;
        Ok(u64::from_le_bytes(s.try_into().expect("8 bytes")))
    }
    fn compact_size(&mut self) -> Result<u64, TxError> {
        let first = self.take(1)?[0];
        Ok(match first {
            253 => {
                let s = self.take(2)?;
                u16::from_le_bytes([s[0], s[1]]) as u64
            }
            254 => self.u32()? as u64,
            255 => self.u64()?,
            n => n as u64,
        })
    }
    fn var_bytes(&mut self) -> Result<Vec<u8>, TxError> {
        let n = self.compact_size()?;
        if n > (1 << 24) {
            return Err(TxError::Truncated(self.pos));
        }
        Ok(self.take(n as usize)?.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{hex, unhex};

    fn sample() -> Transaction {
        let mut t = Transaction::new_v4();
        t.vin.push(TxIn::new(OutPoint {
            txid: [0x11; 32],
            n: 1,
        }));
        t.vout.push(TxOut {
            value: 12_345,
            script_pubkey: script::p2pkh_script(&[0x22; 20]),
        });
        t.lock_time = 5;
        t.expiry_height = 300;
        t
    }

    #[test]
    fn serialize_parse_round_trip() {
        let t = sample();
        let bytes = t.serialize().unwrap();
        // header, group id, 1 vin (32+4+1+4), 1 vout (8+1+25), locktime, expiry, valueBalance,
        // two empty vectors, empty joinsplits.
        assert_eq!(bytes.len(), 4 + 4 + 1 + 41 + 1 + 34 + 4 + 4 + 8 + 1 + 1 + 1);
        assert_eq!(&bytes[..8], &unhex("0400008085202f89").unwrap()[..]);
        let (p, txid) = Transaction::parse(&bytes).unwrap();
        assert_eq!(p, t);
        assert_eq!(txid, t.txid().unwrap());
        assert_eq!(
            Transaction::parse(&bytes[..bytes.len() - 1]),
            Err(TxError::Truncated(bytes.len() - 1))
        );
        let mut extra = bytes.clone();
        extra.push(0);
        assert_eq!(Transaction::parse(&extra), Err(TxError::Trailing(1)));
    }

    #[test]
    fn parse_skips_shielded_components() {
        // A v4 tx with one Sapling output and no transparent inputs: the transparent part
        // reads, the shielded part is skipped by size, the binding signature is consumed.
        let mut b = Vec::new();
        b.extend_from_slice(&TX_HEADER_V4.to_le_bytes());
        b.extend_from_slice(&SAPLING_VERSION_GROUP_ID.to_le_bytes());
        b.push(0); // vin
        b.push(1); // vout
        write_txout(
            &mut b,
            &TxOut {
                value: 7,
                script_pubkey: script::p2pkh_script(&[1; 20]),
            },
        );
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&(-7i64).to_le_bytes());
        b.push(0); // spends
        b.push(1); // outputs
        b.extend(std::iter::repeat_n(0xabu8, OUTPUT_DESCRIPTION_SIZE));
        b.push(0); // joinsplits
        b.extend(std::iter::repeat_n(0xcdu8, BINDING_SIG_SIZE));
        let (t, _) = Transaction::parse(&b).unwrap();
        assert_eq!(t.vout[0].value, 7);
        assert_eq!(
            t.shielded,
            ShieldedSummary {
                spends: 0,
                outputs: 1,
                joinsplits: 0,
                value_balance: -7
            }
        );
        assert_eq!(t.serialize(), Err(TxError::Shielded));
        // Legacy v1 (pre-Overwinter) also parses: no group id, no expiry, no joinsplits.
        let mut v1 = Vec::new();
        v1.extend_from_slice(&1u32.to_le_bytes());
        v1.push(0);
        v1.push(0);
        v1.extend_from_slice(&0u32.to_le_bytes());
        let (t, _) = Transaction::parse(&v1).unwrap();
        assert_eq!(t.version(), 1);
        assert!(!t.overwintered());
    }

    #[test]
    fn sighash_is_deterministic_and_branch_bound() {
        let t = sample();
        let spk = script::p2pkh_script(&[0x33; 20]);
        let a = t
            .sighash(0, &spk, 50_000, SIGHASH_ALL, 0x76b8_09bb)
            .unwrap();
        let b = t
            .sighash(0, &spk, 50_000, SIGHASH_ALL, 0x76b8_09bb)
            .unwrap();
        let c = t
            .sighash(0, &spk, 50_000, SIGHASH_ALL, 0x2bb4_0e60)
            .unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(
            t.sighash(1, &spk, 1, SIGHASH_ALL, 1),
            Err(TxError::InputIndex(1))
        );
    }

    #[test]
    fn signing_produces_a_verifiable_low_s_der_signature() {
        let mut t = sample();
        let sk = SecretKey::from_secret_bytes([9u8; 32]).unwrap();
        let pk = secp256k1::PublicKey::from_secret_key(&sk);
        let spk = script::p2pkh_script(&crate::keys::hash160(&pk.serialize()));
        let digest = t
            .sign_p2pkh_input(0, &sk, &spk, 50_000, 0x76b8_09bb)
            .unwrap();
        let pushes = script::pushes(&t.vin[0].script_sig).unwrap();
        assert_eq!(pushes.len(), 2);
        assert_eq!(pushes[1], pk.serialize());
        let der = &pushes[0][..pushes[0].len() - 1];
        assert_eq!(*pushes[0].last().unwrap(), 1);
        let sig = secp256k1::ecdsa::Signature::from_der(der).unwrap();
        secp256k1::ecdsa::verify(&sig, Message::from_digest(digest), &pk).unwrap();
        // Deterministic (RFC 6979): signing again gives the same bytes.
        let mut t2 = sample();
        t2.sign_p2pkh_input(0, &sk, &spk, 50_000, 0x76b8_09bb)
            .unwrap();
        assert_eq!(t.vin[0].script_sig, t2.vin[0].script_sig);
        assert_eq!(hex(&t.txid().unwrap()).len(), 64);
    }

    #[test]
    fn txid_hex_round_trip() {
        let t = [0xab; 32];
        let s = txid_hex(&t);
        assert_eq!(txid_from_hex(&s).unwrap(), t);
        let mut asc = [0u8; 32];
        asc[0] = 1;
        assert!(txid_hex(&asc).ends_with("01"));
    }
}
