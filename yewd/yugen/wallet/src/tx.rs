// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The Yugen transaction as proposed in yewd/yugen/docs/node-interface.md W-TX (the node defines the final
//! bytes): a v4 overwintered transaction, version group `0x59474e47`, no Sapling or Sprout
//! parts, followed by the Yugen field (transfer, proof A, proof B). Transparent inputs are
//! signed by ZIP-243 (Published: ZIP-243, Zcash) extended with `hashYugen` after `valueBalance`
//! (Original, the Ycash developers, 2026: proposal W-TX). The deposit key is a P2PKH key
//! derived from the Yugen seed (decision Y-W4).

use blake2b_simd::Params;
use secp256k1::{Message, PublicKey, SecretKey, SECP256K1};
use sha2::{Digest, Sha256};

pub const YUGEN_VERSION_GROUP_ID: u32 = 0x5947_4e47;
pub const HEADER: u32 = 0x8000_0004;

pub fn compact(o: &mut Vec<u8>, n: u64) {
    match n {
        0..=0xfc => o.push(n as u8),
        0xfd..=0xffff => {
            o.push(0xfd);
            o.extend((n as u16).to_le_bytes())
        }
        0x1_0000..=0xffff_ffff => {
            o.push(0xfe);
            o.extend((n as u32).to_le_bytes())
        }
        _ => {
            o.push(0xff);
            o.extend(n.to_le_bytes())
        }
    }
}
fn varbytes(o: &mut Vec<u8>, b: &[u8]) {
    compact(o, b.len() as u64);
    o.extend(b);
}

#[derive(Clone, Debug)]
pub struct TxIn {
    /// Previous txid in internal byte order.
    pub prev: [u8; 32],
    pub vout: u32,
    pub value: u64,
    pub script_pubkey: Vec<u8>,
    pub script_sig: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct TxOut {
    pub value: u64,
    pub script: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct YugenTx {
    pub vin: Vec<TxIn>,
    pub vout: Vec<TxOut>,
    pub expiry: u32,
    pub transfer: Vec<u8>,
    pub proof_a: Vec<u8>,
    pub proof_b: Vec<u8>,
}

/// Consensus serialisation of a `vout` vector (what the transfer hash binds, spec §7.3).
pub fn vout_bytes(vout: &[TxOut]) -> Vec<u8> {
    let mut o = Vec::new();
    compact(&mut o, vout.len() as u64);
    for x in vout {
        o.extend(x.value.to_le_bytes());
        varbytes(&mut o, &x.script);
    }
    o
}

fn b2(personal: &[u8], data: &[u8]) -> [u8; 32] {
    Params::new().hash_length(32).personal(personal).hash(data).as_bytes().try_into().unwrap()
}

impl YugenTx {
    pub fn serialize(&self) -> Vec<u8> {
        let mut o = Vec::new();
        o.extend(HEADER.to_le_bytes());
        o.extend(YUGEN_VERSION_GROUP_ID.to_le_bytes());
        compact(&mut o, self.vin.len() as u64);
        for i in &self.vin {
            o.extend(i.prev);
            o.extend(i.vout.to_le_bytes());
            varbytes(&mut o, &i.script_sig);
            o.extend(0xffff_ffffu32.to_le_bytes());
        }
        o.extend(&vout_bytes(&self.vout)[..]);
        o.extend(0u32.to_le_bytes()); // nLockTime
        o.extend(self.expiry.to_le_bytes());
        o.extend(0i64.to_le_bytes()); // valueBalance (Sapling)
        o.extend([0, 0, 0]); // no Sapling spends, outputs, JoinSplits
        varbytes(&mut o, &self.transfer);
        varbytes(&mut o, &self.proof_a);
        varbytes(&mut o, &self.proof_b);
        o
    }

    /// ZIP-243 SIGHASH_ALL for input `n`, with `hashYugen` (W-TX).
    pub fn sighash(&self, n: usize, branch_id: u32) -> [u8; 32] {
        let mut prevouts = Vec::new();
        let mut seq = Vec::new();
        for i in &self.vin {
            prevouts.extend(i.prev);
            prevouts.extend(i.vout.to_le_bytes());
            seq.extend(0xffff_ffffu32.to_le_bytes());
        }
        let outs = vout_bytes(&self.vout)[1..].to_vec();
        let z = [0u8; 32];
        let hp = if self.vin.is_empty() { z } else { b2(b"ZcashPrevoutHash", &prevouts) };
        let hs = if self.vin.is_empty() { z } else { b2(b"ZcashSequencHash", &seq) };
        let ho = b2(b"ZcashOutputsHash", &outs); // SIGHASH_ALL: the hash even of no outputs (as ycashd)
        let mut m = Vec::new();
        m.extend(HEADER.to_le_bytes());
        m.extend(YUGEN_VERSION_GROUP_ID.to_le_bytes());
        m.extend(hp);
        m.extend(hs);
        m.extend(ho);
        m.extend(z); // JoinSplits
        m.extend(z); // Sapling spends
        m.extend(z); // Sapling outputs
        m.extend(0u32.to_le_bytes());
        m.extend(self.expiry.to_le_bytes());
        m.extend(0i64.to_le_bytes());
        m.extend(b2(b"ZcashYugenTxHash", &self.transfer));
        m.extend(1u32.to_le_bytes()); // SIGHASH_ALL
        let i = &self.vin[n];
        m.extend(i.prev);
        m.extend(i.vout.to_le_bytes());
        varbytes(&mut m, &i.script_pubkey);
        m.extend(i.value.to_le_bytes());
        m.extend(0xffff_ffffu32.to_le_bytes());
        let mut personal = b"ZcashSigHash".to_vec();
        personal.extend(branch_id.to_le_bytes());
        b2(&personal, &m)
    }

    /// Signs every input with `key` (all inputs are P2PKH of that key).
    pub fn sign_all(&mut self, key: &SecretKey, branch_id: u32) {
        let pk = PublicKey::from_secret_key(SECP256K1, key).serialize();
        for n in 0..self.vin.len() {
            let h = self.sighash(n, branch_id);
            let sig = SECP256K1.sign_ecdsa(&Message::from_digest(h), key);
            let mut der = sig.serialize_der().to_vec();
            der.push(1);
            let mut ss = Vec::new();
            ss.push(der.len() as u8);
            ss.extend(der);
            ss.push(33);
            ss.extend(pk);
            self.vin[n].script_sig = ss;
        }
    }

    /// The txid (RPC byte order) of the serialisation with proofs (W-TX keeps proofs inline).
    /// The txid: SHA256d of the serialization with both proof fields empty (ycash6 decision
    /// N-D7: the txid does not cover the leaf proofs).
    pub fn txid(&self) -> String {
        let mut t = self.clone();
        t.proof_a.clear();
        t.proof_b.clear();
        let d = Sha256::digest(Sha256::digest(t.serialize()));
        let mut r = d.to_vec();
        r.reverse();
        hex::encode(r)
    }
}

/// The deposit key: `SHA256("Yugen/yewd/deposit-key/v1" || seed)` (Y-W4).
pub fn deposit_key(seed: &[u8]) -> SecretKey {
    let d = Sha256::new().chain_update(b"Yugen/yewd/deposit-key/v1").chain_update(seed).finalize();
    SecretKey::from_slice(&d).expect("valid scalar")
}
pub fn p2pkh_script(key: &SecretKey) -> Vec<u8> {
    let pk = PublicKey::from_secret_key(SECP256K1, key).serialize();
    let h = ripemd::Ripemd160::digest(Sha256::digest(pk));
    let mut s = vec![0x76, 0xa9, 0x14];
    s.extend(h);
    s.extend([0x88, 0xac]);
    s
}
/// Base58Check t-address. Ycash prefixes (ycash6 chainparams.cpp): mainnet 1c28, testnet and regtest 1c95.
pub fn taddr(key: &SecretKey, network: u8) -> String {
    let pk = PublicKey::from_secret_key(SECP256K1, key).serialize();
    let h = ripemd::Ripemd160::digest(Sha256::digest(pk));
    let mut p = if network == 0 { vec![0x1c, 0x28] } else { vec![0x1c, 0x95] };
    p.extend(h);
    bs58::encode(p).with_check().into_string()
}
