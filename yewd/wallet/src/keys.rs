// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! Public key material only (K-24, plan §4.3 rule 2): the transparent account's xpub with
//! CKDpub for `m/44'/347'/0'/{0,1}/i` (the same tree yew-core's `KeyRing` derives privately,
//! proved equal in the tests), the post-quantum public keys of the signer's bundle, and the
//! lookups that decide what is "mine".

use std::collections::BTreeMap;

use hmac::{Hmac, KeyInit, Mac};
use secp256k1::{PublicKey, Scalar};
use yew_core::keys::{self, HARDENED};
use yew_core::params::Network;
use yew_core::pq::PqKeyId;
use yewd_proto::{AccountXpub, PqPublic};

type HmacSha512 = Hmac<sha2::Sha512>;

/// How many keys past the last issued one each chain watches (ycashd's default `-keypool`).
pub const LOOKAHEAD: u32 = 100;
/// How many post-quantum keys past the last issued one each scheme watches (ycashd's
/// `PQ_KEY_LOOKAHEAD`).
pub const PQ_LOOKAHEAD: u32 = 20;

/// The external (receive) and internal (change) chains.
pub const EXTERNAL: u32 = 0;
pub const INTERNAL: u32 = 1;
/// The signer's imported keys (`importprivkey`, S3): `chain` 2 of a [`TKey`], `index` the store's.
pub const IMPORTED: u32 = yewd_proto::IMPORTED_CHAIN;

#[derive(Clone, Debug)]
pub struct Xpub {
    pub key: PublicKey,
    pub chain_code: [u8; 32],
}

impl Xpub {
    pub fn from_proto(a: &AccountXpub) -> Result<Xpub, String> {
        let pk = hex::decode(&a.pubkey).map_err(|e| e.to_string())?;
        let cc = hex::decode(&a.chain_code).map_err(|e| e.to_string())?;
        Ok(Xpub {
            key: PublicKey::from_slice(&pk).map_err(|e| e.to_string())?,
            chain_code: cc
                .try_into()
                .map_err(|_| "chain code is not 32 bytes".to_string())?,
        })
    }

    /// CKDpub (BIP32, non-hardened children only).
    pub fn child(&self, index: u32) -> Result<Xpub, String> {
        if index >= HARDENED {
            return Err("a hardened child needs the private key".into());
        }
        let mut mac = HmacSha512::new_from_slice(&self.chain_code).expect("any key length");
        mac.update(&self.key.serialize());
        mac.update(&index.to_be_bytes());
        let i: [u8; 64] = mac.finalize().into_bytes().into();
        let il: [u8; 32] = i[..32].try_into().expect("32 bytes");
        let tweak = Scalar::from_be_bytes(il).map_err(|_| format!("child {index}: invalid"))?;
        let key = self
            .key
            .add_exp_tweak(&tweak)
            .map_err(|_| format!("child {index}: invalid"))?;
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&i[32..]);
        Ok(Xpub { key, chain_code })
    }
}

/// One transparent key of the wallet.
#[derive(Clone, Debug)]
pub struct TKey {
    pub chain: u32,
    pub index: u32,
    pub pubkey: [u8; 33],
    pub hash: [u8; 20],
}

/// One post-quantum key of the wallet.
#[derive(Clone, Debug)]
pub struct PqOwn {
    pub scheme: u8,
    pub index: u32,
    pub pk: Vec<u8>,
    pub id: PqKeyId,
}

/// The wallet's keys: transparent keys up to `issued + LOOKAHEAD` on both chains, every PQ key of
/// the bundle.
#[derive(Clone, Debug, Default)]
pub struct KeyBook {
    pub tkeys: Vec<TKey>,
    by_hash: BTreeMap<[u8; 20], usize>,
    pub pq: BTreeMap<[u8; 33], PqOwn>,
    chains: Vec<Xpub>,
}

impl KeyBook {
    pub fn new(account: &AccountXpub) -> Result<KeyBook, String> {
        let acct = Xpub::from_proto(account)?;
        Ok(KeyBook {
            chains: vec![acct.child(EXTERNAL)?, acct.child(INTERNAL)?],
            ..KeyBook::default()
        })
    }

    /// Derive the keys of `chain` up to `upto` (exclusive).
    pub fn extend(&mut self, chain: u32, upto: u32) -> Result<(), String> {
        let have = self.tkeys.iter().filter(|k| k.chain == chain).count() as u32;
        for index in have..upto {
            let k = self.chains[chain as usize].child(index)?;
            let pubkey = k.key.serialize();
            let hash = keys::hash160(&pubkey);
            self.by_hash.insert(hash, self.tkeys.len());
            self.tkeys.push(TKey {
                chain,
                index,
                pubkey,
                hash,
            });
        }
        Ok(())
    }

    /// Watch the signer's imported key `index` (its public key from the signer's bundle).
    pub fn add_imported(&mut self, index: u32, pubkey: [u8; 33]) {
        if self.key(IMPORTED, index).is_some() {
            return;
        }
        let hash = keys::hash160(&pubkey);
        // a key the seed also derives stays the seed's
        self.by_hash.entry(hash).or_insert(self.tkeys.len());
        self.tkeys.push(TKey {
            chain: IMPORTED,
            index,
            pubkey,
            hash,
        });
    }

    pub fn key(&self, chain: u32, index: u32) -> Option<&TKey> {
        self.tkeys
            .iter()
            .find(|k| k.chain == chain && k.index == index)
    }

    pub fn by_hash(&self, h: &[u8; 20]) -> Option<&TKey> {
        self.by_hash.get(h).map(|&i| &self.tkeys[i])
    }

    pub fn add_pq(&mut self, p: &PqPublic) -> Result<(), String> {
        let pk = hex::decode(&p.pk).map_err(|e| e.to_string())?;
        let id = PqKeyId::of(p.scheme, &pk);
        self.pq.insert(
            id.to_bytes(),
            PqOwn {
                scheme: p.scheme,
                index: p.index,
                pk,
                id,
            },
        );
        Ok(())
    }

    pub fn pq_by_id(&self, id: &PqKeyId) -> Option<&PqOwn> {
        self.pq.get(&id.to_bytes())
    }

    pub fn pq_key(&self, scheme: u8, index: u32) -> Option<&PqOwn> {
        self.pq
            .values()
            .find(|p| p.scheme == scheme && p.index == index)
    }

    /// How many PQ keys of `scheme` the book holds (indices `0..n`).
    pub fn pq_count(&self, scheme: u8) -> u32 {
        self.pq.values().filter(|p| p.scheme == scheme).count() as u32
    }

    /// Whether `script` pays this wallet: P2PKH to a held key or `TX_PQPKH` to a held PQ key.
    pub fn owns_script(&self, script: &[u8]) -> Option<Owner> {
        if let Some(h) = yew_core::script::p2pkh_hash(script) {
            return self.by_hash(&h).map(|k| Owner::T(k.chain, k.index));
        }
        let id = yew_core::pq::pqpkh_of(script)?;
        self.pq_by_id(&id).map(|p| Owner::Pq(p.scheme, p.index))
    }
}

/// Which key a script pays.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Owner {
    T(u32, u32),
    Pq(u8, u32),
}

/// The address ycashd prints for a script (`ExtractDestination` + `EncodeDestination`): `s…`/`t…`
/// for P2PKH, P2SH, `sq…`/`tq…`/`rq…` for `TX_PQPKH`; `None` for anything else.
pub fn script_address(network: Network, script: &[u8]) -> Option<String> {
    if let Some(h) = yew_core::script::p2pkh_hash(script) {
        return Some(keys::encode_p2pkh(network, &h));
    }
    if let Some(h) = yew_core::script::p2sh_hash(script) {
        return Some(keys::encode_p2sh(network, &h));
    }
    let id = yew_core::pq::pqpkh_of(script)?;
    keys::encode_pq_yec(network, &id)
}

/// The Yellowback address of a holder script (`ScriptToYedAddress`): `yr…` for P2PKH, the
/// 53-character PQ form for `TX_PQPKH`.
pub fn yed_address(network: Network, script: &[u8]) -> Option<String> {
    if let Some(h) = yew_core::script::p2pkh_hash(script) {
        return Some(keys::encode_yellowback(network, &h));
    }
    let id = yew_core::pq::pqpkh_of(script)?;
    keys::encode_pq_yellowback(network, &id)
}

/// `scheme ‖ keyHash` as 66 hex digits (the `pqkeyid` of `doc/vault-rpc.md`).
pub fn pqkeyid_hex(id: &PqKeyId) -> String {
    hex::encode(id.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use yew_core::keys::{Chain, KeyRing};

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    /// CKDpub over the signer's xpub gives exactly the keys yew-core's `KeyRing` derives privately.
    #[test]
    fn ckdpub_matches_the_private_tree() {
        let ks = yewd_signer::Keystore::from_mnemonic(Network::Regtest, PHRASE);
        let b = ks.public(&Default::default()).unwrap();
        let mut book = KeyBook::new(&b.account).unwrap();
        book.extend(EXTERNAL, 5).unwrap();
        book.extend(INTERNAL, 3).unwrap();
        let ring = KeyRing::from_mnemonic(PHRASE, "").unwrap();
        for i in 0..5 {
            let k = ring.key(Chain::External, i).unwrap();
            assert_eq!(
                book.key(EXTERNAL, i).unwrap().hash,
                k.hash160,
                "external {i}"
            );
        }
        for i in 0..3 {
            let k = ring.key(Chain::Change, i).unwrap();
            assert_eq!(book.key(INTERNAL, i).unwrap().hash, k.hash160, "change {i}");
        }
        let addr = keys::encode_p2pkh(Network::Regtest, &book.key(EXTERNAL, 0).unwrap().hash);
        assert_eq!(
            addr,
            ring.key(Chain::External, 0)
                .unwrap()
                .address_s(Network::Regtest)
        );
        let script = yew_core::script::p2pkh_script(&book.key(EXTERNAL, 4).unwrap().hash);
        assert_eq!(book.owns_script(&script), Some(Owner::T(EXTERNAL, 4)));
        assert!(Xpub::from_proto(&b.account)
            .unwrap()
            .child(HARDENED)
            .is_err());
    }
}
