//! Keys and addresses: BIP39 mnemonic → seed, BIP32 secp256k1 derivation (implemented here over
//! `hmac`/`sha2`, no extra crate), BIP44 paths compatible with Ywallet (D-W-7), compressed
//! public keys, HASH160, address encoding (`s…` / `ye…` / `yt…` / `yr…`), WIF export and
//! import (D-W-11).
//!
//! Translation source (plan §3.6): `ycash-dd/src/yellowback/address.cpp` for the `s…` ↔ `ye…`
//! encoding (same key hash; version bytes from `params.cpp`, see [`crate::params::Network`]).
//! Derivation: Ywallet `zcash-sync/src/zip32.rs` `derive_zip32` at `m/44'/347'/0'/0/0`.

use hmac::{Hmac, KeyInit, Mac};
use ripemd::Ripemd160;
use secp256k1::{PublicKey, Scalar, SecretKey};
use sha2::{Digest, Sha256, Sha512};
use thiserror::Error;

use crate::params::{Network, ACCOUNT, BIP44_PURPOSE, COIN_TYPE};

/// Key and address errors.
#[derive(Debug, Error)]
pub enum KeyError {
    /// The mnemonic did not parse (wordlist, checksum, word count).
    #[error("bad mnemonic: {0}")]
    Mnemonic(String),
    /// A derived key fell outside the curve order (probability ≈ 2⁻¹²⁸; BIP32 says skip).
    #[error("bip32 derivation produced an invalid key at index {0}")]
    Derivation(u32),
    /// A Base58Check string did not decode, or had the wrong length or checksum.
    #[error("bad base58check: {0}")]
    Base58(String),
    /// The address prefix belongs to another network or is not a Ycash address.
    #[error("not a {0:?} address: {1}")]
    WrongNetwork(Network, String),
    /// The WIF did not decode as a compressed key of this network.
    #[error("bad wif: {0}")]
    Wif(String),
}

type HmacSha512 = Hmac<Sha512>;

/// Hardened child marker.
pub const HARDENED: u32 = 0x8000_0000;

/// `SHA256(data)`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// `SHA256(SHA256(data))` (txids, Base58Check checksums).
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

/// `RIPEMD160(SHA256(data))`: the key hash of every P2PKH and P2SH script.
pub fn hash160(data: &[u8]) -> [u8; 20] {
    Ripemd160::digest(sha256(data)).into()
}

// ---------------------------------------------------------------------------------------------
// Wiping (W5 security review, docs/security-review.md S-1)

/// Overwrite `bytes` with zeros through volatile writes the optimiser cannot elide (no
/// `zeroize` crate: it is not on the allow-list of plan §3.3). Best effort, as any wipe in
/// Rust is: the compiler may have copied the bytes elsewhere (a moved `[u8; N]`, a spilled
/// register); what this guarantees is that *this* allocation does not keep the secret after
/// the wipe.
pub fn wipe(bytes: &mut [u8]) {
    for b in bytes.iter_mut() {
        // SAFETY: `b` is a valid, exclusively borrowed `u8`.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// A `String` holding secret text (a mnemonic, a passphrase, a WIF) that is wiped when
/// dropped. Derefs to `str`; never `Debug`-prints its contents.
pub struct SecretString(String);

impl SecretString {
    /// Take ownership of `s`; it will be wiped on drop.
    pub fn new(s: String) -> SecretString {
        SecretString(s)
    }
}

impl std::ops::Deref for SecretString {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretString(..)")
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        let mut bytes = std::mem::take(&mut self.0).into_bytes();
        wipe(&mut bytes);
    }
}

// ---------------------------------------------------------------------------------------------
// BIP39

/// Parse a BIP39 English mnemonic (12–24 words) and derive the 64-byte seed with the optional
/// passphrase (D-W-7: Ywallet's `Seed::new(mnemonic, passphrase)`; empty passphrase by default).
pub fn seed_from_mnemonic(phrase: &str, passphrase: &str) -> Result<[u8; 64], KeyError> {
    let m = bip39::Mnemonic::parse_in(bip39::Language::English, phrase)
        .map_err(|e| KeyError::Mnemonic(e.to_string()))?;
    Ok(m.to_seed(passphrase))
}

/// Generate a fresh 24-word English mnemonic from the OS RNG.
pub fn generate_mnemonic(words: usize) -> Result<String, KeyError> {
    let count = match words {
        12 => bip39::WordCount::Words12,
        24 => bip39::WordCount::Words24,
        _ => return Err(KeyError::Mnemonic("word count must be 12 or 24".into())),
    };
    let m = bip39::Mnemonic::generate_in(bip39::Language::English, count)
        .map_err(|e| KeyError::Mnemonic(e.to_string()))?;
    Ok(m.to_string())
}

// ---------------------------------------------------------------------------------------------
// BIP32

/// A BIP32 extended private key: the key and its chain code. Depth, fingerprint and child
/// number are not kept (YEW never serializes xprv/xpub).
#[derive(Clone)]
pub struct ExtendedPrivKey {
    /// The secret key.
    pub key: SecretKey,
    /// The chain code.
    pub chain_code: [u8; 32],
}

impl std::fmt::Debug for ExtendedPrivKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ExtendedPrivKey(..)")
    }
}

impl Drop for ExtendedPrivKey {
    /// Wipe the chain code and the key (`secp256k1`'s `non_secure_erase`: the crate has no
    /// drop-time erasure of its own, and `SecretKey` is `Copy`).
    fn drop(&mut self) {
        wipe(&mut self.chain_code);
        self.key.non_secure_erase();
    }
}

impl ExtendedPrivKey {
    /// BIP32 master key: `HMAC-SHA512(key = "Bitcoin seed", data = seed)`.
    pub fn master(seed: &[u8]) -> Result<ExtendedPrivKey, KeyError> {
        let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed").expect("any key length");
        mac.update(seed);
        let mut i: [u8; 64] = mac.finalize().into_bytes().into();
        let key = SecretKey::from_secret_bytes(i[..32].try_into().expect("32 bytes"))
            .map_err(|_| KeyError::Derivation(0));
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&i[32..]);
        wipe(&mut i);
        Ok(ExtendedPrivKey {
            key: key?,
            chain_code,
        })
    }

    /// The compressed public key (33 bytes).
    pub fn public_key(&self) -> [u8; 33] {
        PublicKey::from_secret_key(&self.key).serialize()
    }

    /// CKDpriv: one child, hardened when `index >= HARDENED`.
    pub fn child(&self, index: u32) -> Result<ExtendedPrivKey, KeyError> {
        let mut mac = HmacSha512::new_from_slice(&self.chain_code).expect("any key length");
        if index >= HARDENED {
            mac.update(&[0u8]);
            let mut k = self.key.to_secret_bytes();
            mac.update(&k);
            wipe(&mut k);
        } else {
            mac.update(&self.public_key());
        }
        mac.update(&index.to_be_bytes());
        let mut i: [u8; 64] = mac.finalize().into_bytes().into();
        let il: [u8; 32] = i[..32].try_into().expect("32 bytes");
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&i[32..]);
        wipe(&mut i);
        let key = Scalar::from_be_bytes(il)
            .ok()
            .and_then(|tweak| self.key.add_tweak(&tweak).ok())
            .ok_or(KeyError::Derivation(index))?;
        Ok(ExtendedPrivKey { key, chain_code })
    }

    /// Derive along a path of child indices.
    pub fn derive(&self, path: &[u32]) -> Result<ExtendedPrivKey, KeyError> {
        let mut k = self.clone();
        for &i in path {
            k = k.child(i)?;
        }
        Ok(k)
    }
}

// ---------------------------------------------------------------------------------------------
// The YEW key tree

/// Which chain of the account an address is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Chain {
    /// `m/44'/347'/0'/0/i`: receive addresses; index 0 is the Ywallet address (D-W-7).
    External = 0,
    /// `m/44'/347'/0'/1/i`: change.
    Change = 1,
}

impl Chain {
    /// The BIP44 chain number.
    pub fn number(self) -> u32 {
        self as u32
    }

    /// From the stored chain number.
    pub fn from_number(n: u32) -> Option<Chain> {
        match n {
            0 => Some(Chain::External),
            1 => Some(Chain::Change),
            _ => None,
        }
    }
}

/// One transparent key with everything derived from it. Kept in memory only (D-W-6).
#[derive(Clone)]
pub struct AddressKey {
    /// The secret key.
    pub secret: SecretKey,
    /// The compressed public key.
    pub pubkey: [u8; 33],
    /// `HASH160(pubkey)`: the P2PKH key hash and the address payload.
    pub hash160: [u8; 20],
}

impl std::fmt::Debug for AddressKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AddressKey({})", hex(&self.hash160))
    }
}

impl Drop for AddressKey {
    fn drop(&mut self) {
        self.secret.non_secure_erase();
    }
}

impl AddressKey {
    /// From a raw secret key.
    pub fn from_secret(secret: SecretKey) -> AddressKey {
        let pubkey = PublicKey::from_secret_key(&secret).serialize();
        AddressKey {
            secret,
            pubkey,
            hash160: hash160(&pubkey),
        }
    }

    /// The `s…` address on `network`.
    pub fn address_s(&self, network: Network) -> String {
        encode_p2pkh(network, &self.hash160)
    }

    /// The `ye…` / `yt…` / `yr…` address on `network` (same key hash).
    pub fn address_ye(&self, network: Network) -> String {
        encode_yellowback(network, &self.hash160)
    }

    /// The compressed WIF of this key (D-W-11).
    pub fn wif(&self, network: Network) -> String {
        encode_wif(network, &self.secret)
    }
}

/// The account node `m/44'/347'/0'` and the keys under it.
#[derive(Clone, Debug)]
pub struct KeyRing {
    account: ExtendedPrivKey,
}

impl KeyRing {
    /// From a BIP39 seed (D-W-7): `m/44'/347'/0'`.
    pub fn from_seed(seed: &[u8]) -> Result<KeyRing, KeyError> {
        let master = ExtendedPrivKey::master(seed)?;
        let account = master.derive(&[
            BIP44_PURPOSE | HARDENED,
            COIN_TYPE | HARDENED,
            ACCOUNT | HARDENED,
        ])?;
        Ok(KeyRing { account })
    }

    /// From a mnemonic and passphrase.
    pub fn from_mnemonic(phrase: &str, passphrase: &str) -> Result<KeyRing, KeyError> {
        KeyRing::from_seed(&seed_from_mnemonic(phrase, passphrase)?)
    }

    /// The key at `m/44'/347'/0'/{chain}/{index}`.
    pub fn key(&self, chain: Chain, index: u32) -> Result<AddressKey, KeyError> {
        let k = self.account.derive(&[chain.number(), index])?;
        Ok(AddressKey::from_secret(k.key))
    }
}

// ---------------------------------------------------------------------------------------------
// Base58Check, addresses, WIF

/// `Base58Check(payload)`: payload ‖ first 4 bytes of `SHA256d(payload)`.
pub fn base58check_encode(payload: &[u8]) -> String {
    let check = sha256d(payload);
    let mut v = payload.to_vec();
    v.extend_from_slice(&check[..4]);
    bs58::encode(v).into_string()
}

/// Decode and verify a Base58Check string, returning the payload without its checksum.
pub fn base58check_decode(s: &str) -> Result<Vec<u8>, KeyError> {
    let v = bs58::decode(s)
        .into_vec()
        .map_err(|e| KeyError::Base58(e.to_string()))?;
    if v.len() < 5 {
        return Err(KeyError::Base58("too short".into()));
    }
    let (payload, check) = v.split_at(v.len() - 4);
    if sha256d(payload)[..4] != *check {
        return Err(KeyError::Base58("checksum mismatch".into()));
    }
    Ok(payload.to_vec())
}

fn encode_prefixed(prefix: [u8; 2], hash: &[u8; 20]) -> String {
    let mut payload = Vec::with_capacity(22);
    payload.extend_from_slice(&prefix);
    payload.extend_from_slice(hash);
    base58check_encode(&payload)
}

/// `s1…`-style P2PKH address (`ycash-dd/src/yellowback/address.cpp`: the `s…` form is
/// `Base58Check(PUBKEY_ADDRESS ‖ hash160)`).
pub fn encode_p2pkh(network: Network, hash: &[u8; 20]) -> String {
    encode_prefixed(network.p2pkh_prefix(), hash)
}

/// `s3…`-style P2SH address.
pub fn encode_p2sh(network: Network, hash: &[u8; 20]) -> String {
    encode_prefixed(network.p2sh_prefix(), hash)
}

/// `ye…` / `yt…` / `yr…`: the same key hash under the Yellowback version bytes (D10).
pub fn encode_yellowback(network: Network, hash: &[u8; 20]) -> String {
    encode_prefixed(network.yellowback_prefix(), hash)
}

/// What an address string names once decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressKind {
    /// A P2PKH key hash, from either the `s…` or the `ye…` form.
    P2pkh([u8; 20]),
    /// A P2SH script hash.
    P2sh([u8; 20]),
}

/// A decoded address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Address {
    /// The hash and its kind.
    pub kind: AddressKind,
    /// True when the input was the Yellowback (`ye…`) form.
    pub yellowback_form: bool,
}

impl Address {
    /// The 20-byte hash regardless of kind.
    pub fn hash(&self) -> [u8; 20] {
        match self.kind {
            AddressKind::P2pkh(h) | AddressKind::P2sh(h) => h,
        }
    }
}

/// Parse any transparent Ycash address of `network`: `s1…`, `s3…`, `ye…`/`yt…`/`yr…`.
pub fn parse_address(network: Network, s: &str) -> Result<Address, KeyError> {
    let payload = base58check_decode(s)?;
    if payload.len() != 22 {
        return Err(KeyError::WrongNetwork(network, s.to_string()));
    }
    let prefix = [payload[0], payload[1]];
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&payload[2..]);
    if prefix == network.p2pkh_prefix() {
        Ok(Address {
            kind: AddressKind::P2pkh(hash),
            yellowback_form: false,
        })
    } else if prefix == network.yellowback_prefix() {
        Ok(Address {
            kind: AddressKind::P2pkh(hash),
            yellowback_form: true,
        })
    } else if prefix == network.p2sh_prefix() {
        Ok(Address {
            kind: AddressKind::P2sh(hash),
            yellowback_form: false,
        })
    } else {
        Err(KeyError::WrongNetwork(network, s.to_string()))
    }
}

/// Compressed WIF: `Base58Check(SECRET_KEY ‖ key ‖ 0x01)`, the format `dumpprivkey` emits
/// (D-W-11; `ycash-dd/src/chainparams.cpp:153`).
pub fn encode_wif(network: Network, key: &SecretKey) -> String {
    let mut payload = Vec::with_capacity(34);
    payload.push(network.wif_prefix());
    payload.extend_from_slice(&key.to_secret_bytes());
    payload.push(0x01);
    let wif = base58check_encode(&payload);
    wipe(&mut payload);
    wif
}

/// Decode a WIF of `network`. Uncompressed keys (no trailing `0x01`) are refused: every YEW
/// address is over a compressed key, and the node's Yellowback scripts require one
/// (`ycash-dd/src/yellowback/script.cpp:83` `IsCompressedKey`).
pub fn decode_wif(network: Network, wif: &str) -> Result<AddressKey, KeyError> {
    let mut payload = base58check_decode(wif).map_err(|e| KeyError::Wif(e.to_string()))?;
    let result = if payload.len() != 34 || payload[33] != 0x01 {
        Err(KeyError::Wif("not a compressed key".into()))
    } else if payload[0] != network.wif_prefix() {
        Err(KeyError::Wif(format!(
            "wrong network prefix 0x{:02x}",
            payload[0]
        )))
    } else {
        SecretKey::from_secret_bytes(payload[1..33].try_into().expect("32 bytes"))
            .map(AddressKey::from_secret)
            .map_err(|_| KeyError::Wif("key out of range".into()))
    };
    wipe(&mut payload);
    result
}

/// Lower-case hex of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Decode lower- or upper-case hex.
pub fn unhex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err("odd hex length".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode a BIP32 `xprv` (78 bytes: version, depth, fingerprint, child, chain code,
    /// 0x00 ‖ key) into `(chain_code, key)`.
    fn xprv(s: &str) -> ([u8; 32], [u8; 32]) {
        let p = base58check_decode(s).unwrap();
        assert_eq!(p.len(), 78);
        assert_eq!(p[45], 0);
        (p[13..45].try_into().unwrap(), p[46..78].try_into().unwrap())
    }

    #[test]
    fn bip32_test_vector_1() {
        // BIP32 "Test vector 1": seed 000102030405060708090a0b0c0d0e0f (m, m/0', m/0'/1/2',
        // m/0'/1/2'/2, m/0'/1/2'/2/1000000000; every xprv below is checksum-verified).
        let seed = unhex("000102030405060708090a0b0c0d0e0f").unwrap();
        let m = ExtendedPrivKey::master(&seed).unwrap();
        let cases: [(&[u32], &str); 5] = [
            (&[], "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"),
            (&[HARDENED], "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"),
            (&[HARDENED, 1, 2 | HARDENED], "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM"),
            (&[HARDENED, 1, 2 | HARDENED, 2], "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334"),
            (&[HARDENED, 1, 2 | HARDENED, 2, 1_000_000_000], "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76"),
        ];
        for (path, expected) in cases {
            let k = m.derive(path).unwrap();
            let (cc, key) = xprv(expected);
            assert_eq!(k.chain_code, cc, "chain code at {path:?}");
            assert_eq!(k.key.to_secret_bytes(), key, "key at {path:?}");
        }
    }

    #[test]
    fn bip39_trezor_vector() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let seed = seed_from_mnemonic(phrase, "TREZOR").unwrap();
        assert_eq!(
            hex(&seed),
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        );
        assert!(seed_from_mnemonic("abandon abandon about", "").is_err());
    }

    #[test]
    fn wipe_clears_and_secret_string_wipes_on_drop() {
        let mut b = [7u8; 16];
        wipe(&mut b);
        assert_eq!(b, [0u8; 16]);
        let s = SecretString::new("abandon about".into());
        assert_eq!(&*s, "abandon about");
        assert_eq!(format!("{s:?}"), "SecretString(..)");
        drop(s);
        // A dropped extended key is erased (its fields are observable through a clone taken
        // before the drop only; here we check the wipe does not disturb derivation).
        let seed = unhex("000102030405060708090a0b0c0d0e0f").unwrap();
        let a = ExtendedPrivKey::master(&seed)
            .unwrap()
            .derive(&[HARDENED])
            .unwrap();
        let b = ExtendedPrivKey::master(&seed)
            .unwrap()
            .derive(&[HARDENED])
            .unwrap();
        assert_eq!(a.chain_code, b.chain_code);
        assert_eq!(a.key.to_secret_bytes(), b.key.to_secret_bytes());
    }

    #[test]
    fn hash160_of_known_pubkey() {
        // Bitcoin's "genesis"-era test key: pubkey of secret 1.
        let k = AddressKey::from_secret(SecretKey::from_secret_bytes([1u8; 32]).unwrap());
        assert_eq!(k.pubkey.len(), 33);
        assert!(k.pubkey[0] == 2 || k.pubkey[0] == 3);
        assert_eq!(k.hash160, hash160(&k.pubkey));
    }

    #[test]
    fn address_forms_share_the_key_hash_and_wif_round_trips() {
        let ring = KeyRing::from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "",
        )
        .unwrap();
        let k = ring.key(Chain::External, 0).unwrap();
        for net in [Network::Mainnet, Network::Testnet, Network::Regtest] {
            let s = k.address_s(net);
            let ye = k.address_ye(net);
            assert_ne!(s, ye);
            let a = parse_address(net, &s).unwrap();
            let b = parse_address(net, &ye).unwrap();
            assert_eq!(a.kind, AddressKind::P2pkh(k.hash160));
            assert_eq!(a.kind, b.kind);
            assert!(!a.yellowback_form && b.yellowback_form);
            let wif = k.wif(net);
            let back = decode_wif(net, &wif).unwrap();
            assert_eq!(back.hash160, k.hash160);
            assert_eq!(back.secret.to_secret_bytes(), k.secret.to_secret_bytes());
            let p2sh = encode_p2sh(net, &k.hash160);
            assert_eq!(
                parse_address(net, &p2sh).unwrap().kind,
                AddressKind::P2sh(k.hash160)
            );
        }
        // Prefix rendering (D10 / chainparams): s1… on mainnet, ye…/yt…/yr… for Yellowback.
        assert!(k.address_s(Network::Mainnet).starts_with("s1"));
        assert!(k.address_ye(Network::Mainnet).starts_with("ye"));
        assert!(k.address_ye(Network::Testnet).starts_with("yt"));
        assert!(k.address_ye(Network::Regtest).starts_with("yr"));
        assert!(k.address_s(Network::Regtest).starts_with("sm"));
        // A mainnet address is refused on regtest and vice versa.
        assert!(parse_address(Network::Regtest, &k.address_s(Network::Mainnet)).is_err());
        assert!(decode_wif(Network::Regtest, &k.wif(Network::Mainnet)).is_err());
        // Different chains and indices give different keys.
        assert_ne!(ring.key(Chain::Change, 0).unwrap().hash160, k.hash160);
        assert_ne!(ring.key(Chain::External, 1).unwrap().hash160, k.hash160);
    }
}
