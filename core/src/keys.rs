// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! Keys and addresses: BIP39 mnemonic → seed, BIP32 secp256k1 derivation (implemented here over
//! `hmac`/`sha2`, no extra crate), BIP44 paths compatible with Ywallet (D-W-7), compressed
//! public keys, HASH160, address encoding (`s…` / `yb…` / `yt…` / `yr…`), WIF export and
//! import (D-W-11).
//!
//! Translation source (plan §3.6): `ycash-dd/src/yellowback/address.cpp` for the `s…` ↔ `yb…`
//! encoding (same key hash; version bytes from `params.cpp`, see [`crate::params::Network`]).
//! Derivation: Ywallet `zcash-sync/src/zip32.rs` `derive_zip32` at `m/44'/347'/0'/0/0`.
//!
//! **Seed scope** (yew-shielded plan S0-1, 2026-10-04). The same BIP39 seed derives two key
//! trees: the transparent keys here at `m/44'/347'/0'/{0,1}/i` (BIP44, secp256k1) and the
//! Ycash Sapling keys of [`crate::shielded_keys`] at `m/32'/347'/0'` (ZIP-32). Both are the
//! paths Ywallet derives for a Ycash account, so one seed backup restores both pools, in YEW and
//! in Ywallet. This reverses wallet-plan D-W-7's "no ZIP-32 keys, ever".

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
    /// A post-quantum (53-character) `yb…`/`yt…`/`yr…` address where a YEC address was
    /// expected, or an SLH-DSA one where a YED address was: it names a vault owner (or, after
    /// Falcon, a YED holder), never a YEC destination (client survey C-10).
    #[error("{0} is a post-quantum vault-owner address, not a payment address")]
    PqOwnerAddress(String),
    /// A post-quantum plain-YEC address (`sq…`/`tq…`/`rq…`, D-Q-20) where a YED address or a
    /// 20-byte key hash was expected: it receives YEC (a `TX_PQPKH` output), never YED.
    #[error("{0} is a post-quantum YEC address (sq…): it receives YEC, not YED")]
    PqYecAddress(String),
    /// A post-quantum Falcon YED address (53-character `yb…`/`yt…`/`yr…`) given as a YEC
    /// destination: D-Q-20 gives plain YEC its own prefix (`sq…`), and the node's `key_io`
    /// decodes only that one (`sendtoaddress` refuses the YED form), so YEW refuses it too.
    #[error("{0} is a post-quantum YED address (yb…); to send YEC to the same wallet, ask for its sq… address")]
    PqYedAddress(String),
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

    /// The `yb…` / `yt…` / `yr…` address on `network` (same key hash).
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

/// `yb…` / `yt…` / `yr…`: the same key hash under the Yellowback version bytes (D10).
pub fn encode_yellowback(network: Network, hash: &[u8; 20]) -> String {
    encode_prefixed(network.yellowback_prefix(), hash)
}

/// `Base58Check(version ‖ keyHash)` under `version(scheme)` (D-9: the 3-byte version names the
/// network, the coin and the scheme). `None` for a scheme outside the registry.
fn encode_pq(id: &crate::pq::PqKeyId, version: impl Fn(u8) -> Option<[u8; 3]>) -> Option<String> {
    if !id.is_known() {
        return None;
    }
    let mut payload = Vec::with_capacity(35);
    payload.extend_from_slice(&version(id.scheme)?);
    payload.extend_from_slice(&id.hash);
    Some(base58check_encode(&payload))
}

/// The inverse of [`encode_pq`]: 35 payload bytes whose first three are `version(s)` for a
/// registered scheme `s` (one table for both directions). Any other version, length or scheme
/// is refused, the pre-D-9 form (`version2 ‖ scheme ‖ keyHash`) among them.
fn decode_pq(
    payload: &[u8],
    version: impl Fn(u8) -> Option<[u8; 3]>,
) -> Option<crate::pq::PqKeyId> {
    if payload.len() != 35 {
        return None;
    }
    for scheme in [
        crate::pq::SCHEME_SLH_DSA_SHA2_128S,
        crate::pq::SCHEME_FN_DSA_512,
    ] {
        if version(scheme).is_some_and(|v| payload[..3] == v) {
            let id = crate::pq::PqKeyId {
                scheme,
                hash: payload[3..].try_into().ok()?,
            };
            return id.is_known().then_some(id);
        }
    }
    None
}

/// The post-quantum Yellowback address of a `CPQKeyID` (quantum spec §4, D-9):
/// `Base58Check(version ‖ keyHash)`, `ybf…`/`ybs…` (test `ytf…`/`yts…`, regtest `yrf…`/`yrs…`),
/// 53 characters (`yellowback::EncodeAddress(const CPQKeyID&)`). `None` for a scheme outside the
/// registry (the node returns "").
pub fn encode_pq_yellowback(network: Network, id: &crate::pq::PqKeyId) -> Option<String> {
    encode_pq(id, |s| network.pq_yellowback_version(s))
}

/// Decode a post-quantum Yellowback address of `network` (`yellowback::DecodeAddress(…,
/// CPQKeyID&)`): 35 payload bytes under one of the network's two PQ versions.
pub fn parse_pq_address(network: Network, s: &str) -> Result<crate::pq::PqKeyId, KeyError> {
    let payload = base58check_decode(s)?;
    decode_pq(&payload, |sc| network.pq_yellowback_version(sc))
        .ok_or_else(|| KeyError::WrongNetwork(network, s.to_string()))
}

/// The post-quantum plain-YEC address of a `CPQKeyID` (D-Q-20, D-9): `Base58Check(version ‖
/// keyHash)`, `sqf…`/`sqs…` (test `tqf…`/`tqs…`, regtest `rqf…`/`rqs…`), 53 characters. `None`
/// for an unregistered scheme.
pub fn encode_pq_yec(network: Network, id: &crate::pq::PqKeyId) -> Option<String> {
    encode_pq(id, |s| network.pq_yec_version(s))
}

/// Decode a post-quantum plain-YEC address of `network` (D-Q-20, D-9): 35 payload bytes under one
/// of the network's two plain PQ versions.
pub fn parse_pq_yec_address(network: Network, s: &str) -> Result<crate::pq::PqKeyId, KeyError> {
    let payload = base58check_decode(s)?;
    decode_pq(&payload, |sc| network.pq_yec_version(sc))
        .ok_or_else(|| KeyError::WrongNetwork(network, s.to_string()))
}

/// The pre-D-9 form (`version2 ‖ scheme ‖ keyHash`: plain YEC `sq…`/`tq…`/`rq…` + a digit when
/// `yed` is false, the 53-character `yb…`/`yt…`/`yr…` when true) of `network`, a registered scheme.
/// Never an address: only for rewriting a record written before D-9 and for checking a key-dump
/// line from before it (the node's `DecodeLegacyPQAddress`, used for exactly those two).
pub fn parse_legacy_pq_address(network: Network, s: &str, yed: bool) -> Option<crate::pq::PqKeyId> {
    let payload = base58check_decode(s).ok()?;
    let (y, plain) = network.legacy_pq_versions();
    let ver = if yed { y } else { plain };
    if payload.len() != 35 || payload[..2] != ver {
        return None;
    }
    crate::pq::PqKeyId::from_bytes(&payload[2..]).filter(|id| id.is_known())
}

/// The scheme's display name (`"SLH-DSA-SHA2-128s"`, `"FN-DSA-512"`), the names the node's
/// balance and listing calls use (beta2 D-9 / W1.5). `None` outside the registry.
pub fn pq_scheme_name(scheme: u8) -> Option<&'static str> {
    match scheme {
        crate::pq::SCHEME_SLH_DSA_SHA2_128S => Some("SLH-DSA-SHA2-128s"),
        crate::pq::SCHEME_FN_DSA_512 => Some("FN-DSA-512"),
        _ => None,
    }
}

/// A YED destination (`yed_send`'s address argument, rpcversion 7: "either address form").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum YedDestination {
    /// A P2PKH holder (`yb…`/`yt…`/`yr…` 35 characters, or the `s…` form of the same key).
    P2pkh([u8; 20]),
    /// A post-quantum holder (`TX_PQPKH`, the 53-character form). Which scheme may receive YED
    /// is the builder's decision (TOK-PQ after Falcon: scheme 2 only).
    Pq(crate::pq::PqKeyId),
}

/// Parse a YED destination of `network`: the 20-byte forms of [`parse_address`] (a P2SH address
/// is refused: YED goes to a key) or a 53-character post-quantum Yellowback address. A
/// post-quantum YEC address (`sq…`) is refused with [`KeyError::PqYecAddress`].
pub fn parse_yed_destination(network: Network, s: &str) -> Result<YedDestination, KeyError> {
    if let Ok(id) = parse_pq_address(network, s) {
        return Ok(YedDestination::Pq(id));
    }
    match parse_address(network, s)?.kind {
        AddressKind::P2pkh(h) => Ok(YedDestination::P2pkh(h)),
        AddressKind::P2sh(_) => Err(KeyError::WrongNetwork(network, s.to_string())),
    }
}

/// A YEC destination (the Send screen's YEC address, `build_yec_send`): a 20-byte transparent
/// address of [`parse_address`], or a post-quantum plain-YEC address (`sq…`/`tq…`/`rq…`, D-Q-20,
/// either scheme: the node's `key_io` decodes both), which is paid a `TX_PQPKH` output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum YecDestination {
    /// `s1…` (or the 35-character `yb…` form of the same key).
    P2pkh([u8; 20]),
    /// `s3…`.
    P2sh([u8; 20]),
    /// `sq…`/`tq…`/`rq…`.
    Pq(crate::pq::PqKeyId),
}

impl YecDestination {
    /// The output script that pays it.
    pub fn script(&self) -> Vec<u8> {
        match self {
            YecDestination::P2pkh(h) => crate::script::p2pkh_script(h),
            YecDestination::P2sh(h) => crate::script::p2sh_script(h),
            YecDestination::Pq(id) => {
                crate::pq::pqpkh_script(id).expect("a parsed PQ address has a registered scheme")
            }
        }
    }
}

/// Parse a YEC destination of `network` (D-Q-20/D-Q-21, `docs/plans/yellowback-quantum-clients.md`
/// C-10): `s1…`, `s3…`, the 35-character `yb…` form, or a post-quantum `sq…`/`tq…`/`rq…`. A
/// 53-character post-quantum `yb…`/`yt…`/`yr…` is refused: a Falcon one names a YED holder
/// ([`KeyError::PqYedAddress`]; YEC goes to its `sq…` form), an SLH-DSA one a vault owner
/// ([`KeyError::PqOwnerAddress`]), and the node's `sendtoaddress` refuses both.
pub fn parse_yec_destination(network: Network, s: &str) -> Result<YecDestination, KeyError> {
    if let Ok(id) = parse_pq_yec_address(network, s) {
        return Ok(YecDestination::Pq(id));
    }
    if let Ok(id) = parse_pq_address(network, s) {
        return Err(if id.scheme == crate::pq::SCHEME_FN_DSA_512 {
            KeyError::PqYedAddress(s.to_string())
        } else {
            KeyError::PqOwnerAddress(s.to_string())
        });
    }
    Ok(match parse_address(network, s)?.kind {
        AddressKind::P2pkh(h) => YecDestination::P2pkh(h),
        AddressKind::P2sh(h) => YecDestination::P2sh(h),
    })
}

/// What an address string names once decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressKind {
    /// A P2PKH key hash, from either the `s…` or the `yb…` form.
    P2pkh([u8; 20]),
    /// A P2SH script hash.
    P2sh([u8; 20]),
}

/// A decoded address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Address {
    /// The hash and its kind.
    pub kind: AddressKind,
    /// True when the input was the Yellowback (`yb…`) form.
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

/// Parse any 20-byte transparent Ycash address of `network`: `s1…`, `s3…`, `yb…`/`yt…`/`yr…`
/// (the callers need a key or script hash: mint payees, change rows, YED holders). A
/// post-quantum owner address ([`parse_pq_address`]) is refused with
/// [`KeyError::PqOwnerAddress`]; a post-quantum YEC address ([`parse_pq_yec_address`]) with
/// [`KeyError::PqYecAddress`]. A YEC send takes those through [`parse_yec_destination`].
pub fn parse_address(network: Network, s: &str) -> Result<Address, KeyError> {
    let payload = base58check_decode(s)?;
    if payload.len() != 22 {
        if parse_pq_address(network, s).is_ok() {
            return Err(KeyError::PqOwnerAddress(s.to_string()));
        }
        if parse_pq_yec_address(network, s).is_ok() {
            return Err(KeyError::PqYecAddress(s.to_string()));
        }
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
        // Prefix rendering (D10 / chainparams): s1… on mainnet, yb…/yt…/yr… for Yellowback.
        assert!(k.address_s(Network::Mainnet).starts_with("s1"));
        assert!(k.address_ye(Network::Mainnet).starts_with("yb"));
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
    /// Quantum spec §4, D-9 and ycash6 `pq_standard_tests.cpp` `pq_yellowback_address`: 53
    /// characters, the scheme in the prefix (`ybf`/`ybs`, `ytf`/`yts`, `yrf`/`yrs`), round trip,
    /// another network and the 20-byte decoder refuse it, an unregistered scheme neither encodes
    /// nor decodes, and the pre-D-9 form (`version2 ‖ scheme ‖ keyHash`) is no address.
    #[test]
    fn pq_yellowback_addresses() {
        use crate::pq::PqKeyId;
        for scheme in [1u8, 2] {
            let tag = if scheme == 2 { "f" } else { "s" };
            for fill in [0x00u8, 0x5a, 0xff] {
                let id = PqKeyId {
                    scheme,
                    hash: [fill; 32],
                };
                for (net, p) in [
                    (Network::Mainnet, "yb"),
                    (Network::Testnet, "yt"),
                    (Network::Regtest, "yr"),
                ] {
                    let a = encode_pq_yellowback(net, &id).unwrap();
                    assert_eq!(a.len(), 53);
                    assert!(a.starts_with(&format!("{p}{tag}")), "{a}");
                    assert_eq!(parse_pq_address(net, &a).unwrap(), id);
                    assert!(matches!(
                        parse_address(net, &a),
                        Err(KeyError::PqOwnerAddress(_))
                    ));
                    // the pre-D-9 form of the same key is refused everywhere
                    let mut old = net.legacy_pq_versions().0.to_vec();
                    old.extend_from_slice(&id.to_bytes());
                    let old = base58check_encode(&old);
                    assert!(parse_pq_address(net, &old).is_err());
                    assert!(parse_yed_destination(net, &old).is_err());
                    assert!(parse_yec_destination(net, &old).is_err());
                    assert_eq!(parse_legacy_pq_address(net, &old, true), Some(id));
                    assert_eq!(parse_legacy_pq_address(net, &old, false), None);
                }
                let m = encode_pq_yellowback(Network::Mainnet, &id).unwrap();
                assert!(parse_pq_address(Network::Testnet, &m).is_err());
                let r = encode_pq_yellowback(Network::Regtest, &id).unwrap();
                assert!(parse_pq_address(Network::Mainnet, &r).is_err());
            }
        }
        let bad = PqKeyId {
            scheme: 3,
            hash: [1; 32],
        };
        assert_eq!(encode_pq_yellowback(Network::Mainnet, &bad), None);
        assert_eq!(Network::Mainnet.pq_yellowback_version(3), None);
        assert_eq!(Network::Mainnet.pq_yec_version(0), None);
        // the 20-byte form still parses as before, and a PQ decoder refuses it
        let h = [0x33u8; 20];
        let ye = encode_yellowback(Network::Mainnet, &h);
        assert_eq!(ye.len(), 35);
        assert_eq!(
            parse_address(Network::Mainnet, &ye).unwrap().kind,
            AddressKind::P2pkh(h)
        );
        assert!(parse_pq_address(Network::Mainnet, &ye).is_err());
    }

    /// The shared D-9 vectors (`ycash6` `src/test/data/pq_address_vectors.json`, branch
    /// `up/b2-pq-prefix`, copied byte for byte; sha256
    /// `dbbd1da05d995d659e1e9f8a671197e141c272998722d6cca85cdbdb52b61797`): every valid address
    /// encodes from and decodes to its (scheme, keyhash) on its own network and coin only, its
    /// 3-byte version is the table's, and every invalid one (old form, unknown version, truncated,
    /// extended, bad checksum) is refused on every network and coin.
    #[test]
    fn pq_address_shared_vectors() {
        use crate::pq::PqKeyId;
        let doc: serde_json::Value =
            serde_json::from_str(include_str!("../tests/vectors/pq_address_vectors.json")).unwrap();
        assert_eq!(doc["format"], "ycash-pq-address-vectors-1");
        let net_of = |s: &str| match s {
            "main" => Network::Mainnet,
            "test" => Network::Testnet,
            "regtest" => Network::Regtest,
            other => panic!("network {other}"),
        };
        let nets = [Network::Mainnet, Network::Testnet, Network::Regtest];
        let parse = |net: Network, yed: bool, a: &str| {
            if yed {
                parse_pq_address(net, a).ok()
            } else {
                parse_pq_yec_address(net, a).ok()
            }
        };
        let valid = doc["valid"].as_array().unwrap();
        assert_eq!(valid.len(), 72);
        for v in valid {
            let net = net_of(v["network"].as_str().unwrap());
            let yed = match v["coin"].as_str().unwrap() {
                "yed" => true,
                "yec" => false,
                c => panic!("coin {c}"),
            };
            let scheme = v["scheme"].as_u64().unwrap() as u8;
            let id = PqKeyId {
                scheme,
                hash: unhex(v["keyhash"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
            };
            let a = v["address"].as_str().unwrap();
            let ver = if yed {
                net.pq_yellowback_version(scheme)
            } else {
                net.pq_yec_version(scheme)
            };
            assert_eq!(hex(&ver.unwrap()), v["version"].as_str().unwrap(), "{a}");
            let enc = if yed {
                encode_pq_yellowback(net, &id)
            } else {
                encode_pq_yec(net, &id)
            };
            assert_eq!(enc.as_deref(), Some(a));
            assert_eq!(a.len(), 53);
            for n in nets {
                for c in [true, false] {
                    let want = (n == net && c == yed).then_some(id);
                    assert_eq!(parse(n, c, a), want, "{a} on {n:?} yed={c}");
                }
            }
        }
        let invalid = doc["invalid"].as_array().unwrap();
        assert_eq!(invalid.len(), 60);
        for v in invalid {
            let a = v["address"].as_str().unwrap();
            for n in nets {
                for c in [true, false] {
                    assert_eq!(parse(n, c, a), None, "{a} ({})", v["reason"]);
                }
                assert!(parse_yec_destination(n, a).is_err(), "{a}");
                assert!(parse_yed_destination(n, a).is_err(), "{a}");
            }
        }
    }

    /// Owner decision D-Q-21: the mainnet YED prefix is `yb…` on this line (20-byte 0x1FDD);
    /// D-Q-20/D-9: plain-YEC PQ addresses `sqf…`/`sqs…` (test `tq…`, regtest `rq…`), recognised
    /// and refused as YED destinations and 20-byte addresses.
    #[test]
    fn yb_prefix_and_sq_addresses() {
        use crate::pq::PqKeyId;
        assert_eq!(
            encode_yellowback(Network::Mainnet, &[0; 20]),
            "ybCxAdkN4XYouwZHde9wgVkDDujbS9ByGQz"
        );
        assert_eq!(
            encode_yellowback(Network::Mainnet, &[0xff; 20]),
            "ybcHmcrfMEjGnkzRifaGzysV1YErNnEcqyf"
        );
        for (net, p) in [
            (Network::Mainnet, "sq"),
            (Network::Testnet, "tq"),
            (Network::Regtest, "rq"),
        ] {
            for scheme in [1u8, 2] {
                let id = PqKeyId {
                    scheme,
                    hash: [0x42; 32],
                };
                let a = encode_pq_yec(net, &id).unwrap();
                assert_eq!(a.len(), 53);
                let tag = if scheme == 2 { "f" } else { "s" };
                assert!(a.starts_with(&format!("{p}{tag}")), "{a}");
                assert_eq!(parse_pq_yec_address(net, &a).unwrap(), id);
                assert!(matches!(
                    parse_address(net, &a),
                    Err(KeyError::PqYecAddress(_))
                ));
                assert!(parse_pq_address(net, &a).is_err());
                assert!(parse_yed_destination(net, &a).is_err());
                // the YED PQ form is a YED destination, never a YEC one
                let y = encode_pq_yellowback(net, &id).unwrap();
                assert_eq!(
                    parse_yed_destination(net, &y).unwrap(),
                    YedDestination::Pq(id)
                );
                assert!(parse_pq_yec_address(net, &y).is_err());
                // the pre-D-9 plain form is no address; only the record rewrite reads it
                let mut old = net.legacy_pq_versions().1.to_vec();
                old.extend_from_slice(&id.to_bytes());
                let old = base58check_encode(&old);
                assert!(parse_pq_yec_address(net, &old).is_err());
                assert_eq!(parse_legacy_pq_address(net, &old, false), Some(id));
                assert_eq!(parse_legacy_pq_address(net, &a, false), None);
            }
        }
        assert_eq!(
            encode_pq_yec(
                Network::Mainnet,
                &PqKeyId {
                    scheme: 3,
                    hash: [0; 32]
                }
            ),
            None
        );
        let h = [7u8; 20];
        for a in [
            encode_yellowback(Network::Regtest, &h),
            encode_p2pkh(Network::Regtest, &h),
        ] {
            assert_eq!(
                parse_yed_destination(Network::Regtest, &a).unwrap(),
                YedDestination::P2pkh(h)
            );
        }
        assert!(
            parse_yed_destination(Network::Regtest, &encode_p2sh(Network::Regtest, &h)).is_err()
        );
        // the pre-D-Q-21 mainnet `ye…` form is no address of this line
        let mut old = vec![0x1F, 0xE4];
        old.extend_from_slice(&h);
        assert!(parse_address(Network::Mainnet, &base58check_encode(&old)).is_err());
        assert_eq!(pq_scheme_name(1), Some("SLH-DSA-SHA2-128s"));
        assert_eq!(pq_scheme_name(2), Some("FN-DSA-512"));
        assert_eq!(pq_scheme_name(3), None);
    }

    /// YEC destinations (D-Q-20/D-Q-21/D-9, clients C-10): `sqf…`/`sqs…` (test `tq…`, regtest
    /// `rq…`) pays a `TX_PQPKH`; a 53-character `ybf…`/`ybs…` (`yt…`, `yr…`) is refused (Falcon: a
    /// YED holder whose YEC form is `sqf…`; SLH-DSA: a vault owner); the 20-byte forms parse as
    /// before. Keys: the node's `pq_standard_tests` mainnet known answers (scheme 1|2, keyHash
    /// 32×0x5a) and a regtest node's `vault_getnewowner` / `validateaddress` pairs (lightwalletd-dd
    /// q/pqaddr f33fb1e `pqPlainVectors`); their D-9 forms computed with an independent
    /// Base58Check (the workspace venv's Python). The pre-D-9 strings of the same keys are refused.
    #[test]
    fn yec_destinations() {
        for (net, yed, plain, scheme, old) in [
            (
                Network::Mainnet,
                "ybs2yeQAU6HatHuTWtMW3GUy4Aa3MXFt8eXxkjSEHZqHM2zHYK76X",
                "sqs34vhLJ1Z48caj6wiH9djY5eGjoq4NiLuf9M1cew8STzJkZtyAr",
                1u8,
                "sq4couNBfnJoRxqXF89SWjiPh5wktFi5bb5S4F89xMMsCrqRf2L4z",
            ),
            (
                Network::Mainnet,
                "ybf359F9nfDGmDdmUPoyqZ2AQvjCtSXnTAq9QC6c2dxgxCKgiEFio",
                "sqf3ARYKcaUk1YK34TAkwvGjSQRuLkLH2sCqnofzQ1Fr59eA2Past",
                2,
                "sq4ekeYR7pAE7ByLpq428jfiHrrsVyMnSTs58MNJeFMXDFL63vTbT",
            ),
            (
                Network::Testnet,
                "yts3cWRxwavSApiaENwJKqRS5JDs4ANysrbpKvo5R6yr4fBm15dEx",
                "tqs34gfTMJi8EMG9RYTBFgzMbTptT9kTNYcGixCaDEadcWRpg4MCp",
                1,
                "tq3uz2dSJQZwKwgiMurAaowUceGWbVkNZQFd9bBy4pwJDEbVRn79A",
            ),
            (
                Network::Regtest,
                "yrs2wCox3ZNcy8vFFh8wejMoNVDfSRKfdjwrp3q4fipDxaJRZPzW3",
                "rqs453qxBF36FCu5fMdq9iVHY25HYqrsBUjqEZTDkkwEN1jMu8gmf",
                1,
                "rq5LdfDfyggmkJz71M7AYoVsjiyhZMAMm7S2diguW13RF2d8n2Rc6",
            ),
            (
                Network::Regtest,
                "yrf1yW8ubn3p8Wf9XWuksXcZs562YHJTTjqdnLuWym3qJQ8SeGH2b",
                "rqf37MAujTiHQadywBQeNWk42bweehqf1UdcCrXg4oAqhqZQhCebM",
                2,
                "rq5MXCssfNHhhz8WuNL5bKAmUKc1k1Wx7TpG2fM8ks9Gz5cPeCqKa",
            ),
        ] {
            let id = parse_pq_address(net, yed).unwrap();
            assert_eq!(id.scheme, scheme);
            if net == Network::Mainnet {
                assert_eq!(id.hash, [0x5a; 32]);
            }
            assert_eq!(encode_pq_yec(net, &id).unwrap(), plain);
            assert_eq!(parse_pq_yec_address(net, plain).unwrap(), id);
            assert_eq!(parse_legacy_pq_address(net, old, false), Some(id));
            assert!(parse_yec_destination(net, old).is_err());
            let d = parse_yec_destination(net, plain).unwrap();
            assert_eq!(d, YecDestination::Pq(id));
            let script = d.script();
            assert_eq!(script.len(), 35);
            assert_eq!(
                (script[0], script[33], script[34]),
                (0x20, 0x50 + id.scheme, 0xc2)
            );
            assert_eq!(crate::pq::pqpkh_of(&script), Some(id));
            match parse_yec_destination(net, yed) {
                Err(KeyError::PqYedAddress(a)) => {
                    assert_eq!(id.scheme, 2);
                    assert_eq!(a, yed);
                }
                Err(KeyError::PqOwnerAddress(_)) => assert_eq!(id.scheme, 1),
                other => panic!("{yed} as a YEC destination: {other:?}"),
            }
            // another network's form is refused
            let other = if net == Network::Mainnet {
                Network::Regtest
            } else {
                Network::Mainnet
            };
            assert!(parse_yec_destination(other, plain).is_err());
        }
        // the 20-byte forms, unchanged
        let h = [9u8; 20];
        for net in [Network::Mainnet, Network::Testnet, Network::Regtest] {
            assert_eq!(
                parse_yec_destination(net, &encode_p2pkh(net, &h)).unwrap(),
                YecDestination::P2pkh(h)
            );
            assert_eq!(
                parse_yec_destination(net, &encode_yellowback(net, &h)).unwrap(),
                YecDestination::P2pkh(h)
            );
            assert_eq!(
                parse_yec_destination(net, &encode_p2sh(net, &h)).unwrap(),
                YecDestination::P2sh(h)
            );
        }
        // a bad checksum: not a destination
        assert!(parse_yec_destination(
            Network::Regtest,
            "rqf37MAujTiHQadywBQeNWk42bweehqf1UdcCrXg4oAqhqZQhCebN"
        )
        .is_err());
    }
}
