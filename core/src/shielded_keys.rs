// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! Sapling keys of the Ycash shielded pool (yew-shielded plan S0-1): from the BIP39 seed YEW
//! already holds, the ZIP-32 extended spending key of account 0 at `m/32'/347'/0'` (coin type
//! 347 = Ycash, [`crate::params::COIN_TYPE`]), its extended full viewing key, the default
//! payment address and the diversified addresses, encoded for one Ycash network
//! (`ys1…` / `ytestsapling1…` / `yregtestsapling1…`, `secret-extended-key-main…`, `zxviews…`;
//! HRPs in [`crate::params::Network`], from `ycash-dd/src/chainparams.cpp`).
//!
//! **Seed scope.** One seed, two pools: the transparent keys of [`crate::keys`] live under
//! `m/44'/347'/0'` (BIP44) and the Sapling keys here under `m/32'/347'/0'` (ZIP-32), both over
//! the same 64-byte BIP39 seed (`keys::seed_from_mnemonic`). Both paths are what Ywallet derives
//! for a Ycash account, so a seed written down from either wallet restores both pools in the
//! other. Ywallet (`zcash-sync/src/key2.rs` `derive_secret_key`): `ExtendedSpendingKey::master
//! (seed)` then `[Hardened(32), Hardened(coin_type()), Hardened(index)]`, `index = 0` for the
//! first account, `coin_type() = 347` on every network (`librustzcash/zcash_primitives/src/
//! consensus/ycash.rs`), the address `fvk.default_address()` under HRP `"ys"`. The node's own
//! HD wallet (`ycash-dd/src/wallet/wallet.cpp:150-156`) takes the same path on mainnet; on
//! testnet and regtest it uses coin type 1, so there `z_getnewaddress` and YEW disagree by
//! design (D-W-7: seed portability is defined against Ywallet). One account only.
//!
//! **Not a Ycash reimplementation.** Derivation and curve arithmetic are the `sapling-crypto`
//! crate (ZIP-32 `ExtendedSpendingKey`), at the exact version boyfromcave/librustzcash6 — the
//! Ycash-aware librustzcash ycashd 6.21.0 pins — locks; `zcash_keys::keys::sapling::
//! spending_key` there is the three-line path walk [`SaplingAccount::from_seed`] repeats.
//! `zcash_keys` itself is not linked yet (its `zcash_transparent` pins a `ripemd` pre-release
//! YEW's `ripemd 0.2.0` cannot sit beside; `Cargo.toml`), so the Bech32 of the encodings is
//! written here from BIP-173, byte for byte what `zcash_keys::encoding` and the node's
//! `KeyIO::EncodePaymentAddress` / `EncodeSpendingKey` produce (`ycash-dd/src/key_io.cpp`).
//! None of the crate's types cross this module's boundary: the surface is strings, byte arrays
//! and integers, so `api.rs` (the bridge) stays free of them.
//!
//! **Wiping** (docs/security-review.md S-1). `sapling_crypto::zip32::ExtendedSpendingKey` has no
//! drop-time erasure, so this module keeps the key as its 169 serialized bytes, rebuilds the
//! typed key for each operation and wipes the bytes on drop; the typed copies are transient and
//! best-effort like every other secret in Rust. The seed is the caller's and is not kept.

use sapling_crypto::zip32::{ExtendedFullViewingKey, ExtendedSpendingKey};
use sapling_crypto::PaymentAddress;
use thiserror::Error;
use zip32::{AccountId, ChildIndex, DiversifierIndex};

use crate::keys::{self, wipe, KeyError, SecretString};
use crate::params::{Network, ACCOUNT, COIN_TYPE, ZIP32_PURPOSE};

/// Sapling key errors.
#[derive(Debug, Error)]
pub enum ShieldedKeyError {
    /// The mnemonic did not parse (from [`keys::seed_from_mnemonic`]).
    #[error(transparent)]
    Key(#[from] KeyError),
    /// A seed shorter than the 32 bytes ZIP-32 requires (a BIP39 seed is 64).
    #[error("zip32 seed too short: {0} bytes")]
    SeedTooShort(usize),
    /// An encoded extended spending key did not decode for this network.
    #[error("bad sapling spending key for {0:?}: {1}")]
    SpendingKey(Network, String),
    /// A Bech32 string did not decode (characters, checksum, padding) or had the wrong HRP.
    #[error("bad bech32: {0}")]
    Bech32(String),
    /// The diversifier index space is exhausted (no valid diversifier at or after the index).
    #[error("no sapling address at or after diversifier index {0}")]
    NoAddress(u64),
}

/// Serialized length of an extended spending key (`ExtendedSpendingKey::to_bytes`).
const EXTSK_LEN: usize = 169;

/// The one Sapling account of a YEW seed: `m/32'/347'/0'` on `network`.
pub struct SaplingAccount {
    /// The extended spending key, serialized; wiped on drop.
    extsk: [u8; EXTSK_LEN],
    network: Network,
}

impl std::fmt::Debug for SaplingAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SaplingAccount({:?}, ..)", self.network)
    }
}

impl Drop for SaplingAccount {
    fn drop(&mut self) {
        wipe(&mut self.extsk);
    }
}

impl SaplingAccount {
    /// Derive account 0 from a BIP39 seed (`m/32'/COIN_TYPE'/ACCOUNT'`).
    pub fn from_seed(seed: &[u8], network: Network) -> Result<SaplingAccount, ShieldedKeyError> {
        if seed.len() < 32 {
            return Err(ShieldedKeyError::SeedTooShort(seed.len()));
        }
        // ZIP-32 §"Sapling key path": m/32'/coin_type'/account' (zcash_keys::keys::sapling::
        // spending_key, librustzcash6 `zcash_keys/src/keys.rs:70-82`).
        let account = AccountId::try_from(ACCOUNT).expect("account 0 is a valid ZIP-32 account");
        let extsk = ExtendedSpendingKey::from_path(
            &ExtendedSpendingKey::master(seed),
            &[
                ChildIndex::hardened(ZIP32_PURPOSE),
                ChildIndex::hardened(COIN_TYPE),
                account.into(),
            ],
        );
        Ok(SaplingAccount {
            extsk: extsk.to_bytes(),
            network,
        })
    }

    /// Derive from a mnemonic and passphrase (Ywallet's `Seed::new(mnemonic, password)`).
    pub fn from_mnemonic(
        phrase: &str,
        passphrase: &str,
        network: Network,
    ) -> Result<SaplingAccount, ShieldedKeyError> {
        let mut seed = keys::seed_from_mnemonic(phrase, passphrase)?;
        let r = SaplingAccount::from_seed(&seed, network);
        wipe(&mut seed);
        r
    }

    /// Import an encoded extended spending key (`secret-extended-key-main1…`, what the node's
    /// `z_exportkey` prints) of `network`. The key need not be account 0 of any seed.
    pub fn from_spending_key(
        network: Network,
        encoded: &str,
    ) -> Result<SaplingAccount, ShieldedKeyError> {
        let data = bech32_decode(network.sapling_spending_key_hrp(), encoded.trim())
            .map_err(|e| ShieldedKeyError::SpendingKey(network, e.to_string()))?;
        let extsk = ExtendedSpendingKey::from_bytes(&data)
            .map_err(|e| ShieldedKeyError::SpendingKey(network, format!("{e:?}")))?;
        let mut data = data;
        wipe(&mut data);
        Ok(SaplingAccount {
            extsk: extsk.to_bytes(),
            network,
        })
    }

    /// The network the encodings below are for.
    pub fn network(&self) -> Network {
        self.network
    }

    fn typed(&self) -> ExtendedSpendingKey {
        ExtendedSpendingKey::from_bytes(&self.extsk).expect("169 bytes we serialized ourselves")
    }

    fn fvk(&self) -> ExtendedFullViewingKey {
        #[allow(deprecated)] // the ExtendedFullViewingKey is what `z_exportviewingkey` prints
        self.typed().to_extended_full_viewing_key()
    }

    /// The extended spending key, Bech32 (`secret-extended-key-main1…`): the `z_importkey` form.
    pub fn spending_key(&self) -> SecretString {
        SecretString::new(bech32_encode(
            self.network.sapling_spending_key_hrp(),
            &self.extsk,
        ))
    }

    /// The extended spending key, serialized (169 bytes). The caller wipes the copy.
    pub fn spending_key_bytes(&self) -> [u8; EXTSK_LEN] {
        self.extsk
    }

    /// The extended full viewing key, Bech32 (`zxviews1…`): the `z_exportviewingkey` /
    /// `z_importviewingkey` form.
    pub fn full_viewing_key(&self) -> String {
        let mut data = Vec::with_capacity(EXTSK_LEN);
        self.fvk()
            .write(&mut data)
            .expect("writing to a Vec cannot fail");
        bech32_encode(self.network.sapling_viewing_key_hrp(), &data)
    }

    /// The default address and its diversifier index: the first valid diversifier from index 0,
    /// what Ywallet shows and what `z_importkey` reports (`ys1…` on mainnet).
    pub fn default_address(&self) -> (u64, String) {
        let (j, addr) = self.fvk().default_address();
        (index_u64(j), self.encode_address(&addr))
    }

    /// The diversified address at the first valid diversifier index at or after `index`, and
    /// that index. About half the indices are valid; `index = 0` gives the default address.
    pub fn address_at(&self, index: u64) -> Result<(u64, String), ShieldedKeyError> {
        let (j, addr) = self
            .fvk()
            .find_address(DiversifierIndex::from(index))
            .ok_or(ShieldedKeyError::NoAddress(index))?;
        Ok((index_u64(j), self.encode_address(&addr)))
    }

    fn encode_address(&self, addr: &PaymentAddress) -> String {
        bech32_encode(self.network.sapling_address_hrp(), &addr.to_bytes())
    }
}

fn index_u64(j: DiversifierIndex) -> u64 {
    u64::try_from(j).expect("diversifier indices YEW hands out start below 2^64")
}

/// Whether `s` is a Sapling payment address of `network` (`ys1…` on mainnet): the Bech32
/// decodes under the network's HRP to a valid 43-byte diversifier ‖ pk_d.
pub fn is_sapling_address(network: Network, s: &str) -> bool {
    bech32_decode(network.sapling_address_hrp(), s.trim())
        .ok()
        .and_then(|d| <[u8; 43]>::try_from(d).ok())
        .and_then(|b| PaymentAddress::from_bytes(&b))
        .is_some()
}

// ---------------------------------------------------------------------------------------------
// Bech32 (BIP-173): what the node's `KeyIO` and `zcash_keys::encoding` wrap the Sapling bytes
// in. Written here, as `keys.rs` writes BIP32 and Base58Check, instead of adding a crate. The
// BIP-173 90-character limit is not applied: an extended key is 285 characters, and neither the
// node (`bech32::Encode` in `src/bech32.cpp`) nor librustzcash enforce it.

const BECH32_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_GEN: [u32; 5] = [
    0x3b6a_57b2,
    0x2650_8e6d,
    0x1ea1_19fa,
    0x3d42_33dd,
    0x2a14_62b3,
];

fn bech32_polymod(values: &[u8]) -> u32 {
    let mut chk: u32 = 1;
    for v in values {
        let b = chk >> 25;
        chk = ((chk & 0x1ff_ffff) << 5) ^ u32::from(*v);
        for (i, g) in BECH32_GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn bech32_hrp_expand(hrp: &str) -> Vec<u8> {
    let b = hrp.as_bytes();
    let mut out = Vec::with_capacity(2 * b.len() + 1);
    out.extend(b.iter().map(|c| c >> 5));
    out.push(0);
    out.extend(b.iter().map(|c| c & 31));
    out
}

/// Regroup `data` from `from`-bit to `to`-bit groups (BIP-173 `convertbits`); `pad` on encode.
fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(data.len() * from as usize / to as usize + 1);
    let maxv = (1u32 << to) - 1;
    for &v in data {
        if u32::from(v) >> from != 0 {
            return None;
        }
        acc = (acc << from) | u32::from(v);
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            out.push(((acc << (to - bits)) & maxv) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        return None;
    }
    Some(out)
}

/// `hrp1` ‖ data in 5-bit groups ‖ 6-character checksum, lower case.
pub fn bech32_encode(hrp: &str, data: &[u8]) -> String {
    let d5 = convert_bits(data, 8, 5, true).expect("8-bit input");
    let mut values = bech32_hrp_expand(hrp);
    values.extend_from_slice(&d5);
    values.extend_from_slice(&[0u8; 6]);
    let polymod = bech32_polymod(&values) ^ 1;
    let mut s = String::with_capacity(hrp.len() + 1 + d5.len() + 6);
    s.push_str(hrp);
    s.push('1');
    for v in &d5 {
        s.push(BECH32_CHARSET[usize::from(*v)] as char);
    }
    for i in 0..6 {
        s.push(BECH32_CHARSET[((polymod >> (5 * (5 - i))) & 31) as usize] as char);
    }
    s
}

/// Decode a Bech32 string whose HRP must be `hrp`; returns the 8-bit data.
pub fn bech32_decode(hrp: &str, s: &str) -> Result<Vec<u8>, ShieldedKeyError> {
    let bad = |m: &str| ShieldedKeyError::Bech32(m.into());
    let has_lower = s.bytes().any(|c| c.is_ascii_lowercase());
    let has_upper = s.bytes().any(|c| c.is_ascii_uppercase());
    if has_lower && has_upper {
        return Err(bad("mixed case"));
    }
    if s.bytes().any(|c| !(33..=126).contains(&c)) {
        return Err(bad("character out of range"));
    }
    let s = s.to_ascii_lowercase();
    let pos = s.rfind('1').ok_or_else(|| bad("no separator"))?;
    if pos == 0 || pos + 7 > s.len() {
        return Err(bad("bad separator position"));
    }
    let (got_hrp, rest) = (&s[..pos], &s[pos + 1..]);
    if got_hrp != hrp {
        return Err(ShieldedKeyError::Bech32(format!(
            "hrp {got_hrp:?}, want {hrp:?}"
        )));
    }
    let mut d5 = Vec::with_capacity(rest.len());
    for c in rest.bytes() {
        let v = BECH32_CHARSET
            .iter()
            .position(|&x| x == c)
            .ok_or_else(|| bad("invalid character"))?;
        d5.push(v as u8);
    }
    let mut values = bech32_hrp_expand(hrp);
    values.extend_from_slice(&d5);
    if bech32_polymod(&values) != 1 {
        return Err(bad("checksum"));
    }
    convert_bits(&d5[..d5.len() - 6], 5, 8, false).ok_or_else(|| bad("padding"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `ywallet.json` mnemonic (24 × `abandon` … `art`).
    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    #[test]
    fn bech32_bip173_vectors() {
        // BIP-173 valid test vectors (checksum-only strings and the empty-data case).
        for v in [
            "A12UEL5L",
            "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
            "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
            "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
        ] {
            let lower = v.to_ascii_lowercase();
            let pos = lower.rfind('1').unwrap();
            let hrp = &lower[..pos];
            let data = bech32_decode(hrp, v).unwrap_or_else(|e| panic!("{v}: {e}"));
            assert_eq!(bech32_encode(hrp, &data), lower, "{v}");
        }
        // Invalid: bad checksum, mixed case, wrong HRP.
        assert!(bech32_decode("a", "A1G7SGD8").is_err());
        assert!(bech32_decode("abc", "aBc1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw").is_err());
        assert!(bech32_decode("abcdeg", "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw").is_err());
        // Round trip of arbitrary bytes, including the 169-byte extended key length.
        for n in [0usize, 1, 2, 3, 20, 43, 169] {
            let data: Vec<u8> = (0..n).map(|i| (i * 37 % 251) as u8).collect();
            let s = bech32_encode("yregtestsapling", &data);
            assert_eq!(bech32_decode("yregtestsapling", &s).unwrap(), data, "{n}");
        }
    }

    #[test]
    fn path_is_zip32_account_zero_at_coin_347() {
        // The same bytes as walking the path by hand: m/32'/347'/0'.
        let seed = keys::seed_from_mnemonic(PHRASE, "").unwrap();
        let a = SaplingAccount::from_seed(&seed, Network::Mainnet).unwrap();
        let by_hand = ExtendedSpendingKey::from_path(
            &ExtendedSpendingKey::master(&seed),
            &[
                ChildIndex::hardened(32),
                ChildIndex::hardened(347),
                ChildIndex::hardened(0),
            ],
        );
        assert_eq!(a.spending_key_bytes(), by_hand.to_bytes());
        // Another path (coin type 1, the node's testnet/regtest HD wallet) is another key.
        let other = ExtendedSpendingKey::from_path(
            &ExtendedSpendingKey::master(&seed),
            &[
                ChildIndex::hardened(32),
                ChildIndex::hardened(1),
                ChildIndex::hardened(0),
            ],
        );
        assert_ne!(a.spending_key_bytes(), other.to_bytes());
    }

    #[test]
    fn encodings_carry_the_network_hrp_and_round_trip() {
        for (net, addr_hrp, sk_hrp, fvk_hrp) in [
            (
                Network::Mainnet,
                "ys1",
                "secret-extended-key-main1",
                "zxviews1",
            ),
            (
                Network::Testnet,
                "ytestsapling1",
                "secret-extended-key-test1",
                "zxviewtestsapling1",
            ),
            (
                Network::Regtest,
                "yregtestsapling1",
                "secret-extended-key-regtest1",
                "zxviewregtestsapling1",
            ),
        ] {
            let a = SaplingAccount::from_mnemonic(PHRASE, "", net).unwrap();
            let (j, addr) = a.default_address();
            assert!(addr.starts_with(addr_hrp), "{net:?}: {addr}");
            assert!(a.spending_key().starts_with(sk_hrp));
            assert!(a.full_viewing_key().starts_with(fvk_hrp));
            assert!(is_sapling_address(net, &addr));
            assert_eq!(a.address_at(0).unwrap(), (j, addr.clone()));
            // Upper case decodes too (BIP-173); the node prints lower case.
            assert!(is_sapling_address(net, &addr.to_ascii_uppercase()));
            // z_exportkey → z_importkey: the encoded key rebuilds the same account.
            let back = SaplingAccount::from_spending_key(net, &a.spending_key()).unwrap();
            assert_eq!(back.spending_key_bytes(), a.spending_key_bytes());
            assert_eq!(back.default_address(), a.default_address());
            // The other networks refuse the encodings.
            for other in [Network::Mainnet, Network::Testnet, Network::Regtest] {
                if other != net {
                    assert!(!is_sapling_address(other, &addr));
                    assert!(SaplingAccount::from_spending_key(other, &a.spending_key()).is_err());
                }
            }
        }
    }

    #[test]
    fn diversified_addresses_differ_and_indices_are_reported() {
        let a = SaplingAccount::from_mnemonic(PHRASE, "", Network::Mainnet).unwrap();
        let (j0, d0) = a.default_address();
        let (j1, d1) = a.address_at(j0 + 1).unwrap();
        assert!(j1 > j0);
        assert_ne!(d0, d1);
        // The reported index is a fixed point, and a later start gives a later index.
        assert_eq!(a.address_at(j1).unwrap(), (j1, d1.clone()));
        let (j2, d2) = a.address_at(j1 + 1).unwrap();
        assert!(j2 > j1);
        assert_ne!(d2, d1);
        assert!(is_sapling_address(Network::Mainnet, &d2));
    }

    #[test]
    fn passphrase_and_seed_length_matter() {
        let a = SaplingAccount::from_mnemonic(PHRASE, "", Network::Mainnet).unwrap();
        let b = SaplingAccount::from_mnemonic(PHRASE, "yew", Network::Mainnet).unwrap();
        assert_ne!(a.default_address(), b.default_address());
        assert!(matches!(
            SaplingAccount::from_seed(&[0u8; 31], Network::Mainnet),
            Err(ShieldedKeyError::SeedTooShort(31))
        ));
        assert!(SaplingAccount::from_mnemonic("abandon about", "", Network::Mainnet).is_err());
        assert_eq!(format!("{a:?}"), "SaplingAccount(Mainnet, ..)");
        assert!(!is_sapling_address(Network::Mainnet, "s1abc"));
        assert!(!is_sapling_address(Network::Mainnet, "ys1abc"));
    }
}
