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
//! **Not a Ycash reimplementation.** Derivation, encodings and curve arithmetic are
//! `zcash_keys` (boyfromcave/librustzcash6, the Ycash-aware librustzcash ycashd 6.21.0 pins:
//! `keys::sapling::spending_key` is exactly the path above, `encoding::*` the Bech32 the node's
//! `KeyIO` writes) and the `sapling-crypto` crate under it, with Ycash's HRPs and coin type
//! supplied from [`crate::params`]. None of their types cross this module's public boundary:
//! the surface is strings, byte arrays and integers, so `api.rs` (the bridge) stays free of them;
//! the one crate-internal exception is [`SaplingAccount::extended_spending_key`] for
//! `crate::shielded` (the light client's account registration and the spend signer).
//!
//! **Wiping** (docs/security-review.md S-1). `sapling_crypto::zip32::ExtendedSpendingKey` has no
//! drop-time erasure, so this module keeps the key as its 169 serialized bytes, rebuilds the
//! typed key for each operation and wipes the bytes on drop; the typed copies are transient and
//! best-effort like every other secret in Rust. The seed is the caller's and is not kept.

use sapling_crypto::PaymentAddress;
use thiserror::Error;
use zcash_keys::encoding::{
    decode_extended_spending_key, decode_payment_address, encode_extended_full_viewing_key,
    encode_extended_spending_key, encode_payment_address,
};
use zcash_keys::keys::sapling::{ExtendedFullViewingKey, ExtendedSpendingKey};
use zip32::{AccountId, DiversifierIndex};

use crate::keys::{self, wipe, KeyError, SecretString};
use crate::params::{Network, ACCOUNT, COIN_TYPE};

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
        // ZIP-32 Sapling key path m/32'/coin_type'/account' (librustzcash6
        // `zcash_keys/src/keys.rs:70-82`), with Ycash's coin type 347.
        let account = AccountId::try_from(ACCOUNT).expect("account 0 is a valid ZIP-32 account");
        let extsk = zcash_keys::keys::sapling::spending_key(seed, COIN_TYPE, account);
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
        let extsk =
            decode_extended_spending_key(network.sapling_spending_key_hrp(), encoded.trim())
                .map_err(|e| ShieldedKeyError::SpendingKey(network, e.to_string()))?;
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

    /// The typed extended spending key, for the shielded wallet (`crate::shielded`) only: it
    /// registers the account's viewing key and signs a spend with a transient copy, which is
    /// dropped when the operation ends. Never stored, never handed to the bridge.
    pub(crate) fn extended_spending_key(&self) -> ExtendedSpendingKey {
        self.typed()
    }

    /// The diversifiable full viewing key, serialized (128 bytes): what the shielded store
    /// holds for the account, compared at open so a store of another seed is refused.
    pub fn viewing_key_bytes(&self) -> [u8; 128] {
        self.typed().to_diversifiable_full_viewing_key().to_bytes()
    }

    fn fvk(&self) -> ExtendedFullViewingKey {
        #[allow(deprecated)] // the ExtendedFullViewingKey is what `z_exportviewingkey` prints
        self.typed().to_extended_full_viewing_key()
    }

    /// The extended spending key, Bech32 (`secret-extended-key-main1…`): the `z_importkey` form.
    pub fn spending_key(&self) -> SecretString {
        SecretString::new(encode_extended_spending_key(
            self.network.sapling_spending_key_hrp(),
            &self.typed(),
        ))
    }

    /// The extended spending key, serialized (169 bytes). The caller wipes the copy.
    pub fn spending_key_bytes(&self) -> [u8; EXTSK_LEN] {
        self.extsk
    }

    /// The extended full viewing key, Bech32 (`zxviews1…`): the `z_exportviewingkey` /
    /// `z_importviewingkey` form.
    pub fn full_viewing_key(&self) -> String {
        encode_extended_full_viewing_key(self.network.sapling_viewing_key_hrp(), &self.fvk())
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
        encode_payment_address(self.network.sapling_address_hrp(), addr)
    }
}

fn index_u64(j: DiversifierIndex) -> u64 {
    u64::try_from(j).expect("diversifier indices YEW hands out start below 2^64")
}

/// Whether `s` is a Sapling payment address of `network` (`ys1…` on mainnet): the Bech32
/// decodes under the network's HRP to a valid 43-byte diversifier ‖ pk_d.
pub fn is_sapling_address(network: Network, s: &str) -> bool {
    decode_payment_address(network.sapling_address_hrp(), s.trim()).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use zip32::ChildIndex;

    /// The `ywallet.json` mnemonic (24 × `abandon` … `art`).
    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

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
