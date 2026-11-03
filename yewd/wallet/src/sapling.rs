// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The Sapling side as a **viewing** wallet (K-24: the façade holds the account's full viewing
//! key only, never the spending key): diversified addresses of the one account (`z_getnewaddress`,
//! plan §3b S1), trial decryption of every Sapling output the wallet scans with the external and
//! internal incoming viewing keys, and the nullifiers that mark a note spent (the note's position
//! in the commitment tree, from the node's `getblock … 1` `trees.sapling.size`). Spending (the
//! witness, the proof, the spend authorization) is the signer's (S2).

use sapling_crypto::keys::PreparedIncomingViewingKey;
use sapling_crypto::note_encryption::{try_sapling_note_decryption, Zip212Enforcement};
use sapling_crypto::zip32::DiversifiableFullViewingKey;
use sapling_crypto::{NullifierDerivingKey, PaymentAddress};
use yew_core::params::Network;
use zip32::{DiversifierIndex, Scope};

/// One output that decrypted to this account.
#[derive(Clone, Debug)]
pub struct Received {
    pub outindex: u32,
    pub value: u64,
    pub address: String,
    /// `None` for an internal-scope (change) note.
    pub diversifier_index: Option<u64>,
    pub internal: bool,
    pub memo: [u8; 512],
    pub note: sapling_crypto::Note,
}

impl Received {
    /// The note's nullifier once its position in the commitment tree is known.
    pub fn nullifier(&self, view: &Viewing, position: u64) -> [u8; 32] {
        let nk = if self.internal {
            &view.nk_internal
        } else {
            &view.nk_external
        };
        self.note.nf(nk, position).0
    }
}

/// The viewing side of the account.
pub struct Viewing {
    network: Network,
    dfvk: DiversifiableFullViewingKey,
    ivk_external: PreparedIncomingViewingKey,
    ivk_internal: PreparedIncomingViewingKey,
    nk_external: NullifierDerivingKey,
    nk_internal: NullifierDerivingKey,
}

impl std::fmt::Debug for Viewing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Viewing(..)")
    }
}

impl Viewing {
    /// From the 128-byte DFVK of the public bundle.
    pub fn new(network: Network, dfvk_hex: &str) -> Result<Viewing, String> {
        let bytes: [u8; 128] = hex::decode(dfvk_hex)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "the Sapling viewing key is not 128 bytes".to_string())?;
        let dfvk = DiversifiableFullViewingKey::from_bytes(&bytes)
            .ok_or_else(|| "invalid Sapling viewing key".to_string())?;
        Ok(Viewing {
            network,
            ivk_external: PreparedIncomingViewingKey::new(&dfvk.to_ivk(Scope::External)),
            ivk_internal: PreparedIncomingViewingKey::new(&dfvk.to_ivk(Scope::Internal)),
            nk_external: dfvk.to_nk(Scope::External),
            nk_internal: dfvk.to_nk(Scope::Internal),
            dfvk,
        })
    }

    pub fn encode(&self, addr: &PaymentAddress) -> String {
        zcash_keys::encoding::encode_payment_address(self.network.sapling_address_hrp(), addr)
    }

    /// The address at the first valid diversifier index at or after `index`, and that index.
    pub fn address_at(&self, index: u64) -> Option<(u64, String)> {
        let (j, a) = self.dfvk.find_address(DiversifierIndex::from(index))?;
        Some((u64::try_from(j).ok()?, self.encode(&a)))
    }

    /// Whether `s` is an address of this account (external scope), and its diversifier index.
    pub fn owns_address(&self, s: &str) -> Option<u64> {
        let a = zcash_keys::encoding::decode_payment_address(self.network.sapling_address_hrp(), s)
            .ok()?;
        match self.dfvk.decrypt_diversifier(&a)? {
            (j, Scope::External) => u64::try_from(j).ok(),
            (_, Scope::Internal) => None,
        }
    }

    /// Trial-decrypt every output of a Sapling bundle (ZIP-212 grace: a mined block was valid).
    pub fn decrypt(
        &self,
        bundle: &sapling_crypto::Bundle<
            sapling_crypto::bundle::Authorized,
            zcash_protocol::value::ZatBalance,
        >,
    ) -> Vec<Received> {
        let mut out = Vec::new();
        for (i, o) in bundle.shielded_outputs().iter().enumerate() {
            for (ivk, internal) in [(&self.ivk_external, false), (&self.ivk_internal, true)] {
                if let Some((note, addr, memo)) =
                    try_sapling_note_decryption(ivk, o, Zip212Enforcement::GracePeriod)
                {
                    let diversifier_index = if internal {
                        None
                    } else {
                        self.dfvk
                            .decrypt_diversifier(&addr)
                            .and_then(|(j, _)| u64::try_from(j).ok())
                    };
                    out.push(Received {
                        outindex: i as u32,
                        value: note.value().inner(),
                        address: self.encode(&addr),
                        diversifier_index,
                        internal,
                        memo,
                        note,
                    });
                    break;
                }
            }
        }
        out
    }
}

/// The nullifiers a bundle reveals.
pub fn nullifiers(
    bundle: &sapling_crypto::Bundle<
        sapling_crypto::bundle::Authorized,
        zcash_protocol::value::ZatBalance,
    >,
) -> Vec<[u8; 32]> {
    bundle
        .shielded_spends()
        .iter()
        .map(|s| s.nullifier().0)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    /// The façade's diversified addresses are yew-core's (the same account, `m/32'/347'/0'`).
    #[test]
    fn addresses_match_yew_core() {
        let ks = yewd_signer::Keystore::from_mnemonic(Network::Regtest, PHRASE);
        let b = ks.public(&Default::default()).unwrap();
        let v = Viewing::new(Network::Regtest, &b.sapling_dfvk).unwrap();
        let acct =
            yew_core::shielded_keys::SaplingAccount::from_mnemonic(PHRASE, "", Network::Regtest)
                .unwrap();
        for i in [0u64, 1, 5, 100] {
            let (j, a) = v.address_at(i).unwrap();
            assert_eq!((j, a.clone()), acct.address_at(i).unwrap());
            assert_eq!(v.owns_address(&a), Some(j));
        }
        assert!(v.address_at(0).unwrap().1.starts_with("yregtestsapling1"));
    }
}
