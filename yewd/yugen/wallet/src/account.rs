// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! Seed to Yugen account (spec §4, §5.1, §9): the reference's derivations, unchanged.

use yugen_ref::address::FullAddress;
use yugen_ref::falcon::{FalconSigner, Signer};
use yugen_ref::keys::{self, AddrId};
use yugen_ref::params::ADDR_FLAG_ONCHAIN;
use yugen_ref::request::PaymentRequest;
use yugen_ref::wallet::Wallet;

pub struct Account {
    pub wallet: Wallet,
    pub signer: Signer,
    /// Receive static-address payments only through the mailbox hosts (M3, W-7): the direct
    /// chain scan no longer tries packages.
    pub by_hosts: bool,
}

impl Account {
    /// Account 0 of `seed` on `network` (spec NET_*). `None` for a seed the spec refuses.
    pub fn from_seed(seed: &[u8], network: u8) -> Option<Self> {
        let k = keys::derive_account(seed, network, 0)?;
        let signer = Signer::from_seed(&k.falcon_seed);
        let pk = signer.public_key();
        Some(Account { wallet: Wallet::new(k, pk), signer, by_hosts: false })
    }
    pub fn network(&self) -> u8 {
        self.wallet.keys.network
    }
    pub fn request(&self, day: u32, c: u16) -> PaymentRequest {
        self.wallet.request(day, c)
    }
    /// Static address `n` with the on-chain package flag and no mailbox hosts (M1).
    pub fn static_address(&self, n: u32) -> FullAddress {
        self.wallet.full_address(n, ADDR_FLAG_ONCHAIN, Vec::new())
    }
    /// Static address `n` naming its mailbox hosts (§12.1 hosts field; the short address commits to them).
    pub fn static_address_hosts(&self, n: u32, hosts: &[String]) -> FullAddress {
        self.wallet.full_address(n, ADDR_FLAG_ONCHAIN, hosts.iter().map(|h| h.as_bytes().to_vec()).collect())
    }
    /// The nullifier key of an address (for marking own notes spent).
    pub fn nk_d(&self, d: AddrId) -> yugen_ref::B32 {
        self.wallet.address_keys(d).nk_d
    }
}
