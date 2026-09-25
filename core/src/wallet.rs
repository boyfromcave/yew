//! The wallet: the key ring, the store and the network bound together. This is what `sync`,
//! the builders and (in W3) `api.rs` operate on. Keys are derived on demand and never stored;
//! imported keys (D-W-11) are stored wrapped under a key derived from the seed (`store.rs`).

use std::collections::HashSet;

use thiserror::Error;

use crate::build::claim::{self, Claimable};
use crate::build::mint::{self, Finished, MintError, MintEstimate};
use crate::build::redeem::{self, RedeemPreview};
use crate::build::yed_transfer::TransferError;
use crate::coins::{self, CoinError, Utxo};
use crate::gate::{GateError, Validator};
use crate::keys::{self, AddressKey, Chain, KeyError, KeyRing};
use crate::net::{CompactClient, NetError, Validation};
use crate::params::{Network, GAP_LIMIT};
use crate::store::{AddressRow, MintRow, Store, StoreError, VaultRow, CHAIN_IMPORTED};
use crate::tx::TxError;

/// Any wallet-level error.
#[derive(Debug, Error)]
pub enum WalletError {
    /// Keys.
    #[error(transparent)]
    Key(#[from] KeyError),
    /// Storage.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// Network.
    #[error(transparent)]
    Net(#[from] NetError),
    /// Transactions.
    #[error(transparent)]
    Tx(#[from] TxError),
    /// Coin selection.
    #[error(transparent)]
    Coins(#[from] CoinError),
    /// The gate.
    #[error(transparent)]
    Gate(#[from] GateError),
    /// A YED transfer could not be built (the node's identifiers).
    #[error(transparent)]
    Transfer(#[from] TransferError),
    /// A mint / claim step could not proceed (W4).
    #[error(transparent)]
    Mint(#[from] MintError),
    /// Anything else, with a message.
    #[error("{0}")]
    Other(String),
}

/// `$N.NN` for a number of cents (negative allowed).
pub fn dollars(cents: i64) -> String {
    let sign = if cents < 0 { "-" } else { "" };
    let c = cents.unsigned_abs();
    format!("{sign}${}.{:02}", c / 100, c % 100)
}

/// The balances the home screen shows (plan §3.4): computed from classes, never from
/// `sum(nValue)` (§3.7).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Balances {
    /// YEC available (class `YEC`), zat.
    pub yec_zat: i64,
    /// YEC reserved for YED fees (class `FEE_RESERVE`), zat.
    pub yec_reserved_zat: i64,
    /// YEC change of the wallet's own unconfirmed transactions, zat (in neither balance).
    pub yec_pending_zat: i64,
    /// YED (class `TOKEN`), cents.
    pub yed_cents: u64,
    /// Pending YED (class `PENDING_TOKEN`), cents.
    pub yed_pending_cents: u64,
    /// `GetPrice.pMint` at the last sync, micro-USD per YEC, when defined.
    pub price_micro_usd: Option<i64>,
}

/// An open wallet.
pub struct Wallet {
    /// The network this wallet is for.
    pub network: Network,
    /// The database.
    pub store: Store,
    keyring: KeyRing,
    /// Wrapping key for imported secrets: `HMAC-SHA256("yew-wrap", seed)`.
    wrap_secret: [u8; 32],
}

impl std::fmt::Debug for Wallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Wallet({:?})", self.network)
    }
}

impl Wallet {
    /// Open the wallet at `path` for `network` with the seed of `mnemonic`/`passphrase`.
    /// `birthday` is the height to scan from for a new database (ignored once set).
    pub fn open(
        path: &str,
        network: Network,
        mnemonic: &str,
        passphrase: &str,
        birthday: Option<u64>,
    ) -> Result<Wallet, WalletError> {
        let seed = keys::seed_from_mnemonic(mnemonic, passphrase)?;
        let store = Store::open(path)?;
        Wallet::from_parts(store, network, &seed, birthday)
    }

    /// Open over an existing store (tests use an in-memory one).
    pub fn from_parts(
        store: Store,
        network: Network,
        seed: &[u8],
        birthday: Option<u64>,
    ) -> Result<Wallet, WalletError> {
        let keyring = KeyRing::from_seed(seed)?;
        match store.meta("network")? {
            None => store.set_meta("network", network.chain_name())?,
            Some(n) if n == network.chain_name() => {}
            Some(n) => {
                return Err(WalletError::Other(format!(
                    "wallet file is for network {n}, asked for {}",
                    network.chain_name()
                )))
            }
        }
        if store.meta("birthday")?.is_none() {
            store.set_meta("birthday", &birthday.unwrap_or(0).to_string())?;
        }
        // The primary address must exist so the seed is bound to the file (D-W-7).
        let primary = keyring.key(Chain::External, 0)?;
        match store.meta("primary_hash160")? {
            None => store.set_meta("primary_hash160", &keys::hex(&primary.hash160))?,
            Some(h) if h == keys::hex(&primary.hash160) => {}
            Some(_) => {
                return Err(WalletError::Other(
                    "wallet file belongs to another seed".into(),
                ))
            }
        }
        let wrap_secret = {
            use hmac::{Hmac, KeyInit, Mac};
            let mut m = Hmac::<sha2::Sha256>::new_from_slice(b"yew-wrap").expect("any key length");
            m.update(seed);
            m.finalize().into_bytes().into()
        };
        let w = Wallet {
            network,
            store,
            keyring,
            wrap_secret,
        };
        w.ensure_gap()?;
        Ok(w)
    }

    /// The birthday height.
    pub fn birthday(&self) -> Result<u64, WalletError> {
        Ok(self.store.meta_u64("birthday")?)
    }

    /// Derive addresses so that both chains have `GAP_LIMIT` unused addresses past the last
    /// used one (plan §3.2 step 1). Returns the rows that were newly created.
    pub fn ensure_gap(&self) -> Result<Vec<AddressRow>, WalletError> {
        let mut created = Vec::new();
        for chain in [Chain::External, Chain::Change] {
            let n = chain.number();
            let last_used = self.store.max_used_index(n)?;
            let want_max = last_used.map(|u| u + GAP_LIMIT).unwrap_or(GAP_LIMIT - 1);
            let have_max = self.store.max_index(n)?;
            let start = have_max.map(|m| m + 1).unwrap_or(0);
            for index in start..=want_max {
                let k = self.keyring.key(chain, index)?;
                let row = AddressRow {
                    chain: n,
                    index,
                    address_s: k.address_s(self.network),
                    address_ye: k.address_ye(self.network),
                    hash160: k.hash160,
                    used: false,
                };
                self.store.insert_address(&row)?;
                created.push(row);
            }
        }
        Ok(created)
    }

    /// Every address row.
    pub fn addresses(&self) -> Result<Vec<AddressRow>, WalletError> {
        Ok(self.store.addresses()?)
    }

    /// The set of own key hashes.
    pub fn own_hashes(&self) -> Result<HashSet<[u8; 20]>, WalletError> {
        Ok(self
            .store
            .addresses()?
            .into_iter()
            .map(|a| a.hash160)
            .collect())
    }

    /// The receive address: the first unused external address. With `reserve`, the one
    /// currently shown is marked used first so the next call shows a fresh one.
    pub fn receive_address(&self, reserve: bool) -> Result<AddressRow, WalletError> {
        if reserve {
            if let Some(cur) = self.store.first_unused(Chain::External.number())? {
                self.store.mark_used(&cur.hash160)?;
                self.ensure_gap()?;
            }
        }
        self.store
            .first_unused(Chain::External.number())?
            .ok_or_else(|| WalletError::Other("no unused external address".into()))
    }

    /// The next change address (first unused on the change chain).
    pub fn change_address(&self) -> Result<AddressRow, WalletError> {
        self.ensure_gap()?;
        self.store
            .first_unused(Chain::Change.number())?
            .ok_or_else(|| WalletError::Other("no unused change address".into()))
    }

    /// The row for an address string in either form, if it is ours.
    pub fn row_for_address(&self, address: &str) -> Result<Option<AddressRow>, WalletError> {
        let a = keys::parse_address(self.network, address)?;
        let h = a.hash();
        Ok(self.store.addresses()?.into_iter().find(|r| r.hash160 == h))
    }

    /// The private key behind an own key hash: HD (re-derived) or imported (unwrapped).
    pub fn key_for_hash(&self, hash160: &[u8; 20]) -> Result<Option<AddressKey>, WalletError> {
        let row = match self
            .store
            .addresses()?
            .into_iter()
            .find(|r| r.hash160 == *hash160)
        {
            Some(r) => r,
            None => return Ok(None),
        };
        if let Some(chain) = row.hd_chain() {
            let k = self.keyring.key(chain, row.index)?;
            if k.hash160 != *hash160 {
                return Err(WalletError::Other(
                    "stored address does not match its derivation".into(),
                ));
            }
            return Ok(Some(k));
        }
        let wrapped = self
            .store
            .imported_key(hash160)?
            .ok_or_else(|| WalletError::Other("imported key missing from store".into()))?;
        let secret = crate::store::wrap_key(&self.wrap_secret, hash160, &wrapped);
        let sk = secp256k1::SecretKey::from_secret_bytes(
            secret
                .as_slice()
                .try_into()
                .map_err(|_| WalletError::Other("wrapped key length".into()))?,
        )
        .map_err(|_| WalletError::Other("wrapped key out of range".into()))?;
        let k = AddressKey::from_secret(sk);
        if k.hash160 != *hash160 {
            return Err(WalletError::Other(
                "imported key does not match its hash".into(),
            ));
        }
        Ok(Some(k))
    }

    /// Export the WIF of an own address (D-W-11).
    pub fn export_wif(&self, address: &str) -> Result<String, WalletError> {
        let row = self.row_for_address(address)?.ok_or_else(|| {
            WalletError::Other(format!("{address} is not an address of this wallet"))
        })?;
        let k = self
            .key_for_hash(&row.hash160)?
            .ok_or_else(|| WalletError::Other("no key".into()))?;
        Ok(k.wif(self.network))
    }

    /// Import a WIF as a watch-and-spend key outside the HD tree (D-W-11). Returns its row.
    /// The key is *not* covered by the seed backup; the caller says so to the user.
    pub fn import_wif(&self, wif: &str) -> Result<AddressRow, WalletError> {
        let k = keys::decode_wif(self.network, wif)?;
        let wrapped =
            crate::store::wrap_key(&self.wrap_secret, &k.hash160, &k.secret.to_secret_bytes());
        self.store.insert_imported_key(&k.hash160, &wrapped)?;
        let row = AddressRow {
            chain: CHAIN_IMPORTED,
            index: 0,
            address_s: k.address_s(self.network),
            address_ye: k.address_ye(self.network),
            hash160: k.hash160,
            used: true,
        };
        self.store.insert_address(&row)?;
        Ok(row)
    }

    /// The balances (plan §3.4) from the stored classes and the last sync's price. Locked
    /// outputs (inputs of the wallet's own unconfirmed transactions) are in neither balance:
    /// what they become is shown as pending until the spend confirms.
    pub fn balances(&self) -> Result<Balances, WalletError> {
        let utxos = self.store.utxos()?;
        let spendable = self.spendable_utxos()?;
        let (yec_zat, yec_reserved_zat) = coins::yec_balances(&spendable);
        let (yed_cents, yed_pending_cents) = coins::yed_balances(&spendable);
        let mut yec_pending_zat = 0;
        for (txid, _, _) in self.store.pending_txs()? {
            let pending_tokens: HashSet<u32> = utxos
                .iter()
                .filter(|u| u.outpoint.txid == txid)
                .map(|u| u.outpoint.n)
                .collect();
            for (n, value, _) in self.store.own_outputs_of(&txid)? {
                if !pending_tokens.contains(&n) {
                    yec_pending_zat += value;
                }
            }
        }
        let price = self.store.meta_u64("price_micro_usd")?;
        Ok(Balances {
            yec_zat,
            yec_reserved_zat,
            yec_pending_zat,
            yed_cents,
            yed_pending_cents,
            price_micro_usd: if price > 0 { Some(price as i64) } else { None },
        })
    }

    // ---- Yellowback operations (plan §3.4, W4). Each takes the connected clients and the
    // last sync's `tip` / `branch_id`; every broadcast runs both gate layers (D-W-5).

    /// `mint_estimate(cents, lockBlocks)`: what the Mint screen shows; nothing is signed.
    pub async fn mint_estimate(
        &self,
        validator: &mut Validator,
        cents: u64,
        lock_blocks: u32,
    ) -> Result<MintEstimate, WalletError> {
        let yb = validator.client_mut().ok_or(GateError::YellowbackAbsent)?;
        mint::estimate(self, yb, cents, lock_blocks).await
    }

    /// `mint_start(...)`: bundle, carrier funding transaction, the `mints` row. Returns the
    /// `mint_id` to pass to [`Wallet::mint_finish`] once a sync has seen the carrier confirm.
    pub async fn mint_start(
        &self,
        client: &mut CompactClient,
        validator: &mut Validator,
        cents: u64,
        lock_blocks: u32,
        tip: u64,
        branch_id: u32,
    ) -> Result<i64, WalletError> {
        mint::start(self, client, validator, cents, lock_blocks, tip, branch_id).await
    }

    /// `mint_finish(mintId)`: the MINT (or, for a claim row, the CLAIM) over the confirmed
    /// carrier. The row must be `CarrierConfirmed` (the sync loop advances it).
    pub async fn mint_finish(
        &self,
        client: &mut CompactClient,
        validator: &mut Validator,
        mint_id: i64,
        tip: u64,
        branch_id: u32,
    ) -> Result<Finished, WalletError> {
        mint::finish(self, client, validator, mint_id, tip, branch_id).await
    }

    /// `mint_sweep(mintId)`: reclaim the carrier of a lapsed row (`CARRIER_VALUE − fee`).
    pub async fn mint_sweep(
        &self,
        client: &mut CompactClient,
        validator: &mut Validator,
        mint_id: i64,
        tip: u64,
        branch_id: u32,
    ) -> Result<Finished, WalletError> {
        mint::sweep(self, client, validator, mint_id, tip, branch_id).await
    }

    /// Every two-step row (mints and claims), oldest first: the progress the Mint screen shows.
    pub fn mints(&self) -> Result<Vec<MintRow>, WalletError> {
        Ok(self.store.mints()?)
    }

    /// `vaults()`: the own vaults as `GetVault` last reported them (the Yellowback screen).
    pub fn vaults(&self) -> Result<Vec<VaultRow>, WalletError> {
        Ok(self.store.vaults()?)
    }

    /// `redeem(vaultTxid)`: build and broadcast the owner-path spend of an own open vault at
    /// or past `lockHeight` (a VOID vault is released). Returns the txid, the node's
    /// validation and the preview that was sent.
    pub async fn redeem(
        &self,
        client: &mut CompactClient,
        validator: &mut Validator,
        vault_txid: &[u8; 32],
        tip: u64,
        branch_id: u32,
    ) -> Result<(String, Validation, RedeemPreview), WalletError> {
        let yb = validator.client_mut().ok_or(GateError::YellowbackAbsent)?;
        let p = redeem::build_redeem(self, yb, vault_txid, tip, branch_id).await?;
        let (txid, v) = redeem::broadcast(self, client, validator, &p).await?;
        Ok((txid, v, p))
    }

    /// `claimable()`: `ListClaimable` for the liquidator persona.
    pub async fn claimable(
        &self,
        validator: &mut Validator,
    ) -> Result<Vec<Claimable>, WalletError> {
        let yb = validator.client_mut().ok_or(GateError::YellowbackAbsent)?;
        claim::claimable(yb).await
    }

    /// `claim(vaultTxid)`: start the two-step claim (bundle, carrier funding transaction, the
    /// `mints` row of kind `Claim`). Returns the row id; [`Wallet::mint_finish`] sends the
    /// CLAIM once the carrier is confirmed.
    pub async fn claim(
        &self,
        client: &mut CompactClient,
        validator: &mut Validator,
        vault_txid: &[u8; 32],
        tip: u64,
        branch_id: u32,
    ) -> Result<i64, WalletError> {
        claim::start(self, client, validator, vault_txid, tip, branch_id).await
    }

    /// The UTXOs that are not locked (the input set every builder selects from).
    pub fn spendable_utxos(&self) -> Result<Vec<Utxo>, WalletError> {
        let locked: HashSet<_> = self
            .store
            .locks()?
            .into_iter()
            .map(|l| l.outpoint)
            .collect();
        Ok(self
            .store
            .utxos()?
            .into_iter()
            .filter(|u| !locked.contains(&u.outpoint))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn wallet() -> Wallet {
        let seed = keys::seed_from_mnemonic(PHRASE, "").unwrap();
        Wallet::from_parts(
            Store::open_in_memory().unwrap(),
            Network::Regtest,
            &seed,
            Some(5),
        )
        .unwrap()
    }

    #[test]
    fn gap_and_addresses() {
        let w = wallet();
        let rows = w.addresses().unwrap();
        assert_eq!(rows.len(), 2 * GAP_LIMIT as usize);
        assert_eq!(w.birthday().unwrap(), 5);
        let first = w.receive_address(false).unwrap();
        assert_eq!((first.chain, first.index), (0, 0));
        assert!(first.address_s.starts_with("sm") && first.address_ye.starts_with("yr"));
        let next = w.receive_address(true).unwrap();
        assert_eq!((next.chain, next.index), (0, 1));
        assert_eq!(w.addresses().unwrap().len(), 2 * GAP_LIMIT as usize + 1);
        let change = w.change_address().unwrap();
        assert_eq!((change.chain, change.index), (1, 0));
        let k = w.key_for_hash(&first.hash160).unwrap().unwrap();
        assert_eq!(k.hash160, first.hash160);
        assert_eq!(
            w.export_wif(&first.address_ye).unwrap(),
            k.wif(Network::Regtest)
        );
        assert!(w
            .row_for_address(&keys::encode_p2pkh(Network::Regtest, &[9; 20]))
            .unwrap()
            .is_none());
    }

    #[test]
    fn import_wif_round_trips_and_is_spendable() {
        let w = wallet();
        let foreign =
            AddressKey::from_secret(secp256k1::SecretKey::from_secret_bytes([7u8; 32]).unwrap());
        let row = w.import_wif(&foreign.wif(Network::Regtest)).unwrap();
        assert_eq!(row.chain, CHAIN_IMPORTED);
        assert_eq!(row.hash160, foreign.hash160);
        let back = w.key_for_hash(&foreign.hash160).unwrap().unwrap();
        assert_eq!(
            back.secret.to_secret_bytes(),
            foreign.secret.to_secret_bytes()
        );
        assert_eq!(
            w.export_wif(&row.address_s).unwrap(),
            foreign.wif(Network::Regtest)
        );
        assert!(w.import_wif(&foreign.wif(Network::Mainnet)).is_err());
    }

    #[test]
    fn dollars_format() {
        assert_eq!(dollars(0), "$0.00");
        assert_eq!(dollars(5), "$0.05");
        assert_eq!(dollars(12_345), "$123.45");
        assert_eq!(dollars(-250), "-$2.50");
    }

    #[test]
    fn wrong_seed_or_network_is_refused() {
        let seed = keys::seed_from_mnemonic(PHRASE, "").unwrap();
        let store = Store::open_in_memory().unwrap();
        let w = Wallet::from_parts(store, Network::Regtest, &seed, None).unwrap();
        let store = w.store;
        assert!(Wallet::from_parts(store, Network::Mainnet, &seed, None).is_err());
        let store = Store::open_in_memory().unwrap();
        let w = Wallet::from_parts(store, Network::Regtest, &seed, None).unwrap();
        let other = keys::seed_from_mnemonic(PHRASE, "x").unwrap();
        assert!(Wallet::from_parts(w.store, Network::Regtest, &other, None).is_err());
    }
}
