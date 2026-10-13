// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The wallet: the key ring, the store and the network bound together. This is what `sync`,
//! the builders and (in W3) `api.rs` operate on. Keys are derived on demand and never stored;
//! imported keys (D-W-11) are stored wrapped under a key derived from the seed (`store.rs`).
//!
//! **Shielded (yew-shielded plan S2).** A wallet opened from a file also holds the Ycash Sapling
//! side ([`crate::shielded::Shielded`]): its own `zcash_client_sqlite` store in
//! `shielded/<file stem>/` beside the transparent file, the Sapling account of the same seed
//! (`m/32'/347'/0'`, [`crate::shielded_keys`]) injected at open and never written, synced by the
//! light client. The two sides never share an input: every transparent builder and the gate's
//! transparent paths see only the UTXO table, the shielded path only notes.

use std::collections::{HashMap, HashSet};

use thiserror::Error;

use crate::build::claim::{self, Claimable};
use crate::build::mint::{self, ConfirmedTerms, Finished, MintError, MintEstimate};
use crate::build::redeem::{self, RedeemBuild};
use crate::build::terms::{ClaimBounds, MintGate};
use crate::build::yed_transfer::TransferError;
use crate::coins::{self, CoinError, Utxo};
use crate::gate::{GateError, Validator};
use crate::keys::{self, AddressKey, Chain, KeyError, KeyRing};
use crate::net::{CompactClient, NetError, Validation};
use crate::params::{Network, GAP_LIMIT};
use crate::shielded::{Shielded, ShieldedError};
use crate::shielded_keys::{SaplingAccount, ShieldedKeyError};
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
    /// The shielded side (yew-shielded plan S2).
    #[error(transparent)]
    Shielded(#[from] ShieldedError),
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

/// `N.NNNNNNNN YEC` for a number of zat (negative allowed).
pub fn yec(zat: i64) -> String {
    let sign = if zat < 0 { "-" } else { "" };
    let z = zat.unsigned_abs();
    format!("{sign}{}.{:08} YEC", z / 100_000_000, z % 100_000_000)
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
    /// YEC at the wallet's own post-quantum keys (class `PQ_OWNED`), zat: in neither balance
    /// above, moved one coin at a time (`build::release::build_pq_coin_move`).
    pub yec_pq_zat: i64,
    /// Those coins (unlocked), oldest first.
    pub pq_coins: Vec<crate::tx::OutPoint>,
}

/// An open wallet.
pub struct Wallet {
    /// The network this wallet is for.
    pub network: Network,
    /// The database.
    pub store: Store,
    keyring: KeyRing,
    /// Wrapping key for imported secrets: `HMAC-SHA256("yew-wrap", seed)`.
    wrap_secret: WrapSecret,
    /// The post-quantum seed root (`HKDF-Extract("", BIP39 seed)`, quantum spec A-12): every
    /// vault owner key is expanded from it ([`Wallet::pq_owner_key`]).
    pq_root: crate::pq::PqSeedRoot,
    /// Owner ids already derived, by external index (SLH-DSA key generation is not free).
    pq_ids: std::sync::Mutex<HashMap<u32, crate::pq::PqKeyId>>,
    /// Falcon holder ids already derived, by holder index ([`falcon_holder_index`]).
    falcon_ids: std::sync::Mutex<HashMap<u32, crate::pq::PqKeyId>>,
    /// The server's post-quantum terms as last read (`params.pq`, rpcversion 7): the size fee
    /// rate and the Falcon activation ([`Wallet::pq_terms`]).
    pq_terms: std::sync::Mutex<crate::build::terms::PqTerms>,
    /// The Sapling side (`None` for a wallet over an in-memory store, as the unit tests use).
    pub shielded: Option<Shielded>,
}

/// The Falcon holder index of an HD key (YEW's own index space; the derivation is the node's
/// `DerivePQSeed(seed, 2, index)`): external key `i` → `i`, change key `i` → `2³¹ + i`. One Falcon
/// holder per HD address, so the gap scan of the address chains is also the gap scan of the
/// holders and a restore that finds the address finds its Falcon YED. `None` past `2³¹`.
pub fn falcon_holder_index(chain: Chain, index: u32) -> Option<u32> {
    const CHANGE: u32 = 0x8000_0000;
    if index >= CHANGE {
        return None;
    }
    Some(match chain {
        Chain::External => index,
        Chain::Change => CHANGE | index,
    })
}

/// The wrapping key, wiped on drop (`Wallet` itself stays `Drop`-free so a test can move its
/// store out).
struct WrapSecret([u8; 32]);

impl Drop for WrapSecret {
    fn drop(&mut self) {
        keys::wipe(&mut self.0);
    }
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
        let mut seed = keys::seed_from_mnemonic(mnemonic, passphrase)?;
        let store = Store::open(path);
        let w = store
            .map_err(WalletError::from)
            .and_then(|store| Wallet::from_parts(store, network, &seed, birthday))
            .and_then(|mut w| {
                // The Sapling side, beside the file (`shielded/<stem>/`), from the same seed.
                let account = SaplingAccount::from_seed(&seed, network).map_err(|e| match e {
                    ShieldedKeyError::Key(k) => WalletError::Key(k),
                    other => WalletError::Other(other.to_string()),
                })?;
                let dir = crate::shielded::shielded_dir(std::path::Path::new(path));
                w.shielded = Some(Shielded::open(&dir, network, account)?);
                // The vault activation height the last sync recorded (regtest: the server's).
                let vault = w.vault_activation()?;
                w.set_vault_activation(vault)?;
                Ok(w)
            });
        keys::wipe(&mut seed);
        w
    }

    /// The vault upgrade's activation height recorded by the last sync (`GetChainInfo`; regtest
    /// only takes it, see [`crate::params::signing_branch_id`]), `None` when the server reported
    /// none.
    pub fn vault_activation(&self) -> Result<Option<u64>, WalletError> {
        Ok(Some(self.store.meta_u64("vault_activation_height")?).filter(|h| *h > 0))
    }

    /// Record the vault upgrade's activation height and hand it to the shielded side, whose
    /// Ycash parameters (scan branch check, proposals, builder) then carry the Vault branch from
    /// that height on (finding 58).
    pub fn set_vault_activation(&mut self, vault: Option<u64>) -> Result<(), WalletError> {
        self.store
            .set_meta("vault_activation_height", &vault.unwrap_or(0).to_string())?;
        if let Some(sh) = self.shielded.as_mut() {
            sh.set_vault_activation(vault)?;
        }
        Ok(())
    }

    /// The shielded side, or an error for a wallet without one (in-memory test wallets).
    pub fn shielded_mut(&mut self) -> Result<&mut Shielded, WalletError> {
        self.shielded
            .as_mut()
            .ok_or_else(|| WalletError::Other("this wallet has no shielded store".into()))
    }

    /// The shielded side, read-only.
    pub fn shielded(&self) -> Result<&Shielded, WalletError> {
        self.shielded
            .as_ref()
            .ok_or_else(|| WalletError::Other("this wallet has no shielded store".into()))
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
            WrapSecret(m.finalize().into_bytes().into())
        };
        let stored_terms = Wallet::stored_pq_terms(&store, network);
        let w = Wallet {
            network,
            store,
            keyring,
            wrap_secret,
            pq_root: crate::pq::PqSeedRoot::from_seed(seed),
            pq_ids: std::sync::Mutex::new(HashMap::new()),
            falcon_ids: std::sync::Mutex::new(HashMap::new()),
            pq_terms: std::sync::Mutex::new(stored_terms),
            shielded: None,
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
        let mut secret = crate::store::wrap_key(&self.wrap_secret.0, hash160, &wrapped);
        let sk = secret
            .as_slice()
            .try_into()
            .map_err(|_| WalletError::Other("wrapped key length".into()))
            .and_then(|b: [u8; 32]| {
                secp256k1::SecretKey::from_secret_bytes(b)
                    .map_err(|_| WalletError::Other("wrapped key out of range".into()))
            });
        keys::wipe(&mut secret);
        let k = AddressKey::from_secret(sk?);
        if k.hash160 != *hash160 {
            return Err(WalletError::Other(
                "imported key does not match its hash".into(),
            ));
        }
        Ok(Some(k))
    }

    /// The SLH-DSA vault-owner key paired with the external (receive) key at `index`
    /// (quantum plan Q7; spec A-12 derivation): `DerivePQSeed(BIP39 seed, scheme 1, index)`.
    ///
    /// **Pairing rule (YEW).** A mint's token goes to a fresh external P2PKH key (spec §3.6: the
    /// holder is no longer the owner), and its vault owner is the PQ key of the *same index*. So
    /// the owner chain needs no index of its own, no store record, and no separate gap scan: a
    /// restore that finds the external keys finds the owners. The key is re-derived on every use
    /// (it is never stored); [`Wallet::pq_owner_id`] caches the public id.
    pub fn pq_owner_key(&self, index: u32) -> crate::pq::PqKey {
        self.pq_root.slh_key(index)
    }

    /// The owner id of [`Wallet::pq_owner_key`]`(index)`, cached in memory and in the store's
    /// `pq_owners` table (schema v5): an SLH-DSA key generation costs ~68 ms in a dev build, so a
    /// gap-limit set is ~1.4 s the first time and free on every later open. The id is public; a
    /// signing path re-derives the key and checks its id ([`Wallet::pq_key_for_owner`]), so a
    /// stale cache entry can never sign for the wrong owner.
    pub fn pq_owner_id(&self, index: u32) -> crate::pq::PqKeyId {
        let mut cache = self.pq_ids.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(id) = cache.get(&index) {
            return *id;
        }
        let id = match self.store.pq_owner(index) {
            Ok(Some(id)) => id,
            _ => {
                let id = self.pq_root.slh_key(index).id();
                // A failed cache write only costs the derivation again next time.
                let _ = self.store.set_pq_owner(index, &id);
                id
            }
        };
        cache.insert(index, id);
        id
    }

    /// The PQ owner paired with an own external HD key hash (`None` for a change or imported
    /// key, or a hash that is not ours).
    pub fn pq_owner_for_hash(
        &self,
        hash160: &[u8; 20],
    ) -> Result<Option<(u32, crate::pq::PqKeyId)>, WalletError> {
        Ok(self
            .store
            .addresses()?
            .into_iter()
            .find(|r| r.hash160 == *hash160 && r.hd_chain() == Some(Chain::External))
            .map(|r| (r.index, self.pq_owner_id(r.index))))
    }

    /// Every PQ owner this wallet can sign for, with the external key hash it is paired with:
    /// the owner of each derived external address (the gap-scanned set, so a restore sees the
    /// vaults of every used receive key).
    pub fn own_pq_owners(&self) -> Result<HashMap<crate::pq::PqKeyId, [u8; 20]>, WalletError> {
        Ok(self
            .store
            .addresses()?
            .into_iter()
            .filter(|r| r.hd_chain() == Some(Chain::External))
            .map(|r| (self.pq_owner_id(r.index), r.hash160))
            .collect())
    }

    /// The signing key of an own PQ owner, found through its paired external key (and checked
    /// against the id).
    pub fn pq_key_for_owner(
        &self,
        owner: &crate::pq::PqKeyId,
        paired_hash160: &[u8; 20],
    ) -> Result<Option<crate::pq::PqKey>, WalletError> {
        let Some((index, id)) = self.pq_owner_for_hash(paired_hash160)? else {
            return Ok(None);
        };
        if id != *owner {
            return Ok(None);
        }
        let key = self.pq_owner_key(index);
        if key.id() != *owner {
            return Err(WalletError::Other(format!(
                "the cached post-quantum owner of key {index} does not match its key; delete the wallet cache and resync"
            )));
        }
        Ok(Some(key))
    }

    // ---- Falcon YED holders (TOK-PQ)

    /// The Falcon (scheme 2) YED holder id paired with the HD address `row` (`None` for an
    /// imported key, which has no seed-derived pair), cached in memory and in the store's
    /// `pq_holders` table (a Falcon key generation is ~10 ms; the gap-limit set is derived once
    /// per wallet). The id is public; [`Wallet::falcon_key_for_id`] re-derives and checks it.
    pub fn falcon_holder_id(&self, row: &AddressRow) -> Option<crate::pq::PqKeyId> {
        let idx = falcon_holder_index(row.hd_chain()?, row.index)?;
        let mut cache = self.falcon_ids.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(id) = cache.get(&idx) {
            return Some(*id);
        }
        let id = match self.store.pq_holder(idx) {
            Ok(Some(id)) if id.scheme == crate::pq::SCHEME_FN_DSA_512 => id,
            _ => {
                let id = self.pq_root.falcon_key(idx).id();
                // A failed cache write only costs the derivation again next time.
                let _ = self.store.set_pq_holder(idx, &id);
                id
            }
        };
        cache.insert(idx, id);
        Some(id)
    }

    /// The Falcon holder address (53 characters, `yb…`/`yt…`/`yr…`) paired with `row`.
    pub fn falcon_holder_address(&self, row: &AddressRow) -> Option<String> {
        keys::encode_pq_yellowback(self.network, &self.falcon_holder_id(row)?)
    }

    /// Every own Falcon holder id with the HD address row it is paired with (the gap-scanned
    /// set of both chains, so a restore finds the YED of every derived key).
    pub fn own_falcon_holders(
        &self,
    ) -> Result<HashMap<crate::pq::PqKeyId, AddressRow>, WalletError> {
        Ok(self
            .store
            .addresses()?
            .into_iter()
            .filter_map(|r| Some((self.falcon_holder_id(&r)?, r)))
            .collect())
    }

    /// [`Wallet::own_falcon_holders`] when `tx` pays any `TX_PQPKH` (else empty: no Falcon key
    /// is derived for a transaction that cannot pay one).
    pub fn own_falcon_holders_for(
        &self,
        tx: &crate::tx::Transaction,
    ) -> Result<HashMap<crate::pq::PqKeyId, AddressRow>, WalletError> {
        if tx
            .vout
            .iter()
            .any(|o| crate::pq::pqpkh_of(&o.script_pubkey).is_some())
        {
            self.own_falcon_holders()
        } else {
            Ok(HashMap::new())
        }
    }

    /// The signing key of an own Falcon holder id: found through its paired address row,
    /// re-derived, and checked against the id (`None` when the id is not this wallet's).
    pub fn falcon_key_for_id(
        &self,
        id: &crate::pq::PqKeyId,
    ) -> Result<Option<crate::pq::PqKey>, WalletError> {
        if id.scheme != crate::pq::SCHEME_FN_DSA_512 {
            return Ok(None);
        }
        let Some(row) = self.own_falcon_holders()?.remove(id) else {
            return Ok(None);
        };
        let idx = falcon_holder_index(row.hd_chain().expect("HD row"), row.index)
            .expect("an HD row with a holder id has a holder index");
        let key = self.pq_root.falcon_key(idx);
        if key.id() != *id {
            return Err(WalletError::Other(format!(
                "the cached Falcon holder of key {idx} does not match its key; delete the wallet cache and resync"
            )));
        }
        Ok(Some(key))
    }

    /// The YED holder output for an own fresh key `row` under the holder rule of the block the
    /// transaction will be mined in (`falcon`: TOK-PQ in force): the Falcon `TX_PQPKH` paired
    /// with `row` once Falcon is active (the default holder from day one on mainnet), a P2PKH
    /// to `row` before it (regtest/devnet pre-Falcon only).
    pub fn yed_holder_script(
        &self,
        row: &AddressRow,
        falcon: bool,
    ) -> Result<Vec<u8>, WalletError> {
        if !falcon {
            return Ok(crate::script::p2pkh_script(&row.hash160));
        }
        let id = self.falcon_holder_id(row).ok_or_else(|| {
            WalletError::Other("an imported key has no Falcon holder pair".into())
        })?;
        Ok(crate::pq::pqpkh_script(&id).expect("scheme 2 is registered"))
    }

    /// True when `script` pays this wallet as a YED holder: a P2PKH to an own key, or a
    /// `TX_PQPKH` to an own Falcon holder id (in `falcon`, from [`Wallet::own_falcon_holders`]).
    pub fn is_own_holder_script(
        script: &[u8],
        own: &HashSet<[u8; 20]>,
        falcon: &HashMap<crate::pq::PqKeyId, AddressRow>,
    ) -> bool {
        if let Some(h) = crate::script::p2pkh_hash(script) {
            return own.contains(&h);
        }
        crate::pq::pqpkh_of(script).is_some_and(|id| falcon.contains_key(&id))
    }

    /// The server's post-quantum terms as last read and accepted ([`Wallet::note_server_params`]);
    /// before any server has answered, [`PqTerms::default_for`] the network.
    ///
    /// **Mainnet and testnet: Falcon from day one** (owner decision 2026-10-10: `pqFalconHeight
    /// = 0`, [`crate::params::PQ_FALCON_HEIGHT_MAINNET`]). The expectation is compiled in and
    /// *checked*, not asserted over the server's answer: the offline default already says Falcon
    /// is active (so a YED holder is a Falcon key from the first block: receive address, change,
    /// mint tokens), and a server reporting another activation is refused
    /// ([`crate::build::terms::check_falcon_activation`]), leaving these terms unchanged. Regtest
    /// follows the server (`-pqfalconheight`), so the P2PKH holder paths stay testable before
    /// Falcon.
    ///
    /// [`PqTerms::default_for`]: crate::build::terms::PqTerms::default_for
    pub fn pq_terms(&self) -> crate::build::terms::PqTerms {
        *self.pq_terms.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// TOK-PQ is in force for the next block as far as this wallet knows (the last synced tip
    /// and the server's terms): its YED receive address is then its Falcon holder address.
    pub fn falcon_now(&self) -> bool {
        let tip = self.store.meta_u64("last_synced_height").unwrap_or(0);
        self.pq_terms().falcon_at(tip + 1)
    }

    /// Remember the post-quantum terms of a `GetYellowbackInfo.params` (rpcversion 7); refused
    /// (and nothing remembered) when they are missing or out of bounds, or (mainnet, testnet) when
    /// the Falcon activation is not this build's.
    pub fn note_server_params(
        &self,
        p: Option<&crate::net::rpc::YellowbackParams>,
    ) -> Result<crate::build::terms::PqTerms, crate::build::mint::MintError> {
        let t = crate::build::terms::pq_terms(
            p.ok_or_else(|| crate::build::mint::MintError::Inconsistent {
                what: "GetYellowbackInfo carries no params".into(),
            })?,
            self.network,
        )?;
        *self.pq_terms.lock().unwrap_or_else(|e| e.into_inner()) = t;
        // Remembered for an offline open (the receive address, the CLI): a failed write only
        // costs the default until the next server answer.
        let _ = self.store.set_meta(
            "pq_terms",
            &format!(
                "{} {} {} {} {} {} {}",
                t.fee_rate_zat_per_kb,
                t.falcon_height.map(|h| h as i64).unwrap_or(-1),
                u8::from(t.falcon_active),
                t.yed_rate_zat_per_kb,
                t.floor_rate_zat_per_kb,
                t.flat_zat,
                t.max_fee_zat
            ),
        );
        Ok(t)
    }

    /// The terms [`Wallet::note_server_params`] last remembered in the store, else
    /// [`crate::build::terms::PqTerms::default_for`] the network. On mainnet and testnet the
    /// Falcon activation is always the compiled one (a value an older build stored from a server
    /// it did not check is not believed).
    fn stored_pq_terms(store: &Store, network: Network) -> crate::build::terms::PqTerms {
        let dflt = crate::build::terms::PqTerms::default_for(network);
        let Some(mut t) = Wallet::stored_pq_terms_raw(store) else {
            return dflt;
        };
        if network.pq_falcon_height().is_some()
            && (t.falcon_height, t.falcon_active) != (dflt.falcon_height, dflt.falcon_active)
        {
            t.falcon_height = dflt.falcon_height;
            t.falcon_active = dflt.falcon_active;
        }
        t
    }

    /// The stored terms as written. A value written before rpcversion 8 (three fields) reads
    /// with the default rates for the rest.
    fn stored_pq_terms_raw(store: &Store) -> Option<crate::build::terms::PqTerms> {
        let v = store.meta("pq_terms").ok()??;
        let mut it = v.split(' ');
        let rate: i64 = it.next()?.parse().ok()?;
        let height: i64 = it.next()?.parse().ok()?;
        let active: u8 = it.next()?.parse().ok()?;
        let d = crate::build::terms::PqTerms::default();
        let mut next =
            |dflt: i64| -> i64 { it.next().and_then(|x| x.parse().ok()).unwrap_or(dflt) };
        let floor = crate::params::RELAY_FLOOR_ZAT_PER_KB;
        let yed = next(d.yed_rate_zat_per_kb).max(floor);
        let floor_rate = next(d.floor_rate_zat_per_kb).max(floor);
        let flat =
            next(d.flat_zat).clamp(crate::params::FEE_ZAT, crate::params::MAX_YED_TX_FEE_ZAT);
        let cap = next(d.max_fee_zat).clamp(flat, crate::params::MAX_YED_TX_FEE_ZAT);
        Some(crate::build::terms::PqTerms {
            fee_rate_zat_per_kb: rate.max(floor),
            yed_rate_zat_per_kb: yed,
            floor_rate_zat_per_kb: floor_rate,
            flat_zat: flat,
            max_fee_zat: cap,
            falcon_height: u64::try_from(height).ok(),
            falcon_active: active != 0,
        })
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
        let mut secret = k.secret.to_secret_bytes();
        let wrapped = crate::store::wrap_key(&self.wrap_secret.0, &k.hash160, &secret);
        keys::wipe(&mut secret);
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
        let mut pq: Vec<&Utxo> = spendable
            .iter()
            .filter(|u| u.class == coins::UtxoClass::PqOwned)
            .collect();
        pq.sort_by_key(|u| (u.height, u.outpoint.txid, u.outpoint.n));
        Ok(Balances {
            yec_pq_zat: coins::pq_yec_balance(&spendable),
            pq_coins: pq.iter().map(|u| u.outpoint).collect(),
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

    /// `mint_estimate(cents, lockBlocks)`: what the Mint screen shows, checked against the
    /// network's rules at `tip` (audit G-1); nothing is signed.
    pub async fn mint_estimate(
        &self,
        validator: &mut Validator,
        cents: u64,
        lock_blocks: u32,
        tip: u64,
    ) -> Result<MintEstimate, WalletError> {
        let yb = validator.client_mut().ok_or(GateError::YellowbackAbsent)?;
        mint::estimate(self, yb, cents, lock_blocks, tip).await
    }

    /// `mint_start(...)`: bundle, carrier funding transaction, the `mints` row. With
    /// `confirmed`, the terms must equal the estimate the user confirmed (audit G-2). Returns
    /// the `mint_id` to pass to [`Wallet::mint_finish`] once a sync has seen the carrier confirm.
    #[allow(clippy::too_many_arguments)]
    pub async fn mint_start(
        &self,
        client: &mut CompactClient,
        validator: &mut Validator,
        cents: u64,
        lock_blocks: u32,
        confirmed: Option<&ConfirmedTerms>,
        tip: u64,
        branch_id: u32,
    ) -> Result<i64, WalletError> {
        mint::start(
            self,
            client,
            validator,
            cents,
            lock_blocks,
            confirmed,
            tip,
            branch_id,
        )
        .await
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

    /// `redeem_preview(vaultTxid)`: build and sign the owner-path spend of an own open vault at
    /// or past `lockHeight` (a VOID vault is released). Nothing is broadcast: the preview
    /// carries the collateral returned, the enforcement fee and its payee, and the burn, for
    /// the screen to show before the slider (audit G-2).
    pub async fn redeem_preview(
        &self,
        validator: &mut Validator,
        vault_txid: &[u8; 32],
        tip: u64,
        branch_id: u32,
    ) -> Result<RedeemBuild, WalletError> {
        let yb = validator.client_mut().ok_or(GateError::YellowbackAbsent)?;
        redeem::build_redeem(self, yb, vault_txid, tip, branch_id).await
    }

    /// `redeem_confirm(preview)`: both gate layers, then broadcast the bytes of
    /// [`Wallet::redeem_preview`]. Returns the txid and the node's validation.
    pub async fn redeem_confirm(
        &self,
        client: &mut CompactClient,
        validator: &mut Validator,
        preview: &RedeemBuild,
    ) -> Result<(String, Validation), WalletError> {
        redeem::broadcast(self, client, validator, preview).await
    }

    /// `claimable()`: `ListClaimable` for the liquidator persona.
    pub async fn claimable(
        &self,
        validator: &mut Validator,
    ) -> Result<Vec<Claimable>, WalletError> {
        let yb = validator.client_mut().ok_or(GateError::YellowbackAbsent)?;
        claim::claimable(self.network, yb).await
    }

    /// `claim(vaultTxid)`: start the two-step claim (bundle, carrier funding transaction, the
    /// `mints` row of kind `Claim`). Returns the row id; [`Wallet::mint_finish`] sends the
    /// CLAIM once the carrier is confirmed. `bounds` are the debt and the take the Claimable
    /// screen showed (H-9.3): the claim is refused before signing when the server's numbers
    /// exceed them.
    #[allow(clippy::too_many_arguments)]
    pub async fn claim(
        &self,
        client: &mut CompactClient,
        validator: &mut Validator,
        vault_txid: &[u8; 32],
        bounds: Option<&ClaimBounds>,
        tip: u64,
        branch_id: u32,
    ) -> Result<i64, WalletError> {
        claim::start(self, client, validator, vault_txid, bounds, tip, branch_id).await
    }

    /// `intents()`: the claim intents paying this wallet (the vault upgrade, U-23) — the
    /// claimant's intent of each claim it made and the residual intent of each own claimed vault
    /// — newest first, with their release heights and states (pending, releasing, released,
    /// cancelled by the attestor set).
    pub fn intents(&self) -> Result<Vec<crate::store::IntentRow>, WalletError> {
        Ok(self.store.intents()?)
    }

    /// `release_preview(intent)`: build and sign the RELEASE of a matured intent (U-15) for the
    /// next block. Nothing is broadcast.
    pub fn release_preview(
        &self,
        intent: &crate::tx::OutPoint,
        tip: u64,
        branch_id: u32,
    ) -> Result<crate::build::release::ReleaseBuild, WalletError> {
        let Some(row) = self.store.intent(intent)? else {
            // Not an intent: an own post-quantum coin the sync found (`PQ_OWNED`) is moved the
            // same way as a released residual's.
            if self
                .store
                .utxo_class(intent)?
                .is_some_and(|c| c == crate::coins::UtxoClass::PqOwned)
            {
                return crate::build::release::build_pq_coin_move(self, intent, tip, branch_id);
            }
            return Err(WalletError::Other(
                "intent-unknown: not an intent of this wallet".into(),
            ));
        };
        crate::build::release::build_release(self, &row, tip, branch_id)
    }

    /// `release_confirm(preview)`: both gate layers, then broadcast the release.
    pub async fn release_confirm(
        &self,
        client: &mut CompactClient,
        validator: &mut Validator,
        preview: &crate::build::release::ReleaseBuild,
    ) -> Result<(String, Validation), WalletError> {
        crate::build::release::broadcast(self, client, validator, preview).await
    }

    /// The mint gate (hardening H-1, H-5): whether a mint can be made now and why not, from
    /// `GetYellowbackInfo` (its parameter set checked), `GetPrice` and `GetStats`.
    pub async fn mint_gate(&self, validator: &mut Validator) -> Result<MintGate, WalletError> {
        let yb = validator.client_mut().ok_or(GateError::YellowbackAbsent)?;
        mint::gate_now(self.network, yb).await
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

    /// Falcon YED holders (TOK-PQ): one per HD key (external i → i, change i → 2³¹ + i), from
    /// `DerivePQSeed(seed, 2, index)`, cached in the store, found back from their id, and the
    /// holder output follows the Falcon rule; an imported key has none.
    #[test]
    fn falcon_holders_pair_with_hd_keys() {
        assert_eq!(falcon_holder_index(Chain::External, 7), Some(7));
        assert_eq!(falcon_holder_index(Chain::Change, 7), Some(0x8000_0007));
        assert_eq!(falcon_holder_index(Chain::Change, 0x8000_0000), None);
        let w = wallet();
        let rows = w.addresses().unwrap();
        let ext0 = rows.iter().find(|r| r.chain == 0 && r.index == 0).unwrap();
        let chg0 = rows.iter().find(|r| r.chain == 1 && r.index == 0).unwrap();
        let a = w.falcon_holder_id(ext0).unwrap();
        let b = w.falcon_holder_id(chg0).unwrap();
        assert_eq!((a.scheme, b.scheme), (2, 2));
        assert_ne!(a, b);
        assert_eq!(a, w.pq_root.falcon_key(0).id());
        assert_eq!(b, w.pq_root.falcon_key(0x8000_0000).id());
        assert_eq!(w.store.pq_holder(0).unwrap(), Some(a));
        let addr = w.falcon_holder_address(ext0).unwrap();
        assert_eq!(addr.len(), 53);
        assert!(addr.starts_with("yr"));
        let key = w.falcon_key_for_id(&a).unwrap().unwrap();
        assert_eq!(key.id(), a);
        assert!(w
            .falcon_key_for_id(&crate::pq::PqKeyId {
                scheme: 2,
                hash: [1; 32]
            })
            .unwrap()
            .is_none());
        assert_eq!(
            w.yed_holder_script(ext0, true).unwrap(),
            crate::pq::pqpkh_script(&a).unwrap()
        );
        assert_eq!(
            w.yed_holder_script(ext0, false).unwrap(),
            crate::script::p2pkh_script(&ext0.hash160)
        );
        let own: HashSet<[u8; 20]> = rows.iter().map(|r| r.hash160).collect();
        let falcon = w.own_falcon_holders().unwrap();
        assert_eq!(falcon.len(), rows.len());
        assert!(Wallet::is_own_holder_script(
            &crate::pq::pqpkh_script(&b).unwrap(),
            &own,
            &falcon
        ));
        assert!(!Wallet::is_own_holder_script(
            &crate::pq::pqpkh_script(&crate::pq::PqKeyId {
                scheme: 2,
                hash: [1; 32]
            })
            .unwrap(),
            &own,
            &falcon
        ));
        // An imported key has no Falcon pair.
        let wif = keys::encode_wif(
            Network::Regtest,
            &secp256k1::SecretKey::from_secret_bytes([7; 32]).unwrap(),
        );
        let imp = w.import_wif(&wif).unwrap();
        assert!(w.falcon_holder_id(&imp).is_none());
        assert!(w.yed_holder_script(&imp, true).is_err());
    }

    /// The server's terms survive an offline reopen; mainnet and testnet are Falcon from day one
    /// (owner decision 2026-10-10) by the compiled default, and a server that disagrees is refused
    /// (LOW-06-Y-4), not overridden; regtest follows the server.
    #[test]
    fn pq_terms_persist_and_mainnet_is_falcon_from_day_one() {
        let seed = keys::seed_from_mnemonic(PHRASE, "").unwrap();
        let w = wallet();
        assert!(!w.falcon_now());
        let p = crate::net::rpc::YellowbackParams {
            pq: Some(crate::net::rpc::YellowbackPqParams {
                schemes: vec![1],
                falcon_active: false,
                falcon_height: 0,
                fee_rate_zat_per_kb: 300,
            }),
            fees: Some(crate::build::terms::fallback_fee_params(300)),
            ..Default::default()
        };
        w.note_server_params(Some(&p)).unwrap();
        assert!(w.falcon_now());
        let store = w.store;
        let w2 = Wallet::from_parts(store, Network::Regtest, &seed, None).unwrap();
        assert_eq!(w2.pq_terms().fee_rate_zat_per_kb, 300);
        assert!(w2.falcon_now());
        for net in [Network::Mainnet, Network::Testnet] {
            let m = Wallet::from_parts(Store::open_in_memory().unwrap(), net, &seed, None).unwrap();
            // offline: the compiled default, Falcon from height 0; the YED holder is a Falcon key
            assert!(m.falcon_now() && m.pq_terms().falcon_at(0) && m.pq_terms().falcon_at(1));
            assert_eq!(m.pq_terms(), crate::build::terms::PqTerms::default_for(net));
            let primary = m.receive_address(false).unwrap();
            let falcon = m.falcon_holder_id(&primary).unwrap();
            assert_eq!(
                m.yed_holder_script(&primary, m.falcon_now()).unwrap(),
                crate::pq::pqpkh_script(&falcon).unwrap()
            );
            // a server reporting Falcon inactive with scheme 2 absent (what the old override
            // masked): refused, and the wallet's terms do not change
            let err = m.note_server_params(Some(&p)).unwrap_err();
            assert!(
                matches!(err, crate::build::mint::MintError::Inconsistent { .. }),
                "{err}"
            );
            assert_eq!(m.pq_terms(), crate::build::terms::PqTerms::default_for(net));
            assert!(m.falcon_now());
            // a server reporting the compiled activation: accepted, its rates taken
            let mut good = p.clone();
            let q = good.pq.as_mut().unwrap();
            q.schemes = vec![1, 2];
            q.falcon_active = true;
            m.note_server_params(Some(&good)).unwrap();
            assert_eq!(m.pq_terms().fee_rate_zat_per_kb, 300);
            assert!(m.falcon_now());
            // a value an older build stored unchecked is not believed on reopen
            m.store
                .set_meta("pq_terms", "300 -1 0 300 300 1000 10000000")
                .unwrap();
            let store = m.store;
            let r = Wallet::from_parts(store, net, &seed, None).unwrap();
            assert!(r.falcon_now() && r.pq_terms().falcon_at(0));
            assert_eq!(r.pq_terms().fee_rate_zat_per_kb, 300);
        }
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

    /// The PQ owner chain (A-12 over the BIP39 seed, paired with the external index): the same
    /// mnemonic gives the same owners (restore), the key matches its cached id, and a change or
    /// foreign key has no owner.
    #[test]
    fn pq_owners_are_deterministic_and_paired_with_external_keys() {
        let w = wallet();
        let first = w.receive_address(false).unwrap();
        let (i, id) = w.pq_owner_for_hash(&first.hash160).unwrap().unwrap();
        assert_eq!(i, 0);
        // the seed is the 64-byte BIP39 seed: HKDF over it directly
        let seed = keys::seed_from_mnemonic(PHRASE, "").unwrap();
        let direct = crate::pq::PqSeedRoot::from_seed(&seed).slh_key(0);
        assert_eq!(direct.id(), id);
        let k = w.pq_key_for_owner(&id, &first.hash160).unwrap().unwrap();
        assert_eq!(k.id(), id);
        assert_eq!(w.pq_owner_id(1), w.pq_owner_key(1).id());
        assert_ne!(w.pq_owner_id(1), id);
        assert_eq!(
            wallet().pq_owner_id(0),
            id,
            "restore derives the same owner"
        );
        let change = w.change_address().unwrap();
        assert_eq!(w.pq_owner_for_hash(&change.hash160).unwrap(), None);
        assert!(w
            .pq_key_for_owner(&w.pq_owner_id(1), &first.hash160)
            .unwrap()
            .is_none());
        let owners = w.own_pq_owners().unwrap();
        assert_eq!(owners.get(&id), Some(&first.hash160));
        assert_eq!(owners.len(), GAP_LIMIT as usize);
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
