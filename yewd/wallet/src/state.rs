// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! What the wallet persists (`<datadir>/<net>/yewd/wallet.json`, written atomically after every
//! change): the public bundle, the issue counters and the address book, the processed tip with a
//! window of recent block hashes (the reorg fork-point search), and the wallet transactions
//! themselves (bytes and block position), from which every balance, coin and note is derived
//! again at load, as ycashd derives them from `mapWallet`. No secret is ever written here.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use yewd_proto::PublicBundle;

pub const STATE_FORMAT: &str = "yewd-wallet-1";
/// How many recent (height, hash) pairs are kept for the fork-point search. A reorg deeper
/// than this rescans from the birthday.
pub const RECENT: usize = 288;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tip {
    pub height: u32,
    pub hash: String,
}

/// Where a wallet transaction sits in the chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockRef {
    pub height: u32,
    pub hash: String,
    /// Its index in the block.
    pub index: u32,
    pub time: i64,
    /// The commitment-tree position of its first Sapling output (when it has outputs of ours).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sapling_pos: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletTx {
    pub hex: String,
    /// `None` while in the mempool.
    pub block: Option<BlockRef>,
    pub time_received: i64,
}

/// An address-book entry (ycashd's `mapAddressBook`): the label and the purpose
/// (`receive`, or `yed` for `yed_getnewaddress`, ycashd's `YED_RECEIVE_PURPOSE`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BookEntry {
    pub label: String,
    pub purpose: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Issued {
    /// Next external / internal index to hand out.
    pub external: u32,
    pub internal: u32,
    /// Next PQ index per scheme (`"1"`, `"2"`).
    pub pq: BTreeMap<String, u32>,
    /// The diversifier indices `z_getnewaddress` handed out, in order.
    pub sapling: Vec<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub format: String,
    pub network: String,
    pub public: PublicBundle,
    pub birthday: u32,
    pub created: i64,
    pub issued: Issued,
    /// Keyed by the address ycashd keys its book by: `s…` for P2PKH, `sq…` for a PQ holder.
    pub book: BTreeMap<String, BookEntry>,
    /// PQ owner keys handed out (`vault_getnewowner`, `yed_getnewaddress "pqowner"`), pqkeyid hex.
    pub owners: BTreeSet<String>,
    pub tip: Option<Tip>,
    pub recent: Vec<Tip>,
    pub wtx: BTreeMap<String, WalletTx>,
    /// Locked outpoints (`txid:n`), as ycashd's `setLockedCoins`; persisted (ycashd keeps them in
    /// memory only, but the coins its vault builds lock are re-locked from `mapVaultBuilds` at
    /// load: the same set survives a restart).
    pub locks: BTreeSet<String>,
    /// The remembered vault and act builds (ycashd `mapVaultBuilds`, the `vaultbuild` row, 07/N-2):
    /// template outpoint (or an act's `vin[0]`) → the unsigned transaction, hex.
    #[serde(default)]
    pub builds: BTreeMap<String, String>,
    /// The intent recipients this wallet built (`mapVaultRecipients`): recipient hash (raw hex) →
    /// the recipient script, hex.
    #[serde(default)]
    pub recipients: BTreeMap<String, String>,
    /// The v3 carriers this wallet funded (ycashd `carriers.dat`, W7): carrier outpoint → record,
    /// until the MINT/CLAIM spends it or `yed_sweepcarriers` reclaims it.
    #[serde(default)]
    pub carriers: BTreeMap<String, CarrierRec>,
    /// Own transactions with a payload that left the mempool unmined (txid → hex): the
    /// `"expired": true` rows of `yed_listtransactions` once past their expiry height (§4.6).
    #[serde(default)]
    pub expired: BTreeMap<String, String>,
    /// Own transactions that left the mempool unmined (an eviction, an expiry): ycashd keeps them
    /// in `mapWallet`, so `gettransaction` still answers for them (txid → the record).
    #[serde(default)]
    pub evicted: BTreeMap<String, WalletTx>,
    /// Redeem scripts this wallet knows (`addmultisigaddress`): P2SH address → script hex.
    #[serde(default)]
    pub scripts: BTreeMap<String, String>,
}

/// A carrier (`CarrierRecord`): its key (external chain index), the bundle it commits to, its
/// reference height and selector.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CarrierRec {
    pub index: u32,
    /// The compressed public key, hex.
    pub pk: String,
    /// The bundle bytes, hex (empty while unarmed).
    pub bundle: String,
    pub ref_height: i64,
    /// The selector, hex (empty for a MINT).
    pub selector: String,
    pub created_height: i64,
}

impl State {
    pub fn new(public: PublicBundle, birthday: u32, now: i64) -> State {
        State {
            format: STATE_FORMAT.into(),
            network: public.network.clone(),
            public,
            birthday,
            created: now,
            issued: Issued::default(),
            book: BTreeMap::new(),
            owners: BTreeSet::new(),
            tip: None,
            recent: Vec::new(),
            wtx: BTreeMap::new(),
            locks: BTreeSet::new(),
            builds: BTreeMap::new(),
            recipients: BTreeMap::new(),
            carriers: BTreeMap::new(),
            expired: BTreeMap::new(),
            evicted: BTreeMap::new(),
            scripts: BTreeMap::new(),
        }
    }

    pub fn pq_issued(&self, scheme: u8) -> u32 {
        self.issued
            .pq
            .get(&scheme.to_string())
            .copied()
            .unwrap_or(0)
    }

    pub fn set_pq_issued(&mut self, scheme: u8, next: u32) {
        self.issued.pq.insert(scheme.to_string(), next);
    }

    pub fn load(path: &Path) -> Result<Option<State>, String> {
        match std::fs::read_to_string(path) {
            Ok(t) => {
                let s: State =
                    serde_json::from_str(&t).map_err(|e| format!("{}: {e}", path.display()))?;
                if s.format != STATE_FORMAT {
                    return Err(format!("{}: unknown format {}", path.display(), s.format));
                }
                Ok(Some(s))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    /// D-9: see [`migrate_pq_book`].
    pub fn migrate_pq_book(&mut self, network: yew_core::params::Network) -> usize {
        migrate_pq_book(&mut self.book, network)
    }

    /// Write atomically (temporary file, fsync, rename).
    pub fn save(&self, path: &Path) -> Result<(), String> {
        use std::io::Write;
        let dir = path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let tmp = path.with_extension("json.tmp");
        let text = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        let mut f = std::fs::File::create(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
        f.write_all(&text)
            .and_then(|_| f.sync_all())
            .map_err(|e| format!("{}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
    }
}

/// D-9: rewrite every address-book key written in the pre-D-9 post-quantum form (`sq…`/`tq…`/
/// `rq…` + a digit, `version2 ‖ scheme ‖ keyHash`) to the D-9 form of the same key (`sqf…`/
/// `sqs…`, …), as ycashd rewrites its address-book records once at load. The old form is never an
/// address, so no other key changes. Returns how many keys were rewritten.
pub fn migrate_pq_book(
    book: &mut BTreeMap<String, BookEntry>,
    network: yew_core::params::Network,
) -> usize {
    use yew_core::keys;
    let old: Vec<(String, String)> = book
        .keys()
        .filter_map(|a| {
            let id = keys::parse_legacy_pq_address(network, a, false)?;
            Some((a.clone(), keys::encode_pq_yec(network, &id)?))
        })
        .collect();
    for (from, to) in &old {
        if let Some(e) = book.remove(from) {
            book.entry(to.clone()).or_insert(e);
        }
    }
    old.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use yew_core::keys;
    use yew_core::params::Network;
    use yew_core::pq::PqKeyId;

    /// D-9: a book written before D-9 keys a post-quantum address by its old form; at load it is
    /// keyed by the D-9 form of the same key, its label and purpose kept, every other key as is.
    #[test]
    fn migrate_pq_book_rewrites_the_pre_d9_form() {
        let net = Network::Regtest;
        let mut book = BTreeMap::new();
        let entry = |l: &str| BookEntry {
            label: l.into(),
            purpose: "receive".into(),
        };
        let ids = [1u8, 2].map(|scheme| PqKeyId {
            scheme,
            hash: [scheme * 7; 32],
        });
        for (i, id) in ids.iter().enumerate() {
            let mut old = net.legacy_pq_versions().1.to_vec();
            old.extend_from_slice(&id.to_bytes());
            book.insert(keys::base58check_encode(&old), entry(&format!("pq{i}")));
        }
        let p2pkh = keys::encode_p2pkh(net, &[5; 20]);
        book.insert(p2pkh.clone(), entry("ecc"));
        assert_eq!(migrate_pq_book(&mut book, net), 2);
        assert_eq!(book.len(), 3);
        assert_eq!(book[&p2pkh].label, "ecc");
        for (i, id) in ids.iter().enumerate() {
            let a = keys::encode_pq_yec(net, id).unwrap();
            assert_eq!(book[&a].label, format!("pq{i}"));
        }
        assert_eq!(migrate_pq_book(&mut book, net), 0);
    }
}
