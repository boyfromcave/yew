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
    /// Keyed by the address ycashd keys its book by: `s…` for P2PKH, `sqf…`/`sqs…` (D-9) for a PQ
    /// holder.
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
    pub fn migrate_pq_book(&mut self, network: yew_core::params::Network) -> PqBookMigration {
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

/// What [`migrate_pq_book`] did: how many keys it rewrote, and the warnings to log (a dropped
/// label of a key the book held in both forms; an old-form key with an unregistered scheme byte,
/// left in the book as it is).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PqBookMigration {
    pub rewritten: usize,
    pub warnings: Vec<String>,
}

/// D-9: rewrite every address-book key written in the pre-D-9 post-quantum form (`sq…`/`tq…`/
/// `rq…` + a digit, `version2 ‖ scheme ‖ keyHash`) to the D-9 form of the same key (`sqf…`/
/// `sqs…`, …), as ycashd rewrites its address-book records once at load. The old form is never an
/// address, so no other key changes. When the book already holds the D-9 form of the same key,
/// that entry stays; it takes the old entry's label and purpose if its own label is empty, and
/// two different non-empty labels keep the new one with a warning naming both. An old-form key
/// whose scheme byte is outside the registry is left in the book, with a warning.
pub fn migrate_pq_book(
    book: &mut BTreeMap<String, BookEntry>,
    network: yew_core::params::Network,
) -> PqBookMigration {
    use yew_core::keys;
    let mut r = PqBookMigration::default();
    let (_, plain) = network.legacy_pq_versions();
    let mut old: Vec<(String, String)> = Vec::new();
    for a in book.keys() {
        match keys::parse_legacy_pq_address(network, a, false) {
            Some(id) => {
                if let Some(to) = keys::encode_pq_yec(network, &id) {
                    old.push((a.clone(), to));
                }
            }
            None => {
                // the old form's shape (35 bytes under the old version) with a scheme byte
                // outside the registry: kept, unread
                if let Ok(payload) = keys::base58check_decode(a) {
                    if payload.len() == 35 && payload[..2] == plain {
                        r.warnings.push(format!(
                            "address book: {a} is a pre-D-9 post-quantum address with the unregistered scheme byte {}; left as it is",
                            payload[2]
                        ));
                    }
                }
            }
        }
    }
    for (from, to) in &old {
        let Some(e) = book.remove(from) else { continue };
        match book.get_mut(to) {
            None => {
                book.insert(to.clone(), e);
            }
            Some(have) if have.label.is_empty() => {
                *have = e;
            }
            Some(have) => {
                if !e.label.is_empty() && e.label != have.label {
                    r.warnings.push(format!(
                        "address book: {from} and {to} are one key; kept the label {:?} of {to}, dropped {:?} of {from}",
                        have.label, e.label
                    ));
                }
            }
        }
        r.rewritten += 1;
    }
    r
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
        assert_eq!(migrate_pq_book(&mut book, net).rewritten, 2);
        assert_eq!(book.len(), 3);
        assert_eq!(book[&p2pkh].label, "ecc");
        for (i, id) in ids.iter().enumerate() {
            let a = keys::encode_pq_yec(net, id).unwrap();
            assert_eq!(book[&a].label, format!("pq{i}"));
        }
        assert_eq!(migrate_pq_book(&mut book, net), PqBookMigration::default());
    }
    fn old_form(net: Network, id: &PqKeyId) -> String {
        let mut old = net.legacy_pq_versions().1.to_vec();
        old.extend_from_slice(&id.to_bytes());
        keys::base58check_encode(&old)
    }

    fn entry(label: &str, purpose: &str) -> BookEntry {
        BookEntry {
            label: label.into(),
            purpose: purpose.into(),
        }
    }

    /// Review of stage 1, finding 1: a key the book holds in both forms keeps one entry, the D-9
    /// one; an empty new label takes the old label and purpose; two different labels keep the
    /// new one and warn naming both; equal labels warn nothing.
    #[test]
    fn migrate_pq_book_merges_a_key_held_in_both_forms() {
        let net = Network::Regtest;
        let id = |b: u8| PqKeyId {
            scheme: 2,
            hash: [b; 32],
        };
        let mut book = BTreeMap::new();
        // empty new label: the old entry wins
        book.insert(old_form(net, &id(1)), entry("old1", "send"));
        book.insert(
            keys::encode_pq_yec(net, &id(1)).unwrap(),
            entry("", "receive"),
        );
        // both labelled, different: the new one stays, with a warning
        book.insert(old_form(net, &id(2)), entry("old2", "send"));
        book.insert(
            keys::encode_pq_yec(net, &id(2)).unwrap(),
            entry("new2", "receive"),
        );
        // both labelled the same: no warning
        book.insert(old_form(net, &id(3)), entry("same", "receive"));
        book.insert(
            keys::encode_pq_yec(net, &id(3)).unwrap(),
            entry("same", "receive"),
        );
        let m = migrate_pq_book(&mut book, net);
        assert_eq!(m.rewritten, 3);
        assert_eq!(book.len(), 3);
        assert_eq!(
            book[&keys::encode_pq_yec(net, &id(1)).unwrap()],
            entry("old1", "send")
        );
        assert_eq!(
            book[&keys::encode_pq_yec(net, &id(2)).unwrap()],
            entry("new2", "receive")
        );
        assert_eq!(
            book[&keys::encode_pq_yec(net, &id(3)).unwrap()],
            entry("same", "receive")
        );
        assert_eq!(m.warnings.len(), 1, "{:?}", m.warnings);
        let w = &m.warnings[0];
        assert!(w.contains("\"new2\"") && w.contains("\"old2\""), "{w}");
        assert!(w.contains(&old_form(net, &id(2))), "{w}");
    }

    /// Review of stage 1, finding 2: an old-form key with a scheme byte outside the registry is
    /// left in the book and warned about once per load.
    #[test]
    fn migrate_pq_book_warns_on_an_unregistered_scheme() {
        let net = Network::Regtest;
        let mut payload = net.legacy_pq_versions().1.to_vec();
        payload.push(9);
        payload.extend_from_slice(&[4; 32]);
        let odd = keys::base58check_encode(&payload);
        let mut book = BTreeMap::new();
        book.insert(odd.clone(), entry("odd", "receive"));
        let m = migrate_pq_book(&mut book, net);
        assert_eq!(m.rewritten, 0);
        assert_eq!(m.warnings.len(), 1);
        assert!(m.warnings[0].contains(&odd) && m.warnings[0].contains("scheme byte 9"));
        assert_eq!(book[&odd], entry("odd", "receive"));
    }
}
