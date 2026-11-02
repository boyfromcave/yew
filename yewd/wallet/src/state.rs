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
    /// Locked outpoints (`txid:n`), as ycashd's `setLockedCoins`.
    pub locks: BTreeSet<String>,
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
