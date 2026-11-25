// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The wallet file: `<datadir>/wallet.json`. It never holds the seed (decision record
//! `docs/yugen-seed-at-rest.md`): the seed reaches the engine per call on an inherited file
//! descriptor (`-seedfd=N`), and the file keeps only a fingerprint of it. A file written before
//! that rule (a `seed` field) is read once, and rewritten without it, its old content overwritten.
//! Written atomically (temporary file, fsync, rename, directory fsync) with mode 0600.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use yugen_ref::keys::AddrId;
use yugen_ref::note::Note;
use yugen_ref::tree::Tree;

use crate::{B32, B48};

pub fn h<const N: usize>(s: &str) -> [u8; N] {
    hex::decode(s).ok().and_then(|v| v.try_into().ok()).unwrap_or_else(|| panic!("hex of {N} bytes: {s}"))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NoteRec {
    /// AddrId as 7 bytes hex (kind, LE32 a, LE16 b).
    pub d: String,
    pub v: u64,
    pub auth: String,
    pub nkc: String,
    pub rho: String,
    pub rcm: String,
    pub pos: u64,
    pub height: u32,
    pub txid: String,
    pub nf: String,
    pub spent_in: Option<String>,
    /// Pending spend submitted (txid), cleared if the transfer expires.
    pub pending: Option<String>,
    /// The membership path recomputed to the root after the block matched (spec §7.7).
    pub applied: bool,
    /// The 512-byte memo of a note package (§10.1), hex; absent for no memo.
    #[serde(default)]
    pub memo: Option<String>,
}

impl NoteRec {
    /// The memo as text: trailing zero bytes removed, UTF-8 (lossy).
    pub fn memo_text(&self) -> Option<String> {
        let b = hex::decode(self.memo.as_ref()?).ok()?;
        let end = b.iter().rposition(|&x| x != 0).map(|i| i + 1).unwrap_or(0);
        Some(String::from_utf8_lossy(&b[..end]).into_owned())
    }
    pub fn note(&self) -> Note {
        Note { asset: 0, v: self.v, auth: h(&self.auth), nkc: h(&self.nkc), rho: h(&self.rho), rcm: h(&self.rcm) }
    }
    pub fn addr(&self) -> AddrId {
        let b: [u8; 7] = h(&self.d);
        AddrId { kind: b[0], a: u32::from_le_bytes(b[1..5].try_into().unwrap()), b: u16::from_le_bytes([b[5], b[6]]) }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Utxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub spent: bool,
}

/// The hex seed of an earlier version's state file: zeroed when dropped, never printed.
#[derive(Clone, Default, Deserialize)]
#[serde(transparent)]
pub struct LegacySeed(pub String);
impl LegacySeed {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn clear(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}
impl Drop for LegacySeed {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}
impl std::fmt::Debug for LegacySeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0.is_empty() { "none" } else { "<redacted>" })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Store {
    /// The seed of a file written before seeds left it (read for migration, never written).
    #[serde(default, rename = "seed", skip_serializing)]
    pub legacy_seed: LegacySeed,
    /// `seed_fingerprint` of the account seed: refuses a call with another seed.
    #[serde(default)]
    pub seed_fp: String,
    pub network: u8,
    /// Last block height applied (None: nothing scanned).
    pub scanned: Option<u32>,
    /// Note-tree leaves (cm) in position order, and the tree size after each scanned height.
    pub leaves: Vec<String>,
    pub sizes: BTreeMap<u32, u64>,
    /// Issued payment requests (day, c).
    pub requests: Vec<(u32, u16)>,
    pub next_change: u32,
    pub otag_counters: BTreeMap<u32, u32>,
    /// Unused since the dummy rule reads the chain (spec §5.6); kept so older files load.
    #[serde(default, skip_serializing)]
    pub dummy_counter: u32,
    /// The next dummy counter per anchor height (§5.6), for recent anchors.
    #[serde(default)]
    pub dummy_next: BTreeMap<u32, u32>,
    pub notes: Vec<NoteRec>,
    pub deposit_utxos: Vec<Utxo>,
    /// Requests this wallet has paid (hex `k`): a payer pays a request once (§9.1; UX-1 P-3).
    #[serde(default)]
    pub paid_requests: Vec<String>,
    /// The boundary of the last host session (§17.8 item 1); None before the first.
    #[serde(default)]
    pub host_synced: Option<u32>,
    /// Payments to short addresses waiting for the sync session that resolves them (ruling 16).
    #[serde(default)]
    pub pending_sends: Vec<PendingSend>,
    /// Short addresses already resolved (hex `flags || short` -> full address hex, §12.2/§12.3).
    #[serde(default)]
    pub resolved: BTreeMap<String, String>,
}

/// A payment to a short Yugen address queued until a scheduled sync resolves it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingSend {
    pub id: u32,
    pub to: String,
    pub amount: u64,
    pub memo: Option<String>,
    /// Tip height when queued.
    pub queued: u32,
    /// "waiting" | "sent" | "failed" | "invalid-record"
    pub state: String,
    pub txid: Option<String>,
    pub error: Option<String>,
}

impl Store {
    pub fn path(dir: &Path) -> PathBuf {
        dir.join("wallet.json")
    }
    pub fn load(dir: &Path) -> Option<Store> {
        // the file may hold a legacy seed: the buffer is zeroed after parsing
        let b = zeroize::Zeroizing::new(std::fs::read(Self::path(dir)).ok()?);
        serde_json::from_slice(&b).ok()
    }
    pub fn save(&self, dir: &Path) -> std::io::Result<()> {
        // a file with the old `seed` field is overwritten in place before it is replaced
        write_private(dir, "wallet.json", &serde_json::to_vec_pretty(self)?, !self.legacy_seed.is_empty())
    }
    pub fn leaf(&self, i: usize) -> B48 {
        h(&self.leaves[i])
    }
    /// Tree size after block `height` (the last scanned height at or below it).
    pub fn size_at(&self, height: u32) -> u64 {
        self.sizes.range(..=height).next_back().map(|(_, s)| *s).unwrap_or(0)
    }
    /// The tree as of the end of block `height`.
    pub fn tree_at(&self, height: u32) -> Tree {
        let mut t = Tree::new();
        for i in 0..self.size_at(height) as usize {
            t.append(&self.leaf(i));
        }
        t
    }
    pub fn balance(&self) -> u64 {
        self.spendable().iter().map(|n| n.v).sum()
    }
    pub fn spendable(&self) -> Vec<&NoteRec> {
        self.notes.iter().filter(|n| n.applied && n.spent_in.is_none() && n.pending.is_none() && n.v > 0).collect()
    }
    pub fn next_otag(&mut self, epoch: u32) -> u32 {
        let c = self.otag_counters.entry(epoch).or_insert(0);
        *c += 1;
        *c - 1
    }
}

pub fn hx(b: &[u8]) -> String {
    hex::encode(b)
}
pub fn addr_hex(d: AddrId) -> String {
    hex::encode(d.to_bytes())
}
pub type Hash32 = B32;

/// `BLAKE2b-256("Ycash_YugenSd_FP", seed)`: identifies a seed without revealing it.
pub fn seed_fingerprint(seed: &[u8]) -> String {
    hex::encode(blake2b_simd::Params::new().hash_length(32).personal(b"Ycash_YugenSd_FP").hash(seed).as_bytes())
}

/// Writes `dir/name` atomically with mode 0600: a temporary file created 0600, written and
/// synced (F_FULLFSYNC on macOS: `sync_all`), renamed over the target, then the directory synced.
/// The directory is made 0700. With `scrub_old` the file being replaced held a seed: it is opened
/// first (O_NOFOLLOW, a regular file only), and only after the rename and the directory sync is
/// the old inode, still open, overwritten with zeros and synced; a crash leaves either the old file
/// whole or the new one in place.
pub fn write_private(dir: &Path, name: &str, bytes: &[u8], scrub_old: bool) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    let old = if scrub_old { open_regular_nofollow(&dir.join(name)) } else { None };
    let tmp = dir.join(format!("{name}.tmp"));
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc_nofollow()).open(&tmp)?;
    f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, dir.join(name))?;
    std::fs::File::open(dir)?.sync_all()?;
    if let Some(f) = old {
        zero_file(f)?;
    }
    Ok(())
}

fn libc_nofollow() -> i32 {
    libc::O_NOFOLLOW
}

/// The file at `p` opened for writing without following a symbolic link, if it is a regular file with one link.
fn open_regular_nofollow(p: &Path) -> Option<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new().write(true).custom_flags(libc_nofollow()).open(p).ok()?;
    // a regular file with a single link only: zeroing another link's content is not ours to do
    f.metadata().ok().filter(|m| m.file_type().is_file() && std::os::unix::fs::MetadataExt::nlink(m) == 1).map(|_| f)
}

fn zero_file(mut f: std::fs::File) -> std::io::Result<()> {
    use std::io::{Seek, Write};
    let n = f.metadata()?.len() as usize;
    f.seek(std::io::SeekFrom::Start(0))?;
    f.write_all(&vec![0u8; n])?;
    f.sync_all()
}

/// Overwrites a file's content with zeros and syncs it (best effort against a plain undelete;
/// copy-on-write file systems and SSD remapping can keep old blocks, stated in the record).
/// A symbolic link or anything but a regular file is left alone.
pub fn scrub(p: &Path) -> std::io::Result<()> {
    match open_regular_nofollow(p) {
        Some(f) => zero_file(f),
        None => Ok(()),
    }
}

/// Constant-time equality (no early exit on the first differing byte).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// Reads the seed from inherited descriptor `fd` and closes it: hex (64 to 128 characters) ended by
/// `'\n'`, read byte by byte into a fixed buffer that is zeroed on drop; never read to end of file, so
/// a writer that keeps the pipe open cannot stall the engine and nothing past the newline is consumed.
pub fn read_seed_fd(fd: i32) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
    use std::os::fd::FromRawFd;
    if fd < 3 {
        return Err("-seedfd: a descriptor above 2".into());
    }
    // SAFETY: the descriptor is inherited for this purpose and owned (and closed) here alone.
    let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut buf = zeroize::Zeroizing::new([0u8; 128]);
    let mut n = 0usize;
    let mut b = zeroize::Zeroizing::new([0u8; 1]);
    loop {
        match std::io::Read::read(&mut f, &mut b[..]) {
            Ok(0) => return Err("-seedfd: the seed must end with a newline".into()),
            Ok(_) if b[0] == b'\n' => break,
            Ok(_) if n < buf.len() => {
                buf[n] = b[0];
                n += 1;
            }
            Ok(_) => return Err("-seedfd: the seed must be 32 to 64 bytes".into()),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("-seedfd: {e}")),
        }
    }
    if n < 64 || n % 2 != 0 {
        return Err("-seedfd: the seed must be 32 to 64 bytes".into());
    }
    let mut out = zeroize::Zeroizing::new(vec![0u8; n / 2]);
    hex::decode_to_slice(&buf[..n], &mut out[..]).map_err(|_| "-seedfd: the seed is not hex")?;
    Ok(out)
}

