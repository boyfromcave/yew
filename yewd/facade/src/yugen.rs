//! The `yugen_*` RPCs (beta4 Yugen addendum §3.2; names: clones/INTERFACES.md, section W final):
//! answered by the Yugen wallet engine `yewd-yugen` (yew/yewd/yugen), run once per call as a
//! child process against the same backend, with its data in `<netdir>/yugen/`.

use std::path::PathBuf;
use std::sync::OnceLock;

use serde_json::{json, Value};

use crate::config::{BackendAuth, Config, Network};

pub struct YugenCfg {
    pub bin: PathBuf,
    pub args: Vec<String>,
    /// `-backendrpcuser/-backendrpcpassword`: written per call to a 0600 cookie-format file the
    /// engine reads (`-rpccookiefile`), never put on the command line (visible to every local user).
    pub userpass: Option<yew_core::keys::SecretString>,
    /// The engine's data directory (`<netdir>/yugen`).
    pub dir: PathBuf,
}

static CFG: OnceLock<YugenCfg> = OnceLock::new();
/// The wallet whose signer gives the Yugen seed per engine call (decision record
/// `yugen/docs/yugen-seed-at-rest.md`).
static WALLET: OnceLock<std::sync::Arc<crate::wallet::WalletService>> = OnceLock::new();

/// Records the wallet service (called once at start, after it is made).
pub fn set_wallet(w: std::sync::Arc<crate::wallet::WalletService>) {
    let _ = WALLET.set(w);
}

/// Records how to run the engine (called once at start).
pub fn init(cfg: &Config) {
    let _ = yewd_wallet::admin::YUGEN_SEALED.set(yewd_wallet::admin::YugenSealed { export: export_sealed, import: import_sealed });
    let exe = std::env::current_exe().unwrap_or_default();
    let dir = exe.parent().map(PathBuf::from).unwrap_or_default();
    let candidates = [
        cfg.yugen_bin.clone(),
        Some(dir.join("yewd-yugen")),
        // yewd/target/<profile>/yewd -> yewd/yugen/target/{release,debug}/yewd-yugen
        dir.parent().and_then(|t| t.parent()).map(|y| y.join("yugen/target/release/yewd-yugen")),
        dir.parent().and_then(|t| t.parent()).map(|y| y.join("yugen/target/debug/yewd-yugen")),
    ];
    let bin = candidates.into_iter().flatten().find(|p| p.is_file()).unwrap_or_else(|| PathBuf::from("yewd-yugen"));
    let ydir = cfg.datadir.join(cfg.network.subdir()).join("yugen");
    let mut args = vec![
        format!("-datadir={}", ydir.display()),
        format!("-node={}", cfg.backend),
        format!("-network={}", match cfg.network { Network::Main => "main", Network::Test => "testnet", Network::Regtest => "regtest" }),
    ];
    let userpass = match &cfg.backend_auth {
        BackendAuth::Cookie(p) => {
            args.push(format!("-rpccookiefile={}", p.display()));
            None
        }
        BackendAuth::UserPass(u, p) => Some(yew_core::keys::SecretString::new(format!("{u}:{p}"))),
    };
    if let Some(h) = &cfg.yugen_hosts {
        args.push(format!("-yugenhosts={h}"));
    }
    let _ = CFG.set(YugenCfg { bin, args, userpass, dir: ydir });
}

pub fn is_yugen(method: &str) -> bool {
    method.starts_with("yugen_")
}

/// One engine run at a time: the scheduler's sync and the user's calls share `wallet.json`. A
/// std mutex taken inside the blocking task, which owns the child: a caller's future that is
/// dropped (cancelled) leaves the task running, so the lock is released only when the child has
/// exited (never while it still writes `wallet.json`).
static ENGINE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Held (write) while a pipe that carries a secret exists without close-on-exec, and (read) by
/// every other process spawn of yewd (`spawn_guarded`), so no other child can inherit it. macOS has
/// no pipe2(O_CLOEXEC).
pub static SPAWN_LOCK: std::sync::RwLock<()> = std::sync::RwLock::new(());

/// `cmd.spawn()` under the read side of `SPAWN_LOCK`.
pub fn spawn_guarded(cmd: &mut std::process::Command) -> std::io::Result<std::process::Child> {
    let _g = SPAWN_LOCK.read().unwrap_or_else(|e| e.into_inner());
    cmd.spawn()
}

/// Runs `yewd-yugen <method> <params>`; `Err((code, message))` on failure. The account seed
/// comes from the signer for this call only (refused with -13 while the wallet is locked) and
/// reaches the engine on an inherited pipe as fd 3 (`-seedfd=3`): never argv, env or a file.
pub async fn engine(method: &str, params: Value) -> Result<Value, (i64, String)> {
    let c = CFG.get().ok_or((-1, "yugen engine not configured".to_string()))?;
    let w = WALLET.get().ok_or((-1, "yugen engine: no wallet".to_string()))?;
    let derived = match w.yugen_seed().await {
        Ok(d) => d,
        Err(e) => {
            if e.code == -13 {
                if let Some(m) = legacy_plain_warning(&c.dir) {
                    if !LEGACY_WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                        eprintln!("{m}");
                    }
                }
            }
            return Err((e.code, e.message));
        }
    };
    let (bin, mut args, dir) = (c.bin.clone(), c.args.clone(), c.dir.clone());
    args.push("-seedfd=3".into());
    args.push(method.to_string());
    args.push(params.to_string());
    let out = tokio::task::spawn_blocking(move || -> Result<std::process::Output, (i64, String)> {
        let _g = ENGINE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let seed = account_seed(&dir, &derived).map_err(|e| (-4, e))?;
        let cred = match CFG.get().and_then(|c| c.userpass.as_ref()) {
            Some(up) => Some(CredFile::new(&dir, up).map_err(|e| (-1, format!("cannot write the engine's credential file: {e}")))?),
            None => None,
        };
        if let Some(f) = &cred {
            args.insert(0, format!("-rpccookiefile={}", f.0.display()));
        }
        run_with_seed(&bin, &args, &seed).map_err(|e| (-1, format!("cannot run the Yugen engine: {e}")))
    })
    .await
    .map_err(|e| (-1, e.to_string()))??;
    let v: Value = serde_json::from_slice(&out.stdout).map_err(|_| (-1, String::from_utf8_lossy(&out.stderr).into_owned()))?;
    match v.get("error") {
        Some(Value::String(e)) if !out.status.success() => Err((-4, e.clone())),
        _ => Ok(v),
    }
}

static LEGACY_WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The warning for a plain seed of an earlier yewd still in `wallet.json` while the wallet is
/// locked (it moves into `legacy-seed.sealed` at the first engine call after `walletpassphrase`).
fn legacy_plain_warning(dir: &std::path::Path) -> Option<String> {
    let p = dir.join("wallet.json");
    let b = read_or_absent(&p).ok()??;
    let mut v = serde_json::from_slice::<Value>(&b).ok()?;
    let held = match v.get_mut("seed") {
        Some(Value::String(s)) => {
            drop(yew_core::keys::SecretString::new(std::mem::take(s)));
            true
        }
        _ => false,
    };
    held.then(|| {
        format!(
            "yewd: WARNING: {} still holds the Yugen seed of an earlier yewd in plain text while the wallet is locked; \
             unlock the wallet (walletpassphrase) so the next Yugen call seals it",
            p.display()
        )
    })
}

/// A 0600 `user:password` file for one engine call, removed when dropped.
struct CredFile(PathBuf);
impl CredFile {
    fn new(dir: &std::path::Path, up: &str) -> std::io::Result<Self> {
        use std::io::Write;
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
        let mut r = [0u8; 8];
        getrandom::getrandom(&mut r).map_err(|e| std::io::Error::other(e.to_string()))?;
        let p = dir.join(format!(".rpccred-{}", hex::encode(r)));
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(&p)?;
        let c = CredFile(p);
        f.write_all(up.as_bytes())?;
        Ok(c)
    }
}
impl Drop for CredFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Runs the engine with `seed` (hex) on a pipe that the child sees as fd 3, framed as hex and a
/// newline (the engine reads to the newline). Both pipe ends are made close-on-exec while
/// `SPAWN_LOCK` is held for writing (no other spawn of this process can fork in between); the
/// child's `dup2` onto 3 clears the flag on its copy only, and the child closes every descriptor
/// from 4 up that is not close-on-exec before exec.
fn run_with_seed(bin: &std::path::Path, args: &[String], seed: &str) -> std::io::Result<std::process::Output> {
    use std::io::Write;
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::os::unix::process::CommandExt;
    let mut fds = [0i32; 2];
    let (r, wr) = {
        let _g = SPAWN_LOCK.write().unwrap_or_else(|e| e.into_inner());
        // SAFETY: `fds` has room for the two descriptors pipe() writes.
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        for fd in fds {
            // SAFETY: fd is open (just made).
            unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
        }
        // SAFETY: pipe() returned two fresh descriptors owned here alone.
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
    };
    {
        let mut f = std::fs::File::from(wr);
        let mut framed = zeroize::Zeroizing::new(Vec::with_capacity(seed.len() + 1));
        framed.extend_from_slice(seed.as_bytes());
        framed.push(b'\n');
        f.write_all(&framed)?; // 65 to 129 bytes: well inside the pipe buffer
    }
    let rfd = fds[0];
    let mut cmd = std::process::Command::new(bin);
    cmd.args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    // SAFETY: dup2, fcntl, close and sysconf are async-signal-safe; this runs in the child between
    // fork and exec.
    unsafe {
        cmd.pre_exec(move || {
            let ok = if rfd == 3 { libc::fcntl(3, libc::F_SETFD, 0) >= 0 } else { libc::dup2(rfd, 3) >= 0 };
            if !ok {
                return Err(std::io::Error::last_os_error());
            }
            let max = libc::sysconf(libc::_SC_OPEN_MAX);
            let max = if max > 0 { max.min(1 << 16) as i32 } else { 1024 };
            for fd in 4..max {
                let fl = libc::fcntl(fd, libc::F_GETFD);
                // close-on-exec descriptors (std's own exec-error pipe among them) close at exec
                if fl >= 0 && fl & libc::FD_CLOEXEC == 0 {
                    libc::close(fd);
                }
            }
            Ok(())
        });
    }
    let out = spawn_guarded(&mut cmd).and_then(|c| c.wait_with_output());
    drop(r);
    out
}

/// Constant-time equality of two hex strings (no early exit on the first differing byte).
fn ct_eq_str(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

fn read_or_absent(p: &std::path::Path) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, String> {
    match std::fs::read(p) {
        Ok(b) => Ok(Some(zeroize::Zeroizing::new(b))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", p.display())),
    }
}

/// The seed the engine's state was made with: the derived seed (N-A2), or, for a state written
/// by an earlier yewd with its own random seed, that seed, kept from then on in
/// `legacy-seed.sealed` encrypted under a key derived from the derived seed (so it is as safe as
/// the wallet's phrase: sealed with it, unlocked with it) and removed from `wallet.json` by the
/// engine on the call that follows. Any read error other than "not found" is an error (never a
/// silent fall-back to the derived seed). The sealed seed is also in the wallet's backup
/// (`legacy_seed_hex`, the signer's dump; decision record Y-W12).
fn account_seed(dir: &std::path::Path, derived: &str) -> Result<yew_core::keys::SecretString, String> {
    use chacha20poly1305::aead::Aead;
    use chacha20poly1305::Nonce;
    let aead = wrap_aead(derived)?;
    if let Some(plain) = unseal(dir, &aead)? {
        return Ok(plain);
    }
    let legacy = match read_or_absent(&dir.join("wallet.json"))? {
        Some(b) => {
            let mut v = serde_json::from_slice::<Value>(&b).map_err(|_| "wallet.json: damaged (not JSON)".to_string())?;
            match v.get_mut("seed") {
                Some(Value::String(s)) => Some(yew_core::keys::SecretString::new(std::mem::take(s))),
                _ => None,
            }
        }
        None => None,
    };
    match legacy {
        Some(l) if !ct_eq_str(&l, derived) => {
            let mut lb = zeroize::Zeroizing::new(hex::decode(&*l).map_err(|_| "wallet.json: the old seed is not hex")?);
            let mut nonce = [0u8; 12];
            getrandom::getrandom(&mut nonce).map_err(|e| e.to_string())?;
            let ct = aead.encrypt(Nonce::from_slice(&nonce), lb.as_slice()).map_err(|_| "seal failed")?;
            yew_core::keys::wipe(&mut lb);
            let mut out = nonce.to_vec();
            out.extend_from_slice(&ct);
            write_private(dir, "legacy-seed.sealed", &out).map_err(|e| e.to_string())?;
            Ok(l)
        }
        _ => Ok(yew_core::keys::SecretString::new(derived.to_string())),
    }
}

/// The key that seals `legacy-seed.sealed`: BLAKE2b-256("Ycash_YugenWrap_", derived seed); the
/// hash value is wiped once the cipher is keyed.
fn wrap_aead(derived: &str) -> Result<chacha20poly1305::ChaCha20Poly1305, String> {
    use chacha20poly1305::aead::KeyInit;
    use chacha20poly1305::{ChaCha20Poly1305, Key};
    let mut dbytes = zeroize::Zeroizing::new(hex::decode(derived).map_err(|_| "the signer's Yugen seed is not hex")?);
    let mut k = blake2b_simd::Params::new().hash_length(32).personal(b"Ycash_YugenWrap_").hash(&dbytes);
    yew_core::keys::wipe(&mut dbytes);
    let mut kb = zeroize::Zeroizing::new([0u8; 32]);
    kb.copy_from_slice(k.as_bytes());
    // SAFETY: blake2b_simd::Hash is plain bytes and a length; zeroing it leaves a valid value
    // (length 0 is never read again).
    unsafe { std::ptr::write_volatile(&mut k as *mut blake2b_simd::Hash, std::mem::zeroed()) };
    Ok(ChaCha20Poly1305::new(Key::from_slice(&kb[..])))
}

/// The seed sealed in `legacy-seed.sealed`, if the file exists.
fn unseal(dir: &std::path::Path, aead: &chacha20poly1305::ChaCha20Poly1305) -> Result<Option<yew_core::keys::SecretString>, String> {
    use chacha20poly1305::aead::Aead;
    use chacha20poly1305::Nonce;
    let sealed_path = dir.join("legacy-seed.sealed");
    let Some(b) = read_or_absent(&sealed_path)? else { return Ok(None) };
    if b.len() < 12 {
        return Err(format!("{}: truncated", sealed_path.display()));
    }
    let plain = zeroize::Zeroizing::new(
        aead.decrypt(Nonce::from_slice(&b[..12]), &b[12..])
            .map_err(|_| format!("{}: not sealed under this wallet's seed", sealed_path.display()))?,
    );
    Ok(Some(yew_core::keys::SecretString::new(hex::encode(&plain[..]))))
}

/// `z_exportwallet`: `legacy-seed.sealed` (hex) when this wallet's Yugen account was made by an
/// earlier yewd with its own seed, which the phrase alone does not restore. The blob is sealed under
/// the phrase's derived seed, so the dump line is no weaker than the phrase line beside it. A seed
/// still in `wallet.json` is sealed first.
pub fn export_sealed(derived: &str) -> Result<Option<String>, String> {
    let Some(c) = CFG.get() else { return Ok(None) };
    export_sealed_in(&c.dir, derived)
}

fn export_sealed_in(dir: &std::path::Path, derived: &str) -> Result<Option<String>, String> {
    let _g = ENGINE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    drop(account_seed(dir, derived)?);
    Ok(read_or_absent(&dir.join("legacy-seed.sealed"))?.map(|b| hex::encode(&b[..])))
}

/// `z_importwallet` of a dump with a `yugensealed=` line: writes `legacy-seed.sealed` so the next
/// engine call opens that account. The blob must open under this wallet's derived seed; a wallet
/// that has another one sealed already refuses it.
pub fn import_sealed(derived: &str, sealed_hex: &str) -> Result<(), String> {
    let c = CFG.get().ok_or("the Yugen engine is not configured: the dump's yugensealed line cannot be restored")?;
    import_sealed_in(&c.dir, derived, sealed_hex)
}

fn import_sealed_in(dir: &std::path::Path, derived: &str, sealed_hex: &str) -> Result<(), String> {
    use chacha20poly1305::aead::Aead;
    use chacha20poly1305::Nonce;
    let _g = ENGINE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let aead = wrap_aead(derived)?;
    let b = hex::decode(sealed_hex).map_err(|_| "yugensealed: not hex")?;
    if b.len() < 12 {
        return Err("yugensealed: truncated".into());
    }
    let given = zeroize::Zeroizing::new(
        aead.decrypt(Nonce::from_slice(&b[..12]), &b[12..]).map_err(|_| "yugensealed: not sealed under this wallet's phrase")?,
    );
    if let Some(have) = unseal(dir, &aead)? {
        return if ct_eq_str(&have, &hex::encode(&given[..])) { Ok(()) } else { Err("another earlier Yugen seed is sealed in this wallet".into()) };
    }
    write_private(dir, "legacy-seed.sealed", &b).map_err(|e| e.to_string())
}

/// `dir/name`, mode 0600, written atomically (temporary file, fsync, rename, directory fsync).
fn write_private(dir: &std::path::Path, name: &str, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    let tmp = dir.join(format!("{name}.tmp"));
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, dir.join(name))?;
    std::fs::File::open(dir)?.sync_all()
}

/// The fee of the Sapling leg of a Yugen -> Sapling payment (a transparent-input, one-output
/// Sapling transaction at the default fee, as ycashd's z_sendmany from a P2PKH address).
pub const SAPLING_HOP_FEE: u64 = 1000;

/// The fixed sync schedule (spec §17.8 item 1, addendum ruling 16): yewd runs the engine's
/// scheduled `sync` after each block of height `h ≡ 0 (mod 16)`, at a delay drawn afresh from
/// `[0, max_delay]` seconds (60 by §17.8; `-yugensyncdelay` lowers it for a devnet), and never
/// on a user's call. `tip` reads the backend's height.
pub fn spawn_scheduler<T, TF>(max_delay: u64, tip: T)
where
    T: Fn() -> TF + Send + 'static,
    TF: std::future::Future<Output = Option<u32>> + Send,
{
    tokio::spawn(async move {
        let mut done: Option<u32> = None;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            let Some(h) = tip().await else { continue };
            let b = h / 16 * 16;
            if done.is_some_and(|d| d >= b) {
                continue;
            }
            let wait = {
                let mut r = [0u8; 8];
                let _ = getrandom::getrandom(&mut r);
                u64::from_le_bytes(r) % (max_delay + 1)
            };
            tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
            match engine("sync", json!([])).await {
                Ok(v) if v.get("retry") == Some(&Value::Bool(true)) => {} // hosts not at the boundary yet
                Ok(v) => {
                    done = Some(b);
                    if v.get("session") == Some(&Value::Bool(true)) {
                        eprintln!("yewd: Yugen scheduled sync at boundary {b}: {v}");
                    }
                }
                // a locked wallet has no seed to sync with: the sync waits for walletpassphrase
                Err((-13, _)) => {}
                Err((_, m)) => eprintln!("yewd: Yugen scheduled sync at boundary {b} failed: {m}"),
            }
        }
    });
}

/// Maps the RPC names to engine methods. `wallet(method, params)` calls this yewd's own
/// (transparent and Sapling) wallet: `yugen_shield` funds the deposit address with
/// `sendtoaddress`; `yugen_send` to a Sapling address forwards with `z_sendmany`.
pub async fn call<W, Fut>(method: &str, params: Vec<Value>, wallet: W) -> Result<Value, (i64, String)>
where
    W: Fn(String, Vec<Value>) -> Fut,
    Fut: std::future::Future<Output = Result<Value, (i64, String)>>,
{
    match method {
        // The one Yugen address (ruling 15): the short form by default; [{"onetime": true}] adds a
        // fresh payment request. ({"reusable": true} is accepted and is the default.)
        "yugen_getaddress" => engine("getaddress", json!(params)).await,
        // a new one-time address (short + fresh request), as getaddress [{"onetime": true}]
        "yugen_newaddress" | "yugen_getnewaddress" => engine("newaddress", json!([])).await,
        "yugen_getbalance" => engine("getbalance", json!([])).await,
        // spendable, pending (found, not yet anchored; change), outgoing_pending, the schedule
        "yugen_getbalances" => engine("getbalances", json!([])).await,
        "yugen_listreceived" | "yugen_listnotes" => engine("listreceived", json!([])).await,
        // never a host session on demand (ruling 16): the chain scan and the schedule's state
        "yugen_sync" => engine("syncstatus", json!([])).await,
        "yugen_status" => engine("status", json!(params)).await,
        // Internal/debug only: never in a user interface (ruling 9(a)); the deposit address is the
        // shield's transparent hop.
        "yugen_debug_getdepositaddress" => engine("depositaddress", json!([])).await,
        "yugen_debug_getstaticaddress" => engine("staticaddress", json!([])).await,
        "yugen_debug_getpaymentrequest" => engine("newrequest", json!([])).await,
        "yugen_send" => {
            // [to, amount, {"route": "leaf", "memo": text}] or [to, amount, memo text]
            let opt = params.get(2);
            if let Some(r) = opt.and_then(|o| o.get("route")).and_then(Value::as_str) {
                if r != "leaf" {
                    return Err((-8, format!("route {r}: only \"leaf\" at M1")));
                }
            }
            let memo = match opt {
                Some(Value::String(m)) => Value::String(m.clone()),
                Some(o) => o.get("memo").cloned().unwrap_or(Value::Null),
                None => Value::Null,
            };
            let to = params.first().cloned().unwrap_or(Value::Null);
            let amount = params.get(1).cloned().unwrap_or(Value::Null);
            if let Some(t) = to.as_str() {
                if is_sapling(&wallet, t).await {
                    return to_sapling(&wallet, t, &amount, &memo).await;
                }
            }
            let mut a = vec![to, amount];
            if !memo.is_null() {
                a.push(memo);
            }
            // a txid, or for a short address not resolved yet the queued payment (ruling 16)
            engine("send", Value::Array(a)).await.map(|r| match r["txid"].as_str() {
                Some(t) => Value::String(t.to_string()),
                None => r,
            })
        }
        "yugen_withdraw" => {
            // [taddr (P2PKH or post-quantum sqs/sqf), amount]; a Sapling address is refused by the engine
            let a = json!([params.first().cloned().unwrap_or(Value::Null), params.get(1).cloned().unwrap_or(Value::Null), params.get(2).cloned().unwrap_or(Value::Null)]);
            engine("withdraw", a).await.map(|r| r["txid"].clone())
        }
        "yugen_shield" => {
            let amount = params.get(1).cloned().ok_or((-8, "yugen_shield [addr, amount]".to_string()))?;
            let dep = engine("depositaddress", json!([])).await?;
            let txid = wallet("sendtoaddress".into(), vec![dep, amount]).await?;
            let txid = txid.as_str().map(String::from).ok_or((-1, format!("sendtoaddress: {txid}")))?;
            // a static full address (hex, §12.1) receives the deposit note directly, with an optional memo
            // the engine sends to the address given (a Yugen address or a static full address hex),
            // or to its own change when the address is this wallet's own
            let to = params.first().cloned().unwrap_or(Value::Null);
            let memo = params.get(2).cloned().unwrap_or(Value::Null);
            let r = engine("shield", json!([txid, to, memo])).await?;
            Ok(r["txid"].clone())
        }
        _ => Err((-32601, "Method not found".into())),
    }
}

/// True when `to` is a Sapling address (the node's `z_validateaddress`, as yewd answers it).
async fn is_sapling<W, Fut>(wallet: &W, to: &str) -> bool
where
    W: Fn(String, Vec<Value>) -> Fut,
    Fut: std::future::Future<Output = Result<Value, (i64, String)>>,
{
    match wallet("z_validateaddress".into(), vec![json!(to)]).await {
        Ok(v) => v["isvalid"] == json!(true) && v["address_type"].as_str().or(v["type"].as_str()) == Some("sapling"),
        Err(_) => false,
    }
}

fn zats_of(v: &Value) -> Option<u64> {
    let c = v.as_f64().or_else(|| v.as_str().and_then(|s| s.parse().ok()))?;
    (c > 0.0).then(|| (c * 1e8).round() as u64)
}

fn coins_str(z: u64) -> String {
    format!("{}.{:08}", z / 100_000_000, z % 100_000_000)
}

/// Yugen -> Sapling as one user action (addendum ruling 9(b); decision Y-W9): a Yugen
/// transaction has no Sapling part (W-TX), so the wallet withdraws `amount + SAPLING_HOP_FEE` to
/// a fresh transparent address of its own (never shown), then sends `amount` from exactly that
/// address to the Sapling address with the memo (z_sendmany, minconf 0, the hop spent whole, no
/// change). Reported as one operation with both txids.
async fn to_sapling<W, Fut>(wallet: &W, to: &str, amount: &Value, memo: &Value) -> Result<Value, (i64, String)>
where
    W: Fn(String, Vec<Value>) -> Fut,
    Fut: std::future::Future<Output = Result<Value, (i64, String)>>,
{
    let z = zats_of(amount).ok_or((-3, "Invalid amount".to_string()))?;
    let memo_hex = match memo.as_str().filter(|m| !m.is_empty()) {
        Some(m) if m.len() > 512 => return Err((-8, "memo longer than 512 bytes".into())),
        Some(m) => Some(hex::encode(m.as_bytes())),
        None => None,
    };
    let hop = wallet("getnewaddress".into(), vec![]).await?;
    let hop = hop.as_str().ok_or((-1, "getnewaddress".to_string()))?.to_string();
    let w = engine("withdraw", json!([hop, coins_str(z + SAPLING_HOP_FEE)])).await?;
    let wtxid = w["txid"].as_str().unwrap_or("").to_string();
    // the wallet sees the withdrawal in the mempool (every wallet call reconciles first)
    let mut seen = false;
    for _ in 0..60 {
        if let Ok(b) = wallet("z_getbalance".into(), vec![json!(hop), json!(0), json!(true)]).await {
            if b.as_u64().or_else(|| b.as_f64().map(|f| f as u64)).unwrap_or(0) >= z + SAPLING_HOP_FEE {
                seen = true;
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    if !seen {
        return Err((-4, format!("Yugen -> Sapling: the withdrawal {wtxid} did not reach this wallet; its coins are at the wallet's own transparent address and stay spendable")));
    }
    let mut out = json!({"address": to, "amount": coins_str(z)});
    if let Some(m) = memo_hex {
        out["memo"] = json!(m);
    }
    let opid = wallet(
        "z_sendmany".into(),
        vec![json!(hop), json!([out]), json!(0), json!(coins_str(SAPLING_HOP_FEE)), json!("AllowRevealedSenders")],
    )
    .await?;
    let opid = opid.as_str().unwrap_or("").to_string();
    for _ in 0..600 {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let st = wallet("z_getoperationstatus".into(), vec![json!([opid])]).await?;
        let s0 = &st[0];
        match s0["status"].as_str() {
            Some("success") => {
                let _ = wallet("z_getoperationresult".into(), vec![json!([opid])]).await;
                let ftxid = s0["result"]["txid"].as_str().unwrap_or("").to_string();
                return Ok(json!({"operation": "yugen-to-sapling", "txid": ftxid, "withdraw_txid": wtxid,
                                 "sapling_txid": ftxid, "amount": coins_str(z),
                                 "fee": coins_str(w["fee"].as_f64().map(|f| (f * 1e8).round() as u64).unwrap_or(0) + SAPLING_HOP_FEE)}));
            }
            Some("failed") | Some("cancelled") => {
                return Err((-4, format!("Yugen -> Sapling: the withdrawal {wtxid} is done; the Sapling send failed ({}): the coins are at the wallet's own transparent address", s0["error"]["message"].as_str().unwrap_or("?"))));
            }
            _ => {}
        }
    }
    Err((-4, format!("Yugen -> Sapling: operation {opid} still running")))
}

#[cfg(test)]
mod seed_tests {
    use super::*;

    #[test]
    fn seed_reaches_the_child_on_fd3_only() {
        // the seed line ends with a newline; the child's read stops there
        let out = run_with_seed(std::path::Path::new("/bin/sh"), &["-c".into(), "read s <&3; echo \"$s\"; echo \"$*\"".into()], "c0ffee").unwrap();
        let s = String::from_utf8(out.stdout).unwrap();
        assert_eq!(s.lines().next(), Some("c0ffee"));
        assert!(!s.lines().nth(1).unwrap_or("").contains("c0ffee"), "not in argv");
    }

    #[test]
    fn legacy_plain_seed_is_warned_about() {
        let dir = std::env::temp_dir().join(format!("yewd-yugen-legacywarn-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(legacy_plain_warning(&dir).is_none(), "no state file: no warning");
        std::fs::write(dir.join("wallet.json"), br#"{"seed_fp":"00"}"#).unwrap();
        assert!(legacy_plain_warning(&dir).is_none(), "no plain seed: no warning");
        std::fs::write(dir.join("wallet.json"), format!(r#"{{"seed":"{}"}}"#, "7e".repeat(32))).unwrap();
        let m = legacy_plain_warning(&dir).expect("a plain seed is warned about");
        assert!(m.contains("walletpassphrase") && !m.contains(&"7e".repeat(32)), "{m}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_seed_is_sealed_under_the_derived_seed() {
        let dir = std::env::temp_dir().join(format!("yewd-yugen-legacy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let derived = "11".repeat(32);
        // no state: the derived seed
        assert_eq!(&*account_seed(&dir, &derived).unwrap(), derived.as_str());
        // a state with the derived seed: the derived seed, nothing sealed
        std::fs::write(dir.join("wallet.json"), format!("{{\"seed\":\"{derived}\"}}")).unwrap();
        assert_eq!(&*account_seed(&dir, &derived).unwrap(), derived.as_str());
        assert!(!dir.join("legacy-seed.sealed").exists());
        // an earlier yewd's own seed: kept, sealed (0600), no hex of it in the sealed file
        let old = "7e".repeat(32);
        std::fs::write(dir.join("wallet.json"), format!("{{\"seed\":\"{old}\"}}")).unwrap();
        assert_eq!(&*account_seed(&dir, &derived).unwrap(), old.as_str());
        let sealed = std::fs::read(dir.join("legacy-seed.sealed")).unwrap();
        assert!(!sealed.windows(32).any(|w| w == [0x7e; 32]));
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(dir.join("legacy-seed.sealed")).unwrap().permissions().mode() & 0o777, 0o600);
        // once the engine has dropped the field, the sealed file still gives it, and only to this wallet
        std::fs::write(dir.join("wallet.json"), "{}").unwrap();
        assert_eq!(&*account_seed(&dir, &derived).unwrap(), old.as_str());
        assert!(account_seed(&dir, &"22".repeat(32)).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn child_holds_no_inherited_descriptor_above_3() {
        // a descriptor this process holds without close-on-exec (as another library might)
        let p = std::ffi::CString::new("/dev/null").unwrap();
        let fd0 = unsafe { libc::open(p.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        let fd = unsafe { libc::fcntl(fd0, libc::F_DUPFD, 40) }; // F_DUPFD: the copy is not close-on-exec
        unsafe { libc::close(fd0) };
        assert!(fd >= 40);
        let script = format!("read s <&3; echo \"$s\"; if [ -e /dev/fd/{fd} ]; then echo LEAK; else echo CLOSED; fi");
        let out = run_with_seed(std::path::Path::new("/bin/sh"), &["-c".into(), script], "c0ffee").unwrap();
        unsafe { libc::close(fd) };
        let s = String::from_utf8(out.stdout).unwrap();
        assert_eq!(s.lines().collect::<Vec<_>>(), vec!["c0ffee", "CLOSED"], "{s}");
    }

    #[test]
    fn an_unreadable_sealed_file_is_an_error_not_the_derived_seed() {
        let dir = std::env::temp_dir().join(format!("yewd-yugen-unreadable-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("legacy-seed.sealed")).unwrap(); // read fails (a directory), not NotFound
        assert!(account_seed(&dir, &"11".repeat(32)).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn earlier_yewd_seed_survives_dump_and_restore() {
        let a = std::env::temp_dir().join(format!("yewd-yugen-dump-a-{}", std::process::id()));
        let b = std::env::temp_dir().join(format!("yewd-yugen-dump-b-{}", std::process::id()));
        for d in [&a, &b] {
            let _ = std::fs::remove_dir_all(d);
            std::fs::create_dir_all(d).unwrap();
        }
        let derived = "11".repeat(32);
        let old = "7e".repeat(32);
        // a wallet whose Yugen account was made by an earlier yewd's own seed
        std::fs::write(a.join("wallet.json"), format!("{{\"seed\":\"{old}\"}}")).unwrap();
        let line = export_sealed_in(&a, &derived).unwrap().expect("the dump carries the sealed seed");
        assert!(!line.contains(&old), "the dump line holds no plain seed");
        // a fresh install restored from the phrase and the dump: the engine gets the earlier seed,
        // which opens the account that holds the funds
        assert_eq!(&*account_seed(&b, &derived).unwrap(), derived.as_str());
        import_sealed_in(&b, &derived, &line).unwrap();
        assert_eq!(&*account_seed(&b, &derived).unwrap(), old.as_str());
        // idempotent; another phrase's wallet refuses it
        import_sealed_in(&b, &derived, &line).unwrap();
        let c = std::env::temp_dir().join(format!("yewd-yugen-dump-c-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&c);
        assert!(import_sealed_in(&c, &"22".repeat(32), &line).is_err());
        // a wallet with no earlier seed puts no line in its dump
        let d = std::env::temp_dir().join(format!("yewd-yugen-dump-d-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        assert_eq!(export_sealed_in(&d, &derived).unwrap(), None);
        for x in [&a, &b, &c, &d] {
            let _ = std::fs::remove_dir_all(x);
        }
    }

    #[test]
    fn credential_file_is_private_and_removed() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("yewd-yugen-cred-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let f = CredFile::new(&dir, "u:p").unwrap();
        let p = f.0.clone();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "u:p");
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        drop(f);
        assert!(!p.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
