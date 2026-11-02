// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The façade's wallet: `yewd-wallet` over the backend connection, the signer as a separate
//! process on a Unix socket (K-24: the seed never enters this process; S2), the barrier every
//! wallet RPC passes (H1) and the poll that keeps the wallet at the node's tip between calls (the
//! fallback the plan requires anyway; ycash6 has no indexer streams).
//!
//! **The signer process.** Unless `-signer=<socket>` names a signer someone else runs, the façade
//! starts `yewd-signer serve -socket=<datadir>/<net>/signer/signer.sock -watchstdin` as its child
//! (after `init`), keeps the child's standard input open, and so stops it by exiting: the signer
//! exits when that pipe closes. Every signature is requested over the socket ([`SocketSigner`]).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use serde_json::Value;
use tokio::sync::Mutex;
use yew_core::params::Network as CoreNetwork;
use yewd_proto::{PublicBundle, PublicRequest};
use yewd_wallet::json::J;
use yewd_wallet::node::{Node, NodeError, NodeFuture};
use yewd_wallet::{code, RpcError, Signer, Wallet};

use crate::backend::{Backend, BackendError};
use crate::config::Network;

pub fn core_network(n: Network) -> CoreNetwork {
    match n {
        Network::Main => CoreNetwork::Mainnet,
        Network::Test => CoreNetwork::Testnet,
        Network::Regtest => CoreNetwork::Regtest,
    }
}

fn net_flag(n: Network) -> Option<&'static str> {
    match n {
        Network::Main => None,
        Network::Test => Some("-testnet"),
        Network::Regtest => Some("-regtest"),
    }
}

/// The signer run as a child process per request (S1). S2 replaces it with the Unix socket.
pub struct ProcessSigner {
    pub bin: PathBuf,
    pub dir: PathBuf,
    pub network: Network,
}

impl ProcessSigner {
    fn run(&self, args: &[String]) -> Result<String, String> {
        let mut cmd = Command::new(&self.bin);
        cmd.arg(format!("-datadir={}", self.dir.display()));
        if let Some(f) = net_flag(self.network) {
            cmd.arg(f);
        }
        cmd.args(args);
        let out = cmd
            .output()
            .map_err(|e| format!("cannot run the signer {}: {e}", self.bin.display()))?;
        if !out.status.success() {
            return Err(format!(
                "the signer failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// `init` (a no-op when the seed exists); returns the seed's birthday. `mnemonic_file`:
    /// ycashd's `-mnemonicfile`, read by the signer (a new seed from that phrase, birthday 0, the
    /// sign-once restore marker set; refused when the seed exists and is another).
    pub fn init(&self, birthday: u32, mnemonic_file: Option<&Path>) -> Result<u32, String> {
        let mut args = vec!["init".to_string(), format!("-birthday={birthday}")];
        if let Some(f) = mnemonic_file {
            args.push(format!("-mnemonicfile={}", f.display()));
        }
        let out = self.run(&args)?;
        let v: Value = serde_json::from_str(out.trim()).map_err(|e| format!("signer init: {e}"))?;
        Ok(v["birthday"].as_u64().unwrap_or(0) as u32)
    }
}

impl Signer for ProcessSigner {
    fn public(&self, req: &PublicRequest) -> Result<PublicBundle, String> {
        let mut args = vec!["public".to_string()];
        for (s, f, c) in &req.pq {
            args.push(format!("-pq={s}:{f}:{c}"));
        }
        let out = self.run(&args)?;
        serde_json::from_str(out.trim()).map_err(|e| format!("signer public: {e}"))
    }
}

/// The signer over its Unix socket (K-24 (a)): the protocol of `yewd-proto`.
pub struct SocketSigner {
    client: yewd_proto::client::SocketClient,
    /// The signer process this façade started (killed with the façade).
    _child: Option<std::sync::Mutex<std::process::Child>>,
}

impl SocketSigner {
    pub fn connect(path: PathBuf) -> SocketSigner {
        SocketSigner {
            client: yewd_proto::client::SocketClient::new(path),
            _child: None,
        }
    }

    /// Start `bin serve` for the signer directory `dir` and wait until it listens.
    pub fn spawn(bin: &Path, dir: &Path, network: Network) -> Result<SocketSigner, String> {
        use std::io::BufRead;
        use std::process::Stdio;
        let sock = yewd_proto::client::socket_path(dir, my_uid());
        let mut cmd = Command::new(bin);
        cmd.arg(format!("-datadir={}", dir.display()));
        if let Some(f) = net_flag(network) {
            cmd.arg(f);
        }
        cmd.arg("serve")
            .arg(format!("-socket={}", sock.display()))
            .arg("-watchstdin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let mut child = cmd
            .spawn()
            .map_err(|e| format!("cannot run the signer {}: {e}", bin.display()))?;
        let out = child.stdout.take().ok_or("the signer has no stdout")?;
        let mut line = String::new();
        std::io::BufReader::new(out)
            .read_line(&mut line)
            .map_err(|e| format!("the signer did not start: {e}"))?;
        if !line.contains("listening") {
            let _ = child.kill();
            return Err(format!("the signer did not start: {}", line.trim()));
        }
        Ok(SocketSigner {
            client: yewd_proto::client::SocketClient::new(sock),
            _child: Some(std::sync::Mutex::new(child)),
        })
    }
}

impl Drop for SocketSigner {
    fn drop(&mut self) {
        if let Some(c) = &self._child {
            if let Ok(mut c) = c.lock() {
                let _ = c.kill();
                let _ = c.wait();
            }
        }
    }
}

impl Signer for SocketSigner {
    fn public(&self, req: &PublicRequest) -> Result<PublicBundle, String> {
        match self.client.call(yewd_proto::Request::Public(req.clone()))? {
            yewd_proto::Response::Public(b) => Ok(b),
            yewd_proto::Response::Refused(r) => Err(format!("{}: {}", r.code, r.reason)),
            other => Err(format!("unexpected signer answer {other:?}")),
        }
    }

    fn request(&self, r: yewd_proto::Request) -> Result<yewd_proto::Response, String> {
        self.client.call(r)
    }
}

fn my_uid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() }
}

/// The signer binary: `-signerbin`, else `yewd-signer` beside this executable.
pub fn default_signer_bin() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("yewd-signer")))
        .unwrap_or_else(|| PathBuf::from("yewd-signer"))
}

/// The node as the wallet sees it: JSON-RPC over the façade's backend leg.
pub struct BackendNode {
    pub backend: Arc<Backend>,
}

impl Node for BackendNode {
    fn call<'a>(&'a self, method: &'a str, params: Value) -> NodeFuture<'a> {
        Box::pin(async move {
            let body = serde_json::json!({"jsonrpc": "1.0", "id": "yewd", "method": method, "params": params});
            let (_, out) = self
                .backend
                .call("/", Bytes::from(body.to_string()))
                .await
                .map_err(|e| match e {
                    BackendError::Unreachable(m) => NodeError::Unreachable(m),
                    other => NodeError::Other(other.to_string()),
                })?;
            let v: Value = serde_json::from_slice(&out)
                .map_err(|e| NodeError::Other(format!("{method}: {e}")))?;
            if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
                return Err(NodeError::Rpc {
                    code: err["code"].as_i64().unwrap_or(-1),
                    message: err["message"].as_str().unwrap_or("").to_string(),
                });
            }
            Ok(v.get("result").cloned().unwrap_or(Value::Null))
        })
    }
}

/// How the wallet's signer is made.
pub enum SignerSource {
    /// `yewd-signer` as a child process serving the socket (production).
    Process(PathBuf),
    /// A signer already serving the socket at this path (`-signer=<socket>`).
    Socket(PathBuf),
    /// An in-process signer (the façade's own tests only).
    Given(Box<dyn Signer>),
}

/// The wallet service: opened on first use (the backend gives a new wallet its birthday).
pub struct WalletService {
    pub network: Network,
    pub dir: PathBuf,
    node: BackendNode,
    signer: std::sync::Mutex<Option<SignerSource>>,
    wallet: Mutex<Option<Wallet>>,
    pub debug: bool,
    /// The wallet options the command line gave (S4).
    pub opts: std::sync::Mutex<WalletArgs>,
    /// Woken by kogany's indexer streams (`crate::indexer`): a sync between polls (H3, H4).
    pub wake: Arc<tokio::sync::Notify>,
    /// `-disablewallet`: never opened; the façade answers no wallet method.
    pub disabled: bool,
}

/// The ycashd wallet arguments yewd gives meaning to (S4; the harness hands them over).
#[derive(Clone, Debug, Default)]
pub struct WalletArgs {
    pub opts: yewd_wallet::admin::Opts,
    /// `-wallet=<file>`: a `backupwallet` file to restore at open (relative to `<datadir>/<net>`;
    /// default `wallet.dat`).
    pub wallet_file: Option<PathBuf>,
    /// `-rescan`: read the chain again from the wallet's birthday at open.
    pub rescan: bool,
    /// `-salvagewallet`: a restored backup carries the sign-once restore marker (07/NEW-1).
    pub salvage: bool,
    /// `-mnemonicfile=<file>`: a new wallet takes its seed from the recovery phrase in the file
    /// (read by the signer), rescans from genesis and carries the sign-once restore marker.
    pub mnemonic_file: Option<PathBuf>,
}

/// The wallet file a yewd wallet answers to (`<datadir>/<net>/wallet.dat`, ycashd's default):
/// yewd keeps its wallet in `<net>/yewd` and `<net>/signer`, and writes this file as their
/// stand-in, so that removing it means what it means to ycashd: the next start opens a new
/// wallet (F-S5-17). The old wallet is moved aside, never deleted.
const WALLET_FILE: &str = "wallet.dat";
/// Inside `<net>/yewd`: the wallet answers to `<net>/wallet.dat` (written by this version).
const WALLET_FILE_RECORD: &str = "walletfile";
const WALLET_FILE_FORMAT: &str = "yewd-wallet-file-1";

/// Before the wallet is opened: if this wallet answers to `<dir>/wallet.dat` and that file is
/// gone, move the wallet (`yewd/`, `signer/`) aside as `*.wiped-<unix time>`, so a new one is
/// created. A wallet without the record (an older yewd's) is left as it is. Returns where the
/// wallet state went.
fn retire_wiped_wallet(dir: &Path) -> Result<Option<PathBuf>, String> {
    let wallet = dir.join("yewd");
    if !wallet.join(WALLET_FILE_RECORD).exists() || dir.join(WALLET_FILE).exists() {
        return Ok(None);
    }
    let mut moved = None;
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    for part in ["yewd", "signer"] {
        let from = dir.join(part);
        if from.exists() {
            let mut to = dir.join(format!("{part}.wiped-{stamp}"));
            let mut n = 1;
            while to.exists() {
                to = dir.join(format!("{part}.wiped-{stamp}.{n}"));
                n += 1;
            }
            std::fs::rename(&from, &to)
                .map_err(|e| format!("cannot move {} aside: {e}", from.display()))?;
            if part == "yewd" {
                moved = Some(to);
            }
        }
    }
    Ok(moved)
}

/// After the wallet is opened: the wallet file exists (a restored backup, or the stand-in
/// written here) and the wallet records that it answers to it.
fn mark_wallet_file(dir: &Path) -> Result<(), String> {
    let file = dir.join(WALLET_FILE);
    if !file.exists() {
        let text = serde_json::json!({
            "format": WALLET_FILE_FORMAT,
            "note": "a yewd wallet: its state is in yewd/ and its seed in signer/ beside this file; \
                     removing this file makes the next start create a new wallet",
        });
        std::fs::write(&file, format!("{text}\n"))
            .map_err(|e| format!("{}: {e}", file.display()))?;
    }
    std::fs::write(dir.join("yewd").join(WALLET_FILE_RECORD), WALLET_FILE)
        .map_err(|e| format!("the wallet file record: {e}"))
}

impl WalletService {
    pub fn new(
        network: Network,
        datadir: &Path,
        backend: Arc<Backend>,
        signer: SignerSource,
        debug: bool,
    ) -> WalletService {
        WalletService {
            network,
            dir: datadir.join(network.subdir()),
            node: BackendNode { backend },
            signer: std::sync::Mutex::new(Some(signer)),
            wallet: Mutex::new(None),
            debug,
            opts: std::sync::Mutex::new(WalletArgs::default()),
            wake: Arc::new(tokio::sync::Notify::new()),
            disabled: false,
        }
    }

    /// The backup to restore at open, if `-wallet` (or `<datadir>/<net>/wallet.dat`) names a
    /// `backupwallet` file this wallet has not restored yet: `(path, digest)`.
    fn pending_restore(&self) -> Option<(PathBuf, String)> {
        let args = self.opts.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let path = match args.wallet_file {
            Some(p) if p.is_absolute() => p,
            Some(p) => self.dir.join(p),
            None => self.dir.join("wallet.dat"),
        };
        let digest = yewd_proto::backup_digest(&path)?;
        let marker = self.wallet_dir().join("restored.sha256");
        // -salvagewallet rebuilds the wallet from the file whatever was restored before (ycashd
        // salvages wallet.dat at every start it is given): the restore marker is set again
        if !args.salvage
            && std::fs::read_to_string(&marker).ok().as_deref() == Some(digest.as_str())
        {
            return None;
        }
        Some((path, digest))
    }

    /// Restore a `backupwallet` file: the signer writes its files back (`yewd-signer restore`),
    /// the façade's state is replaced, and the backup is remembered so it is restored once.
    fn restore(&self, bin: &Path, from: &Path, digest: &str) -> Result<(), String> {
        let salvage = self.opts.lock().unwrap_or_else(|e| e.into_inner()).salvage;
        let mut cmd = Command::new(bin);
        cmd.arg(format!("-datadir={}", self.dir.join("signer").display()));
        if let Some(f) = net_flag(self.network) {
            cmd.arg(f);
        }
        cmd.arg("restore").arg(format!("-from={}", from.display()));
        if salvage {
            cmd.arg("-salvage");
        }
        let out = cmd
            .output()
            .map_err(|e| format!("cannot run the signer {}: {e}", bin.display()))?;
        if !out.status.success() {
            return Err(format!(
                "the signer could not restore {}: {}",
                from.display(),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        let facade = String::from_utf8_lossy(&out.stdout).trim().to_string();
        std::fs::create_dir_all(self.wallet_dir()).map_err(|e| e.to_string())?;
        let tmp = self.wallet_dir().join("wallet.json.restore");
        std::fs::write(&tmp, facade).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, self.wallet_dir().join("wallet.json")).map_err(|e| e.to_string())?;
        std::fs::write(self.wallet_dir().join("restored.sha256"), digest)
            .map_err(|e| e.to_string())?;
        eprintln!("yewd: restored the wallet from {}", from.display());
        Ok(())
    }

    /// Whether the wallet is encrypted (the signer's state; false before it is open).
    pub async fn encrypted(&self) -> bool {
        let slot = self.wallet.lock().await;
        slot.as_ref().map(|w| w.signer_state().0).unwrap_or(false)
    }

    /// The raw-transaction helpers, served here (K-25): no wallet, the node's next height only.
    pub async fn raw_helper(&self, method: &str, params: &[Value]) -> Result<String, RpcError> {
        let net = core_network(self.network);
        let r = match method {
            "decoderawtransaction" => yewd_wallet::raw::decoderawtransaction(net, params),
            "decodescript" => yewd_wallet::raw::decodescript(net, params),
            "createrawtransaction" => {
                let h = yewd_wallet::node::block_count(&self.node).await?;
                yewd_wallet::raw::createrawtransaction(net, h + 1, params)
            }
            _ => Err(RpcError::new(code::METHOD_NOT_FOUND, "Method not found")),
        };
        match r {
            Ok(j) => Ok(j.text()),
            // a refusal's text is the C++ library's where ycashd's deserializer throws ("TX decode
            // failed: …: unspecified iostream_category error"): a backend that has the helper
            // (ycash6) gives its own words; one that lacks it (kogany: -32601) gets ours (F-S4-4)
            Err(e) => match self.node.call(method, Value::Array(params.to_vec())).await {
                Err(NodeError::Rpc { code: c, message }) if c != code::METHOD_NOT_FOUND => {
                    Err(RpcError::new(c, message))
                }
                _ => Err(e),
            },
        }
    }

    fn wallet_dir(&self) -> PathBuf {
        self.dir.join("yewd")
    }

    /// Create the wallet without a node (`-initwallet`): a new seed's birthday is 0, so a
    /// backend started afterwards with `-mineraddress=<the coinbase address>` pays it from its
    /// first block (H8). Returns the coinbase address.
    pub fn init_offline(
        network: Network,
        datadir: &Path,
        signer_bin: PathBuf,
        mnemonic_file: Option<&Path>,
        wallet_file_given: bool,
    ) -> Result<(String, Option<String>, Option<PathBuf>), String> {
        let dir = datadir.join(network.subdir());
        let moved = if wallet_file_given {
            None
        } else {
            retire_wiped_wallet(&dir)?
        };
        let ps = ProcessSigner {
            bin: signer_bin,
            dir: dir.join("signer"),
            network,
        };
        let birthday = ps.init(0, mnemonic_file)?;
        let w = Wallet::open(
            &dir.join("yewd"),
            core_network(network),
            Box::new(ps),
            birthday,
        )?;
        if !wallet_file_given {
            mark_wallet_file(&dir)?;
        }
        Ok((
            w.taddr(yewd_wallet::keys::EXTERNAL, 0),
            w.sapling_coinbase_address(),
            moved,
        ))
    }

    async fn ensure_open<'a>(
        &'a self,
        slot: &mut tokio::sync::MutexGuard<'a, Option<Wallet>>,
    ) -> Result<(), RpcError> {
        if slot.is_some() {
            return Ok(());
        }
        let source = self.signer.lock().unwrap_or_else(|e| e.into_inner()).take();
        let Some(source) = source else {
            return Err(RpcError::new(
                code::WALLET_ERROR,
                "yewd: the wallet could not be opened",
            ));
        };
        let args = self.opts.lock().unwrap_or_else(|e| e.into_inner()).clone();
        // the wallet file stands in for a wallet whose seed this façade's own signer holds
        let own_files = matches!(source, SignerSource::Process(_)) && args.wallet_file.is_none();
        if own_files {
            match retire_wiped_wallet(&self.dir) {
                Ok(Some(to)) => eprintln!(
                    "yewd: {} was removed: the wallet was moved aside to {} and a new one is created",
                    self.dir.join(WALLET_FILE).display(),
                    to.display()
                ),
                Ok(None) => {}
                Err(e) => {
                    *self.signer.lock().unwrap_or_else(|e| e.into_inner()) = Some(source);
                    return Err(RpcError::new(code::WALLET_ERROR, format!("yewd: {e}")));
                }
            }
        }
        if let (SignerSource::Process(bin), Some((from, digest))) =
            (&source, self.pending_restore())
        {
            if let Err(e) = self.restore(bin, &from, &digest) {
                *self.signer.lock().unwrap_or_else(|e| e.into_inner()) = Some(source);
                return Err(RpcError::new(code::WALLET_ERROR, format!("yewd: {e}")));
            }
        }
        let exists = self.wallet_dir().join("wallet.json").exists();
        // a new wallet's birthday: the node's height now (a new seed has no earlier history); a
        // seed restored from -mnemonicfile has an unknown birthday: it rescans from genesis
        let height = if exists || args.mnemonic_file.is_some() {
            0
        } else {
            match yewd_wallet::node::block_count(&self.node).await {
                Ok(h) => h,
                Err(e) => {
                    *self.signer.lock().unwrap_or_else(|e| e.into_inner()) = Some(source);
                    return Err(e.into());
                }
            }
        };
        let (signer, birthday): (Box<dyn Signer>, u32) = match source {
            SignerSource::Process(bin) => {
                let dir = self.dir.join("signer");
                let ps = ProcessSigner {
                    bin: bin.clone(),
                    dir: dir.clone(),
                    network: self.network,
                };
                let b = ps
                    .init(height, args.mnemonic_file.as_deref())
                    .map_err(|e| RpcError::new(code::WALLET_ERROR, format!("yewd: {e}")))?;
                let s = match SocketSigner::spawn(&bin, &dir, self.network) {
                    Ok(s) => s,
                    Err(e) => {
                        *self.signer.lock().unwrap_or_else(|e| e.into_inner()) =
                            Some(SignerSource::Process(bin));
                        return Err(RpcError::new(
                            code::WALLET_UNLOCK_NEEDED,
                            format!("yewd: {e}"),
                        ));
                    }
                };
                (Box::new(s), b)
            }
            SignerSource::Socket(path) => (Box::new(SocketSigner::connect(path)), height),
            SignerSource::Given(s) => (s, height),
        };
        let w = Wallet::open(
            &self.wallet_dir(),
            core_network(self.network),
            signer,
            birthday,
        )
        .map_err(|e| RpcError::new(code::WALLET_ERROR, format!("yewd: {e}")))?;
        let mut w = w;
        if own_files {
            mark_wallet_file(&self.dir)
                .map_err(|e| RpcError::new(code::WALLET_ERROR, format!("yewd: {e}")))?;
        }
        w.opts = args.opts;
        if args.rescan {
            w.rescan_all();
        }
        **slot = Some(w);
        Ok(())
    }

    /// One served wallet method: open, barrier (sync to the node's tip), answer.
    pub async fn call(&self, method: &str, params: &[Value]) -> Result<String, RpcError> {
        let mut slot = self.wallet.lock().await;
        self.ensure_open(&mut slot).await?;
        let w = slot.as_mut().expect("opened");
        w.sync(&self.node).await?;
        let r: J = w.call(&self.node, method, params).await?;
        Ok(r.text())
    }

    /// `sendrawtransaction`'s H7 guard (`allowyedburn`): the type checks of `RPCTypeCheck`, then
    /// the refusal of a transaction that destroys this wallet's YED unless the caller allows it.
    pub async fn burn_guard(&self, params: &[Value]) -> Result<(), RpcError> {
        for (i, want) in [(1usize, "bool"), (2, "bool")] {
            if let Some(v) = params.get(i).filter(|v| !v.is_null()) {
                if !v.is_boolean() {
                    let got = match v {
                        Value::String(_) => "string",
                        Value::Number(_) => "number",
                        Value::Array(_) => "array",
                        Value::Object(_) => "object",
                        _ => "null",
                    };
                    return Err(RpcError::new(
                        code::TYPE_ERROR,
                        format!("Expected type {want}, got {got}"),
                    ));
                }
            }
        }
        if params.get(2).and_then(|v| v.as_bool()) == Some(true) {
            return Ok(());
        }
        let mut slot = self.wallet.lock().await;
        self.ensure_open(&mut slot).await?;
        let w = slot.as_mut().expect("opened");
        w.sync(&self.node).await?;
        w.yed_burn_guard(&self.node, params).await
    }

    /// A read the wallet answers without forwarding (`z_validateaddress`).
    pub async fn local(&self, method: &str, params: &[Value]) -> Result<String, RpcError> {
        let mut slot = self.wallet.lock().await;
        self.ensure_open(&mut slot).await?;
        let w = slot.as_mut().expect("opened");
        match method {
            "z_validateaddress" => Ok(w.z_validateaddress(params)?.text()),
            _ => Err(RpcError::new(code::METHOD_NOT_FOUND, "Method not found")),
        }
    }

    /// Complete a forwarded node read (`result` is its JSON text).
    pub async fn augment(
        &self,
        method: &str,
        params: &[Value],
        result: &str,
    ) -> Result<String, RpcError> {
        let mut slot = self.wallet.lock().await;
        self.ensure_open(&mut slot).await?;
        let w = slot.as_mut().expect("opened");
        w.sync(&self.node).await?;
        w.augment(&self.node, method, params, result).await
    }

    /// The poll fallback: sync every `every` (never when zero) or when the indexer streams wake
    /// the wallet, until the process stops.
    pub fn spawn_poll(self: &Arc<Self>, every: Duration) {
        let me = self.clone();
        tokio::spawn(async move {
            loop {
                if every.is_zero() {
                    me.wake.notified().await;
                } else {
                    tokio::select! {
                        _ = tokio::time::sleep(every) => {}
                        _ = me.wake.notified() => {}
                    }
                }
                let mut slot = me.wallet.lock().await;
                if me.ensure_open(&mut slot).await.is_err() {
                    continue;
                }
                if let Some(w) = slot.as_mut() {
                    if let Err(e) = w.sync(&me.node).await {
                        if me.debug {
                            eprintln!("yewd: wallet sync: {e}");
                        }
                    } else if !w.pending.is_empty() {
                        w.complete_pending(&me.node).await;
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// F-S5-17: the stand-in wallet file; removing it retires the wallet (moved aside, never
    /// deleted); a wallet without the record (an older yewd's) is never retired.
    #[test]
    fn wallet_file_stand_in() {
        let d = std::env::temp_dir().join(format!("yewd-walletfile-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("yewd")).unwrap();
        std::fs::create_dir_all(d.join("signer")).unwrap();
        // no record: left alone even without wallet.dat
        assert_eq!(retire_wiped_wallet(&d).unwrap(), None);
        mark_wallet_file(&d).unwrap();
        assert!(d.join(WALLET_FILE).exists());
        assert_eq!(yewd_proto::backup_digest(&d.join(WALLET_FILE)), None);
        assert_eq!(retire_wiped_wallet(&d).unwrap(), None);
        std::fs::remove_file(d.join(WALLET_FILE)).unwrap();
        let moved = retire_wiped_wallet(&d).unwrap().unwrap();
        assert!(moved.join(WALLET_FILE_RECORD).exists());
        assert!(!d.join("yewd").exists() && !d.join("signer").exists());
        assert_eq!(
            std::fs::read_dir(&d)
                .unwrap()
                .filter(|e| e
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with("signer.wiped-"))
                .count(),
            1
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}
