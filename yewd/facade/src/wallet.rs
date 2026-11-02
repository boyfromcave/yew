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

    /// `init` (a no-op when the seed exists); returns the seed's birthday.
    pub fn init(&self, birthday: u32) -> Result<u32, String> {
        let out = self.run(&["init".into(), format!("-birthday={birthday}")])?;
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
        let sock = dir.join("signer.sock");
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
    ) -> Result<String, String> {
        let dir = datadir.join(network.subdir());
        let ps = ProcessSigner {
            bin: signer_bin,
            dir: dir.join("signer"),
            network,
        };
        let birthday = ps.init(0)?;
        let w = Wallet::open(
            &dir.join("yewd"),
            core_network(network),
            Box::new(ps),
            birthday,
        )?;
        Ok(w.taddr(yewd_wallet::keys::EXTERNAL, 0))
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
        let exists = self.wallet_dir().join("wallet.json").exists();
        // a new wallet's birthday: the node's height now (a new seed has no earlier history)
        let height = if exists {
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
                    .init(height)
                    .map_err(|e| RpcError::new(code::WALLET_ERROR, format!("yewd: {e}")))?;
                let s = SocketSigner::spawn(&bin, &dir, self.network)
                    .map_err(|e| RpcError::new(code::WALLET_UNLOCK_NEEDED, format!("yewd: {e}")))?;
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

    /// The poll fallback: sync every `every` until the process stops.
    pub fn spawn_poll(self: &Arc<Self>, every: Duration) {
        let me = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(every).await;
                let mut slot = me.wallet.lock().await;
                if me.ensure_open(&mut slot).await.is_err() {
                    continue;
                }
                if let Some(w) = slot.as_mut() {
                    if let Err(e) = w.sync(&me.node).await {
                        if me.debug {
                            eprintln!("yewd: wallet sync: {e}");
                        }
                    }
                }
            }
        });
    }
}
