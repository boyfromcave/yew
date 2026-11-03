// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! `yewd`'s façade: a ycashd-compatible JSON-RPC server in front of a wallet-less node
//! (workspace plan `docs/plans/kogany/kogany-yellowback-plan.md` §3b, §4.3; `yew/docs/plans/yewd-plan.md`).
//! S0: authentication, the method table, forwarding of every node RPC, `help` and `stop`.

pub mod allowip;
pub mod auth;
pub mod backend;
pub mod config;
pub mod indexer;
pub mod methods;
pub mod server;
pub mod wallet;
pub mod ycashd;

use std::net::SocketAddr;
use std::sync::Arc;

pub use config::{Args, Config};

/// A started façade.
pub struct Running {
    pub addrs: Vec<SocketAddr>,
    pub facade: Arc<server::Facade>,
    pub task: tokio::task::JoinHandle<()>,
    /// The cookie file, removed when this is dropped (`None` with `-rpcpassword`).
    pub cookie: Option<auth::Cookie>,
}

/// Write the cookie (when no password is configured), bind and serve.
pub async fn start(cfg: &Config) -> std::io::Result<Running> {
    if let Some(sock) = &cfg.signer {
        return start_with(cfg, wallet::SignerSource::Socket(sock.clone())).await;
    }
    let bin = cfg
        .signer_bin
        .clone()
        .unwrap_or_else(wallet::default_signer_bin);
    start_with(cfg, wallet::SignerSource::Process(bin)).await
}

/// [`start`] with the wallet's signer given (the façade's tests pass an in-process one).
pub async fn start_with(cfg: &Config, signer: wallet::SignerSource) -> std::io::Result<Running> {
    let (cookie, creds) = match &cfg.user_pass {
        Some((u, p)) => (None, auth::Credentials::user_pass(u, p)),
        None => {
            let (c, creds) = auth::Cookie::create(&cfg.cookie_file)?;
            (Some(c), creds)
        }
    };
    let backend = Arc::new(backend::Backend::new(cfg.backend, cfg.backend_auth.clone()));
    let mut service = wallet::WalletService::new(
        cfg.network,
        &cfg.datadir,
        backend.clone(),
        signer,
        cfg.debug,
    );
    service.disabled = cfg.disable_wallet;
    yewd_wallet::set_mocktime(cfg.mocktime);
    yewd_wallet::set_pq_fee_rate(cfg.pq_fee_rate);
    yewd_wallet::set_falcon_height(cfg.falcon_height);
    let wallet = Arc::new(service);
    *wallet.opts.lock().unwrap_or_else(|e| e.into_inner()) = cfg.wallet_args.clone();
    if !cfg.disable_wallet && (cfg.wallet_poll_ms > 0 || cfg.backend_indexer.is_some()) {
        wallet.spawn_poll(std::time::Duration::from_millis(cfg.wallet_poll_ms));
    }
    if let Some(addr) = cfg.backend_indexer.filter(|_| !cfg.disable_wallet) {
        indexer::spawn(addr, wallet.wake.clone(), cfg.debug);
    }
    let (facade, rx) = server::Facade::new(
        creds,
        cfg.allow.clone(),
        backend,
        wallet,
        cfg.stop_backend,
        cfg.debug,
    );
    let lost = match (&cfg.backend_auth, cfg.backend_lost_exit) {
        (_, 0) => None,
        (config::BackendAuth::Cookie(c), n) => Some((Some(c.clone()), n)),
        (_, n) => Some((None, n)),
    };
    if cfg.stop_backend && (cfg.backend_exit_grace > 0 || lost.is_some()) {
        spawn_backend_watch(facade.clone(), cfg.backend, cfg.backend_exit_grace, lost);
    }
    let (addrs, task) = server::serve(facade.clone(), &cfg.bind, rx).await?;
    Ok(Running {
        addrs,
        facade,
        task,
        cookie,
    })
}

/// A backend that is gone crashed unless this façade stopped it, or (cookie auth) it removed its
/// cookie, as a node does on a clean shutdown.
fn lost_is_crash(cookie: Option<&std::path::Path>, stopped_by_us: bool) -> bool {
    !stopped_by_us && cookie.is_none_or(|c| c.exists())
}

/// H6, the pair is one node: with `-stopbackend` the façade exits once its backend has been gone
/// (nothing listening) for `grace` seconds after it was up, as when the node stops itself (an
/// `AbortNode`, a `stop` sent to it directly). A restart within `grace` is followed instead.
/// `lost`: `-backendlostexit` (and the backend's cookie, when it uses one): gone that long without
/// this façade having stopped it (and, with a cookie, with the cookie still on disk) is a crash,
/// not a stop, and the façade logs it and SIGKILLs itself, as the node did.
fn spawn_backend_watch(
    facade: std::sync::Arc<server::Facade>,
    addr: SocketAddr,
    grace: u64,
    lost: Option<(Option<std::path::PathBuf>, u64)>,
) {
    tokio::spawn(async move {
        let mut seen_up = false;
        let mut down_since: Option<std::time::Instant> = None;
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            let up = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                tokio::net::TcpStream::connect(addr),
            )
            .await
            .is_ok_and(|r| r.is_ok());
            // a node that aborted can linger (a crash report being written) with its listener
            // still accepting: with -backendlostexit an RPC must answer too
            // a listener that accepted, or any answered call, means the backend was up, even when
            // it died between two probes right after start (a fault on the first block)
            seen_up |= up || facade.backend.answered();
            let up = up
                && (lost.is_none()
                    || tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        facade.backend.call(
                            "/",
                            bytes::Bytes::from_static(
                                br#"{"jsonrpc":"1.0","id":"watch","method":"getblockcount","params":[]}"#,
                            ),
                        ),
                    )
                    .await
                    .is_ok_and(|r| r.is_ok()));
            if up {
                seen_up = true;
                down_since = None;
                continue;
            }
            if !seen_up {
                continue;
            }
            let since = *down_since.get_or_insert_with(std::time::Instant::now);
            if let Some((cookie, n)) = &lost {
                let stopped = facade
                    .backend_stop_sent
                    .load(std::sync::atomic::Ordering::SeqCst);
                if lost_is_crash(cookie.as_deref(), stopped)
                    && since.elapsed() >= std::time::Duration::from_secs(*n)
                {
                    eprintln!("yewd: the backend was lost (gone {n} s, not stopped by yewd: it crashed); ending as it did (-backendlostexit)");
                    // SAFETY: kill(2) on this process's own pid
                    unsafe { libc::kill(libc::getpid(), libc::SIGKILL) };
                }
            }
            if grace > 0 && since.elapsed() >= std::time::Duration::from_secs(grace) {
                eprintln!("yewd: the backend has been gone {grace} s; stopping (-stopbackend: the pair is one node)");
                facade.shutdown();
                return;
            }
        }
    });
}

#[cfg(test)]
mod lost_tests {
    use super::lost_is_crash;

    #[test]
    fn crash_detection_is_auth_independent() {
        let dir = std::env::temp_dir().join(format!("yewd-lost-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let c = dir.join(".cookie");
        // password auth: lost without a stop from yewd is a crash
        assert!(lost_is_crash(None, false));
        assert!(!lost_is_crash(None, true));
        // cookie auth: the cookie left behind marks a crash, a removed one a clean stop
        std::fs::write(&c, "x").unwrap();
        assert!(lost_is_crash(Some(&c), false));
        assert!(!lost_is_crash(Some(&c), true));
        std::fs::remove_file(&c).unwrap();
        assert!(!lost_is_crash(Some(&c), false));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
