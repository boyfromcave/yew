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
pub mod methods;
pub mod server;

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
    let (cookie, creds) = match &cfg.user_pass {
        Some((u, p)) => (None, auth::Credentials::user_pass(u, p)),
        None => {
            let (c, creds) = auth::Cookie::create(&cfg.cookie_file)?;
            (Some(c), creds)
        }
    };
    let backend = backend::Backend::new(cfg.backend, cfg.backend_auth.clone());
    let (facade, rx) = server::Facade::new(
        creds,
        cfg.allow.clone(),
        backend,
        cfg.stop_backend,
        cfg.debug,
    );
    let (addrs, task) = server::serve(facade.clone(), &cfg.bind, rx).await?;
    Ok(Running {
        addrs,
        facade,
        task,
        cookie,
    })
}
