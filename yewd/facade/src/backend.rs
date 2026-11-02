// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The façade→backend leg: one HTTP/1.1 POST per call to the wallet-less node's JSON-RPC
//! endpoint, authenticated with the backend's cookie (re-read after a 401, so a backend restart
//! is followed) or a configured user and password. The body goes out and comes back as bytes:
//! nothing is re-encoded, so amounts keep the node's decimal text.

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use crate::auth::basic_header;
use crate::config::BackendAuth;

/// How long one forwarded call may take (a `generate` of many blocks on regtest is slow).
pub const CALL_TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Debug)]
pub enum BackendError {
    /// Nothing listens, or the cookie is not written yet: the backend is starting (H5).
    Unreachable(String),
    /// The backend refused the credentials twice.
    Unauthorized,
    Other(String),
}

impl std::fmt::Display for BackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackendError::Unreachable(m) => write!(f, "backend not reachable: {m}"),
            BackendError::Unauthorized => f.write_str("backend refused the credentials"),
            BackendError::Other(m) => write!(f, "backend error: {m}"),
        }
    }
}

pub struct Backend {
    addr: SocketAddr,
    auth: BackendAuth,
    header: Mutex<Option<String>>,
}

impl Backend {
    pub fn new(addr: SocketAddr, auth: BackendAuth) -> Self {
        Backend {
            addr,
            auth,
            header: Mutex::new(None),
        }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    async fn auth_header(&self, reload: bool) -> Result<String, BackendError> {
        let mut h = self.header.lock().await;
        if reload || h.is_none() {
            *h = Some(match &self.auth {
                BackendAuth::UserPass(u, p) => basic_header(&format!("{u}:{p}")),
                BackendAuth::Cookie(path) => {
                    let line = tokio::task::spawn_blocking({
                        let path = path.clone();
                        move || std::fs::read_to_string(path)
                    })
                    .await
                    .map_err(|e| BackendError::Other(e.to_string()))?
                    .map_err(|e| {
                        BackendError::Unreachable(format!("cookie {}: {e}", path.display()))
                    })?;
                    basic_header(line.trim())
                }
            });
        }
        Ok(h.clone().unwrap_or_default())
    }

    /// POST `body` to `path` and return the backend's status and body unchanged.
    pub async fn call(&self, path: &str, body: Bytes) -> Result<(StatusCode, Bytes), BackendError> {
        let first = self.auth_header(false).await?;
        let (status, out) = self.post(path, body.clone(), &first).await?;
        if status != StatusCode::UNAUTHORIZED {
            return Ok((status, out));
        }
        let second = self.auth_header(true).await?;
        let (status, out) = self.post(path, body, &second).await?;
        if status == StatusCode::UNAUTHORIZED {
            return Err(BackendError::Unauthorized);
        }
        Ok((status, out))
    }

    async fn post(
        &self,
        path: &str,
        body: Bytes,
        auth: &str,
    ) -> Result<(StatusCode, Bytes), BackendError> {
        let fut = async {
            let stream = TcpStream::connect(self.addr)
                .await
                .map_err(|e| BackendError::Unreachable(format!("{}: {e}", self.addr)))?;
            let (mut send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
                .await
                .map_err(|e| BackendError::Unreachable(e.to_string()))?;
            tokio::spawn(conn);
            let req = Request::post(path)
                .header(hyper::header::HOST, self.addr.to_string())
                .header(hyper::header::AUTHORIZATION, auth)
                .header(hyper::header::CONTENT_TYPE, "application/json")
                .body(Full::new(body))
                .map_err(|e| BackendError::Other(e.to_string()))?;
            let resp = send
                .send_request(req)
                .await
                .map_err(|e| BackendError::Other(e.to_string()))?;
            let status = resp.status();
            let out = resp
                .into_body()
                .collect()
                .await
                .map_err(|e| BackendError::Other(e.to_string()))?
                .to_bytes();
            Ok((status, out))
        };
        tokio::time::timeout(CALL_TIMEOUT, fut)
            .await
            .map_err(|_| BackendError::Other("timed out".into()))?
    }
}
