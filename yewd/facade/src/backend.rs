// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The façade→backend leg: one HTTP/1.1 POST per call to the wallet-less node's JSON-RPC
//! endpoint over a small pool of kept-alive connections (a connection per call left thousands of
//! sockets in TIME_WAIT under the parity suites and ran the host out of ephemeral ports, finding
//! F-S5-8), authenticated with the backend's cookie (re-read after a 401, so a backend restart
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

/// Idle kept-alive connections the façade keeps to its backend.
const POOL_MAX: usize = 8;

type Sender = hyper::client::conn::http1::SendRequest<Full<Bytes>>;

pub struct Backend {
    addr: SocketAddr,
    auth: BackendAuth,
    header: Mutex<Option<String>>,
    idle: std::sync::Mutex<Vec<Sender>>,
    /// Set once any call was answered: the backend has been up (the H6 watch's `seen_up`).
    answered: std::sync::atomic::AtomicBool,
}

impl Backend {
    pub fn new(addr: SocketAddr, auth: BackendAuth) -> Self {
        Backend {
            addr,
            auth,
            header: Mutex::new(None),
            idle: std::sync::Mutex::new(Vec::new()),
            answered: std::sync::atomic::AtomicBool::new(false),
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
        self.answered
            .store(true, std::sync::atomic::Ordering::Relaxed);
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

    /// Whether any call has been answered since start.
    pub fn answered(&self) -> bool {
        self.answered.load(std::sync::atomic::Ordering::Relaxed)
    }

    async fn connect(&self) -> Result<Sender, BackendError> {
        let stream = TcpStream::connect(self.addr)
            .await
            .map_err(|e| BackendError::Unreachable(format!("{}: {e}", self.addr)))?;
        let (send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|e| BackendError::Unreachable(e.to_string()))?;
        tokio::spawn(conn);
        Ok(send)
    }

    /// An idle pooled connection that is still open, if any.
    fn take_idle(&self) -> Option<Sender> {
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        while let Some(s) = idle.pop() {
            if !s.is_closed() && s.is_ready() {
                return Some(s);
            }
        }
        None
    }

    fn put_idle(&self, s: Sender) {
        if s.is_closed() {
            return;
        }
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        if idle.len() < POOL_MAX {
            idle.push(s);
        }
    }

    async fn post(
        &self,
        path: &str,
        body: Bytes,
        auth: &str,
    ) -> Result<(StatusCode, Bytes), BackendError> {
        // a pooled connection the backend closed meanwhile fails before any byte is answered:
        // the call is then sent once more on a fresh connection
        if let Some(send) = self.take_idle() {
            match self.post_on(send, path, body.clone(), auth).await {
                Err((true, _)) => {} // never sent: the connection was gone
                r => return r.map_err(|(_, e)| e),
            }
        }
        let send = self.connect().await?;
        self.post_on(send, path, body, auth)
            .await
            .map_err(|(_, e)| e)
    }

    async fn post_on(
        &self,
        mut send: Sender,
        path: &str,
        body: Bytes,
        auth: &str,
    ) -> Result<(StatusCode, Bytes), (bool, BackendError)> {
        let fut = async {
            let req = Request::post(path)
                .header(hyper::header::HOST, self.addr.to_string())
                .header(hyper::header::AUTHORIZATION, auth)
                .header(hyper::header::CONTENT_TYPE, "application/json")
                .body(Full::new(body))
                .map_err(|e| (false, BackendError::Other(e.to_string())))?;
            // is_canceled: hyper never sent the request (the connection had closed)
            let resp = send
                .send_request(req)
                .await
                .map_err(|e| (e.is_canceled(), BackendError::Other(e.to_string())))?;
            let status = resp.status();
            let keep = !resp
                .headers()
                .get(hyper::header::CONNECTION)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.eq_ignore_ascii_case("close"));
            let out = resp
                .into_body()
                .collect()
                .await
                .map_err(|e| (false, BackendError::Other(e.to_string())))?
                .to_bytes();
            Ok((status, out, keep))
        };
        let (status, out, keep) = tokio::time::timeout(CALL_TIMEOUT, fut)
            .await
            .map_err(|_| (false, BackendError::Other("timed out".into())))??;
        if keep {
            self.put_idle(send);
        }
        Ok((status, out))
    }
}
