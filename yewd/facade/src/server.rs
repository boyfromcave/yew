// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The JSON-RPC server: ycashd's HTTP conventions (POST only, Basic auth with a 250 ms delay on
//! a bad password, `-rpcallowip`, JSON-RPC 1.0 replies `{"result","error","id"}` with HTTP 404 for
//! `-32601`, 400 for `-32600`, 500 for other errors, batches answered with 200), the method table
//! (`methods.rs`), forwarding of every node RPC to the backend, and the façade's own `help`/`stop`.

use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use serde_json::value::RawValue;
use tokio::net::TcpListener;
use tokio::sync::watch;

use crate::allowip::AllowIp;
use crate::auth::Credentials;
use crate::backend::{Backend, BackendError};
use crate::methods::{self, Class};

/// ycashd's JSON-RPC error codes the façade answers with (`src/rpc/protocol.h`).
pub mod code {
    pub const MISC_ERROR: i64 = -1;
    pub const IN_WARMUP: i64 = -28;
    pub const INVALID_REQUEST: i64 = -32600;
    pub const METHOD_NOT_FOUND: i64 = -32601;
    pub const PARSE_ERROR: i64 = -32700;
}

/// The largest request body accepted (ycashd's limit is 32 MB, `httpserver.cpp` MAX_SIZE).
const MAX_BODY: usize = 32 * 1024 * 1024;

pub struct Facade {
    pub creds: Credentials,
    pub allow: AllowIp,
    pub backend: Backend,
    pub stop_backend: bool,
    pub debug: bool,
    shutdown: watch::Sender<bool>,
}

#[derive(Deserialize)]
struct Envelope<'a> {
    #[serde(borrow, default)]
    method: Option<&'a RawValue>,
    #[serde(borrow, default)]
    id: Option<&'a RawValue>,
    #[serde(borrow, default)]
    params: Option<&'a RawValue>,
}

/// One JSON-RPC reply: an HTTP status and the reply object's bytes (no trailing newline).
type Reply = (StatusCode, Bytes);

fn error_reply(code: i64, message: &str, id: Option<&RawValue>) -> Reply {
    let status = match code {
        code::METHOD_NOT_FOUND => StatusCode::NOT_FOUND,
        code::INVALID_REQUEST => StatusCode::BAD_REQUEST,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    let id = id.map(RawValue::get).unwrap_or("null");
    let msg = serde_json::to_string(message).unwrap_or_else(|_| "\"\"".into());
    (
        status,
        Bytes::from(format!(
            r#"{{"result":null,"error":{{"code":{code},"message":{msg}}},"id":{id}}}"#
        )),
    )
}

fn result_reply(result: &serde_json::Value, id: Option<&RawValue>) -> Reply {
    let id = id.map(RawValue::get).unwrap_or("null");
    (
        StatusCode::OK,
        Bytes::from(format!(r#"{{"result":{result},"error":null,"id":{id}}}"#)),
    )
}

fn trim_newline(b: Bytes) -> Bytes {
    let mut n = b.len();
    while n > 0 && matches!(b[n - 1], b'\n' | b'\r') {
        n -= 1;
    }
    b.slice(..n)
}

impl Facade {
    pub fn new(
        creds: Credentials,
        allow: AllowIp,
        backend: Backend,
        stop_backend: bool,
        debug: bool,
    ) -> (Arc<Self>, watch::Receiver<bool>) {
        let (tx, rx) = watch::channel(false);
        (
            Arc::new(Facade {
                creds,
                allow,
                backend,
                stop_backend,
                debug,
                shutdown: tx,
            }),
            rx,
        )
    }

    async fn handle(
        self: Arc<Self>,
        req: Request<Incoming>,
        peer: IpAddr,
    ) -> Response<Full<Bytes>> {
        let plain = |status: StatusCode, text: &'static str| {
            let mut r = Response::new(Full::new(Bytes::from_static(text.as_bytes())));
            *r.status_mut() = status;
            r
        };
        if !self.allow.allows(peer) {
            return plain(StatusCode::FORBIDDEN, "");
        }
        if req.method() != Method::POST {
            return plain(
                StatusCode::METHOD_NOT_ALLOWED,
                "JSONRPC server handles only POST requests",
            );
        }
        if !self.creds.check(
            req.headers()
                .get(hyper::header::AUTHORIZATION)
                .map(|v| v.as_bytes()),
        ) {
            eprintln!("yewd: incorrect password attempt from {peer}");
            tokio::time::sleep(Duration::from_millis(250)).await;
            let mut r = plain(StatusCode::UNAUTHORIZED, "");
            r.headers_mut().insert(
                hyper::header::WWW_AUTHENTICATE,
                hyper::header::HeaderValue::from_static("Basic realm=\"jsonrpc\""),
            );
            return r;
        }
        let path = req.uri().path().to_string();
        let body = match Limited::new(req.into_body(), MAX_BODY).collect().await {
            Ok(b) => b.to_bytes(),
            Err(_) => return plain(StatusCode::PAYLOAD_TOO_LARGE, ""),
        };
        let (status, out) = self.dispatch(&path, body).await;
        let mut bytes = Vec::with_capacity(out.len() + 1);
        bytes.extend_from_slice(&out);
        bytes.push(b'\n');
        let mut r = Response::new(Full::new(Bytes::from(bytes)));
        *r.status_mut() = status;
        r.headers_mut().insert(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("application/json"),
        );
        r
    }

    /// A request body: one call, or a batch (answered with HTTP 200, each element in order).
    pub async fn dispatch(&self, path: &str, body: Bytes) -> Reply {
        let first = body.iter().find(|b| !b.is_ascii_whitespace()).copied();
        if first != Some(b'[') {
            return self.one(path, body).await;
        }
        let elems: Vec<&RawValue> = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(_) => return error_reply(code::PARSE_ERROR, "Parse error", None),
        };
        let mut out = Vec::from(&b"["[..]);
        for (i, e) in elems.iter().enumerate() {
            if i > 0 {
                out.push(b',');
            }
            let (_, r) = self
                .one(path, Bytes::copy_from_slice(e.get().as_bytes()))
                .await;
            out.extend_from_slice(&r);
        }
        out.push(b']');
        (StatusCode::OK, Bytes::from(out))
    }

    async fn one(&self, path: &str, body: Bytes) -> Reply {
        let env: Envelope = match serde_json::from_slice(&body) {
            Ok(e) => e,
            Err(_) => return error_reply(code::PARSE_ERROR, "Parse error", None),
        };
        let id = env.id;
        let method: String = match env.method.map(|m| serde_json::from_str::<String>(m.get())) {
            None => return error_reply(code::INVALID_REQUEST, "Missing method", id),
            Some(Err(_)) => {
                return error_reply(code::INVALID_REQUEST, "Method must be a string", id)
            }
            Some(Ok(m)) => m,
        };
        if self.debug {
            eprintln!("yewd: {method}");
        }
        match methods::classify(&method) {
            Some(Class::Wallet { stage, .. }) => error_reply(
                code::METHOD_NOT_FOUND,
                &methods::not_implemented_message(&method, stage),
                id,
            ),
            Some(Class::OutOfScope) => error_reply(
                code::METHOD_NOT_FOUND,
                &methods::out_of_scope_message(&method),
                id,
            ),
            Some(Class::Own) if method == "help" => {
                self.help(path, body.clone(), env.params, id).await
            }
            Some(Class::Own) => self.stop(path, id).await,
            // node RPCs, the raw helpers (S4 serves them locally) and the augmented reads
            // (S1 adds the wallet fields): forwarded unchanged in S0
            Some(Class::Local | Class::Augmented) | None => {
                self.forward(path, body.clone(), id).await
            }
        }
    }

    async fn forward(&self, path: &str, body: Bytes, id: Option<&RawValue>) -> Reply {
        match self.backend.call(path, body).await {
            Ok((status, out)) => (status, trim_newline(out)),
            Err(e @ BackendError::Unreachable(_)) => {
                error_reply(code::IN_WARMUP, &format!("yewd: {e}"), id)
            }
            Err(e) => error_reply(code::MISC_ERROR, &format!("yewd: {e}"), id),
        }
    }

    async fn help(
        &self,
        path: &str,
        body: Bytes,
        params: Option<&RawValue>,
        id: Option<&RawValue>,
    ) -> Reply {
        let topic = params
            .and_then(|p| serde_json::from_str::<Vec<serde_json::Value>>(p.get()).ok())
            .and_then(|v| v.first().and_then(|t| t.as_str().map(str::to_string)));
        if let Some(m) = topic {
            return match methods::classify(&m) {
                Some(Class::Wallet { stage, .. }) => result_reply(
                    &serde_json::Value::String(format!(
                        "{m}\n\n{}\n",
                        methods::not_implemented_message(&m, stage)
                    )),
                    id,
                ),
                Some(Class::OutOfScope) => result_reply(
                    &serde_json::Value::String(format!(
                        "{m}\n\n{}\n",
                        methods::out_of_scope_message(&m)
                    )),
                    id,
                ),
                Some(Class::Own) if m == "stop" => result_reply(
                    &serde_json::Value::String(
                        "stop\n\nStop yewd (and, with -stopbackend, the backend node).\n".into(),
                    ),
                    id,
                ),
                _ => self.forward(path, body, id).await,
            };
        }
        let (status, out) = self.forward(path, body, id).await;
        if status != StatusCode::OK {
            return (status, out);
        }
        let text = serde_json::from_slice::<serde_json::Value>(&out)
            .ok()
            .and_then(|v| v.get("result").and_then(|r| r.as_str().map(str::to_string)))
            .unwrap_or_default();
        result_reply(
            &serde_json::Value::String(format!("{text}{}", wallet_help_section())),
            id,
        )
    }

    async fn stop(&self, path: &str, id: Option<&RawValue>) -> Reply {
        let mut text = "yewd stopping".to_string();
        if self.stop_backend {
            let stop =
                Bytes::from_static(br#"{"jsonrpc":"1.0","id":"yewd","method":"stop","params":[]}"#);
            match self.backend.call(path, stop).await {
                Ok(_) => text.push_str(" (backend stopping)"),
                Err(e) => eprintln!("yewd: stop: {e}"),
            }
        }
        let tx = self.shutdown.clone();
        tokio::spawn(async move {
            // let the reply reach the caller first
            tokio::time::sleep(Duration::from_millis(200)).await;
            let _ = tx.send(true);
        });
        result_reply(&serde_json::Value::String(text), id)
    }

    /// Ask the server to stop (as `stop` does, without touching the backend).
    pub fn shutdown(&self) {
        let _ = self.shutdown.send(true);
    }
}

/// The section `help` appends to the backend's listing.
pub fn wallet_help_section() -> String {
    let mut s = String::from("\n== Wallet (yewd) ==\n");
    for (m, _, stage) in methods::wallet_methods() {
        s.push_str(&format!(
            "{m}  (yewd: not yet implemented, {})\n",
            stage.name()
        ));
    }
    s
}

/// Listen on `addrs` and serve until `shutdown` turns true. Returns the bound addresses (port 0
/// resolved) and the task.
pub async fn serve(
    facade: Arc<Facade>,
    addrs: &[SocketAddr],
    mut shutdown: watch::Receiver<bool>,
) -> std::io::Result<(Vec<SocketAddr>, tokio::task::JoinHandle<()>)> {
    let mut listeners = Vec::new();
    for a in addrs {
        listeners.push(TcpListener::bind(a).await?);
    }
    let bound = listeners
        .iter()
        .map(|l| l.local_addr())
        .collect::<Result<Vec<_>, _>>()?;
    let task = tokio::spawn(async move {
        let mut accepts = tokio::task::JoinSet::new();
        for l in listeners {
            let f = facade.clone();
            accepts.spawn(async move {
                loop {
                    let Ok((stream, peer)) = l.accept().await else {
                        continue;
                    };
                    let f = f.clone();
                    tokio::spawn(async move {
                        let svc = service_fn(move |req| {
                            let f = f.clone();
                            async move { Ok::<_, Infallible>(f.handle(req, peer.ip()).await) }
                        });
                        let _ = hyper::server::conn::http1::Builder::new()
                            .keep_alive(true)
                            .serve_connection(TokioIo::new(stream), svc)
                            .await;
                    });
                }
            });
        }
        while !*shutdown.borrow() {
            if shutdown.changed().await.is_err() {
                break;
            }
        }
        accepts.abort_all();
    });
    Ok((bound, task))
}
