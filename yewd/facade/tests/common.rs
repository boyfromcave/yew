// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! A fake backend node and a client, for the façade's tests.
#![allow(dead_code)]

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use yewd_facade::auth::basic_header;
use yewd_facade::backend::Backend;
use yewd_facade::config::BackendAuth;
use yewd_facade::{Args, Config, Running};

/// A node stand-in: answers every method with `{"method": <m>, "amount": 1.00000000}` (the
/// amount's text must reach the client unchanged), `-32601` for `nosuchmethod`, and records
/// every method it saw. Authenticates against `cookie` (re-read per request, so a test can rotate it).
pub struct FakeNode {
    pub addr: SocketAddr,
    pub cookie: PathBuf,
    pub seen: Arc<Mutex<Vec<String>>>,
}

pub fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("yewd-test-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

pub fn write_cookie(path: &Path, secret: &str) {
    std::fs::write(path, format!("__cookie__:{secret}")).unwrap();
}

pub async fn fake_node(dir: &Path) -> FakeNode {
    let cookie = dir.join("backend.cookie");
    write_cookie(&cookie, "first");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (c, s) = (cookie.clone(), seen.clone());
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let (c, s) = (c.clone(), s.clone());
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                    let (c, s) = (c.clone(), s.clone());
                    async move {
                        let want = basic_header(std::fs::read_to_string(&c).unwrap().trim());
                        let ok = req
                            .headers()
                            .get("authorization")
                            .map(|v| v.as_bytes() == want.as_bytes())
                            .unwrap_or(false);
                        if !ok {
                            let mut r = Response::new(Full::new(Bytes::new()));
                            *r.status_mut() = StatusCode::UNAUTHORIZED;
                            return Ok::<_, Infallible>(r);
                        }
                        let body = req.into_body().collect().await.unwrap().to_bytes();
                        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
                        let m = v["method"].as_str().unwrap().to_string();
                        let id = v["id"].to_string();
                        s.lock().unwrap().push(m.clone());
                        let (status, text) = match m.as_str() {
                            "nosuchmethod" => (
                                StatusCode::NOT_FOUND,
                                format!(
                                    r#"{{"result":null,"error":{{"code":-32601,"message":"Method not found"}},"id":{id}}}"#
                                ),
                            ),
                            "help" => (
                                StatusCode::OK,
                                format!(
                                    r#"{{"result":"== Blockchain ==\ngetblockcount\n","error":null,"id":{id}}}"#
                                ),
                            ),
                            _ => (
                                StatusCode::OK,
                                format!(
                                    r#"{{"result":{{"method":"{m}","amount":1.00000000}},"error":null,"id":{id}}}"#
                                ),
                            ),
                        };
                        let mut r = Response::new(Full::new(Bytes::from(text + "\n")));
                        *r.status_mut() = status;
                        Ok(r)
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    FakeNode { addr, cookie, seen }
}

/// A façade on an ephemeral port in front of `backend`, with `user:pass` or a cookie.
pub async fn facade(dir: &Path, backend: SocketAddr, cookie: &Path, extra: &[&str]) -> Running {
    let mut v = vec![
        "-regtest".to_string(),
        "-rpcbind=127.0.0.1:0".to_string(),
        format!("-datadir={}", dir.display()),
        format!("-backendrpcport={}", backend.port()),
        format!("-backendrpccookiefile={}", cookie.display()),
    ];
    v.extend(extra.iter().map(|s| s.to_string()));
    let cfg = Config::load(Args::from_cli(v).unwrap()).unwrap();
    yewd_facade::start(&cfg).await.unwrap()
}

/// A client of the façade (the façade's own backend leg, pointed at it).
pub fn client(r: &Running, user: &str, pass: &str) -> Backend {
    Backend::new(r.addrs[0], BackendAuth::UserPass(user.into(), pass.into()))
}

pub async fn call(
    c: &Backend,
    method: &str,
    params: &str,
) -> (StatusCode, serde_json::Value, String) {
    let body = format!(r#"{{"jsonrpc":"1.0","id":"t","method":"{method}","params":{params}}}"#);
    let (status, out) = c.call("/", Bytes::from(body)).await.unwrap();
    let text = String::from_utf8(out.to_vec()).unwrap();
    (status, serde_json::from_str(&text).unwrap(), text)
}
