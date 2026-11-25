// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! A minimal JSON-RPC 1.0 client over HTTP/1.1 (std only) for ycashd or yewd.

use std::io::{Read, Write};
use std::net::TcpStream;

use base64::Engine;
use serde_json::{json, Value};

#[derive(Clone, Debug)]
pub struct Rpc {
    pub addr: String,
    pub auth: String,
}

#[derive(Debug)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
}
impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "rpc error {}: {}", self.code, self.message)
    }
}

impl Rpc {
    pub fn new(addr: &str, user: &str, pass: &str) -> Self {
        Rpc { addr: addr.into(), auth: base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}")) }
    }
    pub fn from_cookie(addr: &str, cookie: &str) -> std::io::Result<Self> {
        let c = std::fs::read_to_string(cookie)?;
        let (u, p) = c.trim().split_once(':').unwrap_or(("", ""));
        Ok(Self::new(addr, u, p))
    }
    /// The node is on this host (127.0.0.0/8, ::1 or "localhost"): a query to it reveals nothing to
    /// another machine.
    pub fn is_loopback(&self) -> bool {
        use std::net::ToSocketAddrs;
        match self.addr.to_socket_addrs() {
            Ok(mut a) => {
                let v: Vec<_> = a.by_ref().collect();
                !v.is_empty() && v.iter().all(|x| x.ip().is_loopback())
            }
            Err(_) => false,
        }
    }
    pub fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let io = |e: std::io::Error| RpcError { code: -1, message: format!("{}: {e}", self.addr) };
        let body = json!({"jsonrpc": "1.0", "id": "yugen", "method": method, "params": params}).to_string();
        let mut s = TcpStream::connect(&self.addr).map_err(io)?;
        write!(
            s,
            "POST / HTTP/1.1\r\nHost: {}\r\nAuthorization: Basic {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            self.addr,
            self.auth,
            body.len(),
            body
        )
        .map_err(io)?;
        let mut resp = Vec::new();
        s.read_to_end(&mut resp).map_err(io)?;
        let text = String::from_utf8_lossy(&resp);
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        let body = if head.to_ascii_lowercase().contains("transfer-encoding: chunked") { dechunk(body) } else { body.to_string() };
        let v: Value = serde_json::from_str(&body).map_err(|_| RpcError { code: -1, message: format!("{}: {}", method, head.lines().next().unwrap_or("")) })?;
        if !v["error"].is_null() {
            return Err(RpcError { code: v["error"]["code"].as_i64().unwrap_or(-1), message: v["error"]["message"].as_str().unwrap_or("").into() });
        }
        Ok(v["result"].clone())
    }
}

fn dechunk(b: &str) -> String {
    let mut out = String::new();
    let mut rest = b;
    while let Some((len, r)) = rest.split_once("\r\n") {
        let n = usize::from_str_radix(len.trim(), 16).unwrap_or(0);
        if n == 0 || r.len() < n {
            break;
        }
        out.push_str(&r[..n]);
        rest = &r[n..].trim_start_matches("\r\n");
    }
    out
}
