// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The wallet's view of the node: its public JSON-RPC, nothing else (plan §4.3 rule 1). The
//! façade implements [`Node`] over its backend connection (kogany, or ycash6 `-disablewallet`);
//! the wallet's tests implement it over a canned chain.

use std::future::Future;
use std::pin::Pin;

use serde_json::Value;

/// A node RPC error.
#[derive(Clone, Debug, PartialEq)]
pub enum NodeError {
    /// The node answered with a JSON-RPC error.
    Rpc { code: i64, message: String },
    /// The node is not reachable (starting, restarting): the wallet answers `-28` (H5).
    Unreachable(String),
    /// Anything else (a malformed answer).
    Other(String),
}

impl std::fmt::Display for NodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeError::Rpc { code, message } => write!(f, "node error {code}: {message}"),
            NodeError::Unreachable(m) => write!(f, "node not reachable: {m}"),
            NodeError::Other(m) => write!(f, "node: {m}"),
        }
    }
}

impl std::error::Error for NodeError {}

pub type NodeFuture<'a> = Pin<Box<dyn Future<Output = Result<Value, NodeError>> + Send + 'a>>;

/// One JSON-RPC call to the node: `method(params)` → the `result` member.
pub trait Node: Send + Sync {
    fn call<'a>(&'a self, method: &'a str, params: Value) -> NodeFuture<'a>;
}

/// Typed helpers over [`Node::call`].
pub async fn call(node: &dyn Node, method: &str, params: Value) -> Result<Value, NodeError> {
    node.call(method, params).await
}

pub async fn best_hash(node: &dyn Node) -> Result<String, NodeError> {
    str_of(call(node, "getbestblockhash", Value::Array(vec![])).await?)
}

pub async fn block_hash(node: &dyn Node, height: u32) -> Result<String, NodeError> {
    str_of(call(node, "getblockhash", serde_json::json!([height])).await?)
}

pub async fn block_count(node: &dyn Node) -> Result<u32, NodeError> {
    call(node, "getblockcount", Value::Array(vec![]))
        .await?
        .as_u64()
        .map(|h| h as u32)
        .ok_or_else(|| NodeError::Other("getblockcount: not a number".into()))
}

/// The raw block (`getblock <hash> 0`).
pub async fn raw_block(node: &dyn Node, hash: &str) -> Result<Vec<u8>, NodeError> {
    let hex = str_of(call(node, "getblock", serde_json::json!([hash, 0])).await?)?;
    hex::decode(hex).map_err(|e| NodeError::Other(format!("getblock {hash}: {e}")))
}

/// `getblock <hash> 1`.
pub async fn block_info(node: &dyn Node, hash: &str) -> Result<Value, NodeError> {
    call(node, "getblock", serde_json::json!([hash, 1])).await
}

pub async fn mempool(node: &dyn Node) -> Result<Vec<String>, NodeError> {
    let v = call(node, "getrawmempool", Value::Array(vec![])).await?;
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|t| t.as_str().map(str::to_string))
                .collect()
        })
        .ok_or_else(|| NodeError::Other("getrawmempool: not an array".into()))
}

/// A mempool transaction's bytes (`getrawtransaction <txid> 0`); `None` when the node no longer
/// has it (mined or evicted between the two calls).
pub async fn raw_tx(node: &dyn Node, txid: &str) -> Result<Option<Vec<u8>>, NodeError> {
    match call(node, "getrawtransaction", serde_json::json!([txid, 0])).await {
        Ok(v) => {
            let hex = str_of(v)?;
            Ok(Some(hex::decode(hex).map_err(|e| {
                NodeError::Other(format!("getrawtransaction {txid}: {e}"))
            })?))
        }
        Err(NodeError::Rpc { code: -5, .. }) => Ok(None),
        Err(e) => Err(e),
    }
}

fn str_of(v: Value) -> Result<String, NodeError> {
    match v {
        Value::String(s) => Ok(s),
        other => Err(NodeError::Other(format!("expected a string, got {other}"))),
    }
}
