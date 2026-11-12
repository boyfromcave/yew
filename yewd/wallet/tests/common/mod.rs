// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The mock chain and the signers the wallet's integration tests share: a scripted chain of real
//! v4 transactions in synthetic blocks behind the [`Node`] interface.

#![allow(dead_code)]

use std::sync::{Arc, Mutex};

pub use serde_json::{json, Value};
pub use yew_core::params::Network;
pub use yew_core::tx::{OutPoint, Transaction, TxIn, TxOut};
use yewd_proto::{PublicBundle, PublicRequest};
use yewd_wallet::node::{Node, NodeError, NodeFuture};
pub use yewd_wallet::{Signer, Wallet};

pub const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

pub struct TestSigner(pub yewd_signer::Keystore);

impl Signer for TestSigner {
    fn public(&self, req: &PublicRequest) -> Result<PublicBundle, String> {
        self.0.public(req).map_err(|e| e.to_string())
    }
}

/// A signer that signs: the real signer core over the test phrase, its records in `dir`.
pub struct CoreSigner(pub yewd_signer::sign::SignerCore);

impl Signer for CoreSigner {
    fn public(&self, req: &PublicRequest) -> Result<PublicBundle, String> {
        match self
            .0
            .handle(&yewd_proto::Envelope::new(yewd_proto::Request::Public(
                req.clone(),
            ))) {
            yewd_proto::Response::Public(b) => Ok(b),
            other => Err(format!("{other:?}")),
        }
    }

    fn request(&self, r: yewd_proto::Request) -> Result<yewd_proto::Response, String> {
        Ok(self.0.handle(&yewd_proto::Envelope::new(r)))
    }
}

pub fn core_signer(dir: &std::path::Path) -> Box<dyn Signer> {
    std::fs::create_dir_all(dir).unwrap();
    Box::new(CoreSigner(
        yewd_signer::sign::SignerCore::open(
            yewd_signer::Keystore::from_mnemonic(Network::Regtest, PHRASE),
            dir,
        )
        .unwrap(),
    ))
}

pub fn signer() -> Box<dyn Signer> {
    Box::new(TestSigner(yewd_signer::Keystore::from_mnemonic(
        Network::Regtest,
        PHRASE,
    )))
}

#[derive(Default)]
pub struct Chain {
    /// (display hash, raw block)
    pub blocks: Vec<(String, Vec<u8>)>,
    pub mempool: Vec<(String, Vec<u8>)>,
    /// What `yed_listtokens` answers (the index's tokens, whatever addresses are asked about).
    pub tokens: Vec<Value>,
    /// The vault upgrade's activation height `getblockchaininfo` reports (none: not scheduled).
    pub vault_height: Option<u64>,
    /// The Sapling outputs of each block, by height.
    pub sapling: Vec<usize>,
    /// Each block's transactions, by height.
    pub txs: Vec<Vec<Vec<u8>>>,
    /// Every transaction `sendrawtransaction` was handed, accepted or not (hex).
    pub sent: Vec<String>,
    /// When set, `sendrawtransaction` refuses with this message (`-26`, or `reject_code`).
    pub reject: Option<String>,
    /// The code of that refusal when not `-26` (a proxy's `-32603`, …).
    pub reject_code: Option<i64>,
    /// When set, `yed_listtokens` fails with this (code, message).
    pub tokens_error: Option<(i64, String)>,
    /// When set, `yed_listtokens` answers this instead of the token list (a malformed answer).
    pub tokens_raw: Option<Value>,
    /// What `yed_getinfo` answers (`-32601` when unset: Yellowback not live).
    pub yed_info: Option<Value>,
    /// When set, `sendrawtransaction`'s answer is lost (a transport error): `true` after the
    /// transaction entered the mempool, `false` without it.
    pub lose_answer: Option<bool>,
    /// The next this many `getbestblockhash` calls fail (the node unreachable: a sync fails).
    pub fail_syncs: u32,
    /// Copied into `fail_syncs` when `sendrawtransaction` accepts (a sync failing right after).
    pub fail_syncs_after_send: u32,
}

#[derive(Clone, Default)]
pub struct MockNode(pub Arc<Mutex<Chain>>);

pub fn rev_hex(b: &[u8]) -> String {
    let mut v = b.to_vec();
    v.reverse();
    hex::encode(v)
}

impl MockNode {
    /// Append a block (on top of the current tip) holding `txs`; `salt` makes sibling blocks differ.
    pub fn mine(&self, txs: Vec<Vec<u8>>, salt: u8) -> String {
        let mut c = self.0.lock().unwrap();
        let prev = c
            .blocks
            .last()
            .map(|(h, _)| {
                hex::decode(h)
                    .unwrap()
                    .into_iter()
                    .rev()
                    .collect::<Vec<u8>>()
            })
            .unwrap_or(vec![0; 32]);
        let mut raw = Vec::new();
        raw.extend_from_slice(&4u32.to_le_bytes());
        raw.extend_from_slice(&prev);
        raw.extend_from_slice(&[0u8; 64]);
        raw.extend_from_slice(&(1_700_000_000u32 + c.blocks.len() as u32).to_le_bytes());
        raw.extend_from_slice(&0x200f0f0fu32.to_le_bytes());
        let mut nonce = [0u8; 32];
        nonce[0] = salt;
        nonce[1] = c.blocks.len() as u8;
        raw.extend_from_slice(&nonce);
        raw.push(0); // empty solution
        raw.push(txs.len() as u8);
        for t in &txs {
            raw.extend_from_slice(t);
        }
        let hash = rev_hex(&yew_core::keys::sha256d(&raw));
        c.blocks.push((hash.clone(), raw));
        let outs = txs
            .iter()
            .map(|t| Transaction::parse(t).unwrap().0.shielded.outputs)
            .sum();
        c.sapling.push(outs);
        c.txs.push(txs.clone());
        let mined: Vec<String> = txs
            .iter()
            .map(|t| Transaction::parse(t).unwrap().1)
            .map(|id| rev_hex(&id))
            .collect();
        c.mempool.retain(|(id, _)| !mined.contains(id));
        hash
    }

    /// Drop the blocks above `height` (their non-coinbase transactions go back to the mempool).
    pub fn disconnect_to(&self, height: usize) {
        let mut c = self.0.lock().unwrap();
        while c.blocks.len() > height + 1 {
            let (_, raw) = c.blocks.pop().unwrap();
            let _ = raw;
            c.sapling.pop();
            c.txs.pop();
        }
    }

    pub fn to_mempool(&self, tx: Vec<u8>) -> String {
        let id = rev_hex(&Transaction::parse(&tx).unwrap().1);
        self.0.lock().unwrap().mempool.push((id.clone(), tx));
        id
    }

    pub fn clear_mempool(&self) {
        self.0.lock().unwrap().mempool.clear();
    }
}

impl Node for MockNode {
    fn call<'a>(&'a self, method: &'a str, params: Value) -> NodeFuture<'a> {
        Box::pin(async move {
            let mut c = self.0.lock().unwrap();
            let p = params.as_array().cloned().unwrap_or_default();
            let tip = c.blocks.len() - 1;
            Ok(match method {
                "getbestblockhash" if c.fail_syncs > 0 => {
                    c.fail_syncs -= 1;
                    return Err(NodeError::Unreachable("mock: connection refused".into()));
                }
                "getbestblockhash" => json!(c.blocks[tip].0),
                "getblockcount" => json!(tip),
                "getblockhash" => {
                    let h = p[0].as_u64().unwrap() as usize;
                    match c.blocks.get(h) {
                        Some((hash, _)) => json!(hash),
                        None => {
                            return Err(NodeError::Rpc {
                                code: -8,
                                message: "Block height out of range".into(),
                            })
                        }
                    }
                }
                "getblock" => {
                    let want = p[0].as_str().unwrap();
                    let (_, raw) =
                        c.blocks
                            .iter()
                            .find(|(h, _)| h == want)
                            .ok_or(NodeError::Rpc {
                                code: -5,
                                message: "Block not found".into(),
                            })?;
                    if p[1].as_u64() == Some(0) {
                        json!(hex::encode(raw))
                    } else {
                        // the Sapling tree's size after this block: every Sapling output so far
                        let upto = c.blocks.iter().position(|(h, _)| h == want).unwrap();
                        let size: usize = c.sapling[..=upto].iter().sum();
                        json!({"trees": {"sapling": {"size": size}}})
                    }
                }
                "getblockchaininfo" => match c.vault_height {
                    Some(h) => json!({
                        "blocks": tip,
                        "upgrades": {"6d5b7a31": {"activationheight": h}},
                        "consensus": {"nextblock": if tip as u64 + 1 >= h { "6d5b7a31" } else { "76b809bb" }},
                    }),
                    None => {
                        json!({"blocks": tip, "upgrades": {}, "consensus": {"nextblock": "76b809bb"}})
                    }
                },
                "sendrawtransaction" => {
                    let hexs = p[0].as_str().unwrap().to_string();
                    drop(c);
                    let mut c = self.0.lock().unwrap();
                    c.sent.push(hexs.clone());
                    if let Some(m) = c.reject.clone() {
                        return Err(NodeError::Rpc {
                            code: c.reject_code.unwrap_or(-26),
                            message: m,
                        });
                    }
                    let raw = hex::decode(&hexs).unwrap();
                    let id = rev_hex(&Transaction::parse(&raw).unwrap().1);
                    match c.lose_answer {
                        Some(accepted) => {
                            if accepted {
                                c.mempool.push((id, raw));
                            }
                            return Err(NodeError::Unreachable("mock: timed out".into()));
                        }
                        None => {
                            c.mempool.push((id.clone(), raw));
                            c.fail_syncs = c.fail_syncs_after_send;
                        }
                    }
                    return Ok(json!(id));
                }
                "z_gettreestate" => json!({"sapling": {}}),
                "vault_getinfo" => {
                    json!({"active": c.vault_height.is_some_and(|h| tip as u64 + 1 >= h)})
                }
                // every set exists (the vault_lock tests name one)
                "set_getinfo" => json!({"unlockthreshold": 1, "memberlist": []}),
                "getblockheader" => {
                    let want = p[0].as_str().unwrap();
                    let h = c
                        .blocks
                        .iter()
                        .position(|(b, _)| b == want)
                        .ok_or(NodeError::Rpc {
                            code: -5,
                            message: "Block not found".into(),
                        })?;
                    json!({"height": h})
                }
                "gettxout" => {
                    // an unspent output of the chain (or, with the mempool flag, of the mempool)
                    let want = p[0].as_str().unwrap();
                    let n = p[1].as_u64().unwrap() as usize;
                    let mut all: Vec<(Option<usize>, Vec<u8>)> = Vec::new();
                    for (h, txs) in c.txs.iter().enumerate() {
                        for t in txs {
                            all.push((Some(h), t.clone()));
                        }
                    }
                    for (_, t) in &c.mempool {
                        all.push((None, t.clone()));
                    }
                    let parsed: Vec<(Option<usize>, Transaction, String)> = all
                        .into_iter()
                        .map(|(h, t)| {
                            let (tx, id) = Transaction::parse(&t).unwrap();
                            (h, tx, rev_hex(&id))
                        })
                        .collect();
                    let spent = parsed.iter().any(|(_, tx, _)| {
                        tx.vin
                            .iter()
                            .any(|i| rev_hex(&i.prevout.txid) == want && i.prevout.n as usize == n)
                    });
                    match parsed.iter().find(|(_, _, id)| id == want) {
                        Some((h, tx, _)) if !spent && n < tx.vout.len() => {
                            let o = &tx.vout[n];
                            json!({
                                "bestblock": c.blocks[tip].0,
                                "confirmations": h.map_or(0, |h| tip - h + 1),
                                "value": o.value as f64 / 1e8,
                                "scriptPubKey": {"hex": hex::encode(&o.script_pubkey)},
                                "coinbase": tx.vin.first().is_some_and(|i| i.prevout.n == u32::MAX),
                            })
                        }
                        _ => Value::Null,
                    }
                }
                "yed_getinfo" => match &c.yed_info {
                    Some(v) => v.clone(),
                    None => {
                        return Err(NodeError::Rpc {
                            code: -32601,
                            message: "Method not found".into(),
                        })
                    }
                },
                "yed_listtokens" => match &c.tokens_error {
                    Some((code, message)) => {
                        return Err(NodeError::Rpc {
                            code: *code,
                            message: message.clone(),
                        })
                    }
                    None => c.tokens_raw.clone().unwrap_or_else(|| json!(c.tokens)),
                },
                "getrawmempool" => json!(c
                    .mempool
                    .iter()
                    .map(|(id, _)| id.clone())
                    .collect::<Vec<_>>()),
                "getrawtransaction" => {
                    let want = p[0].as_str().unwrap();
                    match c.mempool.iter().find(|(id, _)| id == want) {
                        Some((_, raw)) => json!(hex::encode(raw)),
                        None => {
                            return Err(NodeError::Rpc {
                                code: -5,
                                message: "No such mempool transaction".into(),
                            })
                        }
                    }
                }
                m => {
                    return Err(NodeError::Rpc {
                        code: -32601,
                        message: format!("mock: {m}"),
                    })
                }
            })
        })
    }
}

pub fn coinbase(height: u32, script: Vec<u8>, value: i64) -> Vec<u8> {
    let mut t = Transaction::new_v4();
    let mut i = TxIn::new(OutPoint {
        txid: [0; 32],
        n: u32::MAX,
    });
    i.script_sig = vec![0x03, height as u8, (height >> 8) as u8, 0];
    t.vin.push(i);
    t.vout.push(TxOut {
        value,
        script_pubkey: script,
    });
    t.expiry_height = 0;
    t.serialize().unwrap()
}

pub fn payment(from: OutPoint, script: Vec<u8>, value: i64) -> Vec<u8> {
    let mut t = Transaction::new_v4();
    let mut i = TxIn::new(from);
    i.script_sig = vec![0x51]; // never validated by the wallet
    t.vin.push(i);
    t.vout.push(TxOut {
        value,
        script_pubkey: script,
    });
    t.serialize().unwrap()
}

pub fn genesis(node: &MockNode) {
    node.mine(vec![coinbase(0, vec![0x51], 0)], 0);
}

pub fn dir(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("yewd-wallet-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

/// Integer zatoshi of an amount the wallet printed (a JSON number or a string), no float.
pub fn zat(v: &Value) -> i64 {
    let s = match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    let (i, f) = s.split_once('.').unwrap_or((&s, ""));
    let neg = i.starts_with('-');
    let i: i64 = i.trim_start_matches('-').parse().unwrap();
    let mut f = f.to_string();
    assert!(f.len() <= 8, "{s}");
    while f.len() < 8 {
        f.push('0');
    }
    let z = i * 100_000_000 + f.parse::<i64>().unwrap();
    if neg {
        -z
    } else {
        z
    }
}

pub async fn call_json(w: &mut Wallet, node: &MockNode, m: &str, p: &[Value]) -> Value {
    serde_json::from_str(&w.call(node, m, p).await.unwrap().text()).unwrap()
}
