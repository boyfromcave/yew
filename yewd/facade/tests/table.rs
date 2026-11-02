// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The S0 exit-gate tests, as S1 leaves them: every listed wallet method not served yet answers
//! `-32601`, a served one is answered by the wallet, and no wallet method ever reaches the
//! backend by name; node RPCs are forwarded byte for byte, batches, `help`, `stop`, auth, warm-up.

mod common;

use bytes::Bytes;
use common::*;
use hyper::StatusCode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use yewd_facade::methods;

#[tokio::test]
async fn every_wallet_method_answers_32601() {
    let dir = scratch("table");
    let node = fake_node(&dir).await;
    let f = facade(
        &dir,
        node.addr,
        &node.cookie,
        &["-rpcuser=u", "-rpcpassword=p"],
    )
    .await;
    let c = client(&f, "u", "p");
    let mut n = 0;
    for (m, _, stage) in methods::wallet_methods() {
        n += 1;
        if yewd_wallet::rpc::served(m) {
            // answered by the wallet (here an error: the fake node is no chain), never forwarded
            let (_, v, _) = call(&c, m, "[]").await;
            let msg = v["error"]["message"].as_str().unwrap_or("");
            assert!(!msg.starts_with("yewd: not yet implemented"), "{m}: {msg}");
            continue;
        }
        let (status, v, _) = call(&c, m, "[]").await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{m}");
        assert_eq!(v["error"]["code"], -32601, "{m}");
        let msg = v["error"]["message"].as_str().unwrap();
        assert!(msg.starts_with("yewd: not yet implemented"), "{m}: {msg}");
        assert!(msg.contains(stage.name()), "{m}: {msg}");
        assert_eq!(v["id"], "t");
        assert!(v["result"].is_null());
    }
    assert_eq!(n, 22 + 25 + 1 + 30 + 4);
    for m in methods::OUT_OF_SCOPE {
        let (status, v, _) = call(&c, m, "[]").await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{m}");
        assert_eq!(v["error"]["code"], -32601, "{m}");
        assert!(
            v["error"]["message"]
                .as_str()
                .unwrap()
                .starts_with("yewd: not served"),
            "{m}"
        );
    }
    let seen = node.seen.lock().unwrap().clone();
    for (m, _, _) in methods::wallet_methods() {
        assert!(!seen.iter().any(|s| s == m), "{m} reached the backend");
    }
    for m in methods::OUT_OF_SCOPE {
        assert!(!seen.iter().any(|s| s == m), "{m} reached the backend");
    }
}

#[tokio::test]
async fn node_rpcs_are_forwarded_unchanged() {
    let dir = scratch("forward");
    let node = fake_node(&dir).await;
    let f = facade(
        &dir,
        node.addr,
        &node.cookie,
        &["-rpcuser=u", "-rpcpassword=p"],
    )
    .await;
    let c = client(&f, "u", "p");
    for m in [
        "getblockchaininfo",
        "generate",
        "vault_getinfo",
        "yed_getinfo",
        "decoderawtransaction",
    ] {
        let (status, v, text) = call(&c, m, "[]").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(v["result"]["method"], m);
        // the amount's decimal text survives (nothing is re-encoded through a float)
        assert!(text.contains(r#""amount":1.00000000"#), "{text}");
    }
    let (status, v, _) = call(&c, "nosuchmethod", "[]").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(v["error"]["message"], "Method not found");
    assert_eq!(node.seen.lock().unwrap().len(), 6);
}

#[tokio::test]
async fn batches_mix_local_and_forwarded() {
    let dir = scratch("batch");
    let node = fake_node(&dir).await;
    let f = facade(
        &dir,
        node.addr,
        &node.cookie,
        &["-rpcuser=u", "-rpcpassword=p"],
    )
    .await;
    let c = client(&f, "u", "p");
    let body = r#"[{"id":1,"method":"getblockcount","params":[]},{"id":2,"method":"yed_mint","params":[]},{"id":3,"method":"sendtoaddress"}]"#;
    let (status, out) = c.call("/", Bytes::from(body)).await.unwrap();
    assert_eq!(status, StatusCode::OK);
    let v: Vec<serde_json::Value> = serde_json::from_slice(&out).unwrap();
    assert_eq!(v.len(), 3);
    assert_eq!(v[0]["id"], 1);
    assert_eq!(v[0]["result"]["method"], "getblockcount");
    assert_eq!(v[1]["error"]["code"], -32601);
    assert_eq!(v[2]["id"], 3);
    assert_eq!(v[2]["error"]["code"], -32601);
    assert_eq!(
        *node.seen.lock().unwrap(),
        vec!["getblockcount".to_string()]
    );
}

#[tokio::test]
async fn help_lists_the_wallet_table() {
    let dir = scratch("help");
    let node = fake_node(&dir).await;
    let f = facade(
        &dir,
        node.addr,
        &node.cookie,
        &["-rpcuser=u", "-rpcpassword=p"],
    )
    .await;
    let c = client(&f, "u", "p");
    let (_, v, _) = call(&c, "help", "[]").await;
    let text = v["result"].as_str().unwrap();
    assert!(text.starts_with("== Blockchain =="));
    assert!(text.contains("== Wallet (yewd) =="));
    for (m, _, _) in methods::wallet_methods() {
        assert!(text.contains(&format!("\n{m}  ")), "{m}");
    }
    let (_, v, _) = call(&c, "help", r#"["vault_lock"]"#).await;
    assert!(v["result"]
        .as_str()
        .unwrap()
        .contains("yewd: not yet implemented"));
    // a node method's help is the backend's, without the wallet section
    let (_, v, _) = call(&c, "help", r#"["getblockcount"]"#).await;
    assert!(!v["result"].as_str().unwrap().contains("yewd"));
}

#[tokio::test]
async fn cookie_auth_and_refusals() {
    let dir = scratch("auth");
    let node = fake_node(&dir).await;
    let f = facade(&dir, node.addr, &node.cookie, &[]).await;
    let cookie = std::fs::read_to_string(dir.join("regtest/.cookie")).unwrap();
    let (user, pass) = cookie.split_once(':').unwrap();
    let (status, v, _) = call(&client(&f, user, pass), "getblockcount", "[]").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["result"]["method"], "getblockcount");
    let refused = client(&f, user, "wrong")
        .call("/", Bytes::from_static(b"{}"))
        .await;
    assert!(matches!(
        refused,
        Err(yewd_facade::backend::BackendError::Unauthorized)
    ));

    // no Authorization header at all: 401 with the challenge
    let mut s = tokio::net::TcpStream::connect(f.addrs[0]).await.unwrap();
    s.write_all(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
        .await
        .unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).await.unwrap();
    assert!(resp.starts_with("HTTP/1.1 401"), "{resp}");
    assert!(
        resp.to_ascii_lowercase()
            .contains("www-authenticate: basic realm=\"jsonrpc\""),
        "{resp}"
    );

    // GET is refused as ycashd refuses it
    let mut s = tokio::net::TcpStream::connect(f.addrs[0]).await.unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).await.unwrap();
    assert!(resp.starts_with("HTTP/1.1 405"), "{resp}");

    drop(f);
    assert!(
        !dir.join("regtest/.cookie").exists(),
        "the cookie is removed at exit"
    );
}

#[tokio::test]
async fn backend_cookie_is_reread_after_a_restart() {
    let dir = scratch("rotate");
    let node = fake_node(&dir).await;
    let f = facade(
        &dir,
        node.addr,
        &node.cookie,
        &["-rpcuser=u", "-rpcpassword=p"],
    )
    .await;
    let c = client(&f, "u", "p");
    assert_eq!(call(&c, "getblockcount", "[]").await.0, StatusCode::OK);
    write_cookie(&node.cookie, "second"); // the backend restarted with a new cookie
    let (status, v, _) = call(&c, "getblockcount", "[]").await;
    assert_eq!(status, StatusCode::OK, "{v}");
}

#[tokio::test]
async fn unreachable_backend_answers_warmup() {
    let dir = scratch("warmup");
    // a port nothing listens on
    let free = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let cookie = dir.join("missing.cookie");
    let f = facade(&dir, free, &cookie, &["-rpcuser=u", "-rpcpassword=p"]).await;
    let (status, v, _) = call(&client(&f, "u", "p"), "getblockcount", "[]").await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(v["error"]["code"], -28, "{v}");
    // a served wallet method waits for the pair (H5), one not served yet answers from the table
    assert_eq!(
        call(&client(&f, "u", "p"), "getbalance", "[]").await.1["error"]["code"],
        -28
    );
    assert_eq!(
        call(&client(&f, "u", "p"), "sendtoaddress", "[]").await.1["error"]["code"],
        -32601
    );
}

#[tokio::test]
async fn stop_stops_the_facade_and_with_stopbackend_the_node() {
    let dir = scratch("stop");
    let node = fake_node(&dir).await;
    let f = facade(
        &dir,
        node.addr,
        &node.cookie,
        &["-rpcuser=u", "-rpcpassword=p", "-stopbackend"],
    )
    .await;
    let (status, v, _) = call(&client(&f, "u", "p"), "stop", "[]").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["result"], "yewd stopping (backend stopping)");
    tokio::time::timeout(std::time::Duration::from_secs(5), f.task)
        .await
        .expect("the façade stops")
        .unwrap();
    assert_eq!(*node.seen.lock().unwrap(), vec!["stop".to_string()]);
}
