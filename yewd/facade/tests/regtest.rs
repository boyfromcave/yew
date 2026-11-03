// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The S0 backend round trip: a real `ycashd -regtest -disablewallet` behind the façade, reached
//! with its own cookie; `getblockchaininfo` through the façade equals the node's own answer, a
//! wallet method is not forwarded, and `stop` with `-stopbackend` stops both.
//!
//! Needs `YEWD_TEST_YCASHD=<path to ycashd>` (ycash6 at the revision `yewd/PIN` names; kogany
//! once it serves the RPCs). Without it the test prints a note and passes, unless
//! `YEWD_TEST_REQUIRE_BACKEND=1` (the CI leg sets both).

mod common;

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use common::*;
use hyper::StatusCode;
use yewd_facade::backend::Backend;
use yewd_facade::config::BackendAuth;

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Kill(std::process::Child);

impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
async fn getblockchaininfo_round_trips_through_ycashd() {
    let Some(ycashd) = std::env::var_os("YEWD_TEST_YCASHD").map(PathBuf::from) else {
        assert!(
            std::env::var("YEWD_TEST_REQUIRE_BACKEND").as_deref() != Ok("1"),
            "YEWD_TEST_REQUIRE_BACKEND=1 but YEWD_TEST_YCASHD is unset"
        );
        eprintln!("regtest round trip skipped: set YEWD_TEST_YCASHD=<ycashd>");
        return;
    };
    let dir = scratch("regtest");
    let node_dir = dir.join("node");
    std::fs::create_dir_all(&node_dir).unwrap();
    std::fs::write(node_dir.join("ycash.conf"), "").unwrap();
    let rpc = free_port();
    let child = Command::new(&ycashd)
        .arg("-regtest")
        .arg(format!("-datadir={}", node_dir.display()))
        .arg("-disablewallet")
        .arg(format!("-rpcport={rpc}"))
        .arg(format!("-port={}", free_port()))
        .args([
            "-listen=0",
            "-discover=0",
            "-showmetrics=0",
            "-printtoconsole=0",
        ])
        .arg("-i-am-aware-zcashd-will-be-replaced-by-zebrad-and-zallet-in-2025")
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("start ycashd");
    let mut child = Kill(child);
    let cookie = node_dir.join("regtest/.cookie");
    let backend: std::net::SocketAddr = format!("127.0.0.1:{rpc}").parse().unwrap();

    // the façade starts first and answers -28 until the node is up (hazard H5)
    let f = facade(
        &dir,
        backend,
        &cookie,
        &["-rpcuser=u", "-rpcpassword=p", "-stopbackend"],
    )
    .await;
    let c = client(&f, "u", "p");
    let deadline = Instant::now() + Duration::from_secs(120);
    let via_facade = loop {
        let (status, v, _) = call(&c, "getblockchaininfo", "[]").await;
        if status == StatusCode::OK {
            break v;
        }
        assert_eq!(v["error"]["code"], -28, "{v}");
        assert!(Instant::now() < deadline, "ycashd did not come up: {v}");
        assert!(child.0.try_wait().unwrap().is_none(), "ycashd exited");
        tokio::time::sleep(Duration::from_millis(250)).await;
    };
    let direct = Backend::new(backend, BackendAuth::Cookie(cookie.clone()));
    let (status, v, _) = call(&direct, "getblockchaininfo", "[]").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(via_facade["result"]["chain"], "regtest");
    assert_eq!(
        via_facade["result"], v["result"],
        "the façade changed the node's answer"
    );
    assert_eq!(via_facade["id"], "t");

    // a ycashd wallet method outside the façade's scope answers from the table; the node (which
    // has no wallet) never sees it (getbalance is served since S1, through the signer)
    let (status, v, _) = call(&c, "dumpwallet", "[]").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{v}");
    assert!(v["error"]["message"]
        .as_str()
        .unwrap()
        .starts_with("yewd: not served"));

    // stop stops the pair
    let (_, v, _) = call(&c, "stop", "[]").await;
    assert_eq!(v["result"], "yewd stopping (backend stopping)");
    tokio::time::timeout(Duration::from_secs(10), f.task)
        .await
        .expect("the façade stops")
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    while child.0.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "ycashd did not stop");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    eprintln!(
        "regtest round trip ok: {}",
        via_facade["result"]["bestblockhash"]
    );
}
