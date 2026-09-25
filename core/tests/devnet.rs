//! Phase W1 devnet acceptance (plan §6.3, §7 W1), ignored unless `YEW_DEVNET=1`:
//! a fresh YEW wallet receives YEC from node 0, sends YEC back, both confirm on the node,
//! and a restore from the same seed into a fresh database reproduces the balance.
//!
//! Environment (defaults match `scripts/devnet-w1.sh`):
//! - `YEW_DEVNET=1` to run; `YEW_DEVNET_SERVER` (`127.0.0.1:9167`), plain HTTP;
//! - `YELLOWBACK_DEVNET_DIR` (`~/yb-devnet-w1`), `YELLOWBACK_DEVNET_PORTSEED` (`57`);
//! - `YEW_DEVNET_TOOL` (`<workspace>/ycash-dd/contrib/yellowback/devnet/yellowback-devnet`),
//!   `YEW_DEVNET_PYTHON` (`<workspace>/.venv/bin/python`), where `<workspace>` is `yew/..`.
//!
//! Run: `YEW_DEVNET=1 cargo test -p yew-core --test devnet -- --ignored --nocapture`.

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use yew_core::build::yec_send;
use yew_core::coins::yec_balances;
use yew_core::keys;
use yew_core::net::{CompactClient, Server};
use yew_core::params::{reserve_zat, Network, FEE_ZAT};
use yew_core::sync::sync;
use yew_core::wallet::Wallet;

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn env_or(k: &str, d: String) -> String {
    std::env::var(k).unwrap_or(d)
}

/// `yellowback-devnet <args>` with the W1 devnet's dir and portseed; returns stdout trimmed.
fn devnet(args: &[&str]) -> String {
    let py = env_or(
        "YEW_DEVNET_PYTHON",
        workspace()
            .join(".venv/bin/python")
            .to_string_lossy()
            .into(),
    );
    let tool = env_or(
        "YEW_DEVNET_TOOL",
        workspace()
            .join("ycash-dd/contrib/yellowback/devnet/yellowback-devnet")
            .to_string_lossy()
            .into(),
    );
    let home = std::env::var("HOME").unwrap_or_default();
    let out = Command::new(&py)
        .arg(&tool)
        .args(args)
        .env(
            "YELLOWBACK_DEVNET_DIR",
            env_or("YELLOWBACK_DEVNET_DIR", format!("{home}/yb-devnet-w1")),
        )
        .env(
            "YELLOWBACK_DEVNET_PORTSEED",
            env_or("YELLOWBACK_DEVNET_PORTSEED", "57".into()),
        )
        .output()
        .unwrap_or_else(|e| panic!("cannot run {py} {tool}: {e}"));
    assert!(
        out.status.success(),
        "yellowback-devnet {args:?} failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .trim_matches('"')
        .to_string()
}

/// `ycash-cli` on node 0 through the devnet tool.
fn node0(args: &[&str]) -> String {
    let mut a = vec!["cli", "--node", "0", "--"];
    a.extend_from_slice(args);
    devnet(&a)
}

async fn wait_for_height(c: &mut CompactClient, at_least: u64) -> u64 {
    let start = Instant::now();
    loop {
        let h = c.latest_height().await.unwrap();
        if h >= at_least {
            // lightwalletd ingests the block a moment after the node reports it.
            tokio::time::sleep(Duration::from_millis(1500)).await;
            return h;
        }
        assert!(
            start.elapsed() < Duration::from_secs(120),
            "lightwalletd did not reach height {at_least}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

#[tokio::test]
#[ignore = "needs the W1 regtest devnet (scripts/devnet-w1.sh) and YEW_DEVNET=1"]
async fn w1_yec_round_trip_and_restore() {
    if std::env::var("YEW_DEVNET").ok().as_deref() != Some("1") {
        eprintln!("YEW_DEVNET is not 1; skipping");
        return;
    }
    let server =
        Server::parse(&env_or("YEW_DEVNET_SERVER", "127.0.0.1:9167".into()), true).unwrap();
    let mut c = CompactClient::connect(&server)
        .await
        .expect("connect to lightwalletd");
    let info = c.lightd_info_for(Network::Regtest).await.unwrap();
    let dir = std::env::temp_dir().join(format!("yew-devnet-w1-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mnemonic = keys::generate_mnemonic(12).unwrap();
    let birthday = info.block_height.saturating_sub(1);
    let path = dir.join("a.sqlite").to_string_lossy().to_string();
    let mut w = Wallet::open(&path, Network::Regtest, &mnemonic, "", Some(birthday)).unwrap();

    // Empty wallet syncs to zero.
    let r = sync(&mut w, &mut c).await.unwrap();
    assert_eq!(r.yec, (0, 0));
    assert_eq!(r.branch_id, info.branch_id);

    // Fund from node 0, mine, sync.
    let addr = w.receive_address(false).unwrap();
    println!("funding {} ({})", addr.address_ye, addr.address_s);
    let fund_txid = node0(&["sendtoaddress", &addr.address_s, "1.5"]);
    assert_eq!(fund_txid.len(), 64, "sendtoaddress txid: {fund_txid}");
    devnet(&["mine", "1"]);
    let h = c.latest_height().await.unwrap();
    wait_for_height(&mut c, h.max(info.block_height + 1)).await;
    let r = sync(&mut w, &mut c).await.unwrap();
    let funded = 150_000_000i64;
    assert_eq!(r.yec.0 + r.yec.1, funded, "balance after funding: {r:?}");
    assert!(
        r.yec.1 <= reserve_zat(),
        "fee reserve never exceeds its target: {r:?}"
    );
    assert_eq!(
        r.yec.1, 0,
        "one coin larger than the reserve is not reserved"
    );
    let hist = w.store.history().unwrap();
    assert!(
        hist.iter()
            .any(|x| yew_core::tx::txid_hex(&x.txid) == fund_txid
                && x.yec_delta == funded
                && !x.pending),
        "{hist:?}"
    );

    // Send half back to node 0.
    let dest = node0(&["getnewaddress"]);
    let send = 50_000_000i64;
    let p = yec_send::build_yec_send(&w, &dest, send, false, r.tip, r.branch_id).unwrap();
    assert_eq!(p.fee, FEE_ZAT);
    let txid = yec_send::broadcast(&w, &mut c, &p)
        .await
        .expect("broadcast accepted by the node");
    println!("sent {txid}");
    assert_eq!(
        w.store.locks().unwrap().len(),
        p.inputs.len(),
        "inputs locked while pending"
    );
    let (avail, _) = yec_balances(&w.spendable_utxos().unwrap());
    assert!(avail < funded - send, "locked inputs are not spendable");
    devnet(&["mine", "1"]);
    let h = c.latest_height().await.unwrap();
    wait_for_height(&mut c, h + 1).await;
    let r = sync(&mut w, &mut c).await.unwrap();
    let expected = funded - send - FEE_ZAT;
    assert_eq!(r.yec.0 + r.yec.1, expected, "balance after send: {r:?}");
    assert!(
        w.store.locks().unwrap().is_empty(),
        "locks released on confirmation"
    );
    assert!(w.store.pending_txs().unwrap().is_empty());
    let hist = w.store.history().unwrap();
    let row = hist
        .iter()
        .find(|x| yew_core::tx::txid_hex(&x.txid) == txid)
        .expect("send in history");
    assert!(!row.pending && row.height > 0);
    assert_eq!(row.yec_delta, -(send + FEE_ZAT));
    // The node confirms the payment.
    let got = node0(&["getreceivedbyaddress", &dest, "1"]);
    assert_eq!(
        got.parse::<f64>().unwrap(),
        0.5,
        "node 0 received 0.5 YEC at {dest}"
    );
    let raw_on_node = node0(&["getrawtransaction", &txid]);
    assert_eq!(
        raw_on_node,
        keys::hex(&p.raw),
        "the node holds exactly the bytes we built"
    );

    // Restore from seed into a fresh file: same addresses, same balance.
    let path2 = dir.join("b.sqlite").to_string_lossy().to_string();
    let mut w2 = Wallet::open(&path2, Network::Regtest, &mnemonic, "", Some(birthday)).unwrap();
    let r2 = sync(&mut w2, &mut c).await.unwrap();
    assert_eq!(r2.yec, r.yec, "restore reproduces the balance");
    assert_eq!(
        w2.receive_address(false).unwrap().index,
        w.receive_address(false).unwrap().index
    );
    assert_eq!(w2.store.utxos().unwrap(), w.store.utxos().unwrap());
    // WIF export round-trips through the node (D-W-11).
    let wif = w.export_wif(&addr.address_ye).unwrap();
    assert_eq!(
        keys::decode_wif(Network::Regtest, &wif).unwrap().hash160,
        addr.hash160
    );
    println!("W1 devnet round trip ok: funded {funded}, sent {send}, final {expected}");
    let _ = std::fs::remove_dir_all(&dir);
}
