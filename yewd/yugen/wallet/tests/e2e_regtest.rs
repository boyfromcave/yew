//! M1 end to end on a running regtest devnet (`yugen-devnet up`): yewd 0 shields,
//! sends a leaf transfer to yewd 1's request, the node mines it, yewd 1 credits the applied note.
//! Needs YUGEN_E2E_NODE, YUGEN_E2E_YEWD0, YUGEN_E2E_YEWD1 (host:port), YUGEN_E2E_USER,
//! YUGEN_E2E_PASS. Skips, saying why, when they are unset or the node has no Yugen RPCs.

use serde_json::{json, Value};
use yewd_yugen::node::Rpc;

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|s| !s.is_empty())
}

#[test]
fn m1_shield_send_receive() {
    let (Some(node), Some(y0), Some(y1)) = (env("YUGEN_E2E_NODE"), env("YUGEN_E2E_YEWD0"), env("YUGEN_E2E_YEWD1")) else {
        eprintln!("SKIP m1_shield_send_receive: YUGEN_E2E_NODE/YEWD0/YEWD1 not set (start yugen-devnet up first)");
        return;
    };
    let (u, p) = (env("YUGEN_E2E_USER").unwrap_or_default(), env("YUGEN_E2E_PASS").unwrap_or_default());
    let (node, w0, w1) = (Rpc::new(&node, &u, &p), Rpc::new(&y0, &u, &p), Rpc::new(&y1, &u, &p));
    let info = match node.call("yugen_getinfo", json!([])) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("SKIP m1_shield_send_receive: node side not ready ({e})");
            return;
        }
    };
    let mine = |n: u64| node.call("generate", json!([n])).expect("generate");
    let tip = info["tip_height"].as_u64().unwrap();
    let act = info["activation_height"].as_u64().unwrap();
    if tip < act + 16 {
        mine(act + 16 - tip);
    }
    let _a0 = w0.call("yugen_newaddress", json!([])).unwrap();
    let b0 = w1.call("yugen_newaddress", json!([])).unwrap();
    let shield = w0.call("yugen_shield", json!([_a0, 10.0])).expect("yugen_shield");
    eprintln!("shield {shield}");
    mine(4);
    let bal0 = w0.call("yugen_getbalance", json!([])).unwrap().as_f64().unwrap();
    assert!(bal0 > 9.9 && bal0 < 10.0, "yewd 0 balance after shield: {bal0}");
    mine(16); // the deposit note must be under an anchor
    let send = w0.call("yugen_send", json!([b0, 1.0, {"route": "leaf"}])).expect("yugen_send");
    eprintln!("send {send}");
    assert_eq!(w1.call("yugen_getbalance", json!([])).unwrap().as_f64().unwrap(), 0.0, "credited before mined");
    mine(1);
    assert_eq!(w1.call("yugen_getbalance", json!([])).unwrap().as_f64().unwrap(), 1.0);
    let rec: Value = w1.call("yugen_listreceived", json!([])).unwrap();
    assert!(rec.as_array().unwrap().iter().any(|n| n["applied"] == true && n["amount"] == 1.0), "{rec}");
}
