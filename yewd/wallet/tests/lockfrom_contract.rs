// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! Every `vault_lock "from"` error row of the vault RPC contract, provoked against yewd and
//! compared with the row's code and message. The contract is `tests/fixtures/vault-rpc-contract.json`,
//! a byte copy of ycash6 `doc/vault-rpc-contract.json` at 82f90b2f9 (`up/b2-wallet-followups-stack`;
//! ycash-dd 4a39e3fcb differs only in its `source.sha256`, kogany `upgrade/vault` 82c14cad4 is
//! identical). The C++ texts the rows abbreviate are compared in full (`src/rpc/vault.cpp`
//! `ParseLockFrom`, `CheckLockFrom`, `FundFromAddress`; `src/yellowback/txbuilder.cpp`
//! `ParseAddressChoice`, `SelectSaplingNotes`). A row this table does not know fails the test, so
//! a contract refresh that adds or changes a `from` row is noticed here.
//!
//! This file is its own test binary: Falcon stays off (no `-pqfalconheight` on regtest), which the
//! scheme-2 row needs, while the send matrix turns it on for the whole of its binary.

mod common;

use common::*;
use sha2::{Digest, Sha256};
use yew_core::pq::PqKeyId;

const CONTRACT: &str = include_str!("fixtures/vault-rpc-contract.json");
/// sha256 of ycash6 82f90b2f9 `doc/vault-rpc-contract.json`. Refresh both together, from the
/// ycash6 tree, byte for byte.
const CONTRACT_SHA256: &str = "2a0e736e2e23afe1aa7dd80c1e82173e8efd14a32c217530e37d4ca34e549681";

/// How yewd meets a contract row: provoked with `from` set to an address, the full C++ text
/// expected; or no yewd source, and why.
enum Provoke {
    From { from: String, text: String },
    NoSource(&'static str),
}

async fn lock(w: &mut Wallet, node: &MockNode, from: &str) -> Result<Value, (i64, String)> {
    lock_value(w, node, json!(from)).await
}

#[test]
fn the_contract_copy_is_the_ycash6_file() {
    assert_eq!(
        hex::encode(Sha256::digest(CONTRACT.as_bytes())),
        CONTRACT_SHA256
    );
}

#[tokio::test]
async fn vault_lock_from_errors_follow_the_contract() {
    assert!(yewd_wallet::falcon_height().is_none());
    let node = MockNode::default();
    node.0.lock().unwrap().vault_height = Some(1);
    genesis(&node);
    let d = dir("lockfromcontract");
    let mut w = Wallet::open(&d, Network::Regtest, core_signer(&d.join("signer")), 0).unwrap();
    w.sync(&node).await.unwrap();
    let text = |v: yewd_wallet::json::J| v.text().trim_matches('"').to_string();
    let empty_t = text(w.call(&node, "getnewaddress", &[]).await.unwrap());
    let empty_z = text(w.call(&node, "z_getnewaddress", &[]).await.unwrap());
    let empty_pq = text(
        w.call(&node, "getnewaddress", &[json!("pqslh")])
            .await
            .unwrap(),
    );
    let foreign_t = yew_core::keys::encode_p2pkh(Network::Regtest, &[0x33; 20]);
    let foreign_pq = yew_core::keys::encode_pq_yec(
        Network::Regtest,
        &PqKeyId {
            scheme: 1,
            hash: [0x66; 32],
        },
    )
    .unwrap();
    let foreign_z = zcash_keys::encoding::encode_payment_address(
        Network::Regtest.sapling_address_hrp(),
        &sapling_crypto::zip32::ExtendedSpendingKey::master(&[7; 32])
            .default_address()
            .1,
    );
    let fn_dsa = yew_core::keys::encode_pq_yec(
        Network::Regtest,
        &PqKeyId {
            scheme: yew_core::pq::SCHEME_FN_DSA_512,
            hash: [0x44; 32],
        },
    )
    .unwrap();

    // contract message -> how yewd meets it
    let table = |m: &str| -> Vec<Provoke> {
        let from = |a: &str, t: &str| Provoke::From {
            from: a.to_string(),
            text: t.to_string(),
        };
        match m {
            "bad-address: from: not a transparent P2PKH, post-quantum or Sapling address of this network" => vec![
                from("nonsense", m),
                from(&yew_core::keys::encode_p2sh(Network::Regtest, &[0x22; 20]), m),
            ],
            "from: not an address of this wallet" => vec![
                from(&foreign_t, m),
                from(&foreign_pq, m),
                from(&foreign_z, m),
            ],
            "from: a watch-only address of this wallet" => vec![Provoke::NoSource(
                "yewd holds no watch-only address (importaddress and the viewing-key imports are outside K-25)",
            )],
            "from: an FN-DSA-512 (scheme 2) address cannot be spent before Falcon is active" => vec![from(
                &fn_dsa,
                "from: an FN-DSA-512 (scheme 2) address cannot be spent before Falcon is active at the next block",
            )],
            "insufficient confirmed funds at" => vec![
                from(&empty_t, &format!("insufficient confirmed funds at {empty_t}: need 1.0001 more")),
                from(&empty_pq, &format!("insufficient confirmed funds at {empty_pq}: need 1.0001 more")),
            ],
            "in confirmed Sapling notes at" => vec![from(
                &empty_z,
                &format!("insufficient-yec: need 1.0001, have 0.00 in confirmed Sapling notes at {empty_z}"),
            )],
            other => panic!("a vault_lock \"from\" contract row this test does not know: {other:?}"),
        }
    };

    let contract: Value = serde_json::from_str(CONTRACT).unwrap();
    let rows: Vec<&Value> = contract["errors"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| {
            e["raisedBy"]
                .as_array()
                .unwrap()
                .iter()
                .any(|m| m == "vault_lock")
                && e["provokedBy"].as_str().unwrap().starts_with("`from`")
        })
        .collect();
    assert_eq!(rows.len(), 6, "the vault_lock \"from\" rows");
    let mut provoked = 0;
    for row in rows {
        let code = row["code"].as_i64().unwrap();
        let message = row["message"].as_str().unwrap();
        for p in table(message) {
            match p {
                Provoke::NoSource(why) => eprintln!("{message:?}: no yewd source: {why}"),
                Provoke::From { from, text } => {
                    let e = lock(&mut w, &node, &from).await.unwrap_err();
                    assert!(e.1.contains(message), "{from}: {e:?} lacks {message:?}");
                    assert_eq!(e, (code, text), "{from}");
                    provoked += 1;
                }
            }
        }
    }
    assert_eq!(provoked, 9);

    // outside the contract rows, the other ParseLockFrom answers (vault.cpp, txbuilder.cpp)
    assert_eq!(
        lock_value(&mut w, &node, json!(7)).await.unwrap_err(),
        (-8, "from must be an address string".into())
    );
    let sprout = yew_core::keys::base58check_encode(&[&[0x16u8, 0x52][..], &[0u8; 64]].concat());
    assert_eq!(
        lock(&mut w, &node, &sprout).await.unwrap_err(),
        (
            -5,
            "bad-address: from: Sprout addresses are not supported".into()
        )
    );
    assert!(node.0.lock().unwrap().sent.is_empty());
}

async fn lock_value(w: &mut Wallet, node: &MockNode, from: Value) -> Result<Value, (i64, String)> {
    let p = json!({
        "tag": "TEST",
        "setid": "11".repeat(32),
        "delay": 1,
        "ownerheight": 1000,
        "amount": 1.0,
        "from": from,
    });
    match w.call(node, "vault_lock", &[p]).await {
        Ok(v) => Ok(serde_json::from_str(&v.text()).unwrap()),
        Err(e) => Err((e.code, e.message)),
    }
}
