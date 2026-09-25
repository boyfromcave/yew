//! Node-generated vectors (plan W0c, `yellowback-devnet vectors`): the core must reproduce the
//! node's bytes exactly (D-W-3). Files live in `core/tests/vectors/`:
//! `transparent.json`, `addresses.json`, `params.json`, `ywallet.json` (`templates.json` is W2/W4).

use std::path::PathBuf;

use serde_json::Value;
use yew_core::keys::{self, unhex, Chain, KeyRing};
use yew_core::params::{Network, FEE_ZAT, TOKEN_VALUE};
use yew_core::script;
use yew_core::tx::{txid_hex, Transaction};

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

fn load(name: &str) -> Value {
    let p = vectors_dir().join(name);
    let s = std::fs::read_to_string(&p).unwrap_or_else(|e| {
        panic!(
            "missing node vector {}: {e}; run `yellowback-devnet vectors` (plan W0c)",
            p.display()
        )
    });
    serde_json::from_str(&s).expect("valid json")
}

fn network_of(v: &Value) -> Network {
    Network::from_name(v["network"].as_str().expect("network")).expect("known network")
}

fn hex_field(v: &Value, k: &str) -> Vec<u8> {
    unhex(v[k].as_str().unwrap_or_else(|| panic!("{k} is hex"))).expect("hex")
}

/// D-W-3: for every transaction, the unsigned bytes re-serialize identically, every ZIP-243
/// sighash matches the node's `SignatureHash`, and the signed bytes (RFC 6979 through the same
/// libsecp256k1) match `signrawtransaction` byte for byte, as does the txid.
#[test]
fn transparent_signing_vectors_byte_for_byte() {
    let v = load("transparent.json");
    let network = network_of(&v);
    let txs = v["transactions"].as_array().expect("transactions");
    assert!(!txs.is_empty());
    for (n, t) in txs.iter().enumerate() {
        let unsigned = hex_field(t, "unsignedHex");
        let (mut tx, _) = Transaction::parse(&unsigned).expect("parse unsigned");
        assert_eq!(
            tx.serialize().unwrap(),
            unsigned,
            "tx {n}: unsigned re-serialization"
        );
        let branch_id = u32::from_str_radix(t["branchId"].as_str().expect("branchId"), 16).unwrap();
        assert_eq!(
            tx.lock_time as u64,
            t["nLockTime"].as_u64().unwrap_or(0),
            "tx {n}: nLockTime"
        );
        assert_eq!(
            tx.expiry_height as u64,
            t["nExpiryHeight"].as_u64().unwrap_or(0),
            "tx {n}: nExpiryHeight"
        );
        let prevouts = t["prevouts"].as_array().expect("prevouts");
        let keys = t["keys"].as_array().expect("keys");
        let sighashes = t["sighashPerInput"].as_array().expect("sighashPerInput");
        assert_eq!(prevouts.len(), tx.vin.len());
        for (i, p) in prevouts.iter().enumerate() {
            let spk = hex_field(p, "scriptPubKeyHex");
            let amount = p["valueZat"].as_i64().expect("valueZat");
            let key =
                keys::decode_wif(network, keys[i]["wif"].as_str().expect("wif")).expect("wif");
            assert_eq!(
                script::p2pkh_hash(&spk),
                Some(key.hash160),
                "tx {n} input {i}: key pays the prevout"
            );
            let digest = tx
                .sign_p2pkh_input(i, &key.secret, &spk, amount, branch_id)
                .unwrap();
            assert_eq!(
                keys::hex(&digest),
                sighashes[i].as_str().unwrap(),
                "tx {n} input {i}: ZIP-243 sighash"
            );
        }
        let signed = tx.serialize().unwrap();
        assert_eq!(
            keys::hex(&signed),
            t["signedHex"].as_str().unwrap(),
            "tx {n}: signed bytes"
        );
        assert_eq!(
            txid_hex(&tx.txid().unwrap()),
            t["txid"].as_str().unwrap(),
            "tx {n}: txid"
        );
    }
}

/// Address encodings: WIF → key → HASH160 → `s…` and `ye…`, both equal to the node's rendering.
#[test]
fn address_vectors() {
    let v = load("addresses.json");
    let network = network_of(&v);
    let versions = &v["versions"];
    assert_eq!(
        hex_field(versions, "pubkey"),
        network.p2pkh_prefix().to_vec()
    );
    assert_eq!(
        hex_field(versions, "script"),
        network.p2sh_prefix().to_vec()
    );
    assert_eq!(hex_field(versions, "secret"), vec![network.wif_prefix()]);
    assert_eq!(
        hex_field(versions, "yellowback"),
        network.yellowback_prefix().to_vec()
    );
    let keys_ = v["keys"].as_array().expect("keys");
    assert!(!keys_.is_empty());
    for k in keys_ {
        let wif = k["wif"].as_str().unwrap();
        let key = keys::decode_wif(network, wif).unwrap();
        assert_eq!(keys::hex(&key.pubkey), k["pubkeyHex"].as_str().unwrap());
        assert_eq!(keys::hex(&key.hash160), k["hash160Hex"].as_str().unwrap());
        assert_eq!(key.address_s(network), k["address_s"].as_str().unwrap());
        assert_eq!(key.address_ye(network), k["address_ye"].as_str().unwrap());
        assert_eq!(key.wif(network), wif, "WIF re-encodes identically (D-W-11)");
        let parsed = keys::parse_address(network, k["address_ye"].as_str().unwrap()).unwrap();
        assert_eq!(parsed.hash(), key.hash160);
        assert!(parsed.yellowback_form);
    }
}

/// The node's parameters agree with `params.rs`.
#[test]
fn params_vector() {
    let v = load("params.json");
    let c = &v["constants"];
    assert_eq!(c["TOKEN_VALUE"].as_i64(), Some(TOKEN_VALUE));
    assert_eq!(
        c["CARRIER_VALUE"].as_i64(),
        Some(yew_core::params::CARRIER_VALUE)
    );
    assert_eq!(
        c["REF_WINDOW"].as_u64(),
        Some(yew_core::params::REF_WINDOW as u64)
    );
    assert_eq!(
        c["MIN_OUTPUT"].as_u64(),
        Some(yew_core::params::MIN_OUTPUT_CENTS)
    );
    assert_eq!(c["YELLOWBACK_FEE"].as_i64(), Some(FEE_ZAT));
    assert_eq!(v["yed_getinfo"]["params"]["feeZat"].as_i64(), Some(FEE_ZAT));
    assert_eq!(
        v["yed_getinfo"]["params"]["tokenValueZat"].as_i64(),
        Some(TOKEN_VALUE)
    );
    assert_eq!(v["txVersion"]["header"].as_str(), Some("80000004"));
    assert_eq!(v["txVersion"]["versionGroupId"].as_str(), Some("892f2085"));
    let network = network_of(&v);
    let av = &v["addressVersions"][match network {
        Network::Mainnet => "mainnet",
        Network::Testnet => "testnet",
        Network::Regtest => "regtest",
    }];
    assert_eq!(
        hex_field(av, "yellowback"),
        network.yellowback_prefix().to_vec()
    );
}

/// D-W-7: the address Ywallet shows for the plan's fixed mnemonic, per passphrase case.
/// `[owner]` capture from a Ywallet desktop build; `ywallet.json` holds `"pending": true` with
/// null expectations until then, so this test is ignored with that reason (run it with
/// `--ignored` once the file is filled; it still skips itself while `pending`).
#[test]
#[ignore = "ywallet.json is pending the [owner] Ywallet desktop capture (plan W0c, D-W-7)"]
fn ywallet_derivation_vector() {
    let v = load("ywallet.json");
    if v["pending"].as_bool() == Some(true) {
        eprintln!(
            "ywallet.json is pending: {}",
            v["reason"].as_str().unwrap_or("")
        );
        return;
    }
    let network = Network::from_name(v["network"].as_str().unwrap_or("main")).expect("network");
    let mnemonic = v["mnemonic"].as_str().expect("mnemonic");
    assert_eq!(v["derivationPath"].as_str(), Some("m/44'/347'/0'/0/0"));
    for case in v["passphraseCases"].as_array().expect("passphraseCases") {
        let pass = case.as_str().expect("passphrase");
        let k = KeyRing::from_mnemonic(mnemonic, pass)
            .unwrap()
            .key(Chain::External, 0)
            .unwrap();
        let expected = &v["expected"][pass];
        assert_eq!(
            k.address_s(network),
            expected["address_s"].as_str().expect("address_s"),
            "passphrase {pass:?}"
        );
        assert_eq!(
            k.address_ye(network),
            expected["address_ye"].as_str().expect("address_ye"),
            "passphrase {pass:?}"
        );
    }
}

/// W2: the node-built templates' payloads (`templates.json`, `yed_decodepayload` results).
/// `payload::encode` of the decoded form must reproduce `payloadHex`, `payload::decode` the
/// reverse, and `find_payload` on the node's raw transfer must find the same assignments the
/// node's `yed_gettxinfo.assigned` reports (contract rule 3: decoded locally for display).
#[test]
fn template_payload_vectors_round_trip() {
    use yew_core::payload::{self, Assignment, Payload};
    let v = load("templates.json");
    let assignments = |d: &Value| -> Vec<Assignment> {
        d["assignments"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|x| Assignment {
                        vout: x["vout"].as_u64().unwrap() as u8,
                        cents: x["cents"].as_u64().unwrap() as u32,
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    for kind in ["mint", "transfer", "redeem"] {
        let t = &v[kind];
        let hex = hex_field(t, "payloadHex");
        let d = &t["payloadDecoded"];
        assert_eq!(d["type"].as_str().unwrap(), kind);
        assert_eq!(d["version"].as_u64().unwrap(), payload::VERSION as u64);
        let expected = match kind {
            "mint" => {
                let mut owner_key = [0u8; 33];
                owner_key.copy_from_slice(&hex_field(d, "ownerPubKey"));
                Payload::Mint {
                    term_class: match d["termClass"].as_str().unwrap() {
                        "A" => 0,
                        "B" => 1,
                        _ => 2,
                    },
                    cents: d["cents"].as_u64().unwrap() as u32,
                    lock_height: d["lockHeight"].as_u64().unwrap() as u32,
                    ref_height: d["refHeight"].as_u64().unwrap() as u32,
                    owner_key,
                    fee_vout: d["feeVout"].as_u64().unwrap() as u8,
                    attest_fee_vout: d["attestFeeVout"].as_u64().unwrap() as u8,
                }
            }
            "transfer" => Payload::Transfer {
                assignments: assignments(d),
            },
            _ => Payload::Redeem {
                ref_height: d["refHeight"].as_u64().unwrap() as u32,
                fee_vout: d["feeVout"].as_u64().unwrap() as u8,
                attest_fee_vout: d["attestFeeVout"].as_u64().unwrap() as u8,
                assignments: assignments(d),
            },
        };
        assert_eq!(payload::encode(&expected).unwrap(), hex, "{kind}: encode");
        assert_eq!(payload::decode(&hex).unwrap(), expected, "{kind}: decode");
        assert_eq!(
            expected.assigned_cents() as u64,
            d["assignedCents"].as_u64().unwrap_or(0),
            "{kind}: assignedCents"
        );
        // The payload is found in the node's raw transaction at its OP_RETURN.
        let (tx, txid) = Transaction::parse(&hex_field(t, "hex")).unwrap();
        assert_eq!(txid_hex(&txid), t["txid"].as_str().unwrap());
        let fp = payload::find_payload(&tx).unwrap_or_else(|| panic!("{kind}: find_payload"));
        assert_eq!(fp.payload, expected);
        let info_assigned: Vec<(u64, u64)> = t["txinfo"]["assigned"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| (a["vout"].as_u64().unwrap(), a["cents"].as_u64().unwrap()))
            .collect();
        let ours: Vec<(u64, u64)> = match kind {
            "mint" => vec![(1, expected.assigned_cents() as u64)],
            _ => fp
                .payload
                .assignments()
                .iter()
                .map(|a| (a.vout as u64, a.cents as u64))
                .collect(),
        };
        if kind != "mint" {
            assert_eq!(
                ours, info_assigned,
                "{kind}: assignments equal yed_gettxinfo.assigned"
            );
        } else {
            // MINT-1: vout[1] carries the minted cents.
            assert_eq!(info_assigned, vec![(1, d["cents"].as_u64().unwrap())]);
        }
        // Every token output of the template is TOKEN_VALUE.
        for (vout, _) in &info_assigned {
            assert_eq!(
                tx.vout[*vout as usize].value, TOKEN_VALUE,
                "{kind}: vout {vout}"
            );
        }
    }
}
