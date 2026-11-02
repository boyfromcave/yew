// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! `vault_vectors.json` replayed in the signer (plan §5 "yewd's CI", the vectors leg): `acts[]`
//! (the `YV` codec, the act message and the recoverable signatures the signer makes over it),
//! `setSigMsgs[]` (the set-signature message), `signatures[]` (RFC 6979 compact signatures,
//! byte-identical to `CKey::SignCompact`) and `signaturesInvalid[]` (refused on recovery), and
//! `ownerSpends[]` (the ZIP-243 sighash recomputed from the bytes and the owner's post-quantum
//! scriptSig the signer builds, byte for byte).

mod common;

use common::{arr, load, unhex};
use yew_core::pq::PqKey;
use yew_core::tx::Transaction;
use yewd_proto::act::{self, Act, Body, Create, Equivocation, OutPoint};

fn outpoint(v: &serde_json::Value) -> OutPoint {
    let b = unhex(v);
    OutPoint {
        txid: b[..32].try_into().unwrap(),
        n: u32::from_le_bytes(b[32..36].try_into().unwrap()),
    }
}

fn body_of(f: &serde_json::Value) -> Body {
    let u = |k: &str| f[k].as_u64().unwrap();
    match u("type") as u8 {
        act::SET_CREATE => Body::Create(Create {
            seats: u("seats") as u8,
            unlock_threshold: u("unlockThreshold") as u8,
            cancel_threshold: u("cancelThreshold") as u8,
            slash_threshold: u("slashThreshold") as u8,
            flags: u("flags") as u8,
            rate_limit_bps: u("rateLimitBps") as u16,
            rate_window: u("rateWindow") as u32,
            liveness_window: u("livenessWindow") as u32,
            bond_min: f["bondMin"].as_i64().unwrap(),
            bond_lock_min: u("bondLockMin") as u32,
            maturity: u("maturity") as u32,
            admit_key: arr(&f["admitKey"]),
        }),
        act::SET_JOIN => Body::Join {
            set_id: arr(&f["setId"]),
            member_key: arr(&f["memberKey"]),
            bond_locktime: u("bondLocktime") as u32,
            bond_vout: u("bondVout") as u8,
        },
        act::SET_HEARTBEAT => Body::Heartbeat {
            set_id: arr(&f["setId"]),
            member_key: arr(&f["memberKey"]),
        },
        act::SET_REMOVE => Body::Remove {
            set_id: arr(&f["setId"]),
            member_key: arr(&f["memberKey"]),
            burn: u("burn") as u8,
        },
        act::SET_EQUIVOCATION => Body::Equivocation(Box::new(Equivocation {
            set_id: arr(&f["setId"]),
            prevout: outpoint(&f["prevout"]),
            role_a: u("roleA") as u8,
            sighash_a: arr(&f["sighashA"]),
            sig_a: arr(&f["sigA"]),
            role_b: u("roleB") as u8,
            sighash_b: arr(&f["sighashB"]),
            sig_b: arr(&f["sigB"]),
        })),
        act::SET_WINDDOWN => Body::Winddown {
            set_id: arr(&f["setId"]),
        },
        t => panic!("type {t}"),
    }
}

fn secret_of(v: &serde_json::Value, label: &str) -> secp256k1::SecretKey {
    let k = v["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["label"] == label)
        .unwrap_or_else(|| panic!("no key {label}"));
    secp256k1::SecretKey::from_secret_bytes(arr(&k["secret"])).unwrap()
}

#[test]
fn acts_replay() {
    let (path, v) = load("vault_vectors.json", "YEWD_VAULT_VECTORS");
    eprintln!("replaying {}", path.display());
    let acts = v["acts"].as_array().unwrap();
    assert!(acts.len() >= 9);
    for a in acts {
        let name = a["name"].as_str().unwrap();
        let body = body_of(&a["fields"]);
        let payload = act::encode_payload(&body);
        assert_eq!(payload, unhex(&a["payload"]), "{name}: payload");
        assert_eq!(
            act::decode_payload(&payload).unwrap(),
            body,
            "{name}: decode"
        );
        let msg = act::act_msg(&payload, &outpoint(&a["prevout"]));
        assert_eq!(msg.to_vec(), unhex(&a["actMsg"]), "{name}: act message");
        // the signer's signatures over the message are the vector's, and recover to the signers
        let mut sigs = Vec::new();
        for (i, label) in a["signers"].as_array().unwrap().iter().enumerate() {
            let sk = secret_of(&v, label.as_str().unwrap());
            let sig = act::sign_recoverable(&sk, &msg);
            assert_eq!(sig.to_vec(), unhex(&a["sigs"][i]), "{name}: signature {i}");
            let rec = act::recover(&msg, &sig).unwrap();
            assert_eq!(
                rec.to_vec(),
                unhex(&a["recovered"][i]),
                "{name}: recovered {i}"
            );
            sigs.push(sig);
        }
        let full = Act { body, sigs };
        let script = act::encode(&full);
        assert_eq!(script, unhex(&a["script"]), "{name}: script");
        assert!(act::is_act_output(&script));
        assert_eq!(act::decode(&script).unwrap(), full, "{name}: decode script");
    }
    for bad in v["actsInvalid"].as_array().unwrap() {
        let p = unhex(&bad["payload"]);
        let name = bad["name"].as_str().unwrap();
        match bad["stage"].as_str().unwrap() {
            "decode" => assert!(act::decode_payload(&p).is_err(), "{name}: decoded"),
            _ => {
                let body = act::decode_payload(&p).unwrap_or_else(|e| panic!("{name}: {e}"));
                let sigs = bad["sigs"]
                    .as_array()
                    .map(|a| a.iter().map(arr::<65>).collect())
                    .unwrap_or_default();
                assert!(
                    !act::fields_valid(&Act { body, sigs }),
                    "{name}: fields accepted"
                );
            }
        }
    }
    for bad in v["actScriptsInvalid"].as_array().unwrap() {
        let s = unhex(&bad["script"]);
        assert!(act::decode(&s).is_err(), "{}: decoded", bad["name"]);
    }
}

#[test]
fn set_sig_msgs_and_signatures_replay() {
    let (_, v) = load("vault_vectors.json", "YEWD_VAULT_VECTORS");
    for m in v["setSigMsgs"].as_array().unwrap() {
        let msg = act::set_sig_msg(
            &arr(&m["setId"]),
            m["role"].as_u64().unwrap() as u8,
            &outpoint(&m["prevout"]),
            &arr(&m["sighash"]),
        );
        assert_eq!(msg.to_vec(), unhex(&m["msg"]));
    }
    for s in v["signatures"].as_array().unwrap() {
        let sk = secp256k1::SecretKey::from_secret_bytes(arr(&s["secret"])).unwrap();
        let msg: [u8; 32] = arr(&s["msg"]);
        let sig = act::sign_recoverable(&sk, &msg);
        assert_eq!(sig.to_vec(), unhex(&s["sig"]), "{}", s["label"]);
        assert_eq!(
            act::recover(&msg, &sig).unwrap().to_vec(),
            unhex(&s["pubkey"])
        );
    }
    for s in v["signaturesInvalid"].as_array().unwrap() {
        let sig: Vec<u8> = unhex(&s["sig"]);
        let Ok(sig) = <[u8; 65]>::try_from(sig) else {
            continue;
        };
        assert!(
            act::recover(&arr(&s["msg"]), &sig).is_none(),
            "{} recovered",
            s["name"]
        );
    }
}

#[test]
fn owner_spends_replay() {
    let (_, v) = load("vault_vectors.json", "YEWD_VAULT_VECTORS");
    let spends = v["ownerSpends"].as_array().unwrap();
    assert!(spends.len() >= 4);
    for s in spends {
        let name = s["name"].as_str().unwrap();
        let raw = unhex(&s["tx"]);
        let (mut tx, _) = Transaction::parse(&raw).unwrap();
        let n = s["nIn"].as_u64().unwrap() as usize;
        let script = unhex(&s["scriptCode"]);
        let amount = s["amount"].as_i64().unwrap();
        let branch = s["branchId"].as_u64().unwrap() as u32;
        tx.vin[n].script_sig.clear();
        let digest = tx.sighash(n, &script, amount, 1, branch).unwrap();
        assert_eq!(digest.to_vec(), unhex(&s["sighash"]), "{name}: sighash");
        // the owner key: the vector's SLH-DSA seed, or its Falcon owner with the recorded entropy
        let selector = s["selector"].as_u64().unwrap() as u8;
        let (key, sig) = if let Some(e) = s.get("falconEntropy") {
            let k = PqKey::from_seed(2, &unhex(&v["falconOwner"]["seed"])).unwrap();
            let sig = k.sign_with_entropy(&digest, &arr(e)).unwrap();
            (k, sig)
        } else {
            let k = PqKey::from_seed(1, &unhex(&v["pqOwner"]["seed"])).unwrap();
            let sig = k.sign(&digest);
            (k, sig)
        };
        let mut sig = sig;
        sig.push(1);
        let ss =
            yewd_signer::sign::owner_script_sig(&script, selector, &sig, key.public_key()).unwrap();
        assert_eq!(ss, unhex(&s["scriptSig"]), "{name}: the owner scriptSig");
    }
}
