// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The attestor role in the signer (plan §3b S3): the 74-byte attestation replayed against the
//! pinned `yellowback_attest_vectors.json` (`vectors[]`, `valid[]`), byte for byte; the
//! equivocation guard (S16, EQV-1 self-protection): the same price again returns the recorded
//! signature, a second price for one `(key, citedHeight, blockHash)` is refused under the same seq
//! and under another seq of the same key, a reorg (another block hash) is not equivocation, and the
//! guard survives a signer restart; the cancel co-signature (price lock through the guard, the
//! claimable statement refused, the message's preimage); `signmessage`; `importprivkey` /
//! `dumpprivkey`; the bond spend's CLTV path.

mod common;

use std::path::PathBuf;

use yew_core::keys;
use yew_core::params::Network;
use yew_core::tx::{OutPoint, Transaction, TxIn, TxOut};
use yewd_proto::{
    refuse, AttestRequest, CosignRequest, Envelope, GatePath, ImportKeyRequest, KeyRef,
    MessageRequest, OwnOutput, Prevout, Request, Response, SignInput, SignRequest, IMPORTED_CHAIN,
};
use yewd_signer::sign::SignerCore;
use yewd_signer::Keystore;

const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("yewd-signer-attest-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn core(d: &std::path::Path) -> SignerCore {
    SignerCore::open(Keystore::from_mnemonic(Network::Regtest, PHRASE), d).unwrap()
}

fn ask(c: &SignerCore, r: Request) -> Response {
    c.handle(&Envelope::new(r))
}

fn import(c: &SignerCore, secret: &[u8]) -> (KeyRef, String) {
    let sk = secp256k1::SecretKey::from_secret_bytes(secret.try_into().unwrap()).unwrap();
    let wif = keys::encode_wif(Network::Regtest, &sk);
    match ask(c, Request::ImportKey(ImportKeyRequest { wif })) {
        Response::ImportedKey(k) => (
            KeyRef::Bip32 {
                chain: IMPORTED_CHAIN,
                index: k.index,
            },
            k.pubkey,
        ),
        other => panic!("{other:?}"),
    }
}

fn attest(
    c: &SignerCore,
    key: KeyRef,
    pubkey: &str,
    seq: u16,
    price: u32,
    cited: u32,
    bh: &str,
) -> Response {
    ask(
        c,
        Request::SignAttestation(AttestRequest {
            key,
            pubkey: pubkey.into(),
            seq,
            price_micro_usd: price,
            cited_height: cited,
            block_hash: bh.into(),
        }),
    )
}

fn refused(r: Response) -> (String, String) {
    match r {
        Response::Refused(f) => (f.code, f.reason),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// `valid[0]` of the pinned file, inline: the replay below needs the file, this does not.
const SECRET0: &str = "d9874f252e363c0d581be654141a3ffe2d753c53d9be3ec18057ecd4fab0717f";
const BH0: &str = "d92227d9e2fbaea0bfbb5ebb44f6df49b79827f385cf21ba8056086ec8c5f44a";
const ATT0: &str = "0000a0860100e8030000c5d41a18a7c5e97962a7f895a2ea6fb47ff9c0912eac4b3bc6a0fc20b4204dd954c0b5d2affb90ef40eb0dfea4be8a671a539d8b5073e86c93bc360598273a68";

#[test]
fn the_attestation_is_ycashds_byte_for_byte() {
    let d = dir("kat");
    let c = core(&d);
    let (k, pk) = import(&c, &keys::unhex(SECRET0).unwrap());
    match attest(&c, k, &pk, 0, 100_000, 1000, BH0) {
        Response::Attestation(a) => {
            assert_eq!(a.hex, ATT0);
            assert!(!a.reused);
        }
        other => panic!("{other:?}"),
    }
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn the_pinned_vectors_replay_in_the_signer() {
    let path = std::env::var_os("YEWD_ATTEST_VECTORS").map(PathBuf::from);
    let found = path.is_some()
        || ["../../../kogany", "../../../../kogany"].iter().any(|u| {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join(u)
                .join("testdata/yellowback/yellowback_attest_vectors.json")
                .exists()
        });
    if !found {
        assert!(
            std::env::var_os("YEWD_REQUIRE_VECTORS").is_none(),
            "yellowback_attest_vectors.json not found (YEWD_ATTEST_VECTORS)"
        );
        eprintln!("skipping: yellowback_attest_vectors.json not found (set YEWD_ATTEST_VECTORS)");
        return;
    }
    let (_, v) = common::load("yellowback_attest_vectors.json", "YEWD_ATTEST_VECTORS");
    let d = dir("vectors");
    let c = core(&d);
    let mut n = 0;
    for t in v["vectors"].as_array().unwrap() {
        let Some(secret) = t["secret"].as_str() else {
            continue;
        };
        let (k, pk) = import(&c, &keys::unhex(secret).unwrap());
        assert_eq!(pk, t["pubkey"].as_str().unwrap());
        let r = attest(
            &c,
            k,
            &pk,
            t["seq"].as_u64().unwrap() as u16,
            t["price"].as_u64().unwrap() as u32,
            t["citedHeight"].as_u64().unwrap() as u32,
            t["blockHash"].as_str().unwrap(),
        );
        let Response::Attestation(a) = r else {
            panic!("{r:?}")
        };
        if t["valid"].as_bool() == Some(true) {
            assert_eq!(a.hex, t["attestation"].as_str().unwrap(), "{t}");
        } else {
            // the signer's own output is always the valid encoding, never the listed bad one
            assert_ne!(a.hex, t["attestation"].as_str().unwrap(), "{t}");
        }
        n += 1;
    }
    for t in v["valid"].as_array().unwrap() {
        let key = v["keys"]
            .as_array()
            .unwrap()
            .iter()
            .find(|k| k["pubkey"] == t["pubkey"])
            .unwrap();
        let (k, pk) = import(&c, &keys::unhex(key["secret"].as_str().unwrap()).unwrap());
        let r = attest(
            &c,
            k,
            &pk,
            t["seq"].as_u64().unwrap() as u16,
            t["priceMicroUsd"].as_u64().unwrap() as u32,
            t["citedHeight"].as_u64().unwrap() as u32,
            t["blockHash"].as_str().unwrap(),
        );
        let Response::Attestation(a) = r else {
            panic!("{r:?}")
        };
        assert_eq!(a.hex, t["attestation"].as_str().unwrap());
        n += 1;
    }
    assert_eq!(n, 18, "vectors[] with a secret (10) and valid[] (8)");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn the_guard_refuses_a_second_price_and_survives_a_restart() {
    let d = dir("guard");
    let c = core(&d);
    let (k, pk) = import(&c, &keys::unhex(SECRET0).unwrap());
    let Response::Attestation(first) = attest(&c, k, &pk, 0, 100_000, 1000, BH0) else {
        panic!()
    };
    // the same price: the recorded signature
    let Response::Attestation(again) = attest(&c, k, &pk, 0, 100_000, 1000, BH0) else {
        panic!()
    };
    assert_eq!(
        (again.hex.as_str(), again.reused),
        (first.hex.as_str(), true)
    );
    // another price, same seq
    let (code, why) = refused(attest(&c, k, &pk, 0, 100_001, 1000, BH0));
    assert_eq!(code, refuse::EQUIVOCATION_GUARD);
    assert_eq!(
        why,
        "equivocation-guard: seq 0 already signed 100000 for height 1000"
    );
    // another price under another seq of the same key (a member that left and rejoined)
    let (code, why) = refused(attest(&c, k, &pk, 7, 100_001, 1000, BH0));
    assert_eq!(code, refuse::EQUIVOCATION_GUARD);
    assert_eq!(
        why,
        "equivocation-guard: this key already signed 100000 for height 1000 under seq 0"
    );
    // another block at that height (a reorg): not equivocation
    let other = "11".repeat(32);
    assert!(matches!(
        attest(&c, k, &pk, 0, 100_001, 1000, &other),
        Response::Attestation(_)
    ));
    // out of range; a key that is not the record's
    assert_eq!(
        refused(attest(&c, k, &pk, 0, 99, 1001, BH0)).0,
        refuse::ATTEST_RANGE
    );
    let wrong = KeyRef::Bip32 { chain: 0, index: 0 };
    assert_eq!(
        refused(attest(&c, wrong, &pk, 0, 100_000, 1001, BH0)).0,
        refuse::KEY_MISMATCH
    );
    // a restart: the guard is on disk
    drop(c);
    let c = core(&d);
    let (code, _) = refused(attest(&c, k, &pk, 0, 100_002, 1000, BH0));
    assert_eq!(code, refuse::EQUIVOCATION_GUARD);
    let Response::Attestation(back) = attest(&c, k, &pk, 0, 100_000, 1000, BH0) else {
        panic!()
    };
    assert_eq!((back.hex, back.reused), (first.hex, true));
    let _ = std::fs::remove_dir_all(&d);
}

fn cosign(c: &SignerCore, key: KeyRef, pk: &str, price: Option<u32>, collateral: i64) -> Response {
    ask(
        c,
        Request::CancelCosign(CosignRequest {
            key,
            pubkey: pk.into(),
            seq: 0,
            set_id: "5e".repeat(32),
            intent: format!("{}:1", "c1".repeat(32)),
            ref_height: 950,
            block_hash: "b1".repeat(32),
            price_micro_usd: price,
            collateral_zat: collateral,
            minted_cents: 10_000,
            claim_threshold_bps: 12_500,
        }),
    )
}

#[test]
fn the_cancel_cosignature_locks_its_price() {
    let d = dir("cosign");
    let c = core(&d);
    let (k, pk) = import(&c, &keys::unhex(SECRET0).unwrap());
    // no price and none signed for R
    assert_eq!(
        refused(cosign(&c, k, &pk, None, 3 * 100_000_000)).0,
        refuse::PRICE_REQUIRED
    );
    // 3 YEC at $40 against $100 of debt at 125 %: 120 % < θ, claimable: refused, nothing recorded
    assert_eq!(
        refused(cosign(&c, k, &pk, Some(40_000_000), 3 * 100_000_000)).0,
        refuse::CANCEL_STATEMENT_CLAIMABLE
    );
    assert!(c.guard.lock().unwrap().is_empty());
    // at $50 it was not
    let Response::Cosign(co) = cosign(&c, k, &pk, Some(50_000_000), 3 * 100_000_000) else {
        panic!()
    };
    assert_eq!(co.price_micro_usd, 50_000_000);
    assert!(!co.reused);
    let e = yewd_proto::attest::CosignEntry::from_bytes(&keys::unhex(&co.cosig).unwrap()).unwrap();
    let msg = yewd_proto::attest::cancel_cosign_message(
        &[0x5e; 32],
        &[0xc1; 32],
        1,
        950,
        50_000_000,
        &[0xb1; 32],
    );
    assert_eq!(
        yewd_proto::act::recover(&msg, &e.sig).map(hex::encode),
        Some(pk.clone())
    );
    // the price is locked for R: the default is it, another is refused, an attestation too
    let Response::Cosign(again) = cosign(&c, k, &pk, None, 3 * 100_000_000) else {
        panic!()
    };
    assert_eq!((again.price_micro_usd, again.reused), (50_000_000, true));
    assert_eq!(
        refused(cosign(&c, k, &pk, Some(60_000_000), 3 * 100_000_000)).0,
        refuse::EQUIVOCATION_GUARD
    );
    assert_eq!(
        refused(attest(&c, k, &pk, 0, 60_000_000, 950, &"b1".repeat(32))).0,
        refuse::EQUIVOCATION_GUARD
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn signmessage_dumpprivkey_and_import() {
    let d = dir("msg");
    let c = core(&d);
    let k = KeyRef::Bip32 { chain: 0, index: 3 };
    let Response::MessageSig(sig) = ask(
        &c,
        Request::SignMessage(MessageRequest {
            key: k,
            message: "binding".into(),
        }),
    ) else {
        panic!()
    };
    let sig: [u8; 65] = keys::unhex(&sig).unwrap().try_into().unwrap();
    let pk = c.bip32_pubkey(0, 3).unwrap();
    assert_eq!(
        yewd_proto::act::recover(&yewd_proto::attest::message_hash("binding"), &sig),
        Some(pk)
    );
    // dump, then import into another signer: the same key, flagged restored
    let Response::Dumped(wif) = ask(&c, Request::DumpKey(k)) else {
        panic!()
    };
    let d2 = dir("msg2");
    let c2 = SignerCore::open(
        Keystore::from_mnemonic(
            Network::Regtest,
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
        ),
        &d2,
    )
    .unwrap();
    assert!(!c2.once.lock().unwrap().restored);
    let Response::ImportedKey(ik) = ask(
        &c2,
        Request::ImportKey(ImportKeyRequest { wif: wif.clone() }),
    ) else {
        panic!()
    };
    assert_eq!(
        (ik.index, ik.pubkey.as_str(), ik.new),
        (0, hex::encode(pk).as_str(), true)
    );
    assert!(c2.once.lock().unwrap().restored);
    let Response::ImportedKey(ik) = ask(&c2, Request::ImportKey(ImportKeyRequest { wif })) else {
        panic!()
    };
    assert!(!ik.new);
    // the bundle names it; a restart keeps it
    drop(c2);
    let c2 = SignerCore::open(
        Keystore::from_mnemonic(
            Network::Regtest,
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
        ),
        &d2,
    )
    .unwrap();
    let Response::Public(b) = ask(&c2, Request::Public(Default::default())) else {
        panic!()
    };
    assert_eq!(b.imported, vec![hex::encode(pk)]);
    assert!(matches!(
        ask(
            &c2,
            Request::ImportKey(ImportKeyRequest {
                wif: "not a key".into()
            })
        ),
        Response::Refused(_)
    ));
    assert_eq!(
        refused(ask(
            &c2,
            Request::DumpKey(KeyRef::Bip32 {
                chain: IMPORTED_CHAIN,
                index: 5
            })
        ))
        .0,
        refuse::KEY_NOT_HELD
    );
    let _ = std::fs::remove_dir_all(&d);
    let _ = std::fs::remove_dir_all(&d2);
}

#[test]
fn the_bond_is_spent_on_its_cltv_path() {
    let d = dir("bond");
    let c = core(&d);
    let pk = c.bip32_pubkey(0, 2).unwrap();
    let lt = 250u32;
    let bond = yewd_proto::act::bond_script_pubkey(lt, &pk);
    let to = yew_core::script::p2pkh_script(&keys::hash160(&c.bip32_pubkey(0, 5).unwrap()));
    let prev = OutPoint {
        txid: [9; 32],
        n: 0,
    };
    let mut tx = Transaction::new_v4();
    tx.lock_time = lt;
    let mut i = TxIn::new(prev);
    i.sequence = 0xffff_fffe;
    tx.vin.push(i);
    tx.vout.push(TxOut {
        value: 999_990_000,
        script_pubkey: to.clone(),
    });
    let prevouts = vec![Prevout {
        outpoint: format!("{}:0", yew_core::tx::txid_hex(&prev.txid)),
        script: hex::encode(&bond),
        amount_zat: 1_000_000_000,
    }];
    let own = vec![OwnOutput {
        n: 0,
        key: KeyRef::Bip32 { chain: 0, index: 5 },
        bond_locktime: None,
    }];
    let req = |key: KeyRef| {
        let signed = [0u32].into_iter().collect();
        let owns = [0u32].into_iter().collect();
        SignRequest {
            tx: hex::encode(tx.serialize().unwrap()),
            branch_id: 0x6d5b_7a31,
            inputs: vec![SignInput {
                prevout: prevouts[0].clone(),
                key,
                carrier_bundle: None,
            }],
            own_outputs: own.clone(),
            gate_path: GatePath::Vault,
            outflow_cap_zat: 10_000,
            preview: yewd_proto::preview::compute(Network::Regtest, &tx, &prevouts, &signed, &owns),
            sapling: None,
        }
    };
    // the wrong locktime does not own the script
    let bad = req(KeyRef::Bond {
        chain: 0,
        index: 2,
        locktime: lt + 1,
    });
    assert_eq!(refused(ask(&c, Request::Sign(bad))).0, refuse::KEY_MISMATCH);
    let Response::Signed(s) = ask(
        &c,
        Request::Sign(req(KeyRef::Bond {
            chain: 0,
            index: 2,
            locktime: lt,
        })),
    ) else {
        panic!()
    };
    let (t, _) = Transaction::parse(&keys::unhex(&s.tx).unwrap()).unwrap();
    let redeem = yewd_proto::act::bond_redeem_script(lt, &pk);
    assert!(t.vin[0].script_sig.ends_with(&redeem));
    let _ = std::fs::remove_dir_all(&d);
}
