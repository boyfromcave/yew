// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The signer's refusals (plan §3b S2 exit gate, §5 "signer refusals" leg): a request the signer
//! cannot bind to a prevout and an amount is never signed; a preview that disagrees with the bytes
//! (a mutated amount, a swapped recipient, a foreign input) is refused; an outflow above the cap is
//! refused; the sign-once record survives a signer restart and refuses a second sighash for one
//! `(setid, prevout)`; and a request of another protocol version is refused before it is read.

use std::collections::BTreeSet;
use std::path::PathBuf;

use yew_core::keys;
use yew_core::params::Network;
use yew_core::pq::{PqKey, PqSeedRoot};
use yew_core::tx::{OutPoint, Transaction, TxIn, TxOut};
use yew_core::vault::{self, VaultParams};
use yewd_proto::{
    refuse, Envelope, GatePath, KeyRef, OwnOutput, Prevout, Request, Response, SetSignRequest,
    SignInput, SignRequest,
};
use yewd_signer::sign::SignerCore;
use yewd_signer::Keystore;

const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
const BRANCH: u32 = 0x6d5b_7a31;

fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("yewd-signer-policy-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn core(d: &PathBuf) -> SignerCore {
    SignerCore::open(Keystore::from_mnemonic(Network::Regtest, PHRASE), d).unwrap()
}

fn p2pkh_of(c: &SignerCore, chain: u32, index: u32) -> Vec<u8> {
    let pk = c.bip32_pubkey(chain, index).unwrap();
    yew_core::script::p2pkh_script(&keys::hash160(&pk))
}

fn op(n: u8) -> OutPoint {
    OutPoint { txid: [n; 32], n: n as u32 }
}

fn opstr(o: &OutPoint) -> String {
    format!("{}:{}", yew_core::tx::txid_hex(&o.txid), o.n)
}

/// A payment: one wallet coin (m/.../0/0, 5 YEC) to a foreign script (2 YEC), change to m/.../1/0.
fn payment(c: &SignerCore) -> (Transaction, Vec<SignInput>, Vec<OwnOutput>) {
    let mut tx = Transaction::new_v4();
    tx.vin.push(TxIn::new(op(1)));
    tx.vout.push(TxOut { value: 200_000_000, script_pubkey: yew_core::script::p2pkh_script(&[9u8; 20]) });
    tx.vout.push(TxOut { value: 299_990_000, script_pubkey: p2pkh_of(c, 1, 0) });
    let inputs = vec![SignInput {
        prevout: Prevout { outpoint: opstr(&op(1)), script: hex::encode(p2pkh_of(c, 0, 0)), amount_zat: 500_000_000 },
        key: KeyRef::Bip32 { chain: 0, index: 0 },
        carrier_bundle: None,
    }];
    let own = vec![OwnOutput { n: 1, key: KeyRef::Bip32 { chain: 1, index: 0 }, bond_locktime: None }];
    (tx, inputs, own)
}

fn request(tx: &Transaction, inputs: Vec<SignInput>, own: Vec<OwnOutput>, cap: i64) -> SignRequest {
    let prev: Vec<Prevout> = inputs.iter().map(|i| i.prevout.clone()).collect();
    let signed: BTreeSet<u32> = inputs.iter().enumerate().filter(|(_, i)| i.key != KeyRef::None).map(|(n, _)| n as u32).collect();
    let mine: BTreeSet<u32> = own.iter().map(|o| o.n).collect();
    let preview = yewd_proto::preview::compute(Network::Regtest, tx, &prev, &signed, &mine);
    SignRequest {
        tx: hex::encode(tx.serialize().unwrap()),
        branch_id: BRANCH,
        inputs,
        own_outputs: own,
        gate_path: GatePath::Yec,
        outflow_cap_zat: cap,
        preview,
    }
}

fn refused(r: Response) -> (String, String) {
    match r {
        Response::Refused(x) => (x.code, x.reason),
        other => panic!("not refused: {other:?}"),
    }
}

fn ask(c: &SignerCore, r: Request) -> Response {
    c.handle(&Envelope::new(r))
}

#[test]
fn signs_a_bound_payment_and_the_signature_verifies() {
    let d = dir("ok");
    let c = core(&d);
    let (tx, inputs, own) = payment(&c);
    let r = ask(&c, Request::Sign(request(&tx, inputs, own, 210_000_000)));
    let Response::Signed(s) = r else { panic!("{r:?}") };
    let (signed, _) = Transaction::parse(&hex::decode(&s.tx).unwrap()).unwrap();
    assert!(!signed.vin[0].script_sig.is_empty());
    // the digest the signer reports is the ZIP-243 sighash recomputed from the bytes
    let want = tx.sighash(0, &p2pkh_of(&c, 0, 0), 500_000_000, 1, BRANCH).unwrap();
    assert_eq!(s.sighashes[0].as_deref(), Some(hex::encode(want).as_str()));
}

#[test]
fn refuses_requests_it_cannot_bind() {
    let d = dir("bind");
    let c = core(&d);
    let (tx, inputs, own) = payment(&c);
    // no prevout for the input
    let mut r = request(&tx, inputs.clone(), own.clone(), i64::MAX);
    r.inputs.clear();
    assert_eq!(refused(ask(&c, Request::Sign(r))).0, refuse::UNBOUND_INPUT);
    // a prevout that is not the one the transaction spends
    let mut r = request(&tx, inputs.clone(), own.clone(), i64::MAX);
    r.inputs[0].prevout.outpoint = opstr(&op(2));
    assert_eq!(refused(ask(&c, Request::Sign(r))).0, refuse::UNBOUND_INPUT);
    // a negative amount
    let mut r = request(&tx, inputs.clone(), own.clone(), i64::MAX);
    r.inputs[0].prevout.amount_zat = -1;
    assert_eq!(refused(ask(&c, Request::Sign(r))).0, refuse::UNBOUND_INPUT);
    // a key that does not own the prevout
    let mut r = request(&tx, inputs.clone(), own.clone(), i64::MAX);
    r.inputs[0].key = KeyRef::Bip32 { chain: 0, index: 1 };
    assert_eq!(refused(ask(&c, Request::Sign(r))).0, refuse::KEY_MISMATCH);
    // an "own" output the key does not own
    let mut r = request(&tx, inputs, own, i64::MAX);
    r.own_outputs[0].n = 0;
    assert_eq!(refused(ask(&c, Request::Sign(r))).0, refuse::KEY_MISMATCH);
}

#[test]
fn refuses_a_preview_that_lies() {
    let d = dir("preview");
    let c = core(&d);
    let (tx, inputs, own) = payment(&c);
    let honest = request(&tx, inputs.clone(), own.clone(), i64::MAX);
    // the device is shown a smaller payment than the bytes make (a mutated amount)
    let mut r = honest.clone();
    r.preview.outputs[0].amount_zat = 100_000_000;
    let (code, why) = refused(ask(&c, Request::Sign(r)));
    assert_eq!(code, refuse::PREVIEW_MISMATCH, "{why}");
    // the bytes pay another recipient than the preview shows (a swapped recipient)
    let mut swapped = tx.clone();
    swapped.vout[0].script_pubkey = yew_core::script::p2pkh_script(&[7u8; 20]);
    let mut r = request(&swapped, inputs.clone(), own.clone(), i64::MAX);
    r.preview = honest.preview.clone();
    let (code, why) = refused(ask(&c, Request::Sign(r)));
    assert_eq!(code, refuse::PREVIEW_MISMATCH, "{why}");
    assert!(why.contains("output 0"), "{why}");
    // a second wallet coin slipped in that the preview does not list (a foreign input)
    let mut two = tx.clone();
    two.vin.push(TxIn::new(op(3)));
    let mut ins = inputs.clone();
    ins.push(SignInput {
        prevout: Prevout { outpoint: opstr(&op(3)), script: hex::encode(p2pkh_of(&c, 0, 2)), amount_zat: 100_000_000 },
        key: KeyRef::Bip32 { chain: 0, index: 2 },
        carrier_bundle: None,
    });
    let mut r = request(&two, ins, own.clone(), i64::MAX);
    r.preview.sign.truncate(1);
    let (code, why) = refused(ask(&c, Request::Sign(r)));
    assert_eq!(code, refuse::FOREIGN_INPUT, "{why}");
    // the fee shown is not the fee paid
    let mut r = honest;
    r.preview.fee_zat += 1;
    assert_eq!(refused(ask(&c, Request::Sign(r))).0, refuse::PREVIEW_MISMATCH);
}

#[test]
fn refuses_an_outflow_above_the_cap() {
    let d = dir("outflow");
    let c = core(&d);
    let (tx, inputs, own) = payment(&c);
    // the wallet pays 2 YEC + 0.0001 fee beyond its change
    let (code, why) = refused(ask(&c, Request::Sign(request(&tx, inputs.clone(), own.clone(), 200_009_999))));
    assert_eq!(code, refuse::OUTFLOW, "{why}");
    assert!(matches!(ask(&c, Request::Sign(request(&tx, inputs, own, 200_010_000))), Response::Signed(_)));
}

#[test]
fn refuses_template_inputs_on_the_yec_path_and_owner_keys_elsewhere() {
    let d = dir("gate");
    let c = core(&d);
    let root = PqSeedRoot::from_seed(&keys::seed_from_mnemonic(PHRASE, "").unwrap());
    let owner = PqKey::from_seed(1, &root.derive(1, 0)).unwrap().id();
    let vp = VaultParams { tag: *b"TEST", cancel_set_id: [5; 32], delay: 3, set_id: [5; 32], owner_height: 100, owner, app_height: 0 };
    let v = vault::build_vault(&vp).unwrap();
    let mut tx = Transaction::new_v4();
    tx.vin.push(TxIn::new(op(4)));
    tx.vout.push(TxOut { value: 90_000, script_pubkey: p2pkh_of(&c, 0, 0) });
    let inputs = vec![SignInput {
        prevout: Prevout { outpoint: opstr(&op(4)), script: hex::encode(&v), amount_zat: 100_000 },
        key: KeyRef::PqOwner { scheme: 1, index: 0, selector: 2 },
        carrier_bundle: None,
    }];
    let own = vec![OwnOutput { n: 0, key: KeyRef::Bip32 { chain: 0, index: 0 }, bond_locktime: None }];
    let mut r = request(&tx, inputs.clone(), own.clone(), i64::MAX);
    assert_eq!(refused(ask(&c, Request::Sign(r.clone()))).0, refuse::GATE);
    r.gate_path = GatePath::Vault;
    assert_eq!(refused(ask(&c, Request::Sign(r.clone()))).0, refuse::GATE);
    // the owner path signs it, with the owner's post-quantum key, and the signature verifies
    r.gate_path = GatePath::Owner;
    let Response::Signed(s) = ask(&c, Request::Sign(r)) else { panic!() };
    let (signed, _) = Transaction::parse(&hex::decode(&s.tx).unwrap()).unwrap();
    let (sel, sig, pk) = vault::parse_owner_script_sig(vault::Kind::Vault, &signed.vin[0].script_sig).unwrap();
    assert_eq!(sel, 2);
    let digest = tx.sighash(0, &v, 100_000, 1, BRANCH).unwrap();
    assert!(yew_core::pq::verify(1, &pk, &sig[..sig.len() - 1], &digest));
    // another owner index does not own the vault
    let mut wrong = inputs;
    wrong[0].key = KeyRef::PqOwner { scheme: 1, index: 1, selector: 2 };
    let mut r = request(&tx, wrong, own, i64::MAX);
    r.gate_path = GatePath::Owner;
    assert_eq!(refused(ask(&c, Request::Sign(r))).0, refuse::KEY_MISMATCH);
}

fn set_request(tx: &Transaction, v: &[u8], set: [u8; 32], keys: Vec<KeyRef>) -> SetSignRequest {
    SetSignRequest {
        tx: hex::encode(tx.serialize().unwrap()),
        branch_id: BRANCH,
        index: 0,
        prevout: Prevout { outpoint: opstr(&tx.vin[0].prevout), script: hex::encode(v), amount_zat: 1_000_000_000 },
        set_id: yew_core::tx::txid_hex(&set),
        role: 1,
        keys,
        acknowledge_restore: false,
    }
}

#[test]
fn sign_once_survives_a_restart_and_refuses_a_second_sighash() {
    let d = dir("once");
    let set = [6u8; 32];
    let owner = yew_core::pq::PqKeyId { scheme: 1, hash: [8; 32] };
    let vp = VaultParams { tag: *b"TEST", cancel_set_id: set, delay: 3, set_id: set, owner_height: 100, owner, app_height: 0 };
    let v = vault::build_vault(&vp).unwrap();
    let member = KeyRef::Bip32 { chain: 0, index: 5 };
    let unlock = |pay: i64| {
        let mut tx = Transaction::new_v4();
        tx.vin.push(TxIn::new(op(9)));
        tx.vout.push(TxOut { value: pay, script_pubkey: yew_core::script::p2pkh_script(&[1u8; 20]) });
        tx
    };
    let a = unlock(400_000_000);
    let b = unlock(300_000_000);
    {
        let c = core(&d);
        let Response::SetSigs(s) = ask(&c, Request::SignSet(set_request(&a, &v, set, vec![member]))) else { panic!() };
        assert_eq!(s.sigs.len(), 1);
        // the signature recovers to the member key over the set message
        let msg: [u8; 32] = hex::decode(&s.msg).unwrap().try_into().unwrap();
        let sig: [u8; 65] = hex::decode(&s.sigs[0]).unwrap().try_into().unwrap();
        assert_eq!(yewd_proto::act::recover(&msg, &sig).unwrap(), c.bip32_pubkey(0, 5).unwrap());
        // the same transaction re-funded (another fee input) has the same sighash: idempotent
        let mut refunded = a.clone();
        refunded.vin.push(TxIn::new(op(10)));
        assert!(matches!(ask(&c, Request::SignSet(set_request(&refunded, &v, set, vec![member]))), Response::SetSigs(_)));
    }
    // a restarted signer keeps the record and refuses a different spend of the same outpoint
    let c = core(&d);
    let (code, why) = refused(ask(&c, Request::SignSet(set_request(&b, &v, set, vec![member]))));
    assert_eq!(code, refuse::SET_SIGN_ONCE, "{why}");
    assert!(why.starts_with("set-sign-once"));
    // even asked for no signature (the wallet only reports), the conflict is refused
    assert_eq!(refused(ask(&c, Request::SignSet(set_request(&b, &v, set, vec![])))).0, refuse::SET_SIGN_ONCE);
    let Response::Records(r) = ask(&c, Request::ListSigned) else { panic!() };
    assert_eq!(r.records.len(), 1);
    // an import of a differing record is refused whole
    let mut other = r.records[0].clone();
    other.sighash = "00".repeat(32);
    assert_eq!(refused(ask(&c, Request::ImportSigned(vec![other]))).0, refuse::SET_SIGN_ONCE);
    // a set that does not govern the vault's unlock branch is refused
    let (code, _) = refused(ask(&c, Request::SignSet(set_request(&a, &v, [7u8; 32], vec![member]))));
    assert_eq!(code, refuse::GATE);
}

#[test]
fn a_restored_seed_refuses_until_acknowledged() {
    let d = dir("restored");
    yewd_signer::init(&d, Network::Regtest, Some(PHRASE), 0).unwrap();
    let c = SignerCore::open(Keystore::load(&d, Network::Regtest).unwrap(), &d).unwrap();
    let set = [6u8; 32];
    let owner = yew_core::pq::PqKeyId { scheme: 1, hash: [8; 32] };
    let vp = VaultParams { tag: *b"TEST", cancel_set_id: set, delay: 3, set_id: set, owner_height: 100, owner, app_height: 0 };
    let v = vault::build_vault(&vp).unwrap();
    let mut tx = Transaction::new_v4();
    tx.vin.push(TxIn::new(op(9)));
    tx.vout.push(TxOut { value: 1, script_pubkey: vec![0x51] });
    let member = KeyRef::Bip32 { chain: 0, index: 5 };
    assert_eq!(refused(ask(&c, Request::SignSet(set_request(&tx, &v, set, vec![member])))).0, refuse::SET_SIGN_RESTORED);
    let mut ack = set_request(&tx, &v, set, vec![member]);
    ack.acknowledge_restore = true;
    assert!(matches!(ask(&c, Request::SignSet(ack)), Response::SetSigs(_)));
    let Response::Acknowledged(r) = ask(&c, Request::AcknowledgeRestore) else { panic!() };
    assert!(!r.restored);
}

#[test]
fn refuses_another_protocol_version() {
    let d = dir("version");
    let c = core(&d);
    let mut e = Envelope::new(Request::Hello);
    e.version = 0;
    assert_eq!(refused(c.handle(&e)).0, refuse::BAD_VERSION);
    assert!(matches!(c.handle(&Envelope::new(Request::Hello)), Response::Hello(_)));
}

#[test]
fn the_socket_checks_and_answers() {
    let d = dir("socket");
    let path = d.join("s.sock");
    let c = core(&d);
    let p2 = path.clone();
    std::thread::spawn(move || yewd_signer::server::serve(c, p2, false));
    for _ in 0..100 {
        if path.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    let client = yewd_proto::client::SocketClient::new(path);
    let Response::Hello(h) = client.call(Request::Hello).unwrap() else { panic!() };
    assert_eq!(h.version, yewd_proto::PROTO_VERSION);
    assert_eq!(h.network, "regtest");
}
