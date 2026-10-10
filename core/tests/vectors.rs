// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! Node-generated vectors (plan W0c, `yellowback-devnet vectors`): the core must reproduce the
//! node's bytes exactly (D-W-3). Files live in `core/tests/vectors/`:
//! `transparent.json`, `addresses.json`, `params.json`, `ywallet.json` (`templates.json` is W2/W4).
//! On `upgrade/vault-in-term` they were taken on an in-term devnet (ycash-dd `upgrade/vault-in-term`,
//! `params.json.generated`), and `scripts/vectors-in-term.py` adds `templates.json`'s
//! `earlyRedeem*` and `claim*` records; every transaction in `templates.json` was mined there.

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
    // The in-term templates (`scripts/vectors-in-term.py`) are a MINT and a REDEEM / CLAIM each.
    for (key, kind) in [
        ("mint", "mint"),
        ("transfer", "transfer"),
        ("redeem", "redeem"),
        ("earlyRedeemMint", "mint"),
        ("earlyRedeem", "redeem"),
        ("claimMint", "mint"),
        ("claim", "redeem"),
    ] {
        let t = &v[key];
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
        assert_eq!(payload::encode(&expected).unwrap(), hex, "{key}: encode");
        assert_eq!(payload::decode(&hex).unwrap(), expected, "{key}: decode");
        assert_eq!(
            expected.assigned_cents() as u64,
            d["assignedCents"].as_u64().unwrap_or(0),
            "{key}: assignedCents"
        );
        // The payload is found in the node's raw transaction at its OP_RETURN.
        let (tx, txid) = Transaction::parse(&hex_field(t, "hex")).unwrap();
        assert_eq!(txid_hex(&txid), t["txid"].as_str().unwrap());
        let fp = payload::find_payload(&tx).unwrap_or_else(|| panic!("{key}: find_payload"));
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
                "{key}: assignments equal yed_gettxinfo.assigned"
            );
        } else {
            // MINT-1: vout[1] carries the minted cents.
            assert_eq!(info_assigned, vec![(1, d["cents"].as_u64().unwrap())]);
        }
        // Every token output of the template is TOKEN_VALUE.
        for (vout, _) in &info_assigned {
            assert_eq!(
                tx.vout[*vout as usize].value, TOKEN_VALUE,
                "{key}: vout {vout}"
            );
        }
    }
}

/// The V-template terms of the vectors' devnet (`params.json`: `yed_getinfo.params`).
fn vault_terms() -> yew_core::build::terms::VaultTerms {
    let p = &load("params.json")["yed_getinfo"]["params"];
    let mut set: [u8; 32] = unhex(p["attestorSetId"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    set.reverse(); // display order → the internal bytes the V pushes
    yew_core::build::terms::VaultTerms {
        attestor_set_id: set,
        claim_delay: p["claimDelay"].as_i64().unwrap(),
        grace: p["grace"].as_u64().unwrap() as u32,
    }
}

/// The branch id every vector was signed under (`transparent.json`, the node's next block).
fn signing_branch_id() -> u32 {
    u32::from_str_radix(load("transparent.json")["branchId"].as_str().unwrap(), 16).unwrap()
}

/// A node-built transaction of `templates.json` with its txid checked.
fn template_tx(t: &Value) -> (Transaction, [u8; 32]) {
    let (tx, txid) = Transaction::parse(&hex_field(t, "hex")).unwrap();
    assert_eq!(txid_hex(&txid), t["txid"].as_str().unwrap());
    (tx, txid)
}

/// `vin[carrier_vin]` spends `carrier`'s `vout[0]`: scriptSig `<bundle> <sig> <carrierScript>`,
/// the 71-byte script committing SHA256(bundle), the bundle's seqs as the node reports them, the
/// pair expiring together, and the signature verifying under the ZIP-243 digest over the redeem
/// script with amount `CARRIER_VALUE`.
fn check_carrier(
    tx: &Transaction,
    carrier_vin: usize,
    carrier: &Value,
    txinfo: &Value,
    ref_height: u32,
) {
    use yew_core::bundle;
    use yew_core::params::{CARRIER_VALUE, REF_WINDOW};
    assert_eq!(carrier_vin, tx.vin.len() - 1, "the carrier is vin[last]");
    let spend = script::parse_carrier_script_sig(&tx.vin[carrier_vin].script_sig)
        .expect("carrier-shaped scriptSig");
    assert_eq!(
        spend.bundle_hash,
        bundle::bundle_hash(&spend.bundle),
        "SHA256(bundle)"
    );
    let seqs: Vec<i64> = bundle::decode(&spend.bundle)
        .unwrap()
        .iter()
        .map(|a| a.seq as i64)
        .collect();
    let node_seqs: Vec<i64> = txinfo["bundleSeqs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_i64().unwrap())
        .collect();
    assert_eq!(
        seqs, node_seqs,
        "the bundle's seqs equal yed_gettxinfo.bundleSeqs"
    );
    assert_eq!(
        script::carrier_script(&spend.pk, &spend.bundle_hash).unwrap(),
        spend.carrier_script
    );
    assert_eq!(
        script::carrier_script_sig(&spend.bundle, &spend.sig, &spend.carrier_script).unwrap(),
        tx.vin[carrier_vin].script_sig,
        "carrier scriptSig push encoding (plan §8.7)"
    );
    let (ctx, ctxid) = template_tx(carrier);
    assert_eq!(tx.vin[carrier_vin].prevout.txid, ctxid);
    assert_eq!(tx.vin[carrier_vin].prevout.n, 0);
    assert_eq!(ctx.vout[0].value, CARRIER_VALUE);
    assert_eq!(
        ctx.vout[0].script_pubkey,
        script::p2sh_of(&spend.carrier_script),
        "carrier P2SH"
    );
    assert_eq!(
        ctx.expiry_height,
        ref_height + REF_WINDOW,
        "the pair expires together"
    );
    let digest = tx
        .sighash(
            carrier_vin,
            &spend.carrier_script,
            CARRIER_VALUE,
            1,
            signing_branch_id(),
        )
        .unwrap();
    let sig = secp256k1::ecdsa::Signature::from_der(&spend.sig[..spend.sig.len() - 1]).unwrap();
    let pk = secp256k1::PublicKey::from_slice(&spend.pk).unwrap();
    assert!(secp256k1::ecdsa::verify(&sig, secp256k1::Message::from_digest(digest), &pk).is_ok());
}

/// One node-built MINT of `templates.json` (with its carrier).
struct NodeMint {
    tx: Transaction,
    txid: [u8; 32],
    vault: yew_core::vault::VaultParams,
    vault_script: Vec<u8>,
    owner: [u8; 33],
    lock_height: u32,
    ref_height: u32,
    term_class: u8,
}

/// The MINT at `key` (carrier at `carrier_key`): `vout[0]` is the in-term V (IT-1, D-IT-15:
/// `ownerHeight = appHeight = refHeight + 1`), rebuilt byte for byte from the payload's owner and
/// `refHeight`, and not the pre-plan V (`lockHeight`, `lockHeight + GRACE`) that MINT-3 refuses
/// for a new mint; then the token, payload and fee outputs, `nExpiryHeight` and the carrier.
fn check_mint(v: &Value, key: &str, carrier_key: &str) -> NodeMint {
    use yew_core::params::REF_WINDOW;
    use yew_core::payload::{self, Payload};
    let network = network_of(v);
    let vt = vault_terms();
    let mint = &v[key];
    let (tx, txid) = template_tx(mint);
    let d = &mint["payloadDecoded"];
    let mut owner = [0u8; 33];
    owner.copy_from_slice(&hex_field(d, "ownerPubKey"));
    let lock_height = d["lockHeight"].as_u64().unwrap() as u32;
    let ref_height = d["refHeight"].as_u64().unwrap() as u32;
    assert_eq!(
        mint["result"]["refHeight"].as_u64(),
        Some(ref_height as u64),
        "{key}"
    );
    let claim_height = mint["result"]["claimHeight"].as_u64().unwrap() as u32;
    assert_eq!(
        claim_height,
        lock_height + vt.grace,
        "{key}: claimHeight = lockHeight + GRACE"
    );
    // vout[0]: the bare V template of the YED vault, in its in-term form.
    let vault_script = vt.mint_vault_script(&owner, ref_height).unwrap();
    assert_eq!(
        tx.vout[0].script_pubkey, vault_script,
        "{key}: the in-term V (IT-1)"
    );
    let vault = yew_core::vault::parse_vault(&vault_script).unwrap();
    assert_eq!(
        (vault.owner_height, vault.app_height),
        (ref_height as i64 + 1, ref_height as i64 + 1),
        "{key}: ownerHeight = appHeight = refHeight + 1 (D-IT-15)"
    );
    assert_eq!(vault, vt.mint_vault_params(&owner, ref_height));
    assert_ne!(
        Some(tx.vout[0].script_pubkey.clone()),
        yew_core::vault::build_vault(&yew_core::vault::yed_vault_params(
            &vt.attestor_set_id,
            vt.claim_delay,
            vt.grace,
            &owner,
            lock_height
        )),
        "{key}: not the pre-plan V"
    );
    assert!(yew_core::vault::is_yed_vault(
        &vault,
        &vt.attestor_set_id,
        vt.claim_delay,
        vt.grace
    ));
    assert_eq!(
        tx.vout[0].value,
        mint["result"]["collateralZat"].as_i64().unwrap()
    );
    // vout[1]: TOKEN_VALUE to P2PKH(owner); vout[2]: the payload; vout[3]/[4]: the fees.
    assert_eq!(tx.vout[1].value, TOKEN_VALUE);
    assert_eq!(
        tx.vout[1].script_pubkey,
        script::p2pkh_script(&keys::hash160(&owner))
    );
    let term_class = match d["termClass"].as_str().unwrap() {
        "A" => 0,
        "B" => 1,
        _ => 2,
    };
    let fee_vout = d["feeVout"].as_u64().unwrap() as u8;
    let attest_fee_vout = d["attestFeeVout"].as_u64().unwrap() as u8;
    let expected = Payload::Mint {
        term_class,
        cents: d["cents"].as_u64().unwrap() as u32,
        lock_height,
        ref_height,
        owner_key: owner,
        fee_vout,
        attest_fee_vout,
    };
    assert_eq!(
        tx.vout[2].script_pubkey,
        payload::payload_script(&payload::encode(&expected).unwrap()),
        "{key}: payload output"
    );
    assert_eq!((fee_vout, attest_fee_vout), (3, 4));
    let payee = keys::parse_address(network, mint["txinfo"]["payee"].as_str().unwrap()).unwrap();
    assert_eq!(
        tx.vout[3].script_pubkey,
        script::p2pkh_script(&payee.hash())
    );
    assert_eq!(tx.vout[3].value, mint["txinfo"]["feeZat"].as_i64().unwrap());
    let attest_payee =
        keys::parse_address(network, mint["txinfo"]["attestPayee"].as_str().unwrap()).unwrap();
    assert_eq!(
        tx.vout[4].script_pubkey,
        script::p2pkh_script(&attest_payee.hash())
    );
    assert_eq!(
        tx.vout[4].value,
        mint["txinfo"]["attestFeeZat"].as_i64().unwrap()
    );
    assert_eq!(
        tx.vout.len(),
        6,
        "{key}: vault, token, payload, fee, attestor fee, change"
    );
    assert_eq!(
        tx.expiry_height,
        ref_height + REF_WINDOW,
        "nExpiryHeight = R + REF_WINDOW"
    );
    assert_eq!(tx.lock_time, 0);
    let carrier_vin = mint["txinfo"]["carrierVin"].as_u64().unwrap() as usize;
    check_carrier(
        &tx,
        carrier_vin,
        &v[carrier_key],
        &mint["txinfo"],
        ref_height,
    );
    NodeMint {
        tx,
        txid,
        vault,
        vault_script,
        owner,
        lock_height,
        ref_height,
        term_class,
    }
}

/// The owner-path REDEEM at `key` of `m` (IT-9 when `early`): vin[0] = the vault, scriptSig
/// `<ownerSig> OP_2`, nSequence 0xFFFFFFFE, nLockTime = the V's ownerHeight (refHeight + 1 of
/// the mint, not lockHeight), nExpiryHeight = R + REF_WINDOW, the owner signature over the V
/// itself; the plan rebuilt from the node's numbers gives the same outputs and payload, and the
/// pool-payee output carries FEE-1 plus the early-redeem fee exactly when it was mined before
/// `lockHeight`.
fn check_redeem(v: &Value, key: &str, m: &NodeMint, early: bool) {
    use yew_core::params::{REF_WINDOW, SEQUENCE_LOCKTIME};
    let network = network_of(v);
    let redeem = &v[key];
    let (rtx, _) = template_tx(redeem);
    assert_eq!(rtx.vin[0].prevout.txid, m.txid);
    assert_eq!(rtx.vin[0].prevout.n, 0);
    assert_eq!(rtx.vin[0].sequence, SEQUENCE_LOCKTIME);
    assert_eq!(
        rtx.lock_time,
        m.ref_height + 1,
        "{key}: nLockTime = ownerHeight = refHeight + 1"
    );
    let height = redeem["txinfo"]["height"].as_u64().unwrap() as u32;
    assert_eq!(
        height < m.lock_height,
        early,
        "{key}: mined at {height}, lockHeight {}",
        m.lock_height
    );
    assert_eq!(redeem["txinfo"]["path"].as_str(), Some("owner"));
    let r = redeem["payloadDecoded"]["refHeight"].as_u64().unwrap() as u32;
    assert_eq!(rtx.expiry_height, r + REF_WINDOW);
    let (selector, args) =
        yew_core::vault::parse_selector(yew_core::vault::Kind::Vault, &rtx.vin[0].script_sig)
            .unwrap();
    assert_eq!(
        (selector, args.len()),
        (2, 1),
        "{key}: the V's OWNER branch"
    );
    assert_eq!(
        rtx.vin[0].script_sig,
        yew_core::vault::vault_owner_script_sig(&args[0])
    );
    let digest = rtx
        .sighash(
            0,
            &m.vault_script,
            m.tx.vout[0].value,
            1,
            signing_branch_id(),
        )
        .unwrap();
    let sig = secp256k1::ecdsa::Signature::from_der(&args[0][..args[0].len() - 1]).unwrap();
    let pk = secp256k1::PublicKey::from_slice(&m.owner).unwrap();
    assert!(secp256k1::ecdsa::verify(&sig, secp256k1::Message::from_digest(digest), &pk).is_ok());
    // IT-9: the early-redeem fee is the class's bps of the collateral, on top of FEE-1, in the
    // pool payee's output; yed_estimateredeem quoted the same before the redeem was built.
    let collateral = m.tx.vout[0].value;
    let early_fee = redeem["result"]["earlyRedeemFeeZat"].as_i64().unwrap();
    let bps = network.term_classes()[m.term_class as usize].early_redeem_fee_bps;
    if early {
        assert!(r + 1 < m.lock_height);
        assert_eq!(
            early_fee,
            yew_core::params::early_redeem_fee_zat(collateral, bps)
        );
        assert!(early_fee > 0);
        let e = &redeem["estimate"];
        assert_eq!(e["early"].as_bool(), Some(true));
        assert_eq!(e["earlyRedeemFeeBps"].as_i64(), Some(bps));
        assert_eq!(e["earlyRedeemFeeZat"].as_i64(), Some(early_fee));
        assert_eq!(e["feeZat"], redeem["result"]["feeZat"]);
    } else {
        assert_eq!(early_fee, 0, "{key}: at or after lockHeight FEE-1 only");
    }
    let fee_zat = redeem["txinfo"]["feeZat"].as_i64().unwrap();
    assert_eq!(fee_zat, redeem["result"]["feeZat"].as_i64().unwrap());
    let fee_vout = redeem["payloadDecoded"]["feeVout"].as_u64().unwrap() as usize;
    assert_eq!(
        rtx.vout[fee_vout].value, fee_zat,
        "{key}: the pool payee's output"
    );
    let rpayee = keys::parse_address(network, redeem["txinfo"]["payee"].as_str().unwrap()).unwrap();
    let shape = yew_core::build::redeem::VaultSpendShape {
        vault_out: rtx.vin[0].prevout,
        vault_value: collateral,
        lock_height: m.lock_height,
        claim_height: m.lock_height + vault_terms().grace,
        owner_height: m.vault.owner_height as u32,
        app_height: m.vault.app_height as u32,
        owner_path: true,
        with_payload: true,
        ref_height: r,
        yed_inputs: rtx.vin[1..]
            .iter()
            .enumerate()
            .map(|(i, x)| yew_core::coins::Utxo {
                outpoint: x.prevout,
                address: String::new(),
                script: Vec::new(),
                value: TOKEN_VALUE,
                height: 0,
                class: yew_core::coins::UtxoClass::Token,
                // The burn's cents sit on the first token; the planner only sums them.
                cents: if i == 0 {
                    redeem["txinfo"]["burned"].as_u64().unwrap()
                } else {
                    0
                },
            })
            .collect(),
        change_cents: 0,
        change_script: Vec::new(),
        payee_script: Some(script::p2pkh_script(&rpayee.hash())),
        fee_zat,
        attest_script: None,
        attest_fee_zat: 0,
        residual_zat: 0,
        owner_script: script::p2pkh_script(&keys::hash160(&m.owner)),
        carrier_value: 0,
        collateral_script: rtx.vout[0].script_pubkey.clone(),
    };
    let plan = yew_core::build::redeem::plan_vault_spend(&shape).unwrap();
    assert_eq!(
        plan.vout, rtx.vout,
        "{key}: REDEEM vout order, values and payload"
    );
    assert_eq!(plan.lock_time, rtx.lock_time);
    assert_eq!(
        plan.vin
            .iter()
            .map(|i| (i.prevout, i.sequence))
            .collect::<Vec<_>>(),
        rtx.vin
            .iter()
            .map(|i| (i.prevout, i.sequence))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        plan.collateral_out,
        redeem["result"]["collateralOut"].as_i64().unwrap()
    );
    assert_eq!(
        plan.burn_cents,
        redeem["result"]["burnedCents"].as_i64().unwrap()
    );
}

/// Plan W4 acceptance on the in-term line (the workspace's
/// docs/plans/yellowback-in-term-claims-plan.md IT-1, IT-2, IT-9): from the node-built armed
/// MINTs, their carriers, the REDEEM at `lockHeight`, the early REDEEM and the in-term CLAIM in
/// `templates.json` (`yellowback-devnet vectors` + `scripts/vectors-in-term.py`), rebuild the V
/// template at `vout[0]`, the MINT `vout` order and values, the payload bytes, the carrier
/// scriptSig push encoding, the owner and claim scriptSigs, `nLockTime` / `nSequence` /
/// `nExpiryHeight` — byte for byte except keys and amounts, which are the node's own here.
#[test]
fn w4_templates_reproduce_the_node_scripts_and_payloads() {
    let v = load("templates.json");
    assert_eq!(v["armed"].as_bool(), Some(true));
    let mint = check_mint(&v, "mint", "carrier");
    check_redeem(&v, "redeem", &mint, false);
    let early = check_mint(&v, "earlyRedeemMint", "earlyRedeemMintCarrier");
    check_redeem(&v, "earlyRedeem", &early, true);
    let target = check_mint(&v, "claimMint", "claimMintCarrier");
    assert_eq!(target.term_class, 2, "the claim target is class C");
    check_in_term_claim(&v, &target);
}

/// The CLAIM of `m` in term (IT-2 (a)): listed claimable by `yed_listclaimable` while in term,
/// vin[0] = the vault with scriptSig `OP_4` (the V's APP branch), nLockTime = appHeight =
/// refHeight + 1 (not lockHeight + GRACE), mined before `lockHeight`; `plan_claim` from the
/// node's numbers gives the same inputs and outputs: the claimant intent of the collateral, the
/// pool and attestor fees, the payload and the fee inputs' change.
fn check_in_term_claim(v: &Value, m: &NodeMint) {
    use yew_core::params::{REF_WINDOW, SEQUENCE_LOCKTIME};
    let network = network_of(v);
    let claim = &v["claim"];
    let (ctx, _) = template_tx(claim);
    let row = &claim["claimableRow"];
    assert_eq!(
        row["vault"].as_str().unwrap(),
        format!("{}:0", txid_hex(&m.txid))
    );
    assert_eq!(row["claimable"].as_bool(), Some(true));
    assert_eq!(row["claimPath"].as_str(), Some("a"));
    assert_eq!(row["lockHeight"].as_u64(), Some(m.lock_height as u64));
    let height = claim["txinfo"]["height"].as_u64().unwrap() as u32;
    assert!(
        height < m.lock_height,
        "in term: mined at {height} < lockHeight {}",
        m.lock_height
    );
    assert_eq!(claim["txinfo"]["path"].as_str(), Some("claim"));
    assert_eq!(claim["result"]["claimPath"].as_str(), Some("a"));
    assert_eq!(claim["result"]["earlyRedeemFeeZat"].as_i64(), Some(0));
    assert_eq!(ctx.vin[0].prevout.txid, m.txid);
    assert_eq!(ctx.vin[0].prevout.n, 0);
    assert_eq!(ctx.vin[0].sequence, SEQUENCE_LOCKTIME);
    assert_eq!(
        ctx.vin[0].script_sig,
        yew_core::vault::vault_app_script_sig()
    );
    assert_eq!(
        ctx.lock_time,
        m.ref_height + 1,
        "IT-1: nLockTime = appHeight = refHeight + 1"
    );
    let r = claim["payloadDecoded"]["refHeight"].as_u64().unwrap() as u32;
    assert_eq!(ctx.expiry_height, r + REF_WINDOW);
    let carrier_vin = claim["txinfo"]["carrierVin"].as_u64().unwrap() as usize;
    check_carrier(&ctx, carrier_vin, &v["claimCarrier"], &claim["txinfo"], r);
    // The inputs' values, from the transactions they spend (all in templates.json).
    let known: Vec<Transaction> = [
        "claimMint",
        "claimMintCarrier",
        "claimCarrier",
        "earlyRedeem",
        "redeem",
        "transfer",
    ]
    .iter()
    .filter(|k| !v[**k].is_null())
    .map(|k| template_tx(&v[*k]).0)
    .collect();
    let value_of = |o: &yew_core::tx::OutPoint| -> (i64, Vec<u8>) {
        let t = known
            .iter()
            .find(|t| t.txid().unwrap() == o.txid)
            .unwrap_or_else(|| {
                panic!(
                    "claim input {}:{} is not in templates.json",
                    txid_hex(&o.txid),
                    o.n
                )
            });
        let out = &t.vout[o.n as usize];
        (out.value, out.script_pubkey.clone())
    };
    let n_yed = claim["txinfo"]["spentTokens"].as_array().unwrap().len();
    let yed_inputs: Vec<yew_core::coins::Utxo> = ctx.vin[1..1 + n_yed]
        .iter()
        .enumerate()
        .map(|(i, x)| {
            let (value, script) = value_of(&x.prevout);
            assert_eq!(value, TOKEN_VALUE);
            yew_core::coins::Utxo {
                outpoint: x.prevout,
                address: String::new(),
                script,
                value,
                height: 0,
                class: yew_core::coins::UtxoClass::Token,
                cents: if i == 0 {
                    claim["txinfo"]["burned"].as_u64().unwrap()
                } else {
                    0
                },
            }
        })
        .collect();
    let funding: Vec<yew_core::coins::Utxo> = ctx.vin[1 + n_yed..carrier_vin]
        .iter()
        .map(|x| {
            let (value, script) = value_of(&x.prevout);
            yew_core::coins::Utxo {
                outpoint: x.prevout,
                address: String::new(),
                script,
                value,
                height: 0,
                class: yew_core::coins::UtxoClass::Yec,
                cents: 0,
            }
        })
        .collect();
    let addr = |k: &str| {
        script::p2pkh_script(
            &keys::parse_address(network, claim["txinfo"][k].as_str().unwrap())
                .unwrap()
                .hash(),
        )
    };
    let to = keys::parse_address(network, claim["result"]["to"].as_str().unwrap()).unwrap();
    let shape = yew_core::build::claim::ClaimShape {
        vault_out: ctx.vin[0].prevout,
        vault: m.vault.clone(),
        vault_script: m.vault_script.clone(),
        vault_value: m.tx.vout[0].value,
        ref_height: r,
        yed_inputs,
        change_cents: 0,
        change_script: Vec::new(),
        payee_script: Some(addr("payee")),
        fee_zat: claim["txinfo"]["feeZat"].as_i64().unwrap(),
        attest_script: Some(addr("attestPayee")),
        attest_fee_zat: claim["txinfo"]["attestFeeZat"].as_i64().unwrap(),
        residual_zat: claim["txinfo"]["residualZat"].as_i64().unwrap(),
        owner_script: script::p2pkh_script(&keys::hash160(&m.owner)),
        claimant_script: script::p2pkh_script(&to.hash()),
        funding,
        funding_change_script: ctx.vout.last().unwrap().script_pubkey.clone(),
        carrier: ctx.vin[carrier_vin].prevout,
    };
    let plan = yew_core::build::claim::plan_claim(&shape).unwrap();
    assert_eq!(plan.lock_time, ctx.lock_time);
    assert_eq!(
        plan.vout, ctx.vout,
        "CLAIM vout order, values, intent and payload"
    );
    assert_eq!(
        plan.vin
            .iter()
            .map(|i| (i.prevout, i.sequence))
            .collect::<Vec<_>>(),
        ctx.vin
            .iter()
            .map(|i| (i.prevout, i.sequence))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        plan.claimant_value,
        claim["result"]["collateralOut"].as_i64().unwrap()
    );
    assert_eq!(
        plan.burn_cents,
        claim["result"]["burnedCents"].as_i64().unwrap()
    );
    assert_eq!(
        yew_core::vault::parse_intent(&ctx.vout[0].script_pubkey).unwrap(),
        yew_core::vault::intent_for(&m.vault, &m.vault_script, &script::p2pkh_script(&to.hash())),
        "the claimant intent pays `to` after CLAIM_DELAY"
    );
    let _ = FEE_ZAT;
}

/// Ycash Sapling keys (yew-shielded plan S0-1): ZIP-32 account 0 at `m/32'/347'/0'` from the
/// BIP39 seed, per network. `sapling_keys_ycash.json` was produced by this code
/// (`YEW_REGEN_SAPLING_VECTORS=1`) and then confirmed against a v4.5.0-line regtest node
/// (`ycash-dd`): for every regtest case `z_importkey` of `spendingKey` reported `defaultAddress`,
/// `z_exportviewingkey` of it returned `fullViewingKey`, and `z_exportkey` returned `spendingKey`
/// (the `nodeCheck` block records the node and the date). Mainnet and testnet differ from regtest
/// only in the HRPs (same key bytes; asserted below).
#[test]
fn sapling_key_vectors_ycash() {
    use yew_core::shielded_keys::SaplingAccount;
    let path = vectors_dir().join("sapling_keys_ycash.json");
    let cases: [(&str, &str); 3] = [
        ("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", ""),
        ("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art", ""),
        ("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art", "yew"),
    ];
    let mut computed = Vec::new();
    for (mnemonic, passphrase) in cases {
        let mut nets = serde_json::Map::new();
        let mut key_bytes = None;
        for net in [Network::Mainnet, Network::Testnet, Network::Regtest] {
            let a = SaplingAccount::from_mnemonic(mnemonic, passphrase, net).unwrap();
            let kb = keys::hex(&a.spending_key_bytes());
            assert_eq!(
                *key_bytes.get_or_insert(kb.clone()),
                kb,
                "same key on every network"
            );
            let (j0, default) = a.default_address();
            let (j1, next) = a.address_at(j0 + 1).unwrap();
            nets.insert(
                net.chain_name().into(),
                serde_json::json!({
                    "spendingKey": &*a.spending_key(),
                    "fullViewingKey": a.full_viewing_key(),
                    "defaultIndex": j0,
                    "defaultAddress": default,
                    "nextIndex": j1,
                    "nextAddress": next,
                }),
            );
        }
        computed.push(serde_json::json!({
            "mnemonic": mnemonic,
            "passphrase": passphrase,
            "path": "m/32'/347'/0'",
            "spendingKeyBytes": key_bytes.unwrap(),
            "networks": nets,
        }));
    }
    if std::env::var_os("YEW_REGEN_SAPLING_VECTORS").is_some() {
        let doc = serde_json::json!({ "cases": computed, "nodeCheck": null });
        std::fs::write(&path, serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
        return;
    }
    let v = load("sapling_keys_ycash.json");
    assert!(
        v["nodeCheck"]["node"].is_string(),
        "sapling_keys_ycash.json has no node confirmation"
    );
    assert_eq!(v["cases"].as_array().unwrap(), &computed);
}
