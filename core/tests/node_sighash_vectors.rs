// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! An external anchor for the hybrid builder's ZIP-243 digests (review YEW-REVIEW-7, the main
//! caveat: `hybrid_vectors` recomputes each sighash with the function the signer uses, so it
//! proves self-consistency only).
//!
//! `vectors/mixed_shapes_chain.json` is kogany's `testdata/mixed-shapes/chain.json` at
//! e27096034 (kogany #17), copied byte for byte (sha256 pinned below): a regtest chain recorded on
//! the C++ lines (ycash-dd 4.5.0 builds and mines, ycash6 6.22.0-rc1 accepts every transaction
//! and block), whose transactions mix Sapling parts with post-quantum inputs and outputs. Each
//! `TX_PQPKH` input of those transactions was signed by ycashd (`signrawtransaction`) over the
//! C++ node's own ZIP-243 digest, which covers the Sapling parts. The file records each such
//! input's index, spent script and amount, but no digest: the anchor is the C++-made signature.
//! For every one, this test computes the digest the way `build::hybrid::Hybrid::digest` does
//! (`SignableInput::from_parts` over the transparent bundle, `SIGHASH_ALL`, the script code and
//! the amount, through `hybrid::script_of`, then `sighash_v4::v4_signature_hash`, which is generic
//! over the authorization, so a parsed finished transaction hashes exactly as the builder's
//! proven-unsigned one) under branch 0x6d5b7a31, and checks the C++ signature against it with
//! `pq::verify`; a digest one zat off must not verify. `Hybrid::digest` itself cannot take a
//! finished transaction (it holds the builder's proven, unsigned Sapling bundle), so the test
//! calls the function it delegates to with the arguments it builds.
//!
//! Covered: one `TX_PQPKH` input of each scheme with a Sapling part (`pq-slh-to-sapling`,
//! `pq-falcon-to-sapling`) and one with a Sapling spend beside it (`sapling-and-pq-to-vault`).
//! Also the C++ `z_sendmany` Sapling -> post-quantum transactions (`sapling-to-pq-slh`,
//! `sapling-to-pq-falcon`): the gate's `SaplingToPq` path admits them for their recipient only
//! (their fee is an explicit one the recorder chose, so only `shape_fee`'s floor is compared).

use sha2::{Digest, Sha256};
use yew_core::build::hybrid::script_of;
use yew_core::gate::{self, Path};
use yew_core::params::VAULT_BRANCH_ID;
use yew_core::tx::Transaction;
use zcash_primitives::transaction::sighash::SignableInput;
use zcash_primitives::transaction::sighash_v4::v4_signature_hash;

const FILE: &str = include_str!("vectors/mixed_shapes_chain.json");
const SHA256: &str = "e524a908d7dd8ef1ae6a8406bf07fbedd0de75bc445598282230dfb4fdfc394b";

fn chain() -> serde_json::Value {
    assert_eq!(
        hex::encode(Sha256::digest(FILE.as_bytes())),
        SHA256,
        "vectors/mixed_shapes_chain.json is kogany e27096034's, byte for byte"
    );
    serde_json::from_str(FILE).unwrap()
}

fn compact(r: &mut std::io::Cursor<&[u8]>) -> u64 {
    use std::io::Read;
    let mut b = [0u8; 1];
    r.read_exact(&mut b).unwrap();
    let n = |r: &mut std::io::Cursor<&[u8]>, k: usize| {
        let mut v = [0u8; 8];
        r.read_exact(&mut v[..k]).unwrap();
        u64::from_le_bytes(v)
    };
    match b[0] {
        0xfd => n(r, 2),
        0xfe => n(r, 4),
        0xff => n(r, 8),
        x => x as u64,
    }
}

/// The raw transaction `txid` (display order) of the recorded chain (its block's height is
/// `height`; the blocks are searched, so the list's first height does not matter).
fn raw_tx(chain: &serde_json::Value, height: u64, txid: &str) -> Vec<u8> {
    let branch = zcash_protocol::consensus::BranchId::try_from(VAULT_BRANCH_ID).unwrap();
    for b in chain["blocks"].as_array().unwrap() {
        let block = hex::decode(b.as_str().unwrap()).unwrap();
        let mut r = std::io::Cursor::new(&block[..]);
        zcash_primitives::block::BlockHeader::read(&mut r).unwrap();
        for _ in 0..compact(&mut r) {
            let start = r.position() as usize;
            let t = zcash_primitives::transaction::Transaction::read(&mut r, branch).unwrap();
            if t.txid().to_string() == txid {
                return block[start..r.position() as usize].to_vec();
            }
        }
    }
    panic!("{txid} (height {height}) is not in the recorded chain");
}

/// The digest of input `n` as `Hybrid::digest` computes it (`SIGHASH_ALL`).
fn digest(raw: &[u8], n: usize, script: &[u8], amount: u64) -> [u8; 32] {
    let branch = zcash_protocol::consensus::BranchId::try_from(VAULT_BRANCH_ID).unwrap();
    let ztx = zcash_primitives::transaction::Transaction::read(raw, branch).unwrap();
    let bundle = ztx.transparent_bundle().unwrap();
    let code = script_of(script).unwrap();
    let input = zcash_transparent::sighash::SignableInput::from_parts(
        bundle,
        zcash_transparent::sighash::SighashType::ALL,
        n,
        &code,
        &code,
        zcash_protocol::value::Zatoshis::from_u64(amount).unwrap(),
    )
    .unwrap();
    v4_signature_hash(&ztx, &SignableInput::Transparent(input))
        .as_ref()
        .try_into()
        .unwrap()
}

#[test]
fn cxx_signed_pq_inputs_verify_over_the_hybrid_digest() {
    let c = chain();
    assert_eq!(c["branchId"].as_u64(), Some(VAULT_BRANCH_ID as u64));
    let mut schemes = std::collections::BTreeSet::new();
    let mut with_spend = false;
    for name in [
        "pq-slh-to-sapling",
        "pq-falcon-to-sapling",
        "sapling-and-pq-to-vault",
    ] {
        let s = &c["shapes"][name];
        let raw = raw_tx(
            &c,
            s["height"].as_u64().unwrap(),
            s["txid"].as_str().unwrap(),
        );
        let (tx, _) = Transaction::parse(&raw).unwrap();
        assert!(tx.shielded.outputs > 0, "{name} has a Sapling part");
        with_spend |= tx.shielded.spends > 0;
        let inputs = s["pqInputs"].as_array().unwrap();
        assert!(!inputs.is_empty(), "{name}");
        for i in inputs {
            let n = i["nIn"].as_u64().unwrap() as usize;
            let script = hex::decode(i["scriptCode"].as_str().unwrap()).unwrap();
            let amount = i["amount"].as_u64().unwrap();
            let scheme = i["scheme"].as_u64().unwrap() as u8;
            let id = yew_core::pq::pqpkh_of(&script).expect("a TX_PQPKH prevout");
            assert_eq!(id.scheme, scheme, "{name}");
            let (sig, pk) = yew_core::pq::parse_pqpkh_script_sig(&tx.vin[n].script_sig).unwrap();
            assert_eq!(*sig.last().unwrap(), 1, "{name}: SIGHASH_ALL");
            assert_eq!(
                yew_core::pq::PqKeyId::of(scheme, &pk),
                id,
                "{name}: the key"
            );
            let d = digest(&raw, n, &script, amount);
            assert!(
                yew_core::pq::verify(scheme, &pk, &sig[..sig.len() - 1], &d),
                "{name} input {n}: the C++ signature does not verify over the hybrid digest"
            );
            // negative control: the digest commits to the amount
            let off = digest(&raw, n, &script, amount - 1);
            assert!(!yew_core::pq::verify(
                scheme,
                &pk,
                &sig[..sig.len() - 1],
                &off
            ));
            schemes.insert(scheme);
        }
    }
    assert_eq!(
        schemes.into_iter().collect::<Vec<_>>(),
        vec![
            yew_core::pq::SCHEME_SLH_DSA_SHA2_128S,
            yew_core::pq::SCHEME_FN_DSA_512
        ]
    );
    assert!(with_spend, "one input beside a Sapling spend");
}

/// The C++ wallet's Sapling -> post-quantum sends (ycash-dd `z_sendmany`): the shape the app's
/// `build::sapling_pq` builds. The gate admits them on `SaplingToPq` for their recipient only.
#[test]
fn cxx_sapling_to_pq_sends_pass_the_gate() {
    let c = chain();
    for name in ["sapling-to-pq-slh", "sapling-to-pq-falcon"] {
        let s = &c["shapes"][name];
        let raw = raw_tx(
            &c,
            s["height"].as_u64().unwrap(),
            s["txid"].as_str().unwrap(),
        );
        let (tx, _) = Transaction::parse(&raw).unwrap();
        assert_eq!(tx.vout.len(), 1, "{name}");
        let id = yew_core::pq::pqpkh_of(&tx.vout[0].script_pubkey).expect("a TX_PQPKH output");
        assert!(
            gate::check(Path::SaplingToPq(id), &raw, |_| None).is_ok(),
            "{name}"
        );
        let other = yew_core::pq::PqKeyId {
            scheme: id.scheme,
            hash: [0x77; 32],
        };
        assert!(gate::check(Path::SaplingToPq(other), &raw, |_| None).is_err());
        // the recorder passes an explicit fee (record.py `FEE`), so only the floor is comparable:
        // it covers the conventional fee `shape_fee` charges for the same shape
        let fee = tx.shielded.value_balance - tx.vout[0].value;
        let conventional =
            yew_core::build::sapling_pq::shape_fee(&tx.vout[0].script_pubkey, tx.shielded.spends);
        assert!(fee >= conventional, "{name}: {fee} < {conventional}");
    }
}
