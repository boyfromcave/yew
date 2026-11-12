// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The hybrid transaction vectors, signed the way yewd-signer's `SignerCore::sign` signs a
//! request with a Sapling part (its `KeyRef::Bip32` and `KeyRef::Pq` arms, reproduced here
//! statement for statement over `Hybrid::digest`, then `Hybrid::finish`), against the pinned
//! bytes in `vectors/hybrid_vectors.json` (review YEW-REVIEW-6 item 3: the regression guard
//! before that loop moves into the core). What is pinned and what is verified:
//! `hybrid_cases/mod.rs`. Needs the Sapling proving parameters (`YEW_SAPLING_PARAMS`, else
//! yewd's default directory).

mod hybrid_cases;

use hybrid_cases::*;
use yew_core::params::SIGHASH_ALL;

#[test]
fn hybrid_vectors_signed_as_the_signer_signs() {
    run_all(|c, h| {
        let mut tx = c.tx.clone();
        let ecdsa = |digest: [u8; 32], sk: &secp256k1::SecretKey| {
            let sig = secp256k1::ecdsa::sign(secp256k1::Message::from_digest(digest), sk);
            let mut der = sig.serialize_der().to_vec();
            der.push(SIGHASH_ALL as u8);
            der
        };
        let mut sighashes = vec![None; tx.vin.len()];
        for (i, inp) in c.inputs.iter().enumerate() {
            let script = inp.script.clone();
            let amount = inp.value;
            let digest = match &inp.key {
                InputKey::Ecc(sk, pk) => {
                    let digest = h
                        .digest(i, &script, &script, amount, SIGHASH_ALL)
                        .expect("digest");
                    tx.vin[i].script_sig =
                        yew_core::script::p2pkh_script_sig(&ecdsa(digest, sk), pk);
                    digest
                }
                InputKey::Pq(k) => {
                    let digest = h
                        .digest(i, &script, &script, amount, SIGHASH_ALL)
                        .expect("digest");
                    let mut sig = k.sign(&digest);
                    sig.push(SIGHASH_ALL as u8);
                    tx.vin[i].script_sig =
                        yew_core::pq::pqpkh_script_sig(&sig, k.public_key()).expect("scriptSig");
                    digest
                }
            };
            sighashes[i] = Some(digest);
        }
        let raw = h.finish(&tx, finish_rng()).expect("finish");
        Signed { sighashes, raw }
    });
}
