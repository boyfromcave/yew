// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The hybrid transaction vectors signed by the core's `build::hybrid::sign_hybrid` (the signing
//! loop's P2PKH and post-quantum arms moved from yewd-signer, review YEW-REVIEW-6 item 4),
//! against the same pinned bytes as `hybrid_vectors.rs` (the signer's arms as they were): the
//! equivalence of the move. And a key that does not own its prevout is refused before signing.

mod hybrid_cases;

use hybrid_cases::*;
use yew_core::build::hybrid::{sign_hybrid, HybridInput, HybridKey};

fn inputs_of(c: &Case) -> Vec<HybridInput<'_>> {
    c.inputs
        .iter()
        .map(|i| HybridInput {
            script: &i.script,
            amount: i.value,
            key: match &i.key {
                InputKey::Ecc(sk, pk) => HybridKey::P2pkh(sk, pk),
                InputKey::Pq(k) => HybridKey::Pq(k),
            },
        })
        .collect()
}

#[test]
fn hybrid_vectors_signed_by_the_core() {
    run_all(|c, h| {
        let (digests, raw) =
            sign_hybrid(h, c.tx.clone(), &inputs_of(c), VAULT_BRANCH, finish_rng())
                .expect("sign_hybrid");
        Signed {
            sighashes: digests.into_iter().map(Some).collect(),
            raw,
        }
    });
}

#[test]
fn a_key_that_does_not_own_its_prevout_is_refused() {
    let cs = cases();
    let c = cs
        .iter()
        .find(|c| c.name == "a_sapling_spend_p2pkh_input_sapling_output")
        .expect("case a");
    let other = cs
        .iter()
        .find(|c| c.name == "c_slh_dsa_to_sapling")
        .expect("case c");
    let mut ins = inputs_of(c);
    ins[0].key = match &other.inputs[0].key {
        InputKey::Pq(k) => HybridKey::Pq(k),
        InputKey::Ecc(sk, pk) => HybridKey::P2pkh(sk, pk),
    };
    let h = prepare(c).expect("prepare");
    let e = sign_hybrid(h, c.tx.clone(), &ins, VAULT_BRANCH, finish_rng()).expect_err("refused");
    assert_eq!(e.0, yew_core::refuse::KEY_MISMATCH, "{e:?}");
    let h = prepare(c).expect("prepare");
    let e = sign_hybrid(h, c.tx.clone(), &[], VAULT_BRANCH, finish_rng()).expect_err("refused");
    assert_eq!(e.0, yew_core::refuse::MALFORMED, "{e:?}");
}
