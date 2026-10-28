//! The post-quantum signatures in the browser: the node's golden vectors
//! (`core/tests/vectors/pq_vectors.json`, a byte copy of ycash-dd's) replayed on wasm32 in a
//! dedicated worker, as `core/src/pq.rs` `pq_reproduces_the_node_vectors` does natively. Falcon
//! runs the vendored C (`core/pq-c/falcon`) through the wasm32 C library of
//! `core/src/pq_wasm_libc.rs`; SLH-DSA is RustCrypto's. Seed → public key and key hash, message →
//! signature byte for byte (Falcon with the recorded 88-byte entropy, then a fresh randomized
//! signature), both verify, and a flipped message, a flipped signature byte or a short signature
//! do not. Needs no server (web/scripts/test-core-wasm.sh: `FUND=0 TESTS=pq`).
use serde_json::Value;
use wasm_bindgen_test::*;
use yew_core::keys::{hex, unhex};
use yew_core::pq::{
    key_hash, pub_key_size, sig_size, verify, PqKey, FALCON_SIGN_ENTROPY_SIZE,
    SCHEME_SLH_DSA_SHA2_128S,
};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

const VECTORS: &str = include_str!("../../../core/tests/vectors/pq_vectors.json");

fn b(v: &Value) -> Vec<u8> {
    unhex(v.as_str().unwrap()).unwrap()
}

#[wasm_bindgen_test]
fn pq_reproduces_the_node_vectors_in_the_browser() {
    let v: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(v["format"], "ycash-pq-vectors-1");
    let (mut slh, mut falcon) = (0, 0);
    for k in v["keys"].as_array().unwrap() {
        let scheme = k["scheme"].as_u64().unwrap() as u8;
        let pk = b(&k["pk"]);
        let keyhash: [u8; 32] = b(&k["keyhash"]).try_into().unwrap();
        assert_eq!(key_hash(scheme, &pk), keyhash, "{}", k["label"]);
        assert_eq!(pk.len(), pub_key_size(scheme));
        assert_eq!(b(&k["sig"]).len(), sig_size(scheme));
        let key = PqKey::from_seed(scheme, &b(&k["seed"])).unwrap();
        assert_eq!(hex(key.public_key()), hex(&pk), "{}", k["label"]);
        let msg: [u8; 32] = b(&k["msg"]).try_into().unwrap();
        let sig = if scheme == SCHEME_SLH_DSA_SHA2_128S {
            slh += 1;
            key.sign(&msg)
        } else {
            falcon += 1;
            let e: [u8; FALCON_SIGN_ENTROPY_SIZE] = b(&k["entropy"]).try_into().unwrap();
            let s = key.sign_with_entropy(&msg, &e).unwrap();
            let r = key.sign(&msg);
            assert_ne!(r, s);
            assert!(verify(scheme, &pk, &r, &msg));
            s
        };
        assert_eq!(hex(&sig), hex(&b(&k["sig"])), "{}", k["label"]);
        assert!(verify(scheme, &pk, &sig, &msg));
        let mut bad = msg;
        bad[0] ^= 1;
        assert!(!verify(scheme, &pk, &sig, &bad));
        let mut bad_sig = sig.clone();
        bad_sig[100] ^= 1;
        assert!(!verify(scheme, &pk, &bad_sig, &msg));
        assert!(!verify(scheme, &pk, &sig[..sig.len() - 1], &msg));
    }
    assert_eq!((slh, falcon), (2, 3));
}
