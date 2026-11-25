// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The two mode-0 wallet provers and their verifiers (decision Y-W2, docs/decisions.md).
//! Input to both: the statement in the specification's vector format (spec §14,
//! `yugen-ref` `vectors::public_json` / `witness_json`); each system decodes it as its own
//! vector tests do.
//!
//! - System A (`yugen-proof-a` f79c8b5): `e2::prove_consensus_leaf`, the masked wallet program of
//!   spec 0.4/0.5.1 (`Params::wallet04_masked`) under row `CAT1_TREE_LEAF_SALTED`, rate 1/4, every
//!   seed from the operating system; verified by `e2::verify_wallet04_with` under that row.
//! - System B (`yugen-proof-b2` 2b0cb46, consensus build `cat1t,blake3`, decision Y-W3b):
//!   `statement04::build(None)`, `ZkLeaf::setup(WALLET_MODE0, cs, 3)` (zero knowledge, rate 1/8,
//!   pin wrapper layout: `StatementId("wallet/mode0", cs, 3, zk)` with `wrapper_derives_public`,
//!   exactly the bundle leaf key); verified by `Public::precheck(0)` then `ZkLeaf::verify_words`.

use serde_json::Value;

fn unhex(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap_or("")).unwrap_or_default()
}
fn arr<const L: usize>(v: &Value) -> Result<[u8; L], String> {
    unhex(v).try_into().map_err(|b: Vec<u8>| format!("{} bytes where {L} are needed", b.len()))
}
fn int(v: &Value) -> Result<u64, String> {
    match v {
        Value::String(s) => s.parse().map_err(|_| format!("{s}: not u64")),
        o => o.as_u64().ok_or_else(|| format!("{o}: not u64")),
    }
}

pub mod a {
    use super::*;
    use yugen_proof_a::circuit::{build, Circuit, Params};
    use yugen_proof_a::e2;
    use yugen_proof_a::native;
    use yugen_proof_a::wallet::v04::{Output, Public, Spend, Witness};

    pub fn public(p: &Value) -> Result<Public, String> {
        Ok(Public {
            anchor_root: arr(&p["anchor_root"])?,
            nf: [arr(&p["nf_1"])?, arr(&p["nf_2"])?],
            cm: [arr(&p["cm_1"])?, arr(&p["cm_2"])?],
            fee: int(&p["fee"])?,
            vb_in: int(&p["vb_in"])?,
            vb_out: int(&p["vb_out"])?,
            m: arr(&p["sig_digest"])?,
            auth_mode: int(&p["auth_mode"])? as u8,
            reg_root: arr(&p["reg_root"])?,
        })
    }
    fn spend(s: &Value) -> Result<Spend, String> {
        Ok(Spend {
            dummy: int(&s["is_dummy"])?,
            dx: arr(&s["dx"])?,
            v: int(&s["v"])?,
            nk: arr(&s["nk_d"])?,
            rho: arr(&s["rho"])?,
            rcm: arr(&s["rcm"])?,
            pos: int(&s["pos"])?,
            path: unhex(&s["path"]).chunks(48).map(|c| c.try_into().unwrap()).collect(),
            salt: arr(&s["salt"])?,
            rkh: arr(&s["rkh"])?,
        })
    }
    fn output(o: &Value) -> Result<Output, String> {
        Ok(Output { w: int(&o["v"])?, auth: arr(&o["auth"])?, nkc: arr(&o["nkc"])?, rcm: arr(&o["rcm"])? })
    }
    pub fn witness(w: &Value) -> Result<Witness, String> {
        let s2 = unhex(&w["sig_s2_le16"]);
        if s2.len() != 2 * native::N {
            return Err("sig_s2_le16 length".into());
        }
        Ok(Witness {
            pk: arr(&w["pk"])?,
            nonce: arr(&w["sig_nonce"])?,
            s2: std::array::from_fn(|i| i16::from_le_bytes([s2[2 * i], s2[2 * i + 1]]) as i32),
            spends: [spend(&w["spend_1"])?, spend(&w["spend_2"])?],
            outputs: [output(&w["output_1"])?, output(&w["output_2"])?],
        })
    }
    pub struct Setup {
        pub circuit: Circuit,
        pub key: e2::Key,
    }
    pub fn setup() -> Setup {
        let circuit = build(&Params::wallet04_masked(), &[]);
        let key = e2::Key::new(&circuit);
        Setup { circuit, key }
    }
    pub fn prove(s: &Setup, public_json: &Value, witness_json: &Value) -> Result<Vec<u8>, String> {
        let p = public(public_json)?;
        let raw = yugen_proof_a::wallet04_raw(&s.circuit.params, &p, &witness(witness_json)?)?;
        e2::prove_consensus_leaf(&s.key, &s.circuit, raw, &p).map(|proof| proof.to_bytes())
    }
    pub fn verify(s: &Setup, public_json: &Value, proof: &[u8]) -> Result<(), String> {
        let p = public(public_json)?;
        let proof = verifier_e2::Proof::from_bytes(proof).ok_or("proof A does not decode")?;
        e2::verify_wallet04_with(&verifier_e2::params::CAT1_TREE_LEAF_SALTED, &s.key, &s.circuit, &p, &proof)
    }
}

pub mod b {
    use super::*;
    use binius_core::word::Word;
    use yugen_proof_b2::prove::{ZkLeaf, WALLET_MODE0};
    use yugen_proof_b2::statement04::{self, Statement};
    use yugen_proof_b2::witness04::{fill, Public, Witness};

    pub const CIRCUIT: &str = WALLET_MODE0;
    pub const LOG_INV_RATE: usize = 3;
    /// The most a leaf transfer's System B proof may be (spec §2 `LEAF_PROOF_MAX_B`, W4).
    /// Spec 0.5.2 (SPEC-214).
    pub const LEAF_PROOF_MAX_B: usize = 817_736;
    pub struct Setup {
        pub st: Statement,
        pub leaf: ZkLeaf,
    }
    pub fn setup() -> Setup {
        let st = statement04::build(None);
        let leaf = ZkLeaf::setup(CIRCUIT, st.circuit.constraint_system(), LOG_INV_RATE);
        Setup { st, leaf }
    }
    pub fn prove(s: &Setup, public_json: &Value, witness_json: &Value) -> Result<Vec<u8>, String> {
        let p = Public::from_json(public_json).map_err(|e| format!("{e:?}"))?;
        let w = Witness::from_json(witness_json).map_err(|e| format!("{e:?}"))?;
        let values = fill(&s.st, &p, &w.raw(&p)).map_err(|e| format!("{e:?}"))?;
        let proof = s.leaf.prove(&values);
        if proof.len() > LEAF_PROOF_MAX_B {
            return Err(format!("proof B: {} bytes, above LEAF_PROOF_MAX_B {LEAF_PROOF_MAX_B}", proof.len()));
        }
        Ok(proof)
    }
    pub fn verify(s: &Setup, public_json: &Value, proof: &[u8]) -> Result<(), String> {
        if proof.len() > LEAF_PROOF_MAX_B {
            return Err(format!("proof B: {} bytes, above LEAF_PROOF_MAX_B {LEAF_PROOF_MAX_B}", proof.len()));
        }
        let p = Public::from_json(public_json).map_err(|e| format!("{e:?}"))?;
        p.precheck(0).map_err(|e| e.to_string())?;
        let words: Vec<Word> = p.words().into_iter().map(Word::from_u64).collect();
        s.leaf.verify_words(&words, proof).map_err(|e| format!("{e:?}"))
    }
}
