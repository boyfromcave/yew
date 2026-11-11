// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The hybrid transaction vectors (review YEW-REVIEW-6, the regression guard before the signing
//! loop moves): fixed keys, fixed randomness, the shapes the Sapling <-> post-quantum and vault
//! funding paths build. Shared by the test files that sign them (`hybrid_vectors.rs`, and later
//! the moved signing loop's own), so every signer is held to the same pinned bytes in
//! `vectors/hybrid_vectors.json`.
//!
//! What is pinned, per case: the transaction bytes, except the scriptSig of each FN-DSA input
//! (Falcon signing draws 88 bytes from the OS RNG inside `PqKey::sign`, not from the injected
//! RNG); those scriptSigs are emptied before hashing and are checked by verification instead. A
//! ZIP-243 digest covers no scriptSig, so every sighash, the Sapling part (proofs, spend
//! authorizations, binding signature), every ECDSA scriptSig (RFC 6979) and every SLH-DSA
//! scriptSig (deterministic, `opt_rand = PK.seed`) are byte-exact. Also pinned: each
//! transparent input's sighash and the shielded sighash under branch 0x6d5b7a31.
//!
//! What is verified, through the verifying code path and not the signer's digest: the final
//! bytes are parsed by librustzcash (`Transaction::read` under the Vault branch); each sighash is
//! recomputed with `sighash_v4::v4_signature_hash` (what `sighash::signature_hash` dispatches a
//! v4 transaction to; `signature_hash` itself needs a `TransparentAuthorizingContext`, which a
//! parsed, authorized transparent bundle does not implement in this librustzcash) from the parsed
//! transaction and the prevouts; each
//! ECDSA and post-quantum signature is verified against it (and its key against the prevout
//! script); the Sapling bundle is checked by `sapling_crypto::BatchValidator` (proofs, spend
//! authorizations, binding signature) over the recomputed shielded sighash with the verifying keys
//! of the proving parameters.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use incrementalmerkletree::{Hashable, Level, Position};
use rand::SeedableRng;
use sapling_crypto::zip32::ExtendedSpendingKey;
use sapling_crypto::{MerklePath, Node, Note, Rseed};
use yew_core::build::hybrid::{sapling_extsk, sapling_prepare, Hybrid};
use yew_core::params::Network;
use yew_core::pq::{self, PqKey};
use yew_core::refuse::Refused;
use yew_core::sapling_part::{SaplingOut, SaplingPart, SaplingSpend};
use yew_core::tx::{OutPoint, Transaction, TxIn, TxOut};

/// The Vault branch (`0x6d5b7a31`).
pub const VAULT_BRANCH: u32 = 0x6d5b7a31;
pub const COIN: i64 = 100_000_000;
const PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/// The seeds of the injected RNGs: one for `sapling_prepare`, one for `Hybrid::finish`.
const PREPARE_SEED: u64 = 0x5945_5750_5245_5031;
const FINISH_SEED: u64 = 0x5945_5746_494e_3031;

/// A transparent input's key.
pub enum InputKey {
    /// A P2PKH coin's ECC key.
    Ecc(secp256k1::SecretKey, [u8; 33]),
    /// A `TX_PQPKH` coin's post-quantum key.
    Pq(PqKey),
}

/// A transparent input: the coin and its key.
pub struct Input {
    pub outpoint: OutPoint,
    pub value: i64,
    /// The prevout's scriptPubKey (also the script code: P2PKH and `TX_PQPKH`).
    pub script: Vec<u8>,
    pub key: InputKey,
}

/// One vector: the transparent part (scriptSigs empty), its inputs' keys, the Sapling part.
pub struct Case {
    pub name: &'static str,
    pub tx: Transaction,
    pub inputs: Vec<Input>,
    pub part: SaplingPart,
    pub extsk: ExtendedSpendingKey,
}

/// What a signer returns: each input's digest (as the signing loop records it) and the final
/// bytes.
pub struct Signed {
    pub sighashes: Vec<Option<[u8; 32]>>,
    pub raw: Vec<u8>,
}

/// The Sapling proving parameters: `YEW_SAPLING_PARAMS`, else where yewd looks (its
/// `params_dir()` default, the directory `send_matrix.rs` proves with).
pub fn params_dir() -> PathBuf {
    if let Ok(d) = std::env::var("YEW_SAPLING_PARAMS") {
        return PathBuf::from(d);
    }
    let home = std::env::var("HOME").unwrap_or_default();
    if cfg!(target_os = "macos") {
        PathBuf::from(format!("{home}/Library/Application Support/ZcashParams"))
    } else {
        PathBuf::from(format!("{home}/.zcash-params"))
    }
}

fn ecc_key(b: u8) -> InputKey {
    let sk = secp256k1::SecretKey::from_secret_bytes([b; 32]).expect("a valid key");
    let pk = secp256k1::PublicKey::from_secret_key(&sk).serialize();
    InputKey::Ecc(sk, pk)
}

fn pq_key(scheme: u8, b: u8) -> PqKey {
    PqKey::from_seed(scheme, &[b; 48]).expect("a PQ key")
}

fn p2pkh_of(pk: &[u8; 33]) -> Vec<u8> {
    yew_core::script::p2pkh_script(&yew_core::keys::hash160(pk))
}

fn pqpkh_of(k: &PqKey) -> Vec<u8> {
    pq::pqpkh_script(&k.id()).expect("a known scheme")
}

fn input(n: u8, value: i64, key: InputKey) -> Input {
    let script = match &key {
        InputKey::Ecc(_, pk) => p2pkh_of(pk),
        InputKey::Pq(k) => pqpkh_of(k),
    };
    Input {
        outpoint: OutPoint {
            txid: [n; 32],
            n: u32::from(n),
        },
        value,
        script,
        key,
    }
}

fn extsk() -> ExtendedSpendingKey {
    sapling_extsk(PHRASE, Network::Regtest).expect("the Sapling key")
}

/// One spendable note of the account (external scope) at position 0 of an otherwise empty tree:
/// the spend and the anchor (hex) its path leads to.
fn note_spend(extsk: &ExtendedSpendingKey, value: u64) -> (SaplingSpend, String) {
    let dfvk = extsk.to_diversifiable_full_viewing_key();
    let addr = dfvk.default_address().1;
    let rseed = [0x42u8; 32];
    let note = Note::from_parts(
        addr,
        sapling_crypto::value::NoteValue::from_raw(value),
        Rseed::AfterZip212(rseed),
    );
    let nodes: Vec<Node> = (0..32u8)
        .map(|l| Node::empty_root(Level::from(l)))
        .collect();
    let path = MerklePath::from_parts(nodes.clone(), Position::from(0u64)).expect("a path");
    let root = path.root(Node::from_cmu(&note.cmu()));
    let spend = SaplingSpend {
        recipient: hex::encode(addr.to_bytes()),
        value,
        rseed: hex::encode(rseed),
        after_zip212: true,
        internal: false,
        position: 0,
        path: nodes.iter().map(|n| hex::encode(n.to_bytes())).collect(),
    };
    (spend, hex::encode(root.to_bytes()))
}

fn own_zaddr(extsk: &ExtendedSpendingKey) -> String {
    let addr = extsk
        .to_diversifiable_full_viewing_key()
        .default_address()
        .1;
    zcash_keys::encoding::encode_payment_address(Network::Regtest.sapling_address_hrp(), &addr)
}

fn part(spends: Vec<SaplingSpend>, anchor: String, outputs: Vec<SaplingOut>) -> SaplingPart {
    SaplingPart {
        target_height: 1000,
        vault_height: Some(1),
        spends,
        outputs,
        anchor,
        params_dir: params_dir().display().to_string(),
    }
}

fn tx_of(inputs: &[Input], vout: Vec<TxOut>) -> Transaction {
    let mut tx = Transaction::new_v4();
    tx.expiry_height = 1040;
    for i in inputs {
        tx.vin.push(TxIn::new(i.outpoint));
    }
    tx.vout = vout;
    tx
}

/// The cases (review YEW-REVIEW-6 item 3): (a) Sapling spend + Sapling output + one P2PKH input;
/// (b) Sapling spend -> one `TX_PQPKH` output, FN-DSA and SLH-DSA; (c) one `TX_PQPKH` input of
/// each scheme -> Sapling output, post-quantum change to the source (D-4); (d) the vault-lock
/// funding shape from a Sapling source (the V the only transparent output, no transparent input,
/// Sapling change).
pub fn cases() -> Vec<Case> {
    let mut out = Vec::new();
    let x = extsk();
    // (a)
    {
        let (spend, anchor) = note_spend(&x, (3 * COIN) as u64);
        let inputs = vec![input(1, COIN, ecc_key(0x11))];
        let InputKey::Ecc(_, payee) = ecc_key(0x12) else {
            unreachable!()
        };
        let tx = tx_of(
            &inputs,
            vec![TxOut {
                value: COIN / 2,
                script_pubkey: p2pkh_of(&payee),
            }],
        );
        let p = part(
            vec![spend],
            anchor,
            vec![
                SaplingOut::Shielded {
                    address: own_zaddr(&x),
                    value: 2 * COIN,
                    memo: String::new(),
                    own: true,
                },
                SaplingOut::Change {
                    value: COIN + COIN / 2 - 10_000,
                },
            ],
        );
        out.push(Case {
            name: "a_sapling_spend_p2pkh_input_sapling_output",
            tx,
            inputs,
            part: p,
            extsk: x.clone(),
        });
    }
    // (b)
    for (name, scheme, b) in [
        ("b_sapling_to_fn_dsa", pq::SCHEME_FN_DSA_512, 0x21u8),
        ("b_sapling_to_slh_dsa", pq::SCHEME_SLH_DSA_SHA2_128S, 0x22u8),
    ] {
        let (spend, anchor) = note_spend(&x, (3 * COIN) as u64);
        let to = pq_key(scheme, b);
        let tx = tx_of(
            &[],
            vec![TxOut {
                value: COIN,
                script_pubkey: pqpkh_of(&to),
            }],
        );
        let p = part(
            vec![spend],
            anchor,
            vec![SaplingOut::Change {
                value: 2 * COIN - 10_000,
            }],
        );
        out.push(Case {
            name,
            tx,
            inputs: Vec::new(),
            part: p,
            extsk: x.clone(),
        });
    }
    // (c)
    for (name, scheme, b) in [
        ("c_fn_dsa_to_sapling", pq::SCHEME_FN_DSA_512, 0x31u8),
        ("c_slh_dsa_to_sapling", pq::SCHEME_SLH_DSA_SHA2_128S, 0x32u8),
    ] {
        let k = pq_key(scheme, b);
        let change = pqpkh_of(&k);
        let inputs = vec![input(3, 2 * COIN, InputKey::Pq(k))];
        let tx = tx_of(
            &inputs,
            vec![TxOut {
                value: COIN / 2 - 20_000,
                script_pubkey: change,
            }],
        );
        let p = part(
            Vec::new(),
            String::new(),
            vec![SaplingOut::Shielded {
                address: own_zaddr(&x),
                value: COIN + COIN / 2,
                memo: String::new(),
                own: true,
            }],
        );
        out.push(Case {
            name,
            tx,
            inputs,
            part: p,
            extsk: x.clone(),
        });
    }
    // (d)
    {
        let (spend, anchor) = note_spend(&x, (3 * COIN) as u64);
        let owner = pq_key(pq::SCHEME_SLH_DSA_SHA2_128S, 0x41).id();
        let v = yew_core::vault::build_vault(&yew_core::vault::VaultParams {
            tag: *b"TEST",
            cancel_set_id: [0x51; 32],
            delay: 144,
            set_id: [0x52; 32],
            owner_height: 2000,
            owner,
            app_height: 0,
        })
        .expect("a valid V");
        let tx = tx_of(
            &[],
            vec![TxOut {
                value: COIN,
                script_pubkey: v,
            }],
        );
        let p = part(
            vec![spend],
            anchor,
            vec![SaplingOut::Change {
                value: 2 * COIN - 10_000,
            }],
        );
        out.push(Case {
            name: "d_vault_lock_from_sapling",
            tx,
            inputs: Vec::new(),
            part: p,
            extsk: x,
        });
    }
    out
}

/// `sapling_prepare` for `c` with the injected RNG.
pub fn prepare(c: &Case) -> Result<Hybrid, Refused> {
    sapling_prepare(
        c.extsk.clone(),
        Network::Regtest,
        &c.part,
        &c.tx,
        VAULT_BRANCH,
        rand::rngs::StdRng::seed_from_u64(PREPARE_SEED),
    )
}

/// The RNG `Hybrid::finish` gets.
pub fn finish_rng() -> rand::rngs::StdRng {
    rand::rngs::StdRng::seed_from_u64(FINISH_SEED)
}

/// What a case pins (`vectors/hybrid_vectors.json`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Pinned {
    /// SHA-256 of `tx_hex`.
    pub tx_sha256: String,
    /// The final bytes, each FN-DSA input's scriptSig emptied.
    pub tx_hex: String,
    /// The inputs whose scriptSig was emptied (FN-DSA).
    pub masked_inputs: Vec<usize>,
    /// Each transparent input's ZIP-243 sighash (SIGHASH_ALL) under 0x6d5b7a31.
    pub sighashes: Vec<String>,
    /// The shielded sighash under 0x6d5b7a31.
    pub shielded_sighash: String,
    /// Sapling spends and outputs in the bundle (outputs padded to two).
    pub sapling_spends: usize,
    pub sapling_outputs: usize,
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/hybrid_vectors.json")
}

pub fn read_vectors() -> BTreeMap<String, Pinned> {
    let s = std::fs::read_to_string(vectors_path()).expect("tests/vectors/hybrid_vectors.json");
    serde_json::from_str(&s).expect("hybrid vectors")
}

/// `YEW_WRITE_HYBRID_VECTORS=1` writes the file from this run (the first run only; review the
/// diff of any rewrite like a change to signing code).
pub fn write_vectors(v: &BTreeMap<String, Pinned>) {
    let mut s = serde_json::to_string_pretty(v).expect("json");
    s.push('\n');
    std::fs::write(vectors_path(), s).expect("write hybrid vectors");
}

fn sha256_hex(b: &[u8]) -> String {
    hex::encode(yew_core::keys::sha256(b))
}

/// Verify `signed` for `c` through the verifying path and return what it pins. Panics on any
/// failure, naming the case.
pub fn verify(c: &Case, signed: &Signed) -> Pinned {
    use zcash_primitives::transaction::sighash::SignableInput;
    use zcash_primitives::transaction::sighash_v4::v4_signature_hash;
    let name = c.name;
    let branch = zcash_protocol::consensus::BranchId::try_from(VAULT_BRANCH).expect("Vault");
    let tx = zcash_primitives::transaction::Transaction::read(&signed.raw[..], branch)
        .unwrap_or_else(|e| panic!("{name}: librustzcash cannot parse the bytes: {e}"));
    assert_eq!(u32::from(tx.consensus_branch_id()), VAULT_BRANCH, "{name}");
    // the transparent part as built (outputs and inputs in order)
    let (ours, _) = Transaction::parse(&signed.raw).expect("YEW parses it");
    assert_eq!(ours.vin.len(), c.inputs.len(), "{name}: inputs");
    assert_eq!(ours.vout, c.tx.vout, "{name}: transparent outputs");
    let mut sighashes = Vec::new();
    let mut masked = Vec::new();
    let mut pinned_tx = ours.clone();
    for (i, inp) in c.inputs.iter().enumerate() {
        assert_eq!(ours.vin[i].prevout, inp.outpoint, "{name}: input {i}");
        let bundle = tx.transparent_bundle().expect("a transparent part");
        let code = yew_core::build::hybrid::script_of(&inp.script).expect("script");
        let input = zcash_transparent::sighash::SignableInput::from_parts(
            bundle,
            zcash_transparent::sighash::SighashType::ALL,
            i,
            &code,
            &code,
            zcash_protocol::value::Zatoshis::from_u64(inp.value as u64).expect("amount"),
        )
        .expect("a signable input");
        let h: [u8; 32] = v4_signature_hash(tx.deref(), &SignableInput::Transparent(input))
            .as_ref()
            .try_into()
            .expect("32 bytes");
        assert_eq!(
            signed.sighashes[i],
            Some(h),
            "{name}: input {i}: the signer's digest is not the recomputed sighash"
        );
        let ss = &ours.vin[i].script_sig;
        match &inp.key {
            InputKey::Ecc(_, pk) => {
                let p = yew_core::script::pushes(ss).expect("push-only scriptSig");
                assert_eq!(p.len(), 2, "{name}: input {i}: <sig> <pubkey>");
                assert_eq!(&p[1][..], &pk[..], "{name}: input {i}: the pubkey");
                assert_eq!(
                    p2pkh_of(pk),
                    inp.script,
                    "{name}: input {i}: key and script"
                );
                let (ht, der) = p[0].split_last().expect("a signature");
                assert_eq!(*ht, 1, "{name}: input {i}: SIGHASH_ALL");
                let sig = secp256k1::ecdsa::Signature::from_der(der).expect("DER");
                let key = secp256k1::PublicKey::from_slice(&p[1]).expect("a key");
                secp256k1::ecdsa::verify(&sig, secp256k1::Message::from_digest(h), &key)
                    .unwrap_or_else(|_| panic!("{name}: input {i}: ECDSA does not verify"));
            }
            InputKey::Pq(k) => {
                let (sig, pk) = pq::parse_pqpkh_script_sig(ss).expect("a TX_PQPKH scriptSig");
                assert_eq!(pk, k.public_key(), "{name}: input {i}: the public key");
                let id = pq::PqKeyId::of(k.scheme(), &pk);
                assert_eq!(
                    pq::pqpkh_script(&id).as_deref(),
                    Some(&inp.script[..]),
                    "{name}: input {i}: key and script"
                );
                let (ht, body) = sig.split_last().expect("a signature");
                assert_eq!(*ht, 1, "{name}: input {i}: SIGHASH_ALL");
                assert!(
                    pq::verify(k.scheme(), &pk, body, &h),
                    "{name}: input {i}: the post-quantum signature does not verify"
                );
                if k.scheme() == pq::SCHEME_FN_DSA_512 {
                    pinned_tx.vin[i].script_sig.clear();
                    masked.push(i);
                }
            }
        }
        sighashes.push(hex::encode(h));
    }
    // the Sapling part, through the batch validator over the recomputed shielded sighash
    let shielded: [u8; 32] = v4_signature_hash(tx.deref(), &SignableInput::Shielded)
        .as_ref()
        .try_into()
        .expect("32 bytes");
    let bundle = tx
        .sapling_bundle()
        .cloned()
        .unwrap_or_else(|| panic!("{name}: no Sapling part"));
    let (spends, outputs) = (
        bundle.shielded_spends().len(),
        bundle.shielded_outputs().len(),
    );
    assert_eq!(spends, c.part.spends.len(), "{name}: spends");
    let dir = params_dir();
    let params = zcash_proofs::load_parameters(
        &dir.join(yew_core::sapling_params::SPEND.name),
        &dir.join(yew_core::sapling_params::OUTPUT.name),
        None,
    );
    let mut bv = sapling_crypto::BatchValidator::new();
    assert!(
        bv.check_bundle(bundle, shielded),
        "{name}: the Sapling bundle fails its checks"
    );
    assert!(
        bv.validate(
            &params.spend_params.verifying_key(),
            &params.output_params.verifying_key(),
            rand::rngs::OsRng
        ),
        "{name}: a Sapling proof or signature does not verify"
    );
    let pinned_raw = splice_transparent(&signed.raw, &ours, &pinned_tx);
    Pinned {
        tx_sha256: sha256_hex(&pinned_raw),
        tx_hex: hex::encode(&pinned_raw),
        masked_inputs: masked,
        sighashes,
        shielded_sighash: hex::encode(shielded),
        sapling_spends: spends,
        sapling_outputs: outputs,
    }
}

/// `raw` with its transparent part (the prefix YEW serializes for `ours`) replaced by the
/// serialization of `pinned`: the Sapling part after it is kept byte for byte.
fn splice_transparent(raw: &[u8], ours: &Transaction, pinned: &Transaction) -> Vec<u8> {
    let mut a = ours.clone();
    a.shielded = Default::default();
    let mut b = pinned.clone();
    b.shielded = Default::default();
    // YEW serializes a v4 transaction with an empty Sapling part as: transparent fields,
    // nLockTime, nExpiryHeight, valueBalance (8), 0 spends, 0 outputs, 0 JoinSplits. Its prefix
    // up to nExpiryHeight is the same as the hybrid's.
    let ea = a.serialize().expect("serialize");
    let eb = b.serialize().expect("serialize");
    let tail = 8 + 1 + 1 + 1;
    let pa = &ea[..ea.len() - tail];
    let pb = &eb[..eb.len() - tail];
    assert_eq!(&raw[..pa.len()], pa, "the transparent prefix");
    let mut out = pb.to_vec();
    out.extend_from_slice(&raw[pa.len()..]);
    out
}

/// Run every case with `sign` and compare with the pinned file (or write it, see
/// [`write_vectors`]).
pub fn run_all(sign: impl Fn(&Case, Hybrid) -> Signed) {
    let mut got = BTreeMap::new();
    for c in cases() {
        let h = prepare(&c).unwrap_or_else(|e| panic!("{}: prepare: {e:?}", c.name));
        let signed = sign(&c, h);
        got.insert(c.name.to_string(), verify(&c, &signed));
    }
    if std::env::var("YEW_WRITE_HYBRID_VECTORS").as_deref() == Ok("1") {
        write_vectors(&got);
    }
    let want = read_vectors();
    assert_eq!(
        want.keys().collect::<Vec<_>>(),
        got.keys().collect::<Vec<_>>(),
        "the cases"
    );
    for (k, w) in &want {
        let g = &got[k];
        assert_eq!(g.sighashes, w.sighashes, "{k}: sighashes");
        assert_eq!(
            g.shielded_sighash, w.shielded_sighash,
            "{k}: shielded sighash"
        );
        assert_eq!(g.masked_inputs, w.masked_inputs, "{k}: masked inputs");
        assert_eq!(
            (g.sapling_spends, g.sapling_outputs),
            (w.sapling_spends, w.sapling_outputs),
            "{k}: Sapling shape"
        );
        assert_eq!(
            g.tx_sha256,
            sha256_hex(&hex::decode(&w.tx_hex).unwrap()),
            "{k}: file"
        );
        assert_eq!(
            g.tx_sha256, w.tx_sha256,
            "{k}: the transaction bytes changed"
        );
        assert_eq!(g.tx_hex, w.tx_hex, "{k}: the transaction bytes changed");
    }
}

use std::ops::Deref;
