// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The hybrid builder: a transparent transaction with a Sapling part, its Sapling bundle built and
//! proven, the ZIP-243 digests its transparent inputs sign over it, and the finished transaction
//! (moved from `yewd/signer/src/sapling.rs`, review YEW-PORT-5 R3, a pure move: the bodies are
//! byte-identical; the lines that are not are listed in that commit). Native only: the prover
//! (`zcash_proofs`) is not part of the browser build.
//!
//! **Not an app API** (review YEW-REVIEW-6 L3). These are signing and proving primitives: they
//! build and sign whatever they are given. They are `pub` only because yewd-signer, another
//! crate, calls them; every caller must pass the finished transaction through
//! [`crate::gate::check`] (and the remote layer, [`crate::gate::confirm`]) before it is shown or
//! broadcast. Nothing in [`crate::api`] (the app bridge's only input) or in `web/core-wasm`
//! names this module; `tests::not_exported_to_the_apps` holds that.

use crate as yew_core;
use crate::params::{Network, SIGHASH_ALL};
use crate::pq::PqKey;
use crate::refuse::{self, no, Refused};
use crate::sapling_part::SaplingOut;
use rand_core::{CryptoRng, RngCore};
use sapling_crypto::value::NoteValue;
use sapling_crypto::zip32::ExtendedSpendingKey;
use sapling_crypto::{Anchor, MerklePath, Node, Note, PaymentAddress, Rseed};
use secp256k1::SecretKey;
use yew_core::shielded_keys::SaplingAccount;
use zcash_protocol::value::Zatoshis;
use zcash_transparent::address::TransparentAddress;
use zip32::Scope;

pub fn hex32(s: &str, what: &str) -> Result<[u8; 32], Refused> {
    hex::decode(s)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| (refuse::MALFORMED, format!("{what}: not 32 bytes of hex")))
}

pub fn zat(v: i64, what: &str) -> Result<Zatoshis, Refused> {
    u64::try_from(v)
        .ok()
        .and_then(|v| Zatoshis::from_u64(v).ok())
        .ok_or_else(|| (refuse::MALFORMED, format!("{what}: {v} is not an amount")))
}

/// A `Script` from its bytes (through its own reader: a compact size, then the bytes).
pub fn script_of(b: &[u8]) -> Result<zcash_transparent::address::Script, Refused> {
    let mut v = Vec::with_capacity(b.len() + 3);
    match b.len() {
        n @ 0..=252 => v.push(n as u8),
        n @ 253..=0xffff => {
            v.push(253);
            v.extend_from_slice(&(n as u16).to_le_bytes());
        }
        n => {
            v.push(254);
            v.extend_from_slice(&(n as u32).to_le_bytes());
        }
    }
    v.extend_from_slice(b);
    zcash_transparent::address::Script::read(&v[..])
        .map_err(|e| (refuse::MALFORMED, format!("a script: {e}")))
}

pub fn taddr_of(script: &[u8]) -> Option<TransparentAddress> {
    if let Some(h) = yew_core::script::p2pkh_hash(script) {
        return Some(TransparentAddress::PublicKeyHash(h));
    }
    yew_core::script::p2sh_hash(script).map(TransparentAddress::ScriptHash)
}

/// The account's extended spending key from its seed phrase (review YEW-PORT-5 R2: the body of
/// yewd-signer's `SignerCore::sapling_extsk` after the lock check, `self.network` as a
/// parameter).
pub fn sapling_extsk(phrase: &str, network: Network) -> Result<ExtendedSpendingKey, Refused> {
    let acct = SaplingAccount::from_mnemonic(phrase, "", network)
        .map_err(|e| (refuse::FAILED, e.to_string()))?;
    let mut b = acct.spending_key_bytes();
    let k = ExtendedSpendingKey::from_bytes(&b)
        .map_err(|_| (refuse::FAILED, "the Sapling spending key".to_string()));
    b.fill(0);
    k
}

// ---------------------------------------------------------------------------------------------
// A transparent transaction with a Sapling part (S4, F-S2-8): a YED mint funded from a Sapling
// address, a redemption or a bond withdrawal paying one. The Sapling bundle is built and proven
// first; every transparent input's ZIP-243 digest then covers it (hashShieldedSpends,
// hashShieldedOutputs, valueBalance), the signer's own scriptSigs are made over those digests,
// and last the spend authorizations and the binding signature over the shielded digest.

/// The authorization of the transaction while its Sapling part is proven but not signed.
struct HybridAuth;

impl zcash_primitives::transaction::Authorization for HybridAuth {
    type TransparentAuth = zcash_transparent::bundle::Authorized;
    type SaplingAuth = sapling_crypto::builder::InProgress<
        sapling_crypto::builder::Proven,
        sapling_crypto::builder::Unsigned,
    >;
    type OrchardAuth = orchard::bundle::Authorized;
}

type ProvenBundle = sapling_crypto::Bundle<
    sapling_crypto::builder::InProgress<
        sapling_crypto::builder::Proven,
        sapling_crypto::builder::Unsigned,
    >,
    zcash_protocol::value::ZatBalance,
>;

/// A transaction's Sapling part, proven, and the digests its transparent inputs sign.
pub struct Hybrid {
    data: zcash_primitives::transaction::TransactionData<HybridAuth>,
    asks: Vec<sapling_crypto::keys::SpendAuthorizingKey>,
}

impl Hybrid {
    /// The ZIP-243 digest of input `index` over `script_code` and `amount`, `SIGHASH_ALL` or
    /// `SIGHASH_ALL|ANYONECANPAY`.
    pub fn digest(
        &self,
        index: usize,
        script_code: &[u8],
        script_pubkey: &[u8],
        amount: i64,
        hash_type: u32,
    ) -> Result<[u8; 32], Refused> {
        let bundle = self
            .data
            .transparent_bundle()
            .ok_or_else(|| (refuse::FAILED, "no transparent part".to_string()))?;
        let sc = script_of(script_code)?;
        let spk = script_of(script_pubkey)?;
        let ht = zcash_transparent::sighash::SighashType::parse(hash_type as u8)
            .ok_or_else(|| (refuse::FAILED, format!("hash type {hash_type}")))?;
        let input = zcash_transparent::sighash::SignableInput::from_parts(
            bundle,
            ht,
            index,
            &sc,
            &spk,
            zat(amount, "input amount")?,
        )
        .map_err(|_| (refuse::UNBOUND_INPUT, format!("input {index}")))?;
        let h = zcash_primitives::transaction::sighash_v4::v4_signature_hash(
            &self.data,
            &zcash_primitives::transaction::sighash::SignableInput::Transparent(input),
        );
        Ok(h.as_bytes().try_into().expect("32 bytes"))
    }

    /// The finished transaction: `signed` (the transparent part with its scriptSigs) and the
    /// Sapling part authorized over the shielded digest. `rng` is the randomness of the spend
    /// authorizations and the binding signature (review YEW-REVIEW-6: injectable for the vector
    /// test; every production caller passes `OsRng`).
    pub fn finish(
        self,
        signed: &yew_core::tx::Transaction,
        rng: impl RngCore + CryptoRng,
    ) -> Result<Vec<u8>, Refused> {
        let shielded = zcash_primitives::transaction::sighash_v4::v4_signature_hash(
            &self.data,
            &zcash_primitives::transaction::sighash::SignableInput::Shielded,
        );
        let sighash: [u8; 32] = shielded.as_bytes().try_into().expect("32 bytes");
        let parts = self.data;
        let sapling = parts
            .sapling_bundle()
            .cloned()
            .ok_or_else(|| (refuse::FAILED, "no Sapling part".to_string()))?;
        let authorized = sapling
            .apply_signatures(rng, sighash, &self.asks)
            .map_err(|e| (refuse::FAILED, format!("the Sapling signatures: {e:?}")))?;
        // the transparent part with its scriptSigs, read through librustzcash's parser
        let raw = signed
            .serialize()
            .map_err(|e| (refuse::FAILED, e.to_string()))?;
        let t =
            zcash_primitives::transaction::Transaction::read(&raw[..], parts.consensus_branch_id())
                .map_err(|e| (refuse::FAILED, format!("the transparent part: {e}")))?;
        let tdata = t.into_data();
        let full = zcash_primitives::transaction::TransactionData::<
            zcash_primitives::transaction::Authorized,
        >::from_parts(
            tdata.version(),
            tdata.consensus_branch_id(),
            tdata.lock_time(),
            tdata.expiry_height(),
            tdata.transparent_bundle().cloned(),
            None,
            Some(authorized),
            None,
        );
        let tx = full
            .freeze()
            .map_err(|e| (refuse::FAILED, format!("the transaction: {e}")))?;
        let mut out = Vec::new();
        tx.write(&mut out)
            .map_err(|e| (refuse::FAILED, e.to_string()))?;
        Ok(out)
    }
}

/// Build and prove `part` for the transparent transaction `tx` (scriptSigs empty) (review
/// YEW-PORT-5 R2: a free function; the spending key and the network are parameters). `rng` is
/// the randomness of the bundle (its order, its dummies, the note commitments' trapdoors) and of
/// the proofs (review YEW-REVIEW-6: injectable for the vector test; every production caller
/// passes `OsRng`).
pub fn sapling_prepare(
    extsk: ExtendedSpendingKey,
    network: Network,
    part: &crate::sapling_part::SaplingPart,
    tx: &yew_core::tx::Transaction,
    branch_id: u32,
    mut rng: impl RngCore + CryptoRng,
) -> Result<Hybrid, Refused> {
    let dfvk = extsk.to_diversifiable_full_viewing_key();
    let internal = extsk.derive_internal();
    let anchor = if part.spends.is_empty() {
        Anchor::empty_tree()
    } else {
        let a = hex32(&part.anchor, "anchor")?;
        Option::<Anchor>::from(Anchor::from_bytes(a))
            .ok_or_else(|| (refuse::MALFORMED, "anchor: not a Sapling root".to_string()))?
    };
    let mut b = sapling_crypto::builder::Builder::new(
        sapling_crypto::note_encryption::Zip212Enforcement::On,
        sapling_crypto::builder::BundleType::DEFAULT,
        anchor,
    );
    for s in &part.spends {
        let (note, path, fvk) = spend_parts(&dfvk, s, &anchor)?;
        b.add_spend(fvk, note, path)
            .map_err(|e| (refuse::FAILED, format!("sapling spend: {e:?}")))?;
    }
    let hrp = network.sapling_address_hrp();
    for o in &part.outputs {
        let (ovk, to, value, memo) = match o {
            SaplingOut::Shielded {
                address,
                value,
                memo,
                ..
            } => {
                let to = zcash_keys::encoding::decode_payment_address(hrp, address)
                    .map_err(|e| (refuse::MALFORMED, format!("{address}: {e}")))?;
                let mut m = [0u8; 512];
                if memo.is_empty() {
                    m[0] = 0xf6;
                } else {
                    let bytes =
                        hex::decode(memo).map_err(|_| (refuse::MALFORMED, "memo".to_string()))?;
                    if bytes.len() > 512 {
                        return no(refuse::MALFORMED, "memo too long");
                    }
                    m[..bytes.len()].copy_from_slice(&bytes);
                }
                (dfvk.to_ovk(Scope::External), to, *value, m)
            }
            SaplingOut::Change { value } => {
                let mut m = [0u8; 512];
                m[0] = 0xf6;
                (
                    dfvk.to_ovk(Scope::Internal),
                    dfvk.change_address().1,
                    *value,
                    m,
                )
            }
            SaplingOut::Transparent { .. } => {
                return no(
                    refuse::MALFORMED,
                    "a transparent output in the Sapling part",
                )
            }
        };
        let v = u64::try_from(value)
            .map_err(|_| (refuse::MALFORMED, "a negative output".to_string()))?;
        b.add_output(Some(ovk), to, NoteValue::from_raw(v), memo)
            .map_err(|e| (refuse::FAILED, format!("sapling output: {e:?}")))?;
    }
    let dir = std::path::Path::new(&part.params_dir);
    yew_core::sapling_params::ensure_verified(dir)
        .map_err(|e| (refuse::FAILED, format!("the Sapling parameters: {e}")))?;
    let prover = zcash_proofs::prover::LocalTxProver::new(
        &dir.join(yew_core::sapling_params::SPEND.name),
        &dir.join(yew_core::sapling_params::OUTPUT.name),
    );
    let (unproven, _) = b
            .build::<zcash_proofs::prover::LocalTxProver, zcash_proofs::prover::LocalTxProver, _, zcash_protocol::value::ZatBalance>(
                &[extsk.clone(), internal.clone()],
                &mut rng,
            )
            .map_err(|e| (refuse::FAILED, format!("the Sapling bundle: {e:?}")))?
            .ok_or_else(|| (refuse::MALFORMED, "an empty Sapling part".to_string()))?;
    let proven: ProvenBundle = unproven.create_proofs(&prover, &prover, &mut rng, ());
    let raw = tx
        .serialize()
        .map_err(|e| (refuse::FAILED, e.to_string()))?;
    let branch = zcash_protocol::consensus::BranchId::try_from(branch_id)
        .map_err(|_| (refuse::MALFORMED, format!("branch id {branch_id:08x}")))?;
    let t = zcash_primitives::transaction::Transaction::read(&raw[..], branch)
        .map_err(|e| (refuse::MALFORMED, format!("the transparent part: {e}")))?;
    let d = t.into_data();
    let data = zcash_primitives::transaction::TransactionData::<HybridAuth>::from_parts(
        d.version(),
        branch,
        d.lock_time(),
        d.expiry_height(),
        d.transparent_bundle().cloned(),
        None,
        Some(proven),
        None,
    );
    Ok(Hybrid {
        data,
        asks: vec![extsk.expsk.ask.clone(), internal.expsk.ask.clone()],
    })
}

/// A spend's note, path and full viewing key, checked as yewd-signer's `sapling_build` does.
fn spend_parts(
    dfvk: &sapling_crypto::zip32::DiversifiableFullViewingKey,
    s: &crate::sapling_part::SaplingSpend,
    anchor: &Anchor,
) -> Result<(Note, MerklePath, sapling_crypto::keys::FullViewingKey), Refused> {
    let addr_bytes: [u8; 43] = hex::decode(&s.recipient)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| {
            (
                refuse::MALFORMED,
                "spend recipient: not 43 bytes".to_string(),
            )
        })?;
    let addr = PaymentAddress::from_bytes(&addr_bytes)
        .ok_or_else(|| (refuse::MALFORMED, "spend recipient".to_string()))?;
    if !s.after_zip212 {
        return no(
            refuse::MALFORMED,
            "a pre-ZIP-212 note is not spent by this signer",
        );
    }
    let note = Note::from_parts(
        addr,
        NoteValue::from_raw(s.value),
        Rseed::AfterZip212(hex32(&s.rseed, "rseed")?),
    );
    let scope = if s.internal {
        Scope::Internal
    } else {
        Scope::External
    };
    match dfvk.decrypt_diversifier(&addr) {
        Some((_, sc)) if sc == scope => {}
        _ => return no(refuse::KEY_MISMATCH, "a spent note is not this account's"),
    }
    if s.path.len() != 32 {
        return no(refuse::MALFORMED, "a Merkle path has 32 nodes");
    }
    let mut nodes = Vec::with_capacity(32);
    for h in &s.path {
        let b = hex32(h, "path node")?;
        nodes.push(
            Option::<Node>::from(Node::from_bytes(b))
                .ok_or_else(|| (refuse::MALFORMED, "path node".to_string()))?,
        );
    }
    let path = MerklePath::from_parts(nodes, incrementalmerkletree::Position::from(s.position))
        .map_err(|_| (refuse::MALFORMED, "a Merkle path".to_string()))?;
    if Anchor::from(path.root(Node::from_cmu(&note.cmu()))) != *anchor {
        return no(
            refuse::PREVIEW_MISMATCH,
            "a note's path does not lead to the anchor",
        );
    }
    let fvk = if s.internal {
        dfvk.to_internal_fvk()
    } else {
        dfvk.fvk().clone()
    };
    Ok((note, path, fvk))
}

// ---------------------------------------------------------------------------------------------
// The signing loop's P2PKH and post-quantum arms (moved from yewd/signer/src/sign.rs
// `SignerCore::sign`, review YEW-REVIEW-6 item 4, a pure move: the bodies are the signer's; the
// lines that are not are listed in that commit). yewd-signer calls them for its `KeyRef::Bip32`
// and `KeyRef::Pq` inputs; [`sign_hybrid`] is the core's loop over them.

/// The ZIP-243 digest of input `i` (`SIGHASH_ALL`) under `branch_id`: over the proven Sapling
/// part when there is one ([`Hybrid::digest`]), else over the transparent transaction (the
/// signer's `digest_of`).
pub fn input_digest(
    hybrid: Option<&Hybrid>,
    branch_id: u32,
    tx: &yew_core::tx::Transaction,
    i: usize,
    script_code: &[u8],
    script: &[u8],
    amount: i64,
) -> Result<[u8; 32], Refused> {
    match hybrid {
        Some(h) => h.digest(i, script_code, script, amount, SIGHASH_ALL),
        None => tx
            .sighash(i, script_code, amount, SIGHASH_ALL, branch_id)
            .map_err(|e| (refuse::FAILED, e.to_string())),
    }
}

/// A DER ECDSA signature over `digest` with the `SIGHASH_ALL` byte appended (the signer's
/// `ecdsa`).
pub fn ecdsa(digest: [u8; 32], sk: &SecretKey) -> Vec<u8> {
    let sig = secp256k1::ecdsa::sign(secp256k1::Message::from_digest(digest), sk);
    let mut der = sig.serialize_der().to_vec();
    der.push(SIGHASH_ALL as u8);
    der
}

/// Sign P2PKH input `i` (prevout `script`, `amount`) with `sk` / `pk`: its scriptSig is set and
/// its digest returned (the signer's `KeyRef::Bip32` arm).
#[allow(clippy::too_many_arguments)]
pub fn sign_p2pkh_input(
    hybrid: Option<&Hybrid>,
    branch_id: u32,
    tx: &mut yew_core::tx::Transaction,
    i: usize,
    script: &[u8],
    amount: i64,
    sk: &SecretKey,
    pk: &[u8; 33],
) -> Result<[u8; 32], Refused> {
    let digest = input_digest(hybrid, branch_id, tx, i, script, script, amount)?;
    tx.vin[i].script_sig = yew_core::script::p2pkh_script_sig(&ecdsa(digest, sk), pk);
    Ok(digest)
}

/// Sign `TX_PQPKH` input `i` (prevout `script`, `amount`) with `k`: its scriptSig is set and its
/// digest returned (the signer's `KeyRef::Pq` arm).
pub fn sign_pq_input(
    hybrid: Option<&Hybrid>,
    branch_id: u32,
    tx: &mut yew_core::tx::Transaction,
    i: usize,
    script: &[u8],
    amount: i64,
    k: &PqKey,
) -> Result<[u8; 32], Refused> {
    let digest = input_digest(hybrid, branch_id, tx, i, script, script, amount)?;
    let mut sig = k.sign(&digest);
    sig.push(SIGHASH_ALL as u8);
    tx.vin[i].script_sig = yew_core::pq::pqpkh_script_sig(&sig, k.public_key())
        .map_err(|e| (refuse::FAILED, e.to_string()))?;
    Ok(digest)
}

/// The finished bytes of the signed `tx`: with a Sapling part, [`Hybrid::finish`] (`rng`: the
/// Sapling authorizations' randomness, `OsRng` in production); else its serialization.
pub fn finish_signed(
    hybrid: Option<Hybrid>,
    tx: &yew_core::tx::Transaction,
    rng: impl RngCore + CryptoRng,
) -> Result<Vec<u8>, Refused> {
    let out = match hybrid {
        Some(h) => h.finish(tx, rng)?,
        None => tx
            .serialize()
            .map_err(|e| (refuse::FAILED, e.to_string()))?,
    };
    Ok(out)
}

/// The key of a transparent input [`sign_hybrid`] signs.
pub enum HybridKey<'a> {
    /// A P2PKH coin: its ECC key and compressed public key.
    P2pkh(&'a SecretKey, &'a [u8; 33]),
    /// A `TX_PQPKH` coin: its post-quantum key.
    Pq(&'a PqKey),
}

/// A transparent input of a hybrid transaction: its prevout's scriptPubKey and amount, its key.
pub struct HybridInput<'a> {
    /// The prevout's scriptPubKey (the script code too: P2PKH and `TX_PQPKH`).
    pub script: &'a [u8],
    /// The prevout's amount, zat.
    pub amount: i64,
    /// The key that owns it.
    pub key: HybridKey<'a>,
}

/// Sign every transparent input of `tx` (`inputs[i]` is `vin[i]`) over the proven Sapling part
/// with [`sign_p2pkh_input`] / [`sign_pq_input`], then [`finish_signed`]. Returns each input's
/// digest and the final bytes. A key that does not own its prevout script is refused before
/// anything is signed. Not an app API: the caller passes the bytes through `gate::check`.
pub fn sign_hybrid(
    hybrid: Hybrid,
    mut tx: yew_core::tx::Transaction,
    inputs: &[HybridInput<'_>],
    branch_id: u32,
    rng: impl RngCore + CryptoRng,
) -> Result<(Vec<[u8; 32]>, Vec<u8>), Refused> {
    // review YEW-REVIEW-7 L3: the digests are taken under the branch the part was prepared under
    if u32::from(hybrid.data.consensus_branch_id()) != branch_id {
        return no(
            refuse::MALFORMED,
            format!("branch id {branch_id:08x}: the Sapling part was prepared under another"),
        );
    }
    if inputs.len() != tx.vin.len() {
        return no(
            refuse::MALFORMED,
            format!("{} inputs and {} keys", tx.vin.len(), inputs.len()),
        );
    }
    for (i, inp) in inputs.iter().enumerate() {
        let owns = match inp.key {
            HybridKey::P2pkh(_, pk) => {
                yew_core::script::p2pkh_script(&yew_core::keys::hash160(pk)) == inp.script
            }
            HybridKey::Pq(k) => yew_core::pq::pqpkh_script(&k.id()).as_deref() == Some(inp.script),
        };
        if !owns {
            return no(
                refuse::KEY_MISMATCH,
                format!("input {i} is not paid to the named key"),
            );
        }
    }
    let mut sighashes = Vec::with_capacity(inputs.len());
    for (i, inp) in inputs.iter().enumerate() {
        let digest = match inp.key {
            HybridKey::P2pkh(sk, pk) => sign_p2pkh_input(
                Some(&hybrid),
                branch_id,
                &mut tx,
                i,
                inp.script,
                inp.amount,
                sk,
                pk,
            )?,
            HybridKey::Pq(k) => sign_pq_input(
                Some(&hybrid),
                branch_id,
                &mut tx,
                i,
                inp.script,
                inp.amount,
                k,
            )?,
        };
        sighashes.push(digest);
    }
    let raw = finish_signed(Some(hybrid), &tx, rng)?;
    Ok((sighashes, raw))
}

#[cfg(test)]
mod tests {
    /// Review YEW-REVIEW-6 L3: the app bridge's only input (`crate::api`, flutter_rust_bridge.yaml
    /// `rust_input`) and the browser build's exports (`web/core-wasm`) name nothing from this
    /// module, so no app call reaches these primitives except through a gated builder.
    #[test]
    fn not_exported_to_the_apps() {
        let sources = [
            ("core/src/api.rs", include_str!("../api.rs")),
            (
                "web/core-wasm/src/lib.rs",
                include_str!("../../../web/core-wasm/src/lib.rs"),
            ),
            (
                "web/core-wasm/src/dto.rs",
                include_str!("../../../web/core-wasm/src/dto.rs"),
            ),
        ];
        let names = [
            "hybrid",
            "sapling_prepare",
            "sapling_extsk",
            "script_of",
            "taddr_of",
            "hex32",
        ];
        for (file, text) in sources {
            let lower = text.to_lowercase();
            for n in names {
                assert!(!lower.contains(n), "{file} names `{n}` (build::hybrid)");
            }
        }
        let bridge = include_str!("../../../flutter_rust_bridge.yaml");
        assert!(bridge.contains("rust_input: crate::api"), "{bridge}");
    }
}
