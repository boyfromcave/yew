// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The Sapling build in the signer (K-24: "the signer runs the whole Sapling build"; finding
//! F-S2-8, resolved in S4): `z_sendmany`'s transaction, its transparent P2PKH inputs signed with
//! the wallet's BIP32 keys, its Sapling spends authorized with the account's extended spending key
//! (external and internal scope), its outputs proven with the local Sapling parameters. The façade
//! hands in the notes it decrypted and their Merkle paths (from the node's tree state); the
//! signer checks every path leads to the anchor, every input key owns its coin, and the outflow
//! cap, then builds with librustzcash6's `zcash_primitives` builder at the target height's branch
//! (the Vault branch from its regtest height).

use rand_core::OsRng;
use sapling_crypto::keys::OutgoingViewingKey;
use sapling_crypto::value::NoteValue;
use sapling_crypto::zip32::ExtendedSpendingKey;
use sapling_crypto::{Anchor, MerklePath, Node, Note, PaymentAddress, Rseed};
use yew_core::shielded_keys::SaplingAccount;
use yewd_proto::{refuse, KeyRef, SaplingBuildRequest, SaplingOut};
use zcash_primitives::transaction::builder::{BuildConfig, Builder};
use zcash_primitives::transaction::fees::fixed::FeeRule;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::Zatoshis;
use zcash_transparent::address::TransparentAddress;
use zcash_transparent::builder::TransparentSigningSet;
use zip32::Scope;

use crate::sign::{no, Refused, SignerCore};
use yew_core::params::Network;

fn hex32(s: &str, what: &str) -> Result<[u8; 32], Refused> {
    hex::decode(s)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| (refuse::MALFORMED, format!("{what}: not 32 bytes of hex")))
}

fn zat(v: i64, what: &str) -> Result<Zatoshis, Refused> {
    u64::try_from(v)
        .ok()
        .and_then(|v| Zatoshis::from_u64(v).ok())
        .ok_or_else(|| (refuse::MALFORMED, format!("{what}: {v} is not an amount")))
}

/// A `Script` from its bytes (through its own reader: a compact size, then the bytes).
fn script_of(b: &[u8]) -> Result<zcash_transparent::address::Script, Refused> {
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

fn taddr_of(script: &[u8]) -> Option<TransparentAddress> {
    if let Some(h) = yew_core::script::p2pkh_hash(script) {
        return Some(TransparentAddress::PublicKeyHash(h));
    }
    yew_core::script::p2sh_hash(script).map(TransparentAddress::ScriptHash)
}

impl SignerCore {
    /// The account's extended spending key (the signer's own use only).
    fn sapling_extsk(&self) -> Result<ExtendedSpendingKey, Refused> {
        drop(self.keys()?);
        let ks = self.keystore();
        let phrase = ks
            .phrase()
            .ok_or_else(|| (refuse::LOCKED, crate::LOCKED.to_string()))?;
        sapling_extsk(phrase, self.network)
    }

    /// `z_sendmany`'s transaction, built, proven and signed.
    pub fn sapling_build(&self, r: &SaplingBuildRequest) -> Result<String, Refused> {
        sapling_build(self.sapling_extsk()?, self.network, r, |chain, index| {
            self.transparent(chain, index)
        })
    }

    /// Build and prove `part` for the transparent transaction `tx` (scriptSigs empty).
    pub(crate) fn sapling_prepare(
        &self,
        part: &yewd_proto::SaplingPart,
        tx: &yew_core::tx::Transaction,
        branch_id: u32,
    ) -> Result<Hybrid, Refused> {
        sapling_prepare(self.sapling_extsk()?, self.network, part, tx, branch_id)
    }
}

/// The account's extended spending key from its seed phrase (review YEW-PORT-5 R2: the body of
/// [`SignerCore::sapling_extsk`] after the lock check, `self.network` as a parameter).
fn sapling_extsk(phrase: &str, network: Network) -> Result<ExtendedSpendingKey, Refused> {
    let acct = SaplingAccount::from_mnemonic(phrase, "", network)
        .map_err(|e| (refuse::FAILED, e.to_string()))?;
    let mut b = acct.spending_key_bytes();
    let k = ExtendedSpendingKey::from_bytes(&b)
        .map_err(|_| (refuse::FAILED, "the Sapling spending key".to_string()));
    b.fill(0);
    k
}

/// `z_sendmany`'s transaction, built, proven and signed (review YEW-PORT-5 R2: a free
/// function; the spending key, the network and the P2PKH-input key lookup are parameters).
fn sapling_build(
    extsk: ExtendedSpendingKey,
    network: Network,
    r: &SaplingBuildRequest,
    transparent: impl Fn(u32, u32) -> Result<(secp256k1::SecretKey, [u8; 33]), Refused>,
) -> Result<String, Refused> {
    let dfvk = extsk.to_diversifiable_full_viewing_key();
    let internal_extsk = extsk.derive_internal();
    let params =
        yew_core::shielded::ycash_network_with_vault(network, r.vault_height.map(u64::from));
    // the spends: each note rebuilt from its parts, each path checked against the anchor
    // outputs alone still need an anchor for the bundle: the empty tree's root
    let anchor = if r.spends.is_empty() {
        Some(Anchor::empty_tree())
    } else {
        let a = hex32(&r.anchor, "anchor")?;
        Some(
            Option::<Anchor>::from(Anchor::from_bytes(a))
                .ok_or_else(|| (refuse::MALFORMED, "anchor: not a Sapling root".to_string()))?,
        )
    };
    let mut builder = Builder::new(
        params,
        BlockHeight::from_u32(r.target_height),
        BuildConfig::Standard {
            sapling_anchor: anchor,
            orchard_anchor: None,
        },
    );
    let mut in_total: i64 = 0;
    for s in &r.spends {
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
        // the note must be this account's in the scope the façade says
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
        let cmu = sapling_crypto::Node::from_cmu(&note.cmu());
        if Some(Anchor::from(path.root(cmu))) != anchor {
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
        builder
            .add_sapling_spend::<std::convert::Infallible>(fvk, note, path)
            .map_err(|e| (refuse::FAILED, format!("sapling spend: {e}")))?;
        in_total += s.value as i64;
    }
    // the transparent inputs: wallet P2PKH coins, each key checked against its script
    let mut signing = TransparentSigningSet::new();
    for i in &r.inputs {
        let script = hex::decode(&i.prevout.script)
            .map_err(|_| (refuse::MALFORMED, "input script".to_string()))?;
        let KeyRef::Bip32 { chain, index } = i.key else {
            return no(
                refuse::KEY_MISMATCH,
                "a transparent input needs a BIP32 key",
            );
        };
        let (sk, pk) = transparent(chain, index)?;
        if yew_core::script::p2pkh_hash(&script) != Some(yew_core::keys::hash160(&pk)) {
            return no(refuse::KEY_MISMATCH, "an input key does not own its coin");
        }
        let sk29 = secp256k1_029::SecretKey::from_slice(&sk.to_secret_bytes())
            .map_err(|_| (refuse::FAILED, "a secret key".to_string()))?;
        let pk29 = signing.add_key(sk29);
        let op = yewd_proto::act::OutPoint::parse(&i.prevout.outpoint).ok_or_else(|| {
            (
                refuse::UNBOUND_INPUT,
                format!("{} is not txid:n", i.prevout.outpoint),
            )
        })?;
        let coin = zcash_transparent::bundle::TxOut::new(
            zat(i.prevout.amount_zat, "input amount")?,
            script_of(&script)?,
        );
        builder
            .add_transparent_p2pkh_input(
                pk29,
                zcash_transparent::bundle::OutPoint::new(op.txid, op.n),
                coin,
            )
            .map_err(|e| (refuse::FAILED, format!("transparent input: {e}")))?;
        in_total += i.prevout.amount_zat;
    }
    // the outputs
    let ovk_ext: OutgoingViewingKey = dfvk.to_ovk(Scope::External);
    let ovk_int: OutgoingViewingKey = dfvk.to_ovk(Scope::Internal);
    let mut own_total: i64 = 0;
    let mut out_total: i64 = 0;
    let hrp = network.sapling_address_hrp();
    for o in &r.outputs {
        match o {
            SaplingOut::Transparent { script, value, own } => {
                let s = hex::decode(script)
                    .map_err(|_| (refuse::MALFORMED, "output script".to_string()))?;
                let to = taddr_of(&s).ok_or_else(|| {
                    (
                        refuse::MALFORMED,
                        "an output script is not P2PKH or P2SH".to_string(),
                    )
                })?;
                builder
                    .add_transparent_output(&to, zat(*value, "output")?)
                    .map_err(|e| (refuse::FAILED, format!("transparent output: {e}")))?;
                if *own {
                    own_total += value;
                }
                out_total += value;
            }
            SaplingOut::Shielded {
                address,
                value,
                memo,
                own,
            } => {
                let to = zcash_keys::encoding::decode_payment_address(hrp, address)
                    .map_err(|e| (refuse::MALFORMED, format!("{address}: {e}")))?;
                let memo = if memo.is_empty() {
                    MemoBytes::empty()
                } else {
                    let b =
                        hex::decode(memo).map_err(|_| (refuse::MALFORMED, "memo".to_string()))?;
                    MemoBytes::from_bytes(&b)
                        .map_err(|_| (refuse::MALFORMED, "memo too long".to_string()))?
                };
                builder
                    .add_sapling_output::<std::convert::Infallible>(
                        Some(ovk_ext),
                        to,
                        zat(*value, "output")?,
                        memo,
                    )
                    .map_err(|e| (refuse::FAILED, format!("sapling output: {e}")))?;
                if *own {
                    own_total += value;
                }
                out_total += value;
            }
            SaplingOut::Change { value } => {
                let (_, to) = dfvk.change_address();
                builder
                    .add_sapling_output::<std::convert::Infallible>(
                        Some(ovk_int),
                        to,
                        zat(*value, "change")?,
                        MemoBytes::empty(),
                    )
                    .map_err(|e| (refuse::FAILED, format!("sapling change: {e}")))?;
                own_total += value;
                out_total += value;
            }
        }
    }
    if in_total - out_total != r.fee_zat {
        return no(
            refuse::PREVIEW_MISMATCH,
            format!(
                "inputs {in_total} minus outputs {out_total} is not the fee {}",
                r.fee_zat
            ),
        );
    }
    if in_total - own_total > r.outflow_cap_zat {
        return no(
            refuse::OUTFLOW,
            format!(
                "outflow: {} leaves the wallet, the cap is {}",
                in_total - own_total,
                r.outflow_cap_zat
            ),
        );
    }
    let dir = std::path::Path::new(&r.params_dir);
    yew_core::sapling_params::ensure_verified(dir)
        .map_err(|e| (refuse::FAILED, format!("the Sapling parameters: {e}")))?;
    let prover = zcash_proofs::prover::LocalTxProver::new(
        &dir.join(yew_core::sapling_params::SPEND.name),
        &dir.join(yew_core::sapling_params::OUTPUT.name),
    );
    let built = builder
        .build(
            &signing,
            &[extsk, internal_extsk],
            &[],
            OsRng,
            &prover,
            &prover,
            &FeeRule::non_standard(zat(r.fee_zat, "fee")?),
        )
        .map_err(|e| (refuse::FAILED, format!("the Sapling build: {e}")))?;
    let mut out = Vec::new();
    built
        .transaction()
        .write(&mut out)
        .map_err(|e| (refuse::FAILED, e.to_string()))?;
    Ok(hex::encode(out))
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
pub(crate) struct Hybrid {
    data: zcash_primitives::transaction::TransactionData<HybridAuth>,
    asks: Vec<sapling_crypto::keys::SpendAuthorizingKey>,
}

impl Hybrid {
    /// The ZIP-243 digest of input `index` over `script_code` and `amount`, `SIGHASH_ALL` or
    /// `SIGHASH_ALL|ANYONECANPAY`.
    pub(crate) fn digest(
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
    /// Sapling part authorized over the shielded digest.
    pub(crate) fn finish(self, signed: &yew_core::tx::Transaction) -> Result<Vec<u8>, Refused> {
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
            .apply_signatures(OsRng, sighash, &self.asks)
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
/// YEW-PORT-5 R2: a free function; the spending key and the network are parameters).
pub(crate) fn sapling_prepare(
    extsk: ExtendedSpendingKey,
    network: Network,
    part: &yewd_proto::SaplingPart,
    tx: &yew_core::tx::Transaction,
    branch_id: u32,
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
                OsRng,
            )
            .map_err(|e| (refuse::FAILED, format!("the Sapling bundle: {e:?}")))?
            .ok_or_else(|| (refuse::MALFORMED, "an empty Sapling part".to_string()))?;
    let proven: ProvenBundle = unproven.create_proofs(&prover, &prover, OsRng, ());
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

/// A spend's note, path and full viewing key, checked as [`SignerCore::sapling_build`] does.
fn spend_parts(
    dfvk: &sapling_crypto::zip32::DiversifiableFullViewingKey,
    s: &yewd_proto::SaplingSpend,
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
