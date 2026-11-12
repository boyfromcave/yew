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
use sapling_crypto::{Anchor, MerklePath, Node, Note, PaymentAddress};
use yewd_proto::{refuse, KeyRef, SaplingBuildRequest, SaplingOut};
use zcash_primitives::transaction::builder::{BuildConfig, Builder};
use zcash_primitives::transaction::fees::fixed::FeeRule;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::memo::MemoBytes;
use zcash_transparent::builder::TransparentSigningSet;
use zip32::Scope;

use crate::sign::{no, Refused, SignerCore};
// review YEW-PORT-5 R3: the hybrid builder and its helpers moved to yew-core (a pure move)
use yew_core::build::hybrid::{
    hex32, owns_in_scope, rseed_of, sapling_extsk, sapling_prepare, script_of, taddr_of, zat,
    Hybrid,
};
use yew_core::params::Network;

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
        sapling_prepare(
            self.sapling_extsk()?,
            self.network,
            part,
            tx,
            branch_id,
            OsRng,
        )
    }
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
        // before ZIP-212 (a note from before Canopy) the façade hands in its `rcm`
        let note = Note::from_parts(addr, NoteValue::from_raw(s.value), rseed_of(s)?);
        // the note must be this account's in the scope the façade says
        let scope = if s.internal {
            Scope::Internal
        } else {
            Scope::External
        };
        if !owns_in_scope(&dfvk, &addr, scope) {
            return no(refuse::KEY_MISMATCH, "a spent note is not this account's");
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

#[cfg(test)]
mod tests {
    use super::*;
    use incrementalmerkletree::{Hashable, Level};
    use sapling_crypto::Rseed;
    use yewd_proto::SaplingSpend;

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn params_dir() -> String {
        if let Ok(d) = std::env::var("YEW_SAPLING_PARAMS") {
            return d;
        }
        let home = std::env::var("HOME").unwrap_or_default();
        if cfg!(target_os = "macos") {
            format!("{home}/Library/Application Support/ZcashParams")
        } else {
            format!("{home}/.zcash-params")
        }
    }

    /// One note of `value` to `addr` at position 0 of an otherwise empty tree: its spend (the
    /// path of empty subtrees) and the anchor that path leads to.
    fn lone_spend(
        addr: &PaymentAddress,
        value: u64,
        rseed: Rseed,
        internal: bool,
    ) -> (SaplingSpend, String) {
        let note = Note::from_parts(*addr, NoteValue::from_raw(value), rseed);
        let mut cur = Node::from_cmu(&note.cmu());
        let mut path = Vec::with_capacity(32);
        for i in 0..32u8 {
            let sib = Node::empty_root(Level::from(i));
            path.push(hex::encode(sib.to_bytes()));
            cur = Node::combine(Level::from(i), &cur, &sib);
        }
        let (rseed, after_zip212) = match note.rseed() {
            Rseed::AfterZip212(r) => (hex::encode(r), true),
            Rseed::BeforeZip212(r) => (hex::encode(r.to_bytes()), false),
        };
        (
            SaplingSpend {
                recipient: hex::encode(addr.to_bytes()),
                value,
                rseed,
                after_zip212,
                internal,
                position: 0,
                path,
            },
            hex::encode(cur.to_bytes()),
        )
    }

    /// Spend the lone note back to the account's change address, paying `fee`.
    fn build_lone(
        extsk: &ExtendedSpendingKey,
        spend: SaplingSpend,
        anchor: String,
    ) -> Result<String, Refused> {
        let fee = 1_000;
        let r = SaplingBuildRequest {
            target_height: 200,
            expiry_height: 240,
            vault_height: Some(1),
            inputs: Vec::new(),
            outputs: vec![SaplingOut::Change {
                value: spend.value as i64 - fee,
            }],
            spends: vec![spend],
            fee_zat: fee,
            anchor,
            outflow_cap_zat: fee,
            params_dir: params_dir(),
        };
        sapling_build(extsk.clone(), Network::Regtest, &r, |_, _| {
            no(refuse::KEY_MISMATCH, "no transparent input here")
        })
    }

    /// Real-stack run YEW-REAL finding 1: a note from before Canopy (pre-ZIP-212: its `rcm`, a
    /// Jubjub scalar, in place of an `rseed`) is spent, external or change; it used to be refused
    /// ("a pre-ZIP-212 note is not spent by this signer"). A `rcm` that is not a scalar is not.
    #[test]
    fn a_pre_zip212_note_is_spent() {
        let extsk = sapling_extsk(PHRASE, Network::Regtest).unwrap();
        let dfvk = extsk.to_diversifiable_full_viewing_key();
        // the façade's encoding of a pre-ZIP-212 note (yewd/wallet zsend.rs): rcm's bytes
        let mut b = [0u8; 32];
        b[0] = 0x2a;
        let probe = SaplingSpend {
            recipient: String::new(),
            value: 0,
            rseed: hex::encode(b),
            after_zip212: false,
            internal: false,
            position: 0,
            path: Vec::new(),
        };
        let rcm = rseed_of(&probe).unwrap();
        assert!(matches!(rcm, Rseed::BeforeZip212(_)));
        for (addr, internal) in [
            (dfvk.default_address().1, false),
            (dfvk.change_address().1, true),
        ] {
            let (s, a) = lone_spend(&addr, 600_000, rcm, internal);
            assert!(!s.after_zip212);
            build_lone(&extsk, s, a).expect("a pre-ZIP-212 note spends");
        }
        let (mut s, a) = lone_spend(&dfvk.default_address().1, 600_000, rcm, false);
        s.rseed = hex::encode([0xff; 32]);
        assert_eq!(build_lone(&extsk, s, a).unwrap_err().0, refuse::MALFORMED);
    }

    /// Real-stack run YEW-REAL finding 0: a note received on the internal (change) scope is
    /// this account's and is spent; it used to be refused as "not this account's" (sapling-crypto
    /// 0.7.0's `decrypt_diversifier` never answers the internal scope). The check itself stands:
    /// a note's scope must be the one the façade names, and another account's note is refused.
    #[test]
    fn a_change_note_is_spent_in_its_own_scope_only() {
        let extsk = sapling_extsk(PHRASE, Network::Regtest).unwrap();
        let dfvk = extsk.to_diversifiable_full_viewing_key();
        let (_, change) = dfvk.change_address();
        let (_, ext) = dfvk.default_address();
        let rs = || Rseed::AfterZip212([7; 32]);
        let (s, a) = lone_spend(&change, 500_000, rs(), true);
        build_lone(&extsk, s, a).expect("the change note spends");
        let (s, a) = lone_spend(&ext, 500_000, rs(), false);
        build_lone(&extsk, s, a).expect("an external note spends");
        // the wrong scope, either way
        for (addr, internal) in [(&change, false), (&ext, true)] {
            let (s, a) = lone_spend(addr, 500_000, rs(), internal);
            let e = build_lone(&extsk, s, a).unwrap_err();
            assert_eq!(e.0, refuse::KEY_MISMATCH, "{e:?}");
        }
        // another account's notes, in either scope
        let other = sapling_extsk(
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
            Network::Regtest,
        )
        .unwrap()
        .to_diversifiable_full_viewing_key();
        for (addr, internal) in [
            (other.change_address().1, true),
            (other.default_address().1, false),
        ] {
            let (s, a) = lone_spend(&addr, 500_000, rs(), internal);
            let e = build_lone(&extsk, s, a).unwrap_err();
            assert_eq!(e.0, refuse::KEY_MISMATCH, "{e:?}");
        }
    }
}
