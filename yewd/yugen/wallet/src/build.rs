// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The transfer builder. Adapts `yugen-ref` `wallet.rs` `Wallet::build` (spec 0.5.1, d25a89c),
//! changed in one place: the caller sets the auxiliary flags, so that a leaf-route transfer
//! carries `FLAG_LEAFFEE` (spec §7.1, §7.9, SPEC-81), which the reference builder leaves clear.
//! With `aux_flags = 0` the output equals the reference's (test `builder_equals_reference`).

#![allow(clippy::all)]
use yugen_ref::falcon::{self, FalconSigner, Sig};
use yugen_ref::keys::AddrId;
use yugen_ref::note::{self, Note};
use yugen_ref::package::{self, Plain};
use yugen_ref::params::*;
use yugen_ref::registry::{exit_tag, NonMember};
use yugen_ref::statement::{OutputWitness, Public, SpendWitness, Witness};
use yugen_ref::transfer::{self, Transfer, TxContext, OREC_NOT_OWN};
use yugen_ref::wallet::{BuildParams, Built, Output, Spend, Wallet};

pub trait BuildExt {
    fn build_flags(&self, signer: &mut dyn FalconSigner, spends: &[Spend; 2], outputs: &[Output; 2], bp: &BuildParams, aux_flags: u16) -> Built;
}

impl BuildExt for Wallet {
    fn build_flags(&self, signer: &mut dyn FalconSigner, spends: &[Spend; 2], outputs: &[Output; 2], bp: &BuildParams, aux_flags: u16) -> Built {
        let network = self.keys.network;
        let zero_path = [[[0u8; 48]; 3]; TREE_DEPTH];
        let mut nf = [[0u8; 32]; 2];
        let mut sw = Vec::new();
        for (i, s) in spends.iter().enumerate() {
            match s {
                Spend::Dummy { c } => {
                    let dx = note::dummy_preimage(&self.keys.rsk, &self.keys.nk, bp.anchor_height, *c);
                    nf[i] = note::nullifier_dummy(&dx);
                    sw.push(SpendWitness {
                        is_dummy: 1,
                        dx,
                        v: 0,
                        nk_d: [0; 32],
                        rho: [0; 48],
                        rcm: [0; 32],
                        pos: 0,
                        path: zero_path,
                        path_b: None,
                        salt: [0; 32],
                        rkh: [0; 32],
                        rk: [0; 32],
                        reg: NonMember::zero(),
                    });
                }
                Spend::Note { d, note: n, pos, path } => {
                    let a = self.address_keys(*d);
                    nf[i] = note::nullifier(&a.nk_d, &n.rho, &n.cm());
                    let recovery = bp.auth_mode == 1;
                    sw.push(SpendWitness {
                        is_dummy: 0,
                        dx: [0; 32],
                        v: n.v as u128,
                        nk_d: a.nk_d,
                        rho: n.rho,
                        rcm: n.rcm,
                        pos: *pos,
                        path: **path,
                        path_b: None,
                        salt: a.salt_d,
                        rkh: a.rkh_d,
                        rk: if recovery { a.rk_d } else { [0u8; 32] },
                        reg: if recovery {
                            bp.registry.non_member(&exit_tag(&a.nkc_d, &a.rk_d)).unwrap_or_else(NonMember::zero)
                        } else {
                            NonMember::zero()
                        },
                    });
                }
            }
        }
        let epoch = transfer::otag_epoch(bp.anchor_height);
        let mut cm = [[0u8; 48]; 2];
        let mut otag = [[0u8; 8]; 2];
        let mut orec = [[0u8; 12]; 2];
        let mut itag = [[0u8; 6]; 2];
        let mut iamt = [[0u8; 8]; 2];
        let mut pkg: [Option<Vec<u8>>; 2] = [None, None];
        let mut ow = Vec::new();
        let mut notes = Vec::new();
        for (idx, o) in outputs.iter().enumerate() {
            let j = idx as u8 + 1;
            let rho = note::rho_out(&nf[0], j);
            let (fi, fa) = transfer::incoming_fill(&self.keys.rsk, &nf[0], j);
            itag[idx] = fi;
            iamt[idx] = fa;
            let (n, info) = match o {
                Output::Request { req, v } => {
                    assert!(req.payable(bp.anchor_height) && req.network == network, "request refused (§9.2)");
                    let (n, t, a) = req.pay(&nf[0], j, *v);
                    itag[idx] = t;
                    iamt[idx] = a;
                    (n, OREC_NOT_OWN)
                }
                Output::Static { addr, v, memo } => {
                    let rid = note::rid(&addr.auth, &addr.nkc);
                    let rseed = note::rseed(&self.keys.rsk, &nf[0], j, *v, &rid, &note::memo_hash(memo));
                    let n = Note { asset: ASSET_YEC, v: *v, auth: addr.auth, nkc: addr.nkc, rho, rcm: note::rcm_static(&rseed) };
                    let plain = Plain { v: *v, rho, rseed, memo: memo.clone() };
                    let sealed = package::seal(&self.keys.rsk, &addr.ek, &n.cm(), j, bp.branch_id, network, &plain).expect("valid encapsulation key");
                    let bucket = yugen_ref::address::pkg_bucket(&addr.ek, bp.anchor_height / MAILBOX_EPOCH_BLOCKS);
                    pkg[idx] = Some([&bucket.to_le_bytes()[..], &sealed].concat());
                    (n, OREC_NOT_OWN)
                }
                Output::Change { n: idx_n, v } => {
                    let d = AddrId::internal(*idx_n);
                    let (auth, nkc) = (self.auth(d), self.address_keys(d).nkc_d);
                    let rseed = note::rseed(&self.keys.rsk, &nf[0], j, *v, &note::rid(&auth, &nkc), &note::memo_hash(&[]));
                    (Note { asset: ASSET_YEC, v: *v, auth, nkc, rho, rcm: note::rcm_static(&rseed) }, *idx_n)
                }
            };
            cm[idx] = n.cm();
            otag[idx] = transfer::otag(&self.keys.ovk_view, epoch, bp.otag_counter[idx]);
            orec[idx] = transfer::orec_xor(&self.keys.ovk_view, &cm[idx], &transfer::orec_plain(n.v, info));
            ow.push(OutputWitness { v: n.v as u128, auth: n.auth, nkc: n.nkc, rcm: n.rcm });
            notes.push(n);
        }
        let t = Transfer {
            fee_class: bp.fee_class,
            anchor_slot: transfer::anchor_slot(bp.anchor_height),
            nf,
            cm,
            otag,
            orec,
            itag,
            iamt,
            value_balance: bp.value_balance,
            pkg,
            canary: false,
            aux_flags,
        };
        let ctx = TxContext {
            branch_id: bp.branch_id,
            network,
            anchor_height: bp.anchor_height,
            anchor_root: bp.anchor_root,
            anchor_block_hash: bp.anchor_block_hash,
            vout: bp.vout.clone(),
        };
        let th = transfer::transfer_hash(&t, &ctx);
        let digest = falcon::sig_digest(&th);
        let sig = if bp.auth_mode == 0 {
            falcon::sig_decode(&signer.sign_digest(&digest)).expect("signer output")
        } else {
            Sig { nonce: [0u8; FALCON_NONCE_LEN], s2: vec![0i16; FALCON_N] }
        };
        let (vb_in, vb_out) = t.vb_split();
        let public = Public {
            anchor_root: bp.anchor_root,
            nf,
            cm,
            fee: t.fee(),
            vb_in,
            vb_out,
            sig_digest: digest,
            auth_mode: bp.auth_mode,
            reg_root: bp.registry.root(),
        };
        let witness = Witness {
            spends: [sw[0].clone(), sw[1].clone()],
            outputs: [ow[0].clone(), ow[1].clone()],
            pk_h: falcon::pk_decode_raw(&self.pk).expect("897-byte public key"),
            sig,
        };
        Built { transfer: t, ctx, transfer_hash: th, public, witness, out_notes: [notes[0].clone(), notes[1].clone()] }
    }
}
