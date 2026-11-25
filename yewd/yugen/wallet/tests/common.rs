// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! A leaf transfer from a payer note to a payee request, built as the wallet builds it.
#![allow(dead_code)]
use yewd_yugen::account::Account;
use yewd_yugen::build::BuildExt;
use yugen_ref::keys::AddrId;
use yugen_ref::registry::Registry;
use yugen_ref::tree::Tree;
use yugen_ref::wallet::{BuildParams, Built, Output, Spend};

pub const NOTE_V: u64 = 5_000_000;
pub const PAY_V: u64 = 1_000_000;
/// The commitment at position 0 before the payer's note.
pub const PRE_CM: [u8; 48] = [1; 48];

pub fn leaf_transfer() -> (Account, Account, Tree, Built) {
    let mut payer = Account::from_seed(&[7u8; 32], 2).unwrap();
    let payee = Account::from_seed(&[9u8; 32], 2).unwrap();
    let d = AddrId::internal(0);
    let note = yugen_ref::note::Note { asset: 0, v: NOTE_V, auth: payer.wallet.auth(d), nkc: payer.wallet.address_keys(d).nkc_d, rho: [3; 48], rcm: [4; 32] };
    let mut tree = Tree::new();
    tree.append(&PRE_CM);
    let pos = tree.append(&note.cm());
    let fee = yugen_ref::params::BASE_FEE + yugen_ref::params::LEAF_PROOF_FEE;
    let spends = [Spend::Note { d, note, pos, path: Box::new(tree.path(pos)) }, Spend::Dummy { c: 0 }];
    let outputs = [Output::Request { req: payee.request(0, 0), v: PAY_V }, Output::Change { n: 1, v: NOTE_V - PAY_V - fee }];
    let bp = BuildParams {
        branch_id: yugen_ref::params::BRANCH_ID,
        fee_class: 0,
        anchor_height: 208,
        anchor_root: tree.root(),
        anchor_block_hash: [5; 32],
        value_balance: 0,
        vout: vec![],
        otag_counter: [0, 1],
        auth_mode: 0,
        registry: Registry::default(),
    };
    let built = payer.wallet.build_flags(&mut payer.signer, &spends, &outputs, &bp, yugen_ref::transfer::FLAG_LEAFFEE);
    (payer, payee, tree, built)
}
