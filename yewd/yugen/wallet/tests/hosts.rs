// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The host-pair client pieces that need no running host: the DPF copy, the pair rule, the
//! deletion token, the short address of a hosted static address.

use yewd_yugen::account::Account;
use yewd_yugen::dpf;
use yewd_yugen::hosts::Pair;
use yewd_yugen::yaddr::{Static, YugenAddress};

#[test]
fn dpf_shares_xor_to_the_point() {
    let (a, b) = dpf::gen_random(37, 24);
    let (x, y) = (a.eval_prefix(64), b.eval_prefix(64));
    for i in 0..64 {
        assert_eq!(x[i] ^ y[i], (i == 37) as u8);
    }
}

#[test]
fn pair_and_short_address() {
    assert!(Pair::new("127.0.0.1:1").is_err(), "one host is not a pair");
    let p = Pair::new("127.0.0.1:1,127.0.0.1:2").unwrap();
    assert_eq!(Pair::del_token(&[1u8; 32]), Pair::del_token(&[1u8; 32]));
    assert_ne!(Pair::del_token(&[1u8; 32]), Pair::del_token(&[2u8; 32]));
    let acct = Account::from_seed(&[9u8; 32], 2).unwrap();
    let a = acct.static_address_hosts(0, &p.names);
    assert_eq!(a.hosts.len(), 2);
    assert_ne!(a.short(), acct.static_address(0).short(), "the short address commits to the hosts");
    let s = YugenAddress { network: 2, stat: Static::Short(a.flags, a.short()), request: None }.encode();
    assert!(s.starts_with("yqrf1") && s.len() == 67, "{s}");
    let m = YugenAddress { network: 0, stat: Static::Short(a.flags, a.short()), request: None }.encode();
    assert_eq!(m.len(), 66, "mainnet short form: 66 characters");
}
