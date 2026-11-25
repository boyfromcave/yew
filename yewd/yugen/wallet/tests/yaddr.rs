// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! UX-1 the Yugen address: vectors from yugen-spec branch `ux-address` 104cc0b
//! (`vectors/yugen_address.json`, copied to tests/data), round trips, refusals, the choice rule.

use serde_json::Value;
use yewd_yugen::yaddr::{bech32m_decode, bech32m_encode, choose, looks_like, Choice, Static, YugenAddress};

fn doc() -> Value {
    serde_json::from_str(&std::fs::read_to_string(format!("{}/tests/data/yugen_address.json", env!("CARGO_MANIFEST_DIR"))).unwrap()).unwrap()
}

#[test]
fn vectors_round_trip() {
    let d = doc();
    let (mut ok, mut refused) = (0, 0);
    for v in d["vectors"].as_array().unwrap() {
        let s = v["string"].as_str().unwrap();
        let net = v["network"].as_u64().unwrap() as u8;
        assert!(looks_like(s));
        let r = YugenAddress::decode(s, net);
        if !v["accepted_at_launch"].as_bool().unwrap() {
            assert!(r.is_err(), "{} {}: scheme 0x02 must be refused at launch", v["source"], v["kind"]);
            refused += 1;
            continue;
        }
        let a = r.unwrap_or_else(|e| panic!("{} {}: {e}", v["source"], v["kind"]));
        assert_eq!(a.encode(), s, "re-encode");
        assert_eq!(YugenAddress::decode(&s.to_uppercase(), net).unwrap(), a, "upper case");
        assert_eq!(a.request.as_ref().map(|r| hex::encode(r.to_bytes())), v["request"].as_str().map(String::from));
        let st = hex::decode(v["static"].as_str().unwrap()).unwrap();
        match &a.stat {
            Static::Full(f) => assert_eq!(f.to_bytes(), st),
            Static::Short(fl, sh) => assert_eq!([&[0, *fl][..], &sh[..]].concat(), st),
        }
        assert!(YugenAddress::decode(s, (net + 1) % 3).is_err(), "other network");
        ok += 1;
    }
    assert_eq!(ok + refused, d["vectors"].as_array().unwrap().len());
    assert!(ok >= 40);
}

#[test]
fn refusals() {
    let d = doc();
    for f in d["refusals"].as_array().unwrap() {
        let r = YugenAddress::decode(f["string"].as_str().unwrap(), f["network"].as_u64().unwrap() as u8);
        assert!(r.is_err(), "{} accepted", f["what"]);
    }
    let s = d["vectors"][1]["string"].as_str().unwrap();
    let mixed = format!("{}{}", &s[..10].to_uppercase(), &s[10..]);
    assert!(YugenAddress::decode(&mixed, 0).is_err(), "mixed case");
    assert!(!looks_like("yugreq1sqqqq"));
    assert!(yewd_yugen::yaddr::is_legacy("yugreq1sqqqq") && yewd_yugen::yaddr::is_legacy("YUG1qqq"));
    assert!(!looks_like("rgf1qqqq") && looks_like("yqrf1qqqq") && looks_like("yqf1q"));
}

#[test]
fn choice_rule() {
    let d = doc();
    for c in d["choice"].as_array().unwrap() {
        let a = YugenAddress::decode(c["string"].as_str().unwrap(), c["network"].as_u64().unwrap() as u8).unwrap();
        let pb = c["paid_before"].as_bool().unwrap();
        let got = choose(&a, c["memo"].as_bool().unwrap(), c["anchor_height"].as_u64().unwrap() as u32, |_| pb).unwrap();
        let want = c["choice"].as_str().unwrap();
        assert_eq!(matches!(got, Choice::Request(_)), want == "request", "{c}");
    }
    // a short-only address cannot be paid at M1 (no record host)
    let short = d["vectors"].as_array().unwrap().iter().find(|v| v["kind"] == "short" && v["accepted_at_launch"] == true).unwrap();
    let a = YugenAddress::decode(short["string"].as_str().unwrap(), short["network"].as_u64().unwrap() as u8).unwrap();
    assert!(choose(&a, false, 0, |_| false).is_err());
}

#[test]
fn bech32m_bip350() {
    // BIP 350 valid Bech32m test strings
    for s in ["a1lqfn3a", "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx", "?1v759aa"] {
        let (h, d) = bech32m_decode(s).unwrap_or_else(|| panic!("{s}"));
        assert_eq!(bech32m_encode(&h, &d), s.to_lowercase());
    }
    assert!(bech32m_decode("a12uel5l").is_none(), "Bech32 (not m) checksum");
}

#[test]
fn wallet_address_and_choice() {
    use yewd_yugen::account::Account;
    let acct = Account::from_seed(&[9u8; 32], 2).unwrap();
    let req = acct.request(2000, 0);
    let a = YugenAddress { network: 2, stat: Static::Full(acct.static_address(0)), request: Some(req.clone()) };
    let s = a.encode();
    assert!(s.starts_with("yqrf1"), "{}", &s[..8]);
    let b = YugenAddress::decode(&s, 2).unwrap();
    assert_eq!(b, a);
    assert!(YugenAddress::decode(&s, 0).is_err());
    let anchor = 2000 * 1152 + 10;
    assert!(matches!(choose(&b, false, anchor, |_| false).unwrap(), Choice::Request(r) if r == req));
    assert!(matches!(choose(&b, true, anchor, |_| false).unwrap(), Choice::Static(_)), "memo -> static");
    assert!(matches!(choose(&b, false, anchor, |r| r.k == req.k).unwrap(), Choice::Static(_)), "paid once -> static");
    assert!(matches!(choose(&b, false, 2007 * 1152, |_| false).unwrap(), Choice::Static(_)), "expired -> static");
    let reusable = YugenAddress { request: None, ..a };
    assert!(matches!(choose(&YugenAddress::decode(&reusable.encode(), 2).unwrap(), false, anchor, |_| false).unwrap(), Choice::Static(_)));
}
