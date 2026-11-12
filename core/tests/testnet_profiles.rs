// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The testnet profiles (`-testnetprofile=fast|slow|legacy`) against the node.
//!
//! `vectors/testnet_profiles.json` is generated from ycash6's `src/chainparams.cpp`,
//! `src/consensus/upgrades.{cpp,h}` and `src/yellowback/params.cpp` at the commit it records
//! (`scripts/gen-testnet-profiles.py`; `scripts/check-testnet-profiles.sh` regenerates it in CI and
//! compares). This test pins YEW's compiled-in tables (`params::MAINNET_UPGRADES`,
//! `params::TESTNET_FAST_UPGRADES`, the YED lifecycle column) to it, and checks what a spend built
//! for testnet-yb-fast commits to at 510,300 (Canopy), 510,400 (the Vault activation block) and
//! 510,421 (the fast network's tip on 2026-11-12).

use serde_json::Value;
use yew_core::params::{
    self, signing_branch_id, BranchError, Network, TestnetProfile, Upgrade, MAINNET_UPGRADES,
    SAPLING_VERSION_GROUP_ID, TESTNET_FAST_UPGRADES, VAULT_BRANCH_ID,
};
use yew_core::tx::{OutPoint, Transaction, TxIn, TxOut};

const FIXTURE: &str = include_str!("vectors/testnet_profiles.json");

const HEARTWOOD: u32 = 0x6631_4da3;
const CANOPY: u32 = 0x19bd_2d2f;
const YCASH: u32 = 0x374d_694f;

fn fixture() -> Value {
    serde_json::from_str(FIXTURE).unwrap()
}

fn node_upgrades(net: &str) -> Vec<(String, u32, Option<u64>)> {
    fixture()["networks"][net]["upgrades"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| {
            (
                u["name"].as_str().unwrap().to_string(),
                u32::from_str_radix(u["branch_id"].as_str().unwrap(), 16).unwrap(),
                u["height"].as_u64(),
            )
        })
        .collect()
}

/// Every upgrade of YEW's table is the node's, and every node upgrade YEW's table leaves out is
/// one the node does not schedule on that network.
fn assert_table(net: &str, ours: &[Upgrade]) {
    let node = node_upgrades(net);
    for u in ours {
        let n = node
            .iter()
            .find(|(name, _, _)| name == u.name)
            .unwrap_or_else(|| panic!("{net}: {} not in the fixture", u.name));
        assert_eq!((n.1, n.2), (u.branch_id, u.height), "{net}: {}", u.name);
    }
    for (name, _, h) in &node {
        if !ours.iter().any(|u| u.name == name) {
            assert_eq!(
                *h, None,
                "{net}: the node schedules {name}, YEW's table lacks it"
            );
        }
    }
}

#[test]
fn the_fixture_names_its_source() {
    let f = fixture();
    assert_eq!(f["source"]["repo"], "boyfromcave/ycash6");
    let c = f["source"]["commit"].as_str().unwrap();
    assert!(
        c.len() == 40 && c.bytes().all(|b| b.is_ascii_hexdigit()),
        "{c}"
    );
}

#[test]
fn mainnet_and_fast_tables_are_the_nodes() {
    assert_table("main", &MAINNET_UPGRADES);
    assert_table("test-fast", &TESTNET_FAST_UPGRADES);
    assert_eq!(Network::Mainnet.upgrades(), Some(&MAINNET_UPGRADES));
    assert_eq!(Network::Testnet.upgrades(), Some(&TESTNET_FAST_UPGRADES));
    assert_eq!(Network::Regtest.upgrades(), None);
    // mainnet's Vault stays unscheduled (P8); fast's is 510,400
    assert_eq!(Network::Mainnet.vault_activation_height(), None);
    assert_eq!(Network::Regtest.vault_activation_height(), None);
    assert_eq!(Network::Testnet.vault_activation_height(), Some(510_400));
}

#[test]
fn the_yed_lifecycle_columns_are_the_nodes() {
    for (net, n) in [("main", Network::Mainnet), ("test-fast", Network::Testnet)] {
        let y = &fixture()["networks"][net]["yed"];
        assert_eq!(y["grace"].as_u64(), Some(n.grace() as u64), "{net} grace");
        assert_eq!(
            y["claimDelay"].as_i64(),
            Some(n.claim_delay()),
            "{net} claimDelay"
        );
        for (c, ours) in y["classes"]
            .as_array()
            .unwrap()
            .iter()
            .zip(n.term_classes())
        {
            assert_eq!(
                c["classMin"].as_u64(),
                Some(ours.min_blocks as u64),
                "{net}"
            );
            assert_eq!(
                c["classMax"].as_u64(),
                Some(ours.max_blocks as u64),
                "{net}"
            );
            assert_eq!(
                c["baseRatioBps"].as_i64(),
                Some(ours.base_ratio_bps),
                "{net}"
            );
            assert_eq!(
                c["earlyRedeemFeeBps"].as_i64(),
                Some(ours.early_redeem_fee_bps),
                "{net}"
            );
        }
    }
    // fast's day is ⌈103 / 30⌉ blocks; mainnet's stays 1,152
    assert_eq!(Network::Testnet.day_blocks(), 4);
    assert_eq!(Network::Mainnet.day_blocks(), 1_152);
}

/// slow and legacy are shadow forks of mainnet under their own branch ids, for which librustzcash6
/// has no consensus parameters: YEW refuses the profiles and never accepts those ids from a server.
#[test]
fn slow_and_legacy_are_refused() {
    let shadow = |net: &str| {
        node_upgrades(net)
            .into_iter()
            .find(|(n, _, _)| n == "shadow")
            .unwrap()
    };
    assert_eq!(shadow("test-slow").1, params::SLOW_SHADOW_BRANCH_ID);
    assert_eq!(shadow("test-legacy").1, params::LEGACY_SHADOW_BRANCH_ID);
    let slow_vault = node_upgrades("test-slow")
        .into_iter()
        .find(|(n, _, _)| n == "vault")
        .unwrap();
    assert_eq!(slow_vault.1, params::SLOW_VAULT_BRANCH_ID);
    for id in [
        params::SLOW_SHADOW_BRANCH_ID,
        params::SLOW_VAULT_BRANCH_ID,
        params::LEGACY_SHADOW_BRANCH_ID,
    ] {
        for n in [Network::Mainnet, Network::Testnet, Network::Regtest] {
            assert!(!n.branch_ids().contains(&id), "{n:?} accepts {id:08x}");
        }
    }
    assert_eq!(TestnetProfile::Fast.network(), Ok(Network::Testnet));
    for p in [TestnetProfile::Slow, TestnetProfile::Legacy] {
        let e = p.network().unwrap_err();
        assert!(e.contains("not supported") && e.contains(p.name()), "{e}");
    }
    assert_eq!(
        TestnetProfile::from_name("fast"),
        Some(TestnetProfile::Fast)
    );
    assert_eq!(TestnetProfile::from_name("testnet3"), None);
    assert_eq!(
        Network::from_name("testnet-yb-fast"),
        Some(Network::Testnet)
    );
    assert_eq!(Network::from_name("testnet-yb-slow"), None);
    assert_eq!(
        Network::Testnet.testnet_profile(),
        Some(TestnetProfile::Fast)
    );
    assert_eq!(TestnetProfile::Fast.datadir(), "testnet-yb-fast");
    assert_eq!(TestnetProfile::Fast.rpc_port(), 18832);
}

/// The branch id of a block at each height, by YEW's table, at fast's boundaries.
#[test]
fn fast_branch_ids_by_height() {
    let t = Network::Testnet;
    assert_eq!(t.branch_id_at(510_253), Some(HEARTWOOD));
    assert_eq!(t.branch_id_at(510_254), Some(CANOPY));
    assert_eq!(t.branch_id_at(510_300), Some(CANOPY));
    assert_eq!(t.branch_id_at(510_399), Some(CANOPY));
    assert_eq!(t.branch_id_at(510_400), Some(VAULT_BRANCH_ID));
    assert_eq!(t.branch_id_at(510_421), Some(VAULT_BRANCH_ID));
    assert_eq!(t.branch_id_at(1), Some(0));
    // mainnet: Canopy today
    assert_eq!(Network::Mainnet.branch_id_at(3_100_000), Some(CANOPY));
}

/// The branch a wallet signs the next block's transaction under, given what the server reports
/// (`GetLightdInfo` chaintip, `GetChainInfo` nextblock and upgrades): for the next block at
/// 510,300, 510,400 and 510,421 (tips 510,299, 510,399, 510,420).
fn fast_signing_branch(next: u64) -> Result<u32, BranchError> {
    let t = Network::Testnet;
    let tip_branch = t.branch_id_at(next - 1).unwrap();
    let next_branch = t.branch_id_at(next).unwrap();
    signing_branch_id(t, tip_branch, next, Some(510_400), Some(next_branch))
}

#[test]
fn fast_signs_for_the_right_branch() {
    assert_eq!(fast_signing_branch(510_300), Ok(CANOPY));
    assert_eq!(fast_signing_branch(510_400), Ok(VAULT_BRANCH_ID));
    assert_eq!(fast_signing_branch(510_421), Ok(VAULT_BRANCH_ID));
    // without GetChainInfo (no Yellowback service): the compiled height alone
    let t = Network::Testnet;
    assert_eq!(
        signing_branch_id(t, CANOPY, 510_400, None, None),
        Ok(VAULT_BRANCH_ID)
    );
    assert_eq!(
        signing_branch_id(t, VAULT_BRANCH_ID, 510_421, None, None),
        Ok(VAULT_BRANCH_ID)
    );
    // a server announcing another Vault height is not believed on testnet: the compiled one rules,
    // and a server that signs a block below it under Vault is refused
    assert!(matches!(
        signing_branch_id(t, CANOPY, 510_390, Some(510_390), Some(VAULT_BRANCH_ID)),
        Err(BranchError::UnscheduledVault("test"))
    ));
    // mainnet is unchanged: Vault unscheduled, a server claiming it is refused
    assert_eq!(
        signing_branch_id(Network::Mainnet, CANOPY, 3_500_000, Some(10), None),
        Ok(CANOPY)
    );
    assert_eq!(
        signing_branch_id(Network::Mainnet, VAULT_BRANCH_ID, 3_500_000, Some(10), None),
        Err(BranchError::UnscheduledVault("main"))
    );
}

fn one_input_tx(script: Vec<u8>, amount: i64, expiry: u32) -> Transaction {
    let mut tx = Transaction::new_v4();
    tx.expiry_height = expiry;
    tx.vin.push(TxIn::new(OutPoint {
        txid: [7; 32],
        n: 0,
    }));
    tx.vout.push(TxOut {
        value: amount - 1_000,
        script_pubkey: script,
    });
    tx
}

/// A transparent P2PKH spend for fast at each height: a v4 Sapling-group transaction whose
/// signature commits to the height's branch (the node verifies it under that id), not to the
/// one librustzcash6's stale `TEST_NETWORK` would give (the Ycash epoch, 0x374d694f).
#[test]
fn a_transparent_spend_for_fast_commits_to_the_heights_branch() {
    let secret = secp256k1::SecretKey::from_secret_bytes([0x11; 32]).unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&secret).serialize();
    let script = yew_core::script::p2pkh_script(&yew_core::keys::hash160(&pubkey));
    for (next, want) in [
        (510_300u64, CANOPY),
        (510_400, VAULT_BRANCH_ID),
        (510_421, VAULT_BRANCH_ID),
    ] {
        let branch = fast_signing_branch(next).unwrap();
        assert_eq!(branch, want, "{next}");
        let mut tx = one_input_tx(script.clone(), 50_000, next as u32 + 40);
        let digest = tx
            .sign_p2pkh_input(0, &secret, &script, 50_000, branch)
            .unwrap();
        let (parsed, _) = Transaction::parse(&tx.serialize().unwrap()).unwrap();
        assert_eq!(parsed.version_group_id, SAPLING_VERSION_GROUP_ID, "{next}");
        assert_eq!(
            parsed
                .sighash(0, &script, 50_000, params::SIGHASH_ALL, want)
                .unwrap(),
            digest,
            "{next}"
        );
        assert_ne!(
            parsed
                .sighash(0, &script, 50_000, params::SIGHASH_ALL, YCASH)
                .unwrap(),
            digest
        );
    }
}

/// A post-quantum (`TX_PQPKH`, SLH-DSA) spend for fast at 510,421, under the Vault branch: the
/// signature verifies over the Vault-branch digest and not over the Canopy one.
#[test]
fn a_post_quantum_spend_for_fast_commits_to_vault() {
    use yew_core::pq;
    let key = pq::PqKey::from_seed(pq::SCHEME_SLH_DSA_SHA2_128S, &[0x22; 48]).unwrap();
    let script = pq::pqpkh_script(&key.id()).unwrap();
    let branch = fast_signing_branch(510_421).unwrap();
    assert_eq!(branch, VAULT_BRANCH_ID);
    let mut tx = one_input_tx(script.clone(), 80_000, 510_461);
    let digest = tx
        .sign_pqpkh_input(0, &key, &script, 80_000, branch)
        .unwrap();
    let raw = tx.serialize().unwrap();
    let (parsed, _) = Transaction::parse(&raw).unwrap();
    assert_eq!(parsed.version_group_id, SAPLING_VERSION_GROUP_ID);
    let (sig, pk) = pq::parse_pqpkh_script_sig(&parsed.vin[0].script_sig).unwrap();
    let sig = &sig[..sig.len() - 1]; // the hashtype byte
    let vault = parsed
        .sighash(0, &script, 80_000, params::SIGHASH_ALL, VAULT_BRANCH_ID)
        .unwrap();
    assert_eq!(vault, digest);
    assert!(pq::verify(pq::SCHEME_SLH_DSA_SHA2_128S, &pk, sig, &vault));
    let canopy = parsed
        .sighash(0, &script, 80_000, params::SIGHASH_ALL, CANOPY)
        .unwrap();
    assert!(!pq::verify(pq::SCHEME_SLH_DSA_SHA2_128S, &pk, sig, &canopy));
}

/// Address encodings on testnet (every profile shares them, ycash6 `CTestNetParams` /
/// `CTestNetShadowParams`, `yellowback/params.cpp` `SetTestnet`): `sm…` P2PKH, `yt…` YED,
/// `tqf…`/`tqs…` plain post-quantum, `ytf…`/`yts…` post-quantum YED, `ytestsapling1…`.
#[test]
fn testnet_addresses_round_trip() {
    use yew_core::keys;
    use yew_core::pq;
    let t = Network::Testnet;
    let h = [0x42u8; 20];
    let p2pkh = keys::encode_p2pkh(t, &h);
    assert!(p2pkh.starts_with("sm"), "{p2pkh}");
    assert!(keys::encode_yellowback(t, &h).starts_with("yt"));
    for (scheme, yec, yed) in [
        (pq::SCHEME_FN_DSA_512, "tqf", "ytf"),
        (pq::SCHEME_SLH_DSA_SHA2_128S, "tqs", "yts"),
    ] {
        let id = pq::PqKeyId::of(scheme, &[0x33; 32]);
        let a = keys::encode_pq_yec(t, &id).unwrap();
        assert!(a.starts_with(yec), "{a}");
        assert_eq!(keys::parse_pq_yec_address(t, &a).unwrap(), id);
        assert!(keys::parse_pq_yec_address(Network::Mainnet, &a).is_err());
        let y = keys::encode_pq_yellowback(t, &id).unwrap();
        assert!(y.starts_with(yed), "{y}");
        assert_eq!(keys::parse_pq_address(t, &y).unwrap(), id);
    }
    assert_eq!(t.sapling_address_hrp(), "ytestsapling");
}

/// Sapling on fast: the light library's parameters (librustzcash6's `TEST_NETWORK`) are
/// testnet-yb-fast's, so `shielded::check_light_params` passes on every network and no Sapling
/// build is refused. (Before librustzcash6 carried fast's heights it refused testnet, naming
/// blossom: the old Ycash testnet's 661,610.)
#[test]
fn sapling_on_fast_uses_the_nodes_heights() {
    use yew_core::shielded::check_light_params;
    assert_eq!(check_light_params(Network::Mainnet), Ok(()));
    assert_eq!(check_light_params(Network::Regtest), Ok(()));
    assert_eq!(check_light_params(Network::Testnet), Ok(()));
}

/// What a Sapling spend for fast commits to, through the light library's parameters (the ones
/// `Shielded::build` and yewd-signer's `z_sendmany` builder use): the height's branch, a v4
/// transaction in the Sapling version group (Vault is v4-only on Ycash), and ZIP-212 notes
/// (Canopy at 510,254). The build itself is `yewd/signer` `a_sapling_spend_for_fast_signs_under_the_heights_branch`.
#[test]
fn sapling_spend_for_fast_commits_to_the_heights_branch() {
    use zcash_primitives::transaction::TxVersion;
    use zcash_protocol::consensus::{BlockHeight, BranchId, NetworkUpgrade, Parameters};
    let p = yew_core::shielded::ycash_network(Network::Testnet);
    for (h, want) in [
        (510_247u32, 0x76b8_09bb),
        (510_248, YCASH),
        (510_250, 0x8e47_1bd6),
        (510_252, HEARTWOOD),
        (510_254, CANOPY),
        (510_300, CANOPY),
        (510_399, CANOPY),
        (510_400, VAULT_BRANCH_ID),
        (510_421, VAULT_BRANCH_ID),
    ] {
        let branch = BranchId::for_height(&p, BlockHeight::from_u32(h));
        assert_eq!(u32::from(branch), want, "{h}");
        // the light library and YEW's own table agree at every height
        assert_eq!(
            Network::Testnet.branch_id_at(u64::from(h)),
            Some(want),
            "{h}"
        );
        if h >= 510_300 {
            let v = TxVersion::suggested_for_branch(branch);
            assert_eq!(v, TxVersion::V4, "{h}");
            assert_eq!(v.version_group_id(), SAPLING_VERSION_GROUP_ID, "{h}");
            assert!(p.is_nu_active(NetworkUpgrade::Canopy, BlockHeight::from_u32(h)));
        }
    }
}
