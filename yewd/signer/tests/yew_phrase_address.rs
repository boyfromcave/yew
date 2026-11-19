// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! A YEW recovery phrase restored in yewd holds the post-quantum addresses the YEW app and the web
//! wallet show for it (beta4 item 7: the recovery of a mining reward paid to a YEW address).
//!
//! The YEW side is the app's own call, `yew_core::api::create_wallet` then
//! `api::receive_address(PqFalcon | PqSlh)` (the web wallet's `receive_address` in
//! `web/core-wasm` reads the same `Wallet::falcon_holder_id` / `pq_owner_id`). The yewd side is the
//! signer's public bundle of the same phrase (`public_from_seed`, what a `-mnemonicfile` restore
//! derives and scans for): the first receive address of each scheme must be key 0 of that scheme.
//!
//! `YEWD_YEW_PHRASE` names another phrase (the end-to-end recovery run, `qa/recover_pq_reward.py`,
//! uses it), `YEWD_YEW_NETWORK` the network (`regtest`, default; `testnet`; `mainnet`). The
//! addresses are printed as one JSON line, `yew-app-addresses {...}`.

use yew_core::api::{self, NetworkId, ReceiveKind};
use yew_core::keys;
use yew_core::params::Network;
use yew_core::pq::PqKeyId;
use yewd_proto::PublicRequest;

/// A fixed test phrase (BIP-39 "abandon … about"); never a wallet that holds funds.
const TEST_PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[test]
fn a_yew_phrase_restores_the_apps_post_quantum_addresses() {
    let phrase = std::env::var("YEWD_YEW_PHRASE").unwrap_or_else(|_| TEST_PHRASE.to_string());
    let (id, network) = match std::env::var("YEWD_YEW_NETWORK").as_deref() {
        Ok("mainnet") => (NetworkId::Mainnet, Network::Mainnet),
        Ok("testnet") => (NetworkId::Testnet, Network::Testnet),
        _ => (NetworkId::Regtest, Network::Regtest),
    };
    let dir = std::env::temp_dir().join(format!("yewd-yew-phrase-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // the app: a restore of the phrase (no server is reached by create_wallet)
    api::create_wallet(
        Some(phrase.clone()),
        String::new(),
        Some(0),
        id,
        "127.0.0.1:9067".into(),
        true,
        None,
        dir.to_string_lossy().into_owned(),
    )
    .expect("the app restores the phrase");
    let falcon = api::receive_address(ReceiveKind::PqFalcon, false)
        .expect("Falcon receive address")
        .address;
    let slh = api::receive_address(ReceiveKind::PqSlh, false)
        .expect("SLH-DSA receive address")
        .address;
    let _ = std::fs::remove_dir_all(&dir);

    // yewd: the signer's public keys of the same phrase, key 0 of each scheme
    let seed = keys::seed_from_mnemonic(&phrase, "").unwrap();
    let bundle = yewd_signer::public_from_seed(
        network,
        &seed,
        &PublicRequest {
            pq: vec![
                (yew_core::pq::SCHEME_FN_DSA_512, 0, 1),
                (yew_core::pq::SCHEME_SLH_DSA_SHA2_128S, 0, 1),
            ],
        },
    )
    .unwrap();
    let addr = |scheme: u8| {
        let k = bundle
            .pq
            .iter()
            .find(|k| k.scheme == scheme && k.index == 0)
            .expect("key 0");
        keys::encode_pq_yec(network, &PqKeyId::of(scheme, &hex::decode(&k.pk).unwrap())).unwrap()
    };
    let yewd_falcon = addr(yew_core::pq::SCHEME_FN_DSA_512);
    let yewd_slh = addr(yew_core::pq::SCHEME_SLH_DSA_SHA2_128S);
    println!(
        "yew-app-addresses {}",
        serde_json::json!({"falcon": falcon, "slh": slh, "yewd_falcon": yewd_falcon, "yewd_slh": yewd_slh})
    );
    assert_eq!(
        falcon, yewd_falcon,
        "the app's Falcon address is yewd's key 0"
    );
    assert_eq!(slh, yewd_slh, "the app's SLH-DSA address is yewd's key 0");
}
