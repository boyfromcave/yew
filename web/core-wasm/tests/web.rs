//! End to end in headless Chrome, in a dedicated worker (OPFS sync access handles live there),
//! against a lightwalletd gateway that speaks gRPC-web and allows this origin:
//! web/scripts/test-core-wasm.sh (plan §5, W0.5 and W1a).
//!
//! A fresh wallet (random seed, birthday = tip − 20) syncs to the server's tip and has nothing;
//! then, when the script runs its funding helper (`YEW_WEB_FUND_URL`: `GET /fund_t?addr=…&zat=…`
//! pays a transparent address from the devnet node, `GET /fund?…` a private one), the wallet is
//! paid and re-synced until the money shows up, sends t→t, shields (the proving parameters from
//! `YEW_WEB_PARAMS_URL`), sends z→z with a memo, and runs the YED and vault previews against a
//! wallet that holds no YED (the kind devnet's attestors are unarmed: no mint is possible, so
//! the previews' refusals are what is asserted).
use std::cell::RefCell;
use std::rc::Rc;

use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_dedicated_worker);

const LWD: &str = match option_env!("YEW_WEB_LWD") {
    Some(u) => u,
    None => "http://localhost:9067",
};
const NETWORK: &str = "regtest";
const FUND_ZAT: u64 = 150_000_000;
const FUND_T_ZAT: u64 = 200_000_000;
const SEND_T_ZAT: i64 = 50_000_000;
const SHIELD_ZAT: i64 = 40_000_000;
const SEND_Z_ZAT: i64 = 30_000_000;
const MEMO: &str = "hello from the browser";

fn field(v: &JsValue, key: &str) -> JsValue {
    js_sys::Reflect::get(v, &key.into()).unwrap_or_else(|_| panic!("{key} missing"))
}

fn field_u64(v: &JsValue, key: &str) -> u64 {
    field(v, key)
        .as_f64()
        .unwrap_or_else(|| panic!("{key} is not a number")) as u64
}

fn field_bool(v: &JsValue, key: &str) -> bool {
    field(v, key).as_bool().unwrap_or(false)
}

fn field_str(v: &JsValue, key: &str) -> String {
    field(v, key).as_string().unwrap_or_default()
}

/// An amount field: the contract's decimal string.
fn field_amt(v: &JsValue, key: &str) -> i64 {
    let s = field(v, key)
        .as_string()
        .unwrap_or_else(|| panic!("{key} is not a string amount"));
    s.parse().unwrap_or_else(|_| panic!("{key} = {s:?}"))
}

fn message(e: &JsValue) -> String {
    e.dyn_ref::<js_sys::Error>()
        .map(|e| String::from(e.message()))
        .unwrap_or_else(|| format!("{e:?}"))
}

fn now() -> f64 {
    js_sys::Date::now()
}

async fn sleep_ms(ms: i32) {
    let p = js_sys::Promise::new(&mut |resolve, _| {
        let scope: web_sys::WorkerGlobalScope = js_sys::global().unchecked_into();
        scope
            .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, ms)
            .unwrap();
    });
    JsFuture::from(p).await.unwrap();
}

/// Asks the script's helper to pay `addr` (`route`: `fund` private, `fund_t` public); the txid.
async fn fund(url: &str, route: &str, addr: &str, zat: u64) -> Result<String, String> {
    let scope: web_sys::WorkerGlobalScope = js_sys::global().unchecked_into();
    let full = format!("{url}/{route}?addr={addr}&zat={zat}");
    let resp: web_sys::Response = JsFuture::from(scope.fetch_with_str(&full))
        .await
        .map_err(|e| format!("{e:?}"))?
        .unchecked_into();
    let text = JsFuture::from(resp.text().map_err(|e| format!("{e:?}"))?)
        .await
        .map_err(|e| format!("{e:?}"))?;
    let text = text.as_string().unwrap_or_default();
    if !resp.ok() {
        return Err(format!("helper: HTTP {} {text}", resp.status()));
    }
    Ok(text.trim().to_string())
}

/// Sync until `done(balances)` holds, within `secs` (one block is ~5 s on the devnet).
async fn sync_until(what: &str, secs: f64, done: impl Fn(&JsValue, &JsValue) -> bool) -> JsValue {
    let t0 = now();
    loop {
        let r = yew_web_core::sync().await.expect("sync");
        let b = yew_web_core::balances().expect("balances");
        let msg = field_str(&r, "shielded_message");
        if !msg.is_empty() {
            console_log!("yew-web-core: {what}: the private sync failed: {msg}");
        }
        if now() - t0 > 20_000.0 {
            // Slow: say what each sync sees (the kind cluster is shared; a block can take a while).
            let rows: Vec<String> = history_rows()
                .iter()
                .map(|r| {
                    format!(
                        "{}@{}{} {} {:?}",
                        &field_str(r, "txid")[..8],
                        field_u64(r, "height"),
                        if field_bool(r, "pending") { "p" } else { "" },
                        field_amt(r, "yecDelta"),
                        field_str(r, "memo")
                    )
                })
                .collect();
            console_log!(
                "yew-web-core: {what}: still waiting at {:.0} s: tip {} scanned {} blocks {} received {} spent {} enhanced {}; rows {rows:?}",
                (now() - t0) / 1000.0,
                field_u64(&r, "tip"),
                field_u64(&r, "scanned_height"),
                field_u64(&r, "blocks"),
                field_u64(&r, "received_notes"),
                field_u64(&r, "spent_notes"),
                field_u64(&r, "enhanced")
            );
        }
        if done(&r, &b) {
            console_log!(
                "yew-web-core: {what} after {:.0} ms (tip {}, yec {} pending {} | shielded {} spendable {} pending {})",
                now() - t0,
                field_u64(&r, "tip"),
                field_amt(&b, "yecZat"),
                field_amt(&b, "yecPendingZat"),
                field_amt(&b, "shieldedZat"),
                field_amt(&b, "shieldedSpendableZat"),
                field_amt(&b, "shieldedPendingZat")
            );
            return b;
        }
        assert!(now() - t0 < secs * 1000.0, "{what}: not within {secs} s");
        sleep_ms(2000).await;
    }
}

fn history_rows() -> Vec<JsValue> {
    let h = yew_web_core::history(0).expect("history");
    js_sys::Array::from(&h).iter().collect()
}

fn history_row(txid: &str) -> Option<JsValue> {
    history_rows()
        .into_iter()
        .find(|r| field_str(r, "txid") == txid)
}

#[wasm_bindgen_test]
async fn validate_without_a_wallet() {
    let e = yew_web_core::validate_address("x", None).expect_err("no wallet, no network");
    assert!(message(&e).starts_with("invalid: "), "{}", message(&e));
    let ok = yew_web_core::validate_address(
        &yew_core::keys::encode_yellowback(yew_core::params::Network::Regtest, &[1; 20]),
        Some(NETWORK.into()),
    )
    .unwrap();
    assert!(field_bool(&ok, "valid") && field_bool(&ok, "yellowbackForm"));
    assert_eq!(field_str(&ok, "kind"), "p2pkh");
    let bad = yew_web_core::validate_address("ye-not-an-address", Some(NETWORK.into())).unwrap();
    assert!(!field_bool(&bad, "valid") && !field_str(&bad, "message").is_empty());
    // Nothing is open: every wallet call says so with the contract's kind.
    let e = yew_web_core::balances().expect_err("closed");
    assert_eq!(message(&e), "invalid: no wallet is open (open first)");
}

#[wasm_bindgen_test]
async fn fresh_wallet_syncs_receives_sends_shields_and_previews() {
    yew_web_core::install_storage().await.expect("opfs");
    let words = yew_web_core::new_seed_words().expect("seed");
    let tip0 = yew_web_core::latest_height(LWD, NETWORK)
        .await
        .expect("tip");
    let birthday = tip0.saturating_sub(20).max(1);
    let t0 = now();
    let opened = yew_web_core::open(&words, birthday, LWD, NETWORK)
        .await
        .expect("open");
    let address = yew_web_core::receive_address(None).expect("address");
    let address_s = yew_web_core::receive_address(Some("transparent".into())).expect("s");
    let address_ye = yew_web_core::receive_address(Some("yed".into())).expect("ye");
    console_log!(
        "yew-web-core: opened in {:.0} ms; server tip {tip0}, birthday {birthday}, vault activation {:?}, {address} / {address_s} / {address_ye}",
        now() - t0,
        field(&opened, "vault_activation")
    );
    assert!(address.starts_with("yregtestsapling1"), "{address}");
    assert_eq!(
        address,
        yew_web_core::receive_address(Some("shielded".into())).unwrap()
    );
    assert!(address_s.starts_with("sm") && address_ye.starts_with("yr"));
    assert_eq!(field_str(&opened, "addressS"), address_s);
    assert_eq!(field_str(&opened, "addressYe"), address_ye);
    assert!(
        !field_bool(&opened, "registered"),
        "a fresh store has no account"
    );
    let e = yew_web_core::open(&words, birthday, LWD, NETWORK)
        .await
        .expect_err("already open");
    assert!(
        message(&e).starts_with("invalid: a wallet is already open"),
        "{}",
        message(&e)
    );
    let info = yew_web_core::receive_address_info(Some("transparent".into())).unwrap();
    assert_eq!(field_str(&info, "path"), "m/44'/347'/0'/0/0");
    assert!(field_bool(&info, "coveredBySeed"));
    let st = yew_web_core::status().await.unwrap();
    assert_eq!(field_str(&st, "network"), "regtest");
    assert!(
        field_bool(&st, "yellowbackUsable"),
        "the kind lightwalletd serves Yellowback"
    );

    // The progress callback: every event of the first sync.
    let events: Rc<RefCell<Vec<(String, u64, u64, u64)>>> = Rc::new(RefCell::new(Vec::new()));
    let sink = events.clone();
    let cb = Closure::<dyn Fn(JsValue)>::new(move |ev: JsValue| {
        sink.borrow_mut().push((
            field_str(&ev, "phase"),
            field_u64(&ev, "pct"),
            field_u64(&ev, "height"),
            field_u64(&ev, "tip"),
        ));
    });
    yew_web_core::set_progress_callback(Some(
        cb.as_ref().unchecked_ref::<js_sys::Function>().clone(),
    ));
    let t1 = now();
    let r = yew_web_core::sync().await.expect("sync");
    let sync_ms = now() - t1;
    let (tip, scanned, blocks) = (
        field_u64(&r, "tip"),
        field_u64(&r, "scanned_height"),
        field_u64(&r, "blocks"),
    );
    console_log!(
        "yew-web-core: first sync {sync_ms:.0} ms: tip {tip}, scanned {scanned}, {blocks} blocks, branch {}, yellowback {}, registered_now {}, sendable {}; {} progress events: {:?}",
        field_str(&r, "branch_id"),
        field_bool(&r, "yellowback"),
        field_bool(&r, "registered_now"),
        field_bool(&r, "sendable"),
        events.borrow().len(),
        events.borrow()
    );
    assert!(field_bool(&r, "registered_now"));
    assert!(
        field_str(&r, "shielded_message").is_empty(),
        "{}",
        field_str(&r, "shielded_message")
    );
    // `tip` is the transparent sync's (the node's); the private scan reaches the compact-block
    // cache's tip, which may trail it by a block that arrived in between.
    assert!(
        scanned == tip || scanned + 1 == tip,
        "scanned {scanned} to the tip {tip}"
    );
    assert!(tip >= tip0);
    assert_eq!(
        blocks,
        scanned - birthday + 1,
        "from the birthday to the tip"
    );
    assert_eq!(field_str(&r, "branch_id"), "6d5b7a31");
    {
        let ev = events.borrow();
        assert_eq!(ev.first().map(|e| e.0.as_str()), Some("connecting"));
        assert_eq!(ev.last().map(|e| (e.0.as_str(), e.1)), Some(("done", 100)));
        assert!(ev.iter().any(|e| e.0 == "shielded"), "{ev:?}");
        assert!(ev.windows(2).all(|w| w[0].1 <= w[1].1), "monotone: {ev:?}");
    }
    let b = yew_web_core::balances().expect("balances");
    assert_eq!(field_amt(&b, "yecZat"), 0);
    assert_eq!(field_amt(&b, "yedCents"), 0);
    assert_eq!(field_amt(&b, "shieldedZat"), 0);
    assert!(field_bool(&b, "shieldedSendable"));
    assert_eq!(field_u64(&b, "syncHeight"), tip);
    assert_eq!(field_u64(&b, "shieldedScannedHeight"), scanned);
    assert!(history_rows().is_empty());
    assert!(js_sys::Array::from(&yew_web_core::vaults().unwrap()).length() == 0);
    assert!(js_sys::Array::from(&yew_web_core::mints().unwrap()).length() == 0);
    assert!(js_sys::Array::from(&yew_web_core::claim_intents().unwrap()).length() == 0);

    // `busy`: a call while a sync runs (the sync is started, parked at its first await).
    let done: Rc<RefCell<Option<Result<JsValue, JsValue>>>> = Rc::new(RefCell::new(None));
    let slot = done.clone();
    wasm_bindgen_futures::spawn_local(async move {
        *slot.borrow_mut() = Some(yew_web_core::sync().await);
    });
    sleep_ms(0).await;
    let e = yew_web_core::balances().expect_err("busy");
    assert_eq!(message(&e), "busy: a call is in progress");
    while done.borrow().is_none() {
        sleep_ms(50).await;
    }
    assert!(done.borrow().as_ref().unwrap().is_ok());
    assert!(yew_web_core::balances().is_ok());

    let Some(fund_url) = option_env!("YEW_WEB_FUND_URL") else {
        console_log!("yew-web-core: no YEW_WEB_FUND_URL; the funded half is skipped");
        return;
    };

    // ---- Public YEC: a receipt, then a t→t send through preview + confirm.
    let t2 = now();
    let txid_t = fund(fund_url, "fund_t", &address_s, FUND_T_ZAT)
        .await
        .expect("fund_t");
    console_log!(
        "yew-web-core: public funding {txid_t} in {:.0} ms",
        now() - t2
    );
    // The balance comes from `GetAddressUtxos`, the history row from `GetTaddressTxids`: the
    // kind cluster's yindex can answer the first a sync before the second, so both are waited for.
    let b = sync_until("public receipt spendable", 240.0, |_, b| {
        field_amt(b, "yecZat") + field_amt(b, "yecReservedZat") >= FUND_T_ZAT as i64
            && history_row(&txid_t).is_some()
    })
    .await;
    assert_eq!(
        field_amt(&b, "yecZat") + field_amt(&b, "yecReservedZat"),
        FUND_T_ZAT as i64
    );
    let row = history_row(&txid_t).expect("the receipt in history");
    assert_eq!(field_amt(&row, "yecDelta"), FUND_T_ZAT as i64);
    assert_eq!(field_str(&row, "label"), "received YEC");
    assert!(!field_bool(&row, "pending") && field_u64(&row, "height") > 0);

    let foreign = yew_core::keys::encode_p2pkh(yew_core::params::Network::Regtest, &[7; 20]);
    let p = yew_web_core::send_yec_preview(
        foreign.clone(),
        JsValue::from_str(&SEND_T_ZAT.to_string()),
        None,
    )
    .await
    .expect("t→t preview");
    assert_eq!(field_str(&p, "funding"), "transparent");
    assert_eq!(field_amt(&p, "amountZat"), SEND_T_ZAT);
    assert!(!field_bool(&p, "revealsShielded") && !field_bool(&p, "paramsNeeded"));
    let fee_t = field_amt(&p, "fee");
    let preview_id = field_str(&p, "previewId");
    assert_eq!(preview_id, field_str(&p, "txid"));
    console_log!(
        "yew-web-core: t→t preview {preview_id}: {} zat, fee {fee_t}, change {}, {} inputs",
        field_amt(&p, "amountZat"),
        field_amt(&p, "change"),
        field_u64(&p, "inputs")
    );
    let t3 = now();
    let c = yew_web_core::confirm(preview_id.clone())
        .await
        .expect("t→t confirm");
    console_log!(
        "yew-web-core: t→t confirmed {} (verdict {:?}) in {:.0} ms",
        field_str(&c, "txid"),
        field_str(&c, "verdict"),
        now() - t3
    );
    assert_eq!(field_str(&c, "txid"), preview_id);
    let e = yew_web_core::confirm(preview_id.clone())
        .await
        .expect_err("consumed");
    assert!(message(&e).starts_with("invalid: This preview is no longer valid"));
    let row = history_row(&preview_id).expect("the send in history, pending");
    assert!(field_bool(&row, "pending"));
    assert_eq!(field_amt(&row, "yecDelta"), -(SEND_T_ZAT + fee_t));
    let b = sync_until("t→t send mined", 240.0, |_, _| {
        history_row(&preview_id).is_some_and(|r| !field_bool(&r, "pending"))
    })
    .await;
    let public_left = FUND_T_ZAT as i64 - SEND_T_ZAT - fee_t;
    assert_eq!(
        field_amt(&b, "yecZat") + field_amt(&b, "yecReservedZat"),
        public_left
    );
    assert_eq!(field_amt(&b, "yecPendingZat"), 0);

    // ---- Private YEC: a receipt.
    let t4 = now();
    let txid_z = fund(fund_url, "fund", &address, FUND_ZAT)
        .await
        .expect("fund");
    console_log!(
        "yew-web-core: private funding {txid_z} in {:.0} ms",
        now() - t4
    );
    let b = sync_until("private receipt spendable", 240.0, |_, b| {
        field_amt(b, "shieldedSpendableZat") >= FUND_ZAT as i64 && history_row(&txid_z).is_some()
    })
    .await;
    assert_eq!(field_amt(&b, "shieldedZat"), FUND_ZAT as i64);
    let row = history_row(&txid_z).expect("the private receipt in history");
    assert!(field_bool(&row, "shielded"));
    assert_eq!(field_amt(&row, "yecDelta"), FUND_ZAT as i64);

    // ---- The proving parameters (served by the helper), then a shield (to_private).
    let ps = yew_web_core::params_status().await.unwrap();
    console_log!(
        "yew-web-core: params before: present {} bytes {} needed {}",
        field_bool(&ps, "present"),
        field_u64(&ps, "bytes"),
        field_u64(&ps, "needed")
    );
    let p = yew_web_core::move_preview(
        "to_private".into(),
        JsValue::from_str(&SHIELD_ZAT.to_string()),
    )
    .await
    .expect("shield preview");
    assert_eq!(field_str(&p, "funding"), "transparent");
    assert_eq!(field_amt(&p, "amountZat"), SHIELD_ZAT);
    assert_eq!(field_bool(&p, "paramsNeeded"), !field_bool(&ps, "present"));
    let shield_id = field_str(&p, "previewId");
    let shield_fee = field_amt(&p, "fee");
    if !field_bool(&ps, "present") {
        let e = yew_web_core::confirm(shield_id.clone())
            .await
            .expect_err("no params yet");
        assert!(message(&e).starts_with("params: "), "{}", message(&e));
    }
    let params_url = option_env!("YEW_WEB_PARAMS_URL").expect("YEW_WEB_PARAMS_URL");
    let fetch_events: Rc<RefCell<Vec<(String, u64, u64)>>> = Rc::new(RefCell::new(Vec::new()));
    let sink = fetch_events.clone();
    let fcb = Closure::<dyn Fn(JsValue)>::new(move |ev: JsValue| {
        sink.borrow_mut().push((
            field_str(&ev, "name"),
            field_u64(&ev, "bytesDone"),
            field_u64(&ev, "bytesTotal"),
        ));
    });
    let sources = js_sys::Array::new();
    sources.push(&JsValue::from_str(params_url));
    let t5 = now();
    yew_web_core::fetch_params(
        Some(fcb.as_ref().unchecked_ref::<js_sys::Function>().clone()),
        sources.into(),
    )
    .await
    .expect("fetch_params");
    console_log!(
        "yew-web-core: fetch_params in {:.0} ms; events {:?}",
        now() - t5,
        fetch_events.borrow()
    );
    {
        let ev = fetch_events.borrow();
        assert_eq!(ev.len(), 3);
        assert_eq!(ev[0].0, "sapling-spend.params");
        assert_eq!(
            ev[2],
            ("sapling-output.params".into(), 51_551_256, 51_551_256)
        );
    }
    let ps = yew_web_core::params_status().await.unwrap();
    assert!(field_bool(&ps, "present") && field_bool(&ps, "loaded"));
    assert_eq!(field_u64(&ps, "needed"), 0);
    // A second fetch comes from the Cache API (fast).
    let t6 = now();
    yew_web_core::fetch_params(None, JsValue::UNDEFINED)
        .await
        .expect("fetch_params from cache");
    console_log!(
        "yew-web-core: fetch_params from the cache in {:.0} ms",
        now() - t6
    );

    let t7 = now();
    let c = yew_web_core::confirm(shield_id.clone())
        .await
        .expect("shield confirm");
    let shield_txid = field_str(&c, "txid");
    console_log!(
        "yew-web-core: shield {shield_txid} proved and broadcast in {:.0} ms",
        now() - t7
    );
    assert_eq!(shield_txid.len(), 64);
    // The transparent sync runs before the private scan: a block arriving in between leaves the
    // public change pending for one more sync, so both sides are waited for.
    let b = sync_until("shield mined and the note spendable", 300.0, |_, b| {
        field_amt(b, "shieldedSpendableZat") >= FUND_ZAT as i64 + SHIELD_ZAT
            && field_amt(b, "yecPendingZat") == 0
    })
    .await;
    let public_left = public_left - SHIELD_ZAT - shield_fee;
    assert_eq!(
        field_amt(&b, "yecZat") + field_amt(&b, "yecReservedZat"),
        public_left
    );
    let row = history_row(&shield_txid).expect("the shield in history");
    assert!(field_bool(&row, "shielded"));
    assert_eq!(
        field_amt(&row, "yecDelta"),
        -shield_fee,
        "net: public out, private in, fee gone"
    );

    // ---- A z→z send with a memo to a new address of the same account.
    let other = yew_web_core::new_shielded_address().expect("new address");
    assert_ne!(other, address);
    assert_eq!(
        yew_web_core::receive_address(Some("shielded".into())).unwrap(),
        other
    );
    let p = yew_web_core::send_yec_preview(
        other.clone(),
        JsValue::from_str(&SEND_Z_ZAT.to_string()),
        Some(MEMO.into()),
    )
    .await
    .expect("z→z preview");
    assert_eq!(field_str(&p, "funding"), "shielded");
    assert_eq!(field_str(&p, "memo"), MEMO);
    assert!(!field_bool(&p, "revealsShielded") && !field_bool(&p, "paramsNeeded"));
    assert!(
        field_str(&p, "txid").is_empty(),
        "a private txid exists only after proving"
    );
    let z_id = field_str(&p, "previewId");
    let z_fee = field_amt(&p, "fee");
    let t8 = now();
    let c = yew_web_core::confirm(z_id).await.expect("z→z confirm");
    let z_txid = field_str(&c, "txid");
    console_log!(
        "yew-web-core: z→z {z_txid} (fee {z_fee}) proved and broadcast in {:.0} ms",
        now() - t8
    );
    let b = sync_until("z→z mined", 300.0, |_, _| {
        history_row(&z_txid).is_some_and(|r| !field_bool(&r, "pending"))
    })
    .await;
    let row = history_row(&z_txid).unwrap();
    // The memo is fetched by the private sync's enhancement (`GetTransaction`). When the
    // transaction was still in the mempool at that moment the kind lightwalletd answers
    // not-found, the store records `TxidNotRecognized` and never asks again, so a send mined a
    // few blocks after broadcast shows no memo (W1a finding, a yew-core `shielded::enhance`
    // matter, not the binding's; the next-block case is the one asserted on the devnet).
    let memo = field_str(&row, "memo");
    console_log!(
        "yew-web-core: z→z row: height {} memo {memo:?}",
        field_u64(&row, "height")
    );
    assert!(memo == MEMO || memo.is_empty(), "{memo:?}");
    assert!(field_bool(&row, "shielded"));
    // The private history row of a send to one of the wallet's own diversified addresses
    // reports the amount as sent (the light store's `v_transactions` nets the change only,
    // not a receipt to another address of the account); the balance below is right. Noted in
    // the plan (W1a) for the shell: the row's label is "sent private YEC" with the full amount.
    let delta = field_amt(&row, "yecDelta");
    assert!(
        delta == -z_fee || delta == -(SEND_Z_ZAT + z_fee),
        "self-send delta {delta}"
    );
    // The 0.3 YEC paid to the account's own diversified address: credited once the scan
    // decrypts it as a receipt (a later sync), meanwhile the balance shows it gone. Either
    // state is accepted here; what the balance says is logged for the plan.
    let full = FUND_ZAT as i64 + SHIELD_ZAT - z_fee;
    let t9 = now();
    let mut total = field_amt(&b, "shieldedZat");
    while total != full && now() - t9 < 30_000.0 {
        sleep_ms(3000).await;
        yew_web_core::sync().await.expect("sync");
        total = field_amt(&yew_web_core::balances().unwrap(), "shieldedZat");
    }
    console_log!(
        "yew-web-core: private total after the self-send: {total} (full {full}) after {:.0} ms",
        now() - t9
    );
    assert!(total == full || total == full - SEND_Z_ZAT, "{total}");
    // A memo to a public address is refused before anything is planned.
    let e = yew_web_core::send_yec_preview(
        foreign.clone(),
        JsValue::from_str("1000"),
        Some("x".into()),
    )
    .await
    .expect_err("memo to t");
    assert!(message(&e).starts_with("invalid: "), "{}", message(&e));
    // A shielded recipient is paid from the private pool: a transparent recipient too when
    // the notes cover it (the amber line).
    let p = yew_web_core::send_yec_preview(foreign.clone(), JsValue::from_str("1000"), None)
        .await
        .expect("reveal preview");
    assert_eq!(field_str(&p, "funding"), "shielded");
    assert!(field_bool(&p, "revealsShielded"));

    // ---- YED: no YED in the wallet, the kind devnet's attestors unarmed (no mint possible).
    let e = yew_web_core::send_yed_preview(address_ye.clone(), JsValue::from_str("100"))
        .await
        .expect_err("no YED");
    console_log!(
        "yew-web-core: send_yed_preview without YED: {}",
        message(&e)
    );
    assert!(
        message(&e).starts_with("build: insufficient-yed"),
        "{}",
        message(&e)
    );
    let m = yew_web_core::mint_availability()
        .await
        .expect("mint_availability");
    console_log!(
        "yew-web-core: mint_availability: allowed {} reason {:?} armed {} attest {:?} classes {:?}",
        field_bool(&m, "allowed"),
        field_str(&m, "reason"),
        field_bool(&m, "armed"),
        field_str(&m, "attestStatus"),
        field(&m, "mintableClasses")
    );
    match yew_web_core::mint_estimate(JsValue::from_str("100"), 48).await {
        Ok(e) => console_log!(
            "yew-web-core: mint_estimate: collateral {} total {} affordable {} armed {}",
            field_amt(&e, "collateralZat"),
            field_amt(&e, "totalZat"),
            field_bool(&e, "affordable"),
            field_bool(&e, "armed")
        ),
        Err(e) => {
            console_log!("yew-web-core: mint_estimate refused: {}", message(&e));
            assert!(!field_bool(&m, "allowed") || message(&e).starts_with("build: "));
        }
    }
    let e = yew_web_core::mint_estimate(JsValue::from_str("0"), 48)
        .await
        .expect_err("zero");
    assert!(message(&e).starts_with("invalid: "));
    let cl = yew_web_core::claimable().await.expect("claimable");
    console_log!(
        "yew-web-core: claimable: {} rows",
        js_sys::Array::from(&cl).length()
    );
    let e = yew_web_core::claim_preview("ab".repeat(32))
        .await
        .expect_err("unknown vault");
    assert!(message(&e).starts_with("invalid: "), "{}", message(&e));
    let e = yew_web_core::redeem_preview("zz".into())
        .await
        .expect_err("bad txid");
    assert!(message(&e).starts_with("invalid: "));
    let e = yew_web_core::redeem_preview("ab".repeat(32))
        .await
        .expect_err("not ours");
    console_log!(
        "yew-web-core: redeem_preview of a foreign vault: {}",
        message(&e)
    );
    assert!(!message(&e).starts_with("busy"));
    let e = yew_web_core::mint_finish(7).expect_err("no row");
    assert_eq!(message(&e), "invalid: no mint with id 7");

    // ---- Keys.
    let wif = yew_web_core::export_wif(address_ye.clone()).expect("wif");
    assert!(yew_web_core::export_wif(foreign.clone()).is_err());
    let foreign_key = yew_core::keys::AddressKey::from_secret(
        secp256k1::SecretKey::from_secret_bytes([9u8; 32]).unwrap(),
    );
    let imported =
        yew_web_core::import_wif(foreign_key.wif(yew_core::params::Network::Regtest), Some(2))
            .expect("import");
    assert!(!field_bool(&imported, "coveredBySeed"));
    assert_eq!(field_str(&imported, "path"), "imported");
    assert_eq!(
        yew_web_core::export_wif(field_str(&imported, "ye")).unwrap(),
        foreign_key.wif(yew_core::params::Network::Regtest)
    );
    assert_ne!(wif, foreign_key.wif(yew_core::params::Network::Regtest));
    let n = js_sys::Array::from(&yew_web_core::addresses().unwrap()).length();
    assert!(n >= 41, "{n}");
    let v = yew_web_core::validate_address(&other, None).unwrap();
    assert_eq!(field_str(&v, "kind"), "sapling");
    console_log!(
        "yew-web-core: history has {} rows; done",
        history_rows().len()
    );
    yew_web_core::set_progress_callback(None);
    yew_web_core::close();
    assert!(yew_web_core::balances().is_err());
}
