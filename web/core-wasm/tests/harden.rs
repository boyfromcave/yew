//! W3 hardening, in headless Chrome, in a dedicated worker, against the same lightwalletd
//! gateway and funding helper as tests/web.rs (web/scripts/test-core-wasm.sh runs both):
//!
//! 1. `restore_from_seed_with_birthday`: a wallet is paid (public and private, the private
//!    note with a memo), closed, and opened again from its seed in a NEW store directory with
//!    birthday = funding height − 2: both balances and the memo return. Opened a third time with
//!    a birthday after the funding, the private note is absent (expected: the scan starts at the
//!    birthday), and so is the public receipt: the transparent sync asks the server for the
//!    addresses' UTXOs and history from the birthday too (`core/src/sync.rs`, `address_utxos(…,
//!    birthday)`), so a wrong birthday hides money on BOTH sides until a restore with an earlier
//!    one — the shell's restore screen must say so.
//! 2. `busy_under_concurrency`: a `sync()` in flight and every other call racing it (`sync`,
//!    `balances`, `history`, `open_at`) answer `busy` / `invalid`, never a storage assertion;
//!    the store is intact after (close, reopen the same directory, the balance is right).
//! 3. `reorg_during_private_sync`: a private receipt mined at height H, then the helper's
//!    `/reorg?height=H` invalidates that block (the node mines a longer branch; the funding is
//!    mined again on it): after re-sync the balance is exactly the funding (no double count),
//!    one history row, and the private scan reports the rewind. **This disturbs the shared
//!    cluster** (every client sees a two-or-three-block reorg); it runs last.
//!
//! Each test needs `YEW_WEB_FUND_URL` (the script's helper); without it the tests skip.
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
const FUND_ZAT: u64 = 120_000_000;
const FUND_T_ZAT: u64 = 110_000_000;
const MEMO: &str = "restore me";

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

/// `GET <helper>/<route>?<query>`; the body.
async fn helper(url: &str, route: &str, query: &str) -> Result<String, String> {
    let scope: web_sys::WorkerGlobalScope = js_sys::global().unchecked_into();
    let full = format!("{url}/{route}?{query}");
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

fn history_rows() -> Vec<JsValue> {
    let h = yew_web_core::history(0).expect("history");
    js_sys::Array::from(&h).iter().collect()
}

fn history_row(txid: &str) -> Option<JsValue> {
    history_rows()
        .into_iter()
        .find(|r| field_str(r, "txid") == txid)
}

fn rows_of(txid: &str) -> usize {
    history_rows()
        .iter()
        .filter(|r| field_str(r, "txid") == txid)
        .count()
}

/// Sync until `done(sync result, balances)` holds, within `secs`.
async fn sync_until(what: &str, secs: f64, done: impl Fn(&JsValue, &JsValue) -> bool) -> JsValue {
    let t0 = now();
    loop {
        let r = yew_web_core::sync().await.expect("sync");
        let b = yew_web_core::balances().expect("balances");
        let msg = field_str(&r, "shielded_message");
        if !msg.is_empty() {
            console_log!("yew-web-core: {what}: the private sync failed: {msg}");
        }
        if done(&r, &b) {
            console_log!(
                "yew-web-core: {what} after {:.0} ms (tip {}, scanned {}, reorgs {}, yec {} | shielded {} spendable {})",
                now() - t0,
                field_u64(&r, "tip"),
                field_u64(&r, "scanned_height"),
                field_u64(&r, "reorgs"),
                field_amt(&b, "yecZat"),
                field_amt(&b, "shieldedZat"),
                field_amt(&b, "shieldedSpendableZat")
            );
            return b;
        }
        assert!(now() - t0 < secs * 1000.0, "{what}: not within {secs} s");
        sleep_ms(2000).await;
    }
}

async fn open_in(words: &str, birthday: u64, dir: &str) -> JsValue {
    let o = yew_web_core::open_at(words, birthday, LWD, NETWORK, dir)
        .await
        .unwrap_or_else(|e| panic!("open_at {dir}: {}", message(&e)));
    console_log!(
        "yew-web-core: opened {dir} at birthday {birthday}: {} / {}",
        field_str(&o, "address"),
        field_str(&o, "addressS")
    );
    o
}

/// The sahpool's management handle (`install` on the registered VFS only returns it). The
/// pool's default capacity is 6 files (sqlite-wasm-vfs 0.2 `OpfsSAHPoolCfg`), which one wallet
/// (its three databases and their journals) nearly fills: a second store directory in the same
/// origin needs more — "unable to open database file" otherwise (W3 finding for the shell's
/// restore and forget flows). The tests reserve what they use and log the pool.
async fn pool() -> sqlite_wasm_vfs::sahpool::OpfsSAHPoolUtil {
    use sqlite_wasm_vfs::sahpool::{install, OpfsSAHPoolCfg};
    install::<sqlite_wasm_rs::WasmOsCallback>(&OpfsSAHPoolCfg::default(), true)
        .await
        .expect("the registered sahpool")
}

async fn reserve_files(n: u32) {
    let p = pool().await;
    p.reserve_minimum_capacity(p.count() + n)
        .await
        .expect("add capacity");
    console_log!(
        "yew-web-core: sahpool: capacity {} files, {} in use: {:?}",
        p.get_capacity(),
        p.count(),
        p.list()
    );
}

/// A unique store directory per run (OPFS persists across runs in the same profile; the
/// test runner's profile is fresh, but a reused one must not see an older store).
fn run_dir(name: &str) -> String {
    format!("yew-w3/{}/{name}", (now() as u64) % 1_000_000)
}

#[wasm_bindgen_test]
async fn restore_from_seed_with_birthday() {
    let Some(fund_url) = option_env!("YEW_WEB_FUND_URL") else {
        console_log!("yew-web-core: no YEW_WEB_FUND_URL; restore test skipped");
        return;
    };
    yew_web_core::install_storage().await.expect("opfs");
    let words = yew_web_core::new_seed_words().expect("seed");
    let tip0 = yew_web_core::latest_height(LWD, NETWORK).await.expect("tip");
    let birthday0 = tip0.saturating_sub(5).max(1);
    let dir_a = run_dir("a");
    reserve_files(6).await;
    open_in(&words, birthday0, &dir_a).await;
    let address_z = yew_web_core::receive_address(None).unwrap();
    let address_s = yew_web_core::receive_address(Some("transparent".into())).unwrap();
    yew_web_core::sync().await.expect("first sync");

    let txid_t = helper(
        fund_url,
        "fund_t",
        &format!("addr={address_s}&zat={FUND_T_ZAT}"),
    )
    .await
    .expect("fund_t");
    let txid_z = helper(
        fund_url,
        "fund",
        &format!("addr={address_z}&zat={FUND_ZAT}&memo={}", MEMO.replace(' ', "%20")),
    )
    .await
    .expect("fund");
    let b = sync_until("both receipts mined", 300.0, |_, b| {
        field_amt(b, "shieldedSpendableZat") >= FUND_ZAT as i64
            && field_amt(b, "yecZat") + field_amt(b, "yecReservedZat") >= FUND_T_ZAT as i64
            && history_row(&txid_t).is_some_and(|r| !field_bool(&r, "pending"))
            && history_row(&txid_z).is_some_and(|r| !field_bool(&r, "pending"))
    })
    .await;
    assert_eq!(field_amt(&b, "shieldedZat"), FUND_ZAT as i64);
    let h_t = field_u64(&history_row(&txid_t).unwrap(), "height");
    let h_z = field_u64(&history_row(&txid_z).unwrap(), "height");
    let memo_a = field_str(&history_row(&txid_z).unwrap(), "memo");
    console_log!(
        "yew-web-core: restore: funded public {txid_t}@{h_t}, private {txid_z}@{h_z} memo {memo_a:?}"
    );
    assert_eq!(memo_a, MEMO, "the memo of a receipt is read by the enhancement");
    yew_web_core::close();
    assert!(yew_web_core::balances().is_err());

    // Restore in a NEW store directory from the seed, birthday = funding height − 2.
    let birthday = h_t.min(h_z).saturating_sub(2).max(1);
    let dir_b = run_dir("b");
    reserve_files(6).await;
    let t0 = now();
    let o = open_in(&words, birthday, &dir_b).await;
    assert_eq!(field_str(&o, "address"), address_z, "the same seed, the same addresses");
    assert_eq!(field_str(&o, "addressS"), address_s);
    assert!(!field_bool(&o, "registered"), "a new store");
    let b = sync_until("restored balances", 300.0, |_, b| {
        field_amt(b, "shieldedSpendableZat") >= FUND_ZAT as i64
            && field_amt(b, "yecZat") + field_amt(b, "yecReservedZat") >= FUND_T_ZAT as i64
            && history_row(&txid_z).is_some_and(|r| field_str(&r, "memo") == MEMO)
    })
    .await;
    console_log!(
        "yew-web-core: restore: both balances and the memo back in {:.0} ms",
        now() - t0
    );
    assert_eq!(field_amt(&b, "shieldedZat"), FUND_ZAT as i64);
    assert_eq!(
        field_amt(&b, "yecZat") + field_amt(&b, "yecReservedZat"),
        FUND_T_ZAT as i64
    );
    assert_eq!(rows_of(&txid_z), 1);
    assert_eq!(rows_of(&txid_t), 1);
    assert_eq!(
        field_u64(&history_row(&txid_z).unwrap(), "height"),
        h_z
    );
    yew_web_core::close();

    // A birthday after the funding: the private note is never scanned (expected), and the
    // public receipt is not asked for either (the transparent sync queries from the birthday).
    let late = h_t.max(h_z) + 1;
    let dir_c = run_dir("c");
    reserve_files(6).await;
    open_in(&words, late, &dir_c).await;
    let b = sync_until("late birthday synced", 300.0, |r, _| {
        field_u64(r, "scanned_height") >= late && field_str(r, "shielded_message").is_empty()
    })
    .await;
    console_log!(
        "yew-web-core: restore: birthday {late} after the funding: shielded {} public {}",
        field_amt(&b, "shieldedZat"),
        field_amt(&b, "yecZat") + field_amt(&b, "yecReservedZat")
    );
    assert_eq!(field_amt(&b, "shieldedZat"), 0, "the note is before the birthday");
    assert!(history_row(&txid_z).is_none());
    assert_eq!(
        field_amt(&b, "yecZat") + field_amt(&b, "yecReservedZat"),
        0,
        "the public side is queried from the birthday too"
    );
    assert!(history_row(&txid_t).is_none());
    yew_web_core::close();
}

#[wasm_bindgen_test]
async fn busy_under_concurrency() {
    yew_web_core::install_storage().await.expect("opfs");
    let words = yew_web_core::new_seed_words().expect("seed");
    let tip0 = yew_web_core::latest_height(LWD, NETWORK).await.expect("tip");
    let dir = run_dir("busy");
    reserve_files(6).await;
    open_in(&words, tip0.saturating_sub(30).max(1), &dir).await;
    yew_web_core::sync().await.expect("first sync");
    let b0 = field_amt(&yew_web_core::balances().unwrap(), "shieldedZat");

    for round in 0..3 {
        let done: Rc<RefCell<Option<Result<JsValue, JsValue>>>> = Rc::new(RefCell::new(None));
        let slot = done.clone();
        wasm_bindgen_futures::spawn_local(async move {
            *slot.borrow_mut() = Some(yew_web_core::sync().await);
        });
        // The first sync is parked at its first await; every other call must say busy.
        sleep_ms(0).await;
        let e = yew_web_core::sync().await.expect_err("second sync");
        assert_eq!(message(&e), "busy: a call is in progress");
        let e = yew_web_core::balances().expect_err("balances");
        assert_eq!(message(&e), "busy: a call is in progress");
        let e = yew_web_core::history(0).expect_err("history");
        assert_eq!(message(&e), "busy: a call is in progress");
        let e = yew_web_core::shielded_balance().expect_err("shielded_balance");
        assert_eq!(message(&e), "busy: a call is in progress");
        let e = yew_web_core::open_at(&words, 1, LWD, NETWORK, &dir)
            .await
            .expect_err("open during a call");
        assert!(message(&e).starts_with("invalid: a wallet is already open"));
        // Also mid-flight (after the network round trips started), not only at the first await.
        let mut busy_mid = 0;
        while done.borrow().is_none() {
            if yew_web_core::balances().is_err() {
                busy_mid += 1;
            }
            sleep_ms(20).await;
        }
        let r = done.borrow_mut().take().unwrap();
        assert!(r.is_ok(), "{}", message(&r.err().unwrap()));
        console_log!("yew-web-core: busy round {round}: {busy_mid} busy answers mid-sync");
        assert!(busy_mid > 0);
        assert!(yew_web_core::balances().is_ok());
    }
    // The store is intact: close, reopen the same directory (the sahpool's one connection per
    // file name was released), the state is there.
    yew_web_core::close();
    let o = open_in(&words, 1, &dir).await;
    assert!(field_bool(&o, "registered"), "the same store");
    let r = yew_web_core::sync().await.expect("sync after reopen");
    assert!(field_str(&r, "shielded_message").is_empty());
    assert_eq!(field_amt(&yew_web_core::balances().unwrap(), "shieldedZat"), b0);
    yew_web_core::close();
}

#[wasm_bindgen_test]
async fn reorg_during_private_sync() {
    let Some(fund_url) = option_env!("YEW_WEB_FUND_URL") else {
        console_log!("yew-web-core: no YEW_WEB_FUND_URL; reorg test skipped");
        return;
    };
    if option_env!("YEW_WEB_NO_REORG").is_some() {
        console_log!("yew-web-core: YEW_WEB_NO_REORG set; reorg test skipped");
        return;
    }
    yew_web_core::install_storage().await.expect("opfs");
    let words = yew_web_core::new_seed_words().expect("seed");
    let tip0 = yew_web_core::latest_height(LWD, NETWORK).await.expect("tip");
    let dir = run_dir("reorg");
    reserve_files(6).await;
    open_in(&words, tip0.saturating_sub(5).max(1), &dir).await;
    yew_web_core::sync().await.expect("first sync");
    let address_z = yew_web_core::receive_address(None).unwrap();
    let txid_z = helper(fund_url, "fund", &format!("addr={address_z}&zat={FUND_ZAT}"))
        .await
        .expect("fund");
    sync_until("private receipt mined", 300.0, |_, b| {
        field_amt(b, "shieldedSpendableZat") >= FUND_ZAT as i64
            && history_row(&txid_z).is_some_and(|r| !field_bool(&r, "pending"))
    })
    .await;
    let h = field_u64(&history_row(&txid_z).unwrap(), "height");
    let tip_before = field_u64(&yew_web_core::sync().await.unwrap(), "tip");
    console_log!("yew-web-core: reorg: {txid_z} mined at {h}; tip {tip_before}; invalidating {h}");

    // The one disturbance of the shared cluster: block h is invalidated, the node mines a
    // longer branch, the funding transaction returns to the mempool and is mined again.
    let t0 = now();
    let r = helper(fund_url, "reorg", &format!("height={h}"))
        .await
        .expect("reorg");
    console_log!("yew-web-core: reorg: {r} in {:.0} ms", now() - t0);

    let t1 = now();
    let b = sync_until("re-synced past the reorg", 400.0, |r, b| {
        // Past the old tip on the new branch, the funding mined again and spendable.
        field_u64(r, "tip") > tip_before
            && field_u64(r, "scanned_height") > tip_before
            && field_amt(b, "shieldedSpendableZat") >= FUND_ZAT as i64
            && history_row(&txid_z).is_some_and(|r| !field_bool(&r, "pending"))
    })
    .await;
    let h2 = field_u64(&history_row(&txid_z).unwrap(), "height");
    console_log!(
        "yew-web-core: reorg: re-synced in {:.0} ms; {txid_z} now at {h2} (was {h}); rows {}",
        now() - t1,
        history_rows().len()
    );
    assert_eq!(
        field_amt(&b, "shieldedZat"),
        FUND_ZAT as i64,
        "the note counted once"
    );
    assert_eq!(field_amt(&b, "shieldedSpendableZat"), FUND_ZAT as i64);
    assert_eq!(rows_of(&txid_z), 1, "one history row");
    assert_eq!(history_rows().len(), 1);
    assert!(h2 >= h, "mined again at or after the invalidated height");
    // A send of the whole balance plans against one note (no phantom second note).
    let other = yew_web_core::new_shielded_address().unwrap();
    let p = yew_web_core::send_yec_preview(other, JsValue::from_str("100000000"), None)
        .await
        .expect("preview after the reorg");
    assert_eq!(field_str(&p, "funding"), "shielded");
    yew_web_core::close();
}
