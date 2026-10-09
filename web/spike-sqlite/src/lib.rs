//! W0 spike (yew/web plan §2, I-4): the Sapling wallet store on OPFS from wasm32.
//! 1. sqlite-wasm-rs + the sahpool VFS (OPFS) is installed as the default VFS;
//! 2. zcash_client_sqlite's WalletDb opens on it and its migrations run (the full schema);
//! 3. a second open reads what the first wrote (persistence across connections).
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand::rngs::OsRng;
use wasm_bindgen::prelude::*;
use zcash_client_sqlite::util::Clock;
use zcash_client_sqlite::wallet::init::init_wallet_db;
use zcash_client_sqlite::WalletDb;
use zcash_protocol::consensus::Network;

/// `SystemTime::now()` is unavailable on wasm32-unknown-unknown; the browser's clock instead.
#[derive(Clone, Copy)]
pub struct JsClock;
impl Clock for JsClock {
    fn now(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_millis(js_sys::Date::now() as u64)
    }
}

fn js(e: impl std::fmt::Debug) -> JsValue {
    JsValue::from_str(&format!("{e:?}"))
}

pub async fn install_opfs() -> Result<(), JsValue> {
    use sqlite_wasm_vfs::sahpool::{install, OpfsSAHPoolCfg};
    install::<sqlite_wasm_rs::WasmOsCallback>(&OpfsSAHPoolCfg::default(), true).await.map_err(js)?;
    Ok(())
}

/// Opens the wallet database at `path` on OPFS and runs every migration; returns the number
/// of tables in the resulting schema.
#[wasm_bindgen]
pub async fn spike_wallet(path: &str) -> Result<u32, JsValue> {
    install_opfs().await?;
    let mut db = WalletDb::for_path(path, Network::MainNetwork, JsClock, OsRng).map_err(js)?;
    init_wallet_db(&mut db, None).map_err(js)?;
    // sahpool tracks open files by name: close the wallet's connection before opening another on the
    // same file (two handles on one name trip its debug assertion on the second close).
    drop(db);
    let conn = rusqlite::Connection::open(path).map_err(js)?;
    let n: u32 = conn
        .query_row("SELECT COUNT(*) FROM sqlite_master WHERE type='table'", [], |r| r.get(0))
        .map_err(js)?;
    Ok(n)
}

/// Plain SQLite round trip on OPFS: insert, reopen, read back.
#[wasm_bindgen]
pub async fn spike_persist(path: &str) -> Result<i64, JsValue> {
    install_opfs().await?;
    {
        let conn = rusqlite::Connection::open(path).map_err(js)?;
        conn.execute_batch("CREATE TABLE IF NOT EXISTS t(x INTEGER); INSERT INTO t VALUES(41);").map_err(js)?;
    }
    let conn = rusqlite::Connection::open(path).map_err(js)?;
    conn.query_row("SELECT MAX(x)+1 FROM t", [], |r| r.get(0)).map_err(js)
}
