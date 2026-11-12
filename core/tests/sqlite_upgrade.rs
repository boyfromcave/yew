// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! A wallet written by an older SQLite opens under the current one (docs/security-review.md Z-14).
//!
//! `tests/fixtures/sqlite-3.51.3/` holds the two native databases a YEW wallet keeps, as the build
//! before the SQLite upgrade wrote them (rusqlite 0.39.0, libsqlite3-sys 0.37.0, bundled SQLite
//! 3.51.3, librustzcash6 cc6068ea): `yew-regtest.sqlite` (the [`Store`]: one address, meta rows)
//! and `shielded/wallet.sqlite` (the `zcash_client_sqlite` store: one Sapling account, imported
//! by viewing key with a birthday at height 1000). The test copies them, opens both through
//! YEW's own paths ([`Store::open`], [`Shielded::open`], which runs the wallet migrations) and
//! reads everything back.
//!
//! Two ignored tests make and re-read the fixture, so the same check runs in both directions:
//! `YEW_SQLITE_FIXTURE_WRITE=<dir> cargo test -p yew-core --test sqlite_upgrade -- --ignored
//! write_fixture` writes one with the build at hand; `YEW_SQLITE_FIXTURE_READ=<dir> … read_fixture`
//! checks one (for example the copy `YEW_SQLITE_FIXTURE_KEEP=<dir>` saves after the main test has
//! opened it with the newer SQLite, read back by the older build).

#![cfg(not(target_arch = "wasm32"))]

use std::path::{Path, PathBuf};

use yew_core::params::Network;
use yew_core::shielded::{Shielded, ShieldedError};
use yew_core::shielded_keys::SaplingAccount;
use yew_core::store::{AddressRow, Store};
use zcash_client_backend::data_api::chain::ChainState;
use zcash_client_backend::data_api::{AccountBirthday, AccountPurpose, WalletRead, WalletWrite};
use zcash_client_sqlite::util::SystemClock;
use zcash_client_sqlite::WalletDb;
use zcash_protocol::consensus::BlockHeight;

const STORE: &str = "yew-regtest.sqlite";
const SHIELDED: &str = "shielded";
/// The account birthday: one above the height of the chain state it is imported with.
const BIRTHDAY: u32 = 1000;
const HASH160: [u8; 20] = [0x5a; 20];

fn account(seed: u8) -> SaplingAccount {
    SaplingAccount::from_seed(&[seed; 64], Network::Regtest).unwrap()
}

fn committed_fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sqlite-3.51.3")
}

fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "yew-sqlite-upgrade-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Copies the two database files (never a `-wal`/`-shm`: the fixture is checkpointed).
fn copy_fixture(from: &Path, to: &Path) {
    std::fs::create_dir_all(to.join(SHIELDED)).unwrap();
    for f in [STORE.to_string(), format!("{SHIELDED}/wallet.sqlite")] {
        std::fs::copy(from.join(&f), to.join(&f)).unwrap_or_else(|e| panic!("{f}: {e}"));
    }
}

fn integrity_ok(path: &Path) {
    let conn = rusqlite::Connection::open(path).unwrap();
    let r: String = conn
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .unwrap();
    assert_eq!(r, "ok", "{}", path.display());
}

/// Opens both stores the way YEW does and checks every row the fixture holds. Returns the
/// SQLite version that wrote the fixture (the Store's `fixture_sqlite` meta row).
fn check(dir: &Path) -> String {
    integrity_ok(&dir.join(STORE));
    integrity_ok(&dir.join(SHIELDED).join("wallet.sqlite"));

    let store = Store::open(dir.join(STORE).to_str().unwrap()).unwrap();
    let written_by = store
        .meta("fixture_sqlite")
        .unwrap()
        .expect("fixture_sqlite");
    assert_eq!(
        store.meta("fixture").unwrap().as_deref(),
        Some("sqlite upgrade")
    );
    let addrs = store.addresses().unwrap();
    assert_eq!(addrs.len(), 1);
    assert_eq!(
        (
            addrs[0].chain,
            addrs[0].index,
            addrs[0].hash160,
            addrs[0].used
        ),
        (0, 7, HASH160, true)
    );
    assert_eq!(addrs[0].address_s, "s-fixture");
    drop(store);

    // The private store: migrations run (none is new), the account is ours, the other seed's is not.
    let shielded_dir = dir.join(SHIELDED);
    let s = Shielded::open(&shielded_dir, Network::Regtest, account(1)).unwrap();
    assert!(s.registered().unwrap());
    let b = s.balance().unwrap();
    assert!(b.registered && b.total_zat == 0);
    drop(s);
    let e = Shielded::open(&shielded_dir, Network::Regtest, account(2)).unwrap_err();
    assert!(matches!(e, ShieldedError::OtherSeed), "{e}");

    let db = WalletDb::for_path(
        shielded_dir.join("wallet.sqlite"),
        yew_core::shielded::ycash_network(Network::Regtest),
        SystemClock,
        rand::rngs::OsRng,
    )
    .unwrap();
    let ids = db.get_account_ids().unwrap();
    assert_eq!(ids.len(), 1);
    assert_eq!(
        db.get_account_birthday(ids[0]).unwrap(),
        BlockHeight::from_u32(BIRTHDAY)
    );
    written_by
}

#[test]
fn opens_a_wallet_written_by_the_previous_sqlite() {
    let dir = scratch("open");
    copy_fixture(&committed_fixture(), &dir);
    let written_by = check(&dir);
    // The fixture crosses the upgrade: written by 3.51.x, read here by >= 3.54.0 (RUSTSEC-2026-0459).
    assert!(
        written_by.starts_with("3.51."),
        "fixture written by {written_by}"
    );
    assert!(
        rusqlite::version_number() >= 3_054_000,
        "linked SQLite {}",
        rusqlite::version()
    );
    // Opened again: nothing the first open wrote stops a second.
    check(&dir);
    if let Ok(keep) = std::env::var("YEW_SQLITE_FIXTURE_KEEP") {
        copy_fixture(&dir, Path::new(&keep));
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Writes a fixture with the SQLite this build links (see the module docs).
#[test]
#[ignore = "makes the fixture; YEW_SQLITE_FIXTURE_WRITE=<dir>"]
fn write_fixture() {
    let dir =
        PathBuf::from(std::env::var("YEW_SQLITE_FIXTURE_WRITE").expect("YEW_SQLITE_FIXTURE_WRITE"));
    std::fs::create_dir_all(dir.join(SHIELDED)).unwrap();

    let store = Store::open(dir.join(STORE).to_str().unwrap()).unwrap();
    store.set_meta("fixture", "sqlite upgrade").unwrap();
    store
        .set_meta("fixture_sqlite", rusqlite::version())
        .unwrap();
    store
        .insert_address(&AddressRow {
            chain: 0,
            index: 7,
            address_s: "s-fixture".into(),
            address_ye: "yb-fixture".into(),
            hash160: HASH160,
            used: true,
        })
        .unwrap();
    drop(store);

    // Creates wallet.sqlite and runs the migrations, then registers the account the way the light
    // library does (viewing key and birthday) without a server.
    let shielded_dir = dir.join(SHIELDED);
    drop(Shielded::open(&shielded_dir, Network::Regtest, account(1)).unwrap());
    let mut db = WalletDb::for_path(
        shielded_dir.join("wallet.sqlite"),
        yew_core::shielded::ycash_network(Network::Regtest),
        SystemClock,
        rand::rngs::OsRng,
    )
    .unwrap();
    let extsk =
        sapling_crypto::zip32::ExtendedSpendingKey::from_bytes(&account(1).spending_key_bytes())
            .unwrap();
    let usk = x402_ycash_light::keys::usk_from_extsk(&extsk);
    let birthday = AccountBirthday::from_parts(
        ChainState::empty(
            BlockHeight::from_u32(BIRTHDAY - 1),
            zcash_primitives::block::BlockHash([0x11; 32]),
        ),
        None,
    );
    db.import_account_ufvk(
        "fixture",
        &usk.to_unified_full_viewing_key(),
        &birthday,
        AccountPurpose::Spending { derivation: None },
        None,
    )
    .unwrap();
    drop(db);
    for f in ["-wal", "-shm", "-journal"] {
        for base in [dir.join(STORE), shielded_dir.join("wallet.sqlite")] {
            let p = PathBuf::from(format!("{}{f}", base.display()));
            assert!(!p.exists(), "{} left behind", p.display());
        }
    }
    check(&dir);
}

/// Checks a fixture with the SQLite this build links (see the module docs).
#[test]
#[ignore = "reads a fixture; YEW_SQLITE_FIXTURE_READ=<dir>"]
fn read_fixture() {
    let from =
        PathBuf::from(std::env::var("YEW_SQLITE_FIXTURE_READ").expect("YEW_SQLITE_FIXTURE_READ"));
    let dir = scratch("read");
    copy_fixture(&from, &dir);
    let written_by = check(&dir);
    eprintln!(
        "sqlite_upgrade: fixture written by SQLite {written_by}, read by {}",
        rusqlite::version()
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
