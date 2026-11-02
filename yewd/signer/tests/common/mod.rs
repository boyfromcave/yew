// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The pinned vector files, read by path (never copied): `$<env>`, else kogany's
//! `testdata/yellowback/` beside yew, else yew's own byte-identical copy `core/tests/vectors/`.
//! Whichever is read must hash to the file's `vector` line in `yewd/PIN`.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use yew_core::keys;

pub fn pinned_sha(file: &str) -> String {
    let pin =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../PIN")).unwrap();
    pin.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.len() >= 3 && f[0] == "vector" && f[1] == file).then(|| f[2].to_string())
        })
        .next()
        .unwrap_or_else(|| panic!("yewd/PIN has no vector line for {file}"))
}

pub fn load(file: &str, env: &str) -> (PathBuf, serde_json::Value) {
    let here = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut c = Vec::new();
    if let Some(p) = std::env::var_os(env) {
        c.push(PathBuf::from(p));
    }
    for up in ["../../../kogany", "../../../../kogany"] {
        c.push(here.join(up).join("testdata/yellowback").join(file));
    }
    c.push(here.join("../../core/tests/vectors").join(file));
    let want = pinned_sha(file);
    for p in &c {
        let Ok(bytes) = std::fs::read(p) else {
            continue;
        };
        assert_eq!(
            keys::hex(&keys::sha256(&bytes)),
            want,
            "{} does not hash to yewd/PIN's value",
            p.display()
        );
        return (p.clone(), serde_json::from_slice(&bytes).unwrap());
    }
    panic!("{file} not found (tried {c:?})");
}

pub fn unhex(v: &serde_json::Value) -> Vec<u8> {
    keys::unhex(v.as_str().unwrap()).unwrap()
}

pub fn arr<const N: usize>(v: &serde_json::Value) -> [u8; N] {
    unhex(v).try_into().unwrap()
}
