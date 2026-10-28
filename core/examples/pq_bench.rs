// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! Post-quantum signing latency on the device the binary runs on (README "Device timings"):
//! SLH-DSA-SHA2-128s (the vault owner, scheme 1) and Falcon-512 padded (the YED holder,
//! scheme 2), each as the wallet does it: keygen from the derived 48-byte seed (the signing path
//! re-derives the key and checks its id), sign, verify. Build it for a device target and run it
//! there, e.g. on the iOS simulator:
//!
//!   cargo build -p yew-core --release --example pq_bench --target aarch64-apple-ios-sim
//!   xcrun simctl spawn booted target/aarch64-apple-ios-sim/release/examples/pq_bench [rounds]
//!
//! or on the Android emulator (`cargo ndk -t arm64-v8a build ... --example pq_bench`, then
//! `adb push` it to /data/local/tmp and `adb shell` it). Prints one line per step: min, median
//! and max over the rounds, in milliseconds.
use std::time::Instant;
use yew_core::pq::{verify, PqSeedRoot};

fn stats(name: &str, mut ms: Vec<f64>) {
    ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    println!(
        "{name:<22} n={:<3} min {:>8.2} ms  median {:>8.2} ms  max {:>8.2} ms",
        ms.len(),
        ms[0],
        ms[ms.len() / 2],
        ms[ms.len() - 1]
    );
}

fn main() {
    let rounds: usize = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(10);
    let root = PqSeedRoot::from_seed(&[7u8; 64]);
    for (label, scheme) in [("SLH-DSA-SHA2-128s", 1u8), ("Falcon-512 padded", 2u8)] {
        let (mut kg, mut sg, mut vf) = (Vec::new(), Vec::new(), Vec::new());
        let mut sig_len = 0;
        for i in 0..rounds {
            let mut msg = [0u8; 32];
            msg[0] = i as u8;
            let t = Instant::now();
            let key = if scheme == 1 {
                root.slh_key(i as u32)
            } else {
                root.falcon_key(i as u32)
            };
            kg.push(t.elapsed().as_secs_f64() * 1e3);
            let t = Instant::now();
            let sig = key.sign(&msg);
            sg.push(t.elapsed().as_secs_f64() * 1e3);
            let t = Instant::now();
            assert!(
                verify(scheme, key.public_key(), &sig, &msg),
                "{label}: verify"
            );
            vf.push(t.elapsed().as_secs_f64() * 1e3);
            sig_len = sig.len();
        }
        println!("{label} (signature {sig_len} bytes)");
        stats("  keygen", kg);
        stats("  sign", sg);
        stats("  verify", vf);
    }
}
