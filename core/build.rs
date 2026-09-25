//! Compiles the pinned lightwalletd protos (`../proto/*.proto`, pinned in `../proto/PIN`) into
//! client stubs for `CompactTxStreamer` and `YellowbackStreamer` (plan §3.1 `net/`).
//! Uses the `protoc` on PATH (or `PROTOC`); nothing is vendored.

use std::path::PathBuf;

fn main() {
    let proto_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../proto");
    let protos =
        ["compact_formats.proto", "service.proto", "yellowback.proto"].map(|f| proto_dir.join(f));
    for p in &protos {
        println!("cargo:rerun-if-changed={}", p.display());
    }
    println!("cargo:rerun-if-changed={}", proto_dir.join("PIN").display());
    println!("cargo:rerun-if-env-changed=PROTOC");
    tonic_prost_build::configure()
        .build_server(false)
        .build_client(true)
        .compile_protos(&protos, &[proto_dir])
        .expect("protoc failed: install protobuf (brew install protobuf / apt install protobuf-compiler)");
}
