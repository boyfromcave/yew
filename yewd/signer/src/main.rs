// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! `yewd-signer`: the separate process that holds the seed, member and attestor keys, the
//! sign-once records and the attestation equivocation guard (workspace plan §3b S2, K-24). It
//! listens on a Unix-domain socket with a peer-UID check and answers `yewd_proto::SignRequest`s.
//! Not yet implemented: S0 ships the binary name and the protocol version only.

fn main() {
    eprintln!(
        "yewd-signer: not yet implemented (protocol version {}; plan §3b S2)",
        yewd_proto::PROTO_VERSION
    );
    std::process::exit(2);
}
