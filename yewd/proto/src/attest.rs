// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The attestor role's messages (the cancel co-signature, its `"YC"` list, `signmessage`'s
//! digest, RED-4): moved to yew-core (`yew_core::cosign`, beta4 item 3d, the light attestor's
//! cancel builder) and re-exported here unchanged, so every `yewd_proto::attest::…` path keeps
//! working.

pub use yew_core::cosign::*;
