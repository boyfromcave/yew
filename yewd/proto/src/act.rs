// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The `YV` act codec, the two set messages and the bond script: moved to yew-core
//! (`yew_core::act`, beta4 item 3d, the light attestor builds the same acts without a node) and
//! re-exported here unchanged, so every `yewd_proto::act::…` path keeps working.

pub use yew_core::act::*;
