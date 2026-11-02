// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! kogany's indexer streams as wake-ups (plan §3b S4 hazards H3, H4).
//!
//! kogany (Zakura) serves the gRPC service `zebra.indexer.rpc.Indexer`
//! (`ref/zakura/crates/zakura-rpc/proto/indexer.proto`) on `[rpc] indexer_listen_addr`. The façade
//! subscribes to `ChainTipChange` (a block connected or a reorg) and `MempoolChange` (a
//! transaction added, invalidated or mined) and wakes the wallet's sync on every message.
//!
//! **Streams are wake-ups, never the source of truth** (H4): a message carries nothing the
//! wallet uses; the wallet then reconciles by JSON-RPC from its last processed hash, as the poll
//! does. A stream that ends or fails is reconnected with backoff, and every (re)connection wakes
//! the wallet once, so a gap while it was away is reconciled at once. The poll stays on beside
//! the streams (`-walletpoll`), so a node without the listener (ycash6) loses nothing.
//!
//! The three messages are written out here with `prost` rather than compiled from the proto: the
//! client reads no field of them, and the façade then needs no `protoc` at build time.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Notify;
use tonic::codegen::http::uri::PathAndQuery;

/// `message Empty {}`.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Empty {}

/// `message BlockHashAndHeight { bytes hash = 1; uint32 height = 2; }`.
#[derive(Clone, PartialEq, prost::Message)]
pub struct BlockHashAndHeight {
    #[prost(bytes = "vec", tag = "1")]
    pub hash: Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub height: u32,
}

/// `message MempoolChangeMessage { ChangeType change_type = 1; bytes tx_hash = 2; bytes auth_digest = 3; }`.
#[derive(Clone, PartialEq, prost::Message)]
pub struct MempoolChangeMessage {
    #[prost(int32, tag = "1")]
    pub change_type: i32,
    #[prost(bytes = "vec", tag = "2")]
    pub tx_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub auth_digest: Vec<u8>,
}

const CHAIN_TIP_CHANGE: &str = "/zebra.indexer.rpc.Indexer/ChainTipChange";
const MEMPOOL_CHANGE: &str = "/zebra.indexer.rpc.Indexer/MempoolChange";

/// Subscribe to both streams of the indexer at `addr` for the life of the process.
pub fn spawn(addr: SocketAddr, wake: Arc<Notify>, debug: bool) {
    tokio::spawn(follow::<BlockHashAndHeight>(
        addr,
        CHAIN_TIP_CHANGE,
        wake.clone(),
        debug,
    ));
    tokio::spawn(follow::<MempoolChangeMessage>(
        addr,
        MEMPOOL_CHANGE,
        wake,
        debug,
    ));
}

async fn follow<M>(addr: SocketAddr, path: &'static str, wake: Arc<Notify>, debug: bool)
where
    M: prost::Message + Default + Send + 'static,
{
    let mut backoff = Duration::from_millis(250);
    loop {
        match stream_once::<M>(addr, path, &wake).await {
            Ok(n) => {
                if debug {
                    eprintln!("yewd: indexer {path}: stream ended after {n} message(s)");
                }
                backoff = Duration::from_millis(250);
            }
            Err(e) => {
                if debug {
                    eprintln!("yewd: indexer {path}: {e}");
                }
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(5));
    }
}

/// One subscription: connect, wake once (reconcile the gap, H4), then wake per message.
async fn stream_once<M>(addr: SocketAddr, path: &'static str, wake: &Notify) -> Result<u64, String>
where
    M: prost::Message + Default + Send + 'static,
{
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
        .map_err(|e| e.to_string())?
        .connect_timeout(Duration::from_secs(5))
        .connect()
        .await
        .map_err(|e| format!("connect: {e}"))?;
    let mut grpc = tonic::client::Grpc::new(channel);
    grpc.ready().await.map_err(|e| format!("ready: {e}"))?;
    let codec = tonic_prost::ProstCodec::<Empty, M>::default();
    let mut stream = grpc
        .server_streaming(
            tonic::Request::new(Empty {}),
            PathAndQuery::from_static(path),
            codec,
        )
        .await
        .map_err(|e| format!("subscribe: {e}"))?
        .into_inner();
    wake.notify_one();
    let mut n = 0u64;
    while let Some(_msg) = stream.message().await.map_err(|e| format!("stream: {e}"))? {
        n += 1;
        wake.notify_one();
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    /// The hand-written messages decode the proto's wire form (field numbers and types).
    #[test]
    fn messages_match_the_proto() {
        // BlockHashAndHeight { hash: [1,2], height: 300 }: tag 1 bytes, tag 2 varint
        let wire = [0x0a, 0x02, 0x01, 0x02, 0x10, 0xac, 0x02];
        let m = BlockHashAndHeight::decode(&wire[..]).unwrap();
        assert_eq!(m.hash, vec![1, 2]);
        assert_eq!(m.height, 300);
        // MempoolChangeMessage { change_type: MINED (2), tx_hash: [9], auth_digest: [] }
        let wire = [0x08, 0x02, 0x12, 0x01, 0x09];
        let m = MempoolChangeMessage::decode(&wire[..]).unwrap();
        assert_eq!(m.change_type, 2);
        assert_eq!(m.tx_hash, vec![9]);
        assert!(Empty {}.encode_to_vec().is_empty());
    }
}
