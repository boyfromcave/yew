//! The typed T0 client over `CompactTxStreamer` (plan §1.4, §3.2; yodl 0.4.6 baseline):
//! `GetLightdInfo`, `GetLatestBlock`, `GetAddressUtxos`, `GetTaddressTxids` (a stream of raw
//! transactions with heights), `GetTaddressBalance`, `SendTransaction`.
//!
//! Nothing here interprets bytes: raw transactions go to [`crate::tx::Transaction::parse`],
//! scripts to [`crate::coins`].

use tonic::transport::Channel;

use super::rpc;
use super::{CompactTxStreamerClient, NetError, Server};
use crate::params::Network;

/// What `GetLightdInfo` told us, reduced to what the wallet keeps (plan §3.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LightdInfo {
    /// `chainName` as reported.
    pub chain_name: String,
    /// The network it maps to, if known.
    pub network: Option<Network>,
    /// `consensusBranchId`, parsed from the hex string the server sends.
    pub branch_id: u32,
    /// `blockHeight`.
    pub block_height: u64,
    /// `saplingActivationHeight`.
    pub sapling_activation_height: u64,
    /// `taddrSupport` (must be true).
    pub taddr_support: bool,
    /// `version`, `vendor` (display only).
    pub version: String,
    /// `zcashdBuild` (display only).
    pub zcashd_build: String,
}

/// One entry of `GetAddressUtxos`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Utxo {
    /// The address the server matched.
    pub address: String,
    /// The txid in internal byte order.
    pub txid: [u8; 32],
    /// The output index.
    pub index: u32,
    /// The scriptPubKey.
    pub script: Vec<u8>,
    /// The value in zatoshi.
    pub value_zat: i64,
    /// The height it was mined at.
    pub height: u64,
}

/// A raw transaction with the height it was mined at (`RawTransaction`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawTx {
    /// The serialized transaction.
    pub data: Vec<u8>,
    /// The height (`u64::MAX` when the server reports −1, i.e. mempool).
    pub height: u64,
}

/// The connected client.
#[derive(Clone, Debug)]
pub struct CompactClient {
    inner: CompactTxStreamerClient<Channel>,
}

/// Page size for `GetAddressUtxos` (`maxEntries`; 0 means unlimited on the server, but a page
/// keeps memory bounded on a phone).
const UTXO_PAGE: u32 = 1000;

impl CompactClient {
    /// Connect to `server`.
    pub async fn connect(server: &Server) -> Result<CompactClient, NetError> {
        let channel = server.connect().await?;
        Ok(CompactClient {
            inner: CompactTxStreamerClient::new(channel),
        })
    }

    /// Wrap an existing channel (tests, or sharing with the Yellowback client).
    pub fn from_channel(channel: Channel) -> CompactClient {
        CompactClient {
            inner: CompactTxStreamerClient::new(channel),
        }
    }

    /// `GetLightdInfo`.
    pub async fn lightd_info(&mut self) -> Result<LightdInfo, NetError> {
        let i = self
            .inner
            .get_lightd_info(rpc::Empty {})
            .await?
            .into_inner();
        let branch_id = u32::from_str_radix(i.consensus_branch_id.trim_start_matches("0x"), 16)
            .map_err(|_| {
                NetError::Mismatch(format!("bad consensusBranchId {:?}", i.consensus_branch_id))
            })?;
        Ok(LightdInfo {
            network: Network::from_name(&i.chain_name),
            chain_name: i.chain_name,
            branch_id,
            block_height: i.block_height,
            sapling_activation_height: i.sapling_activation_height,
            taddr_support: i.taddr_support,
            version: format!("{} {}", i.vendor, i.version),
            zcashd_build: i.zcashd_build,
        })
    }

    /// `GetLightdInfo`, then check it is a server for `network` with transparent support
    /// (plan §3.5).
    pub async fn lightd_info_for(&mut self, network: Network) -> Result<LightdInfo, NetError> {
        let info = self.lightd_info().await?;
        if info.network != Some(network) {
            return Err(NetError::Mismatch(format!(
                "server chain is {:?}, wallet is {}",
                info.chain_name,
                network.chain_name()
            )));
        }
        if !info.taddr_support {
            return Err(NetError::Mismatch("server has no taddrSupport".into()));
        }
        Ok(info)
    }

    /// `GetLatestBlock`: the tip height.
    pub async fn latest_height(&mut self) -> Result<u64, NetError> {
        Ok(self
            .inner
            .get_latest_block(rpc::ChainSpec {})
            .await?
            .into_inner()
            .height)
    }

    /// `GetBlock(height)`: the block hash in internal (wire) byte order — what the node's
    /// `uint256::begin()` gives and what `AttestMessage` hashes (`attest.h:19-22`);
    /// lightwalletd's `CompactBlock.hash` is `GetEncodableHash`, little-endian wire order
    /// (`lightwalletd-dd/parser/block.go:52-55`).
    pub async fn block_hash(&mut self, height: u64) -> Result<[u8; 32], NetError> {
        let b = self
            .inner
            .get_block(rpc::BlockId {
                height,
                hash: Vec::new(),
            })
            .await?
            .into_inner();
        let mut h = [0u8; 32];
        if b.hash.len() != 32 {
            return Err(NetError::Mismatch(format!(
                "block {height}: hash of {} bytes",
                b.hash.len()
            )));
        }
        h.copy_from_slice(&b.hash);
        Ok(h)
    }

    /// `GetAddressUtxos` for `addresses` from `start_height`, paged by `maxEntries`. The proto
    /// has no cursor, so paging re-asks with a larger `maxEntries` until the reply is shorter
    /// than the page; the last page is the whole set.
    pub async fn address_utxos(
        &mut self,
        addresses: &[String],
        start_height: u64,
    ) -> Result<Vec<Utxo>, NetError> {
        let mut max_entries = UTXO_PAGE;
        loop {
            let reply = self
                .inner
                .get_address_utxos(rpc::GetAddressUtxosArg {
                    addresses: addresses.to_vec(),
                    start_height,
                    max_entries,
                })
                .await?
                .into_inner();
            let n = reply.address_utxos.len() as u32;
            if n < max_entries {
                return Ok(reply.address_utxos.into_iter().map(from_reply).collect());
            }
            max_entries = max_entries.saturating_mul(4);
            if max_entries == u32::MAX {
                return Ok(reply.address_utxos.into_iter().map(from_reply).collect());
            }
        }
    }

    /// `GetTaddressTxids` for one address over `[start, end]`: every transaction touching it,
    /// as raw bytes with heights (the yodl baseline streams the transactions themselves).
    pub async fn taddress_txs(
        &mut self,
        address: &str,
        start: u64,
        end: u64,
    ) -> Result<Vec<RawTx>, NetError> {
        let filter = rpc::TransparentAddressBlockFilter {
            address: address.to_string(),
            range: Some(rpc::BlockRange {
                start: Some(rpc::BlockId {
                    height: start,
                    hash: Vec::new(),
                }),
                end: Some(rpc::BlockId {
                    height: end,
                    hash: Vec::new(),
                }),
            }),
        };
        let mut stream = self.inner.get_taddress_txids(filter).await?.into_inner();
        let mut out = Vec::new();
        while let Some(t) = stream.message().await? {
            out.push(RawTx {
                data: t.data,
                height: t.height,
            });
        }
        Ok(out)
    }

    /// `GetTaddressBalance`: the server's `sum(nValue)` over the addresses — display and
    /// cross-check only, never the wallet's balance (plan §3.7: balances come from classes).
    pub async fn taddress_balance(&mut self, addresses: &[String]) -> Result<i64, NetError> {
        let b = self
            .inner
            .get_taddress_balance(rpc::AddressList {
                addresses: addresses.to_vec(),
            })
            .await?
            .into_inner();
        Ok(b.value_zat)
    }

    /// `SendTransaction`: broadcast `raw`. Returns the node's reply text (the txid on success).
    pub async fn send_transaction(&mut self, raw: Vec<u8>) -> Result<String, NetError> {
        let r = self
            .inner
            .send_transaction(rpc::RawTransaction {
                data: raw,
                height: 0,
            })
            .await?
            .into_inner();
        if r.error_code != 0 {
            return Err(NetError::SendRejected {
                code: r.error_code,
                message: r.error_message,
            });
        }
        // lightwalletd relays zcashd's JSON reply, so the txid arrives quoted.
        Ok(r.error_message.trim().trim_matches('"').to_string())
    }
}

fn from_reply(r: rpc::GetAddressUtxosReply) -> Utxo {
    let mut txid = [0u8; 32];
    if r.txid.len() == 32 {
        txid.copy_from_slice(&r.txid);
    }
    Utxo {
        address: r.address,
        txid,
        index: r.index.max(0) as u32,
        script: r.script,
        value_zat: r.value_zat,
        height: r.height,
    }
}
