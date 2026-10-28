// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The typed T1–T3 client over `YellowbackStreamer` (plan §1.4, §3.5, §4 rule 1; lightwalletd
//! plan §3, §4.1, §5): every method of `lightwalletd-dd/walletrpc/yellowback.proto`, each a
//! thin proxy of one read-only `yed_*` RPC on the server's node. Streams are collected.
//!
//! Contract rule 1 lives in [`YellowbackClient::probe`]: `UNIMPLEMENTED` ⇒ no Yellowback here
//! (T0 only, YED hidden); an `rpcversion` other than [`KNOWN_RPCVERSION`] ⇒ refused; YED is
//! shown only when `enabled && upgrade.status == "active"` (rpcversion 5: the vault upgrade's
//! status, `yed_getactivation`; the v3 activation state machine is gone). Errors (lightwalletd plan §3.3):
//! a node RPC error arrives as `FAILED_PRECONDITION` with the node's identifier
//! (`change-floor: …`, `tx-not-found`, …) and is mapped to [`NetError::Node`] with that
//! identifier split off; transport failures to the node are `UNAVAILABLE`.
//!
//! Nothing here interprets a verdict: [`crate::gate`] reads [`Validation`], [`crate::sync`]
//! reads [`Token`] and `YedTxInfo`. The remaining results are returned as the generated
//! messages (`super::rpc`), whose field names are the node contract's JSON names.

use tonic::Code;

use super::rpc;
use super::{limits, Channel, NetError, Server, YellowbackStreamerClient};
use crate::tx::{txid_from_hex, OutPoint};

/// The node `rpcversion` this build implements (`ycash-dd/doc/yellowback-rpc-contract.json`;
/// lightwalletd plan §3.4: "a client refuses an `rpcversion` it does not know"). `5` is the
/// vault upgrade (`ycash-dd/doc/yellowback-rpc.md`, branch `upgrade/vault`): YED is a consensus
/// module of the vault primitive, the vault is the V template, a claim moves it into intents.
/// `6` is the in-term claims line this build implements (branch `upgrade/vault-in-term`, the
/// workspace's `docs/plans/yellowback-in-term-claims-plan.md` §4.1): `ListClaimable` lists every
/// ACTIVE vault whose claim branch is open, in term too, with `claimable` true or false; the
/// params carry `inTermClaims`, `claimThresholdBps` and `earlyRedeemFeeBps`. The match stays
/// exact: an rpcversion-5 node's rows would read as `claimable: false`, which is not what it meant.
/// `7` is the post-quantum line this build implements (branch `upgrade/quantum-vaults`, the
/// workspace's `docs/plans/yellowback-quantum-spec.md` §6.2): every vault owner is a post-quantum
/// key (`ownerScheme` + `ownerHash`, the 53-character `ownerAddress`; no public key on chain), a
/// MINT's payload is version 4 (`attest.mintPayloadVersion`), and `params.pq` carries the owner
/// schemes, the Falcon activation and the size-priced fee rate. Exact again: an rpcversion-6
/// node would hand back secp256k1 owners this build can neither sign for nor check.
/// `8` is the fee structure this build implements (branch `q/fees`, the workspace's
/// `docs/plans/yellowback-quantum-fees-spec.md` §3.4, owner decisions D-Q-23..D-Q-26): the protocol fee
/// is dollars of the debt in marginal bands at the vault's stored `pMint` (`params.fees.protocol`,
/// `YedVault.pMint`), the early-redeem fee is of the debt, network fees are dollars per KB at the
/// attested price (`params.fees.network`), `maxMintCents` is $100,000, `params.feeMinZat` /
/// `feeBps` and `GetFeePayee`'s collateral and fee are gone. Exact again: an rpcversion-7 node
/// charges a collateral fee this build no longer computes.
pub const KNOWN_RPCVERSION: i64 = 8;

/// The upgrade status string that means "active" (`YellowbackActivation.status`, rpcversion 5:
/// `"pending"` | `"active"`).
pub const STATUS_ACTIVE: &str = "active";

/// The largest address list `GetAddressTokens` accepts per call (`yed_listtokens`: 1..100).
pub const TOKENS_MAX_ADDRESSES: usize = 100;

/// What [`YellowbackClient::probe`] found (contract rule 1).
#[derive(Clone, Debug, PartialEq)]
pub enum Availability {
    /// The server answered `UNIMPLEMENTED`: an old server, the flag off, or a stock node. T0
    /// only; nothing YED-related is shown.
    Absent,
    /// The service answered with a known `rpcversion`.
    Present {
        /// `GetYellowbackInfo` as returned.
        info: Box<rpc::YellowbackInfo>,
        /// `info.enabled`.
        enabled: bool,
        /// `info.upgrade.status == "active"`.
        active: bool,
    },
}

impl Availability {
    /// True when YED features may be shown and used (`enabled && active`).
    pub fn usable(&self) -> bool {
        matches!(
            self,
            Availability::Present {
                enabled: true,
                active: true,
                ..
            }
        )
    }
}

/// One live YED output of an own address (`YedToken`; `yed_listtokens`): the authoritative
/// UTXO set of the TOKEN class (D-W-8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token {
    /// The outpoint (txid in internal order).
    pub outpoint: OutPoint,
    /// The assigned cents.
    pub cents: u64,
    /// `valueZat` (`TOKEN_VALUE`).
    pub value_zat: i64,
    /// The height the token was created at.
    pub height: i64,
    /// The `yb…` form.
    pub address: String,
    /// The `s…` form.
    pub transparent_address: String,
}

/// `ValidateRawTransaction`'s answer (`YedValidation`; `yed_validaterawtransaction`), the gate's
/// input (D-W-5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Validation {
    /// Scripts verify and the §3.8 dry run passed at the tip.
    pub valid: bool,
    /// The verdict identifier (`"ok"` or a rule name).
    pub verdict: String,
    /// Cents the transaction would burn.
    pub burned: i64,
    /// An enforcing miner would refuse it (vault spends; MP-1).
    pub would_be_rejected: bool,
    /// RED-1..4 for a vault spend.
    pub block_valid: bool,
    /// The MP-1 expiry bound.
    pub mempool_expiry_ok: bool,
    /// Inputs the index does not know (unconfirmed parents).
    pub unconfirmed_inputs: Vec<OutPoint>,
    /// The payload type name (`""` when non-Yellowback).
    pub tx_type: String,
    /// `"owner"`, `"claim"` or `""`.
    pub path: String,
    /// Cents in.
    pub yed_in: i64,
    /// Cents out.
    pub yed_out: i64,
    /// The enforcement fee it pays.
    pub fee_zat: i64,
    /// The fee payee.
    pub payee: String,
}

/// The connected client.
#[derive(Clone, Debug)]
pub struct YellowbackClient {
    inner: YellowbackStreamerClient<Channel>,
}

/// Map a gRPC status to the client's error (lightwalletd plan §3.3).
fn map_status(s: tonic::Status) -> NetError {
    match s.code() {
        Code::Unimplemented => NetError::Unimplemented,
        Code::FailedPrecondition => {
            let message = s.message().to_string();
            let identifier = message.split(':').next().unwrap_or("").trim().to_string();
            NetError::Node {
                identifier,
                message,
            }
        }
        _ => NetError::Status(s),
    }
}

/// lightwalletd-dd's per-peer limiter on this service (`frontend/yellowback_ratelimit.go`: a
/// burst of 20 calls, one more per second) answers `RESOURCE_EXHAUSTED` when a wallet with many
/// vaults syncs on a fast link. Every call this client makes is a read or a dry run (nothing here
/// broadcasts), so it is paced: wait one refill interval and ask again, at most
/// [`PACE_ATTEMPTS`] times (a full burst refills in 20 s), then return the original error.
const PACE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
/// See [`PACE_INTERVAL`].
const PACE_ATTEMPTS: u32 = 25;

async fn paced<T, F, Fut>(f: F) -> Result<T, tonic::Status>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, tonic::Status>>,
{
    paced_with(PACE_INTERVAL, PACE_ATTEMPTS, f).await
}

/// [`paced`] with the interval and the attempt bound given (the unit test's fast clock).
async fn paced_with<T, F, Fut>(
    interval: std::time::Duration,
    attempts: u32,
    mut f: F,
) -> Result<T, tonic::Status>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, tonic::Status>>,
{
    let mut tries = 1;
    loop {
        match f().await {
            Err(s) if s.code() == Code::ResourceExhausted && tries < attempts => {
                tries += 1;
                tokio::time::sleep(interval).await;
            }
            r => return r,
        }
    }
}

/// Collect a server stream up to `limit` messages (audit G-7).
async fn collect<T>(
    stream: &mut tonic::Streaming<T>,
    what: &'static str,
    limit: usize,
) -> Result<Vec<T>, NetError> {
    let mut out = Vec::new();
    while let Some(v) = stream.message().await.map_err(map_status)? {
        if out.len() >= limit {
            return Err(NetError::TooLarge { what, limit });
        }
        out.push(v);
    }
    Ok(out)
}

fn outpoint_of(txid: &str, vout: u32) -> Result<OutPoint, NetError> {
    let txid =
        txid_from_hex(txid).map_err(|e| NetError::Mismatch(format!("txid {txid:?}: {e}")))?;
    Ok(OutPoint { txid, n: vout })
}

impl YellowbackClient {
    /// Connect to `server`.
    pub async fn connect(server: &Server) -> Result<YellowbackClient, NetError> {
        Ok(YellowbackClient::from_channel(server.connect().await?))
    }

    /// Wrap an existing channel (shared with the [`super::CompactClient`]).
    pub fn from_channel(channel: Channel) -> YellowbackClient {
        YellowbackClient {
            inner: YellowbackStreamerClient::new(channel),
        }
    }

    /// Contract rule 1: `GetYellowbackInfo`; `UNIMPLEMENTED` ⇒ [`Availability::Absent`]; an
    /// `rpcversion` other than [`KNOWN_RPCVERSION`] ⇒ [`NetError::UnknownRpcVersion`];
    /// otherwise [`Availability::Present`] with the `enabled && active` gate evaluated.
    pub async fn probe(&mut self) -> Result<Availability, NetError> {
        let info = match paced(|| {
            let mut c = self.inner.clone();
            let req = rpc::Empty {};
            async move { c.get_yellowback_info(req).await }
        })
        .await
        {
            Ok(r) => r.into_inner(),
            Err(s) if s.code() == Code::Unimplemented => return Ok(Availability::Absent),
            Err(s) => return Err(map_status(s)),
        };
        if info.rpcversion != KNOWN_RPCVERSION {
            return Err(NetError::UnknownRpcVersion(info.rpcversion));
        }
        let enabled = info.enabled;
        let active = info
            .upgrade
            .as_ref()
            .map(|a| a.status == STATUS_ACTIVE)
            .unwrap_or(false);
        Ok(Availability::Present {
            info: Box::new(info),
            enabled,
            active,
        })
    }

    /// `GetYellowbackInfo` (`yed_getinfo`), unchecked.
    pub async fn info(&mut self) -> Result<rpc::YellowbackInfo, NetError> {
        Ok(paced(|| {
            let mut c = self.inner.clone();
            let req = rpc::Empty {};
            async move { c.get_yellowback_info(req).await }
        })
        .await
        .map_err(map_status)?
        .into_inner())
    }

    /// `GetPrice` (`yed_getprice [height]`; 0 = the index tip). `pMint` is the display price
    /// (plan §1.1); a field of 0 means "undefined" on the wire (proto3 has no null).
    pub async fn price(&mut self, height: u32) -> Result<rpc::YedPrice, NetError> {
        Ok(paced(|| {
            let mut c = self.inner.clone();
            let req = rpc::HeightFilter { height };
            async move { c.get_price(req).await }
        })
        .await
        .map_err(map_status)?
        .into_inner())
    }

    /// `GetStats` (`yed_getstats`).
    pub async fn stats(&mut self) -> Result<rpc::YellowbackStats, NetError> {
        Ok(paced(|| {
            let mut c = self.inner.clone();
            let req = rpc::Empty {};
            async move { c.get_stats(req).await }
        })
        .await
        .map_err(map_status)?
        .into_inner())
    }

    /// `GetActivation` (`yed_getactivation`).
    pub async fn activation(&mut self) -> Result<rpc::YellowbackActivation, NetError> {
        Ok(paced(|| {
            let mut c = self.inner.clone();
            let req = rpc::Empty {};
            async move { c.get_activation(req).await }
        })
        .await
        .map_err(map_status)?
        .into_inner())
    }

    /// `GetTxInfo` (`yed_gettxinfo <txid>`): the index's `TxLog` record — the verdict every
    /// history label derives from (contract rule 3). `txid` in display order. A txid the index
    /// does not know is [`NetError::Node`] with identifier `tx-not-found`.
    pub async fn tx_info(&mut self, txid: &str) -> Result<rpc::YedTxInfo, NetError> {
        Ok(paced(|| {
            let mut c = self.inner.clone();
            let req = rpc::YedTxid {
                txid: txid.to_string(),
            };
            async move { c.get_tx_info(req).await }
        })
        .await
        .map_err(map_status)?
        .into_inner())
    }

    /// `GetChainInfo` (lightwalletd-dd 0b3448e+, x402 X-F71): the next block's consensus branch
    /// id (`getblockchaininfo.consensus.nextblock`) and the server's height. `None` when the
    /// server predates it (`UNIMPLEMENTED`); then the chaintip id of `GetLightdInfo` is the best
    /// available, wrong only on the block before a network upgrade. Used by the shielded spend
    /// path (`shielded.rs`) to refuse building with branch-id parameters the next block rejects.
    pub async fn chain_info(&mut self) -> Result<Option<(u64, u32)>, NetError> {
        match paced(|| {
            let mut c = self.inner.clone();
            let req = rpc::Empty {};
            async move { c.get_chain_info(req).await }
        })
        .await
        {
            Ok(r) => {
                let c = r.into_inner();
                let id = u32::from_str_radix(c.next_block_branch_id.trim_start_matches("0x"), 16)
                    .map_err(|_| {
                    NetError::Mismatch(format!(
                        "bad nextBlockBranchId {:?}",
                        c.next_block_branch_id
                    ))
                })?;
                Ok(Some((c.block_height, id)))
            }
            Err(s) if s.code() == Code::Unimplemented => Ok(None),
            Err(s) => Err(map_status(s)),
        }
    }

    /// `ValidateRawTransaction` (`yed_validaterawtransaction <hex>`): the dry run of §3.8 at
    /// the tip plus script verification. Never commits anything.
    pub async fn validate_raw(&mut self, raw: Vec<u8>) -> Result<Validation, NetError> {
        let v = paced(|| {
            let mut c = self.inner.clone();
            let req = rpc::RawTransaction {
                data: raw.clone(),
                height: 0,
            };
            async move { c.validate_raw_transaction(req).await }
        })
        .await
        .map_err(map_status)?
        .into_inner();
        let mut unconfirmed_inputs = Vec::with_capacity(v.unconfirmed_inputs.len());
        for o in &v.unconfirmed_inputs {
            unconfirmed_inputs.push(outpoint_of(&o.txid, o.vout)?);
        }
        Ok(Validation {
            valid: v.valid,
            verdict: v.verdict,
            burned: v.burned,
            would_be_rejected: v.would_be_rejected,
            block_valid: v.block_valid,
            mempool_expiry_ok: v.mempool_expiry_ok,
            unconfirmed_inputs,
            tx_type: v.r#type,
            path: v.path,
            yed_in: v.yed_in,
            yed_out: v.yed_out,
            fee_zat: v.fee_zat,
            payee: v.payee,
        })
    }

    /// `DecodePayload` (`yed_decodepayload <hex>`): the node's parse of a payload, for
    /// cross-checking [`crate::payload`] — never for display in the app, which decodes locally.
    pub async fn decode_payload(&mut self, hex: &str) -> Result<rpc::YedPayload, NetError> {
        Ok(paced(|| {
            let mut c = self.inner.clone();
            let req = rpc::YedHex {
                hex: hex.to_string(),
            };
            async move { c.decode_payload(req).await }
        })
        .await
        .map_err(map_status)?
        .into_inner())
    }

    /// `GetVault` (`yed_getvault <txid>`).
    pub async fn vault(&mut self, txid: &str) -> Result<rpc::YedVault, NetError> {
        Ok(paced(|| {
            let mut c = self.inner.clone();
            let req = rpc::YedTxid {
                txid: txid.to_string(),
            };
            async move { c.get_vault(req).await }
        })
        .await
        .map_err(map_status)?
        .into_inner())
    }

    /// `ListVaults` (`yed_listvaults [status] [count] [skip]`), collected.
    pub async fn list_vaults(
        &mut self,
        status: &str,
        count: u32,
        skip: u32,
    ) -> Result<Vec<rpc::YedVault>, NetError> {
        let mut stream = paced(|| {
            let mut c = self.inner.clone();
            let req = rpc::YedVaultFilter {
                status: status.to_string(),
                count,
                skip,
            };
            async move { c.list_vaults(req).await }
        })
        .await
        .map_err(map_status)?
        .into_inner();
        collect(&mut stream, "vaults", limits::MAX_VAULTS).await
    }

    /// `ListVaultOutputs` (`vault_list {tag, setid, owner, kind}`, upgrade plan §15.8): the
    /// primitive's unspent V / I outputs matching the filter (`""` = any), collected. YEW reads
    /// it for its own YED vaults (`owner` = the owner key hex, `kind` `"vault"`: a vault an
    /// attestor cancel re-created at a new outpoint) and for the claim intents it waits on.
    pub async fn list_vault_outputs(
        &mut self,
        tag: &str,
        set_id: &str,
        owner: &str,
        kind: &str,
    ) -> Result<Vec<rpc::VaultOutput>, NetError> {
        let mut stream = paced(|| {
            let mut c = self.inner.clone();
            let req = rpc::VaultOutputFilter {
                tag: tag.to_string(),
                setid: set_id.to_string(),
                owner: owner.to_string(),
                kind: kind.to_string(),
            };
            async move { c.list_vault_outputs(req).await }
        })
        .await
        .map_err(map_status)?
        .into_inner();
        collect(&mut stream, "vault outputs", limits::MAX_VAULTS).await
    }

    /// `GetChainInfo` once (it is rate-limited with this service, finding 52): the server's
    /// height, the next block's branch id and the vault upgrade's activation height
    /// ([`vault_activation`]). `None` from an older server.
    pub async fn chain_info_vault(&mut self) -> Result<Option<(u64, u32, Option<u64>)>, NetError> {
        let Some(c) = self.chain_info_full().await? else {
            return Ok(None);
        };
        let id = u32::from_str_radix(c.next_block_branch_id.trim_start_matches("0x"), 16).map_err(
            |_| {
                NetError::Mismatch(format!(
                    "bad nextBlockBranchId {:?}",
                    c.next_block_branch_id
                ))
            },
        )?;
        Ok(Some((c.block_height, id, vault_activation(&c))))
    }

    /// `GetChainInfo`'s full answer (the upgrades list included), `None` from an older server.
    pub async fn chain_info_full(&mut self) -> Result<Option<rpc::YedChainInfo>, NetError> {
        match paced(|| {
            let mut c = self.inner.clone();
            let req = rpc::Empty {};
            async move { c.get_chain_info(req).await }
        })
        .await
        {
            Ok(r) => Ok(Some(r.into_inner())),
            Err(s) if s.code() == Code::Unimplemented => Ok(None),
            Err(s) => Err(map_status(s)),
        }
    }

    /// `ListClaimable` (`yed_listclaimable`), collected.
    pub async fn list_claimable(&mut self) -> Result<Vec<rpc::YedClaimable>, NetError> {
        let mut stream = paced(|| {
            let mut c = self.inner.clone();
            let req = rpc::Empty {};
            async move { c.list_claimable(req).await }
        })
        .await
        .map_err(map_status)?
        .into_inner();
        collect(&mut stream, "claimable vaults", limits::MAX_VAULTS).await
    }

    /// `GetNotice` (`yed_getnotice <vaultTxid>`).
    pub async fn notice(&mut self, vault_txid: &str) -> Result<rpc::YedNotice, NetError> {
        Ok(paced(|| {
            let mut c = self.inner.clone();
            let req = rpc::YedTxid {
                txid: vault_txid.to_string(),
            };
            async move { c.get_notice(req).await }
        })
        .await
        .map_err(map_status)?
        .into_inner())
    }

    /// `EstimateCollateral` (`yed_estimatecollateral <cents> <lockBlocks> [priceMicroUsd]`).
    pub async fn estimate_collateral(
        &mut self,
        cents: u64,
        lock_blocks: u32,
        price_micro_usd: u64,
    ) -> Result<rpc::YedCollateralEstimate, NetError> {
        Ok(paced(|| {
            let mut c = self.inner.clone();
            let req = rpc::YedMintQuery {
                cents,
                lock_blocks,
                price_micro_usd,
            };
            async move { c.estimate_collateral(req).await }
        })
        .await
        .map_err(map_status)?
        .into_inner())
    }

    /// `EstimateFee` (`yed_estimatefee <mintedCents> [priceMicroUsd]`, rpcversion 8): the protocol fee
    /// of a debt; `price_micro_usd` 0 = the node's reference price.
    pub async fn estimate_fee(
        &mut self,
        minted_cents: u64,
        price_micro_usd: u64,
    ) -> Result<rpc::YedFeeEstimate, NetError> {
        Ok(paced(|| {
            let mut c = self.inner.clone();
            let req = rpc::YedFeeQuery {
                minted_cents,
                price_micro_usd,
            };
            async move { c.estimate_fee(req).await }
        })
        .await
        .map_err(map_status)?
        .into_inner())
    }

    /// `GetFeePayee` (`yed_getfeepayee <refHeight> [selectorHex]`; rpcversion 8: no collateral, no fee).
    pub async fn fee_payee(
        &mut self,
        ref_height: u32,
        selector_hex: &str,
    ) -> Result<rpc::YedPayee, NetError> {
        Ok(paced(|| {
            let mut c = self.inner.clone();
            let req = rpc::YedPayeeQuery {
                ref_height,
                selector_hex: selector_hex.to_string(),
            };
            async move { c.get_fee_payee(req).await }
        })
        .await
        .map_err(map_status)?
        .into_inner())
    }

    /// `BuildBundle` (`yed_buildbundle <refHeight> <selectorHex>`).
    pub async fn build_bundle(
        &mut self,
        ref_height: u32,
        selector_hex: &str,
    ) -> Result<rpc::YedBundle, NetError> {
        Ok(paced(|| {
            let mut c = self.inner.clone();
            let req = rpc::YedBundleQuery {
                ref_height,
                selector_hex: selector_hex.to_string(),
            };
            async move { c.build_bundle(req).await }
        })
        .await
        .map_err(map_status)?
        .into_inner())
    }

    /// `GetSelection` (`yed_getselection <refHeight> <selectorHex>`).
    pub async fn selection(
        &mut self,
        ref_height: u32,
        selector_hex: &str,
    ) -> Result<rpc::YedSelection, NetError> {
        Ok(paced(|| {
            let mut c = self.inner.clone();
            let req = rpc::YedBundleQuery {
                ref_height,
                selector_hex: selector_hex.to_string(),
            };
            async move { c.get_selection(req).await }
        })
        .await
        .map_err(map_status)?
        .into_inner())
    }

    /// `GetAttestations` (`yed_getattestations`), collected.
    pub async fn attestations(&mut self) -> Result<Vec<rpc::YedAttestation>, NetError> {
        let mut stream = paced(|| {
            let mut c = self.inner.clone();
            let req = rpc::Empty {};
            async move { c.get_attestations(req).await }
        })
        .await
        .map_err(map_status)?
        .into_inner();
        collect(&mut stream, "attestations", limits::MAX_ATTESTATIONS).await
    }

    /// `ListAttestors` (`yed_listattestors [height]`; 0 = the tip), collected.
    pub async fn list_attestors(&mut self, height: u32) -> Result<Vec<rpc::YedAttestor>, NetError> {
        let mut stream = paced(|| {
            let mut c = self.inner.clone();
            let req = rpc::HeightFilter { height };
            async move { c.list_attestors(req).await }
        })
        .await
        .map_err(map_status)?
        .into_inner();
        collect(&mut stream, "attestors", limits::MAX_ATTESTORS).await
    }

    /// `GetAddressTokens` (`yed_listtokens <addresses> [minHeight]`; lightwalletd Phase L2):
    /// the live YED outputs paying any of `addresses` (`s…` or `yb…` form), whoever holds the
    /// keys — **the only source of the TOKEN class** (D-W-8). Spent tokens are never listed
    /// (IN-1 erases them). Chunked by [`TOKENS_MAX_ADDRESSES`]; the stream is collected.
    pub async fn address_tokens(
        &mut self,
        addresses: &[String],
        min_height: u32,
    ) -> Result<Vec<Token>, NetError> {
        let mut out = Vec::new();
        for chunk in addresses.chunks(TOKENS_MAX_ADDRESSES) {
            let mut stream = paced(|| {
                let mut c = self.inner.clone();
                let req = rpc::YedAddressList {
                    addresses: chunk.to_vec(),
                    min_height,
                };
                async move { c.get_address_tokens(req).await }
            })
            .await
            .map_err(map_status)?
            .into_inner();
            while let Some(t) = stream.message().await.map_err(map_status)? {
                if out.len() >= limits::MAX_TOKENS {
                    return Err(NetError::TooLarge {
                        what: "tokens",
                        limit: limits::MAX_TOKENS,
                    });
                }
                out.push(Token {
                    outpoint: outpoint_of(&t.txid, t.vout)?,
                    cents: t.cents,
                    value_zat: t.value_zat,
                    height: t.height,
                    address: t.address,
                    transparent_address: t.transparent_address,
                });
            }
        }
        Ok(out)
    }
}

/// The vault upgrade's activation height in a `GetChainInfo` answer (`upgrades`, branch
/// `6d5b7a31`), `None` when it is absent or unscheduled (height 0).
pub fn vault_activation(ci: &rpc::YedChainInfo) -> Option<u64> {
    ci.upgrades
        .iter()
        .find(|u| {
            u32::from_str_radix(u.branch_id.trim_start_matches("0x"), 16)
                .is_ok_and(|b| b == crate::params::VAULT_BRANCH_ID)
        })
        .filter(|u| u.activation_height > 0)
        .map(|u| u.activation_height as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A closure that answers `RESOURCE_EXHAUSTED` `busy` times, then `Ok(7)`; counts calls.
    async fn run_paced(busy: u32, attempts: u32, code: Code) -> (Result<u32, tonic::Status>, u32) {
        let calls = std::cell::Cell::new(0u32);
        let r = paced_with(std::time::Duration::from_millis(1), attempts, || {
            calls.set(calls.get() + 1);
            let n = calls.get();
            async move {
                if n <= busy {
                    Err(tonic::Status::new(
                        code,
                        "rate limited: at most 20 calls per burst",
                    ))
                } else {
                    Ok(7)
                }
            }
        })
        .await;
        (r, calls.get())
    }

    #[tokio::test]
    async fn paced_retries_rate_limits_and_gives_up_with_the_original_error() {
        // Rate-limited three times, then served: four calls, the answer.
        let (r, calls) = run_paced(3, PACE_ATTEMPTS, Code::ResourceExhausted).await;
        assert_eq!((r.unwrap(), calls), (7, 4));
        // Never served: exactly `attempts` calls, then the server's own status, unchanged.
        let (r, calls) = run_paced(u32::MAX, 5, Code::ResourceExhausted).await;
        let s = r.unwrap_err();
        assert_eq!(
            (s.code(), s.message(), calls),
            (
                Code::ResourceExhausted,
                "rate limited: at most 20 calls per burst",
                5
            )
        );
        // Any other status is not retried.
        let (r, calls) = run_paced(u32::MAX, PACE_ATTEMPTS, Code::Unavailable).await;
        assert_eq!((r.unwrap_err().code(), calls), (Code::Unavailable, 1));
        // The production bound covers a full burst refill (20 calls at 1 s).
        assert!(PACE_ATTEMPTS as u64 * PACE_INTERVAL.as_secs() >= 20);
    }

    #[test]
    fn vault_activation_reads_the_upgrades_list() {
        let up = |b: &str, h: i64| rpc::YedUpgrade {
            branch_id: b.into(),
            name: String::new(),
            activation_height: h,
            status: String::new(),
        };
        let mut ci = rpc::YedChainInfo::default();
        assert_eq!(vault_activation(&ci), None);
        ci.upgrades = vec![up("19bd2d2f", 1), up("6d5b7a31", 0)];
        assert_eq!(vault_activation(&ci), None, "unscheduled");
        ci.upgrades = vec![up("19bd2d2f", 1), up("0x6d5b7a31", 230)];
        assert_eq!(vault_activation(&ci), Some(230));
    }

    #[test]
    fn status_mapping_splits_the_node_identifier() {
        let e = map_status(tonic::Status::failed_precondition(
            "change-floor: 9950 cents cannot be sent from these coins",
        ));
        match e {
            NetError::Node {
                identifier,
                message,
            } => {
                assert_eq!(identifier, "change-floor");
                assert!(message.starts_with("change-floor: 9950"));
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            map_status(tonic::Status::failed_precondition("tx-not-found")),
            NetError::Node { identifier, .. } if identifier == "tx-not-found"
        ));
        assert!(matches!(
            map_status(tonic::Status::unimplemented("x")),
            NetError::Unimplemented
        ));
        assert!(matches!(
            map_status(tonic::Status::unavailable("x")),
            NetError::Status(_)
        ));
    }

    #[test]
    fn availability_gate() {
        let present = |enabled, active| Availability::Present {
            info: Box::default(),
            enabled,
            active,
        };
        assert!(present(true, true).usable());
        assert!(!present(true, false).usable());
        assert!(!present(false, true).usable());
        assert!(!Availability::Absent.usable());
    }
}
