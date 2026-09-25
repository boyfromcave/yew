//! The typed T1–T3 client over `YellowbackStreamer` (plan §1.4, §3.5, §4 rule 1; lightwalletd
//! plan §3, §4.1, §5): every method of `lightwalletd-dd/walletrpc/yellowback.proto`, each a
//! thin proxy of one read-only `yed_*` RPC on the server's node. Streams are collected.
//!
//! Contract rule 1 lives in [`YellowbackClient::probe`]: `UNIMPLEMENTED` ⇒ no Yellowback here
//! (T0 only, YED hidden); an `rpcversion` other than [`KNOWN_RPCVERSION`] ⇒ refused; YED is
//! shown only when `enabled && activation.status == "active"`. Errors (lightwalletd plan §3.3):
//! a node RPC error arrives as `FAILED_PRECONDITION` with the node's identifier
//! (`change-floor: …`, `tx-not-found`, …) and is mapped to [`NetError::Node`] with that
//! identifier split off; transport failures to the node are `UNAVAILABLE`.
//!
//! Nothing here interprets a verdict: [`crate::gate`] reads [`Validation`], [`crate::sync`]
//! reads [`Token`] and `YedTxInfo`. The remaining results are returned as the generated
//! messages (`super::rpc`), whose field names are the node contract's JSON names.

use tonic::transport::Channel;
use tonic::Code;

use super::rpc;
use super::{NetError, Server, YellowbackStreamerClient};
use crate::tx::{txid_from_hex, OutPoint};

/// The node `rpcversion` this build implements (`ycash-dd/doc/yellowback-rpc-contract.json`;
/// lightwalletd plan §3.4: "a client refuses an `rpcversion` it does not know").
pub const KNOWN_RPCVERSION: i64 = 3;

/// The activation status string that means "active" (`YellowbackActivationState.status`).
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
        /// `info.activation.status == "active"`.
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
    /// The `ye…` form.
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
        let info = match self.inner.get_yellowback_info(rpc::Empty {}).await {
            Ok(r) => r.into_inner(),
            Err(s) if s.code() == Code::Unimplemented => return Ok(Availability::Absent),
            Err(s) => return Err(map_status(s)),
        };
        if info.rpcversion != KNOWN_RPCVERSION {
            return Err(NetError::UnknownRpcVersion(info.rpcversion));
        }
        let enabled = info.enabled;
        let active = info
            .activation
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
        Ok(self
            .inner
            .get_yellowback_info(rpc::Empty {})
            .await
            .map_err(map_status)?
            .into_inner())
    }

    /// `GetPrice` (`yed_getprice [height]`; 0 = the index tip). `pMint` is the display price
    /// (plan §1.1); a field of 0 means "undefined" on the wire (proto3 has no null).
    pub async fn price(&mut self, height: u32) -> Result<rpc::YedPrice, NetError> {
        Ok(self
            .inner
            .get_price(rpc::HeightFilter { height })
            .await
            .map_err(map_status)?
            .into_inner())
    }

    /// `GetStats` (`yed_getstats`).
    pub async fn stats(&mut self) -> Result<rpc::YellowbackStats, NetError> {
        Ok(self
            .inner
            .get_stats(rpc::Empty {})
            .await
            .map_err(map_status)?
            .into_inner())
    }

    /// `GetActivation` (`yed_getactivation`).
    pub async fn activation(&mut self) -> Result<rpc::YellowbackActivation, NetError> {
        Ok(self
            .inner
            .get_activation(rpc::Empty {})
            .await
            .map_err(map_status)?
            .into_inner())
    }

    /// `GetTxInfo` (`yed_gettxinfo <txid>`): the index's `TxLog` record — the verdict every
    /// history label derives from (contract rule 3). `txid` in display order. A txid the index
    /// does not know is [`NetError::Node`] with identifier `tx-not-found`.
    pub async fn tx_info(&mut self, txid: &str) -> Result<rpc::YedTxInfo, NetError> {
        Ok(self
            .inner
            .get_tx_info(rpc::YedTxid {
                txid: txid.to_string(),
            })
            .await
            .map_err(map_status)?
            .into_inner())
    }

    /// `ValidateRawTransaction` (`yed_validaterawtransaction <hex>`): the dry run of §3.8 at
    /// the tip plus script verification. Never commits anything.
    pub async fn validate_raw(&mut self, raw: Vec<u8>) -> Result<Validation, NetError> {
        let v = self
            .inner
            .validate_raw_transaction(rpc::RawTransaction {
                data: raw,
                height: 0,
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
        Ok(self
            .inner
            .decode_payload(rpc::YedHex {
                hex: hex.to_string(),
            })
            .await
            .map_err(map_status)?
            .into_inner())
    }

    /// `GetVault` (`yed_getvault <txid>`).
    pub async fn vault(&mut self, txid: &str) -> Result<rpc::YedVault, NetError> {
        Ok(self
            .inner
            .get_vault(rpc::YedTxid {
                txid: txid.to_string(),
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
        let mut stream = self
            .inner
            .list_vaults(rpc::YedVaultFilter {
                status: status.to_string(),
                count,
                skip,
            })
            .await
            .map_err(map_status)?
            .into_inner();
        let mut out = Vec::new();
        while let Some(v) = stream.message().await.map_err(map_status)? {
            out.push(v);
        }
        Ok(out)
    }

    /// `ListClaimable` (`yed_listclaimable`), collected.
    pub async fn list_claimable(&mut self) -> Result<Vec<rpc::YedClaimable>, NetError> {
        let mut stream = self
            .inner
            .list_claimable(rpc::Empty {})
            .await
            .map_err(map_status)?
            .into_inner();
        let mut out = Vec::new();
        while let Some(v) = stream.message().await.map_err(map_status)? {
            out.push(v);
        }
        Ok(out)
    }

    /// `GetNotice` (`yed_getnotice <vaultTxid>`).
    pub async fn notice(&mut self, vault_txid: &str) -> Result<rpc::YedNotice, NetError> {
        Ok(self
            .inner
            .get_notice(rpc::YedTxid {
                txid: vault_txid.to_string(),
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
        Ok(self
            .inner
            .estimate_collateral(rpc::YedMintQuery {
                cents,
                lock_blocks,
                price_micro_usd,
            })
            .await
            .map_err(map_status)?
            .into_inner())
    }

    /// `EstimateFee` (`yed_estimatefee <collateralZat>`).
    pub async fn estimate_fee(
        &mut self,
        collateral_zat: i64,
    ) -> Result<rpc::YedFeeEstimate, NetError> {
        Ok(self
            .inner
            .estimate_fee(rpc::YedFeeQuery { collateral_zat })
            .await
            .map_err(map_status)?
            .into_inner())
    }

    /// `GetFeePayee` (`yed_getfeepayee <refHeight> <collateralZat> [selectorHex]`).
    pub async fn fee_payee(
        &mut self,
        ref_height: u32,
        collateral_zat: i64,
        selector_hex: &str,
    ) -> Result<rpc::YedPayee, NetError> {
        Ok(self
            .inner
            .get_fee_payee(rpc::YedPayeeQuery {
                ref_height,
                collateral_zat,
                selector_hex: selector_hex.to_string(),
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
        Ok(self
            .inner
            .build_bundle(rpc::YedBundleQuery {
                ref_height,
                selector_hex: selector_hex.to_string(),
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
        Ok(self
            .inner
            .get_selection(rpc::YedBundleQuery {
                ref_height,
                selector_hex: selector_hex.to_string(),
            })
            .await
            .map_err(map_status)?
            .into_inner())
    }

    /// `GetAttestations` (`yed_getattestations`), collected.
    pub async fn attestations(&mut self) -> Result<Vec<rpc::YedAttestation>, NetError> {
        let mut stream = self
            .inner
            .get_attestations(rpc::Empty {})
            .await
            .map_err(map_status)?
            .into_inner();
        let mut out = Vec::new();
        while let Some(v) = stream.message().await.map_err(map_status)? {
            out.push(v);
        }
        Ok(out)
    }

    /// `ListAttestors` (`yed_listattestors [height]`; 0 = the tip), collected.
    pub async fn list_attestors(&mut self, height: u32) -> Result<Vec<rpc::YedAttestor>, NetError> {
        let mut stream = self
            .inner
            .list_attestors(rpc::HeightFilter { height })
            .await
            .map_err(map_status)?
            .into_inner();
        let mut out = Vec::new();
        while let Some(v) = stream.message().await.map_err(map_status)? {
            out.push(v);
        }
        Ok(out)
    }

    /// `GetAddressTokens` (`yed_listtokens <addresses> [minHeight]`; lightwalletd Phase L2):
    /// the live YED outputs paying any of `addresses` (`s…` or `ye…` form), whoever holds the
    /// keys — **the only source of the TOKEN class** (D-W-8). Spent tokens are never listed
    /// (IN-1 erases them). Chunked by [`TOKENS_MAX_ADDRESSES`]; the stream is collected.
    pub async fn address_tokens(
        &mut self,
        addresses: &[String],
        min_height: u32,
    ) -> Result<Vec<Token>, NetError> {
        let mut out = Vec::new();
        for chunk in addresses.chunks(TOKENS_MAX_ADDRESSES) {
            let mut stream = self
                .inner
                .get_address_tokens(rpc::YedAddressList {
                    addresses: chunk.to_vec(),
                    min_height,
                })
                .await
                .map_err(map_status)?
                .into_inner();
            while let Some(t) = stream.message().await.map_err(map_status)? {
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

#[cfg(test)]
mod tests {
    use super::*;

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
