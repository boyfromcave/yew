//! Network parameters and protocol constants: address version bytes, the fee, `TOKEN_VALUE`,
//! `CARRIER_VALUE`, `REF_WINDOW`, `MIN_OUTPUT`, the v4 transaction header, the fee reserve.
//!
//! Translation source: `ycash-dd/src/chainparams.cpp`, `src/yellowback/params.{h,cpp}`,
//! `src/primitives/transaction.h`, `src/wallet/wallet.h`, `src/main.h`, `src/policy/fees.h`
//! (branch `feature/yellowback-price-attest`). Every constant below cites its line.
//!
//! `consensusBranchId` is deliberately **not** a constant: it is stored from `GetLightdInfo`
//! at connect time (plan §3.5) and passed to the signer.

/// The three Ycash networks. The chain name is what `GetLightdInfo.chainName` reports
/// (`"main"`, `"test"`, `"regtest"`) and what `yellowback::Params::network` holds
/// (`ycash-dd/src/yellowback/params.cpp:140,154,186`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Network {
    /// Ycash mainnet.
    Mainnet,
    /// Ycash testnet.
    Testnet,
    /// Regtest, the devnet.
    Regtest,
}

impl Network {
    /// Parse a `chainName` / `--network` string.
    pub fn from_name(name: &str) -> Option<Network> {
        match name {
            "main" | "mainnet" => Some(Network::Mainnet),
            "test" | "testnet" => Some(Network::Testnet),
            "regtest" => Some(Network::Regtest),
            _ => None,
        }
    }

    /// The `chainName` string the server reports for this network.
    pub fn chain_name(self) -> &'static str {
        match self {
            Network::Mainnet => "main",
            Network::Testnet => "test",
            Network::Regtest => "regtest",
        }
    }

    /// Base58Check version bytes of a P2PKH address (`s1…` on mainnet).
    /// `ycash-dd/src/chainparams.cpp:149` (main `{0x1C,0x28}`), `:409` (test `{0x1C,0x95}`),
    /// `:613` (regtest, same as test).
    pub fn p2pkh_prefix(self) -> [u8; 2] {
        match self {
            Network::Mainnet => [0x1C, 0x28],
            Network::Testnet | Network::Regtest => [0x1C, 0x95],
        }
    }

    /// Base58Check version bytes of a P2SH address (`s3…` on mainnet).
    /// `ycash-dd/src/chainparams.cpp:151` (main `{0x1C,0x2C}`), `:411`, `:614` (`{0x1C,0x2A}`).
    pub fn p2sh_prefix(self) -> [u8; 2] {
        match self {
            Network::Mainnet => [0x1C, 0x2C],
            Network::Testnet | Network::Regtest => [0x1C, 0x2A],
        }
    }

    /// The WIF version byte (`dumpprivkey` / `importprivkey`, D-W-11).
    /// `ycash-dd/src/chainparams.cpp:153` (`0x80`), `:413`, `:615` (`0xEF`).
    pub fn wif_prefix(self) -> u8 {
        match self {
            Network::Mainnet => 0x80,
            Network::Testnet | Network::Regtest => 0xEF,
        }
    }

    /// Yellowback address version bytes: the same key hash as the `s…` P2PKH address under a
    /// prefix that renders `ye…` / `yt…` / `yr…` (spec D10).
    /// `ycash-dd/src/yellowback/params.cpp:142` (main `{0x1F,0xE4}`), `:156` (test
    /// `{0x20,0x07}`), `:189` (regtest `{0x20,0x02}`).
    pub fn yellowback_prefix(self) -> [u8; 2] {
        match self {
            Network::Mainnet => [0x1F, 0xE4],
            Network::Testnet => [0x20, 0x07],
            Network::Regtest => [0x20, 0x02],
        }
    }
}

/// SLIP-44 coin type of Ycash, the BIP44 `coin_type'` level of every YEW key (D-W-7; Ywallet
/// `zcash-sync/src/consensus/ycash.rs` `coin_type()`).
pub const COIN_TYPE: u32 = 347;

/// BIP44 `purpose'`.
pub const BIP44_PURPOSE: u32 = 44;

/// The one account YEW derives (D-W-7: multi-account is out of scope).
pub const ACCOUNT: u32 = 0;

/// The address gap limit on both the external and the change chain (D-W-7).
pub const GAP_LIMIT: u32 = 20;

/// The flat network fee, in zatoshi, that every YEW transaction pays: **1,000 zat**.
///
/// Why this number (plan §7 W1, first task):
/// - `ycash-dd/src/yellowback/params.h:79` `DEFAULT_YELLOWBACK_FEE = 1000` — "Flat network
///   fee; equals policy DEFAULT_FEE"; `-yellowbackfee` may not go below it
///   (`src/init.cpp:1186-1189`), and every node-built Yellowback template pays exactly it
///   (`src/yellowback/txbuilder.cpp:338` `b.SetFee(g_yellowbackFee)`).
/// - `ycash-dd/src/policy/fees.h:15` `DEFAULT_FEE = 1000`, the fee `z_sendmany` and friends pay.
/// - `ycash-dd/src/wallet/wallet.h:265` `DEFAULT_TRANSACTION_MINFEE = 1000` (`-mintxfee`).
/// - `ycash-dd/src/main.h:68` `DEFAULT_MIN_RELAY_TX_FEE = 100` zat/kB is the relay floor: a
///   transparent transaction of a few inputs is well under 10 kB, so 1,000 zat clears it.
/// - `yed_getinfo` exposes it as `params.feeZat` (`src/rpc/yellowback.cpp:669`); confirmed on
///   the regtest devnet in Phase W1 (`scripts/devnet-w1.sh`).
pub const FEE_ZAT: i64 = 1_000;

/// The floor of the YEC fee reserve (plan §3.7, "Fee reserve" item 1):
/// `reserveZat = max(RESERVE_MIN, RESERVE_K · (FEE_ZAT + 2 · TOKEN_VALUE))`.
///
/// Fixed in Phase W1 at exactly five TRANSFERs' worth with the fee above:
/// `5 · (1_000 + 2 · 10_000) = 105_000` zat, so with the default fee the two terms of the
/// `max` are equal and the floor only matters if a build ever lowers `FEE_ZAT`.
pub const RESERVE_MIN: i64 = 105_000;

/// `k` in the fee-reserve formula: five TRANSFERs' worth (plan §3.7 item 1).
pub const RESERVE_K: i64 = 5;

/// The reserve the wallet keeps for YED fees, in zat (plan §3.7 item 1).
pub const fn reserve_zat() -> i64 {
    let k = RESERVE_K * (FEE_ZAT + 2 * TOKEN_VALUE);
    if k > RESERVE_MIN {
        k
    } else {
        RESERVE_MIN
    }
}

/// YEC carried by every Yellowback token output: 10,000 zat
/// (`ycash-dd/src/yellowback/params.h:77`). A P2PKH output of exactly this value is what a
/// YED holding looks like on the chain (plan §3.7).
pub const TOKEN_VALUE: i64 = 10_000;

/// Value of a carrier output: 10,000 zat, wallet policy, never hashed
/// (`ycash-dd/src/yellowback/params.h:206`, `wallet.h:48`).
pub const CARRIER_VALUE: i64 = 10_000;

/// MINT-2 reference window: `H - REF_WINDOW <= refHeight <= H - 1`
/// (`ycash-dd/src/yellowback/params.h:71`).
pub const REF_WINDOW: u32 = 40;

/// The smallest YED output a payload may assign, in cents ($1.00;
/// `ycash-dd/src/yellowback/coinselect.h:23`).
pub const MIN_OUTPUT_CENTS: u64 = 100;

/// The node's `maxInputs` cap for YED selection (plan §3.7).
pub const MAX_INPUTS: usize = 250;

/// The v4 transaction header: `fOverwintered = 1` in bit 31, `nVersion = 4`
/// (`ycash-dd/src/primitives/transaction.h:43` `SAPLING_TX_VERSION = 4`, `:575-587`).
pub const TX_HEADER_V4: u32 = 0x8000_0004;

/// `nVersionGroupId` of a Sapling v4 transaction
/// (`ycash-dd/src/primitives/transaction.h:39` `SAPLING_VERSION_GROUP_ID = 0x892F2085`).
pub const SAPLING_VERSION_GROUP_ID: u32 = 0x892F_2085;

/// `nVersionGroupId` of an Overwinter v3 transaction, accepted by the parser only
/// (`ycash-dd/src/primitives/transaction.h:28`).
pub const OVERWINTER_VERSION_GROUP_ID: u32 = 0x03C4_8270;

/// The node's default `nExpiryHeight` delta after Blossom: the transaction expires
/// `TX_EXPIRY_DELTA` blocks after the tip it was built at
/// (`ycash-dd/src/main.h:78-79` `DEFAULT_POST_BLOSSOM_TX_EXPIRY_DELTA = 20 · 2 = 40`, equal to `REF_WINDOW`
/// by the note at `src/yellowback/params.h:66-69`).
pub const TX_EXPIRY_DELTA: u32 = 40;

/// `nSequence` of an input that does not opt into `nLockTime` (`0xFFFFFFFF`).
pub const SEQUENCE_FINAL: u32 = 0xFFFF_FFFF;

/// `nSequence` of a vault spend's `vin[0]` (`0xFFFFFFFE`: opts into `nLockTime`, spec §3.4;
/// `ycash-dd/src/yellowback/txbuilder.cpp:61`).
pub const SEQUENCE_LOCKTIME: u32 = 0xFFFF_FFFE;

/// `TX_EXPIRING_SOON_THRESHOLD` (`ref/ycash/src/main.h:81`): the mempool refuses a transaction
/// whose `nExpiryHeight < nextHeight + 3`, so a two-step window is open only while
/// `tip + 1 + 3 <= refHeight + REF_WINDOW` (`txbuilder.cpp:316-321` `CheckExpiry`).
pub const TX_EXPIRING_SOON_THRESHOLD: u32 = 3;

/// `BPS`: basis points per unit.
pub const BPS: i64 = 10_000;

/// `COIN`: zatoshi per YEC.
pub const COIN: i64 = 100_000_000;

/// `SIGHASH_ALL`, the only hash type YEW signs with.
pub const SIGHASH_ALL: u32 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserve_is_five_transfers() {
        assert_eq!(reserve_zat(), 105_000);
        assert_eq!(reserve_zat(), RESERVE_K * (FEE_ZAT + 2 * TOKEN_VALUE));
    }

    #[test]
    fn network_names_round_trip() {
        for n in [Network::Mainnet, Network::Testnet, Network::Regtest] {
            assert_eq!(Network::from_name(n.chain_name()), Some(n));
        }
        assert_eq!(Network::from_name("regtest"), Some(Network::Regtest));
        assert_eq!(Network::from_name("nope"), None);
    }
}
