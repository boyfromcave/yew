// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! Network parameters and protocol constants: address version bytes, the fee, `TOKEN_VALUE`,
//! `CARRIER_VALUE`, `REF_WINDOW`, `MIN_OUTPUT`, the v4 transaction header, the fee reserve.
//!
//! Translation source: `ycash-dd/src/chainparams.cpp`, `src/yellowback/params.{h,cpp}`,
//! `src/primitives/transaction.h`, `src/wallet/wallet.h`, `src/main.h`, `src/policy/fees.h`
//! (branch `feature/yellowback-price-attest`). Every constant below cites its line.
//!
//! `consensusBranchId` is stored from `GetLightdInfo` at connect time (plan §3.5) and passed to
//! the signer, but only after [`Network::branch_ids`] has accepted it (audit G-5): the ZIP-243
//! personalization is the one domain separator between Ycash and Zcash, so a server naming a
//! branch id of another chain is refused before anything is signed.
//!
//! The protocol constants a server-supplied mint, claim or vault is checked against (audit
//! G-1, G-2) live here too: the term classes, `GRACE`, `FEE_MIN` / `FEE_BPS`,
//! `ATTEST_FEE_BPS`, the mint bounds. Every value is the node's compiled-in parameter set
//! (`ycash-dd/src/yellowback/params.cpp` `SetCommon` `:14-104`, `RegtestParams` `:186-240`).

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

    /// Bech32 human-readable part of a Sapling payment address (`ys1…` on mainnet).
    /// `ycash-dd/src/chainparams.cpp:164` (main `"ys"`), `:424` (test `"ytestsapling"`),
    /// `:623` (regtest `"yregtestsapling"`). Ywallet renders the same (`zcash-sync`
    /// `librustzcash/zcash_primitives/src/consensus/ycash.rs` `hrp_sapling_payment_address`).
    pub fn sapling_address_hrp(self) -> &'static str {
        match self {
            Network::Mainnet => "ys",
            Network::Testnet => "ytestsapling",
            Network::Regtest => "yregtestsapling",
        }
    }

    /// Bech32 HRP of a Sapling extended spending key (what `z_exportkey` prints and
    /// `z_importkey` reads). `ycash-dd/src/chainparams.cpp:167`, `:427`, `:626`.
    pub fn sapling_spending_key_hrp(self) -> &'static str {
        match self {
            Network::Mainnet => "secret-extended-key-main",
            Network::Testnet => "secret-extended-key-test",
            Network::Regtest => "secret-extended-key-regtest",
        }
    }

    /// Bech32 HRP of a Sapling extended full viewing key (`z_exportviewingkey`).
    /// `ycash-dd/src/chainparams.cpp:168`, `:428`, `:627`.
    pub fn sapling_viewing_key_hrp(self) -> &'static str {
        match self {
            Network::Mainnet => "zxviews",
            Network::Testnet => "zxviewtestsapling",
            Network::Regtest => "zxviewregtestsapling",
        }
    }
}

/// A term class of a mint (spec §2 table, V19): the lock range in blocks and the base
/// collateral ratio (`ycash-dd/src/yellowback/params.cpp:50-52`, regtest `:214-216`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TermClass {
    /// `0`, `1`, `2` (the payload's `termClass`).
    pub index: u8,
    /// `"A"`, `"B"`, `"C"` (what `EstimateCollateral.termClass` reports).
    pub letter: &'static str,
    /// `classMin`.
    pub min_blocks: u32,
    /// `classMax`.
    pub max_blocks: u32,
    /// `baseRatioBps`: 500 %, 400 %, 300 %.
    pub base_ratio_bps: i64,
}

const MAIN_CLASSES: [TermClass; 3] = [
    TermClass {
        index: 0,
        letter: "A",
        min_blocks: 34_560,
        max_blocks: 103_680,
        base_ratio_bps: 50_000,
    },
    TermClass {
        index: 1,
        letter: "B",
        min_blocks: 103_681,
        max_blocks: 420_480,
        base_ratio_bps: 40_000,
    },
    TermClass {
        index: 2,
        letter: "C",
        min_blocks: 420_481,
        max_blocks: 2_102_400,
        base_ratio_bps: 30_000,
    },
];

const REGTEST_CLASSES: [TermClass; 3] = [
    TermClass {
        index: 0,
        letter: "A",
        min_blocks: 48,
        max_blocks: 96,
        base_ratio_bps: 50_000,
    },
    TermClass {
        index: 1,
        letter: "B",
        min_blocks: 97,
        max_blocks: 144,
        base_ratio_bps: 40_000,
    },
    TermClass {
        index: 2,
        letter: "C",
        min_blocks: 145,
        max_blocks: 240,
        base_ratio_bps: 30_000,
    },
];

impl Network {
    /// The three term classes of this network.
    pub fn term_classes(self) -> &'static [TermClass; 3] {
        match self {
            Network::Mainnet | Network::Testnet => &MAIN_CLASSES,
            Network::Regtest => &REGTEST_CLASSES,
        }
    }

    /// `Params::ClassForLockBlocks` (`params.cpp:124-130`): the class `lock_blocks` falls in.
    pub fn class_for_lock_blocks(self, lock_blocks: u32) -> Option<&'static TermClass> {
        self.term_classes()
            .iter()
            .find(|c| lock_blocks >= c.min_blocks && lock_blocks <= c.max_blocks)
    }

    /// `GRACE`: `claimHeight = lockHeight + GRACE` (spec §2 table; `params.cpp:46`, regtest
    /// `:213`).
    pub fn grace(self) -> u32 {
        match self {
            Network::Mainnet | Network::Testnet => 34_560,
            Network::Regtest => 24,
        }
    }

    /// The `consensusBranchId`s a server for this network may report: the Ycash epochs from the
    /// Ycash fork on (`ref/ycash/src/consensus/upgrades.cpp:33-57`, `chainparams.cpp:126-138`
    /// main, `:379-395` test). Sprout, Overwinter and Sapling are pre-fork and shared with
    /// Zcash: a signature under them could spend a pre-fork duplicate on Zcash (audit G-5),
    /// so they are never accepted. Regtest activates the upgrades by `-nuparams`; the devnet
    /// signs under Canopy (`yellowback_util.py:139`).
    pub fn branch_ids(self) -> &'static [u32] {
        const YCASH_EPOCHS: [u32; 5] = [
            0x374d_694f, // Ycash
            0x8e47_1bd6, // Blossom
            0x6631_4da3, // Heartwood
            0x19bd_2d2f, // Canopy
            0xf919_a198, // NU5 (no activation height on 4.5.0; reserved)
        ];
        match self {
            Network::Mainnet | Network::Testnet | Network::Regtest => &YCASH_EPOCHS,
        }
    }
}

/// `FEE_MIN`: the enforcement fee floor, 0.5 YEC (`params.cpp:43`, V10).
pub const FEE_MIN_ZAT: i64 = 50_000_000;

/// `FEE_BPS`: the enforcement fee rate, 0.25 % of the collateral (`params.cpp:44`).
pub const FEE_BPS: i64 = 25;

/// `ATTEST_FEE_BPS`: the attestor fee as a share of the enforcement fee (`params.cpp:94`,
/// AFEE-1, D-3).
pub const ATTEST_FEE_BPS: i64 = 2_500;

/// `MIN_MINT`: $100 (`params.cpp:16`, MINT-2).
pub const MIN_MINT_CENTS: u64 = 10_000;

/// `MAX_MINT`: $10,000 (`params.cpp:17`, MINT-2).
pub const MAX_MINT_CENTS: u64 = 1_000_000;

/// `sigmaMultBps` is clamped to `[10⁴, SIGMA_MULT_MAX_BPS]` (spec SIGMA-1; `params.cpp:59`).
pub const SIGMA_MULT_MIN_BPS: i64 = 10_000;
/// See [`SIGMA_MULT_MIN_BPS`].
pub const SIGMA_MULT_MAX_BPS: i64 = 30_000;

/// `LOCKTIME_THRESHOLD`: a vault's `claimHeight` must be below it (MINT-2;
/// `ref/ycash/src/script/script.h` `LOCKTIME_THRESHOLD = 500000000`).
pub const LOCKTIME_THRESHOLD: u32 = 500_000_000;

/// **FEE-1**: `feeZat(collateralZat) = max(FEE_MIN, collateralZat · FEE_BPS / 10⁴)`
/// (spec §3.3; `ycash-dd/src/yellowback/rules.cpp` `FeeZat`).
pub fn fee_zat_for(collateral_zat: i64) -> i64 {
    FEE_MIN_ZAT.max(collateral_zat.saturating_mul(FEE_BPS) / BPS)
}

/// **AFEE-1**: `attestFeeZat = feeZat · ATTEST_FEE_BPS / 10⁴` (spec §3.3 v3).
pub fn attest_fee_zat_for(fee_zat: i64) -> i64 {
    fee_zat.saturating_mul(ATTEST_FEE_BPS) / BPS
}

/// `requiredZat(cents, class, S) = ⌈cents · minRatioBps · COIN / pMint⌉` (spec §3.3 "Required
/// collateral"), in 128-bit arithmetic as the node uses `arith_uint256`; `None` when `p_mint`
/// is undefined (≤ 0) or the quotient does not fit `i64` (K14 "unsatisfiable").
pub fn required_zat(cents: u64, min_ratio_bps: i64, p_mint: i64) -> Option<i64> {
    if p_mint <= 0 || min_ratio_bps <= 0 {
        return None;
    }
    let num = (cents as u128) * (min_ratio_bps as u128) * (COIN as u128);
    let den = p_mint as u128;
    let q = num.div_ceil(den);
    i64::try_from(q).ok()
}

/// SLIP-44 coin type of Ycash, the `coin_type'` level of every YEW key: BIP44 for the
/// transparent keys (D-W-7) and ZIP-32 for the Sapling keys (yew-shielded plan S0-1), on every
/// network, as Ywallet derives (`zcash-sync` `librustzcash/zcash_primitives/src/consensus/
/// ycash.rs` `coin_type()` returns 347 for its testnet too). The node's own HD wallet uses
/// `bip44CoinType = 1` on testnet and regtest (`ycash-dd/src/chainparams.cpp:341,552`), so a
/// node-derived `z_getnewaddress` differs from YEW's on those networks; seed portability is
/// defined against Ywallet, not the node (D-W-7).
pub const COIN_TYPE: u32 = 347;

/// ZIP-32 `purpose'` of the Sapling keys (`m/32'/347'/0'`; `ycash-dd/src/wallet/wallet.cpp:154`).
pub const ZIP32_PURPOSE: u32 = 32;

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
    fn protocol_table_matches_the_node() {
        // params.cpp SetCommon / RegtestParams.
        for n in [Network::Mainnet, Network::Testnet] {
            assert_eq!(n.grace(), 34_560);
            assert_eq!(n.class_for_lock_blocks(34_560).unwrap().letter, "A");
            assert_eq!(n.class_for_lock_blocks(103_680).unwrap().letter, "A");
            assert_eq!(n.class_for_lock_blocks(103_681).unwrap().letter, "B");
            assert_eq!(n.class_for_lock_blocks(420_481).unwrap().letter, "C");
            assert_eq!(n.class_for_lock_blocks(2_102_400).unwrap().index, 2);
            assert!(n.class_for_lock_blocks(34_559).is_none());
            assert!(n.class_for_lock_blocks(2_102_401).is_none());
        }
        assert_eq!(Network::Regtest.grace(), 24);
        assert_eq!(
            Network::Regtest.class_for_lock_blocks(48).unwrap().letter,
            "A"
        );
        assert_eq!(
            Network::Regtest.class_for_lock_blocks(144).unwrap().letter,
            "B"
        );
        assert_eq!(
            Network::Regtest.class_for_lock_blocks(240).unwrap().letter,
            "C"
        );
        assert!(Network::Regtest.class_for_lock_blocks(47).is_none());
        assert!(Network::Regtest.class_for_lock_blocks(241).is_none());
        // FEE-1 / AFEE-1.
        assert_eq!(fee_zat_for(1_000_000_000), 50_000_000);
        assert_eq!(fee_zat_for(400_000_000_000), 1_000_000_000);
        assert_eq!(attest_fee_zat_for(50_000_000), 12_500_000);
        // The spec's worked example: $100 at 300 % and $0.05/YEC = 6,000 YEC.
        assert_eq!(required_zat(10_000, 30_000, 50_000), Some(600_000_000_000));
        assert_eq!(required_zat(10_000, 30_000, 0), None);
        // Class A at the 3x cap and PRICE_MIN exceeds i64: unsatisfiable, not a wrap.
        assert_eq!(required_zat(1_000_000, 150_000, 1), None);
        // Branch ids: the Ycash epochs, never a pre-fork (Zcash-shared) one.
        for n in [Network::Mainnet, Network::Testnet, Network::Regtest] {
            assert!(n.branch_ids().contains(&0x19bd_2d2f));
            assert!(!n.branch_ids().contains(&0x76b8_09bb)); // Sapling
            assert!(!n.branch_ids().contains(&0x5ba8_1b19)); // Overwinter
            assert!(!n.branch_ids().contains(&0));
        }
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
