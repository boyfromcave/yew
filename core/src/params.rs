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
//! (`ycash-dd/src/yellowback/params.cpp` `SetCommon` `:14-106`, `RegtestParams` `:196-263`),
//! at branch `harden/yellowback` (hardening H-1, H-4, H-12: mainnet and testnet differ
//! from regtest in `FEE_BPS`, `ATTEST_FEE_BPS` and `MAX_MINT`, so those are per [`Network`]),
//! with the in-term claims parameter set of branch `upgrade/vault-in-term` (the workspace's
//! `docs/plans/yellowback-in-term-claims-plan.md` §3: classes A/B/C at 300 / 400 / 500 %, θ
//! 125 %, the σ multiplier pinned at 1, `CLAIM_DELAY` 12 h, the early-redeem fee per class). The server's own `GetYellowbackInfo.params` is compared against them
//! (`build::terms::check_server_params`) and never used in their place (audit G-1, G-2).

/// `pqFalconHeight` on mainnet: Falcon holders (`TOK-PQ`) from day one, owner decision D-Q-2
/// (2026-10-10). ycash-dd `src/chainparams.cpp:148`, ycash6 `src/chainparams.cpp:159`.
pub const PQ_FALCON_HEIGHT_MAINNET: u64 = 0;
/// `pqFalconHeight` on testnet (D-Q-2). ycash-dd `src/chainparams.cpp:414`, ycash6
/// `src/chainparams.cpp:463`.
pub const PQ_FALCON_HEIGHT_TESTNET: u64 = 0;

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
    /// prefix that renders `yb…` / `yt…` / `yr…` (spec D10; on the post-quantum line the mainnet
    /// prefix is `yb…`, owner decision D-Q-21, superseding D10's `ye…` there).
    /// Main `{0x1F,0xDD}` (D-Q-21; the node's `yellowback/params.cpp` still says `{0x1F,0xE4}` =
    /// `ye…` until the plan's §8.1 Y-B sweep), test `{0x20,0x07}`, regtest `{0x20,0x02}`
    /// (`ycash-dd/src/yellowback/params.cpp:156`, `:189`; unchanged).
    pub fn yellowback_prefix(self) -> [u8; 2] {
        match self {
            Network::Mainnet => [0x1F, 0xDD],
            Network::Testnet => [0x20, 0x07],
            Network::Regtest => [0x20, 0x02],
        }
    }

    /// Post-quantum Yellowback address version bytes (quantum spec §4, F-4): the 33-byte payload
    /// `scheme ‖ keyHash` of a `CPQKeyID` renders `yb…` / `yt…` / `yr…` at 53 characters, beside
    /// the 35-character 20-byte form. Main `{0x56,0xAB}` (D-Q-21; the node's
    /// `pqAddressVersion` is `{0x56,0xBF}` = `ye…` until the Y-B sweep), test `{0x57,0x1E}`,
    /// regtest `{0x57,0x10}` (`ycash-dd/src/yellowback/params.cpp` `pqAddressVersion`) — each
    /// the lowest version whose whole payload interval keeps the prefix and the length.
    pub fn pq_yellowback_prefix(self) -> [u8; 2] {
        match self {
            Network::Mainnet => [0x56, 0xAB],
            Network::Testnet => [0x57, 0x1E],
            Network::Regtest => [0x57, 0x10],
        }
    }

    /// Post-quantum plain-YEC address version bytes (owner decision D-Q-20): the same 33-byte
    /// `scheme ‖ keyHash` payload and the same `TX_PQPKH` script as the post-quantum Yellowback
    /// form, rendered `sq…` / `tq…` / `rq…` (53 characters): main `{0x4D,0xD9}`, test
    /// `{0x4F,0x61}`, regtest `{0x4C,0x51}` (the node's `key_io` `PlainPQAddressVersion`,
    /// decoded chain-wide since the plan's §8.1 "SQ" step). YEW sends YEC to it
    /// (`keys::parse_yec_destination`) and syncs its own keys' forms through lightwalletd's taddr
    /// methods, which index `TX_PQPKH` under it.
    pub fn pq_yec_prefix(self) -> [u8; 2] {
        match self {
            Network::Mainnet => [0x4D, 0xD9],
            Network::Testnet => [0x4F, 0x61],
            Network::Regtest => [0x4C, 0x51],
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
    /// `baseRatioBps`: 300 %, 400 %, 500 % (in-term plan D-IT-4: the longer the term, the higher).
    pub base_ratio_bps: i64,
    /// `earlyRedeemFeeBps` (in-term plan IT-9, D-IT-16): of the collateral, paid on top of FEE-1 by a
    /// redeem before `lockHeight` — 5 %, 2.5 %, 1 %.
    pub early_redeem_fee_bps: i64,
}

impl TermClass {
    /// `Params::IsClassEnabled` (hardening H-5): a class with an empty term range
    /// (`classMin > classMax`) is disabled; no lock length falls in it.
    pub fn enabled(&self) -> bool {
        self.min_blocks <= self.max_blocks
    }
}

/// Mainnet and testnet (`ycash-dd/src/yellowback/params.cpp` `SetCommon`, branch
/// `upgrade/vault-in-term`; in-term plan D-IT-4, D-IT-9, D-IT-10): three flat tiers — A 30–90
/// days at 300 %, B 91–180 days at 400 %, C 181–365 days at 500 % (hardening H-5's disabling of B
/// and C is reversed), with the early-redeem fee 5 / 2.5 / 1 % (D-IT-16).
const MAIN_CLASSES: [TermClass; 3] = [
    TermClass {
        index: 0,
        letter: "A",
        min_blocks: 34_560,
        max_blocks: 103_680,
        base_ratio_bps: 30_000,
        early_redeem_fee_bps: 500,
    },
    TermClass {
        index: 1,
        letter: "B",
        min_blocks: 103_681,
        max_blocks: 207_360,
        base_ratio_bps: 40_000,
        early_redeem_fee_bps: 250,
    },
    TermClass {
        index: 2,
        letter: "C",
        min_blocks: 207_361,
        max_blocks: 420_480,
        base_ratio_bps: 50_000,
        early_redeem_fee_bps: 100,
    },
];

const REGTEST_CLASSES: [TermClass; 3] = [
    TermClass {
        index: 0,
        letter: "A",
        min_blocks: 48,
        max_blocks: 96,
        base_ratio_bps: 30_000,
        early_redeem_fee_bps: 500,
    },
    TermClass {
        index: 1,
        letter: "B",
        min_blocks: 97,
        max_blocks: 144,
        base_ratio_bps: 40_000,
        early_redeem_fee_bps: 250,
    },
    TermClass {
        index: 2,
        letter: "C",
        min_blocks: 145,
        max_blocks: 240,
        base_ratio_bps: 50_000,
        early_redeem_fee_bps: 100,
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

    /// The enabled term classes, in class order (all three on every network since the in-term
    /// plan's D-IT-9; the filter stays for a parameter set that disables one, H-5).
    pub fn enabled_classes(self) -> impl Iterator<Item = &'static TermClass> {
        self.term_classes().iter().filter(|c| c.enabled())
    }

    /// `ATTEST_FEE_BPS`, the attestor fee as a share of the protocol fee (AFEE-1′): 50 % on
    /// mainnet and testnet (H-4, `params.cpp:93`, D-3 had 2,500), 25 % on regtest (`:223`).
    pub fn attest_fee_bps(self) -> i64 {
        match self {
            Network::Mainnet | Network::Testnet => 5_000,
            Network::Regtest => 2_500,
        }
    }

    /// `MAX_MINT` (MINT-2): $100,000 on every network (rpcversion 8, owner decision D-Q-24:
    /// DigiByte's `maxMintAmount` restored; it reverses hardening H-12's $2,500 launch guard; the node's
    /// `params.cpp` `p.maxMint = 10000000`, "bands, the floor and maxMint are mainnet's on every network").
    pub fn max_mint_cents(self) -> u64 {
        MAX_MINT_CENTS
    }

    /// `MINT_REQUIRES_ARMED` where the network fixes it (hardening H-1, `params.cpp:105`):
    /// `Some(true)` on mainnet and testnet, so a server reporting `mintRequiresArmed = false`
    /// there is not believed; `None` on regtest, where `-yellowbackmintrequiresarmed` sets it
    /// and the server's `GetYellowbackInfo.mintRequiresArmed` is the only source.
    pub fn mint_requires_armed(self) -> Option<bool> {
        match self {
            Network::Mainnet | Network::Testnet => Some(true),
            Network::Regtest => None,
        }
    }

    /// The post-Blossom target block spacing, seconds: 75 on every network
    /// (`ycash-dd/src/chainparams.cpp:107,360,570` `nPostBlossomPowTargetSpacing =
    /// POST_BLOSSOM_POW_TARGET_SPACING`, `src/consensus/params.h` 75). The wallet's deadline
    /// dates (H-9.2) are `now + (height − tip) · spacing`.
    pub fn target_spacing_secs(self) -> i64 {
        75
    }

    /// One day in blocks **on the network's own calendar**, the lead of the "claim opens
    /// soon" warning (H-9.2: from `claimHeight − 1 day`): `⌈GRACE / 30⌉`, since `GRACE` is
    /// 30 days (`params.cpp:46`). Mainnet and testnet: 1,152 blocks (= 86,400 s / 75 s);
    /// regtest, whose classes and grace are scaled to blocks a laptop can mine (GRACE 24): 1.
    pub fn day_blocks(self) -> u32 {
        self.grace().div_ceil(30)
    }

    /// The `consensusBranchId`s a server for this network may report: the Ycash epochs from the
    /// Ycash fork on (`ref/ycash/src/consensus/upgrades.cpp:33-57`, `chainparams.cpp:126-138`
    /// main, `:379-395` test). Sprout, Overwinter and Sapling are pre-fork and shared with
    /// Zcash: a signature under them could spend a pre-fork duplicate on Zcash (audit G-5),
    /// so they are never accepted. Regtest activates the upgrades by `-nuparams`; the devnet
    /// signs under Canopy (`yellowback_util.py:139`).
    pub fn branch_ids(self) -> &'static [u32] {
        const YCASH_EPOCHS: [u32; 6] = [
            0x374d_694f,     // Ycash
            0x8e47_1bd6,     // Blossom
            0x6631_4da3,     // Heartwood
            0x19bd_2d2f,     // Canopy
            0xf919_a198,     // NU5 (no activation height on 4.5.0; reserved)
            VAULT_BRANCH_ID, // the vault upgrade (upgrade plan §15.1, U-9)
        ];
        match self {
            Network::Mainnet | Network::Testnet | Network::Regtest => &YCASH_EPOCHS,
        }
    }
}

impl Network {
    /// `CLAIM_DELAY` (upgrade plan U-23, `ycash-dd/src/yellowback/params.cpp` `SetCommon`
    /// `claimDelay = 576` — 12 h, in-term plan D-IT-13, was 1,152 —, `RegtestParams` `claimDelay =
    /// 10`, branch `upgrade/vault-in-term`): the YED vault's delay, i.e. how long a claim's intents
    /// wait before release, the window in which one attestor can cancel a wrong-price claim. A
    /// server reporting another value is refused.
    pub fn claim_delay(self) -> i64 {
        match self {
            Network::Mainnet | Network::Testnet => 576,
            Network::Regtest => 10,
        }
    }

    /// The `UPGRADE_VAULT` activation height compiled into this build: `None` on every network
    /// today (upgrade plan §15.1: mainnet and testnet `NO_ACTIVATION_HEIGHT` until P8 sets them;
    /// regtest by `-nuparams=6d5b7a31:<h>`). Regtest takes the server's height
    /// ([`Network::vault_activation_from_server`]); on mainnet and testnet a server announcing an
    /// activation this build does not know is not believed (see [`signing_branch_id`]).
    pub fn vault_activation_height(self) -> Option<u64> {
        None
    }

    /// True when this network takes the vault activation height from the server (regtest only).
    pub fn vault_activation_from_server(self) -> bool {
        self == Network::Regtest
    }

    /// The Falcon (`TOK-PQ`, scheme 2) activation height compiled into this build
    /// (`Consensus::Params::pqFalconHeight`): [`PQ_FALCON_HEIGHT_MAINNET`] /
    /// [`PQ_FALCON_HEIGHT_TESTNET`]; `None` on regtest, which follows the server
    /// (`-pqfalconheight`). A server reporting another height on mainnet or testnet is refused
    /// (`build::terms::pq_terms`), never silently overridden: if a release ever moves the height,
    /// YEW ships the new constant before connecting to such a node (`docs/release.md`).
    pub fn pq_falcon_height(self) -> Option<u64> {
        match self {
            Network::Mainnet => Some(PQ_FALCON_HEIGHT_MAINNET),
            Network::Testnet => Some(PQ_FALCON_HEIGHT_TESTNET),
            Network::Regtest => None,
        }
    }

    /// The network's YED attestor set (U-22, `Params::attestorSetId`): unset on mainnet and
    /// testnet (YED is off there until a release sets it); regtest's comes from the server
    /// (`-yellowbackattestorset`).
    pub fn attestor_set_id(self) -> Option<[u8; 32]> {
        None
    }
}

/// The consensus branch id of the vault upgrade, `UPGRADE_VAULT` (upgrade plan §15.1, U-9;
/// `ycash-dd/src/consensus/upgrades.cpp` `{0x6d5b7a31, "Vault", …}`). Every ZIP-243 signature in
/// a block at or above the activation height commits to it (`VAULT_BRANCH_ID` in the Python
/// `test_framework/util.py`).
pub const VAULT_BRANCH_ID: u32 = 0x6d5b_7a31;

/// Why a branch id for the next block could not be chosen.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BranchError {
    /// The server's next-block id contradicts the height rule (an upgrade boundary the server and
    /// this wallet disagree on): nothing is signed.
    #[error("branch-mismatch: the server signs block {height} under {server:08x}, the vault upgrade rule gives {ours:08x}")]
    Mismatch {
        /// The next block's height.
        height: u64,
        /// The server's `nextblock` id.
        server: u32,
        /// The id the rule gives.
        ours: u32,
    },
    /// The server reports the Vault branch on a network whose vault activation this build does
    /// not know (mainnet / testnet before P8).
    #[error("branch-unknown: the server reports the vault upgrade active on {0}, which this build does not schedule")]
    UnscheduledVault(&'static str),
}

/// The branch id every transparent signature of a transaction for the **next block** commits to
/// (ZIP-243): the Vault id once `next_height` reaches the vault activation height, else the
/// server's pre-upgrade epoch id (`chaintip`, already checked against [`Network::branch_ids`]).
///
/// `activation`: the network's compiled-in height, or on regtest the server's
/// (`GetChainInfo.upgrades["6d5b7a31"]`). `next_block_server`: `GetChainInfo.nextBlockBranchId`
/// when the server offers it; it must agree with the rule (the one block where `chaintip` and
/// `nextblock` differ is the block before an upgrade, which is what this function exists for).
pub fn signing_branch_id(
    network: Network,
    chaintip_branch: u32,
    next_height: u64,
    activation: Option<u64>,
    next_block_server: Option<u32>,
) -> Result<u32, BranchError> {
    let activation =
        network
            .vault_activation_height()
            .or(if network.vault_activation_from_server() {
                activation
            } else {
                None
            });
    let ours = match activation {
        Some(a) if next_height >= a => VAULT_BRANCH_ID,
        _ => {
            if chaintip_branch == VAULT_BRANCH_ID || next_block_server == Some(VAULT_BRANCH_ID) {
                if !network.vault_activation_from_server() {
                    return Err(BranchError::UnscheduledVault(network.chain_name()));
                }
                return Err(BranchError::Mismatch {
                    height: next_height,
                    server: next_block_server.unwrap_or(chaintip_branch),
                    ours: chaintip_branch,
                });
            }
            chaintip_branch
        }
    };
    if let Some(server) = next_block_server {
        if server != ours {
            return Err(BranchError::Mismatch {
                height: next_height,
                server,
                ours,
            });
        }
    }
    Ok(ours)
}

/// `MAX_MINT`: $100,000 on every network (D-Q-24; [`Network::max_mint_cents`]).
pub const MAX_MINT_CENTS: u64 = 10_000_000;

/// **FEE-1′** (rpcversion 8, owner decision D-Q-23 Option D; `ycash-dd/src/yellowback/params.cpp`
/// `feeBands`, branch `q/fees`): the protocol fee is the debt's dollars in marginal bands, like tax
/// brackets — 1.0 % of the first $1,000, 0.5 % up to $10,000, 0.1 % above (`uptoCents` 0 = unbounded) —
/// the same on every network.
pub const PROTOCOL_FEE_BANDS: [(u64, i64); 3] = [(100_000, 100), (1_000_000, 50), (0, 10)];

/// FEE-1′'s floor: $1 per action (mint, redeem, claim) (`params.cpp` `feeFloorCents = 100`).
pub const PROTOCOL_FEE_FLOOR_CENTS: i64 = 100;

/// MINT-6b (D-Q-23a): one mint's debt is at most max(`MAX_VAULT_SHARE_BPS` of the supply cap,
/// `VAULT_SHARE_FLOOR_CENTS`) (`params.cpp` `maxVaultShareBps = 1000`, `vaultShareFloorCents = 1000000`).
pub const MAX_VAULT_SHARE_BPS: i64 = 1_000;
/// See [`MAX_VAULT_SHARE_BPS`].
pub const VAULT_SHARE_FLOOR_CENTS: i64 = 1_000_000;

/// FEE-1′ in cent-bps (`math.h` `ProtocolFeeUnits`): Σ over the bands of (the debt inside the band) ×
/// its bps, at least `PROTOCOL_FEE_FLOOR_CENTS × 10⁴`.
pub fn protocol_fee_units(debt_cents: u64) -> i64 {
    if debt_cents == 0 {
        return 0;
    }
    let debt = debt_cents.min(i64::MAX as u64) as i64;
    let mut units: i64 = 0;
    let mut lo: i64 = 0;
    for (upto, bps) in PROTOCOL_FEE_BANDS {
        let hi = upto as i64;
        let in_band = if hi == 0 { debt } else { debt.min(hi) } - lo;
        if in_band <= 0 {
            break;
        }
        units = units.saturating_add(in_band.saturating_mul(bps.max(0)));
        lo = hi;
        if hi == 0 {
            break;
        }
    }
    units.max(PROTOCOL_FEE_FLOOR_CENTS * BPS)
}

/// FEE-1′ in cents for display and the RPC (`ProtocolFeeCents`): `⌈units / 10⁴⌉`.
pub fn protocol_fee_cents(debt_cents: u64) -> i64 {
    (protocol_fee_units(debt_cents) + BPS - 1) / BPS
}

/// FEE-1′ in zat at the vault's mint price (`ProtocolFeeZat`): `⌈units · COIN / pMint⌉`; `None` when
/// `p_mint` is undefined (≤ 0).
pub fn protocol_fee_zat(debt_cents: u64, p_mint: i64) -> Option<i64> {
    if p_mint <= 0 {
        return None;
    }
    let num = (protocol_fee_units(debt_cents) as u128) * (COIN as u128);
    Some(i64::try_from(num.div_ceil(p_mint as u128)).unwrap_or(i64::MAX))
}

/// `MIN_MINT`: $100 (`params.cpp:16`, MINT-2).
pub const MIN_MINT_CENTS: u64 = 10_000;

/// `sigmaMultBps` is clamped to `[10⁴, SIGMA_MULT_MAX_BPS]` (spec SIGMA-1; `params.cpp:59`). In-term
/// plan D-IT-5: the multiplier is pinned at 1 (`sigmaRefBps = 0`, `sigmaMultMaxBps = 10,000`), so the
/// required ratio is the class's base ratio.
pub const SIGMA_MULT_MIN_BPS: i64 = 10_000;
/// See [`SIGMA_MULT_MIN_BPS`].
pub const SIGMA_MULT_MAX_BPS: i64 = 10_000;

/// `LOCKTIME_THRESHOLD`: a vault's `claimHeight` must be below it (MINT-2;
/// `ref/ycash/src/script/script.h` `LOCKTIME_THRESHOLD = 500000000`).
pub const LOCKTIME_THRESHOLD: u32 = 500_000_000;

/// **AFEE-1′**: `attestFeeZat = feeZat · ATTEST_FEE_BPS / 10⁴` of the protocol fee (spec §3.3 v3;
/// `math.h` `AttestFeeZat`).
pub fn attest_fee_zat_for(network: Network, fee_zat: i64) -> i64 {
    if fee_zat <= 0 {
        return 0;
    }
    fee_zat.saturating_mul(network.attest_fee_bps()) / BPS
}

/// `CLAIM_THRESHOLD_BPS` θ: 125 % (in-term plan D-IT-2, `params.cpp` `SetCommon`, every network;
/// the upgrade line had 110 %): a vault is underwater at `pClaim` when `collateral · pClaim <
/// mintedCents · 1.25 · COIN` (`math.h` `IsUnderwater`), and the claimant's take under clause (a)
/// carries this margin (RED-5). Since IT-2 a claim is valid at that test at every height from
/// the block after the mint, in term too.
pub const CLAIM_THRESHOLD_BPS: i64 = 12_500;

/// How close the claim price may come to a vault's claimable-at price (`underwaterAt`) before the
/// wallet warns (in-term plan IT-8: "your wallet will warn you"): within 25 % above it, the same
/// margin as YecWallet's `YellowbackPositionsModel::WARN_MARGIN_BPS`.
pub const WARN_MARGIN_BPS: i64 = 2_500;

/// The early-redeem fee of IT-9′ (rpcversion 8; `ycash-dd/src/yellowback/math.h` `EarlyRedeemFeeZat`,
/// branch `q/fees`): `earlyRedeemFeeBps` of the **debt** at the vault's mint price,
/// `⌈debt · bps · COIN / pMint⌉`, no floor; 0 for a class without a fee or an undefined price.
/// Charged (RED-3′, `bad-redeem-early-fee`) on an owner redeem mined below `lockHeight`, on top of
/// FEE-1′, on the FEE-1′ payee's output; not due under FEE-0 (no eligible payee).
pub fn early_redeem_fee_zat(debt_cents: u64, early_redeem_fee_bps: i64, p_mint: i64) -> i64 {
    if debt_cents == 0 || early_redeem_fee_bps <= 0 || p_mint <= 0 {
        return 0;
    }
    let f = ((debt_cents as u128) * (early_redeem_fee_bps as u128) * (COIN as u128))
        .div_ceil(p_mint as u128);
    i64::try_from(f).unwrap_or(i64::MAX)
}

/// The early-redeem fee in dollars (`yed_estimateredeem.earlyRedeemFeeCents`): `⌈debt · bps / 10⁴⌉`
/// cents; what YEW shows beside the debt (the lockup report's recommendation).
pub fn early_redeem_fee_cents(debt_cents: u64, early_redeem_fee_bps: i64) -> i64 {
    if debt_cents == 0 || early_redeem_fee_bps <= 0 {
        return 0;
    }
    let f = (debt_cents as u128 * early_redeem_fee_bps as u128).div_ceil(BPS as u128);
    i64::try_from(f).unwrap_or(i64::MAX)
}

/// True when the claim price `p_claim` (micro-USD per YEC) is within [`WARN_MARGIN_BPS`] above
/// the vault's claimable-at price `underwater_at`: the "your wallet will warn you" state of IT-8.
/// False when either price is unknown (≤ 0).
pub fn near_threshold(p_claim: i64, underwater_at: i64) -> bool {
    p_claim > 0
        && underwater_at > 0
        && (p_claim as i128) * (BPS as i128)
            < (underwater_at as i128) * ((BPS + WARN_MARGIN_BPS) as i128)
}

/// `RESIDUAL_MIN_ZAT`: 0.001 YEC (`params.cpp:92`, RED-5): a smaller residual is not paid.
pub const RESIDUAL_MIN_ZAT: i64 = 100_000;

/// **RED-5b (A1)**: `pEmerg = min(xClaim, aClaim)`, the node's `PriceCombine` when both
/// prices are defined. `None` when either is undefined (≤ 0). Path (b) sizes the claimant cap
/// at this price; it is not `pClaim`.
pub fn emergency_price(x_claim: i64, a_claim: i64) -> Option<i64> {
    if x_claim <= 0 || a_claim <= 0 {
        return None;
    }
    Some(x_claim.min(a_claim))
}

/// **RED-5**: the residual a CLAIM returns to the owner (`math.h` `ClaimantMaxZat`,
/// `ResidualZat`). `claimantMax = ⌈cents · margin · COIN / price⌉` with `margin` =
/// `CLAIM_THRESHOLD_BPS` under clause `"a"` and `10⁴` under `"b"` (no extra margin).
/// **RED-5b (A1):** `price` is `pClaim` under `"a"` and `pEmerg` ([`emergency_price`]) under
/// `"b"` — the same margin as before, the emergency price instead of `pClaim`.
/// `residual = collateral − claimantMax` when positive and at least `RESIDUAL_MIN_ZAT`, else 0.
/// `None` when the sizing price is undefined (the claim is refused).
pub fn residual_zat_for(
    collateral_zat: i64,
    minted_cents: u64,
    price: i64,
    claim_path: &str,
) -> Option<i64> {
    if price <= 0 || minted_cents == 0 {
        return None;
    }
    let margin = if claim_path == "a" {
        CLAIM_THRESHOLD_BPS
    } else {
        BPS
    };
    let num = (minted_cents as u128) * (margin as u128) * (COIN as u128);
    let claimant_max = num.div_ceil(price as u128);
    let residual = match i64::try_from(claimant_max) {
        Ok(m) if collateral_zat > m => collateral_zat - m,
        _ => 0,
    };
    Some(if residual >= RESIDUAL_MIN_ZAT {
        residual
    } else {
        0
    })
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

/// `zat` of YEC in US cents at `price_micro_usd` (µUSD per YEC), rounded down: `zat · price /
/// 10¹²` (10⁸ zat per YEC, 10⁴ µUSD per cent). 0 for an unknown (≤ 0) price. Display only (the
/// early-redeem fee in dollars, the lockup investigation's recommendation); nothing is priced by it.
pub fn zat_to_usd_cents(zat: i64, price_micro_usd: i64) -> i64 {
    if price_micro_usd <= 0 || zat <= 0 {
        return 0;
    }
    ((zat as i128 * price_micro_usd as i128) / 1_000_000_000_000) as i64
}

/// The relay floor, zatoshi per 1,000 bytes (`ycash-dd/src/main.h:68` `DEFAULT_MIN_RELAY_TX_FEE`,
/// the same on ycash6): the lowest size rate YEW ever charges, whatever a server reports.
pub const RELAY_FLOOR_ZAT_PER_KB: i64 = 100;

/// The highest `params.pq.feeRateZatPerKB` YEW accepts from a server: 100× the relay floor
/// (an 8 KB SLH-DSA owner spend would then cost 80,000 zat). A server reporting more is refused
/// as inconsistent rather than allowed to drain fees (the quantum plan's Q8 release multiplier
/// is expected to be a small single digit).
pub const MAX_PQ_FEE_RATE_ZAT_PER_KB: i64 = 100 * RELAY_FLOOR_ZAT_PER_KB;

/// The network fee of a transaction of `size` bytes that spends a post-quantum input (quantum
/// plan §4.5, client survey C-5): `max(floor, rate × size)`, with `CFeeRate::GetFee`'s rounding
/// (`ycash-dd/src/amount.cpp:27-35`: `rate · size / 1000`, and the rate itself when that is 0),
/// exactly the node's `PQSizeFee` (`ycash-dd/src/policy/policy.cpp` `PQSizeFee`, upgrade/quantum-vaults).
///
/// `rate` is the server's `params.pq.feeRateZatPerKB` (at least [`RELAY_FLOOR_ZAT_PER_KB`]).
/// Callers also take the max with [`zip317_conventional_fee`] (audit 04/N-1: both node lines'
/// wallets pay the 6.20.0 conventional fee for a post-quantum input, which a ycash6 relay that
/// opts into ZIP-317 demands and every ycash6 limiter's eviction order rewards).
pub fn pq_size_fee(floor: i64, rate_zat_per_kb: i64, size: usize) -> i64 {
    let rate = rate_zat_per_kb.max(RELAY_FLOOR_ZAT_PER_KB);
    let mut f = rate.saturating_mul(size as i64) / 1000;
    if f == 0 {
        f = rate;
    }
    floor.max(f)
}

/// `CFeeRate::GetFee` (`ycash-dd/src/amount.cpp:27-35`): `rate · size / 1000`, and the rate itself
/// when that rounds to 0 for a positive rate.
pub fn rate_fee(rate_zat_per_kb: i64, size: usize) -> i64 {
    let f = rate_zat_per_kb.max(0).saturating_mul(size as i64) / 1000;
    if f == 0 && rate_zat_per_kb > 0 {
        rate_zat_per_kb
    } else {
        f
    }
}

/// The attested fee floor (rpcversion 8, D-Q-23a; `ycash-dd/src/policy/policy.h`
/// `DEFAULT_ATTESTED_FEE_FLOOR_PER_KB`): no dollar-priced rate goes below 5,000 zat/KB.
pub const ATTESTED_FEE_FLOOR_ZAT_PER_KB: i64 = 5_000;

/// The highest dollars-per-KB target (µUSD/KB) YEW believes from a server: $1/KB (the defaults are
/// $0.02 plain and $0.05 Yellowback, D-Q-26).
pub const MAX_USD_PER_KB_MICRO: i64 = 1_000_000;

/// The highest attested-fee floor (zat/KB) YEW believes from a server: 20× the default.
pub const MAX_FEE_FLOOR_ZAT_PER_KB: i64 = 20 * ATTESTED_FEE_FLOOR_ZAT_PER_KB;

/// The absolute ceiling of a vault / Yellowback network fee (`-yellowbackmaxtxfee`, default 10 YEC;
/// review M-1): whatever cap a server reports, YEW never pays more for one transaction.
pub const MAX_YED_TX_FEE_ZAT: i64 = 10 * COIN;

/// `PRICE_MAX` (owner decision D-Q-22): `UINT32_MAX` µUSD.
pub const PRICE_MAX_MICRO_USD: i64 = 4_294_967_295;

/// `AttestedRateZatPerKB` (`policy.cpp`): the zat/KB rate of a dollar target at a price,
/// `max(floor, ⌈usdPerKBMicro · COIN / price⌉)`; the floor when either is ≤ 0.
pub fn attested_rate_zat_per_kb(usd_per_kb_micro: i64, price_micro_usd: i64, floor: i64) -> i64 {
    if usd_per_kb_micro <= 0 || price_micro_usd <= 0 {
        return floor.max(0);
    }
    let r = ((usd_per_kb_micro as u128) * (COIN as u128)).div_ceil(price_micro_usd as u128);
    i64::try_from(r).unwrap_or(i64::MAX).max(floor.max(0))
}

/// `PQSpendInputSize` (`ycash-dd/src/policy/policy.cpp`): one post-quantum input's serialized size —
/// the outpoint and sequence (40), the scriptSig's compact size and the chunked pushes. SLH-DSA 7,981.
pub fn pq_spend_input_size(scheme: u8) -> usize {
    match crate::pq::pq_sig_pushes_size(scheme) {
        Some(ss) => 40 + if ss > 252 { 3 } else { 1 } + ss,
        None => 0,
    }
}

/// `YedEstimatedSize` (`ycash-dd/src/yellowback/txbuilder.cpp`): the size the node's YED builder prices
/// a Yellowback transaction at before signing — 1,000 bytes, 150 per non-PQ input, and each PQ input
/// (a Falcon holder, the vault owner) at [`pq_spend_input_size`].
pub fn yed_estimated_size(other_inputs: usize, pq_schemes: &[u8]) -> usize {
    1000 + 150 * other_inputs
        + pq_schemes
            .iter()
            .map(|s| pq_spend_input_size(*s))
            .sum::<usize>()
}

/// `ZIP317_MARGINAL_FEE` (`ycash-dd/src/policy/policy.h`, ycash6 `src/zip317.h` `MARGINAL_FEE`):
/// zat per ZIP-317 logical action.
pub const ZIP317_MARGINAL_FEE: i64 = 500;
/// `ZIP317_GRACE_ACTIONS`: the fewest actions a transaction is charged.
pub const ZIP317_GRACE_ACTIONS: usize = 2;
/// `ZIP317_INPUT_SIZE` (`P2PKH_STANDARD_INPUT_SIZE`): transparent input bytes per action.
pub const ZIP317_INPUT_SIZE: usize = 150;
/// `ZIP317_OUTPUT_SIZE` (`P2PKH_STANDARD_OUTPUT_SIZE`): transparent output bytes per action.
pub const ZIP317_OUTPUT_SIZE: usize = 34;

/// `Zip317ConventionalFee(txInBytes, txOutBytes, shieldedActions)` (`ycash-dd/src/policy/policy.cpp`,
/// audit 04/N-1): the 6.20.0 line's ZIP-317 conventional fee,
/// `500 · max(2, max(⌈in/150⌉, ⌈out/34⌉) + shielded)`. `in_bytes` / `out_bytes` are the serialized
/// `vin` / `vout` without their count prefixes. A post-quantum input counts by its bytes (SLH-DSA
/// ~54 actions, Falcon ~11): a ycash6 node started with `-txunpaidactionlimit=0` refuses a
/// transaction paying less, and every ycash6 node's ZIP-401 limiter ranks it first for eviction,
/// so YEW pays at least this for every transaction with a post-quantum input (as both node lines'
/// wallets and builders do).
pub fn zip317_conventional_fee(in_bytes: usize, out_bytes: usize, shielded_actions: usize) -> i64 {
    let actions = in_bytes
        .div_ceil(ZIP317_INPUT_SIZE)
        .max(out_bytes.div_ceil(ZIP317_OUTPUT_SIZE))
        + shielded_actions;
    ZIP317_MARGINAL_FEE.saturating_mul(actions.max(ZIP317_GRACE_ACTIONS) as i64)
}

/// `YED_OUTPUT_BYTES_ESTIMATE` (`ycash-dd/src/yellowback/txbuilder.h`): the `vout` bytes the YED
/// builders' conventional-fee estimate assumes, above any YED transaction's outputs.
pub const YED_OUTPUT_BYTES_ESTIMATE: usize = 600;

/// `YedConventionalFeeEstimate` (`ycash-dd/src/yellowback/txbuilder.cpp`, audit 04/N-1): the
/// ZIP-317 conventional fee a YED transaction with these inputs pays at least, estimated before
/// signing — each post-quantum input at [`pq_spend_input_size`], 150 bytes per other input plus
/// one the caller may not list (the V on the claim path, a carrier), the outputs at
/// [`YED_OUTPUT_BYTES_ESTIMATE`]. 0 without a post-quantum input (the flat and size fees stand).
pub fn yed_conventional_fee_estimate(other_inputs: usize, pq_schemes: &[u8]) -> i64 {
    if pq_schemes.is_empty() {
        return 0;
    }
    let in_bytes = 150 * (other_inputs + 1)
        + pq_schemes
            .iter()
            .map(|s| pq_spend_input_size(*s))
            .sum::<usize>();
    zip317_conventional_fee(in_bytes, YED_OUTPUT_BYTES_ESTIMATE, 0)
}

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

/// `SIGHASH_ALL | SIGHASH_ANYONECANPAY` (`0x81`), the hash type every set signature is made over
/// (`OP_CHECKSETSIG`, audit 01/V-2: a fee input added after the set signed does not break it).
/// YEW never makes a set signature (sets sign through the node's `set_sign*` RPCs); the constant
/// is here so the vector replay checks the node's set-signature digests.
pub const SET_SIGHASH: u32 = SIGHASH_ALL | 0x80;

#[cfg(test)]
mod tests {
    use super::*;

    /// audit 04/N-1: the 6.20.0 conventional fee (`pq_conventional_fee` in the node's
    /// `pq_wallet_tests.cpp`): the grace floor, bytes per action on either side, shielded actions
    /// added, and the YED builders' estimate is 0 without a PQ input.
    #[test]
    fn zip317_conventional_fee_matches_the_node() {
        assert_eq!(zip317_conventional_fee(0, 0, 0), 1_000);
        assert_eq!(zip317_conventional_fee(150, 34, 0), 1_000);
        assert_eq!(zip317_conventional_fee(451, 34, 0), 2_000);
        assert_eq!(zip317_conventional_fee(150, 35 * 34, 0), 17_500);
        assert_eq!(zip317_conventional_fee(150, 34, 3), 2_000);
        // an SLH-DSA input (7,981 bytes) is 54 actions; a Falcon one (1,620) 11
        assert_eq!(
            zip317_conventional_fee(pq_spend_input_size(1), 34, 0),
            27_000
        );
        assert_eq!(
            zip317_conventional_fee(pq_spend_input_size(2), 34, 0),
            5_500
        );
        assert_eq!(yed_conventional_fee_estimate(3, &[]), 0);
        // one SLH-DSA owner + one Falcon holder + 2 P2PKH (+1 unlisted): 7,981 + 1,620 + 450
        assert_eq!(
            yed_conventional_fee_estimate(2, &[1, 2]),
            500 * (7_981 + 1_620 + 450usize).div_ceil(150) as i64
        );
        assert_eq!(SET_SIGHASH, 0x81);
    }

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
            assert!(n.class_for_lock_blocks(34_559).is_none());
            assert!(n.class_for_lock_blocks(2_102_400).is_none());
            // In-term plan D-IT-9 / D-IT-10: B 91–180 d, C 181–365 d, enabled again.
            assert_eq!(n.class_for_lock_blocks(103_681).unwrap().letter, "B");
            assert_eq!(n.class_for_lock_blocks(207_360).unwrap().letter, "B");
            assert_eq!(n.class_for_lock_blocks(207_361).unwrap().letter, "C");
            assert_eq!(n.class_for_lock_blocks(420_480).unwrap().letter, "C");
            assert!(n.class_for_lock_blocks(420_481).is_none());
            let enabled: Vec<&str> = n.enabled_classes().map(|c| c.letter).collect();
            assert_eq!(enabled, ["A", "B", "C"]);
            // D-IT-4 / D-IT-16: 300 / 400 / 500 %, the early-redeem fee 5 / 2.5 / 1 %.
            let ratios: Vec<i64> = n.term_classes().iter().map(|c| c.base_ratio_bps).collect();
            assert_eq!(ratios, [30_000, 40_000, 50_000]);
            let fees: Vec<i64> = n
                .term_classes()
                .iter()
                .map(|c| c.early_redeem_fee_bps)
                .collect();
            assert_eq!(fees, [500, 250, 100]);
            assert_eq!(n.attest_fee_bps(), 5_000);
            assert_eq!(n.max_mint_cents(), 10_000_000);
            assert_eq!(n.mint_requires_armed(), Some(true));
            assert_eq!(n.day_blocks(), 1_152);
            assert_eq!(n.day_blocks() as i64 * n.target_spacing_secs(), 86_400);
        }
        assert_eq!(Network::Regtest.enabled_classes().count(), 3);
        assert_eq!(Network::Regtest.attest_fee_bps(), 2_500);
        assert_eq!(Network::Regtest.max_mint_cents(), 10_000_000);
        assert_eq!(Network::Regtest.mint_requires_armed(), None);
        assert_eq!(Network::Regtest.day_blocks(), 1);
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
            Network::Regtest.class_for_lock_blocks(97).unwrap().letter,
            "B"
        );
        assert_eq!(
            Network::Regtest.class_for_lock_blocks(240).unwrap().letter,
            "C"
        );
        assert!(Network::Regtest.class_for_lock_blocks(47).is_none());
        assert!(Network::Regtest.class_for_lock_blocks(241).is_none());
        // FEE-1′ (every network) / AFEE-1′ (per network).
        assert_eq!(protocol_fee_cents(100_000), 1_000); // 1 % of $1,000
        assert_eq!(protocol_fee_cents(10_000), 100); // the $1 floor
        assert_eq!(protocol_fee_cents(1), 100);
        assert_eq!(protocol_fee_cents(0), 0);
        assert_eq!(protocol_fee_cents(1_000_000), 5_500); // $10 + 0.5 % of $9,000
        assert_eq!(protocol_fee_cents(10_000_000), 14_500); // $55 + 0.1 % of $90,000
        assert_eq!(protocol_fee_cents(100_001), 1_001); // ⌈⌉
                                                        // The node's yed_estimatefee example: $1 at $0.018 = ⌈10⁶ · 10⁸ / 18,000⌉.
        assert_eq!(protocol_fee_zat(10_000, 18_000), Some(5_555_555_556));
        assert_eq!(protocol_fee_zat(100_000, 1_990_000), Some(502_512_563));
        assert_eq!(protocol_fee_zat(100_000, 0), None);
        let r = Network::Regtest;
        assert_eq!(attest_fee_zat_for(r, 50_000_000), 12_500_000);
        let m = Network::Mainnet;
        assert_eq!(attest_fee_zat_for(m, 50_000_000), 25_000_000);
        assert_eq!(attest_fee_zat_for(m, 0), 0);
        // RED-5: $100 at $0.52 under clause (a): claimantMax = ⌈10⁴ · 1.25 · 10⁸ / 520,000⌉.
        let cm = (10_000u128 * 12_500 * 100_000_000).div_ceil(520_000) as i64;
        assert_eq!(
            residual_zat_for(cm + 100_000, 10_000, 520_000, "a"),
            Some(100_000)
        );
        assert_eq!(residual_zat_for(cm + 99_999, 10_000, 520_000, "a"), Some(0));
        assert_eq!(residual_zat_for(cm - 1, 10_000, 520_000, "a"), Some(0));
        let cb = (10_000u128 * 10_000 * 100_000_000).div_ceil(520_000) as i64;
        // Path (b) at a known pEmerg (here equal to the figure passed in): margin stays 10⁴.
        assert_eq!(
            residual_zat_for(cb + 500_000, 10_000, 520_000, "b"),
            Some(500_000)
        );
        assert_eq!(residual_zat_for(cb, 10_000, 0, "a"), None);
        assert_eq!(emergency_price(420_000, 349_000), Some(349_000));
        assert_eq!(emergency_price(349_000, 420_000), Some(349_000));
        assert_eq!(emergency_price(420_000, 0), None);
        assert_eq!(emergency_price(0, 349_000), None);
        // RED-5b A1 worked example: $100,000, 300,000 YEC, pClaim 0.42, pEmerg 0.349.
        // Path (b) residual is 13,467.0487106 YEC. Sizing that row at pClaim is 61,904.76190476 YEC.
        let collateral = 300_000 * COIN;
        let cents = 10_000_000u64;
        assert_eq!(
            residual_zat_for(collateral, cents, 349_000, "b"),
            Some(1_346_704_871_060)
        );
        assert_eq!(
            residual_zat_for(collateral, cents, 420_000, "b"),
            Some(6_190_476_190_476)
        );
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
            assert!(n.branch_ids().contains(&VAULT_BRANCH_ID));
        }
        assert_eq!(Network::Mainnet.claim_delay(), 576);
        assert_eq!(Network::Regtest.claim_delay(), 10);
        assert_eq!(CLAIM_THRESHOLD_BPS, 12_500);
        assert_eq!(SIGMA_MULT_MAX_BPS, SIGMA_MULT_MIN_BPS);
        let rr: Vec<i64> = Network::Regtest
            .term_classes()
            .iter()
            .map(|c| c.base_ratio_bps)
            .collect();
        assert_eq!(rr, [30_000, 40_000, 50_000]);
    }

    #[test]
    fn early_redeem_fee_is_the_nodes() {
        // math.h EarlyRedeemFeeZat (IT-9′): 5 % of the $1,000 debt at $1.99 = ⌈5·10¹⁵ / 1,990,000⌉.
        assert_eq!(early_redeem_fee_zat(100_000, 500, 1_990_000), 2_512_562_815);
        assert_eq!(early_redeem_fee_zat(100_000, 0, 1_990_000), 0);
        assert_eq!(early_redeem_fee_zat(0, 500, 1_990_000), 0);
        assert_eq!(early_redeem_fee_zat(100_000, 500, 0), 0);
        assert_eq!(early_redeem_fee_zat(u64::MAX, 10_000, 1), i64::MAX);
        assert_eq!(early_redeem_fee_cents(100_000, 500), 5_000);
        assert_eq!(early_redeem_fee_cents(100_001, 250), 2_501);
    }

    #[test]
    fn warning_within_a_quarter_above_the_claimable_price() {
        // YecWallet's nearThreshold: pClaim · 10⁴ < underwaterAt · 12,500.
        assert!(near_threshold(500_000, 400_001));
        assert!(!near_threshold(500_000, 400_000));
        assert!(near_threshold(400_000, 400_000));
        assert!(near_threshold(1, 400_000));
        assert!(!near_threshold(0, 400_000));
        assert!(!near_threshold(500_000, 0));
    }

    #[test]
    fn branch_id_by_height() {
        const CANOPY: u32 = 0x19bd_2d2f;
        let r = Network::Regtest;
        // Before activation: the epoch id; from the activation height on: Vault.
        assert_eq!(
            signing_branch_id(r, CANOPY, 149, Some(150), None),
            Ok(CANOPY)
        );
        assert_eq!(
            signing_branch_id(r, CANOPY, 150, Some(150), None),
            Ok(VAULT_BRANCH_ID)
        );
        // The block before the upgrade: chaintip says Canopy, nextblock Vault; both agree.
        assert_eq!(
            signing_branch_id(r, CANOPY, 150, Some(150), Some(VAULT_BRANCH_ID)),
            Ok(VAULT_BRANCH_ID)
        );
        assert_eq!(
            signing_branch_id(r, VAULT_BRANCH_ID, 151, Some(150), Some(VAULT_BRANCH_ID)),
            Ok(VAULT_BRANCH_ID)
        );
        // No activation known: the server's nextblock may not claim Vault.
        assert!(matches!(
            signing_branch_id(r, CANOPY, 150, None, Some(VAULT_BRANCH_ID)),
            Err(BranchError::Mismatch { .. })
        ));
        // A disagreeing server is refused.
        assert!(matches!(
            signing_branch_id(r, CANOPY, 150, Some(150), Some(CANOPY)),
            Err(BranchError::Mismatch { .. })
        ));
        // Mainnet schedules no vault upgrade in this build: a server activation is not believed.
        assert_eq!(
            signing_branch_id(Network::Mainnet, CANOPY, 3_500_000, Some(10), None),
            Ok(CANOPY)
        );
        assert!(matches!(
            signing_branch_id(Network::Mainnet, VAULT_BRANCH_ID, 3_500_000, Some(10), None),
            Err(BranchError::UnscheduledVault("main"))
        ));
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
