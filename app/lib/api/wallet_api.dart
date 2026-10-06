// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

// The interface every screen depends on (plan §3.4). One implementation is the generated
// flutter_rust_bridge functions (rust_wallet_api.dart); the widget tests use a fake. The
// models are the generated data classes of src/rust/api.dart: plain, const, no behaviour.
import '../src/rust/api.dart';

export '../src/rust/api.dart'
    show
        AddressCheck,
        AddressPair,
        Balances,
        ClaimableItem,
        ClaimTerms,
        Created,
        DefaultEndpoint,
        DryRun,
        ErrorKind,
        HistoryItem,
        HistoryPage,
        MintAvailability,
        MintEstimate,
        MintStatus,
        MintTerms,
        MoveDirection,
        NetworkId,
        ParamsProgress,
        ParamsStatus,
        ReceiveKind,
        Recipient,
        RedeemPreview,
        RedeemResult,
        SendResult,
        ServerProbe,
        Status,
        SyncEvent,
        SyncStage,
        VaultSummary,
        WifExport,
        YecFunding,
        YecPreview,
        YedPreview,
        YellowbackStatus,
        YewError;

abstract class WalletApi {
  /// The default endpoints for a network, in order (none for mainnet and testnet until the
  /// owner supplies them: docs/release.md "Default endpoints").
  List<DefaultEndpoint> defaultServers({required NetworkId network});

  /// [caPem] pins one certificate (PEM) as the only trust anchor for the server (audit G-4);
  /// null or empty = the platform's roots plus the bundled Mozilla roots.
  Future<ServerProbe> probeServer({
    required String server,
    required bool plain,
    String? caPem,
    required NetworkId network,
  });

  Future<Created> createWallet({
    String? seedWords,
    required String passphrase,
    int? birthday,
    required NetworkId network,
    required String server,
    required bool plain,
    String? caPem,
    required String dataDir,
  });

  Future<String> unlock({
    required String seedWords,
    required String passphrase,
    required NetworkId network,
    required String server,
    required bool plain,
    String? caPem,
    required String dataDir,
  });

  Future<void> lock();

  bool isUnlocked();

  Future<void> setServer({required String server, required bool plain, String? caPem});

  Future<Status> status();

  Future<Balances> balances();

  /// The receive address of [kind]: `s…` (transparent), `ye…` (YED) or `ys1…` (private).
  Future<AddressPair> receiveAddress({ReceiveKind kind = ReceiveKind.transparent, required bool fresh});

  /// A new private address of the same private balance (Receive → "New private address").
  Future<AddressPair> newShieldedAddress();

  Future<List<AddressPair>> addresses();

  Future<HistoryPage> history({required int page, required int pageSize});

  /// Funded privacy first by the core; [memo] only for a private (`ys1…`) recipient.
  Future<YecPreview> sendYecPreview({
    required String to,
    required int zat,
    required bool sendEverything,
    String? memo,
  });

  Future<SendResult> sendYecConfirm({required String previewId});

  /// Move YEC between the wallet's own private and public balances (yew-shielded plan S4);
  /// [amountZat] null = all, less the fee. The preview is a send preview to the own address.
  Future<YecPreview> movePreview({required MoveDirection direction, int? amountZat});

  Future<SendResult> moveConfirm({required String previewId});

  /// The Sapling proving files on this device (no network).
  Future<ParamsStatus> paramsStatus();

  /// Fetch the proving files from [baseUrl] (Settings; no host is compiled in), each kept only
  /// if its SHA-256 matches the core's pin. Ends with a `finished` event.
  Stream<ParamsProgress> downloadParams({required String baseUrl});

  Future<YedPreview> sendYedPreview({required List<Recipient> recipients});

  Future<SendResult> sendYedConfirm({required String previewId});

  Future<WifExport> exportWif({required String address});

  Future<AddressPair> importWif({required String wif, int? birthday});

  Stream<SyncEvent> syncNow();

  // ---- Yellowback operations (plan §3.4, §5.3; Phase W4). Every broadcast runs through the
  // core's gate; the app only renders the rows the core returns.

  /// Whether a mint can be made now (hardening H-1, H-5): `allowed`, else the `reason` the Mint
  /// screen shows instead of the form (the price not armed under `mintRequiresArmed`, or no
  /// term class mintable). Connects; no sync.
  Future<MintAvailability> mintAvailability();

  Future<MintEstimate> mintEstimate({required int cents, required int lockBlocks});

  /// [confirmed] is the estimate the user saw: the core refuses a server answer whose
  /// collateral, fee, payee or class differs from it (audit G-2).
  Future<MintStatus> mintStart({required int cents, required int lockBlocks, required MintTerms confirmed});

  Future<MintStatus> mintStatus({required int mintId});

  Future<List<MintStatus>> mints();

  Future<MintStatus> mintFinish({required int mintId});

  Future<MintStatus> mintSweep({required int mintId});

  Future<List<VaultSummary>> vaults();

  /// Build and sign the redeem (or VOID release); nothing is sent. The preview carries the
  /// fee, its payee and the collateral returned, shown before the slider (audit G-2).
  Future<RedeemPreview> redeemPreview({required String vaultTxid});

  Future<RedeemResult> redeemConfirm({required String previewId});

  Future<List<ClaimableItem>> claimable();

  /// [confirmed] is the debt and the take the user saw on the row (H-9.3): the core refuses
  /// before signing when the server's numbers would burn more YED or pay less YEC.
  Future<MintStatus> claim({required String vaultTxid, required ClaimTerms confirmed});

  String generateSeedWords({required int words});

  /// Throws a [YewError] of kind [ErrorKind.input] when the words are not a mnemonic.
  void checkSeedWords({required String seedWords});

  AddressCheck validateAddress({required NetworkId network, required String address});

  String coreVersion();
}

/// The text to show for any error the bridge throws: a [YewError]'s message verbatim
/// (a gate refusal carries the node's verdict), anything else as-is.
String messageOf(Object error) => error is YewError ? error.message : error.toString();

/// The kind of a bridge error, or `null` for anything else.
ErrorKind? kindOf(Object error) => error is YewError ? error.kind : null;

/// The largest memo a private payment carries, in UTF-8 bytes (Sapling memo field).
const int maxMemoBytes = 512;
