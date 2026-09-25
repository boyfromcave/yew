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
        Created,
        DefaultEndpoint,
        DryRun,
        ErrorKind,
        HistoryItem,
        HistoryPage,
        MintEstimate,
        MintStatus,
        NetworkId,
        Recipient,
        RedeemResult,
        SendResult,
        ServerProbe,
        Status,
        SyncEvent,
        SyncStage,
        VaultSummary,
        WifExport,
        YecPreview,
        YedPreview,
        YellowbackStatus,
        YewError;

abstract class WalletApi {
  /// The default endpoints for a network, in order (none for mainnet and testnet until the
  /// owner supplies them: docs/release.md "Default endpoints").
  List<DefaultEndpoint> defaultServers({required NetworkId network});

  Future<ServerProbe> probeServer({
    required String server,
    required bool plain,
    required NetworkId network,
  });

  Future<Created> createWallet({
    String? seedWords,
    required String passphrase,
    int? birthday,
    required NetworkId network,
    required String server,
    required bool plain,
    required String dataDir,
  });

  Future<String> unlock({
    required String seedWords,
    required String passphrase,
    required NetworkId network,
    required String server,
    required bool plain,
    required String dataDir,
  });

  Future<void> lock();

  bool isUnlocked();

  Future<void> setServer({required String server, required bool plain});

  Future<Status> status();

  Future<Balances> balances();

  Future<AddressPair> receiveAddress({required bool fresh});

  Future<List<AddressPair>> addresses();

  Future<HistoryPage> history({required int page, required int pageSize});

  Future<YecPreview> sendYecPreview({
    required String to,
    required int zat,
    required bool sendEverything,
  });

  Future<SendResult> sendYecConfirm({required String previewId});

  Future<YedPreview> sendYedPreview({required List<Recipient> recipients});

  Future<SendResult> sendYedConfirm({required String previewId});

  Future<WifExport> exportWif({required String address});

  Future<AddressPair> importWif({required String wif, int? birthday});

  Stream<SyncEvent> syncNow();

  // ---- Yellowback operations (plan §3.4, §5.3; Phase W4). Every broadcast runs through the
  // core's gate; the app only renders the rows the core returns.

  Future<MintEstimate> mintEstimate({required int cents, required int lockBlocks});

  Future<MintStatus> mintStart({required int cents, required int lockBlocks});

  Future<MintStatus> mintStatus({required int mintId});

  Future<List<MintStatus>> mints();

  Future<MintStatus> mintFinish({required int mintId});

  Future<MintStatus> mintSweep({required int mintId});

  Future<List<VaultSummary>> vaults();

  Future<RedeemResult> redeem({required String vaultTxid});

  Future<List<ClaimableItem>> claimable();

  Future<MintStatus> claim({required String vaultTxid});

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
