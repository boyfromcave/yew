// The one real implementation of WalletApi: the generated flutter_rust_bridge functions
// (src/rust/api.dart, from core/src/api.rs). Nothing else under lib/ calls the bridge.
import '../src/rust/api.dart' as rust;
import '../src/rust/frb_generated.dart';
import 'wallet_api.dart';

class RustWalletApi implements WalletApi {
  const RustWalletApi();

  /// Load the core once, before `runApp`.
  static Future<void> init() => RustLib.init();

  @override
  List<DefaultEndpoint> defaultServers({required NetworkId network}) => rust.defaultServers(network: network);

  @override
  Future<ServerProbe> probeServer({
    required String server,
    required bool plain,
    required NetworkId network,
  }) => rust.probeServer(server: server, plain: plain, network: network);

  @override
  Future<Created> createWallet({
    String? seedWords,
    required String passphrase,
    int? birthday,
    required NetworkId network,
    required String server,
    required bool plain,
    required String dataDir,
  }) => rust.createWallet(
    seedWords: seedWords,
    passphrase: passphrase,
    birthday: birthday,
    network: network,
    server: server,
    plain: plain,
    dataDir: dataDir,
  );

  @override
  Future<String> unlock({
    required String seedWords,
    required String passphrase,
    required NetworkId network,
    required String server,
    required bool plain,
    required String dataDir,
  }) => rust.unlock(
    seedWords: seedWords,
    passphrase: passphrase,
    network: network,
    server: server,
    plain: plain,
    dataDir: dataDir,
  );

  @override
  Future<void> lock() => rust.lock();

  @override
  bool isUnlocked() => rust.isUnlocked();

  @override
  Future<void> setServer({required String server, required bool plain}) =>
      rust.setServer(server: server, plain: plain);

  @override
  Future<Status> status() => rust.status();

  @override
  Future<Balances> balances() => rust.balances();

  @override
  Future<AddressPair> receiveAddress({required bool fresh}) => rust.receiveAddress(fresh: fresh);

  @override
  Future<List<AddressPair>> addresses() => rust.addresses();

  @override
  Future<HistoryPage> history({required int page, required int pageSize}) =>
      rust.history(page: page, pageSize: pageSize);

  @override
  Future<YecPreview> sendYecPreview({
    required String to,
    required int zat,
    required bool sendEverything,
  }) => rust.sendYecPreview(to: to, zat: zat, sendEverything: sendEverything);

  @override
  Future<SendResult> sendYecConfirm({required String previewId}) =>
      rust.sendYecConfirm(previewId: previewId);

  @override
  Future<YedPreview> sendYedPreview({required List<Recipient> recipients}) =>
      rust.sendYedPreview(recipients: recipients);

  @override
  Future<SendResult> sendYedConfirm({required String previewId}) =>
      rust.sendYedConfirm(previewId: previewId);

  @override
  Future<WifExport> exportWif({required String address}) => rust.exportWif(address: address);

  @override
  Future<AddressPair> importWif({required String wif, int? birthday}) =>
      rust.importWif(wif: wif, birthday: birthday);

  @override
  Stream<SyncEvent> syncNow() => rust.syncNow();

  @override
  Future<MintEstimate> mintEstimate({required int cents, required int lockBlocks}) =>
      rust.mintEstimate(cents: cents, lockBlocks: lockBlocks);

  @override
  Future<MintStatus> mintStart({required int cents, required int lockBlocks}) =>
      rust.mintStart(cents: cents, lockBlocks: lockBlocks);

  @override
  Future<MintStatus> mintStatus({required int mintId}) => rust.mintStatus(mintId: mintId);

  @override
  Future<List<MintStatus>> mints() => rust.mints();

  @override
  Future<MintStatus> mintFinish({required int mintId}) => rust.mintFinish(mintId: mintId);

  @override
  Future<MintStatus> mintSweep({required int mintId}) => rust.mintSweep(mintId: mintId);

  @override
  Future<List<VaultSummary>> vaults() => rust.vaults();

  @override
  Future<RedeemResult> redeem({required String vaultTxid}) => rust.redeem(vaultTxid: vaultTxid);

  @override
  Future<List<ClaimableItem>> claimable() => rust.claimable();

  @override
  Future<MintStatus> claim({required String vaultTxid}) => rust.claim(vaultTxid: vaultTxid);

  @override
  String generateSeedWords({required int words}) => rust.generateSeedWords(words: words);

  @override
  void checkSeedWords({required String seedWords}) => rust.checkSeedWords(seedWords: seedWords);

  @override
  AddressCheck validateAddress({required NetworkId network, required String address}) =>
      rust.validateAddress(network: network, address: address);

  @override
  String coreVersion() => rust.coreVersion();
}
