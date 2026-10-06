// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

// The one real implementation of WalletApi: the generated flutter_rust_bridge functions
// (src/rust/api.dart, from core/src/api.rs). Nothing else under lib/ calls the bridge.
import 'dart:io' show Platform;

import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart' show ExternalLibrary;

import '../src/rust/api.dart' as rust;
import '../src/rust/frb_generated.dart';
import 'wallet_api.dart';

class RustWalletApi implements WalletApi {
  const RustWalletApi();

  /// Load the core once, before `runApp`. On iOS the core is a static library force-loaded
  /// into the app binary (ios/Flutter/YewCore.xcconfig), so the symbols are looked up in the
  /// process; Android and desktop load `libyew_core.so` / the default library by name.
  static Future<void> init() => RustLib.init(
    externalLibrary: Platform.isIOS ? ExternalLibrary.process(iKnowHowToUseIt: true) : null,
  );

  @override
  List<DefaultEndpoint> defaultServers({required NetworkId network}) => rust.defaultServers(network: network);

  @override
  Future<ServerProbe> probeServer({
    required String server,
    required bool plain,
    String? caPem,
    required NetworkId network,
  }) => rust.probeServer(server: server, plain: plain, caPem: caPem, network: network);

  @override
  Future<Created> createWallet({
    String? seedWords,
    required String passphrase,
    int? birthday,
    required NetworkId network,
    required String server,
    required bool plain,
    String? caPem,
    required String dataDir,
  }) => rust.createWallet(
    seedWords: seedWords,
    passphrase: passphrase,
    birthday: birthday,
    network: network,
    server: server,
    plain: plain,
    caPem: caPem,
    dataDir: dataDir,
  );

  @override
  Future<String> unlock({
    required String seedWords,
    required String passphrase,
    required NetworkId network,
    required String server,
    required bool plain,
    String? caPem,
    required String dataDir,
  }) => rust.unlock(
    seedWords: seedWords,
    passphrase: passphrase,
    network: network,
    server: server,
    plain: plain,
    caPem: caPem,
    dataDir: dataDir,
  );

  @override
  Future<void> lock() => rust.lock();

  @override
  bool isUnlocked() => rust.isUnlocked();

  @override
  Future<void> setServer({required String server, required bool plain, String? caPem}) =>
      rust.setServer(server: server, plain: plain, caPem: caPem);

  @override
  Future<Status> status() => rust.status();

  @override
  Future<Balances> balances() => rust.balances();

  @override
  Future<AddressPair> receiveAddress({ReceiveKind kind = ReceiveKind.transparent, required bool fresh}) =>
      rust.receiveAddress(kind: kind, fresh: fresh);

  @override
  Future<AddressPair> newShieldedAddress() => rust.newShieldedAddress();

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
    String? memo,
  }) => rust.sendYecPreview(to: to, zat: zat, sendEverything: sendEverything, memo: memo);

  @override
  Future<SendResult> sendYecConfirm({required String previewId}) =>
      rust.sendYecConfirm(previewId: previewId);

  @override
  Future<YecPreview> movePreview({required MoveDirection direction, int? amountZat}) =>
      rust.movePreview(direction: direction, amountZat: amountZat);

  @override
  Future<SendResult> moveConfirm({required String previewId}) => rust.moveConfirm(previewId: previewId);

  @override
  Future<ParamsStatus> paramsStatus() => rust.paramsStatus();

  @override
  Stream<ParamsProgress> downloadParams({required String baseUrl}) => rust.downloadParams(baseUrl: baseUrl);

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
  Future<MintAvailability> mintAvailability() => rust.mintAvailability();

  @override
  Future<MintEstimate> mintEstimate({required int cents, required int lockBlocks}) =>
      rust.mintEstimate(cents: cents, lockBlocks: lockBlocks);

  @override
  Future<MintStatus> mintStart({required int cents, required int lockBlocks, required MintTerms confirmed}) =>
      rust.mintStart(cents: cents, lockBlocks: lockBlocks, confirmed: confirmed);

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
  Future<RedeemPreview> redeemPreview({required String vaultTxid}) => rust.redeemPreview(vaultTxid: vaultTxid);

  @override
  Future<RedeemResult> redeemConfirm({required String previewId}) => rust.redeemConfirm(previewId: previewId);

  @override
  Future<List<ClaimableItem>> claimable() => rust.claimable();

  @override
  Future<MintStatus> claim({required String vaultTxid, required ClaimTerms confirmed}) =>
      rust.claim(vaultTxid: vaultTxid, confirmed: confirmed);

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
