// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

// A fake WalletApi for the widget tests (plan §6.2 "Flutter widget tests with a mocked
// bridge"): scripted answers, recorded calls, no core.
import 'dart:async';
import 'dart:typed_data' show Uint32List;
import 'dart:ui' show Size;

import 'package:flutter_test/flutter_test.dart';

import 'package:yew_app/api/wallet_api.dart';
import 'package:yew_app/app.dart';
import 'package:yew_app/state/app_state.dart';
import 'package:yew_app/state/secrets.dart';

const fakeYe = 'yr1qkfcjyqz9y4d3qz9v6y8v6y8v6y8v6y8v6y8v6y8v6y8v6y8';
const fakeS = 'smV6y8v6y8v6y8v6y8v6y8v6y8v6y8v6y8v6y8v';
const fakeZ = 'yregtestsapling1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqfake';
const fakeZ2 = 'yregtestsapling1zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzsecond';
const fakeWords = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

class FakeWalletApi implements WalletApi {
  bool unlockedFlag = false;
  final List<String> calls = [];
  Balances balancesAnswer = const Balances(
    yecZat: 150000000,
    yecReservedZat: 105000,
    yecPendingZat: 0,
    yedCents: 5000,
    yedPendingCents: 0,
    priceMicroUsd: 520000,
    heldCount: 0,
    syncHeight: 484,
    yedSendMinZat: 21000, yecShieldedZat: 0, yecShieldedSpendableZat: 0, yecShieldedPendingZat: 0, shieldedScannedHeight: 0, shieldedSendable: false,
  );
  List<HistoryItem> historyAnswer = const [];
  Object? yedPreviewError;
  Object? yedConfirmError;
  Object? yecPreviewError;
  DryRun dryRun = const DryRun(valid: true, verdict: 'ok', burnedCents: 0, wouldBeRejected: false, yedInCents: 5000, yedOutCents: 5000, accepted: true);
  AddressPair address = const AddressPair(ye: fakeYe, s: fakeS, path: "m/44'/347'/0'/0/0", coveredBySeed: true, address: fakeS, kind: ReceiveKind.transparent);
  int fresh = 0;

  // ---- S3: private (shielded) answers, scripted.
  AddressPair privateAddress = const AddressPair(ye: '', s: '', path: "m/32'/347'/0'", coveredBySeed: true, address: fakeZ, kind: ReceiveKind.shielded);
  int freshPrivate = 0;
  YecFunding yecFunding = YecFunding.transparent;
  bool revealsShielded = false;
  bool paramsNeeded = false;
  Object? yecConfirmError;
  List<ParamsProgress> paramsEvents = const [
    ParamsProgress(file: 'sapling-spend.params', doneBytes: 25000000, totalBytes: 51551256, finished: false),
    ParamsProgress(file: 'sapling-output.params', doneBytes: 51551256, totalBytes: 51551256, finished: true),
  ];
  Object? paramsError;
  StreamController<ParamsProgress>? paramsController;

  /// When set, `syncNow` streams from it (a test drives the private-scan states).
  StreamController<SyncEvent>? syncController;

  // ---- W4: the two-step table and the vaults, scripted.
  List<MintStatus> mintsAnswer = [];
  List<VaultSummary> vaultsAnswer = const [];
  List<ClaimableItem> claimableAnswer = const [];
  Object? mintEstimateError;
  Object? mintStartError;
  Object? mintFinishError;
  Object? mintSweepError;
  Object? redeemError;
  Object? redeemConfirmError;
  String payee = fakeS;
  Object? claimableError;
  Object? claimError;
  int tip = 484;
  bool armed = true;

  MintStatus mintRow({required int id, required String state, String kind = 'mint', int cents = 2500, int tip = 484, int refHeight = 480, String vaultTxid = ''}) {
    final expiry = refHeight + 40;
    final open = tip + 1 + 3 <= expiry;
    return MintStatus(
      mintId: id,
      kind: kind,
      state: state,
      createdHeight: refHeight + 2,
      cents: cents,
      lockBlocks: 48,
      termClass: 'A',
      refHeight: refHeight,
      lockHeight: refHeight + 48,
      claimHeight: refHeight + 68,
      expiryHeight: expiry,
      collateralZat: 950000000,
      feeZat: 1000,
      attestFeeZat: 0,
      residualZat: 0,
      payee: payee,
      attestPayee: '',
      bundleSeqs: '0,1,2',
      carrierTxid: 'ca' * 32,
      mainTxid: state == 'MAIN_SENT' || state == 'DONE' ? 'ma' * 32 : '',
      sweepTxid: state == 'SWEEP_SENT' || state == 'SWEPT' ? '5e' * 32 : '',
      vaultTxid: vaultTxid,
      tip: tip,
      inProgress: state == 'CARRIER_SENT' || state == 'CARRIER_CONFIRMED' || state == 'MAIN_SENT',
      windowOpen: open,
      blocksLeft: open ? expiry - (tip + 4) : 0,
      canFinish: state == 'CARRIER_CONFIRMED' && open,
      canSweep: state == 'LAPSED',
      note: '',
    );
  }

  VaultSummary vault({required String txid, String status = 'ACTIVE', int cents = 2500, int lockHeight = 528, int tip = 484, bool underwater = false, String voidReason = ''}) => VaultSummary(
    vaultTxid: txid,
    status: status,
    ownerAddress: fakeYe,
    termClass: 'A',
    cents: cents,
    collateralZat: 950000000,
    lockHeight: lockHeight,
    claimHeight: lockHeight + 20,
    mintHeight: 482,
    tip: tip,
    open: status == 'ACTIVE' || status == 'VOID',
    redeemable: status == 'ACTIVE' && tip >= lockHeight,
    blocksUntilRedeem: lockHeight > tip ? lockHeight - tip : 0,
    releasable: status == 'VOID',
    claimable: underwater,
    underwaterAtMicroUsd: 400000,
    underwater: underwater,
    closeHeight: status == 'CLOSED' || status == 'CLAIMED' ? 530 : 0,
    closingTxid: status == 'CLOSED' || status == 'CLAIMED' ? 'c1' * 32 : '',
    voidReason: voidReason,
  );

  void _set(MintStatus m) {
    final i = mintsAnswer.indexWhere((x) => x.mintId == m.mintId);
    if (i < 0) {
      mintsAnswer.add(m);
    } else {
      mintsAnswer[i] = m;
    }
  }

  @override
  Future<MintEstimate> mintEstimate({required int cents, required int lockBlocks}) async {
    calls.add('mintEstimate $cents $lockBlocks');
    if (mintEstimateError != null) throw mintEstimateError!;
    final klass = lockBlocks <= 96 ? 'A' : (lockBlocks <= 144 ? 'B' : 'C');
    final collateral = cents * 19000 * 2 ~/ 1; // 1 YED = $1, $0.52/YEC, 200 %
    final total = collateral + 10000 + 10000 + 2000 + 1000;
    final available = balancesAnswer.yecZat + balancesAnswer.yecReservedZat;
    return MintEstimate(
      cents: cents,
      lockBlocks: lockBlocks,
      termClass: klass,
      refHeight: tip - 4,
      lockHeight: tip - 4 + lockBlocks,
      claimHeight: tip - 4 + lockBlocks + 20,
      expiryHeight: tip - 4 + 40,
      requiredZat: collateral - 500,
      collateralZat: collateral,
      feeZat: 1000,
      attestFeeZat: 0,
      payee: payee,
      carrierZat: 10000,
      tokenZat: 10000,
      networkFeeZat: 2000,
      totalZat: total,
      availableZat: available,
      affordable: available >= total,
      pMintMicroUsd: 520000,
      armed: armed,
      bundleSeqs: Uint32List.fromList([0, 1, 2]),
    );
  }

  @override
  Future<MintStatus> mintStart({required int cents, required int lockBlocks, required MintTerms confirmed}) async {
    calls.add('mintStart $cents $lockBlocks');
    calls.add('mintStart confirmed ${confirmed.collateralZat} ${confirmed.feeZat} ${confirmed.payee} ${confirmed.termClass}');
    if (mintStartError != null) throw mintStartError!;
    final m = mintRow(id: mintsAnswer.length + 1, state: 'CARRIER_SENT', cents: cents, tip: tip, refHeight: tip - 4);
    _set(m);
    return m;
  }

  @override
  Future<MintStatus> mintStatus({required int mintId}) async => mintsAnswer.firstWhere((m) => m.mintId == mintId);

  @override
  Future<List<MintStatus>> mints() async => List.of(mintsAnswer);

  @override
  Future<MintStatus> mintFinish({required int mintId}) async {
    calls.add('mintFinish $mintId');
    if (mintFinishError != null) throw mintFinishError!;
    final old = mintsAnswer.firstWhere((m) => m.mintId == mintId);
    final m = mintRow(id: mintId, state: 'MAIN_SENT', kind: old.kind, cents: old.cents, tip: old.tip, refHeight: old.refHeight, vaultTxid: old.vaultTxid);
    _set(m);
    return m;
  }

  @override
  Future<MintStatus> mintSweep({required int mintId}) async {
    calls.add('mintSweep $mintId');
    if (mintSweepError != null) throw mintSweepError!;
    final old = mintsAnswer.firstWhere((m) => m.mintId == mintId);
    final m = mintRow(id: mintId, state: 'SWEEP_SENT', kind: old.kind, cents: old.cents, tip: old.tip, refHeight: old.refHeight);
    _set(m);
    return m;
  }

  @override
  Future<List<VaultSummary>> vaults() async => vaultsAnswer;

  @override
  Future<RedeemPreview> redeemPreview({required String vaultTxid}) async {
    calls.add('redeemPreview $vaultTxid');
    if (redeemError != null) throw redeemError!;
    final v = vaultsAnswer.firstWhere((x) => x.vaultTxid == vaultTxid);
    return RedeemPreview(
      previewId: 'rp-$vaultTxid',
      vaultTxid: vaultTxid,
      kind: v.releasable ? 'release' : 'redeem',
      burnCents: v.releasable ? 0 : v.cents,
      extraBurnCents: 0,
      changeCents: v.releasable ? 0 : balancesAnswer.yedCents - v.cents,
      yedInputs: v.releasable ? 0 : 1,
      feeZat: v.releasable ? 0 : 50000000,
      payee: v.releasable ? '' : payee,
      collateralZat: v.collateralZat - (v.releasable ? 1000 : 50001000),
      collateralAddress: fakeS,
      lockTime: v.lockHeight,
      expiryHeight: tip + 40,
      txid: 'ed' * 32,
    );
  }

  @override
  Future<RedeemResult> redeemConfirm({required String previewId}) async {
    calls.add('redeemConfirm $previewId');
    if (redeemConfirmError != null) throw redeemConfirmError!;
    final vaultTxid = previewId.substring(3);
    final v = vaultsAnswer.firstWhere((x) => x.vaultTxid == vaultTxid);
    return RedeemResult(
      txid: 'ed' * 32,
      verdict: 'ok',
      kind: v.releasable ? 'release' : 'redeem',
      burnCents: v.releasable ? 0 : v.cents,
      extraBurnCents: 0,
      changeCents: v.releasable ? 0 : balancesAnswer.yedCents - v.cents,
      feeZat: v.releasable ? 0 : 50000000,
      payee: v.releasable ? '' : payee,
      collateralZat: v.collateralZat - (v.releasable ? 1000 : 50001000),
      collateralAddress: fakeS,
      lockTime: v.lockHeight,
      expiryHeight: tip + 40,
    );
  }

  @override
  Future<List<ClaimableItem>> claimable() async {
    calls.add('claimable');
    if (claimableError != null) throw claimableError!;
    return claimableAnswer;
  }

  @override
  Future<MintStatus> claim({required String vaultTxid}) async {
    calls.add('claim $vaultTxid');
    if (claimError != null) throw claimError!;
    final c = claimableAnswer.firstWhere((x) => x.vaultTxid == vaultTxid);
    final m = mintRow(id: mintsAnswer.length + 1, state: 'CARRIER_SENT', kind: 'claim', cents: c.cents, tip: tip, refHeight: tip - 4, vaultTxid: vaultTxid);
    _set(m);
    return m;
  }

  @override
  List<DefaultEndpoint> defaultServers({required NetworkId network}) => switch (network) {
    NetworkId.regtest => const [DefaultEndpoint(address: '127.0.0.1:9067', plain: true)],
    _ => const [],
  };

  @override
  Future<ServerProbe> probeServer({required String server, required bool plain, String? caPem, required NetworkId network}) async {
    calls.add('probe $server $plain ${network.name}${caPem == null ? '' : ' pinned'}');
    return const ServerProbe(
      serverVersion: 'v0-dev',
      chainName: 'regtest',
      tip: 484,
      taddrSupport: true,
      yellowback: YellowbackStatus(present: true, usable: true, rpcversion: 3, enabled: true, active: true, serverVersion: 'lwd', feeZat: 1000),
    );
  }

  @override
  Future<Created> createWallet({String? seedWords, required String passphrase, int? birthday, required NetworkId network, required String server, required bool plain, String? caPem, required String dataDir}) async {
    calls.add('create words=${seedWords != null} birthday=$birthday ${network.name} $server plain=$plain${caPem == null ? '' : ' pinned'}');
    if (seedWords != null) checkSeedWords(seedWords: seedWords);
    unlockedFlag = true;
    return Created(walletId: 'yew-test', seedWords: seedWords == null ? fakeWords : null, addressYe: fakeYe);
  }

  @override
  Future<String> unlock({required String seedWords, required String passphrase, required NetworkId network, required String server, required bool plain, String? caPem, required String dataDir}) async {
    calls.add('unlock${caPem == null ? '' : ' pinned'}');
    unlockedFlag = true;
    return 'yew-test';
  }

  @override
  Future<void> lock() async {
    calls.add('lock');
    unlockedFlag = false;
  }

  @override
  bool isUnlocked() => unlockedFlag;

  @override
  Future<void> setServer({required String server, required bool plain, String? caPem}) async => calls.add('setServer $server $plain${caPem == null ? '' : ' pinned'}');

  @override
  Future<Status> status() async => Status(
    walletId: 'yew-test',
    network: NetworkId.regtest,
    server: '127.0.0.1:9267',
    plain: true,
    caPinned: false,
    serverVersion: 'v0-dev',
    chainName: 'regtest',
    branchId: '19bd2d2f',
    tip: 484,
    birthday: 1,
    syncHeight: 484,
    addresses: 40,
    yellowback: const YellowbackStatus(present: true, usable: true, rpcversion: 3, enabled: true, active: true, serverVersion: 'lwd', feeZat: 1000),
    coreVersion: '0.1.0',
  );

  @override
  Future<Balances> balances() async => balancesAnswer;

  @override
  Future<AddressPair> receiveAddress({ReceiveKind kind = ReceiveKind.transparent, required bool fresh}) async {
    if (kind == ReceiveKind.shielded) return privateAddress;
    if (fresh) this.fresh++;
    return address;
  }

  @override
  Future<AddressPair> newShieldedAddress() async {
    freshPrivate++;
    calls.add('newShieldedAddress');
    privateAddress = const AddressPair(ye: '', s: '', path: "m/32'/347'/0'", coveredBySeed: true, address: fakeZ2, kind: ReceiveKind.shielded);
    return privateAddress;
  }

  @override
  Future<ParamsStatus> paramsStatus() async => ParamsStatus(ready: !paramsNeeded, verified: false, missingBytes: paramsNeeded ? 51551256 : 0, totalBytes: 51551256);

  @override
  Stream<ParamsProgress> downloadParams({required String baseUrl}) {
    calls.add('downloadParams $baseUrl');
    if (paramsController != null) return paramsController!.stream;
    if (paramsError != null) return Stream.error(paramsError!);
    paramsNeeded = false;
    return Stream.fromIterable(paramsEvents);
  }

  @override
  Future<List<AddressPair>> addresses() async => [address, const AddressPair(ye: 'yr1second', s: 'smSecond', path: 'imported', coveredBySeed: false, address: 'smSecond', kind: ReceiveKind.transparent)];

  @override
  Future<HistoryPage> history({required int page, required int pageSize}) async => HistoryPage(rows: historyAnswer, page: page, total: historyAnswer.length);

  @override
  Future<YecPreview> sendYecPreview({required String to, required int zat, required bool sendEverything, String? memo}) async {
    calls.add('yecPreview $to $zat $sendEverything${memo == null ? '' : ' memo=$memo'}');
    if (yecPreviewError != null) throw yecPreviewError!;
    final private = yecFunding == YecFunding.shielded;
    return YecPreview(previewId: 'p1', to: to, amountZat: zat, amountBumped: zat == 10000, feeZat: private ? 10000 : 1000, changeZat: 150000000 - zat - 1000, inputs: 1, usesReserve: sendEverything, keepsReservedZat: 105000, expiryHeight: 524, txid: private ? '' : 'aa' * 32, funding: yecFunding, revealsShielded: revealsShielded, memo: memo, paramsNeeded: private && paramsNeeded);
  }

  @override
  Future<SendResult> sendYecConfirm({required String previewId}) async {
    calls.add('yecConfirm $previewId');
    if (yecConfirmError != null) {
      final e = yecConfirmError!;
      yecConfirmError = null;
      throw e;
    }
    return SendResult(txid: 'aa' * 32, verdict: 'ok');
  }

  // ---- S4: moves between the own private and public balances.
  Object? movePreviewError;

  @override
  Future<YecPreview> movePreview({required MoveDirection direction, int? amountZat}) async {
    calls.add('movePreview ${direction.name} ${amountZat ?? 'all'}');
    if (movePreviewError != null) throw movePreviewError!;
    final toPrivate = direction == MoveDirection.toPrivate;
    const fee = 15000;
    final zat = amountZat ?? (toPrivate ? balancesAnswer.yecZat : balancesAnswer.yecShieldedSpendableZat) - fee;
    return YecPreview(previewId: 'm1', to: toPrivate ? fakeZ : fakeS, amountZat: zat, amountBumped: false, feeZat: fee, changeZat: 0, inputs: 1, usesReserve: false, keepsReservedZat: balancesAnswer.yecReservedZat, expiryHeight: 525, txid: '', funding: toPrivate ? YecFunding.transparent : YecFunding.shielded, revealsShielded: !toPrivate, memo: null, paramsNeeded: paramsNeeded);
  }

  @override
  Future<SendResult> moveConfirm({required String previewId}) async {
    calls.add('moveConfirm $previewId');
    return SendResult(txid: 'mm' * 32, verdict: 'ok');
  }

  @override
  Future<YedPreview> sendYedPreview({required List<Recipient> recipients}) async {
    calls.add('yedPreview ${recipients.map((r) => '${r.address}:${r.cents}').join(',')}');
    if (yedPreviewError != null) throw yedPreviewError!;
    final total = recipients.fold<int>(0, (a, r) => a + r.cents);
    return YedPreview(previewId: 'p2', recipients: recipients, totalCents: total, stage: 'single', yedInputs: 1, changeCents: 5000 - total, yecInputs: 1, feeZat: 1000, yecChangeZat: 84000, expiryHeight: 524, txid: 'bb' * 32, dryRun: dryRun);
  }

  @override
  Future<SendResult> sendYedConfirm({required String previewId}) async {
    calls.add('yedConfirm $previewId');
    if (yedConfirmError != null) throw yedConfirmError!;
    return SendResult(txid: 'bb' * 32, verdict: 'ok');
  }

  @override
  Future<WifExport> exportWif({required String address}) async {
    calls.add('exportWif $address');
    return WifExport(addressYe: fakeYe, addressS: fakeS, wif: 'cVfakeWif1111111111111111111111111111111111111111111', coveredBySeed: true);
  }

  @override
  Future<AddressPair> importWif({required String wif, int? birthday}) async {
    calls.add('importWif $birthday');
    return const AddressPair(ye: 'yr1imported', s: 'smImported', path: 'imported', coveredBySeed: false, address: 'smImported', kind: ReceiveKind.transparent);
  }

  @override
  Stream<SyncEvent> syncNow() {
    calls.add('sync');
    if (syncController != null) return syncController!.stream;
    return Stream.fromIterable(const [
      SyncEvent(stage: SyncStage.connecting, message: 'Connecting', tip: 0, syncHeight: 0, yellowbackUsable: false, percent: 0, shieldedHeight: 0, shieldedSendable: false, shieldedMessage: ''),
      SyncEvent(stage: SyncStage.probing, message: 'Yellowback service present', tip: 484, syncHeight: 0, yellowbackUsable: true, percent: 0, shieldedHeight: 0, shieldedSendable: false, shieldedMessage: ''),
      SyncEvent(stage: SyncStage.done, message: 'Synced to 484', tip: 484, syncHeight: 484, yellowbackUsable: true, percent: 100, shieldedHeight: 0, shieldedSendable: false, shieldedMessage: ''),
    ]);
  }

  @override
  String generateSeedWords({required int words}) => fakeWords;

  @override
  void checkSeedWords({required String seedWords}) {
    if (seedWords.trim() != fakeWords) {
      throw const YewError(kind: ErrorKind.input, message: 'bad mnemonic: invalid checksum');
    }
  }

  @override
  AddressCheck validateAddress({required NetworkId network, required String address}) => address.startsWith('yregtestsapling1')
      ? const AddressCheck(valid: true, kind: 'sapling', yellowbackForm: false, message: '')
      : address.startsWith('yr1') || address.startsWith('sm')
      ? AddressCheck(valid: true, kind: 'p2pkh', yellowbackForm: address.startsWith('yr1'), message: '')
      : const AddressCheck(valid: false, kind: '', yellowbackForm: false, message: 'not a Regtest address: bad base58check');

  @override
  String coreVersion() => '0.1.0-test';
}

/// The app over the fake, with an in-memory keystore and no biometric prompt.
class Harness {
  Harness({bool withWallet = false}) {
    if (withWallet) {
      secrets.write('seed', fakeWords);
      secrets.write('settings', const WalletSettings(server: '127.0.0.1:9267', plain: true, network: NetworkId.regtest, trustAccepted: true).encode());
    }
    state = AppState(api: api, secrets: secrets, auth: const NoAuthenticator(), dirs: const FixedDataDirs('/tmp/yew-test'))
      ..mintPollInterval = null;
  }

  final FakeWalletApi api = FakeWalletApi();
  final MemorySecretStore secrets = MemorySecretStore();
  late final AppState state;

  YewApp get app => YewApp(state: state);

  /// Pump the app on a phone-tall viewport (the screens are lazy ListViews).
  Future<void> pump(WidgetTester tester) async {
    tester.view.physicalSize = const Size(1080, 2400);
    tester.view.devicePixelRatio = 2.0;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    await tester.pumpWidget(app);
    await tester.pumpAndSettle();
  }
}
