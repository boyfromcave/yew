// A fake WalletApi for the widget tests (plan §6.2 "Flutter widget tests with a mocked
// bridge"): scripted answers, recorded calls, no core.
import 'dart:async';
import 'dart:ui' show Size;

import 'package:flutter_test/flutter_test.dart';

import 'package:yew_app/api/wallet_api.dart';
import 'package:yew_app/app.dart';
import 'package:yew_app/state/app_state.dart';
import 'package:yew_app/state/secrets.dart';

const fakeYe = 'yr1qkfcjyqz9y4d3qz9v6y8v6y8v6y8v6y8v6y8v6y8v6y8v6y8';
const fakeS = 'smV6y8v6y8v6y8v6y8v6y8v6y8v6y8v6y8v6y8v';
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
    yedSendMinZat: 21000,
  );
  List<HistoryItem> historyAnswer = const [];
  Object? yedPreviewError;
  Object? yedConfirmError;
  Object? yecPreviewError;
  DryRun dryRun = const DryRun(valid: true, verdict: 'ok', burnedCents: 0, wouldBeRejected: false, yedInCents: 5000, yedOutCents: 5000, accepted: true);
  AddressPair address = const AddressPair(ye: fakeYe, s: fakeS, path: "m/44'/347'/0'/0/0", coveredBySeed: true);
  int fresh = 0;

  @override
  Future<ServerProbe> probeServer({required String server, required bool plain, required NetworkId network}) async {
    calls.add('probe $server $plain ${network.name}');
    return const ServerProbe(
      serverVersion: 'v0-dev',
      chainName: 'regtest',
      tip: 484,
      taddrSupport: true,
      yellowback: YellowbackStatus(present: true, usable: true, rpcversion: 3, enabled: true, active: true, serverVersion: 'lwd', feeZat: 1000),
    );
  }

  @override
  Future<Created> createWallet({String? seedWords, required String passphrase, int? birthday, required NetworkId network, required String server, required bool plain, required String dataDir}) async {
    calls.add('create words=${seedWords != null} birthday=$birthday ${network.name} $server plain=$plain');
    if (seedWords != null) checkSeedWords(seedWords: seedWords);
    unlockedFlag = true;
    return Created(walletId: 'yew-test', seedWords: seedWords == null ? fakeWords : null, addressYe: fakeYe);
  }

  @override
  Future<String> unlock({required String seedWords, required String passphrase, required NetworkId network, required String server, required bool plain, required String dataDir}) async {
    calls.add('unlock');
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
  Future<void> setServer({required String server, required bool plain}) async => calls.add('setServer $server $plain');

  @override
  Future<Status> status() async => Status(
    walletId: 'yew-test',
    network: NetworkId.regtest,
    server: '127.0.0.1:9267',
    plain: true,
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
  Future<AddressPair> receiveAddress({required bool fresh}) async {
    if (fresh) this.fresh++;
    return address;
  }

  @override
  Future<List<AddressPair>> addresses() async => [address, const AddressPair(ye: 'yr1second', s: 'smSecond', path: 'imported', coveredBySeed: false)];

  @override
  Future<HistoryPage> history({required int page, required int pageSize}) async => HistoryPage(rows: historyAnswer, page: page, total: historyAnswer.length);

  @override
  Future<YecPreview> sendYecPreview({required String to, required int zat, required bool sendEverything}) async {
    calls.add('yecPreview $to $zat $sendEverything');
    if (yecPreviewError != null) throw yecPreviewError!;
    return YecPreview(previewId: 'p1', to: to, amountZat: zat, amountBumped: zat == 10000, feeZat: 1000, changeZat: 150000000 - zat - 1000, inputs: 1, usesReserve: sendEverything, keepsReservedZat: 105000, expiryHeight: 524, txid: 'aa' * 32);
  }

  @override
  Future<SendResult> sendYecConfirm({required String previewId}) async {
    calls.add('yecConfirm $previewId');
    return SendResult(txid: 'aa' * 32, verdict: 'ok');
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
    return const AddressPair(ye: 'yr1imported', s: 'smImported', path: 'imported', coveredBySeed: false);
  }

  @override
  Stream<SyncEvent> syncNow() {
    calls.add('sync');
    return Stream.fromIterable(const [
      SyncEvent(stage: SyncStage.connecting, message: 'Connecting', tip: 0, syncHeight: 0, yellowbackUsable: false),
      SyncEvent(stage: SyncStage.probing, message: 'Yellowback service present', tip: 484, syncHeight: 0, yellowbackUsable: true),
      SyncEvent(stage: SyncStage.done, message: 'Synced to 484', tip: 484, syncHeight: 484, yellowbackUsable: true),
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
  AddressCheck validateAddress({required NetworkId network, required String address}) => address.startsWith('yr1') || address.startsWith('sm')
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
    state = AppState(api: api, secrets: secrets, auth: const NoAuthenticator(), dirs: const FixedDataDirs('/tmp/yew-test'));
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
