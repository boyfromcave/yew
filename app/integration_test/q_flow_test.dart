// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

// The post-quantum flow on a device (quantum line, rpcversion 7), unattended: a quantum devnet
// with Falcon active (`scripts/devnet-falcon.sh up`, YEW_PQ_FALCON_HEIGHT below the tip, the
// way mainnet runs from the vault activation) and the devnet operator
// (`scripts/devnet-operator.py`), which funds and mines when the test asks.
//
//   scripts/run-ios.sh 127.0.0.1:<lwd port> --test q      (+ --dart-define=YEW_OPERATOR=127.0.0.1:<port>)
//   scripts/run-android.sh 10.0.2.2:<lwd port> --test q   (+ --dart-define=YEW_OPERATOR=10.0.2.2:<port>)
//
// Steps: onboarding; the YED receive address is the 53-character Falcon holder (`yr…`) on screen;
// YEC and YED arrive; a YED send to a second wallet's Falcon address (Falcon-signed input, the
// node's verdict ok); a mint of $100.00 whose owner is this wallet's SLH-DSA key; the owner
// redeem in term from the Vault screen (SLH-DSA, ~8 KB scriptSig) with the UI kept live while
// the core signs; the second wallet restored from its seed finds its Falcon token. It prints
// `YEW Q: timing ...` lines (the preview calls, which sync, build and sign; a bare sync is
// timed just before for the difference) and `YEW Q: jank ...`
// (the longest gap between frames the test pumped every 16 ms while the core signed: the
// signing runs on the bridge's worker thread, so the UI isolate keeps drawing).
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/scheduler.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:path_provider/path_provider.dart';
import 'package:yew_app/api/rust_wallet_api.dart';
import 'package:yew_app/api/wallet_api.dart';
import 'package:yew_app/app.dart';
import 'package:yew_app/state/app_state.dart';
import 'package:yew_app/state/secrets.dart';
import 'package:yew_app/term_classes.dart';

import 'device.dart';

const stepWait = Duration(minutes: 4);

String _host(String name, String androidDefault, String iosDefault) {
  final fromEnv = switch (name) {
    'YEW_SERVER' => const String.fromEnvironment('YEW_SERVER'),
    _ => const String.fromEnvironment('YEW_OPERATOR'),
  };
  if (fromEnv.isNotEmpty) return fromEnv;
  return Platform.isAndroid ? androidDefault : iosDefault;
}

String get devnetServer =>
    _host('YEW_SERVER', '10.0.2.2:2399', '127.0.0.1:2399');
String get operator => _host('YEW_OPERATOR', '10.0.2.2:2398', '127.0.0.1:2398');

// ignore: avoid_print
void say(String s) => print('YEW Q: $s');

/// One devnet action through the operator (scripts/devnet-operator.py).
Future<Map<String, dynamic>> op(String path) async {
  final client = HttpClient();
  try {
    final rq = await client.getUrl(Uri.parse('http://$operator$path'));
    final rs = await rq.close();
    final body = jsonDecode(
      await rs.transform(utf8.decoder).join(),
    ) as Map<String, dynamic>;
    if (body['ok'] != true) fail('operator $path: ${body['error']}');
    return body;
  } finally {
    client.close(force: true);
  }
}

/// Mine one block at a time and sync until [until] holds.
Future<void> mineUntil(
  WidgetTester tester,
  AppState state,
  String what,
  bool Function() until,
) async {
  final deadline = DateTime.now().add(stepWait);
  while (true) {
    if (DateTime.now().isAfter(deadline)) {
      fail('$what did not happen within $stepWait; on screen: ${onScreen()}');
    }
    try {
      await state.sync();
    } catch (e) {
      fail('sync while waiting for $what: ${messageOf(e)}');
    }
    // AppState keeps the last sync event's message (refresh() clears lastError): a Failed
    // sync is reported here, and the loop backs off instead of mining past the step.
    if (!state.syncMessage.startsWith('Synced')) {
      say('sync failed while waiting for $what: ${state.syncMessage}');
      // lightwalletd's per-peer Yellowback budget (20 heavy calls, one more per second) is
      // shared by everything on this host's loopback.
      await Future<void>.delayed(const Duration(seconds: 10));
      continue;
    }
    await tester.pump(const Duration(milliseconds: 100));
    if (until()) return;
    await op('/mine?n=1');
  }
}

/// Pump a frame every 16 ms until [done] (the core works on its own thread meanwhile); returns
/// the elapsed time and the longest gap between two pumps, with the frames the engine reported.
Future<
  ({
    Duration took,
    Duration worstGap,
    int frames,
    Duration worstBuild,
    Duration worstRaster,
  })
>
liveUntil(
  WidgetTester tester,
  bool Function() done, {
  Duration timeout = const Duration(seconds: 120),
}) async {
  final timings = <FrameTiming>[];
  void onTimings(List<FrameTiming> t) => timings.addAll(t);
  SchedulerBinding.instance.addTimingsCallback(onTimings);
  final sw = Stopwatch()..start();
  var last = sw.elapsed;
  var worst = Duration.zero;
  try {
    while (!done()) {
      final err = find.byKey(const Key('error'));
      if (err.evaluate().isNotEmpty) {
        fail('screen error: ${tester.widget<Text>(err).data}');
      }
      if (sw.elapsed > timeout) {
        fail('timed out after $timeout; on screen: ${onScreen()}');
      }
      await tester.pump(const Duration(milliseconds: 16));
      await Future<void>.delayed(const Duration(milliseconds: 16));
      final now = sw.elapsed;
      if (now - last > worst) worst = now - last;
      last = now;
    }
  } finally {
    SchedulerBinding.instance.removeTimingsCallback(onTimings);
  }
  final build = timings.fold<Duration>(
    Duration.zero,
    (m, t) => t.buildDuration > m ? t.buildDuration : m,
  );
  final raster = timings.fold<Duration>(
    Duration.zero,
    (m, t) => t.rasterDuration > m ? t.rasterDuration : m,
  );
  return (
    took: sw.elapsed,
    worstGap: worst,
    frames: timings.length,
    worstBuild: build,
    worstRaster: raster,
  );
}

/// How long one sync takes right now (each preview syncs first, then builds, signs and asks
/// the node for a dry run): the preview's time less this is the build + sign + dry-run.
Future<int> syncMs() async {
  final sw = Stopwatch()..start();
  await const RustWalletApi().syncNow().drain<void>();
  return sw.elapsedMilliseconds;
}

Future<void> onboard(WidgetTester tester) async {
  for (final k in ['create', 'trust-check', 'next', 'network']) {
    await tapKey(tester, k);
    await tester.pumpAndSettle();
  }
  await tester.tap(find.text('regtest').last);
  await tester.pumpAndSettle();
  await enterKey(tester, 'server', devnetServer);
  await setSwitchKey(tester, 'plain', true);
  await tester.pumpAndSettle();
  await tapKey(tester, 'probe');
  await waitFor(
    tester,
    () => find.textContaining('Server ok').evaluate().isNotEmpty,
    timeout: const Duration(seconds: 30),
  );
  await tapKey(tester, 'next');
  await tester.pumpAndSettle();
  await tapKey(tester, 'finish');
  await waitFor(
    tester,
    () => find.byKey(const Key('written')).evaluate().isNotEmpty,
  );
  await tapKey(tester, 'written');
  await tester.pumpAndSettle();
  await tapKey(tester, 'done');
  await tester.pumpAndSettle();
}

void main() {
  final binding = IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  // Real frames while the core works (the timing and jank lines measure the live UI).
  binding.framePolicy = LiveTestWidgetsFlutterBindingFramePolicy.fullyLive;
  // A bridge error prints as "Instance of 'YewError'": show its kind and message too.
  final report = reportTestException;
  reportTestException = (details, description) {
    final e = details.exception;
    if (e is YewError) say('uncaught YewError ${e.kind}: ${e.message}');
    report(details, description);
  };

  late String dataDir;
  setUpAll(() async {
    await RustWalletApi.init();
    final base = (await getApplicationSupportDirectory()).path;
    dataDir = '$base/q-${DateTime.now().millisecondsSinceEpoch}';
  });

  testWidgets('Q: Falcon YED receive and send, SLH-DSA owner mint and redeem, restore', (
    tester,
  ) async {
    const api = RustWalletApi();
    final secrets = MemorySecretStore();
    final state = AppState(
      api: api,
      secrets: secrets,
      auth: const NoAuthenticator(),
      dirs: FixedDataDirs('$dataDir/a'),
    );
    say(
      'server $devnetServer, operator $operator, tip ${(await op('/height'))['height']}',
    );
    await tester.pumpWidget(YewApp(state: state));
    await tester.pumpAndSettle();
    await onboard(tester);
    final seedA = (await secrets.read('seed'))!;
    await waitFor(tester, () => find.text('\$0.00').evaluate().isNotEmpty);

    // 1. The YED receive address is the Falcon holder (53 characters, yr… on regtest), on screen.
    await tapKey(tester, 'receive');
    await tester.pumpAndSettle();
    final ye = state.receive!.ye;
    final s = state.receive!.s;
    say('receive: YED $ye (${ye.length} chars), YEC $s');
    expect(
      ye.length,
      53,
      reason: 'a Falcon holder address once Falcon is active: $ye',
    );
    expect(ye.startsWith('yr'), isTrue);
    expect(s.startsWith('sm'), isTrue);
    final segmented = find.text('YED');
    if (segmented.evaluate().isNotEmpty) {
      await tester.tap(segmented.first);
      await tester.pumpAndSettle();
    }
    expect(
      find.textContaining(ye.substring(0, 12)),
      findsWidgets,
      reason: 'the Falcon address is on the Receive screen',
    );
    await tester.pageBack();
    await tester.pumpAndSettle();

    // 2. Funding: 20 YEC to the public address, $150.00 YED to the Falcon holder.
    await op('/yec?to=$s&amount=20');
    await op('/yed?to=$ye&cents=15000');
    await mineUntil(
      tester,
      state,
      'the funding',
      () =>
          state.balances.yedCents == 15000 &&
          state.balances.yecZat + state.balances.yecReservedZat >= 2000000000,
    );
    expect(find.text('\$150.00'), findsOneWidget);

    // A second wallet on the same device (the core holds one wallet at a time).
    await api.lock();
    final c = await api.createWallet(
      passphrase: '',
      birthday: null,
      network: NetworkId.regtest,
      server: devnetServer,
      plain: true,
      dataDir: '$dataDir/b',
    );
    // A fresh regtest wallet learns the server's Falcon height on its first sync (mainnet and
    // testnet are Falcon from day one without one); then its YED address is the Falcon holder.
    await api.syncNow().drain<void>();
    final addrB = (await api.receiveAddress(
      kind: ReceiveKind.yed,
      fresh: false,
    )).ye;
    await api.lock();
    final seedB = c.seedWords!;
    await api.unlock(
      seedWords: seedA,
      passphrase: '',
      network: NetworkId.regtest,
      server: devnetServer,
      plain: true,
      dataDir: '$dataDir/a',
    );
    say('wallet B YED address $addrB (${addrB.length} chars)');
    expect(addrB.length, 53, reason: 'B receives on its Falcon holder: $addrB');

    // 3. YED send $12.34 to B: a Falcon-signed input (preview builds and signs; timed).
    await tapKey(tester, 'send');
    await tester.pumpAndSettle();
    await enterKey(tester, 'address', addrB);
    await enterKey(tester, 'amount', '12.34');
    final sendSync = await syncMs();
    await tapKey(tester, 'preview');
    final sendLive = await liveUntil(
      tester,
      () =>
          find.text('verdict ok').evaluate().isNotEmpty ||
          find.textContaining('verdict').evaluate().isNotEmpty,
    );
    say(
      'timing falcon-send-preview ${sendLive.took.inMilliseconds} ms (sync + build + Falcon sign + node dry-run; a sync alone just before: $sendSync ms)',
    );
    say(
      'jank falcon-send worstGap ${sendLive.worstGap.inMilliseconds} ms, frames ${sendLive.frames}, worstBuild ${sendLive.worstBuild.inMilliseconds} ms, worstRaster ${sendLive.worstRaster.inMilliseconds} ms',
    );
    await expectVisible(tester, find.text('verdict ok'));
    await longPressKey(tester, 'slide-to-confirm');
    await waitFor(
      tester,
      () => find.byKey(const Key('txid')).evaluate().isNotEmpty,
    );
    await tapKey(tester, 'done');
    await tester.pumpAndSettle();
    await mineUntil(
      tester,
      state,
      'the YED send to confirm',
      () =>
          state.balances.yedCents == 15000 - 1234 &&
          state.balances.yedPendingCents == 0,
    );

    // 4. Mint $100.00 (class A, the shortest term): the vault owner is this wallet's SLH-DSA key.
    final lock = termClassesFor(NetworkId.regtest).first.minBlocks;
    final avail = await api.mintAvailability().catchError(
      (Object e) => fail('mintAvailability: ${messageOf(e)}'),
    );
    expect(avail.allowed, isTrue, reason: avail.reason);
    final est = await api
        .mintEstimate(cents: 10000, lockBlocks: lock)
        .catchError((Object e) => fail('mintEstimate: ${messageOf(e)}'));
    var m = await api
        .mintStart(
          cents: est.cents,
          lockBlocks: est.lockBlocks,
          confirmed: MintTerms(
            collateralZat: est.collateralZat,
            feeZat: est.feeZat,
            payee: est.payee,
            termClass: est.termClass,
          ),
        )
        .catchError((Object e) => fail('mintStart: ${messageOf(e)}'));
    say('mint ${m.mintId}: carrier sent, lock $lock blocks');
    await mineUntil(
      tester,
      state,
      'the carrier',
      () => state.mintById(m.mintId)?.state != 'CARRIER_SENT',
    );
    say('mint ${m.mintId}: ${state.mintById(m.mintId)!.state}');
    if (state.mintById(m.mintId)!.state != 'MAIN_SENT' &&
        state.mintById(m.mintId)!.state != 'DONE') {
      try {
        m = await api.mintFinish(mintId: m.mintId);
      } catch (e) {
        fail('mintFinish: ${messageOf(e)}');
      }
    }
    await mineUntil(
      tester,
      state,
      'the MINT',
      () => state.mintById(m.mintId)?.state == 'DONE',
    );
    expect(state.balances.yedCents, 15000 - 1234 + 10000);
    final vault = state.vaults.firstWhere((v) => v.open);
    say(
      'vault ${vault.vaultTxid}: owner ${vault.ownerAddress} (${vault.ownerAddress.length} chars), lockHeight ${vault.lockHeight}',
    );

    // 5. The owner redeem in term (SLH-DSA): preview (build + sign, timed, UI live), slide, a block.
    await tapKey(tester, 'tab-yellowback');
    await tester.pumpAndSettle();
    await tapKey(tester, 'vault-${vault.vaultTxid}');
    await tester.pumpAndSettle();
    await expectVisible(tester, find.byKey(const Key('owner-pq')));
    final redeemSync = await syncMs();
    await tapKey(tester, 'preview');
    final redeemLive = await liveUntil(
      tester,
      () => find.byKey(const Key('redeem-preview')).evaluate().isNotEmpty,
    );
    say(
      'timing slh-redeem-preview ${redeemLive.took.inMilliseconds} ms (sync + re-derive the SLH-DSA key + build + sign ~7.9 KB + node dry-run; a sync alone just before: $redeemSync ms)',
    );
    say(
      'jank slh-redeem worstGap ${redeemLive.worstGap.inMilliseconds} ms, frames ${redeemLive.frames}, worstBuild ${redeemLive.worstBuild.inMilliseconds} ms, worstRaster ${redeemLive.worstRaster.inMilliseconds} ms',
    );
    expect(
      redeemLive.worstGap,
      lessThan(const Duration(milliseconds: 250)),
      reason: 'the UI isolate kept drawing while the core signed',
    );
    await expectVisible(tester, find.byKey(const Key('network-fee')));
    await longPressKey(tester, 'slide-to-confirm');
    await waitFor(
      tester,
      () => find.text('Vault redeemed').evaluate().isNotEmpty,
    );
    await tapKey(tester, 'done');
    await tester.pumpAndSettle();
    await mineUntil(
      tester,
      state,
      'the redeem to confirm',
      () => state.vaultByTxid(vault.vaultTxid)?.status == 'CLOSED',
    );
    expect(state.balances.yedCents, 15000 - 1234);

    // 6. B restored from its seed in a fresh directory finds its Falcon token.
    await api.lock();
    await api.unlock(
      seedWords: seedB,
      passphrase: '',
      network: NetworkId.regtest,
      server: devnetServer,
      plain: true,
      dataDir: '$dataDir/b2',
    );
    await api.syncNow().drain<void>();
    final b = await api.balances();
    say('restored B: yed ${b.yedCents} cents');
    expect(b.yedCents, 1234);
    await api.lock();
  });
}
