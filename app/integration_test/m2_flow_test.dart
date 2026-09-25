// Plan §6.3, the M2 flow on a device against the W4 devnet (`scripts/devnet-w4.sh up`:
// the ARMED devnet, lightwalletd-dd --yellowback on 9267, plain HTTP/2). NOT RUN: no
// simulator or emulator exists on the machine this was written on (Xcode and the Android SDK
// are [owner] installs, plan §7 W3/W4). Written against the real core; the fake is not used.
//
//   Android emulator:  flutter test integration_test/m2_flow_test.dart -d emulator-5554
//   iOS simulator:     flutter test integration_test/m2_flow_test.dart -d <simulator id>
//
// The server is 10.0.2.2:9267 on the Android emulator and localhost:9267 on the iOS
// simulator; --dart-define=YEW_SERVER=host:port overrides. The devnet has no heartbeat: an
// operator (or a loop of `yellowback-devnet mine`) mines a pool block whenever this test
// prints "mine"; it waits up to STEP_WAIT for each height it needs. The price shock for the
// claim is `yellowback-devnet price --shock=-80%` (restore with `price 50` afterwards).
// The steps, in order (plan §7 W4 acceptance):
//   1. wallet A funded with 20 YEC from node 2 (the pool node; README "devnet funding");
//   2. mint $25.00, class A, 48 blocks: carrier, one block, the MINT sent by the app, one block,
//      the vault on the Yellowback screen, the YED in the balance;
//   3. kill-and-resume: a second mint's carrier is funded, the app state is torn down and
//      rebuilt on the same data directory, the progress screen resumes from the persisted row;
//   4. forced lapse: a third carrier is funded and the operator mines past R + REF_WINDOW
//      without the app finishing; the row shows "window closed, sweeping carrier"; sweep;
//   5. redeem after the lock: mine to lockHeight, the vault reads "Redeemable", slide, the
//      collateral is back after a block;
//   6. claim after a shock: wallet B (restored on the same device) mints a vault, the operator
//      shocks the price, wallet A sees it under Claimable and claims it; after two blocks the
//      vault is CLAIMED and A's YEC grew by the collateral.
import 'dart:io' show Platform;

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:path_provider/path_provider.dart';
import 'package:yew_app/api/rust_wallet_api.dart';
import 'package:yew_app/api/wallet_api.dart';
import 'package:yew_app/app.dart';
import 'package:yew_app/state/app_state.dart';
import 'package:yew_app/state/secrets.dart';

import 'device.dart';

const stepWait = Duration(minutes: 3);

String get devnetServer {
  const fromEnv = String.fromEnvironment('YEW_SERVER');
  if (fromEnv.isNotEmpty) return fromEnv;
  return Platform.isAndroid ? '10.0.2.2:9267' : 'localhost:9267';
}

// ignore: avoid_print
void say(String s) => print('YEW M2: $s');

/// Sync until [until] holds or [stepWait] passes; the operator mines meanwhile.
Future<void> waitFor(WidgetTester tester, AppState state, String what, bool Function() until) async {
  final deadline = DateTime.now().add(stepWait);
  say('waiting for $what (mine)');
  while (!until()) {
    expect(DateTime.now().isBefore(deadline), isTrue, reason: '$what did not happen within $stepWait');
    await Future<void>.delayed(const Duration(seconds: 10));
    await state.sync();
    await tester.pumpAndSettle();
  }
}

Future<AppState> openWallet(WidgetTester tester, {required String dir, required MemorySecretStore secrets, String? words}) async {
  const api = RustWalletApi();
  final state = AppState(api: api, secrets: secrets, auth: const NoAuthenticator(), dirs: FixedDataDirs(dir));
  if (words != null) {
    await secrets.write('seed', words);
    await secrets.write('settings', const WalletSettings(server: '', plain: true, network: NetworkId.regtest, trustAccepted: true).copyWith(server: devnetServer).encode());
  }
  await tester.pumpWidget(YewApp(state: state));
  await tester.pumpAndSettle(const Duration(seconds: 5));
  return state;
}

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  late String base;
  setUpAll(() async {
    await RustWalletApi.init();
    base = '${(await getApplicationSupportDirectory()).path}/m2-${DateTime.now().millisecondsSinceEpoch}';
  });

  testWidgets('M2: mint, kill-and-resume, lapse and sweep, redeem after lock, claim after shock', (tester) async {
    const api = RustWalletApi();
    final secretsA = MemorySecretStore();
    var state = await openWallet(tester, dir: '$base/a', secrets: secretsA);

    // Onboarding as in the M1 flow (create, trust, regtest + plain, probe, finish, backup).
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
    await tester.pumpAndSettle(const Duration(seconds: 2));
    expect(find.textContaining('Server ok'), findsOneWidget, reason: 'the W4 devnet lightwalletd must be up on $devnetServer');
    for (final k in ['next', 'finish', 'written', 'done']) {
      await tapKey(tester, k);
      await tester.pumpAndSettle(const Duration(seconds: 2));
    }
    final wordsA = (await secretsA.read('seed'))!;

    // 1. Funding from node 2: `yellowback-devnet ... sendtoaddress <s> 20` (README "devnet funding").
    say('fund this address with 20 YEC from node 2: ${state.receive!.s}');
    await waitFor(tester, state, 'the funding', () => state.balances.yecZat + state.balances.yecReservedZat >= 2000000000);

    // 2. Mint $25.00, class A, 48 blocks.
    await tapKey(tester, 'tab-yellowback');
    await tester.pumpAndSettle();
    await tapKey(tester, 'mint');
    await tester.pumpAndSettle();
    await enterKey(tester, 'amount', '25');
    await tapKey(tester, 'estimate');
    await tester.pumpAndSettle(const Duration(seconds: 5));
    expect(find.text('class A · 48 blocks'), findsOneWidget);
    await tapKey(tester, 'start');
    await tester.pumpAndSettle(const Duration(seconds: 5));
    expect(find.text('CARRIER_SENT'), findsOneWidget);
    final mint1 = state.mintsInProgress.single.mintId;
    // One block confirms the carrier; the progress screen sends the MINT by itself on the next sync.
    await waitFor(tester, state, 'the carrier of mint $mint1 to confirm', () => state.mintById(mint1)!.state != 'CARRIER_SENT');
    await tester.pumpAndSettle(const Duration(seconds: 5));
    expect(find.text('MAIN_SENT'), findsOneWidget);
    await waitFor(tester, state, 'mint $mint1 to confirm', () => state.mintById(mint1)!.state == 'DONE');
    await tapKey(tester, 'done');
    await tester.pumpAndSettle();
    expect(state.balances.yedCents, 2500);
    expect(state.vaults.where((v) => v.open).length, 1);
    final vault1 = state.vaults.single;
    expect(find.byKey(Key('vault-${vault1.vaultTxid}')), findsOneWidget);

    // 3. Kill-and-resume: fund a second carrier, tear the app down, rebuild on the same directory.
    await tapKey(tester, 'mint');
    await tester.pumpAndSettle();
    await enterKey(tester, 'amount', '5');
    await tapKey(tester, 'estimate');
    await tester.pumpAndSettle(const Duration(seconds: 5));
    await tapKey(tester, 'start');
    await tester.pumpAndSettle(const Duration(seconds: 5));
    final mint2 = state.mintsInProgress.single.mintId;
    await state.lock();
    await tester.pumpWidget(const SizedBox());
    state = await openWallet(tester, dir: '$base/a', secrets: secretsA);
    await tester.pumpAndSettle(const Duration(seconds: 5));
    await tapKey(tester, 'tab-yellowback');
    await tester.pumpAndSettle();
    expect(find.byKey(Key('mint-$mint2')), findsOneWidget, reason: 'the row persisted');
    await tapKey(tester, 'mint-$mint2');
    await tester.pumpAndSettle();
    await waitFor(tester, state, 'mint $mint2 to finish after the restart', () => state.mintById(mint2)!.state == 'DONE');
    await tapKey(tester, 'done');
    await tester.pumpAndSettle();
    expect(state.balances.yedCents, 3000);

    // 4. Forced lapse: a third carrier, then the operator mines past R + REF_WINDOW (40 blocks)
    //    while the app does not sync (no progress screen open, no timer). Then sweep.
    await tapKey(tester, 'mint');
    await tester.pumpAndSettle();
    await enterKey(tester, 'amount', '1');
    await tapKey(tester, 'estimate');
    await tester.pumpAndSettle(const Duration(seconds: 5));
    await tapKey(tester, 'start');
    await tester.pumpAndSettle(const Duration(seconds: 5));
    final mint3 = state.mintsInProgress.single.mintId;
    final expiry3 = state.mintById(mint3)!.expiryHeight;
    await tester.pageBack();
    await tester.pumpAndSettle();
    say('mine ${expiry3 + 1} or more blocks in total (window of mint $mint3 closes at $expiry3) before continuing');
    await Future<void>.delayed(const Duration(seconds: 30));
    await waitFor(tester, state, 'mint $mint3 to lapse', () => state.mintById(mint3)!.state == 'LAPSED');
    expect(find.text('window closed, sweeping carrier'), findsOneWidget);
    await tapKey(tester, 'mint-$mint3');
    await tester.pumpAndSettle();
    await tapKey(tester, 'sweep');
    await tester.pumpAndSettle(const Duration(seconds: 5));
    expect(find.text('SWEEP_SENT'), findsOneWidget);
    await waitFor(tester, state, 'the sweep to confirm', () => state.mintById(mint3)!.state == 'SWEPT');
    await tapKey(tester, 'done');
    await tester.pumpAndSettle();

    // 5. Redeem vault 1 after its lock (the lapse step mined most of the way there).
    await waitFor(tester, state, 'height ${vault1.lockHeight}', () => state.vaultByTxid(vault1.vaultTxid)!.redeemable);
    await tapKey(tester, 'vault-${vault1.vaultTxid}');
    await tester.pumpAndSettle();
    expect(find.textContaining('Redeemable'), findsOneWidget);
    await longPressKey(tester, 'slide-to-confirm');
    await tester.pumpAndSettle(const Duration(seconds: 5));
    expect(find.text('Vault redeemed'), findsOneWidget);
    await tapKey(tester, 'done');
    await tester.pumpAndSettle();
    await waitFor(tester, state, 'the redeem to confirm', () => state.vaultByTxid(vault1.vaultTxid)!.status == 'CLOSED');
    expect(state.balances.yedCents, 500);

    // 6. Claim after a shock: wallet B mints a vault; the operator shocks the price; A claims.
    say('wallet B: fund it, it mints \$5.00; then `yellowback-devnet price --shock=-80%`');
    final secretsB = MemorySecretStore();
    await api.lock();
    await tester.pumpWidget(const SizedBox());
    final stateB = await openWallet(tester, dir: '$base/b', secrets: secretsB);
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
    await tester.pumpAndSettle(const Duration(seconds: 2));
    for (final k in ['next', 'finish', 'written', 'done']) {
      await tapKey(tester, k);
      await tester.pumpAndSettle(const Duration(seconds: 2));
    }
    say('fund B with 20 YEC from node 2: ${stateB.receive!.s}');
    await waitFor(tester, stateB, 'B funded', () => stateB.balances.yecZat + stateB.balances.yecReservedZat >= 2000000000);
    await tapKey(tester, 'tab-yellowback');
    await tester.pumpAndSettle();
    await tapKey(tester, 'mint');
    await tester.pumpAndSettle();
    await enterKey(tester, 'amount', '5');
    await tapKey(tester, 'estimate');
    await tester.pumpAndSettle(const Duration(seconds: 5));
    await tapKey(tester, 'start');
    await tester.pumpAndSettle(const Duration(seconds: 5));
    final mintB = stateB.mintsInProgress.single.mintId;
    await waitFor(tester, stateB, 'B\'s mint to confirm', () => stateB.mintById(mintB)!.state == 'DONE');
    final vaultB = stateB.vaults.single.vaultTxid;
    say('shock the price now: yellowback-devnet price --shock=-80%, then mine one block');
    await stateB.lock();
    await tester.pumpWidget(const SizedBox());
    state = await openWallet(tester, dir: '$base/a', secrets: secretsA, words: wordsA);
    await waitFor(tester, state, 'the shock', () => (state.balances.priceMicroUsd ?? 0) > 0 && state.balances.priceMicroUsd! <= 150000);
    await tapKey(tester, 'tab-yellowback');
    await tester.pumpAndSettle();
    await tapKey(tester, 'claimable');
    await tester.pumpAndSettle(const Duration(seconds: 5));
    expect(find.byKey(Key('claimable-$vaultB')), findsOneWidget, reason: 'B\'s vault is claimable after the shock');
    await tapKey(tester, 'claimable-$vaultB');
    await tester.pumpAndSettle();
    final yecBefore = state.balances.yecZat + state.balances.yecReservedZat;
    await longPressKey(tester, 'slide-to-confirm');
    await tester.pumpAndSettle(const Duration(seconds: 5));
    expect(find.text('CARRIER_SENT'), findsOneWidget);
    final claimRow = state.mintsInProgress.single.mintId;
    await waitFor(tester, state, 'the claim to confirm', () => state.mintById(claimRow)!.state == 'DONE');
    expect(state.balances.yedCents, 0, reason: 'the \$5.00 debt was burned');
    expect(state.balances.yecZat + state.balances.yecReservedZat, greaterThan(yecBefore + 800000000));
    await api.lock();
  });
}
