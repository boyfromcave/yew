// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

// yew-shielded plan S3 (and the S4 Move sheet, shots 13-15) on a device against a regtest devnet with private (Sapling) support
// (`KEEP=1 scripts/devnet-s2.sh dd|6 <seed>` leaves one up; lightwalletd-dd on 9067 + seed).
// Written against the real core. Drives the private screens and prints two kinds of markers
// for a host-side helper:
//
//   YEW-S3 FUND z=<ys1…> t=<s…> ye=<ye…>   fund these (node 0: z_sendmany with a memo to z,
//                                          sendtoaddress to t, yed_send to ye), mine a block
//   YEW-S3 MINE                            mine one block (the private change becomes spendable)
//   YEW-S3 SHOT <name>                     the screen is ready: capture it now (4 s pause)
//
//   flutter test integration_test/s3_screens_test.dart -d <simulator> \
//     --dart-define=YEW_SERVER=localhost:9074 --dart-define=YEW_PARAMS_URL='file:///…/ZcashParams/'
//
// YEW_PARAMS_URL is where the one-time sheet downloads the proving files from (a file:// copy
// on the host works on the iOS simulator; no host is compiled into the app).
import 'dart:io' show Platform;

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:path_provider/path_provider.dart';
import 'package:yew_app/api/rust_wallet_api.dart';
import 'package:yew_app/app.dart';
import 'package:yew_app/state/app_state.dart';
import 'package:yew_app/state/secrets.dart';

import 'device.dart';

const fundWait = Duration(minutes: 4);
const memo = 'Lunch on Friday, thanks!';

String get devnetServer {
  const fromEnv = String.fromEnvironment('YEW_SERVER');
  if (fromEnv.isNotEmpty) return fromEnv;
  return Platform.isAndroid ? '10.0.2.2:9074' : 'localhost:9074';
}

Future<void> shot(WidgetTester tester, String name) async {
  await tester.pumpAndSettle();
  // ignore: avoid_print
  print('YEW-S3 SHOT $name');
  await Future<void>.delayed(const Duration(seconds: 4));
}

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  late String dataDir;
  setUpAll(() async {
    await RustWalletApi.init();
    dataDir = '${(await getApplicationSupportDirectory()).path}/s3-${DateTime.now().millisecondsSinceEpoch}';
  });

  testWidgets('S3: private balance, receive, send with a message, params sheet, history, reveal line', (tester) async {
    const api = RustWalletApi();
    final secrets = MemorySecretStore();
    final state = AppState(api: api, secrets: secrets, auth: const NoAuthenticator(), dirs: FixedDataDirs('$dataDir/a'));
    await tester.pumpWidget(YewApp(state: state));
    await tester.pumpAndSettle();

    await tapKey(tester, 'create');
    await tester.pumpAndSettle();
    await tapKey(tester, 'trust-check');
    await tester.pumpAndSettle();
    await tapKey(tester, 'next');
    await tester.pumpAndSettle();
    await tapKey(tester, 'network');
    await tester.pumpAndSettle();
    await tester.tap(find.text('regtest').last);
    await tester.pumpAndSettle();
    await enterKey(tester, 'server', devnetServer);
    await setSwitchKey(tester, 'plain', true);
    await tester.pumpAndSettle();
    await tapKey(tester, 'probe');
    await tester.pumpAndSettle(const Duration(seconds: 2));
    await tapKey(tester, 'next');
    await tester.pumpAndSettle();
    await tapKey(tester, 'finish');
    await waitFor(tester, () => find.byKey(const Key('written')).evaluate().isNotEmpty);
    await tapKey(tester, 'written');
    await tester.pumpAndSettle();
    await tapKey(tester, 'done');
    await waitFor(tester, () => !state.syncing && state.balances.syncHeight > 0);

    final z = state.receivePrivate!.address;
    final t = state.receive!.s;
    final ye = state.receive!.ye;
    // ignore: avoid_print
    print('YEW-S3 FUND z=$z t=$t ye=$ye');
    final deadline = DateTime.now().add(fundWait);
    while (state.balances.yecShieldedZat == 0 || state.balances.yecZat == 0 || !state.balances.shieldedSendable) {
      expect(DateTime.now().isBefore(deadline), isTrue, reason: 'not funded within $fundWait');
      await Future<void>.delayed(const Duration(seconds: 5));
      await state.sync();
      await tester.pumpAndSettle();
    }
    await shot(tester, '01-home');

    await tapKey(tester, 'receive');
    await tester.pumpAndSettle();
    await shot(tester, '02-receive-private');
    await tester.tap(find.text('Public'));
    await shot(tester, '03-receive-public');
    await tester.tap(find.text('Private'));
    await tester.pumpAndSettle();
    await tapKey(tester, 'new-address');
    await tester.pumpAndSettle();
    final z2 = state.receivePrivate!.address;
    await tester.pageBack();
    await tester.pumpAndSettle();

    // A private payment with a message, to the wallet's own second private address.
    await tapKey(tester, 'send');
    await tester.pumpAndSettle();
    await tester.tap(find.text('YEC'));
    await tester.pumpAndSettle();
    await enterKey(tester, 'address', z2);
    await tester.pumpAndSettle();
    await enterKey(tester, 'amount', '0.5');
    await enterKey(tester, 'memo', memo);
    FocusManager.instance.primaryFocus?.unfocus();
    await shot(tester, '04-send-message');
    await tapKey(tester, 'preview');
    await waitForKey(tester, 'slide-to-confirm');
    await shot(tester, '05-send-preview-private');
    await longPressKey(tester, 'slide-to-confirm');
    await waitFor(tester, () => find.byKey(const Key('params-title')).evaluate().isNotEmpty);
    await shot(tester, '06-params-sheet-unset');
    await tapKey(tester, 'params-set-url');
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('params-url-field')), const String.fromEnvironment('YEW_PARAMS_URL'));
    await tester.tap(find.byKey(const Key('params-url-save')));
    await tester.pumpAndSettle();
    await shot(tester, '07-params-sheet-ready');
    await tester.tap(find.byKey(const Key('params-download')));
    await waitFor(tester, () => find.byKey(const Key('txid')).evaluate().isNotEmpty, timeout: const Duration(minutes: 3));
    await shot(tester, '08-sent');
    await tapKey(tester, 'done');
    await tester.pumpAndSettle();
    // Own change is spendable after a block: ask the helper for one and wait for it.
    // ignore: avoid_print
    print('YEW-S3 MINE');
    final mined = DateTime.now().add(fundWait);
    do {
      expect(DateTime.now().isBefore(mined), isTrue, reason: 'no block within $fundWait');
      await Future<void>.delayed(const Duration(seconds: 5));
      await state.sync();
      await tester.pumpAndSettle();
    } while (state.balances.yecShieldedPendingZat > 0 || state.balances.yecShieldedSpendableZat < 30000000);

    // The reveal line: a payment from the private balance to the wallet's own public address.
    await tapKey(tester, 'send');
    await tester.pumpAndSettle();
    await tester.tap(find.text('YEC'));
    await tester.pumpAndSettle();
    await enterKey(tester, 'address', t);
    await enterKey(tester, 'amount', '0.3');
    FocusManager.instance.primaryFocus?.unfocus();
    await tapKey(tester, 'preview');
    await waitForKey(tester, 'slide-to-confirm');
    await expectVisible(tester, find.text('This payment leaves your private balance'));
    await shot(tester, '09-send-preview-reveal');
    await tapKey(tester, 'cancel');
    await tester.pageBack();
    await tester.pumpAndSettle();

    // History: the private rows carry a lock; the incoming one shows the node's message.
    await tester.pumpAndSettle(const Duration(seconds: 2));
    await state.sync();
    await tester.pumpAndSettle();
    await tapKey(tester, 'tab-history');
    await tester.pumpAndSettle();
    await shot(tester, '10-history');
    final rows = state.history.where((h) => h.shielded && h.memo.isNotEmpty && h.yecDeltaZat > 0).toList();
    if (rows.isNotEmpty) {
      await tester.tap(find.byKey(Key('tx-${rows.first.txid}')));
      await tester.pumpAndSettle();
      await shot(tester, '11-history-message');
      await tester.tapAt(const Offset(20, 80));
      await tester.pumpAndSettle();
    }

    // Mint short of public YEC with a private balance: "Move YEC to public first".
    await tapKey(tester, 'tab-yellowback');
    await tester.pumpAndSettle();
    await tapKey(tester, 'mint');
    await tester.pumpAndSettle();
    await enterKey(tester, 'amount', '10000');
    FocusManager.instance.primaryFocus?.unfocus();
    await tester.pumpAndSettle();
    await tapKey(tester, 'estimate');
    await waitForKey(tester, 'unaffordable');
    await expectVisible(tester, find.byKey(const Key('move-public')));
    await shot(tester, '12-mint-move-public');

    // S4: the hint opens Move → To public with the shortfall filled in (capped at the private
    // balance); then Home → Move… → To private, previewed and sent.
    await tester.ensureVisible(find.byKey(const Key('move-public-open')));
    await tester.pumpAndSettle();
    await tapKey(tester, 'move-public-open');
    await tester.pumpAndSettle();
    expect(find.text('Move YEC'), findsOneWidget);
    await shot(tester, '13-move-public-prefilled');
    Navigator.of(tester.element(find.byKey(const Key('move-amount')))).pop();
    await tester.pumpAndSettle();
    await tester.pageBack(); // the mint screen
    await tester.pumpAndSettle();
    await tapKey(tester, 'tab-home');
    await tester.pumpAndSettle();
    await tapKey(tester, 'move');
    await tester.pumpAndSettle();
    await enterKey(tester, 'move-amount', '0.1');
    FocusManager.instance.primaryFocus?.unfocus();
    await tapKey(tester, 'move-preview');
    await waitForKey(tester, 'slide-to-confirm');
    await shot(tester, '14-move-private-preview');
    await longPressKey(tester, 'slide-to-confirm');
    await waitFor(tester, () => find.byKey(const Key('move-txid')).evaluate().isNotEmpty, timeout: const Duration(minutes: 3));
    await shot(tester, '15-moved');
    await tapKey(tester, 'move-done');
    await tester.pumpAndSettle();
  });
}
