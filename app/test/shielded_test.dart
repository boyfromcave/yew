// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

// yew-shielded plan S3: the private (Sapling) states of the existing screens, over the fake.
import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:yew_app/api/wallet_api.dart';
import 'package:yew_app/state/secrets.dart';
import 'package:yew_app/widgets/preview_card.dart';

import 'fake_wallet_api.dart';

const synced = Balances(
  yecZat: 150000000,
  yecReservedZat: 105000,
  yecPendingZat: 0,
  yedCents: 5000,
  yedPendingCents: 0,
  priceMicroUsd: 520000,
  heldCount: 0,
  syncHeight: 484,
  yedSendMinZat: 21000,
  yecShieldedZat: 50000000,
  yecShieldedSpendableZat: 40000000,
  yecShieldedPendingZat: 10000000,
  shieldedScannedHeight: 484,
  shieldedSendable: true,
);

SyncEvent ev(SyncStage stage, int percent, {String shieldedMessage = '', bool sendable = false}) => SyncEvent(
  stage: stage,
  message: stage == SyncStage.done ? 'Synced to 484' : 'Scanning private balance',
  tip: 484,
  syncHeight: 484,
  yellowbackUsable: true,
  percent: percent,
  shieldedHeight: 300,
  shieldedSendable: sendable,
  shieldedMessage: shieldedMessage,
);

Future<void> openSendYec(WidgetTester tester, Harness h) async {
  await h.pump(tester);
  await tester.tap(find.byKey(const Key('send')));
  await tester.pumpAndSettle();
  await tester.tap(find.text('YEC'));
  await tester.pumpAndSettle();
}

Future<void> previewTo(WidgetTester tester, String to, {String amount = '0.5', String? memo}) async {
  await tester.enterText(find.byKey(const Key('address')), to);
  await tester.enterText(find.byKey(const Key('amount')), amount);
  await tester.pump();
  if (memo != null) await tester.enterText(find.byKey(const Key('memo')), memo);
  await tester.tap(find.byKey(const Key('preview')));
  await tester.pumpAndSettle();
}

void main() {
  testWidgets('home: one YEC total split into Private and Public; YED card unchanged', (tester) async {
    final h = Harness(withWallet: true);
    h.api.balancesAnswer = synced;
    await h.pump(tester);
    expect(find.text('2.00105000'), findsOneWidget); // 0.5 private + 1.5 + 0.00105 public
    expect(find.text('Private'), findsOneWidget);
    expect(find.text('Public'), findsOneWidget);
    expect(tester.widget<Text>(find.byKey(const Key('yec-private'))).data, '0.50000000 YEC');
    expect(tester.widget<Text>(find.byKey(const Key('yec-public'))).data, '1.50105000 YEC');
    expect(find.text('0.10000000 YEC pending'), findsOneWidget); // private, on its way
    expect(find.text('0.00105000 YEC reserved for fees'), findsOneWidget);
    expect(find.byKey(const Key('private-note')), findsNothing); // sendable: no note
    expect(find.text('\$50.00'), findsOneWidget);
  });

  testWidgets('home: while the private scan runs, "sending available at 100%"; after, why it stopped', (tester) async {
    final h = Harness(withWallet: true);
    final ctl = StreamController<SyncEvent>();
    h.api.syncController = ctl;
    // Not Harness.pump: the sync spinner never settles while the stream is open.
    tester.view.physicalSize = const Size(1080, 2400);
    tester.view.devicePixelRatio = 2.0;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    await tester.pumpWidget(h.app);
    for (var i = 0; i < 5; i++) {
      await tester.pump(const Duration(milliseconds: 100));
    }
    ctl.add(ev(SyncStage.shieldedScanning, 42));
    await tester.pump();
    expect(find.text('Syncing private balance… sending available at 100%'), findsOneWidget);
    expect(find.text('Scanning private balance · 42%'), findsOneWidget);
    ctl.add(ev(SyncStage.done, 100, shieldedMessage: 'private sync skipped: the server is unreachable'));
    await ctl.close();
    await tester.pumpAndSettle();
    expect(find.text('private sync skipped: the server is unreachable'), findsOneWidget);
    expect(find.textContaining('Syncing private balance'), findsNothing);
  });

  testWidgets('receive: private address by default once synced; Public and YED toggles; new private address', (tester) async {
    final h = Harness(withWallet: true);
    h.api.balancesAnswer = synced;
    await h.pump(tester);
    await tester.tap(find.byKey(const Key('receive')));
    await tester.pumpAndSettle();
    expect(find.text(fakeZ), findsOneWidget);
    expect(find.textContaining('hidden on the chain'), findsOneWidget);
    await tester.tap(find.byKey(const Key('new-address')));
    await tester.pumpAndSettle();
    expect(find.text('New private address'), findsOneWidget);
    expect(h.api.freshPrivate, 1);
    expect(h.api.fresh, 0);
    expect(find.text(fakeZ2), findsOneWidget);
    await tester.tap(find.text('Public'));
    await tester.pumpAndSettle();
    expect(find.text(fakeS), findsOneWidget);
    await tester.tap(find.text('YED'));
    await tester.pumpAndSettle();
    expect(find.text(fakeYe), findsOneWidget);
    expect(find.text('New address'), findsOneWidget);
  });

  testWidgets('send: the message field appears only for a private address, counts bytes, caps at 512', (tester) async {
    final h = Harness(withWallet: true);
    h.api.balancesAnswer = synced;
    h.api.yecFunding = YecFunding.shielded;
    await openSendYec(tester, h);
    expect(find.text('0.40000000 YEC private · 1.50000000 YEC public'), findsOneWidget);
    await tester.enterText(find.byKey(const Key('address')), 'smRecipient');
    await tester.pump();
    expect(find.byKey(const Key('memo')), findsNothing);
    expect(find.byKey(const Key('everything')), findsOneWidget);
    await tester.enterText(find.byKey(const Key('address')), fakeZ);
    await tester.pump();
    expect(find.byKey(const Key('memo')), findsOneWidget);
    expect(find.byKey(const Key('everything')), findsNothing);
    // 300 two-byte characters: 600 bytes, over the limit although under 512 characters.
    await tester.enterText(find.byKey(const Key('memo')), 'é' * 300);
    await tester.pump();
    expect(find.text('600 / 512 bytes'), findsOneWidget);
    expect(find.text('Too long: at most 512 bytes'), findsOneWidget);
    expect(tester.widget<FilledButton>(find.byKey(const Key('preview'))).onPressed, isNull);
    await tester.enterText(find.byKey(const Key('memo')), 'thanks for lunch');
    await tester.enterText(find.byKey(const Key('amount')), '0.25');
    await tester.pump();
    expect(find.text('16 / 512 bytes'), findsOneWidget);
    await tester.tap(find.byKey(const Key('preview')));
    await tester.pumpAndSettle();
    // The send preview parses the ys1… recipient in the core (validate_address kind sapling).
    expect(h.api.calls, contains('yecPreview $fakeZ 25000000 false memo=thanks for lunch'));
    expect(find.text('your private balance'), findsOneWidget);
    expect(find.widgetWithText(PreviewRow, 'thanks for lunch'), findsOneWidget);
    expect(find.byKey(const Key('reveals')), findsNothing);
    await tester.longPress(find.byKey(const Key('slide-to-confirm')));
    await tester.pumpAndSettle();
    expect(h.api.calls, contains('yecConfirm p1'));
  });

  testWidgets('send: YED to a private address is refused before the core', (tester) async {
    final h = Harness(withWallet: true);
    await h.pump(tester);
    await tester.tap(find.byKey(const Key('send')));
    await tester.pumpAndSettle();
    await previewTo(tester, fakeZ, amount: '1');
    expect(find.text('YED can only be sent to a public address (ye… or s…).'), findsOneWidget);
    expect(find.byKey(const Key('memo')), findsNothing);
    expect(h.api.calls.where((c) => c.startsWith('yedPreview')), isEmpty);
  });

  testWidgets('send: the amber line when a payment leaves the private balance', (tester) async {
    final h = Harness(withWallet: true);
    h.api.balancesAnswer = synced;
    h.api.yecFunding = YecFunding.shielded;
    h.api.revealsShielded = true;
    await openSendYec(tester, h);
    await previewTo(tester, 'smRecipient');
    expect(h.api.calls, contains('yecPreview smRecipient 50000000 false'));
    expect(find.text('This payment leaves your private balance'), findsOneWidget);
    expect(find.text('your private balance'), findsOneWidget);
  });

  testWidgets('send: first private send with no address set downloads from the standard source, then sends', (tester) async {
    final h = Harness(withWallet: true);
    h.api.balancesAnswer = synced;
    h.api.yecFunding = YecFunding.shielded;
    h.api.paramsNeeded = true;
    await openSendYec(tester, h);
    await previewTo(tester, fakeZ);
    await tester.longPress(find.byKey(const Key('slide-to-confirm')));
    await tester.pumpAndSettle();
    expect(find.text('Preparing private sending (52 MB, once)'), findsOneWidget);
    expect(find.byKey(const Key('params-unset')), findsNothing);
    expect(tester.widget<FilledButton>(find.byKey(const Key('params-download'))).onPressed, isNotNull);
    // "Not now": nothing sent, the preview stays.
    await tester.tap(find.byKey(const Key('params-cancel')));
    await tester.pumpAndSettle();
    expect(h.api.calls.where((c) => c.startsWith('yecConfirm')), isEmpty);
    expect(find.byKey(const Key('slide-to-confirm')), findsOneWidget);
    // Again: Download with no address set asks the core for its standard sources (empty base URL).
    await tester.longPress(find.byKey(const Key('slide-to-confirm')));
    await tester.pumpAndSettle();
    expect(h.state.settings.paramsUrl, '');
    await tester.tap(find.byKey(const Key('params-download')));
    await tester.pumpAndSettle();
    expect(h.api.calls, contains('downloadParams '));
    expect(h.api.calls, contains('yecConfirm p1'));
    expect(find.text('Sent'), findsWidgets);
  });

  testWidgets('send: the params sheet shows progress, and a core that finds them missing gets the sheet once', (tester) async {
    final h = Harness(withWallet: true);
    h.secrets.write('settings', const WalletSettings(server: '127.0.0.1:9267', plain: true, network: NetworkId.regtest, trustAccepted: true, paramsUrl: 'https://params.example/').encode());
    h.api.balancesAnswer = synced;
    h.api.yecFunding = YecFunding.shielded;
    h.api.yecConfirmError = const YewError(kind: ErrorKind.paramsMissing, message: 'proving parameters missing');
    final ctl = StreamController<ParamsProgress>();
    h.api.paramsController = ctl;
    await openSendYec(tester, h);
    await previewTo(tester, fakeZ);
    await tester.longPress(find.byKey(const Key('slide-to-confirm')));
    await tester.pumpAndSettle();
    expect(find.text('Preparing private sending (52 MB, once)'), findsOneWidget);
    await tester.tap(find.byKey(const Key('params-download')));
    await tester.pump();
    ctl.add(const ParamsProgress(file: 'sapling-spend.params', doneBytes: 25000000, totalBytes: 51551256, finished: false));
    await tester.pump();
    expect(find.byKey(const Key('params-progress')), findsOneWidget);
    expect(find.text('25.0 of 51.6 MB'), findsOneWidget);
    ctl.add(const ParamsProgress(file: 'sapling-output.params', doneBytes: 51551256, totalBytes: 51551256, finished: true));
    await ctl.close();
    await tester.pumpAndSettle();
    expect(h.api.calls.where((c) => c == 'yecConfirm p1').length, 2);
    expect(find.text('Sent'), findsWidgets);
  });

  testWidgets('settings: private sending files use the standard source unless an address is set', (tester) async {
    final h = Harness(withWallet: true);
    await h.pump(tester);
    await tester.tap(find.byKey(const Key('settings')));
    await tester.pumpAndSettle();
    expect(find.text('Standard source (the one ycashd uses)'), findsOneWidget);
    await tester.tap(find.byKey(const Key('params-url')));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('params-url-field')), 'https://params.example/');
    await tester.tap(find.byKey(const Key('params-url-save')));
    await tester.pumpAndSettle();
    expect(find.text('https://params.example/'), findsOneWidget);
    expect(WalletSettings.decode((await h.secrets.read('settings'))!).paramsUrl, 'https://params.example/');
  });

  testWidgets('history: private rows carry a lock; tapping shows the message', (tester) async {
    final h = Harness(withWallet: true);
    h.api.historyAnswer = [
      HistoryItem(txid: 'ee' * 32, height: 480, pending: false, yecDeltaZat: 25000000, yedDeltaCents: 0, label: 'received YEC', verdict: '', kind: '', hasPayload: false, shielded: true, memo: 'for the bike, thanks!'),
      HistoryItem(txid: 'ef' * 32, height: 460, pending: false, yecDeltaZat: 50000000, yedDeltaCents: 0, label: 'received YEC (public)', verdict: '', kind: '', hasPayload: false, shielded: false, memo: ''),
    ];
    await h.pump(tester);
    await tester.tap(find.byKey(const Key('tab-history')));
    await tester.pumpAndSettle();
    expect(find.byKey(Key('lock-${'ee' * 32}')), findsOneWidget);
    expect(find.byKey(Key('lock-${'ef' * 32}')), findsNothing);
    expect(find.text('for the bike, thanks!'), findsNothing);
    await tester.tap(find.text('received YEC'));
    await tester.pumpAndSettle();
    expect(find.text('for the bike, thanks!'), findsOneWidget);
    expect(find.text('has a private part, hidden on the chain'), findsOneWidget);
  });

  testWidgets('mint: short of public YEC with a private balance: "Move YEC to public first"', (tester) async {
    final h = Harness(withWallet: true);
    h.api.balancesAnswer = const Balances(yecZat: 100000, yecReservedZat: 0, yecPendingZat: 0, yedCents: 0, yedPendingCents: 0, priceMicroUsd: 520000, heldCount: 0, syncHeight: 484, yedSendMinZat: 21000, yecShieldedZat: 200000000, yecShieldedSpendableZat: 200000000, yecShieldedPendingZat: 0, shieldedScannedHeight: 484, shieldedSendable: true);
    await h.pump(tester);
    await tester.tap(find.byKey(const Key('tab-yellowback')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('mint')));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('amount')), '25');
    await tester.tap(find.byKey(const Key('estimate')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('unaffordable')), findsOneWidget);
    expect(find.text('Move YEC to public first'), findsOneWidget);
    expect(find.textContaining('Minting uses public YEC, and 2.00000000 YEC is in your private balance.'), findsOneWidget);
  });

  testWidgets('send YED: no public YEC for the fee but a private balance: the same hint', (tester) async {
    final h = Harness(withWallet: true);
    h.api.balancesAnswer = const Balances(yecZat: 0, yecReservedZat: 0, yecPendingZat: 0, yedCents: 5000, yedPendingCents: 0, heldCount: 0, syncHeight: 484, yedSendMinZat: 21000, yecShieldedZat: 30000000, yecShieldedSpendableZat: 30000000, yecShieldedPendingZat: 0, shieldedScannedHeight: 484, shieldedSendable: true);
    h.api.yedPreviewError = const YewError(kind: ErrorKind.needYecForFees, message: 'You need about 0.00021000 YEC to send YED. Receive YEC first.');
    await h.pump(tester);
    await tester.tap(find.byKey(const Key('send')));
    await tester.pumpAndSettle();
    await previewTo(tester, 'yr1recipient', amount: '1');
    expect(find.text('Move YEC to public first'), findsOneWidget);
    expect(find.textContaining('Sending YED uses public YEC'), findsOneWidget);
  });
}
