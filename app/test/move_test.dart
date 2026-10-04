// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

// yew-shielded plan S4: Move between the own private and public balances, over the fake.
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:yew_app/api/wallet_api.dart';

import 'fake_wallet_api.dart';
import 'shielded_test.dart' show synced;

Future<void> openMove(WidgetTester tester, Harness h) async {
  await h.pump(tester);
  await tester.tap(find.byKey(const Key('move')));
  await tester.pumpAndSettle();
}

void main() {
  testWidgets('home: Move… to private, preview card, slide, moved', (tester) async {
    final h = Harness(withWallet: true);
    h.api.balancesAnswer = synced;
    await openMove(tester, h);
    expect(find.text('Move YEC'), findsOneWidget);
    expect(find.text('1.50000000 YEC public can move. 0.00105000 YEC stays reserved for fees.'), findsOneWidget);
    await tester.enterText(find.byKey(const Key('move-amount')), '1');
    await tester.tap(find.byKey(const Key('move-preview')));
    await tester.pumpAndSettle();
    expect(h.api.calls, contains('movePreview toPrivate 100000000'));
    expect(find.text('your private balance'), findsOneWidget); // To
    expect(find.text('your public balance'), findsOneWidget); // From
    expect(find.text('0.00015000 YEC'), findsOneWidget); // fee
    expect(find.text('0.00105000 YEC for YED fees'), findsOneWidget);
    expect(find.byKey(const Key('reveals')), findsNothing);
    expect(h.api.calls.where((c) => c.startsWith('moveConfirm')), isEmpty);
    await tester.longPress(find.byKey(const Key('slide-to-confirm')));
    await tester.pumpAndSettle();
    expect(h.api.calls, contains('moveConfirm m1'));
    expect(find.text('Moved'), findsOneWidget);
    expect(find.text('mm' * 32), findsOneWidget);
    await tester.tap(find.byKey(const Key('move-done')));
    await tester.pumpAndSettle();
    expect(find.text('Move YEC'), findsNothing);
  });

  testWidgets('to public, all: the amount becomes visible, said in amber', (tester) async {
    final h = Harness(withWallet: true);
    h.api.balancesAnswer = synced;
    await openMove(tester, h);
    await tester.tap(find.text('To public'));
    await tester.pumpAndSettle();
    expect(find.text('0.40000000 YEC private can move. The amount will be visible on the chain.'), findsOneWidget);
    await tester.tap(find.byKey(const Key('move-all')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('move-preview')));
    await tester.pumpAndSettle();
    expect(h.api.calls, contains('movePreview toPublic all'));
    expect(find.text('0.39985000 YEC'), findsOneWidget);
    expect(find.text('your private balance'), findsOneWidget); // From
    expect(find.text('your public balance'), findsOneWidget); // To
    expect(find.text('The amount will be visible on the chain'), findsOneWidget);
    expect(find.text('Slide to move 0.39985000 YEC'), findsOneWidget);
  });

  testWidgets('first move fetches the proving files once, then confirms', (tester) async {
    final h = Harness(withWallet: true);
    h.api.balancesAnswer = synced;
    h.api.paramsNeeded = true;
    await openMove(tester, h);
    await tester.enterText(find.byKey(const Key('move-amount')), '0.1');
    await tester.tap(find.byKey(const Key('move-preview')));
    await tester.pumpAndSettle();
    await tester.longPress(find.byKey(const Key('slide-to-confirm')));
    await tester.pumpAndSettle();
    expect(find.textContaining('52 MB'), findsWidgets);
    expect(h.api.calls.where((c) => c.startsWith('moveConfirm')), isEmpty);
  });

  testWidgets('an error from the core is shown verbatim; nothing is confirmed', (tester) async {
    final h = Harness(withWallet: true);
    h.api.balancesAnswer = synced;
    h.api.movePreviewError = const YewError(kind: ErrorKind.needYecForFees, message: 'not enough YEC: need 200015000 zat, have 150000000');
    await openMove(tester, h);
    await tester.enterText(find.byKey(const Key('move-amount')), '2');
    await tester.tap(find.byKey(const Key('move-preview')));
    await tester.pumpAndSettle();
    expect(find.text('not enough YEC: need 200015000 zat, have 150000000'), findsOneWidget);
    expect(find.byKey(const Key('slide-to-confirm')), findsNothing);
  });

  testWidgets('mint short of public YEC: the hint opens Move → To public with the shortfall', (tester) async {
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
    // The fake: collateral 2500 · 38000 zat + 23000 zat of fees and outputs, 100000 public.
    const shortfall = 2500 * 38000 + 23000 - 100000;
    expect(find.textContaining('0.94923000 YEC more is needed.'), findsOneWidget);
    await tester.ensureVisible(find.byKey(const Key('move-public-open')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('move-public-open')));
    await tester.pumpAndSettle();
    expect(find.text('Move YEC'), findsOneWidget);
    final seg = tester.widget<SegmentedButton<MoveDirection>>(find.byKey(const Key('move-direction')));
    expect(seg.selected, {MoveDirection.toPublic});
    expect(tester.widget<TextField>(find.byKey(const Key('move-amount'))).controller!.text, '0.94923000');
    await tester.tap(find.byKey(const Key('move-preview')));
    await tester.pumpAndSettle();
    expect(h.api.calls, contains('movePreview toPublic $shortfall'));
  });

  testWidgets('a shortfall larger than the private balance opens Move all', (tester) async {
    final h = Harness(withWallet: true);
    h.api.balancesAnswer = const Balances(yecZat: 100000, yecReservedZat: 0, yecPendingZat: 0, yedCents: 0, yedPendingCents: 0, priceMicroUsd: 520000, heldCount: 0, syncHeight: 484, yedSendMinZat: 21000, yecShieldedZat: 50000000, yecShieldedSpendableZat: 50000000, yecShieldedPendingZat: 0, shieldedScannedHeight: 484, shieldedSendable: true);
    await h.pump(tester);
    await tester.tap(find.byKey(const Key('tab-yellowback')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('mint')));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('amount')), '25');
    await tester.tap(find.byKey(const Key('estimate')));
    await tester.pumpAndSettle();
    await tester.ensureVisible(find.byKey(const Key('move-public-open')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('move-public-open')));
    await tester.pumpAndSettle();
    expect(tester.widget<SwitchListTile>(find.byKey(const Key('move-all'))).value, isTrue);
    await tester.tap(find.byKey(const Key('move-preview')));
    await tester.pumpAndSettle();
    expect(h.api.calls, contains('movePreview toPublic all'));
  });

  testWidgets('send YED without public fee money: the hint prefills the missing fee YEC', (tester) async {
    final h = Harness(withWallet: true);
    h.api.balancesAnswer = const Balances(yecZat: 0, yecReservedZat: 0, yecPendingZat: 0, yedCents: 5000, yedPendingCents: 0, heldCount: 0, syncHeight: 484, yedSendMinZat: 21000, yecShieldedZat: 30000000, yecShieldedSpendableZat: 30000000, yecShieldedPendingZat: 0, shieldedScannedHeight: 484, shieldedSendable: true);
    h.api.yedPreviewError = const YewError(kind: ErrorKind.needYecForFees, message: 'You need about 0.00021000 YEC to send YED. Receive YEC first.');
    await h.pump(tester);
    await tester.tap(find.byKey(const Key('send')));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('address')), 'yr1recipient');
    await tester.enterText(find.byKey(const Key('amount')), '1');
    await tester.tap(find.byKey(const Key('preview')));
    await tester.pumpAndSettle();
    await tester.ensureVisible(find.byKey(const Key('move-public-open')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('move-public-open')));
    await tester.pumpAndSettle();
    expect(tester.widget<TextField>(find.byKey(const Key('move-amount'))).controller!.text, '0.00021000');
  });

  testWidgets('send: the message field follows the core\'s address kind, not a prefix guess', (tester) async {
    final h = Harness(withWallet: true);
    h.api.balancesAnswer = synced;
    await h.pump(tester);
    await tester.tap(find.byKey(const Key('send')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('YEC'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('address')), fakeZ);
    await tester.pump();
    expect(find.byKey(const Key('memo')), findsOneWidget);
    // A Sapling-looking prefix the core rejects is not private: no message field.
    await tester.enterText(find.byKey(const Key('address')), 'yregtestsapling-not');
    await tester.pump();
    expect(find.byKey(const Key('memo')), findsNothing);
  });
}
