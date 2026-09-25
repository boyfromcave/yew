import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:yew_app/api/wallet_api.dart';

import 'fake_wallet_api.dart';

Future<void> openMint(WidgetTester tester, Harness h) async {
  await h.pump(tester);
  await tester.tap(find.byKey(const Key('tab-yellowback')));
  await tester.pumpAndSettle();
  await tester.tap(find.byKey(const Key('mint')));
  await tester.pumpAndSettle();
}

void main() {
  testWidgets('estimate shows the collateral, fees and heights; start records the row and shows its progress', (tester) async {
    final h = Harness(withWallet: true);
    await openMint(tester, h);
    expect(find.byKey(const Key('two-step')), findsOneWidget);
    expect(find.text('1.50105000 YEC available for collateral and fees'), findsOneWidget);
    // The picker: class B sets the lock to the class's shortest length.
    await tester.tap(find.textContaining('B · 97'));
    await tester.pumpAndSettle();
    expect(find.text('97'), findsOneWidget);
    await tester.tap(find.textContaining('A · 48'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('amount')), '25');
    await tester.tap(find.byKey(const Key('estimate')));
    await tester.pumpAndSettle();
    expect(h.api.calls, contains('mintEstimate 2500 48'));
    expect(find.text('\$25.00'), findsOneWidget);
    expect(find.text('0.95000000 YEC'), findsOneWidget); // collateral
    expect(find.text('class A · 48 blocks'), findsOneWidget);
    expect(find.text('height 528'), findsOneWidget); // lock
    expect(find.text('height 548'), findsOneWidget); // claim
    expect(find.text('0.00001000 YEC'), findsOneWidget); // enforcement fee
    expect(find.text('0.95023000 YEC'), findsOneWidget); // total
    expect(find.text('480 · window closes at 520'), findsOneWidget);
    expect(find.text('0, 1, 2'), findsOneWidget);
    expect(h.api.calls.where((c) => c.startsWith('mintStart')), isEmpty);
    await tester.tap(find.byKey(const Key('start')));
    await tester.pumpAndSettle();
    expect(h.api.calls, contains('mintStart 2500 48'));
    // The progress screen renders the CARRIER_SENT row: step one now, the rest to do.
    expect(find.text('Mint \$25.00'), findsOneWidget);
    expect(find.text('funding carrier'), findsOneWidget);
    expect(find.text('waiting for 1 confirmation'), findsOneWidget);
    expect(find.text('minting'), findsOneWidget);
    expect(find.text('CARRIER_SENT'), findsOneWidget);
    expect(find.byKey(const Key('finish')), findsNothing);
    expect(find.byKey(const Key('sweep')), findsNothing);
  });

  testWidgets('a confirmed carrier is finished by itself and the row moves to MAIN_SENT; DONE shows Done', (tester) async {
    final h = Harness(withWallet: true);
    h.api.mintsAnswer = [h.api.mintRow(id: 4, state: 'CARRIER_CONFIRMED')];
    await h.pump(tester);
    await tester.tap(find.byKey(const Key('tab-yellowback')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('mint-4')));
    await tester.pumpAndSettle();
    expect(h.api.calls, contains('mintFinish 4'));
    expect(find.text('MAIN_SENT'), findsOneWidget);
    expect(find.textContaining('Sent. Waiting for one confirmation'), findsOneWidget);
    expect(find.byKey(const Key('done')), findsNothing);
    // The sync loop confirms it (the fake's table changes; a sync refreshes the screen).
    h.api.mintsAnswer = [h.api.mintRow(id: 4, state: 'DONE')];
    await tester.tap(find.byKey(const Key('sync')));
    await tester.pumpAndSettle();
    expect(find.text('DONE'), findsOneWidget);
    expect(find.textContaining('The mint confirmed'), findsOneWidget);
    expect(find.byKey(const Key('done')), findsOneWidget);
  });

  testWidgets('a lapsed row shows "window closed, sweeping carrier" and the sweep action', (tester) async {
    final h = Harness(withWallet: true);
    h.api.mintsAnswer = [h.api.mintRow(id: 5, state: 'LAPSED', tip: 530)];
    await h.pump(tester);
    await tester.tap(find.byKey(const Key('tab-yellowback')));
    await tester.pumpAndSettle();
    expect(find.text('window closed, sweeping carrier'), findsOneWidget);
    await tester.tap(find.byKey(const Key('mint-5')));
    await tester.pumpAndSettle();
    expect(find.text('window closed'), findsOneWidget);
    expect(find.text('sweeping carrier'), findsOneWidget);
    expect(h.api.calls.where((c) => c.startsWith('mintFinish')), isEmpty);
    await tester.tap(find.byKey(const Key('sweep')));
    await tester.pumpAndSettle();
    expect(h.api.calls, contains('mintSweep 5'));
    expect(find.text('SWEEP_SENT'), findsOneWidget);
    expect(find.byKey(const Key('sweep')), findsNothing);
  });

  testWidgets('the gate refusal of the carrier surfaces verbatim and no row is shown', (tester) async {
    final h = Harness(withWallet: true);
    const refusal = 'gate: refused by the node\'s dry run: verdict "carrier-value", valid false, burned 0 cents, wouldBeRejected true, 0 unconfirmed input(s)';
    h.api.mintStartError = const YewError(kind: ErrorKind.gate, message: refusal);
    await openMint(tester, h);
    await tester.enterText(find.byKey(const Key('amount')), '10');
    await tester.tap(find.byKey(const Key('estimate')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('start')));
    await tester.pumpAndSettle();
    expect(find.text(refusal), findsOneWidget);
    expect(find.text('Mint \$10.00'), findsNothing);
    expect(h.state.mints, isEmpty);
  });

  testWidgets('an unaffordable estimate disables the start and says how much YEC is missing', (tester) async {
    final h = Harness(withWallet: true);
    h.api.balancesAnswer = const Balances(yecZat: 100000, yecReservedZat: 0, yecPendingZat: 0, yedCents: 0, yedPendingCents: 0, priceMicroUsd: 520000, heldCount: 0, syncHeight: 484, yedSendMinZat: 21000);
    await openMint(tester, h);
    await tester.enterText(find.byKey(const Key('amount')), '25');
    await tester.tap(find.byKey(const Key('estimate')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('unaffordable')), findsOneWidget);
    expect(find.textContaining('needs 0.95023000 YEC and the wallet has 0.00100000'), findsOneWidget);
    await tester.tap(find.byKey(const Key('start')));
    await tester.pumpAndSettle();
    expect(h.api.calls.where((c) => c.startsWith('mintStart')), isEmpty);
  });
}
