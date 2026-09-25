import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'fake_wallet_api.dart';

Future<void> openYellowback(WidgetTester tester, Harness h) async {
  await h.pump(tester);
  await tester.tap(find.byKey(const Key('tab-yellowback')));
  await tester.pumpAndSettle();
}

void main() {
  testWidgets('Yellowback tab: YED held, locked collateral, vaults with lock height and the underwater warning', (tester) async {
    final h = Harness(withWallet: true);
    h.api.vaultsAnswer = [
      h.api.vault(txid: 'v1' * 32, lockHeight: 528),
      h.api.vault(txid: 'v2' * 32, lockHeight: 470, underwater: true),
      h.api.vault(txid: 'v3' * 32, status: 'CLOSED'),
    ];
    await openYellowback(tester, h);
    expect(find.text('\$50.00'), findsOneWidget);
    expect(find.text('19.00000000 YEC locked as collateral in 2 vaults'), findsOneWidget);
    expect(find.textContaining('redeemable at 528 · 44 blocks to go'), findsOneWidget);
    expect(find.textContaining('redeemable now (lock height 470)'), findsOneWidget);
    expect(find.textContaining('Underwater: the price is at or below \$0.40 per YEC'), findsOneWidget);
    expect(find.textContaining('closed at 530'), findsOneWidget);
    expect(find.byKey(const Key('mint')), findsOneWidget);
    expect(find.byKey(const Key('claimable')), findsOneWidget);
    expect(find.text('In progress'), findsNothing);
  });

  testWidgets('no vaults: the empty line; a row in flight is listed with its state', (tester) async {
    final h = Harness(withWallet: true);
    h.api.mintsAnswer = [h.api.mintRow(id: 1, state: 'CARRIER_SENT'), h.api.mintRow(id: 2, state: 'DONE')];
    await openYellowback(tester, h);
    expect(find.byKey(const Key('no-vaults')), findsOneWidget);
    expect(find.text('In progress'), findsOneWidget);
    expect(find.text('funding carrier → waiting for 1 confirmation'), findsOneWidget);
    expect(find.byKey(const Key('mint-2')), findsNothing, reason: 'a DONE row is history, not progress');
    await tester.tap(find.byKey(const Key('mint-1')));
    await tester.pumpAndSettle();
    expect(find.text('Mint \$25.00'), findsOneWidget);
    expect(find.textContaining('Waiting for the carrier to confirm'), findsOneWidget);
  });
}
