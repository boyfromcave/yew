// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'fake_wallet_api.dart';

Future<void> openYellowback(WidgetTester tester, Harness h) async {
  await h.pump(tester);
  await tester.tap(find.byKey(const Key('tab-yellowback')));
  await tester.pumpAndSettle();
}

void main() {
  testWidgets('Yellowback tab: YED held, locked collateral, vaults with their term, claimable-at price and claimable now', (tester) async {
    final h = Harness(withWallet: true);
    h.api.vaultsAnswer = [
      h.api.vault(txid: 'v1' * 32, lockHeight: 528),
      h.api.vault(txid: 'v2' * 32, lockHeight: 470, underwater: true),
      h.api.vault(txid: 'v3' * 32, status: 'CLOSED'),
    ];
    await openYellowback(tester, h);
    expect(find.text('\$50.00'), findsOneWidget);
    expect(find.text('19.00000000 YEC locked as collateral in 2 vaults'), findsOneWidget);
    expect(find.textContaining('redeemable now (early-redeem fee 5 % until 528'), findsOneWidget);
    expect(find.textContaining('claimable below \$0.40 per YEC'), findsOneWidget);
    expect(find.textContaining('CLAIMABLE NOW: anyone may close it by paying its debt'), findsOneWidget);
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
