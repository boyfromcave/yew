import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:yew_app/api/wallet_api.dart';

import 'fake_wallet_api.dart';

const claimable1 = ClaimableItem(
  vaultTxid: 'f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0',
  ownerAddress: 'yr1someoneelse',
  cents: 1000,
  collateralZat: 950000000,
  claimHeight: 470,
  claimPath: 'a',
  pClaimMicroUsd: 100000,
  feeZat: 1000,
  attestFeeZat: 0,
  residualZat: 0,
  claimantZat: 949998000,
);

Future<void> openClaimable(WidgetTester tester, Harness h) async {
  await h.pump(tester);
  await tester.tap(find.byKey(const Key('tab-yellowback')));
  await tester.pumpAndSettle();
  await tester.tap(find.byKey(const Key('claimable')));
  await tester.pumpAndSettle();
}

void main() {
  testWidgets('the ListClaimable rows; picking one shows the numbers; the slider starts the claim and hands over to progress', (tester) async {
    final h = Harness(withWallet: true);
    h.api.claimableAnswer = const [claimable1];
    await openClaimable(tester, h);
    expect(h.api.calls, contains('claimable'));
    expect(find.text('\$10.00 debt · 9.50000000 YEC'), findsOneWidget);
    expect(find.byKey(const Key('slide-to-confirm')), findsNothing);
    await tester.tap(find.byKey(Key('claimable-${claimable1.vaultTxid}')));
    await tester.pumpAndSettle();
    expect(find.text('9.49998000 YEC'), findsOneWidget); // you keep
    expect(find.text('a · underwater at \$0.10 per YEC'), findsOneWidget);
    await tester.longPress(find.byKey(const Key('slide-to-confirm')));
    await tester.pumpAndSettle();
    expect(h.api.calls, contains('claim ${claimable1.vaultTxid}'));
    expect(find.text('Claim \$10.00'), findsOneWidget);
    expect(find.text('claiming'), findsOneWidget);
    expect(find.text('CARRIER_SENT'), findsOneWidget);
    expect(h.state.mintsInProgress.single.kind, 'claim');
  });

  testWidgets('nothing claimable; a core error while listing is shown verbatim', (tester) async {
    final h = Harness(withWallet: true);
    await openClaimable(tester, h);
    expect(find.byKey(const Key('none')), findsOneWidget);
    h.api.claimableError = const YewError(kind: ErrorKind.yellowbackUnavailable, message: 'gate: no usable Yellowback service on this server');
    await tester.tap(find.byKey(const Key('reload')));
    await tester.pumpAndSettle();
    expect(find.text('gate: no usable Yellowback service on this server'), findsOneWidget);
  });

  testWidgets('a claim needs the debt in YED; the carrier refusal is verbatim', (tester) async {
    final h = Harness(withWallet: true);
    h.api.claimableAnswer = const [claimable1];
    h.api.balancesAnswer = const Balances(yecZat: 150000000, yecReservedZat: 105000, yecPendingZat: 0, yedCents: 500, yedPendingCents: 0, priceMicroUsd: 100000, heldCount: 0, syncHeight: 484, yedSendMinZat: 21000);
    await openClaimable(tester, h);
    await tester.tap(find.byKey(Key('claimable-${claimable1.vaultTxid}')));
    await tester.pumpAndSettle();
    expect(find.text('This claim burns \$10.00 of YED; this wallet holds \$5.00.'), findsOneWidget);
    await tester.longPress(find.byKey(const Key('slide-to-confirm')));
    await tester.pumpAndSettle();
    expect(h.api.calls.where((c) => c.startsWith('claim ')), isEmpty);

    h.api.balancesAnswer = const Balances(yecZat: 150000000, yecReservedZat: 105000, yecPendingZat: 0, yedCents: 5000, yedPendingCents: 0, priceMicroUsd: 100000, heldCount: 0, syncHeight: 484, yedSendMinZat: 21000);
    const refusal = 'insufficient-yec: the mint needs 10023000 zat of YEC (collateral 0, token 10000, fees 3000, carrier 10000), have 5000 zat spendable';
    h.api.claimError = const YewError(kind: ErrorKind.needYecForFees, message: refusal);
    await h.state.refresh();
    await tester.pumpAndSettle();
    await tester.longPress(find.byKey(const Key('slide-to-confirm')));
    await tester.pumpAndSettle();
    expect(find.text(refusal), findsOneWidget);
  });
}
