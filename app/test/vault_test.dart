// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:yew_app/api/wallet_api.dart';

import 'fake_wallet_api.dart';

Future<void> openVault(WidgetTester tester, Harness h, String txid) async {
  await h.pump(tester);
  await tester.tap(find.byKey(const Key('tab-yellowback')));
  await tester.pumpAndSettle();
  await tester.tap(find.byKey(Key('vault-$txid')));
  await tester.pumpAndSettle();
}

void main() {
  testWidgets('a vault before its lock height: details shown, the slider disabled', (tester) async {
    final h = Harness(withWallet: true);
    final txid = 'v1' * 32;
    h.api.vaultsAnswer = [h.api.vault(txid: txid, lockHeight: 528)];
    await openVault(tester, h, txid);
    expect(find.text('\$25.00'), findsOneWidget);
    expect(find.text('minted against 9.50000000 YEC'), findsOneWidget);
    expect(find.text('Locked until height 528: 44 blocks to go (synced to 484)'), findsOneWidget);
    expect(find.text('Redeem unlocks at height 528.'), findsOneWidget);
    // No preview before the lock: the button is disabled and no slider exists yet.
    expect(tester.widget<FilledButton>(find.byKey(const Key('preview'))).onPressed, isNull);
    expect(find.byKey(const Key('slide-to-confirm')), findsNothing);
    expect(h.api.calls.where((c) => c.startsWith('redeem')), isEmpty);
  });

  testWidgets('at the lock height: preview first (fee and payee shown), then the slider confirms the same preview', (tester) async {
    final h = Harness(withWallet: true);
    final txid = 'v2' * 32;
    h.api.vaultsAnswer = [h.api.vault(txid: txid, lockHeight: 484, cents: 3000)];
    await openVault(tester, h, txid);
    expect(find.text('Redeemable: the lock height 484 is reached (synced to 484)'), findsOneWidget);
    expect(find.byKey(const Key('locked')), findsNothing);
    // Nothing is sent until the preview is on screen (audit G-2).
    expect(find.byKey(const Key('slide-to-confirm')), findsNothing);
    await tester.tap(find.byKey(const Key('preview')));
    await tester.pumpAndSettle();
    expect(h.api.calls, contains('redeemPreview $txid'));
    expect(h.api.calls.where((c) => c.startsWith('redeemConfirm')), isEmpty);
    expect(find.byKey(const Key('redeem-preview')), findsOneWidget);
    expect(find.text('0.50000000 YEC'), findsOneWidget); // the enforcement fee, FEE_MIN
    expect(find.text('Fee paid to'), findsOneWidget);
    expect(find.text('8.99999000 YEC'), findsOneWidget); // collateral back
    expect(find.text('Slide to redeem: burn \$30.00, pay 0.50000000 YEC fee'), findsOneWidget);
    await tester.longPress(find.byKey(const Key('slide-to-confirm')));
    await tester.pumpAndSettle();
    expect(h.api.calls, contains('redeemConfirm rp-$txid'));
    expect(find.text('Vault redeemed'), findsOneWidget);
    expect(find.text('ed' * 32), findsOneWidget);
    expect(find.text('\$30.00'), findsOneWidget); // burned
    expect(find.text('\$20.00'), findsOneWidget); // YED change
    expect(find.textContaining('YED change'), findsOneWidget);
  });

  testWidgets('a VOID vault offers the release; a refusal at the preview is shown verbatim and nothing is sent', (tester) async {
    final h = Harness(withWallet: true);
    final txid = 'v3' * 32;
    h.api.vaultsAnswer = [h.api.vault(txid: txid, status: 'VOID', voidReason: 'abandoned', lockHeight: 528)];
    const refusal = 'inconsistent-server: the server answered an inconsistent vault (feeZat 949998000 for collateral 950000000 (FEE-1 gives 50000000)); try another server';
    h.api.redeemError = const YewError(kind: ErrorKind.refused, message: refusal);
    await openVault(tester, h, txid);
    expect(find.text('VOID (abandoned): the collateral can be released'), findsOneWidget);
    await tester.tap(find.byKey(const Key('preview')));
    await tester.pumpAndSettle();
    expect(find.text(refusal), findsOneWidget);
    expect(find.byKey(const Key('slide-to-confirm')), findsNothing);
    expect(h.api.calls.where((c) => c.startsWith('redeemConfirm')), isEmpty);
    expect(find.text('Collateral released'), findsNothing);
  });

  testWidgets('a gate refusal at confirm is shown verbatim', (tester) async {
    final h = Harness(withWallet: true);
    final txid = 'v5' * 32;
    h.api.vaultsAnswer = [h.api.vault(txid: txid, status: 'VOID', voidReason: 'abandoned', lockHeight: 528)];
    const refusal = 'gate: refused by the node\'s dry run: verdict "vault-locked", valid false, burned 0 cents, wouldBeRejected true, 0 unconfirmed input(s)';
    h.api.redeemConfirmError = const YewError(kind: ErrorKind.gate, message: refusal);
    await openVault(tester, h, txid);
    await tester.tap(find.byKey(const Key('preview')));
    await tester.pumpAndSettle();
    expect(find.text('Slide to release 9.49999000 YEC'), findsOneWidget);
    await tester.longPress(find.byKey(const Key('slide-to-confirm')));
    await tester.pumpAndSettle();
    expect(find.text(refusal), findsOneWidget);
    expect(find.text('Collateral released'), findsNothing);
  });

  testWidgets('redeeming needs the debt in YED: too little YED disables the slider and says so', (tester) async {
    final h = Harness(withWallet: true);
    final txid = 'v4' * 32;
    h.api.vaultsAnswer = [h.api.vault(txid: txid, lockHeight: 400, cents: 9900)];
    await openVault(tester, h, txid);
    expect(find.text('Redeeming burns \$99.00 of YED; this wallet holds \$50.00.'), findsOneWidget);
    expect(tester.widget<FilledButton>(find.byKey(const Key('preview'))).onPressed, isNull);
    expect(h.api.calls.where((c) => c.startsWith('redeem')), isEmpty);
  });
}
