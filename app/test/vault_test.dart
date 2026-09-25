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
    await tester.longPress(find.byKey(const Key('slide-to-confirm')));
    await tester.pumpAndSettle();
    expect(h.api.calls.where((c) => c.startsWith('redeem')), isEmpty);
  });

  testWidgets('at the lock height the slider redeems through the core and shows the burn and the collateral back', (tester) async {
    final h = Harness(withWallet: true);
    final txid = 'v2' * 32;
    h.api.vaultsAnswer = [h.api.vault(txid: txid, lockHeight: 484, cents: 3000)];
    await openVault(tester, h, txid);
    expect(find.text('Redeemable: the lock height 484 is reached (synced to 484)'), findsOneWidget);
    expect(find.byKey(const Key('locked')), findsNothing);
    await tester.longPress(find.byKey(const Key('slide-to-confirm')));
    await tester.pumpAndSettle();
    expect(h.api.calls, contains('redeem $txid'));
    expect(find.text('Vault redeemed'), findsOneWidget);
    expect(find.text('ed' * 32), findsOneWidget);
    expect(find.text('9.49998000 YEC'), findsOneWidget);
    expect(find.text('\$30.00'), findsOneWidget); // burned
    expect(find.text('\$20.00'), findsOneWidget); // YED change
    expect(find.textContaining('YED change'), findsOneWidget);
  });

  testWidgets('a VOID vault offers the release; a gate refusal at redeem is shown verbatim', (tester) async {
    final h = Harness(withWallet: true);
    final txid = 'v3' * 32;
    h.api.vaultsAnswer = [h.api.vault(txid: txid, status: 'VOID', voidReason: 'abandoned', lockHeight: 528)];
    const refusal = 'gate: refused by the node\'s dry run: verdict "vault-locked", valid false, burned 0 cents, wouldBeRejected true, 0 unconfirmed input(s)';
    h.api.redeemError = const YewError(kind: ErrorKind.gate, message: refusal);
    await openVault(tester, h, txid);
    expect(find.text('VOID (abandoned): the collateral can be released'), findsOneWidget);
    expect(find.text('Slide to release 9.50000000 YEC'), findsOneWidget);
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
    await tester.longPress(find.byKey(const Key('slide-to-confirm')));
    await tester.pumpAndSettle();
    expect(h.api.calls.where((c) => c.startsWith('redeem')), isEmpty);
  });
}
