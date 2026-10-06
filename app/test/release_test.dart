// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

// The vault upgrade (U-15, U-23, U-24): claims wait in intents, are released after the claim
// delay, or are cancelled by the attestor set; a claimed own vault shows CLAIMING.
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'fake_wallet_api.dart';

Future<void> openYellowback(WidgetTester tester, Harness h) async {
  await h.pump(tester);
  await tester.tap(find.byKey(const Key('tab-yellowback')));
  await tester.pumpAndSettle();
}

void main() {
  testWidgets('pending, releasable, residual and cancelled claims are listed with their state', (tester) async {
    final h = Harness(withWallet: true);
    h.api.intentsAnswer = [
      h.api.intent(txid: 'a1' * 32, height: 480),
      h.api.intent(txid: 'a2' * 32, height: 470),
      h.api.intent(txid: 'a3' * 32, role: 'residual', height: 470, valueZat: 300000),
      h.api.intent(txid: 'a4' * 32, state: 'CANCELLED', height: 460),
      h.api.intent(txid: 'a5' * 32, height: 0),
    ];
    await openYellowback(tester, h);
    expect(find.text('Claims and releases'), findsOneWidget);
    expect(find.textContaining('claim · released from height 490 · 5 blocks to go'), findsOneWidget);
    expect(find.text('claim · releasable now'), findsOneWidget);
    expect(find.text('residual of your claimed vault · releasable now'), findsOneWidget);
    expect(find.textContaining('claim cancelled by the attestor set'), findsOneWidget);
    expect(find.textContaining('the YED you burned is not refunded'), findsOneWidget);
    expect(find.text('claim · waiting for the claim to confirm'), findsOneWidget);
  });

  testWidgets('a releasable claim opens the release preview; the slider sends it', (tester) async {
    final h = Harness(withWallet: true);
    final i = h.api.intent(txid: 'a2' * 32, height: 470);
    h.api.intentsAnswer = [i];
    await openYellowback(tester, h);
    await tester.tap(find.byKey(Key('intent-${i.intent}')));
    await tester.pumpAndSettle();
    expect(h.api.calls, contains('releasePreview ${i.intent}'));
    expect(find.text('9.37499000 YEC'), findsWidgets);
    await tester.longPress(find.byKey(const Key('slide-to-confirm')));
    await tester.pumpAndSettle();
    expect(h.api.calls, contains('releaseConfirm rl-${i.intent}'));
    expect(find.text('Released'), findsOneWidget);
  });

  testWidgets('a pending (not yet mature) claim is not tappable; a claimed own vault reads CLAIMING', (tester) async {
    final h = Harness(withWallet: true);
    final i = h.api.intent(txid: 'a1' * 32, height: 480);
    h.api.intentsAnswer = [i];
    h.api.vaultsAnswer = [h.api.vault(txid: 'v1' * 32, status: 'CLAIMING'), h.api.vault(txid: 'v2' * 32, status: 'REOPENED')];
    await openYellowback(tester, h);
    await tester.tap(find.byKey(Key('intent-${i.intent}')));
    await tester.pumpAndSettle();
    expect(h.api.calls.where((c) => c.startsWith('releasePreview')), isEmpty);
    expect(find.textContaining('being claimed'), findsOneWidget);
    expect(find.textContaining('claim cancelled by the attestor set: the vault continues at'), findsOneWidget);
  });
}
