// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'fake_wallet_api.dart';

void main() {
  testWidgets('before the private balance has synced receive shows the yb… form, toggles to s…, and asks for a new address', (tester) async {
    final h = Harness(withWallet: true);
    await h.pump(tester);
    await tester.tap(find.byKey(const Key('receive')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('qr-text')), findsOneWidget);
    expect(find.text(fakeYe), findsOneWidget);
    expect(find.text(fakeS), findsNothing);
    expect(find.text("m/44'/347'/0'/0/0"), findsOneWidget);
    // C-10: the YED receive form is the holder key, never the vault owner's post-quantum address.
    expect(find.textContaining('A vault-owner address (53 characters) is never a receive address.'), findsOneWidget);
    expect(find.text(fakeOwnerPq), findsNothing);

    await tester.tap(find.text('Public'));
    await tester.pumpAndSettle();
    expect(find.text(fakeS), findsOneWidget);
    expect(find.text(fakeYe), findsNothing);

    await tester.tap(find.byKey(const Key('new-address')));
    await tester.pumpAndSettle();
    expect(h.api.fresh, 1);
  });

  // beta2 D-8, D-9: the post-quantum tab, the scheme visible in the label and the prefix.
  testWidgets('receive offers the post-quantum addresses with the scheme named', (tester) async {
    final h = Harness(withWallet: true);
    await h.pump(tester);
    await tester.tap(find.byKey(const Key('receive')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('PQ'));
    await tester.pumpAndSettle();
    expect(find.text(fakePqFalcon), findsOneWidget);
    expect(fakePqFalcon.startsWith('rqf'), isTrue);
    expect(find.text('FN-DSA-512 · sqf…'), findsOneWidget);
    expect(find.textContaining('post-quantum FN-DSA-512 (Falcon) address'), findsOneWidget);
    expect(find.text("m/44'/347'/0'/0/0 (FN-DSA-512)"), findsOneWidget);
    await tester.tap(find.text('SLH-DSA · sqs…'));
    await tester.pumpAndSettle();
    expect(find.text(fakePqSlh), findsOneWidget);
    expect(find.text(fakePqFalcon), findsNothing);
    expect(find.textContaining('~7.9 KB signature, so its fees are the largest'), findsOneWidget);
  });

  testWidgets('without Yellowback on the server the post-quantum tab is hidden', (tester) async {
    final h = Harness(withWallet: true);
    h.api.yellowbackPresent = false;
    await h.pump(tester);
    await tester.tap(find.byKey(const Key('receive')));
    await tester.pumpAndSettle();
    expect(find.text('PQ'), findsNothing);
    expect(find.text(fakePqFalcon), findsNothing);
  });
}
