// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'fake_wallet_api.dart';

void main() {
  testWidgets('before the private balance has synced receive shows the ye… form, toggles to s…, and asks for a new address', (tester) async {
    final h = Harness(withWallet: true);
    await h.pump(tester);
    await tester.tap(find.byKey(const Key('receive')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('qr-text')), findsOneWidget);
    expect(find.text(fakeYe), findsOneWidget);
    expect(find.text(fakeS), findsNothing);
    expect(find.text("m/44'/347'/0'/0/0"), findsOneWidget);

    await tester.tap(find.text('Public'));
    await tester.pumpAndSettle();
    expect(find.text(fakeS), findsOneWidget);
    expect(find.text(fakeYe), findsNothing);

    await tester.tap(find.byKey(const Key('new-address')));
    await tester.pumpAndSettle();
    expect(h.api.fresh, 1);
  });
}
