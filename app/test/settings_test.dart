// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:yew_app/screens/keys.dart';
import 'package:yew_app/trust_text.dart';

import 'fake_wallet_api.dart';

Future<void> openSettings(WidgetTester tester, Harness h) async {
  await h.pump(tester);
  await tester.tap(find.byKey(const Key('settings')));
  await tester.pumpAndSettle();
}

void main() {
  testWidgets('the Server screen takes a pinned certificate and passes it to probe and save (audit G-4)', (tester) async {
    final h = Harness(withWallet: true);
    await openSettings(tester, h);
    await tester.tap(find.byKey(const Key('server')));
    await tester.pumpAndSettle();
    // Regtest with plain on: no certificate field. Switch plain off: the field appears.
    expect(find.byKey(const Key('ca-pem')), findsNothing);
    await tester.tap(find.byKey(const Key('plain')));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('server')), 'lwd.example.org:443');
    await tester.enterText(find.byKey(const Key('ca-pem')), '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----');
    await tester.tap(find.byKey(const Key('probe')));
    await tester.pumpAndSettle();
    expect(h.api.calls, contains('probe lwd.example.org:443 false regtest pinned'));
    await tester.tap(find.byKey(const Key('save')));
    await tester.pumpAndSettle();
    expect(h.api.calls, contains('setServer lwd.example.org:443 false pinned'));
    expect(h.state.settings.caPem, contains('BEGIN CERTIFICATE'));
    // Settings shows the pin; the next unlock passes it to the core.
    expect(find.textContaining('(pinned)'), findsOneWidget);
  });

  testWidgets('the device-unlock toggle moves the seed into the presence-bound keystore entry (audit G-10)', (tester) async {
    final h = Harness(withWallet: true);
    await openSettings(tester, h);
    expect(h.secrets.bound, isFalse);
    await tester.tap(find.byKey(const Key('biometrics')));
    await tester.pumpAndSettle();
    expect(h.state.settings.biometrics, isTrue);
    expect(h.secrets.bound, isTrue);
    await tester.tap(find.byKey(const Key('biometrics')));
    await tester.pumpAndSettle();
    expect(h.secrets.bound, isFalse);
  });

  testWidgets('export private key shows the warning before the key, then the WIF and both address forms', (tester) async {
    final h = Harness(withWallet: true);
    await openSettings(tester, h);
    await tester.tap(find.byKey(const Key('export-key')));
    await tester.pumpAndSettle();
    expect(find.text(exportWarning), findsOneWidget);
    expect(find.textContaining('the YEC and the YED on it move with the key'), findsOneWidget);
    expect(find.byKey(const Key('qr-text')), findsNothing);
    expect(h.api.calls.where((c) => c.startsWith('exportWif')), isEmpty);
    await tester.tap(find.byKey(const Key('reveal')));
    await tester.pumpAndSettle();
    expect(h.api.calls, contains('exportWif $fakeYe'));
    expect(find.text('cVfakeWif1111111111111111111111111111111111111111111'), findsOneWidget);
    expect(find.text(fakeYe), findsOneWidget);
    expect(find.text(fakeS), findsOneWidget);
  });

  testWidgets('import private key calls the bridge with the birthday and flags the key as outside the seed', (tester) async {
    final h = Harness(withWallet: true);
    await openSettings(tester, h);
    await tester.tap(find.byKey(const Key('import-key')));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('wif')), 'cVsomething');
    await tester.enterText(find.byKey(const Key('birthday')), '300');
    await tester.tap(find.byKey(const Key('import')));
    await tester.pumpAndSettle();
    expect(h.api.calls, contains('importWif 300'));
    expect(find.text('yr1imported'), findsOneWidget);
    expect(find.textContaining('not covered by the recovery phrase'), findsWidgets);
  });

  testWidgets('trust statement, seed backup and lock from Settings', (tester) async {
    final h = Harness(withWallet: true);
    await openSettings(tester, h);
    await tester.tap(find.byKey(const Key('trust')));
    await tester.pumpAndSettle();
    expect(find.text(trustParagraphs.first), findsOneWidget);
    // The last paragraph is below the fold on a phone (audit G-3 added one): scroll to it.
    await tester.scrollUntilVisible(find.text(trustParagraphs.last), 200, scrollable: find.byType(Scrollable).first);
    expect(find.text(trustParagraphs.last), findsOneWidget);
    await tester.pageBack();
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('seed-backup')));
    await tester.pumpAndSettle();
    expect(find.text('1. abandon'), findsOneWidget);
    expect(find.byKey(const Key('done')), findsNothing);
    await tester.pageBack();
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('lock')));
    await tester.pumpAndSettle();
    expect(h.api.calls, contains('lock'));
    expect(h.state.unlocked, isFalse);
    expect(find.text('Locked'), findsOneWidget);
    await tester.tap(find.byKey(const Key('unlock')));
    await tester.pumpAndSettle();
    expect(h.state.unlocked, isTrue);
    expect(find.byKey(const Key('send')), findsOneWidget);
  });
}
