import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:yew_app/trust_text.dart';

import 'fake_wallet_api.dart';

void main() {
  testWidgets('create flow: trust statement, server, biometrics, seed backup, home', (tester) async {
    final h = Harness();
    await h.pump(tester);
    expect(find.text('Create a new wallet'), findsOneWidget);
    expect(find.textContaining('Transparent only'), findsOneWidget);

    await tester.tap(find.byKey(const Key('create')));
    await tester.pumpAndSettle();
    // The trust statement (plan §4 rule 7), verbatim, and it must be acknowledged.
    expect(find.text(trustTitle), findsOneWidget);
    expect(find.text(trustParagraphs.first), findsOneWidget);
    expect(tester.widget<FilledButton>(find.byKey(const Key('next'))).onPressed, isNull);
    await tester.tap(find.byKey(const Key('trust-check')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('next')));
    await tester.pumpAndSettle();

    // Server step: pick regtest + plain, probe fills the birthday with the tip.
    await tester.tap(find.byKey(const Key('network')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('regtest').last);
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('server')), '10.0.2.2:9267');
    await tester.tap(find.byKey(const Key('plain')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('probe')));
    await tester.pumpAndSettle();
    expect(find.text('Server ok · tip 484'), findsOneWidget);
    await tester.tap(find.byKey(const Key('next')));
    await tester.pumpAndSettle();

    await tester.tap(find.byKey(const Key('biometrics')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('finish')));
    await tester.pumpAndSettle();

    // A generated seed is shown once and must be acknowledged.
    expect(find.text('Recovery phrase'), findsOneWidget);
    expect(find.text('12. about'), findsOneWidget);
    expect(tester.widget<FilledButton>(find.byKey(const Key('done'))).onPressed, isNull);
    await tester.tap(find.byKey(const Key('written')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('done')));
    await tester.pumpAndSettle();

    expect(h.api.calls, contains('probe 10.0.2.2:9267 true regtest'));
    expect(h.api.calls, contains('create words=false birthday=484 regtest 10.0.2.2:9267 plain=true'));
    expect(await h.secrets.read('seed'), fakeWords);
    expect(h.state.settings.biometrics, isTrue);
    expect(h.state.settings.trustAccepted, isTrue);
    // Home.
    expect(find.text('YED'), findsOneWidget);
    expect(find.byKey(const Key('send')), findsOneWidget);
  });

  testWidgets('restore flow passes the words and birthday and shows no seed screen', (tester) async {
    final h = Harness();
    await h.pump(tester);
    await tester.tap(find.byKey(const Key('restore')));
    await tester.pumpAndSettle();
    expect(tester.widget<FilledButton>(find.byKey(const Key('next'))).onPressed, isNull);
    await tester.enterText(find.byKey(const Key('words')), fakeWords);
    await tester.enterText(find.byKey(const Key('birthday')), '120');
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('next')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('trust-check')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('next')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('next')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('finish')));
    await tester.pumpAndSettle();
    expect(h.api.calls.any((c) => c.startsWith('create words=true birthday=120 mainnet')), isTrue);
    expect(find.text('Recovery phrase'), findsNothing);
    expect(find.byKey(const Key('send')), findsOneWidget);
  });

  testWidgets('a bad mnemonic surfaces the core message verbatim', (tester) async {
    final h = Harness();
    await h.pump(tester);
    await tester.tap(find.byKey(const Key('restore')));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('words')), 'a b c d e f g h i j k l');
    await tester.pumpAndSettle();
    for (final step in ['next', 'trust-check', 'next', 'next', 'finish']) {
      await tester.tap(find.byKey(Key(step)));
      await tester.pumpAndSettle();
    }
    expect(find.text('bad mnemonic: invalid checksum'), findsOneWidget);
    expect(h.state.hasWallet, isFalse);
    expect(h.api.calls.where((c) => c.startsWith('create')), isEmpty);
  });
}
