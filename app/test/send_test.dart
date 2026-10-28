// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:yew_app/api/wallet_api.dart';

import 'fake_wallet_api.dart';

Future<void> openSend(WidgetTester tester, Harness h) async {
  await h.pump(tester);
  await tester.tap(find.byKey(const Key('send')));
  await tester.pumpAndSettle();
}

void main() {
  testWidgets('YED preview shows the fee in YEC and the dry-run verdict, then confirms', (tester) async {
    final h = Harness(withWallet: true);
    await openSend(tester, h);
    expect(find.text('\$50.00 YED available'), findsOneWidget);
    await tester.enterText(find.byKey(const Key('address')), 'yr1recipient');
    await tester.enterText(find.byKey(const Key('amount')), '12.34');
    await tester.tap(find.byKey(const Key('preview')));
    await tester.pumpAndSettle();
    expect(h.api.calls, contains('yedPreview yr1recipient:1234'));
    expect(find.text('0.00001000 YEC (about \$0.01) (1 YEC input)'), findsOneWidget); // rpcversion 8: dollars per KB
    expect(find.text('verdict ok'), findsOneWidget);
    expect(find.text('\$37.66'), findsOneWidget); // YED change
    // Nothing was sent by previewing.
    expect(h.api.calls.where((c) => c.startsWith('yedConfirm')), isEmpty);
    await tester.longPress(find.byKey(const Key('slide-to-confirm')));
    await tester.pumpAndSettle();
    expect(h.api.calls, contains('yedConfirm p2'));
    expect(find.text('Sent'), findsWidgets);
    expect(find.text('bb' * 32), findsOneWidget);
  });

  testWidgets('a gate refusal at confirm surfaces the node verdict verbatim and nothing is marked sent', (tester) async {
    final h = Harness(withWallet: true);
    const refusal = 'gate: refused by the node\'s dry run: verdict "transfer-over-assigned", valid false, burned 0 cents, wouldBeRejected true, 0 unconfirmed input(s)';
    h.api.yedConfirmError = const YewError(kind: ErrorKind.gate, message: refusal);
    await openSend(tester, h);
    await tester.enterText(find.byKey(const Key('address')), 'yr1recipient');
    await tester.enterText(find.byKey(const Key('amount')), '99.99');
    await tester.tap(find.byKey(const Key('preview')));
    await tester.pumpAndSettle();
    await tester.longPress(find.byKey(const Key('slide-to-confirm')));
    await tester.pumpAndSettle();
    expect(find.text(refusal), findsOneWidget);
    expect(find.text('Sent'), findsNothing);
    expect(find.byKey(const Key('slide-to-confirm')), findsNothing);
  });

  testWidgets('a dry run the gate would refuse disables the slider', (tester) async {
    final h = Harness(withWallet: true);
    h.api.dryRun = const DryRun(valid: true, verdict: 'transfer-burn', burnedCents: 100, wouldBeRejected: false, yedInCents: 5000, yedOutCents: 4900, accepted: false);
    await openSend(tester, h);
    await tester.enterText(find.byKey(const Key('address')), 'yr1recipient');
    await tester.enterText(find.byKey(const Key('amount')), '49');
    await tester.tap(find.byKey(const Key('preview')));
    await tester.pumpAndSettle();
    expect(find.textContaining('verdict transfer-burn'), findsOneWidget);
    expect(find.textContaining('burned \$1.00'), findsOneWidget);
    await tester.longPress(find.byKey(const Key('slide-to-confirm')));
    await tester.pumpAndSettle();
    expect(h.api.calls.where((c) => c.startsWith('yedConfirm')), isEmpty);
  });

  testWidgets('no YEC for fees: the explanation with the receive address one tap away', (tester) async {
    final h = Harness(withWallet: true);
    h.api.balancesAnswer = const Balances(yecZat: 0, yecReservedZat: 0, yecPendingZat: 0, yedCents: 5000, yedPendingCents: 0, heldCount: 0, syncHeight: 484, yedSendMinZat: 21000, yecShieldedZat: 0, yecShieldedSpendableZat: 0, yecShieldedPendingZat: 0, shieldedScannedHeight: 0, shieldedSendable: false, yecPqZat: 0, pqCoins: []);
    h.api.yedPreviewError = const YewError(kind: ErrorKind.needYecForFees, message: 'You need about 0.00021000 YEC to send YED. Receive YEC first.');
    await openSend(tester, h);
    await tester.enterText(find.byKey(const Key('address')), 'yr1recipient');
    await tester.enterText(find.byKey(const Key('amount')), '1');
    await tester.tap(find.byKey(const Key('preview')));
    await tester.pumpAndSettle();
    expect(find.text('You need about 0.00021000 YEC to send YED. Receive YEC first.'), findsOneWidget);
    await tester.tap(find.byKey(const Key('show-receive')));
    await tester.pumpAndSettle();
    expect(find.text(fakeYe), findsOneWidget);
  });

  testWidgets('YEC preview: amount in zat, fee, reserve kept; bad address refused before the core', (tester) async {
    final h = Harness(withWallet: true);
    await openSend(tester, h);
    await tester.tap(find.text('YEC'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('address')), 'not-an-address');
    await tester.enterText(find.byKey(const Key('amount')), '0.5');
    await tester.tap(find.byKey(const Key('preview')));
    await tester.pumpAndSettle();
    expect(find.text('not a Regtest address: bad base58check'), findsOneWidget);
    expect(h.api.calls.where((c) => c.startsWith('yecPreview')), isEmpty);
    await tester.enterText(find.byKey(const Key('address')), 'smRecipient');
    await tester.tap(find.byKey(const Key('preview')));
    await tester.pumpAndSettle();
    expect(h.api.calls, contains('yecPreview smRecipient 50000000 false'));
    expect(find.text('0.50000000 YEC'), findsOneWidget);
    expect(find.text('0.00001000 YEC'), findsOneWidget);
    expect(find.text('0.00105000 YEC for YED fees'), findsOneWidget);
    await tester.longPress(find.byKey(const Key('slide-to-confirm')));
    await tester.pumpAndSettle();
    expect(h.api.calls, contains('yecConfirm p1'));
    expect(find.text('aa' * 32), findsOneWidget);
  });

  // Post-quantum destinations (D-Q-20/D-Q-21): YEC to rq…/sq…, YED to a 53-character yr…/yb…
  // Falcon holder; the other way round is refused before the core, with the reason.
  const pqYec = 'rq5MXCssfNHhhz8WuNL5bKAmUKc1k1Wx7TpG2fM8ks9Gz5cPeCqKa';
  const pqYed = 'yr2VA5rANyC4wfgx6kmvLPy2LxuhHYitwJ8xazzFCdXa1gEZSXSRH';
  const pqOwner = 'yr2UGYBxhHb8yzYYCjZ1HtJ8cNHP6tNJawkjC4L1wmRiGdFQVjNy5';

  testWidgets('YEC to a post-quantum rq… address goes to the core preview', (tester) async {
    final h = Harness(withWallet: true);
    await openSend(tester, h);
    await tester.tap(find.text('YEC'));
    await tester.pumpAndSettle();
    expect(find.text('ys1…, s… or sq… address'), findsOneWidget);
    await tester.enterText(find.byKey(const Key('address')), pqYec);
    await tester.enterText(find.byKey(const Key('amount')), '0.5');
    await tester.tap(find.byKey(const Key('preview')));
    await tester.pumpAndSettle();
    expect(h.api.calls, contains('yecPreview $pqYec 50000000 false'));
    expect(find.byKey(const Key('slide-to-confirm')), findsOneWidget);
  });

  testWidgets('YEC to a post-quantum YED (yr…) or vault-owner address is refused before the core', (tester) async {
    final h = Harness(withWallet: true);
    await openSend(tester, h);
    await tester.tap(find.text('YEC'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('address')), pqYed);
    await tester.enterText(find.byKey(const Key('amount')), '0.5');
    await tester.tap(find.byKey(const Key('preview')));
    await tester.pumpAndSettle();
    expect(
      find.text('This is a post-quantum YED address (yb…). To send YEC to the same wallet, ask for its sq… address.'),
      findsOneWidget,
    );
    await tester.enterText(find.byKey(const Key('address')), pqOwner);
    await tester.tap(find.byKey(const Key('preview')));
    await tester.pumpAndSettle();
    expect(find.text('$pqOwner is a post-quantum vault-owner address, not a payment address'), findsOneWidget);
    expect(h.api.calls.where((c) => c.startsWith('yecPreview')), isEmpty);
  });

  testWidgets('YED to a post-quantum YEC (rq…) address is refused; to a Falcon yr… it previews', (tester) async {
    final h = Harness(withWallet: true);
    await openSend(tester, h);
    await tester.enterText(find.byKey(const Key('address')), pqYec);
    await tester.enterText(find.byKey(const Key('amount')), '1');
    await tester.tap(find.byKey(const Key('preview')));
    await tester.pumpAndSettle();
    expect(
      find.text('This is a post-quantum YEC address (sq…): it receives YEC, not YED. Ask for a yb… address.'),
      findsOneWidget,
    );
    expect(h.api.calls.where((c) => c.startsWith('yedPreview')), isEmpty);
    await tester.enterText(find.byKey(const Key('address')), pqYed);
    await tester.tap(find.byKey(const Key('preview')));
    await tester.pumpAndSettle();
    expect(h.api.calls, contains('yedPreview $pqYed:100'));
  });
}
