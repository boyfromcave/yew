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
    h.api.balancesAnswer = const Balances(yecZat: 0, yecReservedZat: 0, yecPendingZat: 0, yedCents: 5000, yedPendingCents: 0, heldCount: 0, syncHeight: 484, yedSendMinZat: 21000, yecShieldedZat: 0, yecShieldedSpendableZat: 0, yecShieldedPendingZat: 0, shieldedScannedHeight: 0, shieldedSendable: false, yecPqZat: 0, yecPqSlhZat: 0, yecPqFalconZat: 0, yecStagedForMintZat: 0, pqCoins: []);
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

  testWidgets('beta2 D-5: combining coins of several public addresses needs the go-ahead', (tester) async {
    final h = Harness(withWallet: true);
    h.api.linkingText = 'No single public address of this wallet holds 0.50001000 YEC (the most one holds is 0.30000000 YEC). Paying it would combine coins from several of your public addresses in one transaction, which shows everyone that they belong to the same wallet. Nothing was sent.';
    await openSend(tester, h);
    await tester.tap(find.text('YEC'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('address')), 'smRecipient');
    await tester.enterText(find.byKey(const Key('amount')), '0.5');
    // declined: the core's text, no preview, nothing built with the go-ahead
    await tester.tap(find.byKey(const Key('preview')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('address-linking-dialog')), findsOneWidget);
    expect(find.text(h.api.linkingText!), findsOneWidget);
    await tester.tap(find.byKey(const Key('address-linking-cancel')));
    await tester.pumpAndSettle();
    expect(h.api.calls, isNot(contains('yecPreview smRecipient 50000000 false link')));
    expect(find.byKey(const Key('slide-to-confirm')), findsNothing);
    // accepted: the same call again with the go-ahead, then the usual preview
    await tester.tap(find.byKey(const Key('preview')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('address-linking-accept')));
    await tester.pumpAndSettle();
    expect(h.api.calls, contains('yecPreview smRecipient 50000000 false link'));
    expect(find.byKey(const Key('slide-to-confirm')), findsOneWidget);
  });

  // Post-quantum destinations (D-Q-20/D-Q-21): YEC to rq…/sq…, YED to a 53-character yr…/yb…
  // Falcon holder; the other way round is refused before the core, with the reason.
  const pqYec = 'rqf37MAujTiHQadywBQeNWk42bweehqf1UdcCrXg4oAqhqZQhCebM';
  const pqYed = 'yrf1yW8ubn3p8Wf9XWuksXcZs562YHJTTjqdnLuWym3qJQ8SeGH2b';
  const pqOwner = 'yrs2wCox3ZNcy8vFFh8wejMoNVDfSRKfdjwrp3q4fipDxaJRZPzW3';

  testWidgets('YEC to a post-quantum rq… address goes to the core preview', (tester) async {
    final h = Harness(withWallet: true);
    await openSend(tester, h);
    await tester.tap(find.text('YEC'));
    await tester.pumpAndSettle();
    expect(find.text('ys1…, s…, sqf… or sqs… address'), findsOneWidget);
    await tester.enterText(find.byKey(const Key('address')), pqYec);
    await tester.enterText(find.byKey(const Key('amount')), '0.5');
    await tester.tap(find.byKey(const Key('preview')));
    await tester.pumpAndSettle();
    expect(h.api.calls, contains('yecPreview $pqYec 50000000 false'));
    expect(find.byKey(const Key('slide-to-confirm')), findsOneWidget);
    // beta2 item 3: from the ECC (Automatic) source, not a post-quantum source: the core's YEC
    // send, whose gate path for a post-quantum recipient is its own (Path::YecToPq)
    expect(h.api.calls.where((c) => c.startsWith('pqPreview')), isEmpty);
    await tester.longPress(find.byKey(const Key('slide-to-confirm')));
    await tester.pumpAndSettle();
    expect(h.api.calls.where((c) => c.startsWith('yecConfirm')), hasLength(1));
    expect(find.text('Sent'), findsWidgets);
  });

  testWidgets('YEC to a post-quantum address on a server without Yellowback: the core\'s refusal is shown, nothing is sent', (tester) async {
    final h = Harness(withWallet: true);
    h.api.yecConfirmError = const YewError(kind: ErrorKind.gate, message: 'gate: the server offers no Yellowback service');
    await openSend(tester, h);
    await tester.tap(find.text('YEC'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('address')), pqYec);
    await tester.enterText(find.byKey(const Key('amount')), '0.5');
    await tester.tap(find.byKey(const Key('preview')));
    await tester.pumpAndSettle();
    await tester.longPress(find.byKey(const Key('slide-to-confirm')));
    await tester.pumpAndSettle();
    expect(find.textContaining('offers no Yellowback service'), findsOneWidget);
    expect(find.text('Sent'), findsNothing);
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
      find.text('This is a post-quantum YED address (ybf…/ybs…). To send YEC to the same wallet, ask for its sqf… or sqs… address.'),
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
      find.text('This is a post-quantum YEC address (sqf…/sqs…): it receives YEC, not YED. Ask for a yb… address.'),
      findsOneWidget,
    );
    expect(h.api.calls.where((c) => c.startsWith('yedPreview')), isEmpty);
    await tester.enterText(find.byKey(const Key('address')), pqYed);
    await tester.tap(find.byKey(const Key('preview')));
    await tester.pumpAndSettle();
    expect(h.api.calls, contains('yedPreview $pqYed:100'));
  });

  // beta2 D-8: a send from an own post-quantum address: the source chooser, the fee with the
  // size and signing time before the slider, the core's messages verbatim.
  const slhSource = PqSource(address: fakePqSlh, scheme: 1, schemeName: 'SLH-DSA-SHA2-128s', balanceZat: 300000000);
  const falconSource = PqSource(address: fakePqFalcon, scheme: 2, schemeName: 'FN-DSA-512', balanceZat: 100000000);

  Future<void> choosePqSource(WidgetTester tester) async {
    await tester.tap(find.text('YEC'));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('from')));
    await tester.pumpAndSettle();
    await tester.tap(find.textContaining('Post-quantum SLH-DSA-SHA2-128s').last);
    await tester.pumpAndSettle();
  }

  testWidgets('YEC from a post-quantum address previews the larger fee and its size, then confirms', (tester) async {
    final h = Harness(withWallet: true);
    h.api.pqSourcesAnswer = const [slhSource];
    await openSend(tester, h);
    await choosePqSource(tester);
    expect(find.text('ys1…, s…, sqf… or sqs… address'), findsOneWidget);
    expect(find.byKey(const Key('everything')), findsNothing);
    await tester.enterText(find.byKey(const Key('address')), fakeS);
    await tester.enterText(find.byKey(const Key('amount')), '0.5');
    await tester.tap(find.byKey(const Key('preview')));
    await tester.pumpAndSettle();
    expect(h.api.calls, contains('pqPreview $fakePqSlh $fakeS 50000000'));
    expect(find.byKey(const Key('pq-preview')), findsOneWidget);
    expect(find.text('0.00002000 YEC'), findsOneWidget);
    expect(find.text('8120 bytes · 1 input'), findsOneWidget);
    expect(find.text('0.90 s on this device'), findsOneWidget);
    expect(find.text('0.00050000 YEC back to the same address'), findsOneWidget);
    expect(find.textContaining('An SLH-DSA signature is about 7.9 KB per input'), findsOneWidget);
    expect(h.api.calls.where((c) => c.startsWith('pqConfirm')), isEmpty);
    await tester.longPress(find.byKey(const Key('slide-to-confirm')));
    await tester.pumpAndSettle();
    expect(h.api.calls, contains('pqConfirm q1'));
    expect(find.text('qq' * 32), findsOneWidget);
  });

  testWidgets('YEC from a post-quantum address to a private ys1… address goes to the core\'s post-quantum preview (beta2 item 5)', (tester) async {
    final h = Harness(withWallet: true);
    h.api.pqSourcesAnswer = const [slhSource];
    await openSend(tester, h);
    await choosePqSource(tester);
    await tester.enterText(find.byKey(const Key('address')), fakeZ);
    await tester.enterText(find.byKey(const Key('amount')), '0.5');
    await tester.tap(find.byKey(const Key('preview')));
    await tester.pumpAndSettle();
    expect(h.api.calls, contains('pqPreview $fakePqSlh $fakeZ 50000000'));
    expect(h.api.calls.where((c) => c.startsWith('yecPreview')), isEmpty);
    expect(find.byKey(const Key('pq-preview')), findsOneWidget);
    await tester.longPress(find.byKey(const Key('slide-to-confirm')));
    await tester.pumpAndSettle();
    expect(h.api.calls, contains('pqConfirm q1'));
  });

  testWidgets('a post-quantum send shows the core\'s refusal and its status-unknown answer verbatim', (tester) async {
    final h = Harness(withWallet: true);
    h.api.pqSourcesAnswer = const [slhSource];
    const refusal = 'Insufficient transparent funds, have 0.03, need 0.50002';
    h.api.pqPreviewError = const YewError(kind: ErrorKind.other, message: refusal);
    await openSend(tester, h);
    await choosePqSource(tester);
    await tester.enterText(find.byKey(const Key('address')), fakeS);
    await tester.enterText(find.byKey(const Key('amount')), '0.5');
    await tester.tap(find.byKey(const Key('preview')));
    await tester.pumpAndSettle();
    expect(find.text(refusal), findsOneWidget);
    h.api.pqPreviewError = null;
    final unknown = 'transport error; status unknown, txid ${'qq' * 32}: check before sending again';
    h.api.pqConfirmError = YewError(kind: ErrorKind.other, message: unknown);
    await tester.tap(find.byKey(const Key('preview')));
    await tester.pumpAndSettle();
    await tester.longPress(find.byKey(const Key('slide-to-confirm')));
    await tester.pumpAndSettle();
    expect(find.text(unknown), findsOneWidget);
    expect(find.text('Sent'), findsNothing);
  });

  testWidgets('an unusually high post-quantum fee is marked with the core\'s reason; no clock reads "not measured"', (tester) async {
    final h = Harness(withWallet: true);
    h.api.pqSourcesAnswer = const [slhSource];
    const note = 'Unusually high fee: 0.50 YEC, above 0.10 YEC for a 8120-byte post-quantum send. It is priced at 6000000 zat/KB from the YEC price the server reports, which this app cannot verify; check the YEC price before you send.';
    h.api.pqFeeNote = note;
    h.api.pqSignUnmeasured = true;
    await openSend(tester, h);
    await choosePqSource(tester);
    await tester.enterText(find.byKey(const Key('address')), fakeS);
    await tester.enterText(find.byKey(const Key('amount')), '0.5');
    await tester.tap(find.byKey(const Key('preview')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('pq-fee-note')), findsOneWidget);
    expect(find.text(note), findsOneWidget);
    expect(find.text('not measured on this device'), findsOneWidget);
    expect(find.textContaining('0.00 s'), findsNothing);
  });

  testWidgets('an unusual fee is never sent by the slider alone: a separate confirmation passes the core\'s acknowledgement', (tester) async {
    final h = Harness(withWallet: true);
    h.api.pqSourcesAnswer = const [slhSource];
    const note = 'Unusual fee: 0.50000000 YEC, 4.2× the usual 0.11880000 YEC for a transaction of this size at the highest YEC price this wallet has seen. The fee terms came from the server.';
    h.api.pqFeeNote = note;
    h.api.pqFeeAck = 'accept-unusual-fee:50000000:qq';
    await openSend(tester, h);
    await choosePqSource(tester);
    await tester.enterText(find.byKey(const Key('address')), fakeS);
    await tester.enterText(find.byKey(const Key('amount')), '0.5');
    await tester.tap(find.byKey(const Key('preview')));
    await tester.pumpAndSettle();
    // the slider opens the separate confirmation; declining sends nothing and keeps the preview
    await tester.longPress(find.byKey(const Key('slide-to-confirm')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('unusual-fee-dialog')), findsOneWidget);
    expect(find.descendant(of: find.byKey(const Key('unusual-fee-dialog')), matching: find.text(note)), findsOneWidget);
    await tester.tap(find.byKey(const Key('unusual-fee-cancel')));
    await tester.pumpAndSettle();
    expect(h.api.calls.where((c) => c.startsWith('pqConfirm')), isEmpty);
    expect(find.text('Sent'), findsNothing);
    expect(find.byKey(const Key('pq-fee-note')), findsOneWidget);
    // accepting passes exactly the acknowledgement the preview carried
    await tester.longPress(find.byKey(const Key('slide-to-confirm')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('unusual-fee-accept')));
    await tester.pumpAndSettle();
    expect(h.api.calls, contains('pqConfirm q1 ack=accept-unusual-fee:50000000:qq'));
    expect(find.text('Sent'), findsWidgets);
  });

  testWidgets('a fee that is not flagged sends with the slider and no acknowledgement', (tester) async {
    final h = Harness(withWallet: true);
    h.api.pqSourcesAnswer = const [slhSource];
    await openSend(tester, h);
    await choosePqSource(tester);
    await tester.enterText(find.byKey(const Key('address')), fakeS);
    await tester.enterText(find.byKey(const Key('amount')), '0.5');
    await tester.tap(find.byKey(const Key('preview')));
    await tester.pumpAndSettle();
    await tester.longPress(find.byKey(const Key('slide-to-confirm')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('unusual-fee-dialog')), findsNothing);
    expect(h.api.calls.where((c) => c.startsWith('pqConfirm')).single.contains('ack='), isFalse);
    expect(find.text('Sent'), findsWidgets);
  });

  testWidgets('a chosen post-quantum source that drops out of the list falls back to Automatic', (tester) async {
    final h = Harness(withWallet: true);
    h.api.pqSourcesAnswer = const [slhSource, falconSource];
    await openSend(tester, h);
    await choosePqSource(tester);
    // beta2 item 5: a private recipient is accepted from a post-quantum source too
    expect(find.text('ys1…, s…, sqf… or sqs… address'), findsOneWidget);
    // the SLH-DSA address is spent elsewhere: the next refresh no longer lists it
    h.api.pqSourcesAnswer = const [falconSource];
    await h.state.refresh();
    await tester.pumpAndSettle();
    expect(tester.takeException(), isNull);
    expect(find.text('Automatic: private first, then public'), findsOneWidget);
    expect(find.text('ys1…, s…, sqf… or sqs… address'), findsOneWidget);
  });

  testWidgets('without post-quantum coins there is no source chooser', (tester) async {
    final h = Harness(withWallet: true);
    await openSend(tester, h);
    await tester.tap(find.text('YEC'));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('from')), findsNothing);
  });

  testWidgets('from the private balance to a post-quantum address: the private -> public notice, then the confirm', (tester) async {
    final h = Harness(withWallet: true);
    h.api.balancesAnswer = Balances(
      yecZat: h.api.balancesAnswer.yecZat, yecReservedZat: 0, yecPendingZat: 0, yedCents: 5000, yedPendingCents: 0,
      heldCount: 0, syncHeight: 484, yedSendMinZat: 21000, yecShieldedZat: 90000000, yecShieldedSpendableZat: 90000000,
      yecShieldedPendingZat: 0, shieldedScannedHeight: 484, shieldedSendable: true, yecPqZat: 0, yecPqSlhZat: 0,
      yecPqFalconZat: 0, yecStagedForMintZat: 0, pqCoins: const []);
    await openSend(tester, h);
    await tester.tap(find.text('YEC'));
    await tester.pumpAndSettle();
    // no post-quantum coins, but a private balance: the chooser offers Private
    await tester.tap(find.byKey(const Key('from')));
    await tester.pumpAndSettle();
    await tester.tap(find.textContaining('Private · 0.90').last);
    await tester.pumpAndSettle();
    expect(find.text('sqf… or sqs… address'), findsOneWidget);
    await tester.enterText(find.byKey(const Key('address')), fakePqSlh);
    await tester.enterText(find.byKey(const Key('amount')), '0.5');
    await tester.tap(find.byKey(const Key('preview')));
    await tester.pumpAndSettle();
    expect(h.api.calls, contains('privatePqPreview $fakePqSlh 50000000'));
    expect(h.api.calls.where((c) => c.startsWith('pqPreview') || c.startsWith('yecPreview')), isEmpty);
    expect(find.text('your private balance'), findsOneWidget);
    expect(find.text('This payment leaves your private balance'), findsOneWidget);
    expect(find.byKey(const Key('pq-size-note')), findsNothing);
    expect(find.textContaining('YEC back to your private balance'), findsOneWidget);
    // nothing sent by previewing
    expect(h.api.calls.where((c) => c.startsWith('pqConfirm')), isEmpty);
    await tester.longPress(find.byKey(const Key('slide-to-confirm')));
    await tester.pumpAndSettle();
    expect(h.api.calls, contains('pqConfirm zq1'));
    expect(find.text('Sent'), findsWidgets);
  });

  testWidgets('review YEW-REVIEW-8 M1: notes the store lacks need the go-ahead before the server is asked', (tester) async {
    final h = Harness(withWallet: true);
    h.api.balancesAnswer = Balances(
      yecZat: h.api.balancesAnswer.yecZat, yecReservedZat: 0, yecPendingZat: 0, yedCents: 5000, yedPendingCents: 0,
      heldCount: 0, syncHeight: 484, yedSendMinZat: 21000, yecShieldedZat: 90000000, yecShieldedSpendableZat: 90000000,
      yecShieldedPendingZat: 0, shieldedScannedHeight: 484, shieldedSendable: true, yecPqZat: 0, yecPqSlhZat: 0,
      yecPqFalconZat: 0, yecStagedForMintZat: 0, pqCoins: const []);
    h.api.noteLookupText = 'To spend older notes the app must ask the server for 2 transactions; the server can then tell which notes this payment spends. Nothing was sent.';
    await openSend(tester, h);
    await tester.tap(find.text('YEC'));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('from')));
    await tester.pumpAndSettle();
    await tester.tap(find.textContaining('Private · 0.90').last);
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('address')), fakePqSlh);
    await tester.enterText(find.byKey(const Key('amount')), '0.5');
    // declined: no lookup, no preview
    await tester.tap(find.byKey(const Key('preview')));
    await tester.pumpAndSettle();
    expect(find.text(h.api.noteLookupText!), findsOneWidget);
    await tester.tap(find.byKey(const Key('note-lookup-cancel')));
    await tester.pumpAndSettle();
    expect(h.api.calls, isNot(contains('privatePqPreview $fakePqSlh 50000000 lookup')));
    expect(find.byKey(const Key('slide-to-confirm')), findsNothing);
    // accepted: the same call again with the go-ahead
    await tester.tap(find.byKey(const Key('preview')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('note-lookup-accept')));
    await tester.pumpAndSettle();
    expect(h.api.calls, contains('privatePqPreview $fakePqSlh 50000000 lookup'));
    expect(find.text('This payment leaves your private balance'), findsOneWidget);
  });

  testWidgets('a private -> post-quantum refusal is shown verbatim and nothing is sent', (tester) async {
    final h = Harness(withWallet: true);
    h.api.balancesAnswer = Balances(
      yecZat: 0, yecReservedZat: 0, yecPendingZat: 0, yedCents: 0, yedPendingCents: 0,
      heldCount: 0, syncHeight: 484, yedSendMinZat: 21000, yecShieldedZat: 1000, yecShieldedSpendableZat: 1000,
      yecShieldedPendingZat: 0, shieldedScannedHeight: 484, shieldedSendable: true, yecPqZat: 0, yecPqSlhZat: 0,
      yecPqFalconZat: 0, yecStagedForMintZat: 0, pqCoins: const []);
    h.api.pqPreviewError = const YewError(kind: ErrorKind.other, message: 'Not enough private YEC: 1000 zat spendable, 50002000 zat needed (amount plus fee).');
    await openSend(tester, h);
    await tester.tap(find.text('YEC'));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('from')));
    await tester.pumpAndSettle();
    await tester.tap(find.textContaining('Private · ').last);
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('address')), fakePqSlh);
    await tester.enterText(find.byKey(const Key('amount')), '0.5');
    await tester.tap(find.byKey(const Key('preview')));
    await tester.pumpAndSettle();
    expect(find.text('Not enough private YEC: 1000 zat spendable, 50002000 zat needed (amount plus fee).'), findsOneWidget);
    expect(find.byKey(const Key('slide-to-confirm')), findsNothing);
  });
}
