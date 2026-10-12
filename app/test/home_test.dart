// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:yew_app/api/wallet_api.dart';
import 'package:yew_app/format.dart';

import 'fake_wallet_api.dart';

void main() {
  testWidgets('home renders balances, reserve, pending and the price line from the bridge', (tester) async {
    final h = Harness(withWallet: true);
    h.api.balancesAnswer = const Balances(
      yecZat: 123456789,
      yecReservedZat: 105000,
      yecPendingZat: 50000,
      yedCents: 1234567,
      yedPendingCents: 250,
      priceMicroUsd: 520000,
      heldCount: 1,
      syncHeight: 484,
      yedSendMinZat: 21000, yecShieldedZat: 0, yecShieldedSpendableZat: 0, yecShieldedPendingZat: 0, shieldedScannedHeight: 0, shieldedSendable: false,
      yecPqZat: 0,
      pqCoins: [],
    );
    await h.pump(tester);
    // The lock screen auto-unlocks (no biometrics) and Home syncs once.
    expect(h.api.calls, contains('unlock'));
    expect(h.api.calls, contains('sync'));
    expect(find.text('\$12,345.67'.replaceAll(',', '')), findsOneWidget);
    expect(find.text('+ \$2.50 pending'), findsOneWidget);
    // One YEC total (private + public, the reserve included), then the two-line split.
    expect(find.text('1.23561789'), findsOneWidget);
    expect(find.text('0.00000000 YEC'), findsOneWidget); // private
    expect(find.text('1.23561789 YEC'), findsOneWidget); // public
    expect(find.text('0.00105000 YEC reserved for fees'), findsOneWidget);
    expect(find.text('0.00050000 YEC pending'), findsOneWidget);
    expect(find.textContaining('1 output held'), findsOneWidget);
    expect(find.text('1 YED = \$1.00 · mint price 1.92 YEC'), findsOneWidget);
    expect(find.text('synced to 484'), findsOneWidget);
  });

  testWidgets('YEC at an own post-quantum address shows apart from the balance and moves to the wallet', (tester) async {
    final h = Harness(withWallet: true);
    final coin = '${'c0' * 32}:0';
    h.api.balancesAnswer = Balances(
      yecZat: 100000,
      yecReservedZat: 0,
      yecPendingZat: 0,
      yedCents: 0,
      yedPendingCents: 0,
      heldCount: 0,
      syncHeight: 484,
      yedSendMinZat: 21000, yecShieldedZat: 0, yecShieldedSpendableZat: 0, yecShieldedPendingZat: 0, shieldedScannedHeight: 0, shieldedSendable: false,
      yecPqZat: 150000000,
      pqCoins: [coin],
    );
    await h.pump(tester);
    // Not in the public balance: no P2PKH path spends it.
    expect(find.text('0.00100000 YEC'), findsOneWidget);
    expect(find.text('1.50000000 YEC at your post-quantum addresses · tap to move it to your wallet'), findsOneWidget);
    await tester.tap(find.byKey(const Key('pq-yec')));
    await tester.pumpAndSettle();
    expect(h.api.calls, contains('releasePreview $coin'));
    expect(find.text('Move to wallet'), findsOneWidget);
    expect(find.text('1.49997000 YEC'), findsOneWidget);
    expect(find.text('0.00003000 YEC (out of the coin, priced by size)'), findsOneWidget);
    expect(find.text('Coin'), findsOneWidget);
    await tester.longPress(find.byKey(const Key('slide-to-confirm')));
    await tester.pumpAndSettle();
    expect(h.api.calls, contains('releaseConfirm rl-$coin'));
  });

  testWidgets('history tab lists verdict labels from the bridge', (tester) async {
    final h = Harness(withWallet: true);
    h.api.historyAnswer = [
      HistoryItem(txid: 'ab' * 32, height: 0, pending: true, yecDeltaZat: -1000, yedDeltaCents: -1234, label: 'sending \$12.34', verdict: '', kind: 'transfer', hasPayload: true, shielded: false, memo: ''),
      HistoryItem(txid: 'cd' * 32, height: 470, pending: false, yecDeltaZat: 100000000, yedDeltaCents: 5000, label: 'received \$50.00', verdict: 'ok', kind: 'transfer', hasPayload: true, shielded: false, memo: ''),
      HistoryItem(txid: 'ef' * 32, height: 460, pending: false, yecDeltaZat: 50000000, yedDeltaCents: 0, label: 'received YEC', verdict: '', kind: '', hasPayload: false, shielded: false, memo: ''),
    ];
    await h.pump(tester);
    await tester.tap(find.byKey(const Key('tab-history')));
    await tester.pumpAndSettle();
    expect(find.text('sending \$12.34'), findsOneWidget);
    expect(find.text('received \$50.00'), findsOneWidget);
    expect(find.text('height 470 · ok'), findsOneWidget);
    expect(find.text('+\$50.00'), findsOneWidget);
    expect(find.text('+0.50000000 YEC'), findsOneWidget);
    await tester.tap(find.text('received \$50.00'));
    await tester.pumpAndSettle();
    expect(find.text('cd' * 32), findsOneWidget);
    expect(find.text('confirmed at height 470'), findsOneWidget);
  });

  test('amount rules', () {
    expect(formatYed(0), '\$0.00');
    expect(formatYed(1234567), '\$12345.67');
    expect(formatYed(-5), '-\$0.05');
    expect(formatYec(21000), '0.00021000');
    expect(formatYec(150000000), '1.50000000');
    expect(parseYedCents('12.3'), 1230);
    expect(parseYedCents('\$0.99'), 99);
    expect(parseYedCents('1.234'), isNull);
    expect(parseYecZat('0.5'), 50000000);
    expect(parseYecZat('1.000000001'), isNull);
    expect(formatPriceLine(null), '1 YED = \$1.00 · mint price unavailable');
    expect(formatPriceLine(2000000), '1 YED = \$1.00 · mint price 0.5000 YEC');
  });
}
