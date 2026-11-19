// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

// beta4: mining rewards (coinbase outputs) shown apart, immature ones with the blocks left, the
// mature ones moved to Sapling at the exact amount, over the fake.
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:yew_app/api/wallet_api.dart';

import 'fake_wallet_api.dart';

void main() {
  testWidgets(
    'home: a mining reward is shown to shield first, immature with blocks left, mature moved to Sapling',
    (tester) async {
      final h = Harness(withWallet: true);
      h.api.miningRewardsAnswer = const [
        MiningReward(
          address: fakePqFalcon,
          postQuantum: true,
          outpoint: 'aa:0',
          valueZat: 1250000000,
          height: 400,
          maturesIn: 0,
        ),
        MiningReward(
          address: fakePqFalcon,
          postQuantum: true,
          outpoint: 'bb:0',
          valueZat: 625000000,
          height: 480,
          maturesIn: 21,
        ),
      ];
      await h.pump(tester);
      expect(find.byKey(const Key('mining-rewards')), findsOneWidget);
      expect(find.text('Mining reward — shield first'), findsOneWidget);
      expect(find.text('6.25000000 YEC matures in 21 blocks'), findsOneWidget);
      expect(find.text('12.50000000 YEC ready to move'), findsOneWidget);
      await tester.ensureVisible(
        find.byKey(const Key('reward-move-$fakePqFalcon')),
      );
      await tester.tap(find.byKey(const Key('reward-move-$fakePqFalcon')));
      await tester.pumpAndSettle();
      expect(h.api.calls, contains('rewardMovePreview $fakePqFalcon'));
      expect(
        find.textContaining(
          'Moves exactly 12.49935000 YEC into your private balance',
        ),
        findsOneWidget,
      );
      expect(h.api.calls.where((c) => c.startsWith('pqConfirm')), isEmpty);
      await tester.tap(find.byKey(const Key('reward-move-confirm')));
      await tester.pumpAndSettle();
      expect(h.api.calls, contains('pqConfirm r1'));
    },
  );

  testWidgets('home: no mining reward, no card', (tester) async {
    final h = Harness(withWallet: true);
    await h.pump(tester);
    expect(find.byKey(const Key('mining-rewards')), findsNothing);
  });
}
