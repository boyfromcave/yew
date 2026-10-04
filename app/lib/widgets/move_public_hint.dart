// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

// "Move YEC to public first" (yew-shielded plan §4, S4): YED, minting and fees use public YEC
// only, and nothing is moved automatically. Shown beside an insufficient-YEC message when the
// private balance holds YEC; one tap opens Move → To public with the shortfall filled in.
import 'package:flutter/material.dart';

import '../api/wallet_api.dart';
import '../format.dart';
import '../state/app_scope.dart';
import 'move_sheet.dart';

class MovePublicHint extends StatelessWidget {
  const MovePublicHint({super.key, required this.what, required this.privateZat, this.shortfallZat});

  /// What needs public YEC: "Minting", "Sending YED".
  final String what;
  final int privateZat;

  /// The public YEC missing, when known: prefilled; when it is more than the spendable private
  /// balance, the sheet opens with "Move all" on instead.
  final int? shortfallZat;

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    final spendable = AppScope.of(context).balances.yecShieldedSpendableZat;
    final need = shortfallZat == null || shortfallZat! <= 0 ? null : shortfallZat;
    final all = need != null && need >= spendable;
    return Padding(
      key: const Key('move-public'),
      padding: const EdgeInsets.only(top: 8),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('Move YEC to public first', style: t.titleSmall),
          const SizedBox(height: 4),
          Text(
            '$what uses public YEC, and ${formatYec(privateZat)} YEC is in your private balance.'
            '${need == null ? '' : ' ${formatYec(need)} YEC more is needed.'}',
            style: t.bodySmall,
          ),
          const SizedBox(height: 4),
          OutlinedButton.icon(
            key: const Key('move-public-open'),
            onPressed: () => showMoveSheet(context, direction: MoveDirection.toPublic, amountZat: all ? null : need, all: all),
            icon: const Icon(Icons.public_rounded),
            label: const Text('Move YEC to public'),
          ),
        ],
      ),
    );
  }
}
