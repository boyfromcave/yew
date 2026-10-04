// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

// "Move YEC to public first" (yew-shielded plan §4): YED, minting and fees use public YEC only,
// and nothing is moved automatically. Shown beside an insufficient-YEC message when the
// private balance holds YEC. The one-tap action is S4; until then the step is explained.
import 'package:flutter/material.dart';

import '../format.dart';

class MovePublicHint extends StatelessWidget {
  const MovePublicHint({super.key, required this.what, required this.privateZat});

  /// What needs public YEC: "Minting", "Sending YED".
  final String what;
  final int privateZat;

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    return Padding(
      key: const Key('move-public'),
      padding: const EdgeInsets.only(top: 8),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('Move YEC to public first', style: t.titleSmall),
          const SizedBox(height: 4),
          Text(
            '$what uses public YEC, and ${formatYec(privateZat)} YEC is in your private balance. '
            'Send what you need to your own public address (Receive → Public), wait for it to confirm, then try again.',
            style: t.bodySmall,
          ),
        ],
      ),
    );
  }
}
