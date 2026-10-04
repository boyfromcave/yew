// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

// The Send error card (plan §3.7 item 4): the core's message verbatim; for a YED send without
// YEC for the fee, the explanation, the receive address one tap away and, when the private
// balance holds YEC, "Move YEC to public first".
import 'package:flutter/material.dart';

import '../api/wallet_api.dart';
import '../format.dart';
import '../screens/receive.dart';
import '../state/app_scope.dart';
import '../theme.dart';
import 'move_public_hint.dart';

class SendErrorCard extends StatelessWidget {
  const SendErrorCard({super.key, required this.message, required this.needYec});
  final String message;
  final bool needYec;

  @override
  Widget build(BuildContext context) {
    final b = AppScope.of(context).balances;
    final c = yewColors(context);
    final t = Theme.of(context).textTheme;
    return Card(
      color: c.danger.withValues(alpha: 0.08),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(message, key: const Key('error'), style: t.bodyMedium),
            if (needYec) ...[
              const SizedBox(height: 8),
              Text(
                'Sending YED costs a small YEC fee (about ${formatYec(b.yedSendMinZat)} YEC). '
                'This wallet has ${formatYec(b.yecZat + b.yecReservedZat)} public YEC.',
                style: t.bodySmall,
              ),
              const SizedBox(height: 8),
              OutlinedButton.icon(
                key: const Key('show-receive'),
                onPressed: () => Navigator.of(context).push(MaterialPageRoute<void>(builder: (_) => const ReceiveScreen(kind: ReceiveKind.yed))),
                icon: const Icon(Icons.qr_code_2_rounded),
                label: const Text('Show my receive address'),
              ),
              if (b.yecShieldedZat > 0)
                MovePublicHint(
                  what: 'Sending YED',
                  privateZat: b.yecShieldedZat,
                  shortfallZat: b.yedSendMinZat - (b.yecZat + b.yecReservedZat),
                ),
            ],
          ],
        ),
      ),
    );
  }
}
