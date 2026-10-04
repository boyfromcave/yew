// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

// The Send result (plan §5.1): the confirming animation, the txid, the node's verdict.
import 'package:flutter/material.dart';

import '../api/wallet_api.dart';
import '../theme.dart';

class SendResultView extends StatelessWidget {
  const SendResultView({super.key, required this.result, required this.accent});
  final SendResult result;
  final Color accent;

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    return Scaffold(
      appBar: AppBar(title: const Text('Sent')),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              TweenAnimationBuilder<double>(
                tween: Tween(begin: 0, end: 1),
                duration: confirmMotion,
                curve: Curves.easeOutBack,
                builder: (_, v, child) => Transform.scale(scale: v, child: child),
                child: Icon(Icons.check_circle_rounded, size: 96, color: accent),
              ),
              const SizedBox(height: 24),
              Text('Sent', style: t.headlineMedium),
              const SizedBox(height: 8),
              SelectableText(result.txid, key: const Key('txid'), textAlign: TextAlign.center, style: t.bodySmall),
              if (result.verdict.isNotEmpty) Text('node verdict: ${result.verdict}', style: t.bodySmall),
              const SizedBox(height: 32),
              FilledButton(key: const Key('done'), onPressed: () => Navigator.of(context).pop(), child: const Text('Done')),
            ],
          ),
        ),
      ),
    );
  }
}
