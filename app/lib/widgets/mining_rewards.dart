// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

// Mining rewards (beta4): a coinbase output at one of the wallet's own addresses. Consensus spends
// it only after 100 blocks and only into a transaction with no transparent output, so it is in no
// balance and no send: it is shown here as "Mining reward — shield first", an immature one with
// the blocks left, and a mature one moved by "Move to Sapling" into the private balance at the
// exact amount (the reward less the fee, no change), proven on this device.
import 'package:flutter/material.dart';

import '../api/wallet_api.dart';
import '../format.dart';
import '../state/app_scope.dart';
import '../theme.dart';
import 'params_sheet.dart';

/// The rewards of one address.
class _Group {
  _Group(this.address, this.postQuantum);
  final String address;
  final bool postQuantum;
  int matureZat = 0;
  final List<MiningReward> immature = [];
}

class MiningRewardsCard extends StatefulWidget {
  const MiningRewardsCard({super.key, required this.rewards});
  final List<MiningReward> rewards;

  @override
  State<MiningRewardsCard> createState() => _MiningRewardsCardState();
}

class _MiningRewardsCardState extends State<MiningRewardsCard> {
  String? _busy;

  List<_Group> get _groups {
    final by = <String, _Group>{};
    for (final r in widget.rewards) {
      final g = by.putIfAbsent(
        r.address,
        () => _Group(r.address, r.postQuantum),
      );
      if (r.maturesIn == 0) {
        g.matureZat += r.valueZat;
      } else {
        g.immature.add(r);
      }
    }
    return by.values.toList();
  }

  Future<void> _move(_Group g) async {
    final app = AppScope.read(context);
    final messenger = ScaffoldMessenger.of(context);
    setState(() => _busy = g.address);
    try {
      Future<(String, int, int, Future<SendResult> Function())>
      preview() async {
        if (g.postQuantum) {
          final p = await app.api.rewardMovePreview(from: g.address);
          return (
            p.previewId,
            p.amountZat,
            p.feeZat,
            () => app.api.pqSendConfirm(previewId: p.previewId),
          );
        }
        final p = await app.api.rewardShieldPreview(from: g.address);
        return (
          p.previewId,
          p.amountZat,
          p.feeZat,
          () => app.api.moveConfirm(previewId: p.previewId),
        );
      }

      (String, int, int, Future<SendResult> Function()) p;
      try {
        p = await preview();
      } catch (e) {
        if (kindOf(e) != ErrorKind.paramsMissing ||
            !mounted ||
            !await preparePrivateSending(context)) {
          rethrow;
        }
        p = await preview();
      }
      if (!mounted) return;
      final ok = await showDialog<bool>(
        context: context,
        builder: (ctx) => AlertDialog(
          title: const Text('Move mining reward to Sapling'),
          content: Text(
            'Moves exactly ${formatYec(p.$2)} YEC into your private balance '
            '(the reward less the fee of ${formatYec(p.$3)} YEC). A mining reward can only be '
            'shielded, at the exact amount, with no change.',
            key: const Key('reward-move-text'),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(ctx).pop(false),
              child: const Text('Cancel'),
            ),
            FilledButton(
              key: const Key('reward-move-confirm'),
              onPressed: () => Navigator.of(ctx).pop(true),
              child: const Text('Move'),
            ),
          ],
        ),
      );
      if (ok != true) return;
      final r = await p.$4();
      messenger.showSnackBar(
        SnackBar(content: Text('Moved to your private balance: ${r.txid}')),
      );
      await app.sync();
    } catch (e) {
      messenger.showSnackBar(SnackBar(content: Text(messageOf(e))));
    } finally {
      if (mounted) setState(() => _busy = null);
    }
  }

  @override
  Widget build(BuildContext context) {
    final c = yewColors(context);
    final t = Theme.of(context).textTheme;
    final small = t.bodySmall?.copyWith(color: c.pending);
    return Card(
      key: const Key('mining-rewards'),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Mining reward — shield first', style: t.titleMedium),
            const SizedBox(height: 4),
            Text(
              'A mining reward is in no balance: it can only be moved into your private balance, '
              'at the exact amount, after 101 confirmations.',
              style: small,
            ),
            for (final g in _groups) ...[
              const SizedBox(height: 12),
              Text(
                '${g.postQuantum ? 'Post-quantum' : 'Public'} · ${g.address.length > 16 ? '${g.address.substring(0, 10)}…${g.address.substring(g.address.length - 6)}' : g.address}',
                style: t.bodyMedium,
              ),
              for (final r in g.immature)
                Text(
                  '${formatYec(r.valueZat)} YEC matures in ${r.maturesIn} block${r.maturesIn == 1 ? '' : 's'}',
                  key: Key('reward-immature-${r.outpoint}'),
                  style: small,
                ),
              if (g.matureZat > 0) ...[
                Text(
                  '${formatYec(g.matureZat)} YEC ready to move',
                  style: t.bodyMedium,
                ),
                const SizedBox(height: 6),
                // full width: the theme's buttons have no intrinsic width (a Row cannot hold one)
                FilledButton.tonal(
                  key: Key('reward-move-${g.address}'),
                  onPressed: _busy == null ? () => _move(g) : null,
                  child: Text(
                    _busy == g.address ? 'Moving…' : 'Move to Sapling',
                  ),
                ),
              ],
            ],
          ],
        ),
      ),
    );
  }
}
