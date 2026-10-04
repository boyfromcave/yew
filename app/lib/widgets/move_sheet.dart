// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

// Move (yew-shielded plan S4): one sheet, two directions, between the wallet's own private and
// public YEC. To private spends public YEC only (never the amount reserved for fees, never
// YED); to public reveals the amount on the chain, said in the preview. The preview card and
// the slider are the Send ones; the first move fetches the proving files once, like a private
// send. Opened from Home ("Move…") and from "Move YEC to public first" with the shortfall.
import 'package:flutter/material.dart';

import '../api/wallet_api.dart';
import '../format.dart';
import '../state/app_scope.dart';
import '../theme.dart';
import 'params_sheet.dart';
import 'preview_card.dart';
import 'slide_to_confirm.dart';

/// Show the Move sheet, starting in [direction] with [amountZat] filled in (null: empty).
/// Returns true when a move was sent.
/// [all] starts with "Move all" on (a shortfall larger than what can move).
Future<bool> showMoveSheet(BuildContext context, {MoveDirection direction = MoveDirection.toPrivate, int? amountZat, bool all = false}) async {
  final sent = await showModalBottomSheet<bool>(
    context: context,
    isScrollControlled: true,
    showDragHandle: true,
    builder: (_) => MoveSheet(direction: direction, amountZat: amountZat, all: all),
  );
  return sent ?? false;
}

class MoveSheet extends StatefulWidget {
  const MoveSheet({super.key, required this.direction, this.amountZat, this.all = false});
  final MoveDirection direction;
  final int? amountZat;
  final bool all;

  @override
  State<MoveSheet> createState() => _MoveSheetState();
}

class _MoveSheetState extends State<MoveSheet> {
  late MoveDirection _dir = widget.direction;
  late final _amount = TextEditingController(text: widget.amountZat == null ? '' : formatYec(widget.amountZat!));
  late bool _all = widget.all;
  bool _busy = false;
  String? _error;
  YecPreview? _preview;
  SendResult? _result;

  @override
  void dispose() {
    _amount.dispose();
    super.dispose();
  }

  void _reset() => setState(() {
    _preview = null;
    _error = null;
  });

  Future<void> _makePreview() async {
    final app = AppScope.read(context);
    final zat = _all ? null : parseYecZat(_amount.text);
    if (!_all && (zat == null || zat <= 0)) {
      setState(() => _error = 'Enter an amount in YEC, up to eight decimals');
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final p = await app.api.movePreview(direction: _dir, amountZat: zat);
      setState(() => _preview = p);
    } catch (e) {
      setState(() => _error = messageOf(e));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _confirm() async {
    final app = AppScope.read(context);
    try {
      if (_preview!.paramsNeeded && !await preparePrivateSending(context)) return;
      SendResult r;
      try {
        r = await app.api.moveConfirm(previewId: _preview!.previewId);
      } catch (e) {
        if (kindOf(e) != ErrorKind.paramsMissing || !mounted || !await preparePrivateSending(context)) rethrow;
        r = await app.api.moveConfirm(previewId: _preview!.previewId);
      }
      setState(() => _result = r);
      await app.refresh();
    } catch (e) {
      setState(() {
        _error = messageOf(e);
        _preview = null;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final b = app.balances;
    final c = yewColors(context);
    final t = Theme.of(context).textTheme;
    final toPrivate = _dir == MoveDirection.toPrivate;
    final p = _preview;
    final inset = MediaQuery.of(context).viewInsets.bottom;
    if (_result != null) {
      return Padding(
        padding: const EdgeInsets.fromLTRB(24, 0, 24, 32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.check_circle_rounded, size: 72, color: c.yec),
            const SizedBox(height: 12),
            Text('Moved', style: t.headlineSmall),
            const SizedBox(height: 4),
            Text(toPrivate ? 'It shows in Private after the next block.' : 'It shows in Public after the next block.', style: t.bodyMedium),
            const SizedBox(height: 8),
            SelectableText(_result!.txid, key: const Key('move-txid'), textAlign: TextAlign.center, style: t.bodySmall),
            const SizedBox(height: 20),
            FilledButton(key: const Key('move-done'), onPressed: () => Navigator.of(context).pop(true), child: const Text('Done')),
          ],
        ),
      );
    }
    return Padding(
      padding: EdgeInsets.fromLTRB(20, 0, 20, 24 + inset),
      child: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text('Move YEC', style: t.titleLarge),
            const SizedBox(height: 12),
            SegmentedButton<MoveDirection>(
              key: const Key('move-direction'),
              segments: const [
                ButtonSegment(value: MoveDirection.toPrivate, label: Text('To private'), icon: Icon(Icons.lock_rounded)),
                ButtonSegment(value: MoveDirection.toPublic, label: Text('To public'), icon: Icon(Icons.public_rounded)),
              ],
              selected: {_dir},
              onSelectionChanged: p != null
                  ? null
                  : (s) => setState(() {
                      _dir = s.first;
                      _error = null;
                    }),
            ),
            const SizedBox(height: 12),
            Text(
              toPrivate
                  ? '${formatYec(b.yecZat)} YEC public can move. ${formatYec(b.yecReservedZat)} YEC stays reserved for fees.'
                  : '${formatYec(b.yecShieldedSpendableZat)} YEC private can move. The amount will be visible on the chain.',
              key: const Key('move-available'),
              style: t.bodyMedium?.copyWith(color: c.pending),
            ),
            const SizedBox(height: 12),
            TextField(
              key: const Key('move-amount'),
              controller: _amount,
              enabled: p == null && !_all,
              keyboardType: const TextInputType.numberWithOptions(decimal: true),
              onChanged: (_) => _reset(),
              style: t.headlineMedium,
              decoration: const InputDecoration(labelText: 'Amount in YEC', suffixText: 'YEC'),
            ),
            SwitchListTile(
              key: const Key('move-all'),
              value: _all,
              onChanged: p != null ? null : (v) => setState(() => _all = v),
              title: const Text('Move all'),
              subtitle: const Text('Less the network fee'),
              contentPadding: EdgeInsets.zero,
            ),
            if (p == null)
              FilledButton(
                key: const Key('move-preview'),
                onPressed: _busy ? null : _makePreview,
                style: FilledButton.styleFrom(backgroundColor: c.yec),
                child: Text(_busy ? 'Building…' : 'Preview'),
              ),
            if (_error != null) ...[
              const SizedBox(height: 12),
              Text(_error!, key: const Key('move-error'), style: t.bodyMedium?.copyWith(color: c.danger)),
            ],
            if (p != null) ...[
              YecPreviewCard(
                p,
                toLabel: toPrivate ? 'your private balance' : 'your public balance',
                revealText: 'The amount will be visible on the chain',
              ),
              const SizedBox(height: 16),
              SlideToConfirm(label: 'Slide to move ${formatYec(p.amountZat)} YEC', color: c.yec, onConfirmed: _confirm),
              TextButton(key: const Key('move-cancel'), onPressed: _reset, child: const Text('Cancel')),
            ],
          ],
        ),
      ),
    );
  }
}
