// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

// Vault (plan §5.3): the details of one own vault; Redeem once `lockHeight` is reached
// (burning the debt from the wallet's YED); Release when the node reports it VOID. Both are
// two calls of the core (audit G-2): `redeemPreview` builds and signs and the card shows the
// collateral back, the enforcement fee and its payee and the burn; the slider then calls
// `redeemConfirm`, which gates and broadcasts those same bytes.
import 'package:flutter/material.dart';

import '../api/wallet_api.dart';
import '../format.dart';
import '../state/app_scope.dart';
import '../theme.dart';
import '../widgets/preview_card.dart';
import '../widgets/slide_to_confirm.dart';

class VaultScreen extends StatefulWidget {
  const VaultScreen({super.key, required this.vaultTxid});
  final String vaultTxid;

  @override
  State<VaultScreen> createState() => _VaultScreenState();
}

class _VaultScreenState extends State<VaultScreen> {
  String? _error;
  RedeemPreview? _preview;
  RedeemResult? _result;
  bool _busy = false;

  Future<void> _previewNow() async {
    final app = AppScope.read(context);
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final p = await app.api.redeemPreview(vaultTxid: widget.vaultTxid);
      setState(() => _preview = p);
    } catch (e) {
      setState(() => _error = messageOf(e));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _confirm() async {
    final app = AppScope.read(context);
    final p = _preview;
    if (p == null) return;
    try {
      final r = await app.api.redeemConfirm(previewId: p.previewId);
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
    final c = yewColors(context);
    final t = Theme.of(context).textTheme;
    final v = app.vaultByTxid(widget.vaultTxid);
    if (_result != null) return _RedeemedView(_result!);
    if (v == null) {
      return Scaffold(appBar: AppBar(title: const Text('Vault')), body: const Center(child: Text('No such vault.')));
    }
    final canAct = v.redeemable || v.releasable;
    final enoughYed = app.balances.yedCents >= v.cents;
    final String status;
    if (v.releasable) {
      status = 'VOID (${v.voidReason}): the collateral can be released';
    } else if (v.redeemable) {
      status = 'Redeemable: the lock height ${v.lockHeight} is reached (synced to ${v.tip})';
    } else if (v.open) {
      status = 'Locked until height ${v.lockHeight}: ${v.blocksUntilRedeem} block${v.blocksUntilRedeem == 1 ? '' : 's'} to go (synced to ${v.tip})';
    } else {
      status = '${v.status} at height ${v.closeHeight}';
    }
    return Scaffold(
      appBar: AppBar(title: const Text('Vault')),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.fromLTRB(20, 8, 20, 32),
          children: [
            Text(formatYed(v.cents), style: t.displayMedium?.copyWith(color: c.yed)),
            Text('minted against ${formatYec(v.collateralZat)} YEC', style: t.titleMedium?.copyWith(color: c.yec)),
            const SizedBox(height: 8),
            Text(status, key: const Key('status'), style: t.bodyMedium?.copyWith(color: v.open ? null : c.pending)),
            if (v.underwater) ...[
              const SizedBox(height: 8),
              Card(
                color: c.danger.withValues(alpha: 0.08),
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Text(
                    'Underwater: the price is at or below ${formatUsdPerYec(v.underwaterAtMicroUsd)}. A liquidator may claim this vault; redeem it when the lock allows.',
                    key: const Key('underwater'),
                    style: t.bodyMedium,
                  ),
                ),
              ),
            ],
            const SizedBox(height: 16),
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  children: [
                    PreviewRow('Status', v.status),
                    PreviewRow('Term', 'class ${v.termClass}'),
                    PreviewRow('Minted at', 'height ${v.mintHeight}'),
                    PreviewRow('Lock height', '${v.lockHeight}'),
                    PreviewRow('Claim height', '${v.claimHeight}'),
                    if (v.underwaterAtMicroUsd > 0) PreviewRow('Underwater at', formatUsdPerYec(v.underwaterAtMicroUsd)),
                    PreviewRow('Claimable (node)', v.claimable ? 'yes' : 'no'),
                    PreviewRow('Owner', shorten(v.ownerAddress, head: 14, tail: 8)),
                    PreviewRow('Vault', shorten(v.vaultTxid)),
                    if (v.closingTxid.isNotEmpty) PreviewRow('Closed by', shorten(v.closingTxid)),
                  ],
                ),
              ),
            ),
            if (_error != null) ...[
              const SizedBox(height: 12),
              Card(
                color: c.danger.withValues(alpha: 0.08),
                child: Padding(padding: const EdgeInsets.all(16), child: Text(_error!, key: const Key('error'), style: t.bodyMedium)),
              ),
            ],
            const SizedBox(height: 16),
            if (v.open) ...[
              if (v.redeemable && !enoughYed)
                Padding(
                  padding: const EdgeInsets.only(bottom: 8),
                  child: Text(
                    'Redeeming burns ${formatYed(v.cents)} of YED; this wallet holds ${formatYed(app.balances.yedCents)}.',
                    key: const Key('need-yed'),
                    style: t.bodySmall?.copyWith(color: c.danger),
                  ),
                ),
              if (_preview == null)
                FilledButton(
                  key: const Key('preview'),
                  onPressed: _busy || !(canAct && (v.releasable || enoughYed)) ? null : _previewNow,
                  style: FilledButton.styleFrom(backgroundColor: v.releasable ? c.yec : c.yed),
                  child: Text(_busy ? 'Preparing…' : (v.releasable ? 'Preview the release' : 'Preview the redeem')),
                ),
              if (_preview != null) ...[
                _RedeemPreviewCard(_preview!),
                const SizedBox(height: 12),
                SlideToConfirm(
                  label: v.releasable
                      ? 'Slide to release ${formatYec(_preview!.collateralZat)} YEC'
                      : 'Slide to redeem: burn ${formatYed(_preview!.burnCents)}, pay ${formatYec(_preview!.feeZat)} YEC fee',
                  color: v.releasable ? c.yec : c.yed,
                  enabled: canAct && (v.releasable || enoughYed),
                  onConfirmed: _confirm,
                ),
                TextButton(key: const Key('cancel'), onPressed: () => setState(() => _preview = null), child: const Text('Cancel')),
              ],
              if (!canAct)
                Padding(
                  padding: const EdgeInsets.only(top: 8),
                  child: Text('Redeem unlocks at height ${v.lockHeight}.', key: const Key('locked'), textAlign: TextAlign.center, style: t.bodySmall?.copyWith(color: c.pending)),
                ),
            ],
          ],
        ),
      ),
    );
  }
}

/// What the redeem will do, from the core's signed preview (audit G-2): the fee and the payee
/// are on screen before anything is sent.
class _RedeemPreviewCard extends StatelessWidget {
  const _RedeemPreviewCard(this.p);
  final RedeemPreview p;

  @override
  Widget build(BuildContext context) {
    final c = yewColors(context);
    final released = p.kind == 'release';
    return Card(
      key: const Key('redeem-preview'),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          children: [
            PreviewRow('Collateral back', '${formatYec(p.collateralZat)} YEC', emphasis: true, color: c.yec),
            if (!released) PreviewRow('You burn', formatYed(p.burnCents), emphasis: true, color: c.yed),
            if (p.extraBurnCents > 0) PreviewRow('Of which remainder', formatYed(p.extraBurnCents)),
            if (p.changeCents > 0) PreviewRow('YED change', formatYed(p.changeCents)),
            PreviewRow('Enforcement fee', p.feeZat > 0 ? '${formatYec(p.feeZat)} YEC' : 'none'),
            if (p.payee.isNotEmpty) PreviewRow('Fee paid to', shorten(p.payee, head: 10, tail: 6)),
            PreviewRow('To', shorten(p.collateralAddress, head: 14, tail: 8)),
            PreviewRow('Expires', 'height ${p.expiryHeight}'),
          ],
        ),
      ),
    );
  }
}

class _RedeemedView extends StatelessWidget {
  const _RedeemedView(this.r);
  final RedeemResult r;

  @override
  Widget build(BuildContext context) {
    final c = yewColors(context);
    final t = Theme.of(context).textTheme;
    final released = r.kind == 'release';
    return Scaffold(
      appBar: AppBar(title: Text(released ? 'Released' : 'Redeemed')),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.all(24),
          children: [
            TweenAnimationBuilder<double>(
              tween: Tween(begin: 0, end: 1),
              duration: confirmMotion,
              curve: Curves.easeOutBack,
              builder: (_, v, child) => Transform.scale(scale: v, child: child),
              child: Icon(Icons.lock_open_rounded, size: 96, color: c.yec),
            ),
            const SizedBox(height: 16),
            Text(released ? 'Collateral released' : 'Vault redeemed', textAlign: TextAlign.center, style: t.headlineMedium),
            const SizedBox(height: 8),
            SelectableText(r.txid, key: const Key('txid'), textAlign: TextAlign.center, style: t.bodySmall),
            if (r.verdict.isNotEmpty) Text('node verdict: ${r.verdict}', textAlign: TextAlign.center, style: t.bodySmall),
            const SizedBox(height: 16),
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  children: [
                    PreviewRow('Collateral back', '${formatYec(r.collateralZat)} YEC', emphasis: true, color: c.yec),
                    if (!released) PreviewRow('Burned', formatYed(r.burnCents), emphasis: true, color: c.yed),
                    if (r.extraBurnCents > 0) PreviewRow('Of which remainder', formatYed(r.extraBurnCents)),
                    if (r.changeCents > 0) PreviewRow('YED change', formatYed(r.changeCents)),
                    if (r.feeZat > 0) PreviewRow('Enforcement fee', '${formatYec(r.feeZat)} YEC'),
                    if (r.payee.isNotEmpty) PreviewRow('Fee paid to', shorten(r.payee, head: 10, tail: 6)),
                    PreviewRow('To', shorten(r.collateralAddress, head: 14, tail: 8)),
                    PreviewRow('Expires', 'height ${r.expiryHeight}'),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 24),
            FilledButton(key: const Key('done'), onPressed: () => Navigator.of(context).pop(), child: const Text('Done')),
          ],
        ),
      ),
    );
  }
}
