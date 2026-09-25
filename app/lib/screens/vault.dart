// Vault (plan §5.3): the details of one own vault; Redeem once `lockHeight` is reached
// (burning the debt from the wallet's YED); Release when the node reports it VOID. Both are
// the core's `redeem`, which builds, dry-runs, gates and broadcasts; the slider only asks.
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
  RedeemResult? _result;

  Future<void> _redeem() async {
    final app = AppScope.read(context);
    try {
      final r = await app.api.redeem(vaultTxid: widget.vaultTxid);
      setState(() => _result = r);
      await app.refresh();
    } catch (e) {
      setState(() => _error = messageOf(e));
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
              SlideToConfirm(
                label: v.releasable ? 'Slide to release ${formatYec(v.collateralZat)} YEC' : 'Slide to redeem: burn ${formatYed(v.cents)}',
                color: v.releasable ? c.yec : c.yed,
                enabled: canAct && (v.releasable || enoughYed),
                onConfirmed: _redeem,
              ),
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
