// Yellowback (plan §5.3): the YED you hold, the vaults you own (status, lock height, the
// underwater warning), the mints and claims in flight, "Mint" and "Claimable". Everything
// shown is a row the core's store holds; nothing is computed here beyond formatting.
import 'package:flutter/material.dart';

import '../api/wallet_api.dart';
import '../format.dart';
import '../state/app_scope.dart';
import '../theme.dart';
import '../widgets/balance_card.dart';
import 'claimable.dart';
import 'mint.dart';
import 'mint_progress.dart';
import 'vault.dart';

class YellowbackScreen extends StatelessWidget {
  const YellowbackScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final b = app.balances;
    final c = yewColors(context);
    final t = Theme.of(context).textTheme;
    final vaults = app.vaults;
    final moving = app.mintsInProgress;
    final locked = vaults.where((v) => v.open).fold<int>(0, (a, v) => a + v.collateralZat);
    return Scaffold(
      appBar: AppBar(title: const Text('Yellowback')),
      body: RefreshIndicator(
        onRefresh: app.sync,
        child: ListView(
          padding: const EdgeInsets.fromLTRB(16, 4, 16, 24),
          children: [
            BalanceCard(
              title: 'YED you hold',
              amount: formatYed(b.yedCents),
              unit: 'YED',
              accent: c.yed,
              subLines: [
                if (b.yedPendingCents > 0) '+ ${formatYed(b.yedPendingCents)} pending',
                if (locked > 0) '${formatYec(locked)} YEC locked as collateral in ${vaults.where((v) => v.open).length} vault${vaults.where((v) => v.open).length == 1 ? '' : 's'}',
                if (!app.yellowbackUsable && b.syncHeight > 0) 'This server offers no Yellowback service',
              ],
            ),
            const SizedBox(height: 16),
            Row(
              children: [
                Expanded(
                  child: FilledButton.icon(
                    key: const Key('mint'),
                    onPressed: () => Navigator.of(context).push(MaterialPageRoute<void>(builder: (_) => const MintScreen())),
                    icon: const Icon(Icons.add_circle_outline_rounded),
                    label: const Text('Mint'),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: OutlinedButton.icon(
                    key: const Key('claimable'),
                    onPressed: () => Navigator.of(context).push(MaterialPageRoute<void>(builder: (_) => const ClaimableScreen())),
                    icon: const Icon(Icons.gavel_rounded),
                    label: const Text('Claimable'),
                  ),
                ),
              ],
            ),
            if (moving.isNotEmpty) ...[
              const SizedBox(height: 24),
              Text('In progress', style: t.titleMedium),
              const SizedBox(height: 8),
              for (final m in moving) _MintTile(m),
            ],
            const SizedBox(height: 24),
            Text('Your vaults', style: t.titleMedium),
            const SizedBox(height: 8),
            if (vaults.isEmpty)
              Padding(
                padding: const EdgeInsets.symmetric(vertical: 16),
                child: Text(
                  b.syncHeight == 0 ? 'Not synced yet.' : 'No vaults. Mint YED against locked YEC to open one.',
                  key: const Key('no-vaults'),
                  style: t.bodyMedium?.copyWith(color: c.pending),
                ),
              ),
            for (final v in vaults) _VaultTile(v),
          ],
        ),
      ),
    );
  }
}

/// One line per state, the wording of plan §5.3.
String mintStateLabel(MintStatus m) {
  final what = m.kind == 'claim' ? 'claiming' : 'minting';
  switch (m.state) {
    case 'CARRIER_SENT':
      return 'funding carrier → waiting for 1 confirmation';
    case 'CARRIER_CONFIRMED':
      return m.windowOpen ? 'carrier confirmed → $what' : 'window closed';
    case 'MAIN_SENT':
      return '$what → waiting for 1 confirmation';
    case 'DONE':
      return 'done';
    case 'LAPSED':
      return 'window closed, sweeping carrier';
    case 'SWEEP_SENT':
      return 'sweeping carrier → waiting for 1 confirmation';
    case 'SWEPT':
      return 'carrier swept';
    case 'FAILED':
      return 'failed: the carrier never confirmed';
  }
  return m.state;
}

class _MintTile extends StatelessWidget {
  const _MintTile(this.m);
  final MintStatus m;

  @override
  Widget build(BuildContext context) {
    final c = yewColors(context);
    final lapsed = m.canSweep || m.state == 'SWEEP_SENT';
    return Card(
      child: ListTile(
        key: Key('mint-${m.mintId}'),
        leading: Icon(lapsed ? Icons.replay_rounded : Icons.hourglass_top_rounded, color: lapsed ? c.danger : c.yed),
        title: Text('${m.kind == 'claim' ? 'Claim' : 'Mint'} ${formatYed(m.cents)}'),
        subtitle: Text(mintStateLabel(m)),
        trailing: const Icon(Icons.chevron_right_rounded),
        onTap: () => Navigator.of(context).push(MaterialPageRoute<void>(builder: (_) => MintProgressScreen(mintId: m.mintId))),
      ),
    );
  }
}

class _VaultTile extends StatelessWidget {
  const _VaultTile(this.v);
  final VaultSummary v;

  @override
  Widget build(BuildContext context) {
    final c = yewColors(context);
    final t = Theme.of(context).textTheme;
    final String when;
    if (!v.open) {
      when = '${v.status.toLowerCase()} at ${v.closeHeight}';
    } else if (v.releasable) {
      when = 'void (${v.voidReason}) · release the collateral';
    } else if (v.redeemable) {
      when = 'redeemable now (lock height ${v.lockHeight})';
    } else {
      when = 'redeemable at ${v.lockHeight} · ${v.blocksUntilRedeem} block${v.blocksUntilRedeem == 1 ? '' : 's'} to go';
    }
    return Card(
      child: ListTile(
        key: Key('vault-${v.vaultTxid}'),
        leading: Icon(
          v.underwater ? Icons.warning_amber_rounded : (v.open ? Icons.lock_rounded : Icons.lock_open_rounded),
          color: v.underwater ? c.danger : (v.open ? c.yed : c.pending),
        ),
        title: Text('${formatYed(v.cents)} · ${formatYec(v.collateralZat)} YEC', style: t.titleMedium),
        subtitle: Text(
          v.underwater ? '$when\nUnderwater: the price is at or below ${formatUsdPerYec(v.underwaterAtMicroUsd)}. A liquidator may claim it.' : when,
          style: v.underwater ? t.bodyMedium?.copyWith(color: c.danger) : null,
        ),
        isThreeLine: v.underwater,
        trailing: const Icon(Icons.chevron_right_rounded),
        onTap: () => Navigator.of(context).push(MaterialPageRoute<void>(builder: (_) => VaultScreen(vaultTxid: v.vaultTxid))),
      ),
    );
  }
}
