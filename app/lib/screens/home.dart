// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

// Home (plan §1.1, §5.1): YED balance (large; "+ pending" when any), one YEC total split into
// Private (shielded) and Public (transparent, with the "reserved for fees" sub-line;
// yew-shielded plan §3), the price line, a sync indicator, Receive / Send.
import 'package:flutter/material.dart';

import '../format.dart';
import '../state/app_scope.dart';
import '../state/app_state.dart';
import '../theme.dart';
import '../widgets/balance_card.dart';
import 'receive.dart';
import 'send.dart';
import 'settings.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      final app = AppScope.read(context);
      if (app.unlocked && !app.syncing) app.sync();
    });
  }

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final b = app.balances;
    final c = yewColors(context);
    final t = Theme.of(context).textTheme;
    return Scaffold(
      appBar: AppBar(
        title: Text('YEW', style: t.titleLarge?.copyWith(color: c.yed, fontWeight: FontWeight.w700)),
        actions: [
          IconButton(
            key: const Key('sync'),
            tooltip: app.syncing ? app.syncMessage : 'Sync now',
            onPressed: app.syncing ? null : app.sync,
            icon: app.syncing
                ? const SizedBox(width: 20, height: 20, child: CircularProgressIndicator(strokeWidth: 2))
                : const Icon(Icons.sync_rounded),
          ),
          IconButton(
            key: const Key('settings'),
            tooltip: 'Settings',
            onPressed: () => Navigator.of(context).push(MaterialPageRoute<void>(builder: (_) => const SettingsScreen())),
            icon: const Icon(Icons.settings_outlined),
          ),
        ],
      ),
      body: RefreshIndicator(
        onRefresh: app.sync,
        child: ListView(
          padding: const EdgeInsets.fromLTRB(16, 4, 16, 24),
          children: [
            BalanceCard(
              title: 'Yellowback',
              amount: formatYed(b.yedCents),
              unit: 'YED',
              accent: c.yed,
              subLines: [
                if (b.yedPendingCents > 0) '+ ${formatYed(b.yedPendingCents)} pending',
                if (!app.yellowbackUsable && app.balances.syncHeight > 0) 'YED hidden: this server offers no Yellowback service',
              ],
            ),
            const SizedBox(height: 12),
            BalanceCard(
              key: const Key('yec-card'),
              title: 'Ycash',
              amount: formatYec(app.totalYecZat),
              unit: 'YEC',
              accent: c.yec,
              child: _YecSplit(app: app),
            ),
            const SizedBox(height: 12),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 4),
              child: Row(
                children: [
                  Expanded(child: Text(formatPriceLine(b.priceMicroUsd), key: const Key('price'), style: t.bodyMedium)),
                  Text(
                    app.syncing ? '${app.syncMessage} · ${app.syncPercent}%' : (b.syncHeight > 0 ? 'synced to ${b.syncHeight}' : 'not synced'),
                    key: const Key('sync-state'),
                    style: t.bodySmall?.copyWith(color: c.pending),
                  ),
                ],
              ),
            ),
            if (app.lastError != null)
              Padding(
                padding: const EdgeInsets.only(top: 12),
                child: Card(
                  color: c.danger.withValues(alpha: 0.08),
                  child: ListTile(
                    title: Text(app.lastError!, key: const Key('error')),
                    trailing: IconButton(icon: const Icon(Icons.close), onPressed: app.clearError),
                  ),
                ),
              ),
            const SizedBox(height: 24),
            Row(
              children: [
                Expanded(
                  child: OutlinedButton.icon(
                    key: const Key('receive'),
                    onPressed: () => Navigator.of(context).push(MaterialPageRoute<void>(builder: (_) => const ReceiveScreen())),
                    icon: const Icon(Icons.qr_code_2_rounded),
                    label: const Text('Receive'),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: FilledButton.icon(
                    key: const Key('send'),
                    onPressed: () => Navigator.of(context).push(MaterialPageRoute<void>(builder: (_) => const SendScreen())),
                    icon: const Icon(Icons.arrow_outward_rounded),
                    label: const Text('Send'),
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}

/// The two lines under the YEC total: Private (shielded) and Public (transparent). Plain words
/// for a non-expert; YED and fees always use the public part (yew-shielded plan §4).
class _YecSplit extends StatelessWidget {
  const _YecSplit({required this.app});
  final AppState app;

  @override
  Widget build(BuildContext context) {
    final b = app.balances;
    final c = yewColors(context);
    final t = Theme.of(context).textTheme;
    final small = t.bodySmall?.copyWith(color: c.pending);
    Widget line(Key key, IconData icon, String label, int zat) => Padding(
      padding: const EdgeInsets.only(top: 4),
      child: Row(
        children: [
          Icon(icon, size: 16, color: c.yec),
          const SizedBox(width: 6),
          Text(label, style: t.bodyMedium),
          const Spacer(),
          Text('${formatYec(zat)} YEC', key: key, style: t.bodyMedium),
        ],
      ),
    );
    Widget note(String s, [Key? key]) => Padding(
      padding: const EdgeInsets.only(left: 22, top: 2),
      child: Text(s, key: key, style: small),
    );
    final String? privateNote = b.shieldedSendable
        ? null
        : app.syncing
        ? 'Syncing private balance… sending available at 100%'
        : (app.shieldedNote.isNotEmpty ? app.shieldedNote : 'Private balance not up to date: sync to send from it');
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        line(const Key('yec-private'), Icons.lock_rounded, 'Private', b.yecShieldedZat),
        if (privateNote != null) note(privateNote, const Key('private-note')),
        if (b.yecShieldedPendingZat > 0) note('${formatYec(b.yecShieldedPendingZat)} YEC pending'),
        line(const Key('yec-public'), Icons.public_rounded, 'Public', app.publicYecZat),
        note('${formatYec(b.yecReservedZat)} YEC reserved for fees'),
        if (b.yecPendingZat > 0) note('${formatYec(b.yecPendingZat)} YEC pending'),
        if (b.heldCount > 0) note('${b.heldCount} output${b.heldCount == 1 ? '' : 's'} held until the server classifies ${b.heldCount == 1 ? 'it' : 'them'}'),
      ],
    );
  }
}
