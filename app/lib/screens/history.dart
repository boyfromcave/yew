// History (plan §5.1): one list, both assets, verdict labels; tap for details.
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../api/wallet_api.dart';
import '../format.dart';
import '../state/app_scope.dart';
import '../theme.dart';

class HistoryScreen extends StatelessWidget {
  const HistoryScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final rows = app.history;
    final t = Theme.of(context).textTheme;
    return Scaffold(
      appBar: AppBar(title: const Text('History')),
      body: rows.isEmpty
          ? Center(
              child: Padding(
                padding: const EdgeInsets.all(32),
                child: Text(
                  app.balances.syncHeight == 0 ? 'Not synced yet.' : 'Nothing yet. Receive YED or YEC to see it here.',
                  textAlign: TextAlign.center,
                  style: t.bodyLarge,
                ),
              ),
            )
          : RefreshIndicator(
              onRefresh: app.sync,
              child: ListView.separated(
                padding: const EdgeInsets.symmetric(vertical: 8),
                itemCount: rows.length,
                separatorBuilder: (_, _) => const Divider(height: 1, indent: 72),
                itemBuilder: (context, i) => _Row(rows[i]),
              ),
            ),
    );
  }
}

class _Row extends StatelessWidget {
  const _Row(this.h);
  final HistoryItem h;

  @override
  Widget build(BuildContext context) {
    final c = yewColors(context);
    final t = Theme.of(context).textTheme;
    final yed = h.yedDeltaCents != 0 || h.kind.isNotEmpty;
    final accent = yed ? c.yed : c.yec;
    final incoming = yed ? h.yedDeltaCents > 0 : h.yecDeltaZat > 0;
    return ListTile(
      key: Key('tx-${h.txid}'),
      leading: CircleAvatar(
        backgroundColor: accent.withValues(alpha: 0.15),
        child: Icon(
          h.pending ? Icons.schedule_rounded : (incoming ? Icons.south_west_rounded : Icons.north_east_rounded),
          color: h.pending ? c.pending : accent,
        ),
      ),
      title: Text(h.label.isEmpty ? (incoming ? 'received' : 'sent') : h.label),
      subtitle: Text(
        h.pending ? 'pending' : 'height ${h.height}${h.verdict.isNotEmpty ? ' · ${h.verdict}' : ''}',
        style: t.bodySmall,
      ),
      trailing: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        crossAxisAlignment: CrossAxisAlignment.end,
        children: [
          if (h.yedDeltaCents != 0) Text(formatYedDelta(h.yedDeltaCents), style: t.titleMedium?.copyWith(color: c.yed)),
          if (h.yecDeltaZat != 0)
            Text('${formatYecDelta(h.yecDeltaZat)} YEC', style: (h.yedDeltaCents != 0 ? t.bodySmall : t.titleMedium)?.copyWith(color: c.yec)),
        ],
      ),
      onTap: () => showModalBottomSheet<void>(context: context, builder: (_) => _Details(h)),
    );
  }
}

class _Details extends StatelessWidget {
  const _Details(this.h);
  final HistoryItem h;

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    Widget row(String k, String v) => Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(width: 110, child: Text(k, style: t.bodySmall)),
          Expanded(child: SelectableText(v, style: t.bodyMedium)),
        ],
      ),
    );
    return Padding(
      padding: const EdgeInsets.fromLTRB(24, 16, 24, 32),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(h.label.isEmpty ? 'Transaction' : h.label, style: t.titleLarge),
          const SizedBox(height: 12),
          row('txid', h.txid),
          row('status', h.pending ? 'pending (unconfirmed)' : 'confirmed at height ${h.height}'),
          if (h.yedDeltaCents != 0) row('YED', formatYedDelta(h.yedDeltaCents)),
          if (h.yecDeltaZat != 0) row('YEC', formatYecDelta(h.yecDeltaZat)),
          if (h.kind.isNotEmpty) row('kind', h.kind),
          if (h.verdict.isNotEmpty) row('verdict', h.verdict),
          if (h.hasPayload) row('payload', h.kind.isEmpty ? 'OP_RETURN present (not a Yellowback verdict)' : 'Yellowback'),
          if (h.shielded) row('note', 'this transaction also has shielded parts YEW cannot read'),
          const SizedBox(height: 12),
          OutlinedButton.icon(
            onPressed: () async {
              await Clipboard.setData(ClipboardData(text: h.txid));
              if (context.mounted) Navigator.of(context).pop();
            },
            icon: const Icon(Icons.copy_rounded),
            label: const Text('Copy txid'),
          ),
        ],
      ),
    );
  }
}
