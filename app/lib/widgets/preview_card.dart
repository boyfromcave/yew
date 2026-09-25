// What a screen renders before a signature is used (plan §3.4: "the preview objects are the
// only thing a screen renders before…"): fee in YEC, change, and for YED the node's dry-run
// verdict, verbatim.
import 'package:flutter/material.dart';

import '../api/wallet_api.dart';
import '../format.dart';
import '../theme.dart';

class PreviewRow extends StatelessWidget {
  const PreviewRow(this.label, this.value, {super.key, this.emphasis = false, this.color});
  final String label;
  final String value;
  final bool emphasis;
  final Color? color;

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(label, style: t.bodyMedium?.copyWith(color: t.bodySmall?.color)),
          const SizedBox(width: 16),
          Expanded(
            child: Text(
              value,
              textAlign: TextAlign.right,
              style: (emphasis ? t.titleMedium : t.bodyMedium)?.copyWith(color: color),
            ),
          ),
        ],
      ),
    );
  }
}

class YecPreviewCard extends StatelessWidget {
  const YecPreviewCard(this.p, {super.key});
  final YecPreview p;

  @override
  Widget build(BuildContext context) {
    final c = yewColors(context);
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          children: [
            PreviewRow('To', shorten(p.to, head: 14, tail: 8)),
            PreviewRow('Amount', '${formatYec(p.amountZat)} YEC', emphasis: true, color: c.yec),
            if (p.amountBumped) const PreviewRow('', 'Raised by 1 zat: exactly 0.0001 YEC would look like a YED token'),
            PreviewRow('Fee', '${formatYec(p.feeZat)} YEC'),
            if (p.changeZat > 0) PreviewRow('Change', '${formatYec(p.changeZat)} YEC'),
            PreviewRow('Inputs', '${p.inputs}'),
            PreviewRow(
              p.usesReserve ? 'Fee reserve' : 'Keeps reserved',
              p.usesReserve ? 'spent (sending everything)' : '${formatYec(p.keepsReservedZat)} YEC for YED fees',
            ),
            PreviewRow('Expires', 'height ${p.expiryHeight}'),
          ],
        ),
      ),
    );
  }
}

class YedPreviewCard extends StatelessWidget {
  const YedPreviewCard(this.p, {super.key});
  final YedPreview p;

  @override
  Widget build(BuildContext context) {
    final c = yewColors(context);
    final d = p.dryRun;
    final ok = d.accepted;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          children: [
            for (final r in p.recipients)
              PreviewRow(shorten(r.address, head: 14, tail: 8), formatYed(r.cents), emphasis: true, color: c.yed),
            if (p.recipients.length > 1) PreviewRow('Total', formatYed(p.totalCents), emphasis: true),
            PreviewRow('YED inputs', '${p.yedInputs} (${p.stage})'),
            if (p.changeCents > 0) PreviewRow('YED change', formatYed(p.changeCents)),
            PreviewRow('Fee', '${formatYec(p.feeZat)} YEC (${p.yecInputs} YEC input${p.yecInputs == 1 ? '' : 's'})'),
            if (p.yecChangeZat > 0) PreviewRow('YEC change', '${formatYec(p.yecChangeZat)} YEC'),
            PreviewRow('Expires', 'height ${p.expiryHeight}'),
            const Divider(height: 20),
            PreviewRow(
              'Node dry run',
              ok ? 'verdict ${d.verdict}' : 'verdict ${d.verdict} · valid ${d.valid} · burned ${formatYed(d.burnedCents)} · wouldBeRejected ${d.wouldBeRejected}',
              emphasis: true,
              color: ok ? c.yec : c.danger,
            ),
            if (p.yedInputs > 20) const PreviewRow('', 'Many inputs: the fee covers a larger transaction'),
          ],
        ),
      ),
    );
  }
}
