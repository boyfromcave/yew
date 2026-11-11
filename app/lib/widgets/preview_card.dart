// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

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
  const YecPreviewCard(this.p, {super.key, this.toLabel, this.revealText});
  final YecPreview p;

  /// Shown instead of the address (a move to the wallet's own balance).
  final String? toLabel;

  /// The amber line's text when not a payment (a move to public).
  final String? revealText;

  /// The amber of the reveal line: the YED accent, which reads as a caution, not an error.
  static const Color amber = yedAccent;

  @override
  Widget build(BuildContext context) {
    final c = yewColors(context);
    final t = Theme.of(context).textTheme;
    final private = p.funding == YecFunding.shielded;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          children: [
            PreviewRow('To', toLabel ?? shorten(p.to, head: 14, tail: 8)),
            PreviewRow('Amount', '${formatYec(p.amountZat)} YEC', emphasis: true, color: c.yec),
            if (p.amountBumped)
              PreviewRow('', toLabel == null ? 'Raised by 1 zat: exactly 0.0001 YEC would look like a YED token' : 'Raised to include change too small to keep public'),
            PreviewRow('From', private ? 'your private balance' : 'your public balance'),
            if (p.memo != null && p.memo!.isNotEmpty) PreviewRow('Message', p.memo!),
            PreviewRow('Fee', '${formatYec(p.feeZat)} YEC'),
            if (p.changeZat > 0) PreviewRow('Change', '${formatYec(p.changeZat)} YEC'),
            if (!private) ...[
              PreviewRow('Inputs', '${p.inputs}'),
              PreviewRow(
                p.usesReserve ? 'Fee reserve' : 'Keeps reserved',
                p.usesReserve ? 'spent (sending everything)' : '${formatYec(p.keepsReservedZat)} YEC for YED fees',
              ),
            ],
            PreviewRow('Expires', 'height ${p.expiryHeight}'),
            if (p.revealsShielded)
              Padding(
                padding: const EdgeInsets.only(top: 8),
                child: Row(
                  key: const Key('reveals'),
                  children: [
                    const Icon(Icons.lock_open_rounded, size: 18, color: amber),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        revealText ?? 'This payment leaves your private balance',
                        style: t.bodyMedium?.copyWith(color: amber, fontWeight: FontWeight.w600),
                      ),
                    ),
                  ],
                ),
              ),
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
            // rpcversion 8: a YED transfer's network fee is dollars per KB at the attested price
            PreviewRow('Fee', '${formatYec(p.feeZat)} YEC${p.feeUsdCents > 0 ? ' (about ${formatYed(p.feeUsdCents)})' : ''} (${p.yecInputs} YEC input${p.yecInputs == 1 ? '' : 's'})', key: const Key('yed-fee')),
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

/// The preview of a send from an own post-quantum address (beta2 D-8): the fee is priced on the
/// transaction's size, and a post-quantum signature is large (SLH-DSA ~7.9 KB, FN-DSA-512 ~1.6 KB
/// per input), so the card shows the size and the signing time next to the fee, before the
/// slider. The change goes back to the source address.
class PqSendPreviewCard extends StatelessWidget {
  const PqSendPreviewCard(this.p, {super.key});
  final PqSendPreviewInfo p;

  @override
  Widget build(BuildContext context) {
    final c = yewColors(context);
    final t = Theme.of(context).textTheme;
    final slh = p.schemeName.startsWith('SLH');
    // no clock in the browser: the core reports no time rather than 0 (review YEW-REVIEW-3 L5)
    final ms = p.signMillis;
    final signing = ms == null
        ? 'not measured on this device'
        : '${(ms.toInt() / 1000).toStringAsFixed(ms.toInt() < 1000 ? 2 : 1)} s on this device';
    return Card(
      key: const Key('pq-preview'),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          children: [
            PreviewRow('To', shorten(p.to, head: 14, tail: 8)),
            PreviewRow('Amount', '${formatYec(p.amountZat)} YEC', emphasis: true, color: c.yec),
            if (p.amountBumped) const PreviewRow('', 'Raised by 1 zat: exactly 0.0001 YEC would look like a YED token'),
            PreviewRow('From', p.fromPrivate ? 'your private balance' : 'post-quantum ${p.schemeName} · ${shorten(p.from, head: 6, tail: 4)}'),
            PreviewRow('Fee', '${formatYec(p.feeZat)} YEC', key: const Key('pq-fee'), color: p.feeNote != null ? c.danger : null, emphasis: p.feeNote != null),
            // review YEW-REVIEW-3 M1: a fee above the unusual threshold rests on the server's price
            if (p.feeNote != null)
              Padding(
                padding: const EdgeInsets.only(bottom: 8),
                child: Text(p.feeNote!, key: const Key('pq-fee-note'), style: t.bodySmall?.copyWith(color: c.danger)),
              ),
            PreviewRow('Size', '${p.sizeBytes} bytes · ${p.inputs} ${p.fromPrivate ? 'note' : 'input'}${p.inputs == 1 ? '' : 's'}'),
            PreviewRow(p.fromPrivate ? 'Proving' : 'Signing', signing, key: const Key('pq-signing')),
            if (p.changeZat > 0) PreviewRow('Change', p.fromPrivate ? '${formatYec(p.changeZat)} YEC back to your private balance' : '${formatYec(p.changeZat)} YEC back to the same address'),
            PreviewRow('Expires', 'height ${p.expiryHeight}'),
            // beta2 D-5: the private -> public notice, in the words of the private -> public send
            if (p.fromPrivate)
              Padding(
                padding: const EdgeInsets.only(top: 8),
                child: Row(
                  key: const Key('reveals'),
                  children: [
                    const Icon(Icons.lock_open_rounded, size: 18, color: YecPreviewCard.amber),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        'This payment leaves your private balance',
                        style: t.bodyMedium?.copyWith(color: YecPreviewCard.amber, fontWeight: FontWeight.w600),
                      ),
                    ),
                  ],
                ),
              ),
            if (!p.fromPrivate)
            Padding(
              padding: const EdgeInsets.only(top: 8),
              child: Text(
                slh
                    ? 'An SLH-DSA signature is about 7.9 KB per input, so this send is large: its fee is higher than a public send\'s and signing takes longer.'
                    : 'An FN-DSA-512 signature is about 1.6 KB per input: the fee is priced on that size.',
                key: const Key('pq-size-note'),
                style: t.bodySmall?.copyWith(color: c.pending),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
