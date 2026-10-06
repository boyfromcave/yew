// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

// Claims and their release (the vault upgrade, upgrade plan U-15, U-23, U-24): a claim moves
// the vault's collateral into a claim intent; after the claim delay the wallet releases it to
// itself (the release needs no signature on the intent, so the wallet just does it first). Until
// then one attestor may cancel a wrong-price claim: the collateral goes back into the vault and
// the claim's burn is not refunded. An own vault's RED-5 residual is an intent of the same kind.
import 'package:flutter/material.dart';

import '../api/wallet_api.dart';
import '../format.dart';
import '../state/app_scope.dart';
import '../theme.dart';
import '../widgets/preview_card.dart';
import '../widgets/slide_to_confirm.dart';

/// One line per intent state.
String intentLabel(ClaimIntent i) {
  final what = i.role == 'residual' ? 'residual of your claimed vault' : 'claim';
  switch (i.state) {
    case 'PENDING':
      if (i.height == 0) return '$what · waiting for the claim to confirm';
      if (i.releasable) return '$what · releasable now';
      return '$what · released from height ${i.releaseHeight} · ${i.blocksUntilRelease} block${i.blocksUntilRelease == 1 ? '' : 's'} to go (${formatDate(i.releaseTimeSecs)})';
    case 'RELEASING':
      return '$what · release sent → waiting for 1 confirmation';
    case 'RELEASED':
      return '$what · released';
    case 'CANCELLED':
      return 'claim cancelled by the attestor set: the collateral went back into the vault; the YED you burned is not refunded';
  }
  return i.state;
}

/// The Yellowback screen's tile for one intent; a releasable one opens [ReleaseScreen].
class IntentTile extends StatelessWidget {
  const IntentTile(this.i, {super.key});
  final ClaimIntent i;

  @override
  Widget build(BuildContext context) {
    final c = yewColors(context);
    final t = Theme.of(context).textTheme;
    final cancelled = i.cancelled;
    return Card(
      color: cancelled ? c.danger.withValues(alpha: 0.08) : null,
      child: ListTile(
        key: Key('intent-${i.intent}'),
        leading: Icon(
          cancelled
              ? Icons.block_rounded
              : (i.releasable ? Icons.lock_open_rounded : (i.state == 'RELEASED' ? Icons.check_circle_outline_rounded : Icons.hourglass_top_rounded)),
          color: cancelled ? c.danger : (i.releasable ? c.yec : c.pending),
        ),
        title: Text('${formatYec(i.valueZat)} YEC', style: t.titleMedium),
        subtitle: Text(intentLabel(i), style: cancelled ? t.bodyMedium?.copyWith(color: c.danger) : null),
        trailing: i.releasable ? const Icon(Icons.chevron_right_rounded) : null,
        onTap: i.releasable ? () => Navigator.of(context).push(MaterialPageRoute<void>(builder: (_) => ReleaseScreen(intent: i))) : null,
      ),
    );
  }
}

class ReleaseScreen extends StatefulWidget {
  const ReleaseScreen({super.key, required this.intent});
  final ClaimIntent intent;

  @override
  State<ReleaseScreen> createState() => _ReleaseScreenState();
}

class _ReleaseScreenState extends State<ReleaseScreen> {
  ReleasePreview? _preview;
  ReleaseResult? _result;
  String? _error;
  bool _busy = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _build());
  }

  Future<void> _build() async {
    final app = AppScope.read(context);
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final p = await app.api.releasePreview(intent: widget.intent.intent);
      setState(() => _preview = p);
    } catch (e) {
      setState(() => _error = messageOf(e));
    } finally {
      setState(() => _busy = false);
    }
  }

  Future<void> _confirm() async {
    final app = AppScope.read(context);
    try {
      final r = await app.api.releaseConfirm(previewId: _preview!.previewId);
      await app.refresh();
      setState(() => _result = r);
    } catch (e) {
      setState(() {
        _error = messageOf(e);
        _preview = null;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final c = yewColors(context);
    final t = Theme.of(context).textTheme;
    final p = _preview;
    final r = _result;
    return Scaffold(
      appBar: AppBar(title: const Text('Release')),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.fromLTRB(16, 8, 16, 32),
          children: [
            Text(
              widget.intent.role == 'residual'
                  ? 'Your vault was claimed. The part of its collateral above the claim (the residual) waited out the claim delay and is yours to release.'
                  : 'The claim delay is over and no attestor cancelled the claim: release the collateral to this wallet.',
              style: t.bodyMedium?.copyWith(color: c.pending),
            ),
            const SizedBox(height: 12),
            if (_error != null)
              Card(
                color: c.danger.withValues(alpha: 0.08),
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Text(_error!, key: const Key('error'), style: t.bodyMedium),
                ),
              ),
            if (_busy)
              const Padding(
                padding: EdgeInsets.all(32),
                child: Center(child: CircularProgressIndicator()),
              ),
            if (r != null)
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Column(
                    children: [
                      PreviewRow('Released', '${formatYec(r.valueZat)} YEC', emphasis: true, color: c.yec),
                      PreviewRow('Transaction', shorten(r.txid)),
                      PreviewRow('Node verdict', r.verdict),
                    ],
                  ),
                ),
              )
            else if (p != null) ...[
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Column(
                    children: [
                      PreviewRow('You receive', '${formatYec(p.valueZat)} YEC', emphasis: true, color: c.yec),
                      PreviewRow('To', shorten(p.recipientAddress, head: 10, tail: 6)),
                      PreviewRow('Network fee', '${formatYec(p.feeZat)} YEC (from your YEC)'),
                      PreviewRow('Intent', shorten(p.intent)),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 12),
              SlideToConfirm(label: 'Slide to release', color: c.yec, onConfirmed: _confirm),
            ],
          ],
        ),
      ),
    );
  }
}
