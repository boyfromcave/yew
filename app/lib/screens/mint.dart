// Mint (plan §5.3): cents, the term-class picker, the estimate (required YEC, fees, heights),
// the two-step explained in one sentence, then the carrier step. The estimate is the core's;
// this screen never computes a collateral. After the start it hands over to MintProgressScreen,
// which renders the row the core persisted (a killed app reopens on the same row).
import 'package:flutter/material.dart';

import '../api/wallet_api.dart';
import '../format.dart';
import '../state/app_scope.dart';
import '../term_classes.dart';
import '../theme.dart';
import '../widgets/preview_card.dart';
import 'mint_progress.dart';
import 'receive.dart';

class MintScreen extends StatefulWidget {
  const MintScreen({super.key});

  @override
  State<MintScreen> createState() => _MintScreenState();
}

class _MintScreenState extends State<MintScreen> {
  final _amount = TextEditingController();
  late final TextEditingController _lock;
  late String _class;
  bool _busy = false;
  String? _error;
  bool _needYec = false;
  MintEstimate? _estimate;

  @override
  void initState() {
    super.initState();
    final terms = termClassesFor(AppScope.read(context).settings.network);
    _class = terms.first.letter;
    _lock = TextEditingController(text: '${terms.first.minBlocks}');
  }

  @override
  void dispose() {
    _amount.dispose();
    _lock.dispose();
    super.dispose();
  }

  void _reset() => setState(() {
    _estimate = null;
    _error = null;
    _needYec = false;
  });

  void _pickClass(TermClass t) => setState(() {
    _class = t.letter;
    _lock.text = '${t.minBlocks}';
    _estimate = null;
    _error = null;
  });

  Future<void> _estimateNow() async {
    final app = AppScope.read(context);
    final cents = parseYedCents(_amount.text);
    final lock = int.tryParse(_lock.text.trim());
    if (cents == null || cents <= 0) {
      setState(() => _error = 'Enter an amount in dollars, like 25.00');
      return;
    }
    if (lock == null || termClassOf(app.settings.network, lock) == null) {
      setState(() => _error = 'The lock must be inside one term class');
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
      _needYec = false;
    });
    try {
      final e = await app.api.mintEstimate(cents: cents, lockBlocks: lock);
      setState(() => _estimate = e);
    } catch (e) {
      setState(() {
        _error = messageOf(e);
        _needYec = kindOf(e) == ErrorKind.needYecForFees;
      });
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _start() async {
    final app = AppScope.read(context);
    final e = _estimate!;
    setState(() => _busy = true);
    try {
      final row = await app.api.mintStart(cents: e.cents, lockBlocks: e.lockBlocks);
      await app.refresh();
      if (!mounted) return;
      Navigator.of(context).pushReplacement(MaterialPageRoute<void>(builder: (_) => MintProgressScreen(mintId: row.mintId)));
    } catch (err) {
      setState(() {
        _error = messageOf(err);
        _needYec = kindOf(err) == ErrorKind.needYecForFees;
        _estimate = null;
      });
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final c = yewColors(context);
    final t = Theme.of(context).textTheme;
    final terms = termClassesFor(app.settings.network);
    final e = _estimate;
    return Scaffold(
      appBar: AppBar(title: const Text('Mint YED')),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.fromLTRB(20, 8, 20, 32),
          children: [
            Text(
              'Minting locks YEC in a vault and creates YED against it, in two transactions: a small carrier first, then the mint once the carrier has one confirmation.',
              key: const Key('two-step'),
              style: t.bodyMedium?.copyWith(color: c.pending),
            ),
            const SizedBox(height: 12),
            Text(
              '${formatYec(app.balances.yecZat + app.balances.yecReservedZat)} YEC available for collateral and fees',
              key: const Key('available'),
              style: t.bodyMedium?.copyWith(color: c.pending),
            ),
            const SizedBox(height: 12),
            TextField(
              key: const Key('amount'),
              controller: _amount,
              enabled: e == null,
              keyboardType: const TextInputType.numberWithOptions(decimal: true),
              onChanged: (_) => _reset(),
              style: t.headlineMedium,
              decoration: const InputDecoration(labelText: 'Amount to mint', prefixText: '\$ ', suffixText: 'YED'),
            ),
            const SizedBox(height: 16),
            Text('Term', style: t.titleSmall),
            const SizedBox(height: 8),
            SegmentedButton<String>(
              key: const Key('term-class'),
              segments: [for (final x in terms) ButtonSegment(value: x.letter, label: Text('${x.letter} · ${x.title}'))],
              selected: {_class},
              onSelectionChanged: e != null ? null : (s) => _pickClass(terms.firstWhere((x) => x.letter == s.first)),
            ),
            const SizedBox(height: 8),
            TextField(
              key: const Key('lock-blocks'),
              controller: _lock,
              enabled: e == null,
              keyboardType: TextInputType.number,
              onChanged: (v) {
                final tc = termClassOf(app.settings.network, int.tryParse(v.trim()) ?? -1);
                setState(() {
                  if (tc != null) _class = tc.letter;
                  _estimate = null;
                });
              },
              decoration: const InputDecoration(labelText: 'Lock, in blocks', helperText: 'Redeem at any time after the lock; a liquidator may claim once the grace period after it has passed'),
            ),
            const SizedBox(height: 16),
            if (e == null)
              FilledButton(
                key: const Key('estimate'),
                onPressed: _busy ? null : _estimateNow,
                style: FilledButton.styleFrom(backgroundColor: c.yed),
                child: Text(_busy ? 'Asking the node…' : 'Estimate'),
              ),
            if (_error != null) ...[
              const SizedBox(height: 12),
              Card(
                color: c.danger.withValues(alpha: 0.08),
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(_error!, key: const Key('error'), style: t.bodyMedium),
                      if (_needYec) ...[
                        const SizedBox(height: 8),
                        OutlinedButton.icon(
                          key: const Key('show-receive'),
                          onPressed: () => Navigator.of(context).push(MaterialPageRoute<void>(builder: (_) => const ReceiveScreen())),
                          icon: const Icon(Icons.qr_code_2_rounded),
                          label: const Text('Show my receive address'),
                        ),
                      ],
                    ],
                  ),
                ),
              ),
            ],
            if (e != null) ...[
              MintEstimateCard(e),
              const SizedBox(height: 16),
              FilledButton(
                key: const Key('start'),
                onPressed: _busy || !e.affordable ? null : _start,
                style: FilledButton.styleFrom(backgroundColor: c.yed),
                child: Text(_busy ? 'Funding the carrier…' : 'Start: fund the carrier'),
              ),
              if (!e.affordable)
                Padding(
                  padding: const EdgeInsets.only(top: 8),
                  child: Text(
                    'Not enough YEC: this mint needs ${formatYec(e.totalZat)} YEC and the wallet has ${formatYec(e.availableZat)}.',
                    key: const Key('unaffordable'),
                    style: t.bodySmall?.copyWith(color: c.danger),
                  ),
                ),
              const SizedBox(height: 8),
              TextButton(key: const Key('cancel'), onPressed: _reset, child: const Text('Change the amount')),
            ],
          ],
        ),
      ),
    );
  }
}

class MintEstimateCard extends StatelessWidget {
  const MintEstimateCard(this.e, {super.key});
  final MintEstimate e;

  @override
  Widget build(BuildContext context) {
    final c = yewColors(context);
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          children: [
            PreviewRow('You mint', formatYed(e.cents), emphasis: true, color: c.yed),
            PreviewRow('Collateral locked', '${formatYec(e.collateralZat)} YEC', emphasis: true, color: c.yec),
            PreviewRow('Term', 'class ${e.termClass} · ${e.lockBlocks} blocks'),
            PreviewRow('Redeemable from', 'height ${e.lockHeight}'),
            PreviewRow('Claimable from', 'height ${e.claimHeight}'),
            if (e.feeZat > 0) PreviewRow('Enforcement fee', '${formatYec(e.feeZat)} YEC'),
            if (e.attestFeeZat > 0) PreviewRow('Attestor fee', '${formatYec(e.attestFeeZat)} YEC'),
            PreviewRow('Carrier + token', '${formatYec(e.carrierZat + e.tokenZat)} YEC'),
            PreviewRow('Network fees', '${formatYec(e.networkFeeZat)} YEC (two transactions)'),
            PreviewRow('Total YEC needed', '${formatYec(e.totalZat)} YEC', emphasis: true),
            const Divider(height: 20),
            PreviewRow('Price at R', e.pMintMicroUsd == null ? 'unavailable' : formatUsdPerYec(e.pMintMicroUsd!)),
            PreviewRow('Reference height', '${e.refHeight} · window closes at ${e.expiryHeight}'),
            PreviewRow('Attestors', e.bundleSeqs.isEmpty ? 'none' : e.bundleSeqs.join(', ')),
            if (!e.armed) const PreviewRow('', 'The price feed is not armed at R: the node will refuse the mint', color: Colors.red),
          ],
        ),
      ),
    );
  }
}
