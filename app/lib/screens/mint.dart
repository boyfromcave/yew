// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

// Mint (plan §5.3): cents, the term-class picker, the estimate (required YEC, fees, heights),
// the two-step explained in one sentence, then the carrier step. The estimate is the core's;
// this screen never computes a collateral. After the start it hands over to MintProgressScreen,
// which renders the row the core persisted (a killed app reopens on the same row).
//
// The screen first asks the core whether a mint can be made at all (hardening H-1, H-5): with
// `mintRequiresArmed` and the price not armed, or with no term class mintable, the form is
// replaced by the reason. Only the classes the node lists as mintable can be picked (class A
// alone at launch). Opened from a vault's Renew (H-9.2), it starts with that vault's amount and
// term.
import 'package:flutter/material.dart';

import '../api/wallet_api.dart';
import '../format.dart';
import '../state/app_scope.dart';
import '../term_classes.dart';
import '../theme.dart';
import '../widgets/move_public_hint.dart';
import '../widgets/preview_card.dart';
import 'mint_progress.dart';
import 'receive.dart';

class MintScreen extends StatefulWidget {
  const MintScreen({super.key, this.initialCents, this.initialLockBlocks, this.renewing});

  /// The amount to start with (a renew re-mints the redeemed vault's debt).
  final int? initialCents;

  /// The lock to start with (a renew keeps the vault's term).
  final int? initialLockBlocks;

  /// The txid of the vault being renewed, when this mint is the second half of a renew.
  final String? renewing;

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
  MintAvailability? _avail;
  String? _availError;
  bool _checking = true;

  @override
  void initState() {
    super.initState();
    final network = AppScope.read(context).settings.network;
    final terms = termClassesFor(network);
    final initial = widget.initialLockBlocks == null ? null : termClassOf(network, widget.initialLockBlocks!);
    _class = (initial ?? terms.first).letter;
    _lock = TextEditingController(text: '${initial == null ? terms.first.minBlocks : widget.initialLockBlocks}');
    if (widget.initialCents != null) _amount.text = formatYed(widget.initialCents!).replaceAll('\$', '');
    WidgetsBinding.instance.addPostFrameCallback((_) => _checkAvailability());
  }

  /// The core's gate (H-1, H-5); the form is usable only when it allows a mint.
  Future<void> _checkAvailability() async {
    final app = AppScope.read(context);
    setState(() {
      _checking = true;
      _availError = null;
    });
    try {
      final a = await app.api.mintAvailability();
      if (!mounted) return;
      setState(() {
        _avail = a;
        // Keep the picked class only if it can be minted now.
        if (a.allowed && !a.mintableClasses.contains(_class)) {
          final first = termClassesFor(app.settings.network).where((t) => a.mintableClasses.contains(t.letter));
          if (first.isNotEmpty) _pickClassSilently(first.first);
        }
      });
    } catch (e) {
      if (mounted) setState(() => _availError = messageOf(e));
    } finally {
      if (mounted) setState(() => _checking = false);
    }
  }

  void _pickClassSilently(TermClass t) {
    _class = t.letter;
    _lock.text = '${t.minBlocks}';
  }

  bool _mintable(String letter) => _avail?.mintableClasses.contains(letter) ?? false;

  bool get _open => _avail?.allowed == true;

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
    final tc = lock == null ? null : termClassOf(app.settings.network, lock);
    if (lock == null || tc == null) {
      setState(() => _error = 'The lock must be inside one term class');
      return;
    }
    if (!_mintable(tc.letter)) {
      setState(() => _error = 'Class ${tc.letter} is not mintable now');
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
      // The gate closed since the screen opened: show the reason in place of the form.
      if (kindOf(e) == ErrorKind.mintBlocked) await _checkAvailability();
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _start() async {
    final app = AppScope.read(context);
    final e = _estimate!;
    setState(() => _busy = true);
    try {
      // The terms shown are the terms confirmed: the core refuses a server answer that differs.
      final row = await app.api.mintStart(
        cents: e.cents,
        lockBlocks: e.lockBlocks,
        confirmed: MintTerms(collateralZat: e.collateralZat, feeZat: e.feeZat, payee: e.payee, termClass: e.termClass),
      );
      await app.refresh();
      if (!mounted) return;
      Navigator.of(context).pushReplacement(MaterialPageRoute<void>(builder: (_) => MintProgressScreen(mintId: row.mintId)));
    } catch (err) {
      setState(() {
        _error = messageOf(err);
        _needYec = kindOf(err) == ErrorKind.needYecForFees;
        _estimate = null;
      });
      if (kindOf(err) == ErrorKind.mintBlocked) await _checkAvailability();
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
            if (widget.renewing != null) ...[
              Card(
                key: const Key('renew-banner'),
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Text(
                    'Renewing vault ${shorten(widget.renewing!)}: mint the same ${widget.initialCents == null ? 'amount' : formatYed(widget.initialCents!)} again. The collateral the redeem returned can fund this mint once the redeem has one confirmation; until then the estimate may show it as missing.',
                    style: t.bodyMedium,
                  ),
                ),
              ),
              const SizedBox(height: 12),
            ],
            if (_checking && _avail == null)
              const Padding(padding: EdgeInsets.only(bottom: 12), child: LinearProgressIndicator(key: Key('mint-checking'))),
            if (_availError != null && _avail == null)
              _BlockedCard(
                key: const Key('mint-unchecked'),
                text: 'Could not check whether minting is open: $_availError',
                onRetry: _checking ? null : _checkAvailability,
              ),
            if (_avail != null && !_avail!.allowed)
              _BlockedCard(key: const Key('mint-blocked'), text: _avail!.reason, onRetry: _checking ? null : _checkAvailability),
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
              enabled: e == null && _open,
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
              segments: [for (final x in terms) ButtonSegment(value: x.letter, label: Text('${x.letter} · ${x.title}'), enabled: _mintable(x.letter))],
              selected: {_class},
              onSelectionChanged: e != null || !_open ? null : (s) => _pickClass(terms.firstWhere((x) => x.letter == s.first)),
            ),
            const SizedBox(height: 8),
            TextField(
              key: const Key('lock-blocks'),
              controller: _lock,
              enabled: e == null && _open,
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
                onPressed: _busy || !_open ? null : _estimateNow,
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
                          onPressed: () => Navigator.of(context).push(MaterialPageRoute<void>(builder: (_) => const ReceiveScreen(kind: ReceiveKind.yed))),
                          icon: const Icon(Icons.qr_code_2_rounded),
                          label: const Text('Show my receive address'),
                        ),
                        if (app.balances.yecShieldedZat > 0) MovePublicHint(what: 'Minting', privateZat: app.balances.yecShieldedZat),
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
                    'Not enough YEC: this mint needs ${formatYec(e.totalZat)} YEC and the wallet has ${formatYec(e.availableZat)} public YEC.',
                    key: const Key('unaffordable'),
                    style: t.bodySmall?.copyWith(color: c.danger),
                  ),
                ),
              if (!e.affordable && app.balances.yecShieldedZat > 0)
                MovePublicHint(what: 'Minting', privateZat: app.balances.yecShieldedZat, shortfallZat: e.totalZat - e.availableZat),
              const SizedBox(height: 8),
              TextButton(key: const Key('cancel'), onPressed: _reset, child: const Text('Change the amount')),
            ],
          ],
        ),
      ),
    );
  }
}

/// Why minting is not open, with a retry (the gate is re-read; the node's state may change).
class _BlockedCard extends StatelessWidget {
  const _BlockedCard({super.key, required this.text, required this.onRetry});
  final String text;
  final VoidCallback? onRetry;

  @override
  Widget build(BuildContext context) {
    final c = yewColors(context);
    final t = Theme.of(context).textTheme;
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: Card(
        color: c.danger.withValues(alpha: 0.08),
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(children: [Icon(Icons.block_rounded, color: c.danger), const SizedBox(width: 8), Text('Minting is not open', style: t.titleSmall)]),
              const SizedBox(height: 8),
              Text(text, key: const Key('mint-blocked-reason'), style: t.bodyMedium),
              const SizedBox(height: 8),
              TextButton(key: const Key('mint-recheck'), onPressed: onRetry, child: const Text('Check again')),
            ],
          ),
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
            if (e.payee.isNotEmpty) PreviewRow('Fee paid to', shorten(e.payee, head: 10, tail: 6)),
            if (e.attestFeeZat > 0) PreviewRow('Attestor fee', '${formatYec(e.attestFeeZat)} YEC'),
            PreviewRow('Carrier + token', '${formatYec(e.carrierZat + e.tokenZat)} YEC'),
            PreviewRow('Network fees', '${formatYec(e.networkFeeZat)} YEC (two transactions)'),
            PreviewRow('Total YEC needed', '${formatYec(e.totalZat)} YEC', emphasis: true),
            const Divider(height: 20),
            PreviewRow('Price at R', e.pMintMicroUsd == null ? 'unavailable' : formatUsdPerYec(e.pMintMicroUsd!)),
            PreviewRow('Reference height', '${e.refHeight} · window closes at ${e.expiryHeight}'),
            PreviewRow('Attestors', e.bundleSeqs.isEmpty ? 'none' : e.bundleSeqs.join(', ')),
            if (!e.armed) const PreviewRow('', 'The price feed is not armed at R', color: Colors.red),
          ],
        ),
      ),
    );
  }
}
