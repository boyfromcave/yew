// The progress of one two-step row (plan §5.3): *funding carrier → waiting for 1
// confirmation → minting → done*, or *window closed, sweeping carrier*. The screen renders
// the row the core holds and moves it forward the only two ways a screen can: `mintFinish`
// once the sync loop has confirmed the carrier, `mintSweep` once it has marked the row
// lapsed. Syncing on a timer while the row moves; every core error verbatim.
import 'dart:async';

import 'package:flutter/material.dart';

import '../api/wallet_api.dart';
import '../format.dart';
import '../state/app_scope.dart';
import '../theme.dart';
import '../widgets/preview_card.dart';

class MintProgressScreen extends StatefulWidget {
  const MintProgressScreen({super.key, required this.mintId});
  final int mintId;

  @override
  State<MintProgressScreen> createState() => _MintProgressScreenState();
}

class _MintProgressScreenState extends State<MintProgressScreen> {
  Timer? _timer;
  bool _busy = false;
  String? _error;
  int? _finishTried;

  @override
  void initState() {
    super.initState();
    final app = AppScope.read(context);
    final every = app.mintPollInterval;
    if (every != null) _timer = Timer.periodic(every, (_) => _tick());
    WidgetsBinding.instance.addPostFrameCallback((_) => _advance());
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  MintStatus? get _row => AppScope.read(context).mintById(widget.mintId);

  Future<void> _tick() async {
    final app = AppScope.read(context);
    final m = _row;
    if (m == null || _busy || app.syncing) return;
    if (!(m.inProgress || m.canSweep || m.state == 'SWEEP_SENT')) {
      _timer?.cancel();
      return;
    }
    await app.sync();
    if (mounted) await _advance();
  }

  /// The main step, once and only once per row height: the core refuses a wrong state.
  Future<void> _advance() async {
    final m = _row;
    if (m == null || !m.canFinish || _busy || _finishTried == m.tip) return;
    _finishTried = m.tip;
    await _finish();
  }

  Future<void> _finish() => _step((api) => api.mintFinish(mintId: widget.mintId));

  Future<void> _sweep() => _step((api) => api.mintSweep(mintId: widget.mintId));

  Future<void> _step(Future<MintStatus> Function(WalletApi api) f) async {
    final app = AppScope.read(context);
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await f(app.api);
      await app.refresh();
    } catch (e) {
      setState(() => _error = messageOf(e));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final c = yewColors(context);
    final t = Theme.of(context).textTheme;
    final m = app.mintById(widget.mintId);
    final title = m?.kind == 'claim' ? 'Claim' : 'Mint';
    if (m == null) {
      return Scaffold(appBar: AppBar(title: Text(title)), body: const Center(child: Text('No such row.')));
    }
    final steps = _steps(m);
    return Scaffold(
      appBar: AppBar(
        title: Text('$title ${formatYed(m.cents)}'),
        actions: [
          IconButton(
            key: const Key('sync'),
            tooltip: 'Sync now',
            onPressed: app.syncing || _busy ? null : _tick,
            icon: app.syncing ? const SizedBox(width: 20, height: 20, child: CircularProgressIndicator(strokeWidth: 2)) : const Icon(Icons.sync_rounded),
          ),
        ],
      ),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.fromLTRB(20, 8, 20, 32),
          children: [
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    for (final s in steps)
                      Padding(
                        padding: const EdgeInsets.symmetric(vertical: 6),
                        child: Row(
                          children: [
                            Icon(
                              s.$2 == _Mark.done ? Icons.check_circle_rounded : (s.$2 == _Mark.now ? Icons.radio_button_checked_rounded : Icons.radio_button_off_rounded),
                              color: s.$2 == _Mark.failed ? c.danger : (s.$2 == _Mark.todo ? c.pending : c.yed),
                            ),
                            const SizedBox(width: 12),
                            Expanded(child: Text(s.$1, style: s.$2 == _Mark.now ? t.titleMedium : t.bodyMedium)),
                          ],
                        ),
                      ),
                    const SizedBox(height: 4),
                    Text(_hint(m), key: const Key('state'), style: t.bodySmall?.copyWith(color: m.canSweep ? c.danger : c.pending)),
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
            const SizedBox(height: 12),
            if (m.canFinish)
              FilledButton(
                key: const Key('finish'),
                onPressed: _busy ? null : _finish,
                style: FilledButton.styleFrom(backgroundColor: c.yed),
                child: Text(_busy ? 'Sending…' : (m.kind == 'claim' ? 'Send the claim now' : 'Send the mint now')),
              ),
            if (m.canSweep)
              FilledButton(
                key: const Key('sweep'),
                onPressed: _busy ? null : _sweep,
                child: Text(_busy ? 'Sweeping…' : 'Sweep the carrier back'),
              ),
            const SizedBox(height: 16),
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  children: [
                    PreviewRow('State', m.state),
                    if (m.vaultTxid.isNotEmpty) PreviewRow('Vault', shorten(m.vaultTxid)),
                    PreviewRow('Collateral', '${formatYec(m.collateralZat)} YEC'),
                    if (m.kind == 'mint') PreviewRow('Term', 'class ${m.termClass} · ${m.lockBlocks} blocks · redeem from ${m.lockHeight}'),
                    if (m.feeZat > 0) PreviewRow('Enforcement fee', '${formatYec(m.feeZat)} YEC'),
                    if (m.attestFeeZat > 0) PreviewRow('Attestor fee', '${formatYec(m.attestFeeZat)} YEC'),
                    if (m.residualZat > 0) PreviewRow('Residual to owner', '${formatYec(m.residualZat)} YEC'),
                    PreviewRow('Reference height', '${m.refHeight} · window closes at ${m.expiryHeight}'),
                    PreviewRow('Carrier', shorten(m.carrierTxid)),
                    if (m.mainTxid.isNotEmpty) PreviewRow(m.kind == 'claim' ? 'Claim' : 'Mint', shorten(m.mainTxid)),
                    if (m.sweepTxid.isNotEmpty) PreviewRow('Sweep', shorten(m.sweepTxid)),
                    if (m.note.isNotEmpty) PreviewRow('Note', m.note),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 16),
            if (!m.inProgress && !m.canSweep)
              FilledButton(key: const Key('done'), onPressed: () => Navigator.of(context).pop(), child: const Text('Done')),
          ],
        ),
      ),
    );
  }

  String _hint(MintStatus m) {
    switch (m.state) {
      case 'CARRIER_SENT':
        return 'Waiting for the carrier to confirm (synced to ${m.tip}). The window closes at ${m.expiryHeight}.';
      case 'CARRIER_CONFIRMED':
        return m.windowOpen ? 'Carrier confirmed. ${m.blocksLeft} block${m.blocksLeft == 1 ? '' : 's'} left in the window.' : 'The window has closed; the next sync marks the carrier for sweeping.';
      case 'MAIN_SENT':
        return 'Sent. Waiting for one confirmation (synced to ${m.tip}).';
      case 'DONE':
        return m.kind == 'claim' ? 'The claim confirmed: the collateral is yours.' : 'The mint confirmed: the YED is in your balance and the vault is on the Yellowback screen.';
      case 'LAPSED':
        return 'Window closed, sweeping carrier: the carrier is unspent and can be swept back (minus one network fee).';
      case 'SWEEP_SENT':
        return 'Sweep sent. Waiting for one confirmation.';
      case 'SWEPT':
        return 'The carrier came back to your YEC.';
      case 'FAILED':
        return 'The carrier never confirmed; nothing is on the chain. ${m.note}';
    }
    return m.state;
  }
}

enum _Mark { done, now, todo, failed }

List<(String, _Mark)> _steps(MintStatus m) {
  final main = m.kind == 'claim' ? 'claiming' : 'minting';
  if (m.state == 'FAILED') {
    return [('funding carrier', _Mark.failed), ('waiting for 1 confirmation', _Mark.todo), (main, _Mark.todo), ('done', _Mark.todo)];
  }
  if (m.canSweep || m.state == 'SWEEP_SENT' || m.state == 'SWEPT' || (m.state == 'CARRIER_CONFIRMED' && !m.windowOpen)) {
    return [
      ('funding carrier', _Mark.done),
      ('waiting for 1 confirmation', _Mark.done),
      ('window closed', _Mark.failed),
      ('sweeping carrier', m.state == 'SWEPT' ? _Mark.done : (m.state == 'SWEEP_SENT' ? _Mark.now : _Mark.todo)),
    ];
  }
  final order = ['CARRIER_SENT', 'CARRIER_CONFIRMED', 'MAIN_SENT', 'DONE'];
  final at = order.indexOf(m.state);
  _Mark mark(int i) => i < at ? _Mark.done : (i == at ? _Mark.now : _Mark.todo);
  return [
    ('funding carrier', at > 0 ? _Mark.done : _Mark.now),
    ('waiting for 1 confirmation', mark(1)),
    (main, mark(2)),
    ('done', at == 3 ? _Mark.done : _Mark.todo),
  ];
}
