// Claimable (plan §5.3, the liquidator persona): the node's `ListClaimable` rows; a claim is
// the same two-step as a mint (bundle, carrier, then the CLAIM) and reuses MintProgressScreen.
// The wallet must hold the debt in YED before the carrier is funded; the core checks that.
import 'package:flutter/material.dart';

import '../api/wallet_api.dart';
import '../format.dart';
import '../state/app_scope.dart';
import '../theme.dart';
import '../widgets/preview_card.dart';
import '../widgets/slide_to_confirm.dart';
import 'mint_progress.dart';

class ClaimableScreen extends StatefulWidget {
  const ClaimableScreen({super.key});

  @override
  State<ClaimableScreen> createState() => _ClaimableScreenState();
}

class _ClaimableScreenState extends State<ClaimableScreen> {
  List<ClaimableItem>? _rows;
  String? _error;
  ClaimableItem? _picked;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _load());
  }

  Future<void> _load() async {
    final app = AppScope.read(context);
    setState(() {
      _error = null;
      _rows = null;
    });
    try {
      final rows = await app.api.claimable();
      setState(() => _rows = rows);
    } catch (e) {
      setState(() {
        _error = messageOf(e);
        _rows = const [];
      });
    }
  }

  Future<void> _claim() async {
    final app = AppScope.read(context);
    final v = _picked!;
    try {
      final row = await app.api.claim(vaultTxid: v.vaultTxid);
      await app.refresh();
      if (!mounted) return;
      Navigator.of(context).pushReplacement(MaterialPageRoute<void>(builder: (_) => MintProgressScreen(mintId: row.mintId)));
    } catch (e) {
      setState(() {
        _error = messageOf(e);
        _picked = null;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final c = yewColors(context);
    final t = Theme.of(context).textTheme;
    final rows = _rows;
    final p = _picked;
    return Scaffold(
      appBar: AppBar(
        title: const Text('Claimable vaults'),
        actions: [IconButton(key: const Key('reload'), tooltip: 'Reload', onPressed: _load, icon: const Icon(Icons.refresh_rounded))],
      ),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.fromLTRB(16, 8, 16, 32),
          children: [
            Text(
              'Vaults the node judges claimable at its tip. Claiming burns the vault\'s debt from your YED and pays you its collateral, in two transactions like a mint.',
              style: t.bodyMedium?.copyWith(color: c.pending),
            ),
            const SizedBox(height: 12),
            if (_error != null)
              Card(
                color: c.danger.withValues(alpha: 0.08),
                child: Padding(padding: const EdgeInsets.all(16), child: Text(_error!, key: const Key('error'), style: t.bodyMedium)),
              ),
            if (rows == null) const Padding(padding: EdgeInsets.all(32), child: Center(child: CircularProgressIndicator())),
            if (rows != null && rows.isEmpty && _error == null)
              Padding(padding: const EdgeInsets.all(24), child: Text('Nothing is claimable right now.', key: const Key('none'), textAlign: TextAlign.center, style: t.bodyLarge)),
            if (rows != null)
              for (final v in rows)
                Card(
                  child: ListTile(
                    key: Key('claimable-${v.vaultTxid}'),
                    selected: p?.vaultTxid == v.vaultTxid,
                    leading: Icon(Icons.gavel_rounded, color: c.yed),
                    title: Text('${formatYed(v.cents)} debt · ${formatYec(v.collateralZat)} YEC', style: t.titleMedium),
                    subtitle: Text('you keep about ${formatYec(v.claimantZat)} YEC · clause ${v.claimPath} · ${shorten(v.ownerAddress, head: 8, tail: 4)}'),
                    onTap: () => setState(() => _picked = p?.vaultTxid == v.vaultTxid ? null : v),
                  ),
                ),
            if (p != null) ...[
              const SizedBox(height: 12),
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Column(
                    children: [
                      PreviewRow('You burn', formatYed(p.cents), emphasis: true, color: c.yed),
                      PreviewRow('Collateral', '${formatYec(p.collateralZat)} YEC', emphasis: true, color: c.yec),
                      if (p.feeZat > 0) PreviewRow('Enforcement fee', '${formatYec(p.feeZat)} YEC'),
                      if (p.attestFeeZat > 0) PreviewRow('Attestor fee', '${formatYec(p.attestFeeZat)} YEC'),
                      if (p.residualZat > 0) PreviewRow('Residual to owner', '${formatYec(p.residualZat)} YEC'),
                      PreviewRow('You keep', '${formatYec(p.claimantZat)} YEC', emphasis: true),
                      PreviewRow('Claim path', p.claimPath == 'a' ? 'a · underwater at ${formatUsdPerYec(p.pClaimMicroUsd)}' : 'b · notice + emergency price'),
                      PreviewRow('Claimable from', 'height ${p.claimHeight}'),
                      PreviewRow('Vault', shorten(p.vaultTxid)),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 12),
              if (app.balances.yedCents < p.cents)
                Padding(
                  padding: const EdgeInsets.only(bottom: 8),
                  child: Text(
                    'This claim burns ${formatYed(p.cents)} of YED; this wallet holds ${formatYed(app.balances.yedCents)}.',
                    key: const Key('need-yed'),
                    style: t.bodySmall?.copyWith(color: c.danger),
                  ),
                ),
              SlideToConfirm(
                label: 'Slide to claim: fund the carrier',
                color: c.yed,
                enabled: app.balances.yedCents >= p.cents,
                onConfirmed: _claim,
              ),
            ],
          ],
        ),
      ),
    );
  }
}
