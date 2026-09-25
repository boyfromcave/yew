// Send (plan §5.1, §3.7 item 4): asset toggle YED/YEC, address (paste, scan), amount,
// preview (fee in YEC, dry-run verdict for YED), slide to confirm, result. Every error the
// core returns is shown verbatim; a gate refusal is the node's verdict.
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../api/wallet_api.dart';
import '../format.dart';
import '../state/app_scope.dart';
import '../theme.dart';
import '../widgets/preview_card.dart';
import '../widgets/scan_sheet.dart';
import '../widgets/slide_to_confirm.dart';
import 'receive.dart';

enum Asset { yed, yec }

class SendScreen extends StatefulWidget {
  const SendScreen({super.key, this.asset = Asset.yed});
  final Asset asset;

  @override
  State<SendScreen> createState() => _SendScreenState();
}

class _SendScreenState extends State<SendScreen> {
  late Asset _asset = widget.asset;
  final _address = TextEditingController();
  final _amount = TextEditingController();
  bool _everything = false;
  bool _busy = false;
  String? _error;
  bool _needYec = false;
  YecPreview? _yec;
  YedPreview? _yed;
  SendResult? _result;

  @override
  void dispose() {
    _address.dispose();
    _amount.dispose();
    super.dispose();
  }

  void _reset() => setState(() {
    _yec = null;
    _yed = null;
    _error = null;
    _needYec = false;
  });

  Future<void> _preview() async {
    final app = AppScope.read(context);
    final to = _address.text.trim();
    final check = app.api.validateAddress(network: app.settings.network, address: to);
    if (!check.valid) {
      setState(() => _error = check.message.isEmpty ? 'Not a valid address' : check.message);
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
      _needYec = false;
    });
    try {
      if (_asset == Asset.yed) {
        final cents = parseYedCents(_amount.text);
        if (cents == null || cents <= 0) throw const YewError(kind: ErrorKind.input, message: 'Enter an amount in dollars, like 12.34');
        final p = await app.api.sendYedPreview(recipients: [Recipient(address: to, cents: cents)]);
        setState(() => _yed = p);
      } else {
        final zat = _everything ? app.balances.yecZat + app.balances.yecReservedZat - 1000 : parseYecZat(_amount.text);
        if (zat == null || zat <= 0) throw const YewError(kind: ErrorKind.input, message: 'Enter an amount in YEC, up to eight decimals');
        final p = await app.api.sendYecPreview(to: to, zat: zat, sendEverything: _everything);
        setState(() => _yec = p);
      }
    } catch (e) {
      setState(() {
        _error = messageOf(e);
        _needYec = kindOf(e) == ErrorKind.needYecForFees;
      });
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _confirm() async {
    final app = AppScope.read(context);
    try {
      final r = _yed != null
          ? await app.api.sendYedConfirm(previewId: _yed!.previewId)
          : await app.api.sendYecConfirm(previewId: _yec!.previewId);
      setState(() => _result = r);
      await app.refresh();
    } catch (e) {
      setState(() {
        _error = messageOf(e);
        _yed = null;
        _yec = null;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final c = yewColors(context);
    final t = Theme.of(context).textTheme;
    final accent = _asset == Asset.yed ? c.yed : c.yec;
    final hasPreview = _yed != null || _yec != null;
    if (_result != null) return _ResultView(result: _result!, accent: accent);
    return Scaffold(
      appBar: AppBar(title: const Text('Send')),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.fromLTRB(20, 8, 20, 32),
          children: [
            SegmentedButton<Asset>(
              key: const Key('asset-toggle'),
              segments: const [
                ButtonSegment(value: Asset.yed, label: Text('YED')),
                ButtonSegment(value: Asset.yec, label: Text('YEC')),
              ],
              selected: {_asset},
              onSelectionChanged: hasPreview
                  ? null
                  : (s) => setState(() {
                      _asset = s.first;
                      _error = null;
                      _needYec = false;
                    }),
            ),
            const SizedBox(height: 16),
            Text(
              _asset == Asset.yed
                  ? '${formatYed(app.balances.yedCents)} YED available'
                  : '${formatYec(app.balances.yecZat)} YEC available · ${formatYec(app.balances.yecReservedZat)} reserved for fees',
              key: const Key('available'),
              style: t.bodyMedium?.copyWith(color: c.pending),
            ),
            const SizedBox(height: 12),
            TextField(
              key: const Key('address'),
              controller: _address,
              enabled: !hasPreview,
              autocorrect: false,
              enableSuggestions: false,
              onChanged: (_) => _reset(),
              decoration: InputDecoration(
                labelText: 'To',
                hintText: _asset == Asset.yed ? 'ye… address' : 'ye… or s… address',
                suffixIcon: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    IconButton(
                      key: const Key('paste'),
                      tooltip: 'Paste',
                      icon: const Icon(Icons.content_paste_rounded),
                      onPressed: () async {
                        final d = await Clipboard.getData('text/plain');
                        if (d?.text != null) setState(() => _address.text = d!.text!.trim());
                      },
                    ),
                    IconButton(
                      key: const Key('scan'),
                      tooltip: 'Scan',
                      icon: const Icon(Icons.qr_code_scanner_rounded),
                      onPressed: () async {
                        final v = await scanQr(context);
                        if (v != null) setState(() => _address.text = v);
                      },
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 12),
            TextField(
              key: const Key('amount'),
              controller: _amount,
              enabled: !hasPreview && !_everything,
              keyboardType: const TextInputType.numberWithOptions(decimal: true),
              onChanged: (_) => _reset(),
              style: t.headlineMedium,
              decoration: InputDecoration(
                labelText: _asset == Asset.yed ? 'Amount in dollars' : 'Amount in YEC',
                prefixText: _asset == Asset.yed ? '\$ ' : null,
                suffixText: _asset == Asset.yed ? 'YED' : 'YEC',
              ),
            ),
            if (_asset == Asset.yec)
              SwitchListTile(
                key: const Key('everything'),
                value: _everything,
                onChanged: hasPreview ? null : (v) => setState(() => _everything = v),
                title: const Text('Send everything, including the fee reserve'),
                subtitle: const Text('Leaves no YEC to send YED with'),
                contentPadding: EdgeInsets.zero,
              ),
            const SizedBox(height: 16),
            if (!hasPreview)
              FilledButton(
                key: const Key('preview'),
                onPressed: _busy ? null : _preview,
                style: FilledButton.styleFrom(backgroundColor: accent),
                child: Text(_busy ? 'Building…' : 'Preview'),
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
                        Text(
                          'Sending YED costs a small YEC fee (about ${formatYec(app.balances.yedSendMinZat)} YEC). '
                          'This wallet has ${formatYec(app.balances.yecZat + app.balances.yecReservedZat)} YEC.',
                          style: t.bodySmall,
                        ),
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
            if (_yec != null) YecPreviewCard(_yec!),
            if (_yed != null) YedPreviewCard(_yed!),
            if (hasPreview) ...[
              const SizedBox(height: 16),
              SlideToConfirm(
                label: _yed != null ? 'Slide to send ${formatYed(_yed!.totalCents)}' : 'Slide to send ${formatYec(_yec!.amountZat)} YEC',
                color: accent,
                enabled: _yed == null || _yed!.dryRun.accepted,
                onConfirmed: _confirm,
              ),
              const SizedBox(height: 8),
              TextButton(key: const Key('cancel'), onPressed: _reset, child: const Text('Cancel')),
            ],
          ],
        ),
      ),
    );
  }
}

class _ResultView extends StatelessWidget {
  const _ResultView({required this.result, required this.accent});
  final SendResult result;
  final Color accent;

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    return Scaffold(
      appBar: AppBar(title: const Text('Sent')),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              TweenAnimationBuilder<double>(
                tween: Tween(begin: 0, end: 1),
                duration: confirmMotion,
                curve: Curves.easeOutBack,
                builder: (_, v, child) => Transform.scale(scale: v, child: child),
                child: Icon(Icons.check_circle_rounded, size: 96, color: accent),
              ),
              const SizedBox(height: 24),
              Text('Sent', style: t.headlineMedium),
              const SizedBox(height: 8),
              SelectableText(result.txid, key: const Key('txid'), textAlign: TextAlign.center, style: t.bodySmall),
              if (result.verdict.isNotEmpty) Text('node verdict: ${result.verdict}', style: t.bodySmall),
              const SizedBox(height: 32),
              FilledButton(key: const Key('done'), onPressed: () => Navigator.of(context).pop(), child: const Text('Done')),
            ],
          ),
        ),
      ),
    );
  }
}
