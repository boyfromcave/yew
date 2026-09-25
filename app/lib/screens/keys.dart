// Export private key (D-W-11): pick an address, show its WIF as text and QR, with the
// warning that YEC **and** YED on that address move with it. Import private key: a WIF from
// YecWallet / ycashd, flagged as not covered by the seed backup.
import 'package:flutter/material.dart';

import '../api/wallet_api.dart';
import '../format.dart';
import '../state/app_scope.dart';
import '../theme.dart';
import '../widgets/address_qr.dart';

/// The warning the plan requires on the export screen.
const String exportWarning =
    'Anyone with this key controls this address: the YEC and the YED on it move with the key. '
    'Import it only into a wallet you control (YecWallet: File → Import Private Key).';

class ExportKeyScreen extends StatefulWidget {
  const ExportKeyScreen({super.key});

  @override
  State<ExportKeyScreen> createState() => _ExportKeyScreenState();
}

class _ExportKeyScreenState extends State<ExportKeyScreen> {
  List<AddressPair> _addresses = const [];
  AddressPair? _chosen;
  WifExport? _wif;
  String? _error;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) async {
      final app = AppScope.read(context);
      try {
        final all = await app.api.addresses();
        setState(() {
          _addresses = all;
          _chosen = app.receive ?? (all.isEmpty ? null : all.first);
        });
      } catch (e) {
        setState(() => _error = messageOf(e));
      }
    });
  }

  Future<void> _reveal() async {
    final app = AppScope.read(context);
    if (app.settings.biometrics && !await app.auth.authenticate('Export a private key')) return;
    try {
      final w = await app.api.exportWif(address: _chosen!.ye);
      setState(() => _wif = w);
    } catch (e) {
      setState(() => _error = messageOf(e));
    }
  }

  @override
  Widget build(BuildContext context) {
    final c = yewColors(context);
    final t = Theme.of(context).textTheme;
    return Scaffold(
      appBar: AppBar(title: const Text('Export private key')),
      body: ListView(
        padding: const EdgeInsets.fromLTRB(20, 8, 20, 32),
        children: [
          Card(
            color: c.danger.withValues(alpha: 0.08),
            child: Padding(padding: const EdgeInsets.all(16), child: Text(exportWarning, key: const Key('warning'), style: t.bodyMedium)),
          ),
          const SizedBox(height: 16),
          DropdownButtonFormField<AddressPair>(
            key: const Key('address-pick'),
            initialValue: _chosen,
            isExpanded: true,
            decoration: const InputDecoration(labelText: 'Address'),
            items: [
              for (final a in _addresses)
                DropdownMenuItem(value: a, child: Text('${shorten(a.ye, head: 12, tail: 6)} · ${a.path}', overflow: TextOverflow.ellipsis)),
            ],
            onChanged: _wif != null ? null : (a) => setState(() => _chosen = a),
          ),
          const SizedBox(height: 16),
          if (_wif == null)
            FilledButton(
              key: const Key('reveal'),
              onPressed: _chosen == null ? null : _reveal,
              style: FilledButton.styleFrom(backgroundColor: c.danger),
              child: const Text('Reveal the key'),
            ),
          if (_error != null) Padding(padding: const EdgeInsets.only(top: 8), child: Text(_error!, style: TextStyle(color: c.danger))),
          if (_wif != null) ...[
            Text(_wif!.addressYe, style: t.bodySmall, textAlign: TextAlign.center),
            Text(_wif!.addressS, style: t.bodySmall, textAlign: TextAlign.center),
            if (!_wif!.coveredBySeed) Text('imported key: not covered by the recovery phrase', style: t.bodySmall?.copyWith(color: c.danger), textAlign: TextAlign.center),
            const SizedBox(height: 12),
            AddressQr(data: _wif!.wif, caption: 'WIF (the format of dumpprivkey)'),
          ],
        ],
      ),
    );
  }
}

class ImportKeyScreen extends StatefulWidget {
  const ImportKeyScreen({super.key});

  @override
  State<ImportKeyScreen> createState() => _ImportKeyScreenState();
}

class _ImportKeyScreenState extends State<ImportKeyScreen> {
  final _wif = TextEditingController();
  final _birthday = TextEditingController();
  bool _busy = false;
  String? _error;
  AddressPair? _imported;

  @override
  void dispose() {
    _wif.dispose();
    _birthday.dispose();
    super.dispose();
  }

  Future<void> _import() async {
    final app = AppScope.read(context);
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final a = await app.api.importWif(wif: _wif.text.trim(), birthday: int.tryParse(_birthday.text.trim()));
      setState(() => _imported = a);
      _wif.clear();
      await app.sync();
    } catch (e) {
      setState(() => _error = messageOf(e));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final c = yewColors(context);
    final t = Theme.of(context).textTheme;
    return Scaffold(
      appBar: AppBar(title: const Text('Import private key')),
      body: ListView(
        padding: const EdgeInsets.fromLTRB(20, 8, 20, 32),
        children: [
          Text(
            'A key from YecWallet or ycashd (dumpprivkey). It is added beside the seed, not derived from it: '
            'the recovery phrase does not restore it. Export it again before forgetting this wallet.',
            style: t.bodyMedium,
          ),
          const SizedBox(height: 16),
          TextField(
            key: const Key('wif'),
            controller: _wif,
            autocorrect: false,
            enableSuggestions: false,
            obscureText: true,
            decoration: const InputDecoration(labelText: 'WIF'),
          ),
          const SizedBox(height: 12),
          TextField(
            key: const Key('birthday'),
            controller: _birthday,
            keyboardType: TextInputType.number,
            decoration: const InputDecoration(labelText: 'Scan from height (optional; the key\'s first use)'),
          ),
          const SizedBox(height: 16),
          FilledButton(key: const Key('import'), onPressed: _busy ? null : _import, child: Text(_busy ? 'Importing…' : 'Import and rescan')),
          if (_error != null) Padding(padding: const EdgeInsets.only(top: 8), child: Text(_error!, key: const Key('error'), style: TextStyle(color: c.danger))),
          if (_imported != null) ...[
            const SizedBox(height: 16),
            Card(
              child: ListTile(
                key: const Key('imported'),
                leading: const Icon(Icons.check_circle_outline_rounded),
                title: Text(_imported!.ye),
                subtitle: Text('${_imported!.s}\nnot covered by the recovery phrase'),
                isThreeLine: true,
              ),
            ),
          ],
        ],
      ),
    );
  }
}
