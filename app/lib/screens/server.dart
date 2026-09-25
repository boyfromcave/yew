// Settings → Server (plan §3.5): one endpoint; TLS required outside regtest (the core refuses
// plain on mainnet and testnet, the switch shows on regtest only); probe before
// saving (contract rule 1: an unknown rpcversion is refused by the core).
import 'package:flutter/material.dart';

import '../api/wallet_api.dart';
import '../state/app_scope.dart';
import '../theme.dart';

class ServerScreen extends StatefulWidget {
  const ServerScreen({super.key});

  @override
  State<ServerScreen> createState() => _ServerScreenState();
}

class _ServerScreenState extends State<ServerScreen> {
  late final TextEditingController _server;
  late bool _plain;
  bool _busy = false;
  String? _note;
  bool _ok = false;

  @override
  void initState() {
    super.initState();
    final s = AppScope.read(context).settings;
    _server = TextEditingController(text: s.server);
    _plain = s.plain;
  }

  @override
  void dispose() {
    _server.dispose();
    super.dispose();
  }

  Future<void> _probe() async {
    final app = AppScope.read(context);
    setState(() {
      _busy = true;
      _note = null;
      _ok = false;
    });
    try {
      final p = await app.api.probeServer(server: _server.text.trim(), plain: _plain, network: app.settings.network);
      setState(() {
        _ok = true;
        _note =
            '${p.serverVersion} · ${p.chainName} · tip ${p.tip} · '
            '${p.yellowback.usable ? 'Yellowback rpcversion ${p.yellowback.rpcversion}' : 'no usable Yellowback service (YED hidden)'}';
      });
    } catch (e) {
      setState(() => _note = messageOf(e));
    } finally {
      setState(() => _busy = false);
    }
  }

  Future<void> _save() async {
    final app = AppScope.read(context);
    try {
      await app.setServer(_server.text.trim(), _plain);
      if (mounted) Navigator.of(context).pop();
    } catch (e) {
      setState(() => _note = messageOf(e));
    }
  }

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final c = yewColors(context);
    final regtest = app.settings.network == NetworkId.regtest;
    return Scaffold(
      appBar: AppBar(title: const Text('Server')),
      body: ListView(
        padding: const EdgeInsets.fromLTRB(20, 8, 20, 32),
        children: [
          Text('Network: ${app.settings.network.name} (fixed at setup)', style: Theme.of(context).textTheme.bodyMedium),
          const SizedBox(height: 12),
          TextField(
            key: const Key('server'),
            controller: _server,
            autocorrect: false,
            onChanged: (_) => setState(() => _ok = false),
            decoration: const InputDecoration(labelText: 'host:port'),
          ),
          if (regtest)
            SwitchListTile(
              key: const Key('plain'),
              value: _plain,
              onChanged: (v) => setState(() {
                _plain = v;
                _ok = false;
              }),
              title: const Text('Plain connection (no TLS)'),
              contentPadding: EdgeInsets.zero,
            ),
          const SizedBox(height: 12),
          OutlinedButton(key: const Key('probe'), onPressed: _busy ? null : _probe, child: Text(_busy ? 'Checking…' : 'Check')),
          if (_note != null) Padding(padding: const EdgeInsets.only(top: 8), child: Text(_note!, key: const Key('note'), style: TextStyle(color: _ok ? null : c.danger))),
          const SizedBox(height: 16),
          FilledButton(key: const Key('save'), onPressed: _ok ? _save : null, child: const Text('Use this server')),
        ],
      ),
    );
  }
}
