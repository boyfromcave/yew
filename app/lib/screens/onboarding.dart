// Onboarding (plan §5.1): create / restore a 12-word seed, birthday height (default: the
// server's tip), the trust statement, the transparent-only notice, biometric unlock.
import 'package:flutter/material.dart';

import '../api/wallet_api.dart';
import '../state/app_scope.dart';
import '../state/secrets.dart';
import '../theme.dart';
import '../trust_text.dart';
import 'seed_backup.dart';

enum _Step { welcome, restore, trust, server, finish }

class OnboardingScreen extends StatefulWidget {
  const OnboardingScreen({super.key});

  @override
  State<OnboardingScreen> createState() => _OnboardingScreenState();
}

class _OnboardingScreenState extends State<OnboardingScreen> {
  _Step _step = _Step.welcome;
  bool _restoring = false;
  bool _trustRead = false;
  bool _biometrics = false;
  bool _busy = false;
  String? _error;
  int? _tip;
  final _words = TextEditingController();
  final _passphrase = TextEditingController();
  final _birthday = TextEditingController();
  final _server = TextEditingController(text: WalletSettings.defaultServer);
  NetworkId _network = NetworkId.mainnet;
  bool _plain = false;

  @override
  void dispose() {
    for (final c in [_words, _passphrase, _birthday, _server]) {
      c.dispose();
    }
    super.dispose();
  }

  Future<void> _probe() async {
    final app = AppScope.read(context);
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final p = await app.api.probeServer(server: _server.text.trim(), plain: _plain, network: _network);
      setState(() {
        _tip = p.tip;
        if (_birthday.text.isEmpty) _birthday.text = '${p.tip}';
        _error = p.yellowback.usable ? null : 'This server offers no usable Yellowback service: YED will be hidden.';
      });
    } catch (e) {
      setState(() => _error = messageOf(e));
    } finally {
      setState(() => _busy = false);
    }
  }

  Future<void> _finish() async {
    final app = AppScope.read(context);
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      if (_restoring) app.api.checkSeedWords(seedWords: _words.text);
      final birthday = _restoring ? int.tryParse(_birthday.text.trim()) : (_tip ?? int.tryParse(_birthday.text.trim()));
      final generated = await app.createWallet(
        seedWords: _restoring ? _words.text.trim() : null,
        passphrase: _passphrase.text,
        birthday: birthday,
        withSettings: WalletSettings(
          server: _server.text.trim(),
          plain: _plain,
          network: _network,
          trustAccepted: true,
          biometrics: _biometrics,
        ),
      );
      if (generated != null && mounted) {
        await Navigator.of(context).push(
          MaterialPageRoute<void>(builder: (_) => SeedBackupScreen(words: generated, firstTime: true)),
        );
      }
    } catch (e) {
      setState(() => _error = messageOf(e));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    final c = yewColors(context);
    return Scaffold(
      appBar: _step == _Step.welcome
          ? null
          : AppBar(
              leading: BackButton(
                onPressed: () => setState(() {
                  _step = switch (_step) {
                    _Step.restore => _Step.welcome,
                    _Step.trust => _restoring ? _Step.restore : _Step.welcome,
                    _Step.server => _Step.trust,
                    _ => _Step.server,
                  };
                }),
              ),
            ),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.fromLTRB(24, 24, 24, 32),
          children: [
            if (_step == _Step.welcome) ...[
              const SizedBox(height: 48),
              Text('YEW', style: t.displayLarge?.copyWith(color: c.yed)),
              Text('Your Electronic Wallet', style: t.titleLarge),
              const SizedBox(height: 24),
              Text('A wallet for Ycash Yellowback (YED) and YEC.', style: t.bodyLarge),
              const SizedBox(height: 16),
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Text(
                    'Transparent only. Everything this wallet does is public on the chain: '
                    'addresses, balances and every transaction. It holds nothing shielded.',
                    style: t.bodyMedium,
                  ),
                ),
              ),
              const SizedBox(height: 32),
              FilledButton(
                key: const Key('create'),
                onPressed: () => setState(() {
                  _restoring = false;
                  _step = _Step.trust;
                }),
                child: const Text('Create a new wallet'),
              ),
              const SizedBox(height: 12),
              OutlinedButton(
                key: const Key('restore'),
                onPressed: () => setState(() {
                  _restoring = true;
                  _step = _Step.restore;
                }),
                child: const Text('Restore from a recovery phrase'),
              ),
            ],
            if (_step == _Step.restore) ...[
              Text('Recovery phrase', style: t.headlineSmall),
              const SizedBox(height: 8),
              Text('12 or 24 words. A Ywallet phrase restores the same address.', style: t.bodyMedium),
              const SizedBox(height: 16),
              TextField(
                key: const Key('words'),
                controller: _words,
                maxLines: 4,
                autocorrect: false,
                enableSuggestions: false,
                onChanged: (_) => setState(() {}),
                decoration: const InputDecoration(hintText: 'word word word …'),
              ),
              const SizedBox(height: 12),
              TextField(
                key: const Key('passphrase'),
                controller: _passphrase,
                obscureText: true,
                decoration: const InputDecoration(labelText: 'Passphrase (optional)'),
              ),
              const SizedBox(height: 12),
              TextField(
                key: const Key('birthday'),
                controller: _birthday,
                keyboardType: TextInputType.number,
                decoration: const InputDecoration(labelText: 'Birthday height (the block the wallet was created around; 0 = scan everything)'),
              ),
              const SizedBox(height: 24),
              FilledButton(
                key: const Key('next'),
                onPressed: _words.text.trim().split(RegExp(r'\s+')).length >= 12 ? () => setState(() => _step = _Step.trust) : null,
                child: const Text('Continue'),
              ),
            ],
            if (_step == _Step.trust) ...[
              Text(trustTitle, style: t.headlineSmall),
              const SizedBox(height: 12),
              for (final p in trustParagraphs)
                Padding(padding: const EdgeInsets.only(bottom: 12), child: Text(p, style: t.bodyMedium)),
              CheckboxListTile(
                key: const Key('trust-check'),
                value: _trustRead,
                onChanged: (v) => setState(() => _trustRead = v ?? false),
                title: const Text('I understand what this wallet trusts'),
                controlAffinity: ListTileControlAffinity.leading,
                contentPadding: EdgeInsets.zero,
              ),
              const SizedBox(height: 12),
              FilledButton(
                key: const Key('next'),
                onPressed: _trustRead ? () => setState(() => _step = _Step.server) : null,
                child: const Text('Continue'),
              ),
            ],
            if (_step == _Step.server) ...[
              Text('Server', style: t.headlineSmall),
              const SizedBox(height: 8),
              Text('The light-client server this wallet trusts (see the statement above).', style: t.bodyMedium),
              const SizedBox(height: 16),
              DropdownButtonFormField<NetworkId>(
                key: const Key('network'),
                initialValue: _network,
                decoration: const InputDecoration(labelText: 'Network'),
                items: [for (final n in NetworkId.values) DropdownMenuItem(value: n, child: Text(n.name))],
                onChanged: (n) => setState(() {
                  _network = n ?? _network;
                  if (_network == NetworkId.mainnet) _plain = false;
                }),
              ),
              const SizedBox(height: 12),
              TextField(
                key: const Key('server'),
                controller: _server,
                autocorrect: false,
                decoration: const InputDecoration(labelText: 'host:port'),
              ),
              if (_network != NetworkId.mainnet)
                SwitchListTile(
                  key: const Key('plain'),
                  value: _plain,
                  onChanged: (v) => setState(() => _plain = v),
                  title: const Text('Plain connection (no TLS; regtest only)'),
                  contentPadding: EdgeInsets.zero,
                ),
              const SizedBox(height: 12),
              OutlinedButton(
                key: const Key('probe'),
                onPressed: _busy ? null : _probe,
                child: Text(_tip == null ? 'Check server' : 'Server ok · tip $_tip'),
              ),
              if (_error != null) Padding(padding: const EdgeInsets.only(top: 8), child: Text(_error!, style: TextStyle(color: c.danger))),
              const SizedBox(height: 24),
              FilledButton(
                key: const Key('next'),
                onPressed: _busy ? null : () => setState(() => _step = _Step.finish),
                child: const Text('Continue'),
              ),
            ],
            if (_step == _Step.finish) ...[
              Text('Unlock', style: t.headlineSmall),
              const SizedBox(height: 8),
              SwitchListTile(
                key: const Key('biometrics'),
                value: _biometrics,
                onChanged: (v) => setState(() => _biometrics = v),
                title: const Text('Ask for the device unlock (Face ID, fingerprint, passcode)'),
                contentPadding: EdgeInsets.zero,
              ),
              const SizedBox(height: 8),
              Text(
                _restoring ? 'The wallet will scan the chain from your birthday height.' : 'A new 12-word recovery phrase will be created and shown once.',
                style: t.bodyMedium,
              ),
              if (_error != null) Padding(padding: const EdgeInsets.only(top: 8), child: Text(_error!, key: const Key('error'), style: TextStyle(color: c.danger))),
              const SizedBox(height: 24),
              FilledButton(
                key: const Key('finish'),
                onPressed: _busy ? null : _finish,
                child: Text(_busy ? 'Working…' : (_restoring ? 'Restore wallet' : 'Create wallet')),
              ),
            ],
          ],
        ),
      ),
    );
  }
}
