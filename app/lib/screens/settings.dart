// Settings (plan §5.1): server, trust statement, seed backup, export private key (WIF, per
// address), import private key, lock, about (build, rpcversion), forget wallet.
import 'package:flutter/material.dart';

import '../state/app_scope.dart';
import '../theme.dart';
import '../trust_text.dart';
import 'keys.dart';
import 'seed_backup.dart';
import 'server.dart';

class SettingsScreen extends StatelessWidget {
  const SettingsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final c = yewColors(context);
    final s = app.settings;
    return Scaffold(
      appBar: AppBar(title: const Text('Settings')),
      body: ListView(
        children: [
          ListTile(
            key: const Key('server'),
            leading: const Icon(Icons.dns_outlined),
            title: const Text('Server'),
            subtitle: Text('${s.server}${s.plain ? ' (plain)' : ''} · ${s.network.name}'),
            onTap: () => Navigator.of(context).push(MaterialPageRoute<void>(builder: (_) => const ServerScreen())),
          ),
          ListTile(
            key: const Key('trust'),
            leading: const Icon(Icons.verified_user_outlined),
            title: const Text('What YEW trusts'),
            subtitle: const Text('The trust statement shown at setup'),
            onTap: () => Navigator.of(context).push(MaterialPageRoute<void>(builder: (_) => const TrustScreen())),
          ),
          const Divider(),
          ListTile(
            key: const Key('seed-backup'),
            leading: const Icon(Icons.key_outlined),
            title: const Text('Recovery phrase'),
            subtitle: const Text('Show the seed words (device unlock)'),
            onTap: () async {
              final words = await app.seedWordsForBackup();
              if (words != null && context.mounted) {
                Navigator.of(context).push(MaterialPageRoute<void>(builder: (_) => SeedBackupScreen(words: words)));
              }
            },
          ),
          ListTile(
            key: const Key('export-key'),
            leading: const Icon(Icons.upload_outlined),
            title: const Text('Export private key'),
            subtitle: const Text('WIF for one address (YecWallet, ycashd)'),
            onTap: () => Navigator.of(context).push(MaterialPageRoute<void>(builder: (_) => const ExportKeyScreen())),
          ),
          ListTile(
            key: const Key('import-key'),
            leading: const Icon(Icons.download_outlined),
            title: const Text('Import private key'),
            subtitle: const Text('A WIF from YecWallet, outside the seed'),
            onTap: () => Navigator.of(context).push(MaterialPageRoute<void>(builder: (_) => const ImportKeyScreen())),
          ),
          SwitchListTile(
            key: const Key('biometrics'),
            secondary: const Icon(Icons.fingerprint_rounded),
            value: s.biometrics,
            onChanged: (v) => app.saveSettings(s.copyWith(biometrics: v)),
            title: const Text('Device unlock'),
            subtitle: const Text('Ask before opening the wallet or showing the phrase'),
          ),
          const Divider(),
          ListTile(
            key: const Key('lock'),
            leading: const Icon(Icons.lock_outline_rounded),
            title: const Text('Lock'),
            subtitle: const Text('Drop the keys from memory'),
            onTap: () async {
              await app.lock();
              if (context.mounted) Navigator.of(context).popUntil((r) => r.isFirst);
            },
          ),
          ListTile(
            key: const Key('about'),
            leading: const Icon(Icons.info_outline_rounded),
            title: const Text('About'),
            subtitle: Text('yew-core ${app.api.coreVersion()}'),
            onTap: () => Navigator.of(context).push(MaterialPageRoute<void>(builder: (_) => const AboutScreen())),
          ),
          const Divider(),
          ListTile(
            key: const Key('forget'),
            leading: Icon(Icons.delete_outline_rounded, color: c.danger),
            title: Text('Forget this wallet', style: TextStyle(color: c.danger)),
            subtitle: const Text('Removes the seed from this device. Only the phrase restores it.'),
            onTap: () async {
              final yes = await showDialog<bool>(
                context: context,
                builder: (ctx) => AlertDialog(
                  title: const Text('Forget this wallet?'),
                  content: const Text('The seed is removed from the keystore. Without your written recovery phrase the YEC and YED are lost.'),
                  actions: [
                    TextButton(onPressed: () => Navigator.of(ctx).pop(false), child: const Text('Keep')),
                    TextButton(key: const Key('forget-yes'), onPressed: () => Navigator.of(ctx).pop(true), child: const Text('Forget')),
                  ],
                ),
              );
              if (yes == true) {
                await app.forgetWallet();
                if (context.mounted) Navigator.of(context).popUntil((r) => r.isFirst);
              }
            },
          ),
        ],
      ),
    );
  }
}

class TrustScreen extends StatelessWidget {
  const TrustScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    return Scaffold(
      appBar: AppBar(title: const Text(trustTitle)),
      body: ListView(
        padding: const EdgeInsets.fromLTRB(24, 8, 24, 32),
        children: [for (final p in trustParagraphs) Padding(padding: const EdgeInsets.only(bottom: 12), child: Text(p, style: t.bodyMedium))],
      ),
    );
  }
}

class AboutScreen extends StatefulWidget {
  const AboutScreen({super.key});

  @override
  State<AboutScreen> createState() => _AboutScreenState();
}

class _AboutScreenState extends State<AboutScreen> {
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => AppScope.read(context).fetchStatus());
  }

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final s = app.status;
    final t = Theme.of(context).textTheme;
    Widget row(String k, String v) => ListTile(dense: true, title: Text(k, style: t.bodySmall), subtitle: SelectableText(v));
    return Scaffold(
      appBar: AppBar(title: const Text('About')),
      body: ListView(
        children: [
          row('YEW', 'Your Electronic Wallet · transparent-only · MIT'),
          row('yew-core', app.api.coreVersion()),
          if (s == null) const ListTile(title: Text('Connecting…')),
          if (s != null) ...[
            row('wallet', s.walletId),
            row('server', '${s.server}${s.plain ? ' (plain)' : ''} · ${s.serverVersion}'),
            row('chain', '${s.chainName} · branch ${s.branchId} · tip ${s.tip}'),
            row('synced to', '${s.syncHeight} (birthday ${s.birthday}, ${s.addresses} addresses)'),
            row(
              'Yellowback',
              s.yellowback.present
                  ? 'rpcversion ${s.yellowback.rpcversion} · enabled ${s.yellowback.enabled} · active ${s.yellowback.active} · fee ${s.yellowback.feeZat} zat · ${s.yellowback.serverVersion}'
                  : 'absent on this server (YEC only)',
            ),
          ],
          if (app.lastError != null) row('error', app.lastError!),
        ],
      ),
    );
  }
}
