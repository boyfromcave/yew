// Seed backup: the recovery phrase, shown once after creation and from Settings (behind the
// device prompt). The words come from the keystore through AppState, never from the core.
import 'package:flutter/material.dart';

import '../state/screen_privacy.dart';
import '../theme.dart';

class SeedBackupScreen extends StatefulWidget {
  const SeedBackupScreen({super.key, required this.words, this.firstTime = false});

  final String words;
  final bool firstTime;

  @override
  State<SeedBackupScreen> createState() => _SeedBackupScreenState();
}

class _SeedBackupScreenState extends State<SeedBackupScreen> {
  bool _written = false;

  @override
  void initState() {
    super.initState();
    setScreenSecure(true);
  }

  @override
  void dispose() {
    setScreenSecure(false);
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    final c = yewColors(context);
    final words = widget.words.trim().split(RegExp(r'\s+'));
    return Scaffold(
      appBar: AppBar(title: const Text('Recovery phrase'), automaticallyImplyLeading: !widget.firstTime),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.fromLTRB(24, 8, 24, 32),
          children: [
            Text(
              'These ${words.length} words are the wallet. Anyone with them can spend your YEC and YED. '
              'Write them down, in order, and keep them offline. YEW never shows them again without the device unlock.',
              style: t.bodyMedium,
            ),
            const SizedBox(height: 16),
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Wrap(
                  spacing: 8,
                  runSpacing: 8,
                  children: [
                    for (var i = 0; i < words.length; i++)
                      Chip(
                        key: Key('word-$i'),
                        label: Text('${i + 1}. ${words[i]}', style: t.bodyLarge),
                        backgroundColor: c.yed.withValues(alpha: 0.10),
                        side: BorderSide.none,
                      ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 16),
            Text('Restores in Ywallet too (same address at m/44\'/347\'/0\'/0/0).', style: t.bodySmall),
            if (widget.firstTime) ...[
              const SizedBox(height: 16),
              CheckboxListTile(
                key: const Key('written'),
                value: _written,
                onChanged: (v) => setState(() => _written = v ?? false),
                title: const Text('I have written the words down'),
                controlAffinity: ListTileControlAffinity.leading,
                contentPadding: EdgeInsets.zero,
              ),
              const SizedBox(height: 8),
              FilledButton(
                key: const Key('done'),
                onPressed: _written ? () => Navigator.of(context).pop() : null,
                child: const Text('Open the wallet'),
              ),
            ],
          ],
        ),
      ),
    );
  }
}
