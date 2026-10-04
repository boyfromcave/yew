// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

// The one-time "Preparing private sending" sheet (yew-shielded plan §3, S0-2): the first
// private send downloads the Sapling proving files (52 MB) from the standard source (the one
// ycashd uses; a Ycash mirror first once one exists), or from the address set in Settings; the
// core keeps them only if their SHA-256s match its pins.
import 'dart:async';

import 'package:flutter/material.dart';

import '../api/wallet_api.dart';
import '../state/app_scope.dart';
import '../state/app_state.dart';

/// Show the sheet; true once the files are in place (the send may go on), false otherwise.
Future<bool> preparePrivateSending(BuildContext context) async {
  final ok = await showModalBottomSheet<bool>(
    context: context,
    isScrollControlled: true,
    isDismissible: false,
    enableDrag: false,
    builder: (_) => const ParamsSheet(),
  );
  return ok ?? false;
}

/// The Settings field for the download address (also offered by the sheet).
Future<void> editParamsUrl(BuildContext context, AppState app) async {
  final url = await showDialog<String>(context: context, builder: (_) => _UrlDialog(initial: app.settings.paramsUrl));
  if (url != null) await app.saveSettings(app.settings.copyWith(paramsUrl: url));
}

/// Owns its controller, so the dialog's closing animation never sees a disposed one.
class _UrlDialog extends StatefulWidget {
  const _UrlDialog({required this.initial});
  final String initial;

  @override
  State<_UrlDialog> createState() => _UrlDialogState();
}

class _UrlDialogState extends State<_UrlDialog> {
  late final _ctl = TextEditingController(text: widget.initial);

  @override
  void dispose() {
    _ctl.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => AlertDialog(
    title: const Text('Private sending files'),
    content: TextField(
      key: const Key('params-url-field'),
      controller: _ctl,
      autocorrect: false,
      keyboardType: TextInputType.url,
      decoration: const InputDecoration(labelText: 'Download address', hintText: 'https://…/'),
    ),
    actions: [
      TextButton(onPressed: () => Navigator.of(context).pop(), child: const Text('Cancel')),
      TextButton(key: const Key('params-url-save'), onPressed: () => Navigator.of(context).pop(_ctl.text.trim()), child: const Text('Save')),
    ],
  );
}

class ParamsSheet extends StatefulWidget {
  const ParamsSheet({super.key});

  @override
  State<ParamsSheet> createState() => _ParamsSheetState();
}

class _ParamsSheetState extends State<ParamsSheet> {
  StreamSubscription<ParamsProgress>? _sub;
  ParamsProgress? _progress;
  String? _error;

  @override
  void dispose() {
    _sub?.cancel();
    super.dispose();
  }

  void _start(AppState app) {
    setState(() {
      _error = null;
      _progress = const ParamsProgress(file: '', doneBytes: 0, totalBytes: 0, finished: false);
    });
    _sub = app.api.downloadParams(baseUrl: app.settings.paramsUrl).listen(
      (p) {
        setState(() => _progress = p);
        if (p.finished && mounted) Navigator.of(context).pop(true);
      },
      onError: (Object e) => setState(() {
        _error = messageOf(e);
        _progress = null;
        _sub = null;
      }),
    );
  }

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final t = Theme.of(context).textTheme;
    final p = _progress;
    final running = p != null;
    String mb(int b) => (b / 1000000).toStringAsFixed(1);
    return SafeArea(
      child: Padding(
        padding: const EdgeInsets.fromLTRB(24, 20, 24, 24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Preparing private sending (52 MB, once)', key: const Key('params-title'), style: t.titleLarge),
            const SizedBox(height: 12),
            Text(
              'Sending from your private balance needs two files that prove a payment without revealing it. '
              'YEW downloads them once, checks them against fingerprints built into the app, and keeps them on this phone.',
              style: t.bodyMedium,
            ),
            const SizedBox(height: 16),

            if (running) ...[
              LinearProgressIndicator(key: const Key('params-progress'), value: p.totalBytes > 0 ? p.doneBytes / p.totalBytes : null),
              const SizedBox(height: 8),
              Text(p.totalBytes > 0 ? '${mb(p.doneBytes)} of ${mb(p.totalBytes)} MB' : 'Starting…', style: t.bodySmall),
            ],
            if (_error != null) ...[
              const SizedBox(height: 8),
              Text(_error!, key: const Key('params-error'), style: t.bodyMedium?.copyWith(color: Theme.of(context).colorScheme.error)),
            ],
            const SizedBox(height: 16),
            FilledButton(
              key: const Key('params-download'),
              onPressed: running ? null : () => _start(app),
              child: Text(_error != null ? 'Try again' : 'Download'),
            ),
            const SizedBox(height: 8),
            // A different address (a mirror, or a copy on this phone) when the standard source is
            // unreachable; the files are checked against the same fingerprints either way.
            TextButton(
              key: const Key('params-set-url'),
              onPressed: running ? null : () => editParamsUrl(context, app),
              child: const Text('Use another address'),
            ),
            TextButton(
              key: const Key('params-cancel'),
              onPressed: () => Navigator.of(context).pop(false),
              child: const Text('Not now'),
            ),
          ],
        ),
      ),
    );
  }
}
