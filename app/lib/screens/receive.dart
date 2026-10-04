// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

// Receive (plan §5.1; yew-shielded plan §3): one QR. The private `ys1…` address by default once
// the private balance has synced; a toggle to the public `s…` address and to the YED `ye…`
// form; copy; "new address" (a new private address on the private tab).
import 'package:flutter/material.dart';

import '../api/wallet_api.dart';
import '../state/app_scope.dart';
import '../theme.dart';
import '../widgets/address_qr.dart';

class ReceiveScreen extends StatefulWidget {
  const ReceiveScreen({super.key, this.kind});

  /// Open on this tab (Mint / Send YED: the YED form); null = private once synced, else YED.
  final ReceiveKind? kind;

  @override
  State<ReceiveScreen> createState() => _ReceiveScreenState();
}

class _ReceiveScreenState extends State<ReceiveScreen> {
  ReceiveKind? _kind;

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final a = app.receive;
    final z = app.receivePrivate;
    final c = yewColors(context);
    final t = Theme.of(context).textTheme;
    final kind = _kind ?? widget.kind ?? (z != null && app.balances.shieldedScannedHeight > 0 ? ReceiveKind.shielded : ReceiveKind.yed);
    final private = kind == ReceiveKind.shielded;
    final String? data = switch (kind) {
      ReceiveKind.shielded => z?.address,
      ReceiveKind.transparent => a?.s,
      ReceiveKind.yed => a?.ye,
    };
    return Scaffold(
      appBar: AppBar(title: const Text('Receive')),
      body: SafeArea(
        child: a == null
            ? const Center(child: CircularProgressIndicator())
            : ListView(
                padding: const EdgeInsets.fromLTRB(24, 8, 24, 32),
                children: [
                  Center(
                    child: SegmentedButton<ReceiveKind>(
                      key: const Key('form-toggle'),
                      segments: [
                        if (z != null) const ButtonSegment(value: ReceiveKind.shielded, label: Text('Private'), icon: Icon(Icons.lock_rounded)),
                        const ButtonSegment(value: ReceiveKind.transparent, label: Text('Public')),
                        const ButtonSegment(value: ReceiveKind.yed, label: Text('YED')),
                      ],
                      selected: {kind},
                      onSelectionChanged: (s) => setState(() => _kind = s.first),
                    ),
                  ),
                  const SizedBox(height: 20),
                  if (data != null)
                    AddressQr(
                      data: data,
                      caption: switch (kind) {
                        ReceiveKind.shielded => 'Send YEC here privately. The amount and any message are hidden on the chain.',
                        ReceiveKind.transparent => 'Your public Ycash address, for any Ycash wallet (YecWallet, Ywallet).',
                        ReceiveKind.yed => 'Send YED or YEC here. Same key as your public address.',
                      },
                    ),
                  const SizedBox(height: 16),
                  if (!private) Text(a.path, textAlign: TextAlign.center, style: t.bodySmall?.copyWith(color: c.pending)),
                  const SizedBox(height: 16),
                  TextButton.icon(
                    key: const Key('new-address'),
                    onPressed: private ? app.newPrivateAddress : app.newReceiveAddress,
                    icon: const Icon(Icons.refresh_rounded),
                    label: Text(private ? 'New private address' : 'New address'),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    private
                        ? 'Every private address reaches the same private balance, and they cannot be linked to each other.'
                        : 'Everything received here is public on the chain. A new address for each payer keeps them from being linked.',
                    textAlign: TextAlign.center,
                    style: t.bodySmall,
                  ),
                ],
              ),
      ),
    );
  }
}
