// Receive (plan §5.1): one QR (`ye…`), a toggle to the `s…` form, copy, "new address".
import 'package:flutter/material.dart';

import '../state/app_scope.dart';
import '../theme.dart';
import '../widgets/address_qr.dart';

class ReceiveScreen extends StatefulWidget {
  const ReceiveScreen({super.key});

  @override
  State<ReceiveScreen> createState() => _ReceiveScreenState();
}

class _ReceiveScreenState extends State<ReceiveScreen> {
  bool _sForm = false;

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final a = app.receive;
    final c = yewColors(context);
    final t = Theme.of(context).textTheme;
    return Scaffold(
      appBar: AppBar(title: const Text('Receive')),
      body: SafeArea(
        child: a == null
            ? const Center(child: CircularProgressIndicator())
            : ListView(
                padding: const EdgeInsets.fromLTRB(24, 8, 24, 32),
                children: [
                  Center(
                    child: SegmentedButton<bool>(
                      key: const Key('form-toggle'),
                      segments: const [
                        ButtonSegment(value: false, label: Text('ye… (YED and YEC)')),
                        ButtonSegment(value: true, label: Text('s… (YecWallet, Ywallet)')),
                      ],
                      selected: {_sForm},
                      onSelectionChanged: (s) => setState(() => _sForm = s.first),
                    ),
                  ),
                  const SizedBox(height: 20),
                  AddressQr(
                    data: _sForm ? a.s : a.ye,
                    caption: _sForm
                        ? 'The same key in its transparent form: paste it into a wallet that does not know ye… addresses.'
                        : 'Send YED or YEC here. Both forms are the same address.',
                  ),
                  const SizedBox(height: 16),
                  Text(a.path, textAlign: TextAlign.center, style: t.bodySmall?.copyWith(color: c.pending)),
                  const SizedBox(height: 16),
                  TextButton.icon(
                    key: const Key('new-address'),
                    onPressed: app.newReceiveAddress,
                    icon: const Icon(Icons.refresh_rounded),
                    label: const Text('New address'),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    'Everything received here is public on the chain. A new address for each payer keeps them from being linked.',
                    textAlign: TextAlign.center,
                    style: t.bodySmall,
                  ),
                ],
              ),
      ),
    );
  }
}
