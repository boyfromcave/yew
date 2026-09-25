// A QR with its text and a copy action (Receive; the export-key screen reuses it).
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:qr_flutter/qr_flutter.dart';

class AddressQr extends StatelessWidget {
  const AddressQr({super.key, required this.data, this.caption, this.size = 220});

  final String data;
  final String? caption;
  final double size;

  @override
  Widget build(BuildContext context) {
    final text = Theme.of(context).textTheme;
    return Column(
      children: [
        Container(
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(color: Colors.white, borderRadius: BorderRadius.circular(16)),
          child: QrImageView(data: data, size: size, backgroundColor: Colors.white),
        ),
        if (caption != null) ...[
          const SizedBox(height: 8),
          Text(caption!, style: text.labelMedium),
        ],
        const SizedBox(height: 8),
        SelectableText(
          data,
          key: const Key('qr-text'),
          textAlign: TextAlign.center,
          style: text.bodyMedium?.copyWith(fontFamily: 'monospace'),
        ),
        const SizedBox(height: 8),
        OutlinedButton.icon(
          key: const Key('copy'),
          onPressed: () async {
            await Clipboard.setData(ClipboardData(text: data));
            if (context.mounted) {
              ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Copied')));
            }
          },
          icon: const Icon(Icons.copy_rounded),
          label: const Text('Copy'),
        ),
      ],
    );
  }
}
