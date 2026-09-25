// The QR scanner, in a bottom sheet opened on demand (the camera plugin is never built
// otherwise, so widget tests can render the Send screen).
import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

/// Opens the scanner; resolves with the first QR text, or null when dismissed.
Future<String?> scanQr(BuildContext context) => showModalBottomSheet<String>(
  context: context,
  isScrollControlled: true,
  builder: (_) => const _ScanSheet(),
);

class _ScanSheet extends StatefulWidget {
  const _ScanSheet();

  @override
  State<_ScanSheet> createState() => _ScanSheetState();
}

class _ScanSheetState extends State<_ScanSheet> {
  bool _done = false;

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      height: MediaQuery.sizeOf(context).height * 0.7,
      child: Column(
        children: [
          const SizedBox(height: 12),
          Text('Scan an address', style: Theme.of(context).textTheme.titleMedium),
          const SizedBox(height: 12),
          Expanded(
            child: ClipRRect(
              borderRadius: BorderRadius.circular(16),
              child: MobileScanner(
                onDetect: (capture) {
                  if (_done) return;
                  for (final b in capture.barcodes) {
                    final v = b.rawValue;
                    if (v != null && v.isNotEmpty) {
                      _done = true;
                      Navigator.of(context).pop(_strip(v));
                      return;
                    }
                  }
                },
              ),
            ),
          ),
          TextButton(onPressed: () => Navigator.of(context).pop(), child: const Text('Cancel')),
          const SizedBox(height: 12),
        ],
      ),
    );
  }

  /// `ycash:ADDR?…` and plain addresses both yield the address.
  static String _strip(String v) {
    var s = v.trim();
    final colon = s.indexOf(':');
    if (colon > 0 && !s.substring(0, colon).contains(RegExp(r'[^a-zA-Z]'))) s = s.substring(colon + 1);
    final q = s.indexOf('?');
    return q >= 0 ? s.substring(0, q) : s;
  }
}
