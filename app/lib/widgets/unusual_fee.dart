// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

// The separate confirmation of an unusual fee (review YEW-REVIEW-4 M2). The core flags a fee
// priced from the server's terms that is well above the usual fee for the transaction's size at
// the highest YEC price this wallet has seen, and refuses the confirm call unless the preview's
// acknowledgement comes back with it. The slider alone never sends such a fee: this dialog shows
// the core's text (the fee in YEC, how many times the usual fee it is, that the terms came from
// the server) and returns the acknowledgement only when the user accepts it.
import 'package:flutter/material.dart';

/// The user declined an unusual fee: nothing is sent.
class UnusualFeeDeclined implements Exception {
  const UnusualFeeDeclined();
}

/// `null` when the preview's fee is not flagged (`ack` null); otherwise the acknowledgement, after
/// the user accepted [note] in a dialog. Throws [UnusualFeeDeclined] when the user declines.
Future<String?> acceptUnusualFee(BuildContext context, {required String? note, required String? ack}) async {
  if (ack == null) return null;
  final ok = await showDialog<bool>(
    context: context,
    barrierDismissible: false,
    builder: (ctx) => AlertDialog(
      key: const Key('unusual-fee-dialog'),
      title: const Text('Unusual fee'),
      content: Text(note ?? 'This fee is unusually high.', key: const Key('unusual-fee-note')),
      actions: [
        TextButton(key: const Key('unusual-fee-cancel'), onPressed: () => Navigator.of(ctx).pop(false), child: const Text('Cancel')),
        FilledButton(key: const Key('unusual-fee-accept'), onPressed: () => Navigator.of(ctx).pop(true), child: const Text('Pay this fee')),
      ],
    ),
  );
  if (ok != true) throw const UnusualFeeDeclined();
  return ack;
}
