// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

// The go-ahead before the app asks the server for the transactions that created the private
// notes a payment spends (review YEW-REVIEW-8 M1). The core reads them from the wallet's own
// store; only notes received since the last sync's memo pass are missing there, and fetching
// them just before the spend tells the server which notes the payment spends. The core refuses
// with ErrorKind.noteLookupNeeded and this dialog shows its text verbatim.
import 'package:flutter/material.dart';

/// True when the user agreed to ask the server; false (nothing sent) otherwise.
Future<bool> askNoteLookup(BuildContext context, String message) async {
  final ok = await showDialog<bool>(
    context: context,
    barrierDismissible: false,
    builder: (ctx) => AlertDialog(
      key: const Key('note-lookup-dialog'),
      title: const Text('Ask the server?'),
      content: Text(message, key: const Key('note-lookup-text')),
      actions: [
        TextButton(key: const Key('note-lookup-cancel'), onPressed: () => Navigator.of(ctx).pop(false), child: const Text('Cancel')),
        FilledButton(key: const Key('note-lookup-accept'), onPressed: () => Navigator.of(ctx).pop(true), child: const Text('Ask the server')),
      ],
    ),
  );
  return ok == true;
}
