// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

// The go-ahead before a public send or a move to private combines coins of several of the
// wallet's public addresses in one transaction (beta2 D-5). Anyone reading the chain then sees
// that those addresses belong to the same wallet; ycashd's z_sendmany refuses the same
// transaction under its default privacy policy. The core takes one address's coins by default,
// refuses with ErrorKind.addressLinkingNeeded when only several together cover the amount, and
// this dialog shows its text verbatim.
import 'package:flutter/material.dart';

/// True when the user agreed to link the addresses; false (nothing sent) otherwise.
Future<bool> askAddressLinking(BuildContext context, String message) async {
  final ok = await showDialog<bool>(
    context: context,
    barrierDismissible: false,
    builder: (ctx) => AlertDialog(
      key: const Key('address-linking-dialog'),
      title: const Text('Link your public addresses?'),
      content: Text(message, key: const Key('address-linking-text')),
      actions: [
        TextButton(key: const Key('address-linking-cancel'), onPressed: () => Navigator.of(ctx).pop(false), child: const Text('Cancel')),
        FilledButton(key: const Key('address-linking-accept'), onPressed: () => Navigator.of(ctx).pop(true), child: const Text('Combine and link them')),
      ],
    ),
  );
  return ok == true;
}
