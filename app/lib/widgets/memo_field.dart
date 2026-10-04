// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

// The optional message (memo) of a private payment (yew-shielded plan §3): shown only for a
// private recipient, at most 512 UTF-8 bytes, with a live byte counter.
import 'package:flutter/material.dart';

import '../api/wallet_api.dart';

class MemoField extends StatelessWidget {
  const MemoField({super.key, required this.controller, required this.enabled, required this.bytes, required this.onChanged});

  final TextEditingController controller;
  final bool enabled;

  /// The UTF-8 length of the current text.
  final int bytes;
  final VoidCallback onChanged;

  @override
  Widget build(BuildContext context) => TextField(
    key: const Key('memo'),
    controller: controller,
    enabled: enabled,
    minLines: 1,
    maxLines: 4,
    onChanged: (_) => onChanged(),
    decoration: InputDecoration(
      labelText: 'Message (optional)',
      helperText: 'Only the recipient can read it',
      counterText: '$bytes / $maxMemoBytes bytes',
      errorText: bytes > maxMemoBytes ? 'Too long: at most $maxMemoBytes bytes' : null,
    ),
  );
}
