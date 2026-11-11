// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

// Send (plan §5.1, §3.7 item 4): asset toggle YED/YEC, address (paste, scan), amount,
// preview (fee in YEC, dry-run verdict for YED), slide to confirm, result. Every error the
// core returns is shown verbatim; a gate refusal is the node's verdict. Post-quantum addresses
// (D-Q-20/D-Q-21): YEC goes to `sq…`, YED to a 53-character `yb…`. Private sending
// (yew-shielded plan §3): the YEC address field also takes `ys1…`, which shows an optional
// message (memo) field; the core funds privacy first and the preview says when a payment
// leaves the private balance; the first private send fetches the proving files once.
// Sends between address types (beta2 D-8): where the wallet holds YEC at its own post-quantum
// addresses, a "From" chooser offers each of them beside the automatic (private first) funding;
// the core plans and signs the post-quantum send (the planner yewd uses) and the preview shows
// the fee, the size and the signing time before the slider. Plain YEC goes to `s…`, `sqf…`
// (FN-DSA-512) or `sqs…` (SLH-DSA); YED to `yb…`/`ybf…`/`ybs…`.
import 'dart:convert' show utf8;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../api/wallet_api.dart';
import '../format.dart';
import '../state/app_scope.dart';
import '../state/app_state.dart';
import '../theme.dart';
import '../widgets/memo_field.dart';
import '../widgets/note_lookup.dart';
import '../widgets/params_sheet.dart';
import '../widgets/preview_card.dart';
import '../widgets/scan_sheet.dart';
import '../widgets/send_error_card.dart';
import '../widgets/send_result.dart';
import '../widgets/slide_to_confirm.dart';
import '../widgets/unusual_fee.dart';

enum Asset { yed, yec }

/// Why a valid address of `kind` (`validateAddress`) is not a destination for `asset`, or null.
/// The post-quantum forms are asset-bound (D-Q-20/D-Q-21): plain YEC goes to `sq…` (testnet
/// `tq…`, regtest `rq…`), YED to the 53-character `yb…` Falcon holder (`yt…`, `yr…`); the core's
/// builders refuse the other way round too, this says so before the preview.
String? destinationMismatch(Asset asset, String kind) {
  if (asset == Asset.yec && kind == 'pq') {
    return 'This is a post-quantum YED address (ybf…/ybs…). To send YEC to the same wallet, ask for its sqf… or sqs… address.';
  }
  if (asset == Asset.yed && kind == 'pq_yec') {
    return 'This is a post-quantum YEC address (sqf…/sqs…): it receives YEC, not YED. Ask for a yb… address.';
  }
  return null;
}

class SendScreen extends StatefulWidget {
  const SendScreen({super.key, this.asset = Asset.yed});
  final Asset asset;

  @override
  State<SendScreen> createState() => _SendScreenState();
}

class _SendScreenState extends State<SendScreen> {
  late Asset _asset = widget.asset;
  final _address = TextEditingController();
  final _amount = TextEditingController();
  final _memo = TextEditingController();
  bool _everything = false;
  bool _busy = false;
  String? _error;
  bool _needYec = false;
  YecPreview? _yec;
  YedPreview? _yed;

  /// The source (beta2 D-8): null = automatic (private first, then public ECC), [privateSource]
  /// = the private balance (to a post-quantum recipient, beta2 D-2), else one of the wallet's
  /// post-quantum addresses.
  String? _from;

  /// The From value of the private balance (never an address).
  static const privateSource = 'private';
  PqSendPreviewInfo? _pq;
  SendResult? _result;

  @override
  void dispose() {
    _address.dispose();
    _amount.dispose();
    _memo.dispose();
    super.dispose();
  }

  void _reset() => setState(() {
    _yec = null;
    _yed = null;
    _pq = null;
    _error = null;
    _needYec = false;
  });

  /// The recipient is a private (`ys1…`) address of the wallet's network (the core decides).
  bool _toPrivate(AppState app) =>
      app.api.validateAddress(network: app.settings.network, address: _address.text.trim()).kind == 'sapling';

  int get _memoBytes => utf8.encode(_memo.text).length;

  Future<void> _preview() async {
    final app = AppScope.read(context);
    final to = _address.text.trim();
    final private = _toPrivate(app);
    if (private && _asset == Asset.yed) {
      setState(() => _error = 'YED can only be sent to a public address (yb… or s…).');
      return;
    }
    if (!private) {
      final check = app.api.validateAddress(network: app.settings.network, address: to);
      if (!check.valid) {
        setState(() => _error = check.message.isEmpty ? 'Not a valid address' : check.message);
        return;
      }
      final wrongAsset = destinationMismatch(_asset, check.kind);
      if (wrongAsset != null) {
        setState(() => _error = wrongAsset);
        return;
      }
    }
    if (private && _memoBytes > maxMemoBytes) {
      setState(() => _error = 'The message is too long: at most $maxMemoBytes bytes.');
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
      _needYec = false;
    });
    try {
      if (_asset == Asset.yed) {
        final cents = parseYedCents(_amount.text);
        if (cents == null || cents <= 0) throw const YewError(kind: ErrorKind.input, message: 'Enter an amount in dollars, like 12.34');
        final p = await app.api.sendYedPreview(recipients: [Recipient(address: to, cents: cents)]);
        setState(() => _yed = p);
      } else {
        if (_from == privateSource) {
          // from the private balance to a post-quantum address (beta2 D-2): proven at the
          // preview, the proving-files sheet first if needed; the core's refusals verbatim
          final zat = parseYecZat(_amount.text);
          if (zat == null || zat <= 0) throw const YewError(kind: ErrorKind.input, message: 'Enter an amount in YEC, up to eight decimals');
          // review YEW-REVIEW-8 M1: the notes' transactions come from the wallet's store; asking
          // the server for missing ones needs the user's go-ahead (the core's text, verbatim)
          var allowLookup = false;
          PqSendPreviewInfo? p;
          for (var attempt = 0; attempt < 3 && p == null; attempt++) {
            try {
              p = await app.api.privatePqSendPreview(to: to, zat: zat, allowNoteLookup: allowLookup);
            } catch (e) {
              if (kindOf(e) == ErrorKind.paramsMissing) {
                if (!mounted || !await preparePrivateSending(context)) return;
              } else if (kindOf(e) == ErrorKind.noteLookupNeeded && !allowLookup) {
                if (!mounted || !await askNoteLookup(context, messageOf(e))) return;
                allowLookup = true;
              } else {
                rethrow;
              }
            }
          }
          if (p == null) return;
          setState(() => _pq = p);
          return;
        }
        if (_from != null) {
          // from a post-quantum address: the core's refusals (the policy, the fee cap,
          // insufficient funds) are shown verbatim. A private (ys1…) recipient is proven at the
          // preview (beta2 item 5): the first time, the one-time proving-files sheet, then the
          // preview again.
          final zat = parseYecZat(_amount.text);
          if (zat == null || zat <= 0) throw const YewError(kind: ErrorKind.input, message: 'Enter an amount in YEC, up to eight decimals');
          PqSendPreviewInfo p;
          try {
            p = await app.api.pqSendPreview(from: _from!, to: to, zat: zat);
          } catch (e) {
            if (kindOf(e) != ErrorKind.paramsMissing) rethrow;
            if (!mounted || !await preparePrivateSending(context)) return;
            p = await app.api.pqSendPreview(from: _from!, to: to, zat: zat);
          }
          setState(() => _pq = p);
          return;
        }
        final everything = _everything && !private;
        final zat = everything ? app.balances.yecZat + app.balances.yecReservedZat - 1000 : parseYecZat(_amount.text);
        if (zat == null || zat <= 0) throw const YewError(kind: ErrorKind.input, message: 'Enter an amount in YEC, up to eight decimals');
        final memo = private && _memo.text.trim().isNotEmpty ? _memo.text : null;
        final p = await app.api.sendYecPreview(to: to, zat: zat, sendEverything: everything, memo: memo);
        setState(() => _yec = p);
      }
    } catch (e) {
      setState(() {
        _error = messageOf(e);
        _needYec = kindOf(e) == ErrorKind.needYecForFees;
      });
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _confirm() async {
    final app = AppScope.read(context);
    try {
      // First private send: the one-time proving-files sheet; the preview stays valid.
      if (_yec != null && _yec!.paramsNeeded && !await preparePrivateSending(context)) return;
      if (!mounted) return;
      final SendResult r;
      if (_yed != null) {
        // review YEW-REVIEW-4 M2: an unusual fee needs its own confirmation
        final ack = await acceptUnusualFee(context, note: _yed!.feeNote, ack: _yed!.unusualFeeAck);
        r = await app.api.sendYedConfirm(previewId: _yed!.previewId, acceptUnusualFee: ack);
      } else if (_pq != null) {
        final ack = await acceptUnusualFee(context, note: _pq!.feeNote, ack: _pq!.unusualFeeAck);
        r = await app.api.pqSendConfirm(previewId: _pq!.previewId, acceptUnusualFee: ack);
      } else {
        r = await _confirmYec(app);
      }
      setState(() => _result = r);
      await app.refresh();
    } on _NotNow {
      return;
    } on UnusualFeeDeclined {
      return; // the preview stays; nothing was sent
    } catch (e) {
      setState(() {
        _error = messageOf(e);
        _yed = null;
        _yec = null;
        _pq = null;
      });
    }
  }

  /// Confirm a YEC preview; a core that finds the proving files missing (the preview did not
  /// say so) gets the sheet once, then the same preview again.
  Future<SendResult> _confirmYec(AppState app) async {
    try {
      return await app.api.sendYecConfirm(previewId: _yec!.previewId);
    } catch (e) {
      if (kindOf(e) != ErrorKind.paramsMissing) rethrow;
      if (!mounted || !await preparePrivateSending(context)) throw _NotNow();
      return app.api.sendYecConfirm(previewId: _yec!.previewId);
    }
  }

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final c = yewColors(context);
    final t = Theme.of(context).textTheme;
    final accent = _asset == Asset.yed ? c.yed : c.yec;
    final hasPreview = _yed != null || _yec != null || _pq != null;
    final private = _asset == Asset.yec && _from == null && _toPrivate(app);
    final sources = app.pqSources;
    // review YEW-REVIEW-3 L5: the chosen source can drop out of the list (spent, a refresh);
    // the dropdown then falls back to Automatic instead of asserting on a missing value
    final listed = _from != null && (_from == privateSource || sources.any((s) => s.address == _from));
    if (_from != null && !listed && _pq == null) {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (mounted && _from != null && _from != privateSource && !AppScope.of(context).pqSources.any((s) => s.address == _from)) {
          setState(() => _from = null);
        }
      });
    }
    final b = app.balances;
    if (_result != null) return SendResultView(result: _result!, accent: accent);
    return Scaffold(
      appBar: AppBar(title: const Text('Send')),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.fromLTRB(20, 8, 20, 32),
          children: [
            SegmentedButton<Asset>(
              key: const Key('asset-toggle'),
              segments: const [
                ButtonSegment(value: Asset.yed, label: Text('YED')),
                ButtonSegment(value: Asset.yec, label: Text('YEC')),
              ],
              selected: {_asset},
              onSelectionChanged: hasPreview
                  ? null
                  : (s) => setState(() {
                      _asset = s.first;
                      _error = null;
                      _needYec = false;
                    }),
            ),
            const SizedBox(height: 16),
            Text(
              _asset == Asset.yed
                  ? '${formatYed(app.balances.yedCents)} YED available'
                  : '${formatYec(b.yecShieldedSpendableZat)} YEC private · ${formatYec(b.yecZat)} YEC public',
              key: const Key('available'),
              style: t.bodyMedium?.copyWith(color: c.pending),
            ),
            if (_asset == Asset.yec && (sources.isNotEmpty || b.yecShieldedSpendableZat > 0)) ...[
              const SizedBox(height: 12),
              // keyed by the listed addresses: a changed list rebuilds the field with a listed value
              KeyedSubtree(
                key: ValueKey('from-${sources.map((s) => s.address).join(',')}'),
                child: DropdownButtonFormField<String?>(
                  key: const Key('from'),
                  initialValue: listed ? _from : null,
                  isExpanded: true,
                  decoration: const InputDecoration(labelText: 'From'),
                  items: [
                    const DropdownMenuItem<String?>(value: null, child: Text('Automatic: private first, then public')),
                    if (b.yecShieldedSpendableZat > 0)
                      DropdownMenuItem<String?>(
                        value: privateSource,
                        child: Text(
                          'Private · ${formatYec(b.yecShieldedSpendableZat)} YEC (to a post-quantum address)',
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                    for (final s in sources)
                      DropdownMenuItem<String?>(
                        value: s.address,
                        child: Text(
                          'Post-quantum ${s.schemeName} · ${shorten(s.address, head: 6, tail: 4)} · ${formatYec(s.balanceZat)} YEC',
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                  ],
                  onChanged: hasPreview
                      ? null
                      : (v) => setState(() {
                          _from = v;
                          _everything = false;
                          _error = null;
                        }),
                ),
              ),
            ],
            const SizedBox(height: 12),
            TextField(
              key: const Key('address'),
              controller: _address,
              enabled: !hasPreview,
              autocorrect: false,
              enableSuggestions: false,
              onChanged: (_) => _reset(),
              decoration: InputDecoration(
                labelText: 'To',
                hintText: _asset == Asset.yed
                    ? 'yb… address'
                    : _from == privateSource
                        ? 'sqf… or sqs… address'
                        : 'ys1…, s…, sqf… or sqs… address',
                suffixIcon: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    IconButton(
                      key: const Key('paste'),
                      tooltip: 'Paste',
                      icon: const Icon(Icons.content_paste_rounded),
                      onPressed: () async {
                        final d = await Clipboard.getData('text/plain');
                        if (d?.text != null) setState(() => _address.text = d!.text!.trim());
                      },
                    ),
                    IconButton(
                      key: const Key('scan'),
                      tooltip: 'Scan',
                      icon: const Icon(Icons.qr_code_scanner_rounded),
                      onPressed: () async {
                        final v = await scanQr(context);
                        if (v != null) setState(() => _address.text = v);
                      },
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 12),
            TextField(
              key: const Key('amount'),
              controller: _amount,
              enabled: !hasPreview && !_everything,
              keyboardType: const TextInputType.numberWithOptions(decimal: true),
              onChanged: (_) => _reset(),
              style: t.headlineMedium,
              decoration: InputDecoration(
                labelText: _asset == Asset.yed ? 'Amount in dollars' : 'Amount in YEC',
                prefixText: _asset == Asset.yed ? '\$ ' : null,
                suffixText: _asset == Asset.yed ? 'YED' : 'YEC',
              ),
            ),
            if (private) ...[
              const SizedBox(height: 12),
              MemoField(controller: _memo, enabled: !hasPreview, bytes: _memoBytes, onChanged: _reset),
            ],
            if (_asset == Asset.yec && !private && _from == null)
              SwitchListTile(
                key: const Key('everything'),
                value: _everything,
                onChanged: hasPreview ? null : (v) => setState(() => _everything = v),
                title: const Text('Send everything, including the fee reserve'),
                subtitle: const Text('Leaves no YEC to send YED with'),
                contentPadding: EdgeInsets.zero,
              ),
            const SizedBox(height: 16),
            if (!hasPreview)
              FilledButton(
                key: const Key('preview'),
                onPressed: _busy || (private && _memoBytes > maxMemoBytes) ? null : _preview,
                style: FilledButton.styleFrom(backgroundColor: accent),
                child: Text(_busy ? 'Building…' : 'Preview'),
              ),
            if (_error != null) ...[
              const SizedBox(height: 12),
              SendErrorCard(message: _error!, needYec: _needYec),
            ],
            if (_yec != null) YecPreviewCard(_yec!),
            if (_yed != null) YedPreviewCard(_yed!),
            if (_pq != null) PqSendPreviewCard(_pq!),
            if (hasPreview) ...[
              const SizedBox(height: 16),
              SlideToConfirm(
                label: _yed != null
                    ? 'Slide to send ${formatYed(_yed!.totalCents)}'
                    : 'Slide to send ${formatYec((_pq?.amountZat ?? _yec!.amountZat))} YEC',
                color: accent,
                enabled: _yed == null || _yed!.dryRun.accepted,
                onConfirmed: _confirm,
              ),
              const SizedBox(height: 8),
              TextButton(key: const Key('cancel'), onPressed: _reset, child: const Text('Cancel')),
            ],
          ],
        ),
      ),
    );
  }
}

/// The user closed the proving-files sheet: the preview stays, nothing is sent.
class _NotNow implements Exception {}
