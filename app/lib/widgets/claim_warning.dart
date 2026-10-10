// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

// The persistent claim warning (hardening H-9.2, reshaped by the in-term claims plan's IT-8:
// "your wallet will warn you, and redeeming stops it"). Since in-term claims anyone may close an
// ACTIVE vault at any height once its collateral is under θ (125 %) × its debt at the claim
// price, so the danger is the price, not a height: the banner shows while a vault is claimable
// now or the claim price is within 25 % above its claimable-at price (`underwaterAt`). It cannot
// be dismissed (it goes away when the vault is redeemed or the price recovers). The flags are the
// core's (`VaultSummary.claimWarning`, `claimable`, `nearThreshold`).
import 'package:flutter/material.dart';

import '../api/wallet_api.dart';
import '../format.dart';
import '../screens/vault.dart';
import '../theme.dart';

/// The one-line text of a vault's claim warning (in-term IT-8).
String claimDeadlineText(VaultSummary v) {
  final at = v.underwaterAtMicroUsd > 0 ? formatUsdPerYec(v.underwaterAtMicroUsd) : 'an undefined price';
  final now = v.claimPriceMicroUsd > 0 ? ' (now ${formatUsdPerYec(v.claimPriceMicroUsd)})' : '';
  final fee = v.earlyRedeem && v.earlyRedeemFeeBps > 0 ? ' Redeeming before the term ends costs the early-redeem fee of ${formatBps(v.earlyRedeemFeeBps)} of the collateral.' : '';
  if (v.claimable) {
    return 'CLAIMABLE NOW: its collateral is worth less than ${formatBps(v.claimThresholdBps)} of its debt at the claim price$now. Anyone may close it by paying its debt, and you would usually receive nothing back. Redeem now to stop it.$fee';
  }
  return 'Warning: the claim price$now is within ${formatBps(2500)} above $at, the price below which anyone may close this vault by paying its debt. Redeem to stop a claim.$fee';
}

class ClaimWarningBanner extends StatelessWidget {
  const ClaimWarningBanner({super.key, required this.vaults});
  final List<VaultSummary> vaults;

  @override
  Widget build(BuildContext context) {
    final due = vaults.where((v) => v.claimWarning).toList();
    if (due.isEmpty) return const SizedBox.shrink();
    final c = yewColors(context);
    final t = Theme.of(context).textTheme;
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: Card(
        key: const Key('claim-warning-banner'),
        color: c.danger.withValues(alpha: 0.10),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 14, 16, 4),
              child: Row(
                children: [
                  Icon(Icons.warning_amber_rounded, color: c.danger),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      due.any((v) => v.claimable)
                          ? (due.length == 1 ? 'A vault is claimable now' : '${due.length} vaults are claimable or near their claim threshold')
                          : (due.length == 1 ? 'A vault is near its claim threshold' : '${due.length} vaults are near their claim threshold'),
                      style: t.titleSmall,
                    ),
                  ),
                ],
              ),
            ),
            for (final v in due)
              ListTile(
                key: Key('claim-warning-${v.vaultTxid}'),
                dense: true,
                title: Text('${formatYed(v.cents)} · ${formatYec(v.collateralZat)} YEC'),
                subtitle: Text(claimDeadlineText(v)),
                trailing: const Icon(Icons.chevron_right_rounded),
                onTap: () => Navigator.of(context).push(MaterialPageRoute<void>(builder: (_) => VaultScreen(vaultTxid: v.vaultTxid))),
              ),
          ],
        ),
      ),
    );
  }
}
