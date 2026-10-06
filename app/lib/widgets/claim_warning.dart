// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

// The persistent deadline warning (hardening H-9.2): from `claimHeight − 1 day` an ACTIVE vault
// may be claimed by a liquidator as soon as it is underwater, so the owner should redeem or
// renew it. The banner shows on Home and on the Yellowback tab while any vault is in that
// window; it cannot be dismissed (it goes away when the vault is redeemed, renewed or closed).
// The flag and the dates are the core's (`VaultSummary.claimWarning`, `claimTimeSecs`).
import 'package:flutter/material.dart';

import '../api/wallet_api.dart';
import '../format.dart';
import '../screens/vault.dart';
import '../theme.dart';

/// The one-line text of a vault's claim deadline.
String claimDeadlineText(VaultSummary v) => v.claimOpen
    ? 'The claim path of this vault is open since ${formatDeadline(v.claimHeight, v.claimTimeSecs)}: a liquidator may claim it as soon as it is underwater. Redeem or renew it now.'
    : 'From ${formatDeadline(v.claimHeight, v.claimTimeSecs)} a liquidator may claim this vault if it is underwater. Redeem or renew it before then.';

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
                  Icon(Icons.schedule_rounded, color: c.danger),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      due.length == 1 ? 'A vault reaches its claim height' : '${due.length} vaults reach their claim height',
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
