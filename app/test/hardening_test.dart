// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

// Hardening H5-b (docs/plans/yellowback-evidence-based-hardening-plan.md §3.4 H-9, §9 H5-b;
// upgrade plan §7): the mint gate (mintRequiresArmed, armed, empty mintableClasses), the vault
// deadlines as dates with renew and the persistent claim warning (no sunset warning), and the
// claim bounds the core is handed.
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:yew_app/api/wallet_api.dart';
import 'package:yew_app/format.dart';

import 'claimable_test.dart' show claimable1, openClaimable;
import 'fake_wallet_api.dart';
import 'mint_test.dart' show openMint;
import 'vault_test.dart' show openVault;

const _unarmed = MintAvailability(
  allowed: false,
  reason: 'Minting is paused: the price feed is not armed (attestation PENDING). The node refuses every mint until enough attestors arm it. Redeeming and claiming are not affected.',
  mintRequiresArmed: true,
  armed: false,
  attestStatus: 'PENDING',
  mintableClasses: [],
  enabledClasses: ['A', 'B', 'C'],
  halts: [],
);

void main() {
  testWidgets('mint gate: unarmed under mintRequiresArmed blocks the form with the reason', (tester) async {
    final h = Harness(withWallet: true);
    h.api.availability = _unarmed;
    await openMint(tester, h);
    expect(h.api.calls, contains('mintAvailability'));
    expect(find.byKey(const Key('mint-blocked')), findsOneWidget);
    expect(find.text(_unarmed.reason), findsOneWidget);
    expect(tester.widget<FilledButton>(find.byKey(const Key('estimate'))).onPressed, isNull);
    expect(tester.widget<TextField>(find.byKey(const Key('amount'))).enabled, isFalse);
    // Check again: the gate opened (the attestors armed).
    h.api.availability = null;
    await tester.tap(find.byKey(const Key('mint-recheck')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('mint-blocked')), findsNothing);
    expect(tester.widget<FilledButton>(find.byKey(const Key('estimate'))).onPressed, isNotNull);
    expect(h.api.calls.where((c) => c.startsWith('mintEstimate')), isEmpty);
  });

  testWidgets('mint gate: empty mintableClasses = no class mintable; nothing is estimated', (tester) async {
    final h = Harness(withWallet: true);
    h.api.availability = const MintAvailability(
      allowed: false,
      reason: 'Minting is halted (GLOBAL_RATIO): no term class is mintable now.',
      mintRequiresArmed: false,
      armed: true,
      attestStatus: 'ARMED',
      mintableClasses: [],
      enabledClasses: ['A', 'B', 'C'],
      halts: ['GLOBAL_RATIO'],
    );
    await openMint(tester, h);
    expect(find.text('Minting is halted (GLOBAL_RATIO): no term class is mintable now.'), findsOneWidget);
    expect(tester.widget<FilledButton>(find.byKey(const Key('estimate'))).onPressed, isNull);
    final seg = tester.widget<SegmentedButton<String>>(find.byKey(const Key('term-class')));
    expect(seg.segments.every((s) => !s.enabled), isTrue);
  });

  testWidgets('mint gate: only the mintable classes can be picked (class A only)', (tester) async {
    final h = Harness(withWallet: true);
    h.api.availability = const MintAvailability(allowed: true, reason: '', mintRequiresArmed: true, armed: true, attestStatus: 'ARMED', mintableClasses: ['A'], enabledClasses: ['A', 'B', 'C'], halts: []);
    await openMint(tester, h);
    final seg = tester.widget<SegmentedButton<String>>(find.byKey(const Key('term-class')));
    expect({for (final s in seg.segments) s.value: s.enabled}, {'A': true, 'B': false, 'C': false});
    // A lock typed into class B is refused on screen, before the core is asked.
    await tester.enterText(find.byKey(const Key('amount')), '25');
    await tester.enterText(find.byKey(const Key('lock-blocks')), '100');
    await tester.tap(find.byKey(const Key('estimate')));
    await tester.pumpAndSettle();
    expect(find.text('Class B is not mintable now'), findsOneWidget);
    expect(h.api.calls.where((c) => c.startsWith('mintEstimate')), isEmpty);
    await tester.enterText(find.byKey(const Key('lock-blocks')), '48');
    await tester.tap(find.byKey(const Key('estimate')));
    await tester.pumpAndSettle();
    expect(h.api.calls, contains('mintEstimate 2500 48'));
  });

  testWidgets('mint gate: a mint-blocked refusal at the estimate re-reads the gate and blocks', (tester) async {
    final h = Harness(withWallet: true);
    await openMint(tester, h);
    h.api.mintEstimateError = const YewError(kind: ErrorKind.mintBlocked, message: 'the price is not armed at the reference height 480');
    h.api.availability = _unarmed;
    await tester.enterText(find.byKey(const Key('amount')), '25');
    await tester.tap(find.byKey(const Key('estimate')));
    await tester.pumpAndSettle();
    expect(find.text('the price is not armed at the reference height 480'), findsOneWidget);
    expect(find.byKey(const Key('mint-blocked')), findsOneWidget);
    expect(h.api.calls.where((c) => c == 'mintAvailability').length, 2);
  });

  testWidgets('deadlines: an ACTIVE vault shows the end of its term as a date and its claimable-at price; no renew and no warning yet', (tester) async {
    final h = Harness(withWallet: true);
    final txid = 'd1' * 32;
    h.api.vaultsAnswer = [h.api.vault(txid: txid, lockHeight: 528)];
    await openVault(tester, h, txid);
    expect(find.byKey(const Key('lock-date')), findsOneWidget);
    // In-term claims: no claim height to show; the claim opens at the threshold, at any height.
    expect(find.byKey(const Key('claim-date')), findsNothing);
    expect(find.byKey(const Key('claimable-at')), findsOneWidget);
    expect(find.text(formatDate(FakeWalletApi.nowSecs + 44 * 75)), findsOneWidget);
    expect(find.byKey(const Key('renew')), findsNothing);
    expect(find.byKey(const Key('claim-warning')), findsNothing);
    expect(find.textContaining('sunset'), findsNothing);
  });

  testWidgets('renew: from lockHeight, redeem then the mint of the same amount and term in one flow', (tester) async {
    final h = Harness(withWallet: true);
    final txid = 'd2' * 32;
    h.api.vaultsAnswer = [h.api.vault(txid: txid, lockHeight: 470, cents: 3000)];
    await openVault(tester, h, txid);
    expect(find.byKey(const Key('preview')), findsOneWidget);
    await tester.tap(find.byKey(const Key('renew')));
    await tester.pumpAndSettle();
    expect(h.api.calls, contains('redeemPreview $txid'));
    expect(find.byKey(const Key('renew-step')), findsOneWidget);
    expect(find.text('Slide to renew: burn \$30.00, pay 0.50000000 YEC fee'), findsOneWidget);
    await tester.longPress(find.byKey(const Key('slide-to-confirm')));
    await tester.pumpAndSettle();
    expect(h.api.calls, contains('redeemConfirm rp-$txid'));
    expect(find.text('Vault redeemed'), findsOneWidget);
    await tester.tap(find.byKey(const Key('remint')));
    await tester.pumpAndSettle();
    // Step 2: the Mint screen with the vault's amount and term, after the gate.
    expect(find.byKey(const Key('renew-banner')), findsOneWidget);
    expect(h.api.calls, contains('mintAvailability'));
    expect(tester.widget<TextField>(find.byKey(const Key('amount'))).controller!.text, '30.00');
    expect(tester.widget<TextField>(find.byKey(const Key('lock-blocks'))).controller!.text, '48');
    await tester.tap(find.byKey(const Key('estimate')));
    await tester.pumpAndSettle();
    expect(h.api.calls, contains('mintEstimate 3000 48'));
  });

  testWidgets('a plain redeem from lockHeight offers no re-mint', (tester) async {
    final h = Harness(withWallet: true);
    final txid = 'd3' * 32;
    h.api.vaultsAnswer = [h.api.vault(txid: txid, lockHeight: 470, cents: 3000)];
    await openVault(tester, h, txid);
    await tester.tap(find.byKey(const Key('preview')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('renew-step')), findsNothing);
    await tester.longPress(find.byKey(const Key('slide-to-confirm')));
    await tester.pumpAndSettle();
    expect(find.text('Vault redeemed'), findsOneWidget);
    expect(find.byKey(const Key('remint')), findsNothing);
  });

  testWidgets('claim warning (in-term IT-8): within 25 % above the claimable-at price, persistent on Home, the Yellowback tab and the vault', (tester) async {
    final h = Harness(withWallet: true);
    final due = 'd4' * 32;
    final calm = 'd5' * 32;
    // Both claimable below $0.40: the due one's claim price $0.45 is within 25 % of it, the calm one's $0.52 is not.
    h.api.vaultsAnswer = [h.api.vault(txid: due, lockHeight: 465, claimPrice: 450000), h.api.vault(txid: calm, lockHeight: 528)];
    await h.pump(tester);
    expect(find.byKey(const Key('claim-warning-banner')), findsOneWidget);
    expect(find.byKey(Key('claim-warning-$due')), findsOneWidget);
    expect(find.byKey(Key('claim-warning-$calm')), findsNothing);
    expect(find.text('A vault is near its claim threshold'), findsOneWidget);
    expect(find.textContaining('the price below which anyone may close this vault by paying its debt'), findsOneWidget);
    await tester.tap(find.byKey(const Key('tab-yellowback')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('claim-warning-banner')), findsOneWidget);
    await tester.tap(find.byKey(Key('claim-warning-$due')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('claim-warning')), findsOneWidget);
    expect(find.byKey(const Key('renew')), findsOneWidget);
    expect(find.textContaining('sunset'), findsNothing);
  });

  testWidgets('claim warning: a claimable vault says CLAIMABLE NOW, in term too; closed and void vaults never warn', (tester) async {
    final h = Harness(withWallet: true);
    final open = 'd6' * 32;
    h.api.vaultsAnswer = [
      h.api.vault(txid: open, lockHeight: 528, underwater: true, claimPrice: 390000),
      h.api.vault(txid: 'd7' * 32, status: 'CLOSED', lockHeight: 400, claimPrice: 390000),
      h.api.vault(txid: 'd8' * 32, status: 'VOID', voidReason: 'abandoned', lockHeight: 400, claimPrice: 390000),
    ];
    await h.pump(tester);
    expect(find.byKey(Key('claim-warning-$open')), findsOneWidget);
    expect(find.byKey(Key('claim-warning-${'d7' * 32}')), findsNothing);
    expect(find.byKey(Key('claim-warning-${'d8' * 32}')), findsNothing);
    expect(find.text('A vault is claimable now'), findsOneWidget);
    expect(find.textContaining('CLAIMABLE NOW: its collateral is worth less than 125 % of its debt'), findsOneWidget);
    expect(find.textContaining('early-redeem fee of 5 %'), findsOneWidget);
  });

  testWidgets('claim: the row shown is the bound the core is handed (H-9.3)', (tester) async {
    final h = Harness(withWallet: true);
    h.api.claimableAnswer = const [claimable1];
    await openClaimable(tester, h);
    await tester.tap(find.byKey(Key('claimable-${claimable1.vaultTxid}')));
    await tester.pumpAndSettle();
    await tester.longPress(find.byKey(const Key('slide-to-confirm')));
    await tester.pumpAndSettle();
    expect(h.api.calls, contains('claim confirmed ${claimable1.cents} ${claimable1.claimantZat}'));
  });

  testWidgets('claim: a bound refusal from the core is shown verbatim and no progress opens', (tester) async {
    final h = Harness(withWallet: true);
    h.api.claimableAnswer = const [claimable1];
    const refusal = 'claim-out-below-min: the claim would pay you 900000000 zat, below the 949998000 you confirmed';
    h.api.claimError = const YewError(kind: ErrorKind.refused, message: refusal);
    await openClaimable(tester, h);
    await tester.tap(find.byKey(Key('claimable-${claimable1.vaultTxid}')));
    await tester.pumpAndSettle();
    await tester.longPress(find.byKey(const Key('slide-to-confirm')));
    await tester.pumpAndSettle();
    expect(find.text(refusal), findsOneWidget);
    expect(find.text('claiming'), findsNothing);
  });

  test('formatRelative and formatDeadline', () {
    final now = DateTime.fromMillisecondsSinceEpoch(FakeWalletApi.nowSecs * 1000);
    expect(formatRelative(FakeWalletApi.nowSecs + 3 * 86400, now: now), 'in about 3 days');
    expect(formatRelative(FakeWalletApi.nowSecs - 5 * 3600, now: now), 'about 5 hours ago');
    expect(formatRelative(FakeWalletApi.nowSecs + 600, now: now), 'in under an hour');
    expect(formatRelative(FakeWalletApi.nowSecs + 90 * 60, now: now), 'in about an hour');
    expect(formatDeadline(548, FakeWalletApi.nowSecs + 86400 * 2, now: now), startsWith('height 548 · '));
  });
}
