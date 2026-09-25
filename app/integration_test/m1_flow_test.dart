// Plan §6.3, the M1 flow on a device against the W2 armed devnet (`scripts/devnet-w2.sh up`:
// lightwalletd-dd --yellowback on port 9267, plain HTTP/2). NOT RUN YET: no simulator or
// emulator exists on the machine this was written on (Xcode and the Android SDK are [owner]
// installs, plan §7 W3). Written against the real core; the fake is not used here.
//
//   Android emulator:  flutter test integration_test/m1_flow_test.dart -d emulator-5554
//   iOS simulator:     flutter test integration_test/m1_flow_test.dart -d <simulator id>
//
// The server is 10.0.2.2:9267 on the Android emulator (the host's loopback) and
// localhost:9267 on the iOS simulator; override with --dart-define=YEW_SERVER=host:port.
// The flow funds the wallet from node 0 by hand (the test prints the address and waits up to
// FUND_WAIT for a sync to see the coins): run `yellowback-devnet` `sendtoaddress` /
// `yed_send` from the workspace while it waits, or pass --dart-define=YEW_FUNDED=1 for a
// wallet already funded. Two wallets on one device are two data directories.
import 'dart:io' show Platform;

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:path_provider/path_provider.dart';
import 'package:yew_app/api/rust_wallet_api.dart';
import 'package:yew_app/api/wallet_api.dart';
import 'package:yew_app/app.dart';
import 'package:yew_app/state/app_state.dart';
import 'package:yew_app/state/secrets.dart';

const fundWait = Duration(minutes: 3);

String get devnetServer {
  const fromEnv = String.fromEnvironment('YEW_SERVER');
  if (fromEnv.isNotEmpty) return fromEnv;
  return Platform.isAndroid ? '10.0.2.2:9267' : 'localhost:9267';
}

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  late String dataDir;
  setUpAll(() async {
    await RustWalletApi.init();
    final base = (await getApplicationSupportDirectory()).path;
    dataDir = '$base/m1-${DateTime.now().millisecondsSinceEpoch}';
  });

  testWidgets('M1: onboarding, sync, receive, YEC send, YED send, history, restore', (tester) async {
    const api = RustWalletApi();
    final secrets = MemorySecretStore();
    final state = AppState(api: api, secrets: secrets, auth: const NoAuthenticator(), dirs: FixedDataDirs('$dataDir/a'));
    await tester.pumpWidget(YewApp(state: state));
    await tester.pumpAndSettle();

    // Onboarding: create, trust, regtest + plain against the devnet, finish, seed backup.
    await tester.tap(find.byKey(const Key('create')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('trust-check')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('next')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('network')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('regtest').last);
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('server')), devnetServer);
    await tester.tap(find.byKey(const Key('plain')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('probe')));
    await tester.pumpAndSettle(const Duration(seconds: 2));
    expect(find.textContaining('Server ok'), findsOneWidget, reason: 'the devnet lightwalletd must be up on $devnetServer');
    await tester.tap(find.byKey(const Key('next')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('finish')));
    await tester.pumpAndSettle(const Duration(seconds: 2));
    final seedWords = (await secrets.read('seed'))!;
    await tester.tap(find.byKey(const Key('written')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('done')));
    await tester.pumpAndSettle(const Duration(seconds: 5));

    // Home synced to zero; the receive address in both forms.
    expect(find.text('\$0.00'), findsOneWidget);
    await tester.tap(find.byKey(const Key('receive')));
    await tester.pumpAndSettle();
    final ye = state.receive!.ye;
    final s = state.receive!.s;
    expect(ye.startsWith('yr'), isTrue);
    expect(s.startsWith('sm'), isTrue);
    // ignore: avoid_print
    print('YEW M1: fund this address from node 0 (1 YEC and \$50.00 YED): $ye / $s');
    await tester.pageBack();
    await tester.pumpAndSettle();

    // Wait for funds (an operator sends them, or YEW_FUNDED says they are there).
    final deadline = DateTime.now().add(fundWait);
    while (state.balances.yedCents == 0 || state.balances.yecZat == 0) {
      expect(DateTime.now().isBefore(deadline), isTrue, reason: 'not funded within $fundWait');
      await Future<void>.delayed(const Duration(seconds: 10));
      await state.sync();
      await tester.pumpAndSettle();
    }
    expect(find.text('\$50.00'), findsOneWidget);
    expect(state.balances.yecReservedZat, greaterThan(0));

    // A second wallet on the same device to receive the sends.
    final walletB = await api.createWallet(passphrase: '', birthday: null, network: NetworkId.regtest, server: devnetServer, plain: true, dataDir: '$dataDir/b')
        .then((c) async {
      // The core holds one wallet at a time: note B's address, lock B, reopen A.
      final addrB = c.addressYe;
      await api.lock();
      await api.unlock(seedWords: seedWords, passphrase: '', network: NetworkId.regtest, server: devnetServer, plain: true, dataDir: '$dataDir/a');
      return (addrB, c.seedWords!);
    });
    final (addrB, seedB) = walletB;

    // YEC send 0.1 to B: preview shows fee and change, confirm returns a txid.
    await tester.tap(find.byKey(const Key('send')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('YEC'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('address')), addrB);
    await tester.enterText(find.byKey(const Key('amount')), '0.1');
    await tester.tap(find.byKey(const Key('preview')));
    await tester.pumpAndSettle(const Duration(seconds: 5));
    expect(find.text('0.00001000 YEC'), findsOneWidget);
    await tester.longPress(find.byKey(const Key('slide-to-confirm')));
    await tester.pumpAndSettle(const Duration(seconds: 5));
    expect(find.byKey(const Key('txid')), findsOneWidget);
    await tester.tap(find.byKey(const Key('done')));
    await tester.pumpAndSettle();

    // YED send $12.34 to B: the dry-run verdict is ok; confirm; pending until a block.
    await tester.tap(find.byKey(const Key('send')));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('address')), addrB);
    await tester.enterText(find.byKey(const Key('amount')), '12.34');
    await tester.tap(find.byKey(const Key('preview')));
    await tester.pumpAndSettle(const Duration(seconds: 5));
    expect(find.text('verdict ok'), findsOneWidget);
    await tester.longPress(find.byKey(const Key('slide-to-confirm')));
    await tester.pumpAndSettle(const Duration(seconds: 5));
    expect(find.byKey(const Key('txid')), findsOneWidget);
    await tester.tap(find.byKey(const Key('done')));
    await tester.pumpAndSettle();
    expect(state.balances.yedPendingCents, 3766, reason: 'the change is PENDING_TOKEN until a block');

    // A malformed amount the node refuses (change-floor): the core's message, verbatim.
    await tester.tap(find.byKey(const Key('send')));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('address')), addrB);
    await tester.enterText(find.byKey(const Key('amount')), '37.16');
    await tester.tap(find.byKey(const Key('preview')));
    await tester.pumpAndSettle(const Duration(seconds: 5));
    expect(find.textContaining('change-floor'), findsOneWidget);
    await tester.pageBack();
    await tester.pumpAndSettle();

    // History shows the pending rows with local labels.
    await tester.tap(find.byKey(const Key('tab-history')));
    await tester.pumpAndSettle();
    expect(find.textContaining('sending \$12.34'), findsOneWidget);

    // Restore B from its seed into a fresh directory: after a block and a sync it holds
    // 0.1 YEC and $12.34 (the operator mines one pool block while this waits).
    await api.lock();
    await api.unlock(seedWords: seedB, passphrase: '', network: NetworkId.regtest, server: devnetServer, plain: true, dataDir: '$dataDir/b2');
    final deadline2 = DateTime.now().add(fundWait);
    var b = await api.balances();
    while (b.yedCents != 1234) {
      expect(DateTime.now().isBefore(deadline2), isTrue, reason: 'mine a pool block on the devnet');
      await Future<void>.delayed(const Duration(seconds: 10));
      await api.syncNow().drain<void>();
      b = await api.balances();
    }
    expect(b.yecZat, 10000000);
    await api.lock();
  });
}
