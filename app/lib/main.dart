// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

// YEW ("Your Electronic Wallet"): a wallet for YEC (private and public) and Ycash Yellowback (YED).
// Everything under lib/ is a view over the Rust core (api/rust_wallet_api.dart); the seed
// lives in the platform keystore (state/secrets.dart). scripts/check-app-imports.sh keeps
// networking, crypto and databases out of this tree.
import 'package:flutter/material.dart';

import 'api/rust_wallet_api.dart';
import 'app.dart';
import 'state/app_state.dart';
import 'state/secrets.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await RustWalletApi.init();
  runApp(
    YewApp(
      state: AppState(
        api: const RustWalletApi(),
        secrets: SecureSecretStore(),
        auth: DeviceAuthenticator(),
        dirs: const AppDataDirs(),
      ),
    ),
  );
}
