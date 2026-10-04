// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

// The device side of D-W-6: the seed lives only in the platform keystore (iOS Keychain,
// Android Keystore through flutter_secure_storage) and is handed to the core at unlock;
// biometrics through local_auth; the data directory through path_provider. Each is behind a
// small interface so the widget tests run with in-memory fakes. Nothing here is crypto.
//
// Audit G-10: with "device unlock" on, the seed and the passphrase move to a keystore entry
// the platform itself binds to the user's presence (Android: a Keystore AES key with
// `enforceBiometrics`, biometric or device credential; iOS: `kSecAccessControl` with
// `userPresence`), so a process inside the app's sandbox cannot read them without the prompt.
// `userPresence` / `biometricOrDeviceCredential` (not "current biometric set") keep the items
// readable after a fingerprint is added or removed. The BIP39 passphrase stays beside the seed
// so unlock needs no typing (W5 review A-7): it protects a seed-only backup, not the keystore.
// On iOS the core's data directory (the SQLite cache) is excluded from iCloud/iTunes backup
// through a small platform channel (`NSURLIsExcludedFromBackupKey`, ios/Runner/AppDelegate.swift).
import 'dart:convert';
import 'dart:io' show Platform;

import 'package:flutter/services.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:local_auth/local_auth.dart';
import 'package:path_provider/path_provider.dart';

import '../api/wallet_api.dart' show NetworkId;

/// The keys whose items are bound to the user's presence when "device unlock" is on.
const Set<String> boundSecretKeys = {'seed', 'passphrase'};

/// Key-value secrets.
abstract class SecretStore {
  Future<String?> read(String key);
  Future<void> write(String key, String value);
  Future<void> delete(String key);

  /// Move the [boundSecretKeys] into (or out of) the presence-bound keystore entry
  /// (audit G-10). A no-op where the platform offers nothing.
  Future<void> bind(bool biometric);

  /// True when reading a bound secret already prompts the user on the platform side, so the
  /// app's own `local_auth` prompt would be a second one.
  bool get bindingPrompts;
}

/// The platform keystore: one entry set without access control (the settings, and the seed
/// while "device unlock" is off) and one the platform binds to the user's presence.
class SecureSecretStore implements SecretStore {
  SecureSecretStore();

  final FlutterSecureStorage _plain = const FlutterSecureStorage(
    iOptions: IOSOptions(accessibility: KeychainAccessibility.first_unlock_this_device),
  );

  /// Android: `AndroidOptions.biometric` (a Keystore AES key, API 28+) with `enforceBiometrics`
  /// in its own namespace so the unbound entries never prompt; iOS: a separate service name
  /// with `userPresence` access control (biometry or passcode, the current set not required).
  final FlutterSecureStorage _bound = const FlutterSecureStorage(
    iOptions: IOSOptions(
      accessibility: KeychainAccessibility.first_unlock_this_device,
      accountName: 'cash.ycash.yew.bound',
      accessControlFlags: [AccessControlFlag.userPresence],
    ),
    aOptions: AndroidOptions.biometric(
      enforceBiometrics: true,
      storageNamespace: 'cash.ycash.yew.bound',
      biometricPromptTitle: 'YEW',
      biometricPromptSubtitle: 'Unlock the wallet',
    ),
  );

  bool _biometric = false;

  FlutterSecureStorage _for(String key) => _biometric && boundSecretKeys.contains(key) ? _bound : _plain;

  @override
  Future<String?> read(String key) => _for(key).read(key: key);
  @override
  Future<void> write(String key, String value) => _for(key).write(key: key, value: value);
  @override
  Future<void> delete(String key) => _for(key).delete(key: key);

  @override
  bool get bindingPrompts => _biometric;

  @override
  Future<void> bind(bool biometric) async {
    if (biometric == _biometric) return;
    final from = _biometric ? _bound : _plain;
    final to = biometric ? _bound : _plain;
    for (final k in boundSecretKeys) {
      final v = await from.read(key: k);
      if (v != null) {
        await to.write(key: k, value: v);
        await from.delete(key: k);
      }
    }
    _biometric = biometric;
  }
}

/// In memory (tests, and the integration test's throwaway wallets).
class MemorySecretStore implements SecretStore {
  final Map<String, String> _m = {};
  bool bound = false;
  @override
  Future<String?> read(String key) async => _m[key];
  @override
  Future<void> write(String key, String value) async => _m[key] = value;
  @override
  Future<void> delete(String key) async => _m.remove(key);
  @override
  Future<void> bind(bool biometric) async => bound = biometric;
  @override
  bool get bindingPrompts => false;
}

/// The biometric / device-credential prompt.
abstract class Authenticator {
  Future<bool> get available;
  Future<bool> authenticate(String reason);
}

class DeviceAuthenticator implements Authenticator {
  final LocalAuthentication _auth = LocalAuthentication();
  @override
  Future<bool> get available async {
    try {
      return await _auth.isDeviceSupported();
    } catch (_) {
      return false;
    }
  }

  @override
  Future<bool> authenticate(String reason) async {
    try {
      return await _auth.authenticate(localizedReason: reason);
    } catch (_) {
      return false;
    }
  }
}

/// No prompt (tests, or biometrics off).
class NoAuthenticator implements Authenticator {
  const NoAuthenticator({this.answer = true});
  final bool answer;
  @override
  Future<bool> get available async => false;
  @override
  Future<bool> authenticate(String reason) async => answer;
}

/// Where the core keeps its SQLite cache (D-W-6: a cache, rebuilt from seed + birthday).
abstract class DataDirs {
  Future<String> dataDir();
}

class AppDataDirs implements DataDirs {
  const AppDataDirs();

  static const MethodChannel _backup = MethodChannel('cash.ycash.yew/backup');

  /// The support directory; on iOS marked `NSURLIsExcludedFromBackupKey` first (audit G-10):
  /// the cache (addresses, history, wrapped imported keys) never enters an iCloud or iTunes
  /// backup. Android already has `allowBackup=false`.
  @override
  Future<String> dataDir() async {
    final path = (await getApplicationSupportDirectory()).path;
    if (Platform.isIOS) {
      try {
        await _backup.invokeMethod<void>('exclude', path);
      } on MissingPluginException {
        // No platform side (tests): nothing to do.
      } on PlatformException {
        // The flag could not be set; the directory still exists. Surfaced nowhere: the
        // owner's device run (README "What is left") checks it.
      }
    }
    return path;
  }
}

class FixedDataDirs implements DataDirs {
  const FixedDataDirs(this.path);
  final String path;
  @override
  Future<String> dataDir() async => path;
}

/// Non-secret settings, kept beside the seed for want of a second store.
class WalletSettings {
  const WalletSettings({
    this.server = defaultServer,
    this.plain = false,
    this.caPem = '',
    this.network = NetworkId.mainnet,
    this.birthday,
    this.trustAccepted = false,
    this.biometrics = false,
    this.paramsUrl = '',
  });

  /// No built-in endpoint: the list is the core's `default_servers(network)` (empty for
  /// mainnet and testnet until the owner supplies it, docs/release.md "Default endpoints");
  /// Onboarding prefills from it and otherwise asks.
  static const String defaultServer = '';

  final String server;
  final bool plain;

  /// A pinned certificate (PEM) for the server, the only trust anchor when non-empty
  /// (audit G-4). Not a secret, kept beside the other settings.
  final String caPem;
  final NetworkId network;
  final int? birthday;
  final bool trustAccepted;
  final bool biometrics;

  /// Where the private-sending files are downloaded from (`https://host/dir/`). No host is
  /// compiled in (yew-shielded plan S0-2: hosting is the owner's decision); empty = not set.
  final String paramsUrl;

  WalletSettings copyWith({
    String? server,
    bool? plain,
    String? caPem,
    NetworkId? network,
    int? birthday,
    bool? trustAccepted,
    bool? biometrics,
    String? paramsUrl,
  }) => WalletSettings(
    server: server ?? this.server,
    plain: plain ?? this.plain,
    caPem: caPem ?? this.caPem,
    network: network ?? this.network,
    birthday: birthday ?? this.birthday,
    trustAccepted: trustAccepted ?? this.trustAccepted,
    biometrics: biometrics ?? this.biometrics,
    paramsUrl: paramsUrl ?? this.paramsUrl,
  );

  String encode() => jsonEncode({
    'server': server,
    'plain': plain,
    'caPem': caPem,
    'network': network.name,
    'birthday': birthday,
    'trustAccepted': trustAccepted,
    'biometrics': biometrics,
    'paramsUrl': paramsUrl,
  });

  static WalletSettings decode(String s) {
    final m = jsonDecode(s) as Map<String, dynamic>;
    return WalletSettings(
      server: m['server'] as String? ?? defaultServer,
      plain: m['plain'] as bool? ?? false,
      caPem: m['caPem'] as String? ?? '',
      network: NetworkId.values.firstWhere(
        (n) => n.name == m['network'],
        orElse: () => NetworkId.mainnet,
      ),
      birthday: m['birthday'] as int?,
      trustAccepted: m['trustAccepted'] as bool? ?? false,
      biometrics: m['biometrics'] as bool? ?? false,
      paramsUrl: m['paramsUrl'] as String? ?? '',
    );
  }
}
