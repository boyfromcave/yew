// The device side of D-W-6: the seed lives only in the platform keystore (iOS Keychain,
// Android Keystore through flutter_secure_storage) and is handed to the core at unlock;
// biometrics through local_auth; the data directory through path_provider. Each is behind a
// small interface so the widget tests run with in-memory fakes. Nothing here is crypto.
import 'dart:convert';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:local_auth/local_auth.dart';
import 'package:path_provider/path_provider.dart';

import '../api/wallet_api.dart' show NetworkId;

/// Key-value secrets.
abstract class SecretStore {
  Future<String?> read(String key);
  Future<void> write(String key, String value);
  Future<void> delete(String key);
}

/// The platform keystore.
class SecureSecretStore implements SecretStore {
  SecureSecretStore()
    : _s = const FlutterSecureStorage(
        iOptions: IOSOptions(accessibility: KeychainAccessibility.first_unlock_this_device),
      );
  final FlutterSecureStorage _s;

  @override
  Future<String?> read(String key) => _s.read(key: key);
  @override
  Future<void> write(String key, String value) => _s.write(key: key, value: value);
  @override
  Future<void> delete(String key) => _s.delete(key: key);
}

/// In memory (tests, and the integration test's throwaway wallets).
class MemorySecretStore implements SecretStore {
  final Map<String, String> _m = {};
  @override
  Future<String?> read(String key) async => _m[key];
  @override
  Future<void> write(String key, String value) async => _m[key] = value;
  @override
  Future<void> delete(String key) async => _m.remove(key);
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
  @override
  Future<String> dataDir() async => (await getApplicationSupportDirectory()).path;
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
    this.network = NetworkId.mainnet,
    this.birthday,
    this.trustAccepted = false,
    this.biometrics = false,
  });

  /// No built-in endpoint: the list is the core's `default_servers(network)` (empty for
  /// mainnet and testnet until the owner supplies it, docs/release.md "Default endpoints");
  /// Onboarding prefills from it and otherwise asks.
  static const String defaultServer = '';

  final String server;
  final bool plain;
  final NetworkId network;
  final int? birthday;
  final bool trustAccepted;
  final bool biometrics;

  WalletSettings copyWith({
    String? server,
    bool? plain,
    NetworkId? network,
    int? birthday,
    bool? trustAccepted,
    bool? biometrics,
  }) => WalletSettings(
    server: server ?? this.server,
    plain: plain ?? this.plain,
    network: network ?? this.network,
    birthday: birthday ?? this.birthday,
    trustAccepted: trustAccepted ?? this.trustAccepted,
    biometrics: biometrics ?? this.biometrics,
  );

  String encode() => jsonEncode({
    'server': server,
    'plain': plain,
    'network': network.name,
    'birthday': birthday,
    'trustAccepted': trustAccepted,
    'biometrics': biometrics,
  });

  static WalletSettings decode(String s) {
    final m = jsonDecode(s) as Map<String, dynamic>;
    return WalletSettings(
      server: m['server'] as String? ?? defaultServer,
      plain: m['plain'] as bool? ?? false,
      network: NetworkId.values.firstWhere(
        (n) => n.name == m['network'],
        orElse: () => NetworkId.mainnet,
      ),
      birthday: m['birthday'] as int?,
      trustAccepted: m['trustAccepted'] as bool? ?? false,
      biometrics: m['biometrics'] as bool? ?? false,
    );
  }
}
