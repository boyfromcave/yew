// The single app state (plan §7 W3: "one store, streams from the core"). Screens read it and
// call its intents; it talks to the core only through WalletApi and to the device only
// through SecretStore / Authenticator / DataDirs. It holds no key material beyond the moment
// the seed is read from the keystore and handed to the core.
import 'dart:async';

import 'package:flutter/foundation.dart';

import '../api/wallet_api.dart';
import 'secrets.dart';

const _kSeed = 'seed';
const _kPassphrase = 'passphrase';
const _kSettings = 'settings';

class AppState extends ChangeNotifier {
  AppState({
    required this.api,
    required this.secrets,
    required this.auth,
    required this.dirs,
  });

  final WalletApi api;
  final SecretStore secrets;
  final Authenticator auth;
  final DataDirs dirs;

  bool loaded = false;
  bool hasWallet = false;
  bool unlocked = false;

  /// Set by an explicit [lock]: the lock screen then waits for a tap instead of unlocking
  /// by itself as it does on a cold start.
  bool explicitLock = false;
  bool syncing = false;
  bool yellowbackUsable = false;
  String syncMessage = '';
  String? lastError;
  WalletSettings settings = const WalletSettings();
  Balances balances = const Balances(
    yecZat: 0,
    yecReservedZat: 0,
    yecPendingZat: 0,
    yedCents: 0,
    yedPendingCents: 0,
    heldCount: 0,
    syncHeight: 0,
    yedSendMinZat: 21000,
  );
  Status? status;
  List<HistoryItem> history = const [];
  AddressPair? receive;
  StreamSubscription<SyncEvent>? _sync;

  /// Read settings and whether a seed exists (first frame).
  Future<void> load() async {
    final s = await secrets.read(_kSettings);
    if (s != null) settings = WalletSettings.decode(s);
    hasWallet = (await secrets.read(_kSeed)) != null;
    unlocked = hasWallet && api.isUnlocked();
    loaded = true;
    notifyListeners();
  }

  Future<void> saveSettings(WalletSettings s) async {
    settings = s;
    await secrets.write(_kSettings, s.encode());
    notifyListeners();
  }

  /// Create a new seed (words `null`) or restore one; store it in the keystore; open the
  /// wallet. Returns the words when they were generated (shown once for backup).
  Future<String?> createWallet({
    String? seedWords,
    String passphrase = '',
    int? birthday,
    required WalletSettings withSettings,
  }) async {
    final created = await api.createWallet(
      seedWords: seedWords,
      passphrase: passphrase,
      birthday: birthday,
      network: withSettings.network,
      server: withSettings.server,
      plain: withSettings.plain,
      dataDir: await dirs.dataDir(),
    );
    final words = seedWords ?? created.seedWords!;
    await secrets.write(_kSeed, words);
    await secrets.write(_kPassphrase, passphrase);
    await saveSettings(withSettings.copyWith(birthday: birthday));
    hasWallet = true;
    unlocked = true;
    notifyListeners();
    await refresh();
    return created.seedWords;
  }

  /// Biometrics (when enabled), then the seed from the keystore into the core.
  Future<bool> unlock() async {
    if (settings.biometrics && !await auth.authenticate('Unlock YEW')) return false;
    final words = await secrets.read(_kSeed);
    if (words == null) return false;
    try {
      if (!api.isUnlocked()) {
        await api.unlock(
          seedWords: words,
          passphrase: await secrets.read(_kPassphrase) ?? '',
          network: settings.network,
          server: settings.server,
          plain: settings.plain,
          dataDir: await dirs.dataDir(),
        );
      }
      unlocked = true;
      explicitLock = false;
      lastError = null;
      notifyListeners();
      await refresh();
      return true;
    } catch (e) {
      lastError = messageOf(e);
      notifyListeners();
      return false;
    }
  }

  Future<void> lock() async {
    await _sync?.cancel();
    _sync = null;
    syncing = false;
    await api.lock();
    unlocked = false;
    explicitLock = true;
    status = null;
    notifyListeners();
  }

  /// The seed for the backup screen: gated by the device prompt, read from the keystore
  /// (never from the core).
  Future<String?> seedWordsForBackup() async {
    if (settings.biometrics && !await auth.authenticate('Show the recovery phrase')) return null;
    return secrets.read(_kSeed);
  }

  /// Forget the wallet on this device (the seed is the backup).
  Future<void> forgetWallet() async {
    await lock();
    await secrets.delete(_kSeed);
    await secrets.delete(_kPassphrase);
    hasWallet = false;
    notifyListeners();
  }

  /// Balances, receive address and history from the core's store (no network).
  Future<void> refresh() async {
    if (!unlocked) return;
    try {
      balances = await api.balances();
      receive = await api.receiveAddress(fresh: false);
      history = (await api.history(page: 0, pageSize: 200)).rows;
      lastError = null;
    } catch (e) {
      lastError = messageOf(e);
    }
    notifyListeners();
  }

  /// Status (connects) — Settings → About.
  Future<Status?> fetchStatus() async {
    try {
      status = await api.status();
      yellowbackUsable = status!.yellowback.usable;
    } catch (e) {
      lastError = messageOf(e);
    }
    notifyListeners();
    return status;
  }

  /// Sync now: the core's progress stream, then a refresh. Completes when the stream ends.
  Future<void> sync() async {
    if (!unlocked || syncing) return;
    syncing = true;
    syncMessage = 'Connecting';
    notifyListeners();
    final done = Completer<void>();
    _sync = api.syncNow().listen(
      (e) {
        syncMessage = e.message;
        if (e.stage == SyncStage.probing || e.stage == SyncStage.done) {
          yellowbackUsable = e.yellowbackUsable;
        }
        if (e.stage == SyncStage.failed) lastError = e.message;
        notifyListeners();
      },
      onError: (Object e) {
        lastError = messageOf(e);
        if (!done.isCompleted) done.complete();
      },
      onDone: () {
        if (!done.isCompleted) done.complete();
      },
    );
    await done.future;
    _sync = null;
    syncing = false;
    await refresh();
  }

  Future<void> setServer(String server, bool plain) async {
    await api.setServer(server: server, plain: plain);
    await saveSettings(settings.copyWith(server: server, plain: plain));
    status = null;
  }

  /// A fresh receive address ("new address" on Receive).
  Future<void> newReceiveAddress() async {
    receive = await api.receiveAddress(fresh: true);
    notifyListeners();
  }

  void clearError() {
    lastError = null;
    notifyListeners();
  }

  /// Send YED is possible only when the server offers Yellowback and there is YEC for the fee.
  bool get canPayYedFee => balances.yecZat + balances.yecReservedZat >= balances.yedSendMinZat;
}
