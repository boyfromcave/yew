// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

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

  /// The overall sync progress 0..100 (transparent to 10, the private scan 10..95).
  int syncPercent = 0;

  /// Why the last sync did not bring the private balance up to date (empty when it did).
  String shieldedNote = '';
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
    yedSendMinZat: 21000, yecShieldedZat: 0, yecShieldedSpendableZat: 0, yecShieldedPendingZat: 0, shieldedScannedHeight: 0, shieldedSendable: false,
  );
  Status? status;
  List<HistoryItem> history = const [];

  /// The two-step rows (mints and claims) and the own vaults, from the core's store (W4).
  List<MintStatus> mints = const [];
  List<VaultSummary> vaults = const [];
  /// The claim intents paying this wallet (the vault upgrade): pending, releasable, released,
  /// cancelled by the attestor set.
  List<ClaimIntent> intents = const [];

  /// How often a screen watching a mint in progress syncs by itself; `null` disables the
  /// timer (the widget tests).
  Duration? mintPollInterval = const Duration(seconds: 15);
  AddressPair? receive;

  /// The private (`ys1…`) receive address; null until the core has one.
  AddressPair? receivePrivate;
  StreamSubscription<SyncEvent>? _sync;

  /// Read settings and whether a seed exists (first frame).
  Future<void> load() async {
    final s = await secrets.read(_kSettings);
    if (s != null) settings = WalletSettings.decode(s);
    // Which keystore entry holds the seed follows the toggle (audit G-10); the items were
    // moved when the toggle changed, so this only selects the entry.
    await secrets.bind(settings.biometrics);
    hasWallet = (await secrets.read(_kSeed)) != null;
    unlocked = hasWallet && api.isUnlocked();
    loaded = true;
    notifyListeners();
  }

  Future<void> saveSettings(WalletSettings s) async {
    final rebind = s.biometrics != settings.biometrics;
    settings = s;
    await secrets.write(_kSettings, s.encode());
    if (rebind) await secrets.bind(s.biometrics);
    notifyListeners();
  }

  /// The device prompt before a secret is read, unless the keystore entry itself prompts.
  Future<bool> _presence(String reason) async {
    if (!settings.biometrics) return true;
    if (secrets.bindingPrompts) return true;
    return auth.authenticate(reason);
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
      caPem: withSettings.caPem.isEmpty ? null : withSettings.caPem,
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
    if (!await _presence('Unlock YEW')) return false;
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
          caPem: settings.caPem.isEmpty ? null : settings.caPem,
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
    if (!await _presence('Show the recovery phrase')) return null;
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
      try {
        receivePrivate = await api.receiveAddress(kind: ReceiveKind.shielded, fresh: false);
      } catch (_) {
        receivePrivate = null; // the private side is unavailable; public receive still works
      }
      history = (await api.history(page: 0, pageSize: 200)).rows;
      mints = await api.mints();
      vaults = await api.vaults();
      intents = await api.claimIntents();
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
    syncPercent = 0;
    notifyListeners();
    final done = Completer<void>();
    _sync = api.syncNow().listen(
      (e) {
        syncMessage = e.message;
        syncPercent = e.percent;
        if (e.stage == SyncStage.done) shieldedNote = e.shieldedMessage;
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

  Future<void> setServer(String server, bool plain, {String caPem = ''}) async {
    await api.setServer(server: server, plain: plain, caPem: caPem.isEmpty ? null : caPem);
    await saveSettings(settings.copyWith(server: server, plain: plain, caPem: caPem));
    status = null;
  }

  /// A fresh receive address ("new address" on Receive).
  Future<void> newReceiveAddress() async {
    receive = await api.receiveAddress(fresh: true);
    notifyListeners();
  }

  /// A new private address of the same private balance ("New private address" on Receive).
  Future<void> newPrivateAddress() async {
    try {
      receivePrivate = await api.newShieldedAddress();
    } catch (e) {
      lastError = messageOf(e);
    }
    notifyListeners();
  }

  void clearError() {
    lastError = null;
    notifyListeners();
  }

  /// Send YED is possible only when the server offers Yellowback and there is YEC for the fee.
  bool get canPayYedFee => balances.yecZat + balances.yecReservedZat >= balances.yedSendMinZat;

  /// Public YEC: available plus the part kept for YED fees.
  int get publicYecZat => balances.yecZat + balances.yecReservedZat;

  /// All YEC, private and public (the Home total).
  int get totalYecZat => publicYecZat + balances.yecShieldedZat;

  /// The rows still moving (the Yellowback screen's "in progress" list).
  List<MintStatus> get mintsInProgress => mints.where((m) => m.inProgress || m.canSweep || m.state == 'SWEEP_SENT').toList();

  /// One row by id, from the last refresh.
  MintStatus? mintById(int id) {
    for (final m in mints) {
      if (m.mintId == id) return m;
    }
    return null;
  }

  /// One vault by txid, from the last refresh.
  VaultSummary? vaultByTxid(String txid) {
    for (final v in vaults) {
      if (v.vaultTxid == txid) return v;
    }
    return null;
  }
}
