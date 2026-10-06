// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

// The term classes of a mint (spec §2 table, V19): the lock range in blocks per class, per
// network. The node decides the class from `lockBlocks` (the estimate reports it); this table
// only gives the Mint screen its picker and each class's shortest lock as the default.
import 'api/wallet_api.dart';

class TermClass {
  const TermClass(this.letter, this.title, this.minBlocks, this.maxBlocks);
  final String letter;
  final String title;
  final int minBlocks;
  final int maxBlocks;

  bool contains(int blocks) => blocks >= minBlocks && blocks <= maxBlocks;
}

/// Mainnet and testnet: 75-second blocks, class A 30–90 days alone. Classes B (90 days – 1
/// year) and C (1–5 years) are disabled by the node's parameter set (hardening H-5: an empty
/// term range), so the picker does not offer them; the core refuses them too.
const List<TermClass> _mainTerms = [
  TermClass('A', '30–90 days', 34560, 103680),
];

/// Regtest (the devnet): the same three classes in blocks a laptop can mine.
const List<TermClass> _regtestTerms = [
  TermClass('A', '48–96 blocks', 48, 96),
  TermClass('B', '97–144 blocks', 97, 144),
  TermClass('C', '145–240 blocks', 145, 240),
];

List<TermClass> termClassesFor(NetworkId network) => network == NetworkId.regtest ? _regtestTerms : _mainTerms;

/// The class a lock length falls in, or null when it is outside every class.
TermClass? termClassOf(NetworkId network, int lockBlocks) {
  for (final t in termClassesFor(network)) {
    if (t.contains(lockBlocks)) return t;
  }
  return null;
}
