# The yewd Yugen wallet's interface to ycashd

What the Yugen wallet of yewd (`yewd/yugen`) needs from a Yugen-capable `ycashd`, and the
transaction it submits. Hex is lower-case; 48-byte values are 96 hex characters. The node defines
the final bytes; this file records the shapes the wallet is built and tested against.

## N-ACT: activation

Network upgrade `Yugen`, ordered after Vault: branch id `0x59474e30` (1497845296), version group
`0x59474e47`. Regtest/devnet activate it with `-nuparams=59474e30:<h>`, which needs an explicit Vault
height `<= h`; the height is a multiple of the anchor grid (16). No mainnet or testnet height is set.
`getblockchaininfo.upgrades["59474e30"]` reports it as for Vault. The wallet reads activation and
branch id from `yugen_getinfo` and needs no `-nuparams` of its own.

## W-RPC: node RPCs the wallet calls

- W-RPC-1 `yugen_getinfo` -> `{"rpcversion", "active": bool (next block), "activation_height": n|-1,
  "branch_id": 1497845296, "network", "tip_height", "tree_size", "root": hex48, "anchor_window": 96,
  "anchor_grid": 16}`.
- W-RPC-2 `yugen_getblockdata <height>` -> `{"height", "hash": hex32 (RPC byte order),
  "tree_size_before", "root_after": hex48, "transfers": [{"txid", "index_in_block",
  "transfer": hex (spec §7.1 encoding)}]}`. Output commitments are appended to the note tree in
  block order, transfer order, cm_1 then cm_2 (spec §8). Empty `transfers` below activation.
- W-RPC-3 `yugen_getanchor <height>` -> `{"height", "root": hex48, "block_hash": hex32}` for a grid
  height (spec §8.3; block hash in internal byte order, as the transfer hash binds it).
- W-RPC-4 submission: `submittransfer {"tx": hex, "route": "leaf"}` -> `{"txid", "nf1": hex32}`,
  else `sendrawtransaction <hex>` of a W-TX transaction.
- W-RPC-5 `gettransferstatus <nf1>` -> `{"state": "mempool|mined|unknown", "height"|"txid"}`.

## W-TX: the Yugen transaction

A v4 overwintered transaction with `nVersionGroupId = 0x59474e47` under branch `0x59474e30`,
serialised as a Sapling v4 transaction (header, version group, vin, vout, nLockTime,
nExpiryHeight, valueBalance = 0, no Sapling spends or outputs, no JoinSplits, no bindingSig),
followed by `compactsize(len) transfer || compactsize(len) proof_a || compactsize(len) proof_b`
(proofs inline).

- Balance: the transfer's fee and a positive `value_balance` add to the transparent value in; a
  negative `value_balance` is value out.
- Sighash for transparent inputs: ZIP-243 under the Yugen branch id, with
  `hashYugen = BLAKE2b-256(personal "ZcashYugenTxHash", transfer bytes)` (proofs excluded) inserted
  after `valueBalance` and before `nHashType`. The transfer hash (spec §7.3) binds `vout` when
  FLAG_VB is set.
- Proofs: A is the yugen-proof-a `e2::Proof` serialisation, B the yugen-proof-b2 `ZkLeaf::prove`
  bytes, at the commits in `yewd/yugen/PINS`; the prover configuration is decision Y-W3
  (`decisions.md`).

## W-FINAL: yewd's own `yugen_*` RPCs

`yugen_newaddress`, `yugen_shield [addr, amount]`, `yugen_send [addr, amount, {"route":"leaf"}]`,
`yugen_getbalance`, `yugen_listreceived`, `yugen_sync`, `yugen_listnotes`, `yugen_status [nf1]`.
yewd finds the engine binary `yewd-yugen` beside itself, under `yewd/yugen/target/{release,debug}/`,
or by `-yugenbin=<path>`; its data lives in `<datadir>/yugen/`.
