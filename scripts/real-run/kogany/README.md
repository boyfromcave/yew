<!-- Copyright (c) 2026 The Ycash developers -->
<!-- Distributed under the MIT software license, see the accompanying -->
<!-- file LICENSE or https://www.opensource.org/licenses/mit-license.php . -->

# The kogany real run (regtest)

yewd with `koganyd` as its node, the kogany line's product configuration, beside ycashd peers
that judge every block and transaction. It is the yewd leg of [`../README.md`](../README.md) with
kogany as the pair's backend. Not part of CI: one run takes about 50 minutes and needs built
binaries from three other trees.

| node | role |
|---|---|
| 0 | plain ycashd wallet: mines the first 200 blocks, the attestor set, a quoting YED pool |
| 1 | the pair under test: `koganyd --features ycash` + yewd + yewd-signer (ycash6's `YEWD_BIN` + `YEWD_KOGANY` harness, `YEWD_SOLVE=1`); yewd reads koganyd over RPC and its indexer gRPC |
| 2 | plain ycashd wallet: the receiver of the matrix, the façade's reference |
| 3 | plain ycashd wallet with `-insightexplorer`: imports yewd's `z_exportwallet` dump (the observer) and is the address index `kparity` compares with |

Phases (`--phases=`, default all):

- `addr`: addresses of every type from yewd; `validateaddress` on yewd, koganyd and ycashd.
- `matrix`: the 16-cell `z_sendmany` matrix (ECC, Sapling, FN-DSA, SLH-DSA), broadcast through
  koganyd, fees against ycash6's.
- `restart`: unconfirmed sends survive a restart of the pair.
- `yed`: vault locks from each source, mints, `yed_send`, `yed_redeem`; kogany and ycashd state
  hashes after each step.
- `facade`: yewd against a ycashd wallet for the calls users type.
- `kparity`: koganyd's own answers against ycashd's for the read RPCs both serve, with
  post-quantum addresses, field by field.
- `restore`: wipe yewd, restore from the phrase, rescan; balances equal.

A per-type balance check against koganyd's address index, the chain's UTXO set and the observer
runs at each step.

```bash
W=<workspace> Y6=<built ycash6 tree> K=<kogany tree> scripts/real-run/kogany/repeat.sh run1 <portseed>
```

The results are in `$S/<run>/results.json` (default `S=target/kogany-real-run`), and the log is
next to it. Every finding is a `FINDING <severity>` line.

Traps:

- The pair backend's cookie is `node1/backend/rpc/.cookie`.
- Without `YEWD_SOLVE=1` kogany's regtest `generate` makes blocks that ycashd refuses.
- Mints need a price: kogany must quote as a pool (`activate_yed_late(test, [0, PAIR], …)`
  sends `yed_setquote` through yewd).
- Use a fresh `--portseed` per run.
