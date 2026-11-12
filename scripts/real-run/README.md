<!-- Copyright (c) 2026 The Ycash developers -->
<!-- Distributed under the MIT software license, see the accompanying -->
<!-- file LICENSE or https://www.opensource.org/licenses/mit-license.php . -->

# The real-stack run (regtest)

yewd and the YEW core driven against a real ycash6 node and lightwalletd-dd on regtest, the
node's own wallets as the oracle. Not part of CI: each leg takes 15-25 minutes (the YED
activation dominates) and needs built binaries outside this repository.

| file | what |
|---|---|
| `yew_real_run.py` | the yewd leg: node 0 a plain wallet (miner, attestor set, YED pool); node 1 the pair under test (ycash6 `-disablewallet` + yewd + yewd-signer, through ycash6's `YEWD_BIN` harness); node 2 the receiver; node 3 the observer, which imports yewd's `z_exportwallet` dump. Phases `addr,matrix,yed,restore`: addresses of every type, the 16-cell `z_sendmany` matrix, vault locks and YED, the seed restore. Results in `$YEW_REAL_OUT/results.json`. |
| `yew_real_light.py` | the core leg: node 0 (`-insightexplorer -txindex`, YED pool) behind lightwalletd `--yellowback`; runs `core/tests/real_run.rs` with the stack's environment |
| `core/tests/real_run.rs` | the core leg's driver: the app API (`yew_core::api`) end to end; every result line starts with `REAL `. `#[ignore]` and a no-op unless `YEW_REAL=1`, so `cargo test` never runs it |

Requirements: a built ycash6 tree (its `qa/rpc-tests` test framework and `src/ycashd`,
`src/ycash-cli`), a lightwalletd-dd binary, the workspace Python (`.venv`), the Sapling
parameters in the default location.

```bash
W=<workspace>; S=<scratch dir>; Y6=<ycash6 tree>; Y=<this yew tree>
(cd $Y && CARGO_TARGET_DIR=$PWD/yewd/target cargo build -j 6 --manifest-path yewd/Cargo.toml --bins)
(cd <lightwalletd-dd tree> && go build -o $S/bin/lightwalletd .)
export YCASH6_QA=$Y6/qa/rpc-tests ZCASHD=$Y6/src/ycashd PYTHONUNBUFFERED=1
# yewd leg; YEW_REAL_PRECANOPY=1 runs regtest without the Ycash upgrades at height 1
YEWD_BIN_PAIR=$Y/yewd/target/debug/yewd YEW_REAL_OUT=$S/run1 \
  $W/.venv/bin/python $Y/scripts/real-run/yew_real_run.py --tmpdir=$S/run1/t --portseed=<n> --nocleanup
# core leg (grep '^REAL ' the log)
LWD_BIN=$S/bin/lightwalletd YEW_TREE=$Y \
  $W/.venv/bin/python $Y/scripts/real-run/yew_real_light.py --tmpdir=$S/light1/t --portseed=<n> --lwdport=<port> --nocleanup > $S/light1/log 2>&1
```

Use a free `--portseed` and lightwalletd port. The test framework stops every node; the light
harness terminates lightwalletd.
