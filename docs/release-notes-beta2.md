<!-- Copyright (c) 2026 The Ycash developers. Distributed under the MIT software license. -->

# YEW and yewd: beta2 wallet notes

YEW is the Ycash light wallet: the YEW core, the mobile app and the web wallet. `yewd` is the YEW
core as a daemon: the wallet sidecar for kogany, answering a subset of ycashd's wallet RPCs. This
beta brings them to the same behaviour as the C++ nodes (ycashd 6.22.0-beta2) for Ycash Yellowback
(YED) and plain YEC: sends between every address type, balances by type, and post-quantum addresses
that show their scheme. No consensus change.

## What changed

### Addresses and the RPC contract

- A post-quantum address names its scheme in its third character: `sqf…`/`sqs…` (FN-DSA-512 /
  SLH-DSA) for YEC, `ybf…`/`ybs…` for YED on mainnet; `tqf`/`tqs`/`ytf`/`yts` on testnet;
  `rqf`/`rqs`/`yrf`/`yrs` on regtest. The earlier form is refused everywhere.
- `yewd` rewrites its address book to the new form once, at load, keeping labels.
- **The YED receive address is the Falcon holder in the app and the web wallet.** Both take it from
  one function in the YEW core. The web wallet used to show the ECC-key form (35 characters), which
  senders refuse from the Falcon height (`bad-yed-holder`; on mainnet and testnet, from the first
  block), so it could not receive YED from another wallet. No YED could arrive at the old form, so
  none is stranded there.
- `yewd z_validateaddress` answers for a post-quantum address with ycashd's fields, in ycashd's
  order: `isvalid`, `address`, `address_type` and `type` (`pq`), `ismine`, `pqscheme`,
  `pqschemename`, `pqkeyhash`. Before, it answered `isvalid: false`.
- The wallet requires RPC contract version 9 exactly (`yed_getinfo.rpcversion`). It does not work
  with a node or lightwalletd at version 8.
- `yewd getnewaddress` takes the type first (`pq`, `pqslh`, `p2pkh`); `getnewaddress "" <type>`
  still works. Another first string is refused with ycashd's text. Its help
  names the scheme-visible prefixes.

### Balances by type

- App and web wallet: Private, Public (ECC), PQ · SLH-DSA, PQ · FN-DSA-512. Held outputs and YEC
  staged for a mint in progress are shown on their own rows and never count as spendable.
- `yewd`: `getwalletinfo` adds `balance_ecc`, `balance_pq`, `unconfirmed_balance_ecc`,
  `unconfirmed_balance_pq` and `pq_by_scheme`. `z_gettotalbalance` (with `transparent_ecc`,
  `transparent_pq`, `pq_by_scheme`) and `listaddresses` (with a `pq` list) are new, read-only.
  `listreceivedbyaddress` and `validateaddress` name the scheme.
- `yewd z_getbalance` takes the wallet's own post-quantum address and refuses a transparent address
  the wallet does not hold: `From address does not belong to this node, transparent or post-quantum
  key or watch-only script not found.`

### Sends between every address type

- `yewd z_sendmany`: from an ECC, SLH-DSA, FN-DSA-512 or Sapling address to any mix of recipient
  types, with ycash6's fees, dust thresholds, privacy-policy refusals and error texts. Post-quantum
  change returns to its source address. A transparent-only `z_sendmany` needs no Sapling proving
  parameters.
- `yewd vault_lock` takes `"from"`: any of the wallet's address types.
- App: a **From** chooser (Automatic, one of the wallet's post-quantum addresses, or Private toward
  a post-quantum recipient). The preview shows the fee, the signed size, the signing time, the change
  and, for payments that leave the private balance, a privacy notice.
- Web wallet: the same, except three shapes (see Known limitations).
- **`yewd sendtoaddress`, `sendmany` and `fundrawtransaction` choose ECC coins
  only**, as ycashd 6.22.0-beta2 does (the beta2 decision, confirmed by the Yellowback lead architect
  on 2026-11-12). Short of ECC coins while post-quantum coins exist, they refuse with ycashd's
  `Insufficient funds in ordinary transparent addresses; this wallet also holds <amount> YEC at
  post-quantum addresses: send from one with z_sendmany, which returns the change to it`. A
  post-quantum input that `fundrawtransaction` is given stays, and is priced by its size.
- **Public YEC to someone else's private address.** The app and the web wallet
  can pay another wallet's Sapling (`ys1…`) address from the public balance. A send from public
  coins takes one address's coins; combining several public addresses in one transaction (which
  links them on the chain) needs the user's go-ahead in the app and is refused in the web wallet.
  `yewd z_sendmany ANY_TADDR` combines addresses only where the privacy policy allows it
  (`AllowLinkingAccountAddresses` or `NoPrivacy`), as ycashd does.
- A public send whose change would be exactly 0.0001 YEC (the value a YED token
  output carries) lowers the change by one zatoshi and adds it to the fee, instead of putting the
  whole 0.0001 YEC into the fee.

### Mints funded from a chosen source

- The app and the web wallet open a vault only through a mint. **Fund from** selects the source:
  the public (ECC) balance, a post-quantum address, or (app only) the private balance. The mint
  transaction itself is unchanged; only the funding step depends on the source.
- From a post-quantum address or the private balance, the YEC for the mint is first staged on a new
  key of the wallet. It is locked to that mint until the mint spends it, or until the mint lapses
  or fails, when it becomes ordinary YEC again.
- `yewd yed_mint` checks the mint's whole need (collateral, fees and the
  carrier), from coins and from Sapling notes, before it broadcasts the carrier, as ycashd does.
  The app's mint estimate prices the inputs the mint will take, and the mint total shown is what
  leaves the balance. An unarmed price feed blocks a mint up front on every network.

### Claims in the web wallet

- **A claim in the browser completes.** It runs in two steps, as in the app: the carrier first,
  then the claim itself once the carrier is confirmed. Before, the web wallet sent the carrier,
  reported "Claim sent" and never sent the claim. The screen now says which step was sent
  ("Claim: step 1 of 2 sent").
- A claim or mint left between its steps is listed under **In progress** on the Yellowback and
  Claimable screens. **Continue** resumes it, also after a reload. When the claim's window has
  closed, the screen offers to sweep the carrier back.
- A claim whose second-step fee rose above what its start accepted asks again ("Slide to send the
  claim at this fee").
- The Claimable list offers only vaults the node judges claimable. The others are listed apart
  under "Not claimable now" and are refused if chosen.

### Fees

- The wallet cannot verify the YEC price a server reports. It refuses fee terms above the rates a
  node would charge at a compiled floor price of $0.01 per YEC, and no post-quantum send pays more
  than 10 YEC.
- A fee is **unusual** when it is above twice the usual fee at the wallet's reference price (the
  median of the last 30 days of the server's price reports, one per day, moved at most ×4 per
  report), or when the server's price is below half the reference. While the reference is weak
  (fewer than three days of reports, or below $0.05), any fee above 0.1 YEC is unusual.
- An unusual fee needs a **separate confirmation**. Without it the send is refused. A mint whose
  finishing fee rose above what its start accepted asks again.
- When the wallet refuses a server's fee terms, the web wallet shows why and
  never shows a 0 FN-DSA or YED balance.

### Keeping YED from being spent as plain YEC (yewd)

- With an unhealthy or unreadable Yellowback index on the node, plain-YEC sends are refused.
- **The has-held-YED guard.** A wallet that has held YED refuses plain-YEC sends while the
  connected node reports Yellowback not live: `This wallet has held YED, but Yellowback is not live
  on the connected node, so its YED outputs cannot be told apart from plain YEC. Connect to a node
  with the network's attestor set, or start yewd with -yellowback=0 to acknowledge that they are
  spendable as plain YEC.` yewd checks at send time, not at start, because it can be pointed at
  another node without a restart. `getwalletinfo` reports `yed_unlocked`, as
  ycashd does.
- **Outputs the node's index has not judged.** An output whose transaction the
  node's Yellowback index has not judged yet (Yellowback not live, or its block above the index
  height) and whose payload may give it YED (a MINT token, a TRANSFER or REDEEM assignment, a claim
  cancel's refund) stays out of every plain-YEC send.

### Private (Sapling) balance

- **Sapling change is found and spent.** Change notes at the internal scope were not recognised as
  the wallet's own, so a second private send could fail ("key-mismatch: a spent note is not this
  account's"). No funds were at risk. The cause is upstream (sapling-crypto 0.7.0's
  `decrypt_diversifier` never answers the internal scope); yew checks ownership in the named scope
  itself.
- **Notes from before Canopy** (mainnet below height 1,100,006) can be spent.
- **Web wallet restore with the default birthday** scans the private pool from the start. Before,
  a birthday of 0 was read as "seed made here" and the scan started at the tip, so a restored
  wallet showed no private balance.

### Sapling proving files

- The web wallet fetches the Sapling proving files from **its own origin** (`/sapling-params/`) by
  default; `download.z.cash` sends no CORS header, so a browser could not use it, and the default
  web wallet could not shield or send privately. The hash check stays mandatory. ycash-infra's web
  image serves the files from the project's `zcash-params-v1` release.
- The app keeps `download.z.cash` and falls back to the Ycash developers' mirror. A source can be
  typed in Settings, and a refused fetch says why.

### yewd answers

- An accepted transaction always returns its txid. If the node's answer is lost, the txid is looked
  up; otherwise the answer is "status unknown, txid …: check before sending again", and the inputs
  stay locked until the transaction is dead or `clearunknownsubmission` releases them.
- A wrong argument count to a method yewd forwards to its node answers
  ycashd's `-32602` with ycashd's help, also when the node is koganyd (which itself answers `-1`).
  `z_getnewaddress sprout` is refused with ycashd's text.
- On regtest, yewd and the core take the network-upgrade heights from the
  node or server instead of assuming Canopy from height 1.
- **`yewd vault_lock "from"` answers the vault RPC contract's codes, with the C++ nodes' texts.**
  `from: not an address of this wallet` and `from: an FN-DSA-512 (scheme 2) address cannot be spent
  before Falcon is active at the next block` answer `-5` (they were `-4` and `-8`). A Sprout address
  answers `-5` `bad-address: from: Sprout addresses are not supported`. A Yellowback outpoint at the
  address is refused with `… (its YED would burn; lock it again with yed_lockcoins)`. yew carries a
  pinned copy of the vault RPC contract, and a test checks every `"from"` error row against it.

- **`yewd -mnemonicfile` finds every coin of its own phrase, as ycashd's seed-only restore.** It
  holds 101 transparent keys per chain past the last one used (ycashd's `-keypool` + 1; it was
  100) and 20 post-quantum keys per scheme, and when that window grew during the scan it reads the
  scanned blocks again until nothing more is found, so keys paid out of chain order are found.
  Before, a restore missed coins paid after a gap of 100 unused addresses and keys paid out of
  order (10 of 311 outputs in ycash6's `wallet_seed_restore_ecc.py`). A restore stopped part-way
  resumes where it was, and `getwalletinfo` reports `restore_in_progress` and
  `lookahead_incomplete` (always false in yewd). A restore reads its blocks about twice; an
  ordinary start reads them once, as before.

### Testnet is the fast profile

- **The testnet YEW and yewd sign for is testnet-yb-fast**, the profile the project's testnet seeds
  run (`-testnet -testnetprofile=fast` on ycashd): Overwinter 207,500, Sapling 280,000, Ycash
  510,248, Blossom 510,250, Heartwood 510,252, Canopy 510,254, **Vault 510,400**, and the fast YED
  terms (grace 103 blocks, claim delay 20 blocks, term classes of 103 to 309, 310 to 618 and 619 to
  1,252 blocks). The heights are pinned by a fixture generated from ycash6, which CI regenerates and
  compares. Before, the app and the web wallet signed nothing on testnet from the Vault height on,
  and YEW read testnet's YED terms with mainnet's values. Mainnet and regtest are unchanged.
- `yewd -testnetprofile=fast` is the default with `-testnet`. `slow` and `legacy` are refused: they
  are shadow forks of mainnet whose branch ids librustzcash6 does not define. `-testnetprofile`
  without `-testnet` is refused, as on ycashd.
- yewd keeps its testnet wallet and cookie in `<datadir>/testnet-yb-fast/`, ycashd's name. If an
  older yewd's `<datadir>/testnet/` exists and the new one does not, yewd stops at start with
  `yewd: <old> is the testnet directory of an older yewd; testnet-yb-fast's is now <new> (ycashd's
  name for the profile): move it there and start again`.
- yewd checks that its node is on testnet-yb-fast (`chain`, `testnetprofile` and the Vault height
  in `getblockchaininfo`); otherwise wallet calls fail with `yewd: the backend is not on
  testnet-yb-fast: …`. The startup line names the network (`network test (testnet profile fast)`).
- On testnet, private (Sapling) transactions are refused (see Known limitations): the refusal names
  the first upgrade height on which librustzcash6 and the node disagree.

### Dependencies

- yew builds against librustzcash6 6ff87bc9, rusqlite 0.41.1 (bundled SQLite 3.54.1) and, in the
  browser, sqlite-wasm-rs 0.6.3 with sqlite-wasm-vfs 0.3 (SQLite 3.54.1). This fixes
  RUSTSEC-2026-0459 (CVE-2026-119375) in both builds, and its exception is removed from every
  scanner configuration.
- A wallet written by the earlier build opens under the new one. For the app and yewd a test opens
  stores written by SQLite 3.51.3. For the web wallet, a funded wallet made by the earlier bundle was
  opened by the new bundle in the same Chrome profile: same addresses, birthday, balances and
  history.

### Tested against real nodes

yewd was run against ycash6 and against koganyd (koganyd as its node and miner), and the web wallet in
a headless browser against a node, lightwalletd-dd and a gRPC-web front. yewd: all sixteen send
shapes between address types accepted, mined and balanced against both nodes; vault locks from every
source, mints, YED sends and redeems; seed restore. Web wallet: all fourteen browser send shapes,
mints from the public balance and an FN-DSA-512 address, a redeem, and the unusual-fee confirmation
completing a send. After the web fixes above, the browser received YED from a ycashd wallet at its
Falcon holder, spent it, and completed a claim through both steps, including a reload between them.
No YED was ever spent as plain YEC. Not run in a real browser: sweeping back a lapsed claim carrier
(covered by the web tests only).

## Known limitations

- **Three shapes are app only.** The web wallet cannot send post-quantum → private, private →
  post-quantum, or fund a mint from the private balance: the builder they need is not compiled for
  the browser in this beta. The web wallet says so and does not offer them.
- **A post-quantum → private send copies the Sapling spending key.** It needs only the outgoing
  viewing key, but the builder copies the full spending key, and the copies are not zeroized. A
  memory disclosure during such a send would expose that key. Accepted for this beta as the beta2
  decision; the fix follows after beta2.
- **The fee reference follows the server's price reports.** A server that is the wallet's only
  source of reports for more than half of the 30-day window sets the reference, moving it by at most
  ×4 per day. A fee below the bound but within twice the usual fee is then not confirmed separately.
  The reference can be reset in Settings (or `fee-reference --reset` in the command-line tool).
- **The has-held-YED mark is not derived from the seed.** A wallet restored from its seed against a
  server without Yellowback has never seen its YED and is not marked. Restore only against a server
  with Yellowback.
- **A ycashd recovery phrase and a yewd one derive different transparent keys.** yewd and YEW use
  `m/44'/347'/0'`, ycashd its seed's legacy account. Moving a wallet between them by phrase does not
  bring its transparent coins; send them instead. A restore misses a coin paid after more than 100
  unused transparent addresses or 20 unused post-quantum keys of a scheme (as ycashd): issue
  addresses past the gap and restart with `-rescan`.
- **YED cannot be minted on the fast testnet** with the current node builds: no attestor set is
  compiled in.
- **No private (Sapling) transactions on testnet.** librustzcash6 still has the old Ycash testnet's
  Blossom, Heartwood and Canopy heights (661,610 / 661,622 / 661,634) and no Vault height, so a
  Sapling transaction built for testnet-yb-fast would carry the wrong branch id and note format.
  The app, the web wallet and yewd refuse to build one, and the private balance cannot be synced
  there. Public and post-quantum sends are not affected. The fix is a librustzcash6 change carrying
  the fast heights, then a dependency bump in yew.
- **The slow and legacy testnet profiles are refused.** Signing for them needs librustzcash6 to
  define their shadow-fork branch ids.
- **The app and web wallet reuse an existing testnet wallet file silently.** The store keeps its
  name (`yew-test.sqlite`) under the new testnet parameters; its keys are unchanged. yewd, by
  contrast, stops until an old testnet directory is moved.
- **Not tested:** a web wallet store that the earlier bundle left with a hot journal (a tab closed
  in the middle of a write), and the web wallet in Firefox.
- **`yewd` does not serve `z_mergetoaddress`**; it answers only its refusals.
- `yewd` prices sends with no post-quantum party at the ZIP-317 fee, where ycash6 defaults to a flat
  1,000 zat; both are at or above the node's rule. Aligning them follows after beta2.
- **No privacy note in the app for a public-funded payment to a private
  address.** When the private balance falls short, the app can pay a `ys1…` address from the public
  balance by itself; the web wallet says that the amount and the public source address are visible
  on the chain, the app's preview says only "From: your public balance".
- **A shield from many small public coins can be refused by the node.** About 49
  or more inputs exceed the node's unpaid-action limit at the 1,000-zat fee (as with ycash6's own
  `z_sendmany`). Nothing is locked or lost; send a smaller amount or merge coins first.
- **The web Mint screen can show a stale "Minting is open"** after a failed
  refresh. The mint itself still goes through the core's gate and the node's policy.
