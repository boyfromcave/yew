<!-- Copyright (c) 2026 The Ycash developers. Distributed under the MIT software license. -->

# YEW and yewd: beta3 wallet notes

YEW is the Ycash light wallet: the YEW core, the mobile app and the web wallet. `yewd` is the YEW
core as a daemon: the wallet in front of koganyd, answering ycashd's wallet RPCs. This beta pays the
same fees as the node's own wallet on every plain send, makes the unusual-fee question rarer and
clearer, and closes yewd's remaining gaps against ycashd's wallet (ycashd 6.22.0-beta3, koganyd
1.8.0-ycash beta3). No consensus change.

## What you must do when upgrading

- **Servers and nodes.** The wallet works with a node or lightwalletd at Yellowback RPC contract
  version 9 (beta2) or 10 (beta3), and refuses any other version, naming the accepted range. Version
  8 servers are still refused.
- **yewd beside koganyd.** yewd has no release binaries: build it from the yew commit named in the
  beta3 release (`cargo build --release --locked --manifest-path yewd/Cargo.toml`). yewd's README now
  has a step-by-step section, "Running yewd beside koganyd". yewd listens where ycashd would, so give
  koganyd's RPC another loopback port.
- **yewd built at the beta2 train commit.** The beta2 release train named yew `6d9017e`; the koganyd
  beta2 notes named `fc56fba7`. Three yewd fixes listed below (post-quantum fee, YED burn guard,
  seed restore) are in `fc56fba7` and later only. If you restored a yewd wallet from its phrase with
  an older build, restore it again with this one.

## What changed

### Fees on plain sends (app, web wallet and yewd)

- **A Sapling send pays what ycashd's own wallet pays for that shape**: a flat 1,000 zat with up to
  50 Sapling outputs, under the node's default fee policy. Before, the app paid Zcash's ZIP-317
  marginal fee (5,000 zat per action) and the web wallet 10,000 or 15,000 zat. This covers private to
  private, private to public, private to post-quantum, and public to private. Sends with a
  post-quantum input keep the node's size-based fee; a mint carrier funded from the private balance
  keeps the Yellowback builder's rule.
- **Moving everything to public** leaves no private change.
- **yewd** `z_sendmany` and `z_mergetoaddress` use the same fee rule, so a yewd send without a
  post-quantum party pays ycashd's flat 1,000 zat instead of the ZIP-317 fee (a beta2 limitation).

### The unusual-fee question

- The question compares the fee with the node's own fee for the same shape.
- **A fee of 0.01 YEC or less is never asked about.** The floor applies per guarded transaction, so a
  mint (carrier and mint) can pass up to 0.02 YEC without the question. A claim after a price drop
  no longer asks "5.0x the usual" about a few cents.
- When only the server's YEC price is low (the fee in dollars is normal), the confirmation is titled
  **YEC price check** instead of "Unusual fee".
- The hard fee caps are unchanged.

### Post-quantum balance on a server that cannot index it

- When the server cannot look up post-quantum addresses, Home says so ("This server cannot look up
  post-quantum addresses: their YEC is not shown here (it may not be 0)…") instead of showing 0.
- A post-quantum coin the wallet holds back because its creating transaction assigns it YED marks the
  wallet as having held YED, as a listed YED token does.

### The hosted web wallet (fast testnet only)

- **https://fastnet-wallet.ycash.team** serves the web wallet built for the fast testnet, with a
  "Fast testnet: coins here have no value" banner above every screen. Its server is fixed to the
  fast testnet's lightwalletd (`fastnet-lightwallet.ycash.team`): it cannot be changed, and no
  proving-file mirror can be set.
- **Keys stay in the browser.** The seed is kept encrypted in the browser's storage (passkey or
  passphrase) and is never sent. The page talks only to that lightwalletd and to its own origin,
  which serves the page and the Sapling proving files (the project's copy, checked against the
  pins in `core/src/sapling_params.rs`).
- **An answer is shown only for the selection it was asked for.** On Receive, Send, Vault and
  Settings a slow answer could arrive after you had changed the selection and be shown under the new
  one (for example an address of the previous type). Such an answer is now dropped. A payment was
  never affected: Send confirms the preview it was shown, by that preview's id.
- **Deployed by hand.** A merge never changes what the name serves: a maintainer runs the
  `web-wallet-deploy` workflow. `/BUNDLE-SHA256SUMS` and `web/scripts/verify-bundle.sh` let you
  compare what the name serves with a build of the commit (`web/README.md`).

### yewd: the gaps against ycashd's wallet

- **Watch-only.** `importaddress` (an ECC P2PKH or P2SH address, a post-quantum address, or a script
  in hex; with `p2sh`, a redeem script and its P2SH) and `importpubkey`, with ycashd's arguments and
  refusals. Watched coins are followed but never spent. They count in `getbalance`,
  `z_gettotalbalance`, `listtransactions`, `gettransaction` and `listreceivedbyaddress` only with
  `includeWatchonly`; `listunspent` lists them `spendable: false`; `validateaddress` says
  `iswatchonly`; `listaddresses` lists them under `imported_watchonly`. An import rescans from
  genesis over RPC by default, which takes hours on mainnet: give `rescan=false` to every import but
  the last. A rescan cut off resumes at the next start.
- **`z_mergetoaddress`** is served: ECC, post-quantum and Sapling sources into one ECC, post-quantum
  or Sapling output, with ycashd's limits, fee and errors. A named P2SH source is refused (`-8`,
  saying why), and `ANY_TADDR` leaves P2SH coins out.
- **`getunconfirmedbalance`** is served. `z_getnewaccount`, `z_getaddressforaccount`,
  `z_listaccounts` and `z_getbalanceforaccount` answer `-8`, as ycashd does while NU5 is not active
  (Ycash schedules no NU5).
- **Vault coin locks are always released**, also when a vault call is cancelled; a lock scope left
  by an interrupted call ends at the next call or at open, and `yed_buildcancel` is scoped too.
- **A vault lock's funding change** goes to a listed external key, so it shows in `gettransaction`'s
  details.
- **Help texts and arity** are regenerated from a beta3 ycashd, including the forwarded
  `getcoinbasetemplatefor`.

### A post-quantum block reward (yewd)

- **yewd's `z_sendmany` shields a post-quantum coinbase**, as ycashd's does in this beta: a pool can
  pay a block reward straight to a post-quantum address (the node's `getcoinbasetemplatefor`). Once
  the coin has 101 confirmations, `z_sendmany` from the address spends it when every recipient is
  shielded, with no change, and when the address's other coins do not cover the send. A send that
  would leave change is refused with the exact amount to send (`-4`); an "Insufficient transparent
  funds…" refusal (`-6`) names the coinbase the send could not use, and immature coinbase as "… which
  can be sent to shielded recipients only, with no change, after 101 confirmations."
- **For a miner or pool operator:** pay a post-quantum reward to an address held in a yewd or ycashd
  wallet, never to one only the YEW app or the web wallet holds (below, "Known limitations"). To
  move rewards, name an amount, read the exact amount in the refusal and send that. Coins are taken
  largest first, so a call moves one reward unless the amount is more than the largest one. Two
  rewards of 6.25 at an FN-DSA address (amounts made up; the fees are those ycashd 6.22 charges on
  regtest, and yewd charges the same in front of koganyd, measured on real nodes by
  `yewd/qa/parity/yewd_pq_coinbase_spend.py`; the refusal always names the exact figure):

  ```
  z_sendmany "<sqf… address>" '[{"address":"<ys1… address>","amount":1}]'
    -> -4 When shielding coinbase funds, the wallet does not allow any change. The proposed transaction
          would result in 5.249935 in change. To spend the selected coins, send exactly 6.249935 to shielded
          recipients (the 6.25 selected less the fee 0.000065).
  z_sendmany "<sqf… address>" '[{"address":"<ys1… address>","amount":7}]'
    -> -4 … would result in 5.49988 in change. To spend the selected coins, send exactly 12.49988 to
          shielded recipients (the 12.50 selected less the fee 0.00012).
  z_sendmany "<sqf… address>" '[{"address":"<ys1… address>","amount":12.49988}]'
    -> both rewards in one transaction: no transparent output, Sapling outputs only
  ```

- `z_shieldcoinbase` (not served by yewd) and `z_mergetoaddress` do not move a post-quantum reward.
  A transparent (ECC) reward and a Sapling reward are unchanged.

### yewd fixes first shipped at `fc56fba7` (after the beta2 train commit)

- **A post-quantum `z_sendmany` within the post-quantum fee cap** is no longer refused by the node as
  `absurdly-high-fee` (it happened with an SLH-DSA input at a YEC price below about $1.60).
- **Raw spends of YED outputs.** `sendrawtransaction` refuses inputs that are unconfirmed, not yet
  judged by the node's Yellowback index, or unreadable and may carry YED, with ycashd's text and code
  (`-4`); only `allowyedburn` passes. `vault_send` and `set_sendact` refuse `allowinputs` coins that
  hold YED.
- **Seed restore** (`-mnemonicfile`) finds every coin the lookahead covers (101 transparent keys per
  chain, 20 post-quantum keys per scheme, a re-pass when the window grows), and the restore stays open
  until the node has synced. Details are in the beta2 notes and yewd's README.

## Known limitations

- **yewd has no release binaries**; build it from source.
- **yewd does not follow a koganyd restart.** koganyd writes a new RPC cookie at every start and
  answers the old one by closing the connection instead of with a 401, and yewd re-reads the cookie
  only after a 401: every call then fails with "connection closed before message completed" until
  yewd is restarted too. Restart yewd after koganyd. Fixed after beta3 (yewd re-reads the cookie
  after such a close as well).
- **A yewd restore never completes on a chain that is not advancing.** After a restore from the
  recovery phrase against a paused chain (no miner), `getwalletinfo.restore_in_progress` stays true
  although the scan reached the tip: it waits for the node to call itself synced, which it never
  does with an old tip. The balances are complete once the scan is at the tip. Fixed after beta3.
- **The YEW app and the web wallet cannot spend a post-quantum block reward.** They cannot tell that
  a coin is a coinbase (the light-client coin listing, lightwalletd's `GetAddressUtxos`, carries no
  such flag), so they show a reward paid to one of their post-quantum addresses as spendable, and
  the node refuses their sends until the coin is 100 blocks deep and the send has only shielded
  recipients and no change. Pay such rewards to an address a yewd or ycashd wallet holds.
- **yewd watch-only:** no `z_importviewingkey` / `z_exportviewingkey` (watch-only Sapling) and no
  `listsinceblock`. Watched scripts are not in a `z_exportwallet` file and not derivable from the
  recovery phrase: after a restore from either, import them again. While an import's rescan runs,
  confirmed balances read low and every wallet call waits for it.
- **`yewd z_mergetoaddress` does not merge P2SH coins** (the signer has no multisig path); ycashd
  merges them.
- **YED cannot be minted on the fast testnet:** no attestor set is compiled in. Public, private and
  post-quantum YEC work there.
- **The fast-testnet server serves YEC only.** It is built in (`fastnet-lightwallet.ycash.team:443`,
  TLS, the testnet default of the app and of the web wallet's testnet build), but it runs without
  the Yellowback service.
- **The web wallet is hosted for the fast testnet only.** A web page is whatever its server sends
  on that visit; keep money in the apps (`web/README.md`).
- **Passkey unlock is not covered by automated tests.** The headless tests unlock with a
  passphrase; for a passkey only cancelling and the two-minute timeout are tested, with a stand-in
  for the browser's passkey prompt.
- **Three shapes are app only.** The web wallet cannot send post-quantum → private, private →
  post-quantum, or fund a mint from the private balance.
- **A post-quantum → private send copies the Sapling spending key**, and the copies are not
  zeroized (unchanged from beta2).
- **The fee reference follows the server's price reports** (unchanged from beta2): a server that is
  the wallet's only source of reports for more than half of the 30-day window sets the reference.
  Reset it in Settings, or with `fee-reference --reset` in the command-line tool.
- **The has-held-YED mark is not derived from the seed.** Restore only against a server with
  Yellowback.
- **A ycashd recovery phrase and a yewd one derive different transparent keys.** Move transparent
  coins between them with a send.
- **The slow and legacy testnet profiles are refused.**
- **No privacy note in the app for a public-funded payment to a private address** (the web wallet
  shows one).
- **The web Mint screen can show a stale "Minting is open"** after a failed refresh; the mint itself
  still passes the core's gate and the node's policy.
