<!-- Copyright (c) 2026 The Ycash developers. Distributed under the MIT software license. -->

# Address types, sends between them, and the safety layers

_YEW 1.x, beta2 (workspace plan `wt/beta2-address-interop-plan.md`, decisions D-2 … D-9). What the
app and the web wallet can send between Ycash address types, which gate path each send passes,
what stays with the full node, the layers that keep a light client from burning Ycash Yellowback
(YED) through a lying server, what each send reveals, and what is still unproven._

## 1. The address types

| type | prefix (mainnet / testnet / regtest) | holds | spent by |
|---|---|---|---|
| Private (Sapling) | `ys1…` | YEC; amounts, parties and memos hidden on chain | Sapling notes, proven on the device |
| Public (ECC) | `s1…` (`sm…` testnet/regtest) | YEC, the fee reserve | secp256k1 P2PKH |
| Public, YED form | `yb…` (35 characters), or the 53-character Falcon holder `ybf…` | YED and the YEC that pays its fees | secp256k1 / FN-DSA-512 |
| Post-quantum · FN-DSA-512 | `sqf…` / `tqf…` / `rqf…` | plain YEC only | FN-DSA-512 (~1.6 KB signature) |
| Post-quantum · SLH-DSA | `sqs…` / `tqs…` / `rqs…` | plain YEC only | SLH-DSA-SHA2-128s (~7.9 KB signature: the largest fees) |

The post-quantum forms are bound to their asset (D-Q-20, D-Q-21): YEC goes to `sqf…`/`sqs…`, YED
to `ybf…`. Each screen refuses the other form before it asks the core, and the core's builders
refuse it again. The scheme is part of the prefix (D-9), so the receive screen shows it in the
label and in the address.

Balances are shown per type: Private, Public (ECC), PQ · SLH-DSA, PQ · FN-DSA-512. Two amounts are
in no balance and never in a spendable total, and are shown on their own:

- **held** outputs (class `HELD`). These are outputs of exactly `TOKEN_VALUE` that the server does
  not list as YED, and plain coins whose creating transaction assigns them YED or could not be
  checked. They are never spent as plain YEC.
- **YEC staged for a mint in progress.** This is the staged funding output of a mint funded from a
  post-quantum address or the private balance. It is locked to its mint row
  (`staged-for-mint:<id>`) until the MINT spends it, or until the row lapses or fails, when it
  becomes ordinary YEC again. The app does not show this amount yet; the web wallet does
  (`build::mint::staged_for_mint_zat`).

## 2. The send matrix

The **From** chooser offers three choices:

- **Automatic.** The private balance pays first, then the public balance.
- **One of the wallet's post-quantum addresses**, with its balance.
- **Private**, only toward a post-quantum recipient.

Each cell below names the core builder and the gate path that both gate layers check.

| from \ to | Public ECC `s…` | Post-quantum `sqf…`/`sqs…` | Private `ys1…` |
|---|---|---|---|
| **Public (ECC)** | Automatic, when the private balance cannot pay: `yec_send`, `Path::Yec` | Automatic (a post-quantum recipient is always paid from public coins): `yec_send`, `Path::YecToPq` | Only to the wallet's own private address, through **Move → Public to private**: `yec_move`, `Path::Shield`. A `ys1…` recipient is always paid from private notes, so ECC coins never pay a foreign `ys1…` directly. |
| **Post-quantum** | `pq_send`, `Path::PqSpend`; change goes back to the source (D-4) | `pq_send`, `Path::PqSpend` | `pq_send` + the hybrid builder, `Path::PqToSapling`. **App only**: not available in the web wallet |
| **Private (Sapling)** | Automatic, when the private balance covers it: `yec_private`, `Path::Shielded` (the preview carries the privacy notice) | From: Private, `sapling_pq`, `Path::SaplingToPq`. **App only**: not available in the web wallet | Automatic: `yec_private`, `Path::Shielded` |

**Funding a mint ("Fund from").** The MINT itself does not change. Only the carrier funding
transaction depends on the source.

| source | builder | gate path of the carrier funding | web wallet |
|---|---|---|---|
| Public (ECC) | `mint::carrier_step` | `Path::Carrier`: vout = [carrier P2SH, at most one P2PKH change to the key recorded before the build] (the claim's carrier funding has the same shape) | yes |
| Post-quantum address | `mint::carrier_step_pq` | `Path::CarrierFromPq`: vout = [carrier P2SH, staged P2PKH], change to the source | yes |
| Private | `mint_sapling::start_from_sapling` | `Path::CarrierFromSapling`: no transparent input, vout = [carrier P2SH, staged P2PKH], Sapling change | **no** |

A mint start takes its terms from the estimate the core issued, never from the screen: the web
wallet passes only the core's estimate id and the acknowledgement tokens; the app's terms must equal
the estimate the core issued for the same amount, lock and source. The carrier fee shown is the
most the funding may pay.

**Why three shapes are app only.** Three shapes use the hybrid builder (`core/src/build/hybrid.rs`):
post-quantum → private, private → post-quantum, and a mint funded from the private balance. That
builder is compiled for native targets only (`#[cfg(not(target_arch = "wasm32"))]`). The web
wallet does not offer these shapes and shows the core's one-line reason (`unavailable_shapes`). The
wasm core answers each with `unsupported: …`:

- **Post-quantum → private** and **a mint from the private balance** are refused outright
  (`pq_send_preview` to a `ys1…` address; `mint_estimate` with `from = private`).
- **Private → post-quantum** has no builder in the browser at all: `send_yec_preview` pays a
  post-quantum recipient from public coins only. When the public balance is too small and the
  private balance holds spendable YEC, the answer is `unsupported: This browser wallet cannot pay a
  post-quantum address from the private balance; use the mobile app or move funds to a public
  address first.` (`yec_private::pq_recipient_needs_private`). With no private YEC either, it is the
  ordinary `insufficient-yec` error.

To enable them in the browser:

1. Compile `build::hybrid`, `build::sapling_pq` and `build::mint_sapling` for wasm32.
2. Give the hybrid builder the browser's prover. Today it reads the parameter files from
   `params_dir`; the browser keeps them in memory (`Shielded::set_prover_bytes`).
3. Replace the native clock in the proving-time measurement.
4. Run the same hybrid vector tests in a wasm test runner.

Every send shows a preview, and nothing can be confirmed without one. The preview shows:

- the fee;
- for post-quantum sends, the signed size and the signing time ("not measured in the browser",
  which has no clock to measure it with);
- the fee note and, for a flagged fee, a **separate** confirmation;
- the privacy notice for payments that leave the private balance.

Refusals, and "…; status unknown, txid …: check before sending again", are shown exactly as the
core words them.

YED sends (`yed_transfer`, `Path::YedTransfer`), redeem, claim and the MINT are unchanged by these
decisions.

## 3. Daemon only

These calls are served by `yewd` (the YEW core as a daemon) and the full nodes. They are not in the
app or the web wallet:

- **`z_mergetoaddress`.** Outside the K-25 RPC set. It merges many inputs into one destination;
  the app's sends pick their inputs themselves.
- **The generic `vault_lock` with `"from"` (D-3).** The app opens a vault only through the MINT. It
  funds that vault from a chosen source with **Fund from** (above), not with a free-standing lock
  transaction.

## 4. The light-client safety layers

A light client cannot see chain state. It sees what the server tells it, and a lying server could
make it spend a YED-carrying output as plain YEC, which burns the YED. These layers stand between
that server and a burn. They are listed in the order a coin meets them.

1. **The server's token list.** At sync, `GetAddressTokens` names the outputs that carry YED; they
   become class `TOKEN` and only the YED builders spend them.
2. **The `TOKEN_VALUE` rule.**
   - An output of exactly `TOKEN_VALUE` that the server does not list is `HELD`.
   - No plain send creates an output of exactly `TOKEN_VALUE`: the amount is raised by 1 zat, and
     the preview says so.
   - The gate refuses any other `TOKEN_VALUE` output, except the carrier (`CARRIER_VALUE` equals
     `TOKEN_VALUE`), which `Path::Carrier`, `Path::CarrierFromPq` and `Path::CarrierFromSapling`
     bind by script.
3. **Provenance, at sync and at broadcast (gate layer 3).**
   - **At sync.** A plain YEC or post-quantum output whose creating transaction could assign it
     YED, or whose creating transaction could not be fetched and checked (txid recomputed), is
     marked `HELD`.
   - **At broadcast.** Before each spend, every plain-YEC input's creating transaction is fetched
     again, its txid recomputed, its payload parsed. Its value and script must equal the stored
     coin.
   - **What the check over-approximates.** YED is assigned only by a payload the node parses, and
     the check treats as YED-carrying:
     - MINT `vout[1]`, exactly;
     - every output a decodable TRANSFER assigns;
     - every output of a REDEEM parent;
     - **the cancelled-claim rule:** every `vout >= 1` of a parent carrying `CANCEL_COSIGN` (the
       node assigns YED to the lowest `vout >= 1` that pays the refund script; the wallet holds them
       all).
     - an unknown Yellowback payload type or version, which is refused.

     The check does not judge whether the assignment was valid: a coin named by a fake payload
     stays unspendable.
4. **The mandatory dry run.** Every path except `Yec`, `Shielded` and `Shield` sends the signed
   transaction to the server's node first (`ValidateRawTransaction`) and needs "valid, burns
   nothing". A server without Yellowback cannot answer, so these sends are refused there:
   post-quantum sends, ECC → post-quantum, carrier fundings, every YED transaction.
5. **The has-held-YED marker.** Once a sync has seen this wallet hold YED, the wallet is marked. A
   marked wallet refuses every plain YEC spend, including `Yec`, `Shielded` and `Shield`, on a
   server whose Yellowback service is not live. **What it cannot cover:** a wallet restored from
   its seed against a server without Yellowback has never seen its YED, so it has no marker. Restore
   only against a server with Yellowback.
6. **The fee bound, the reference price and the second confirmation.**
   - **The bound.** The server's fee terms are refused above the rates of the node's dollar targets
     at a compiled price floor of $0.01 per YEC. No send pays more than this build's limit: 10 YEC
     for a post-quantum send.
   - **The reference price.** A fee is flagged as unusual against a reference price: the 30-day
     median of the server's reports, one per day, moving at most ×4 per day.
   - **When the reference is weak.** With fewer than three days of reports, or below $0.05, every
     fee above 0.1 YEC is flagged.
   - **The second confirmation.** A flagged fee needs the user's separate confirmation, and the
     core refuses it without that confirmation. A mint's finish whose fee rose above what the start
     accepted is refused, with a new acknowledgement in the message.

   **The maximum a hostile server can take per send without the separate confirmation:**

   | state | FN-DSA send | SLH-DSA send | YED transfer |
   |---|---|---|---|
   | first use (no reports: weak) | 0.1 YEC | 0.1 YEC | 0.1 YEC |
   | honest reference $0.30 (≥ 3 days) | 0.24 YEC (honest fee 0.12) | 1.08 YEC (0.54) | 0.38 YEC (0.19) |
   | poisoned low (reference < $0.05: weak) | 0.1 YEC | 0.1 YEC | 0.1 YEC |
   | poisoned high, one $4,000 report on an honest window | as at $0.30 (the median does not move; one report moves it ×4 at most) | as at $0.30 | as at $0.30 |
   | poisoned high, hostile reports on more than half of 30 days | about 0 unflagged; every honest fee is flagged by the low-price rule | same | same |

   **With the separate confirmation**, up to the limit:

   | send | size | limit |
   |---|---|---|
   | FN-DSA | ~1.8 KB | 3.6 YEC |
   | SLH-DSA | ~8.1 KB | 10 YEC |
   | YED transfer | ~1.15 KB | 5.75 YEC |

   **Residual risk.** A server that is the wallet's only source of reports for more than half of
   the window sets the reference (by at most ×4 per day). Two things get out of that: resetting the
   reference (the app's Settings, or `fee-reference --reset` in the command-line tool) and the 0.1 YEC rule for a weak
   reference.

## 5. Privacy

- **Payments that leave the private balance** reveal on the chain what they pay out. The preview
  says so before the slider.
  - Private → a public `s…` address: the amount.
  - Private → a post-quantum address: the amount and the recipient (D-5, the `AllowRevealedRecipients`
    policy of the full node).
  - A mint funded from the private balance: the carrier and the staged YEC paid to a public key of
    the wallet. The change stays private.
- **Spends from a post-quantum address** reveal the source address and its coins, as any
  transparent spend does (`AllowFullyTransparent`).
- **Note-lookup consent.** A private spend built by the hybrid builder (private → post-quantum, a
  mint from the private balance) must decrypt each spent note again from the transaction that
  created it. The wallet reads those transactions from its own store; memo enhancement keeps every
  transaction that paid it a note.
  - If one is missing, the core stops with `NoteLookupNeeded` and asks, in plain words, before it
    asks the server.
  - Fetching links the coming spend to those notes, in the eyes of the server that will also
    receive the spend.
  - Declining sends nothing.

  The web wallet never reaches this question: it does not build these shapes.

## 6. Known limitations

**Key handling**
- **The full Sapling spending key is copied on an output-only send.** A post-quantum → private
  send needs only the outgoing viewing key, yet `SaplingSide` copies the full
  `ExtendedSpendingKey`, and `Hybrid` keeps the spend authorizing keys. None of the copies is
  zeroized: sapling-crypto's types do not implement `Zeroize`. (Reviews YEW-REVIEW-7 L2 and E.)
- **`rseed` is not stored at scan time.** The note store (zcash_client_sqlite) keeps `rcm` only.
  The compact scan does see `rseed`, but inside the light library. So every Sapling-source hybrid
  spend re-decrypts its notes from their creating transactions (see §5). Their `cmu` and value are
  bound to the store's note.

**Gate bindings and the mint**
- **The carrier hash is re-derived from the carrier key and the bundle the start holds**
  (`derived_carrier_hash`, YEW-REVIEW-9 L1), so a `vout[0]` built from another key or bundle fails
  the gate. The bundle itself is the start's verified bundle, the one later stored in the mint
  row; no earlier record of it exists to compare with.
- **A mint from the private balance asks the note-lookup question before it derives any key**
  (YEW-REVIEW-9 L2), so it checks every spendable note, not only the ones the mint will spend
  (their amount is known only after the estimate is re-checked). The count is therefore an upper
  bound, and the question says "up to n transactions"; with the go-ahead only the selected notes'
  missing transactions are fetched.

**Display and tests**
- **Staged-for-mint YEC is shown by the web wallet only**; the app does not show the amount yet.
- **One test skips** where the machine has no Sapling parameters:
  `core/src/sapling_params.rs:989` (`real_parameters_verify_over_file_and_http_when_available`).

### Still to be confirmed against a real node and lightwalletd

None of the following has been run against a real `ycashd` and `lightwalletd`. The core's tests use
a mock chain, the real signer and real Sapling proofs.

**Dry runs**
- The node's dry run accepts:
  - an ECC → post-quantum send (`Path::YecToPq`);
  - a private → post-quantum send;
  - a carrier funded from a post-quantum address;
  - a carrier funded from the private balance (`CarrierFromSapling`, which has no transparent
    input);
  - the MINT that follows each of these carriers.

**Provenance (layer 3) and the store**
- Layer 3 accepts the MINT's staged input whose parent was funded from Sapling.
- lightwalletd's `GetTransaction` answers for mempool parents, under 4 concurrent requests and the
  20 s timeout.
- `GetTransaction` returns a note's creating transaction (the note-lookup path), and
  `NoteLookupNeeded` arises against a real server.
- `Shielded::stored_transactions` re-serializes parsed v4 transactions byte for byte. A parse error
  aborts the spend; it is not treated as "missing".
- Enhancement queues every transaction that paid the wallet a note.

**Fees and addresses**
- The re-acknowledgement of a mint finish against a real fee change.
- lightwalletd's `GetAddressUtxos` accepts the D-9 strings (`sqf`/`sqs`/`rqf`/`rqs`).

**Not run at all**
- `core/tests/devnet.rs`.
- The web wallet in a browser against a server. Only its view-models were run, against a mock core.
