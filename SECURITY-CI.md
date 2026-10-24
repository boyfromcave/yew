# Security CI

YEW holds the user's seed and every key derived from it and signs vault spends on the phone, so its
CI runs security scanners beside the build and tests (`.github/workflows/ci.yml`). Three workflows,
the same shape in every Yellowback repository:

| Leg | Workflow / job | What it scans | Gate | Where results go |
|---|---|---|---|---|
| Semgrep | `semgrep.yml` | Rust core and CLI, shell and Python scripts, workflows, secrets; YEW's own rules (`contrib/semgrep/rules/yew.yaml`) | PR: fails on a **new critical** finding (diff-aware). Push/nightly: report, then `sync` | run summary, code scanning (`semgrep`), at most four rolling PRs `semgrep/<bucket>` |
| Semgrep rule tests | `secops.yml` `semgrep-rules` | `contrib/semgrep/rules/yew.rs` against `yew.yaml` | fails when a rule stops matching its test cases | run log |
| CodeQL | `codeql.yml` | `rust` (build-mode none) and `actions`, `security-extended` | never fails a PR on an existing alert; new alerts show on the PR | code scanning (`codeql/<language>`) |
| Workflow security | `secops.yml` `zizmor` | every workflow and `dependabot.yml` | fails on any finding (default persona) | run summary, code scanning (`zizmor`) |
| Secrets | `secops.yml` `gitleaks` | PR: the PR's commits; nightly, dispatch, push to `upgrade/vault`: the whole history | fails on a leak not in `.gitleaksignore` | run summary, code scanning (`gitleaks`, redacted) |
| Dependency vulnerabilities | `secops.yml` `osv-scanner` | `Cargo.lock` and `app/pubspec.lock` | fails on a known vulnerability not in `osv-scanner.toml` | run summary, code scanning (`osv-scanner`) |
| Rust advisories | `ci.yml` `audit` (cargo-audit, `scripts/audit.sh`) | `Cargo.lock` | fails on an advisory with a reachable fix | run log |
| Code-scanning triage | `code-scanning.yml` (`contrib/secops/code-scanning-triage.py`) | the open code-scanning alerts | dismisses the alerts listed in `contrib/secops/code-scanning-dismissals.json`; never fails on an open one | run summary (alerts left open), artifact `code-scanning-alerts` |
| Dependency updates | `.github/dependabot.yml` | cargo, pub, github-actions | security updates only, one grouped PR per ecosystem; version updates off | Dependabot PRs |

Nightly: Semgrep 02:17 UTC, code-scanning triage 03:53 UTC, devnet (hosted) 03:17 UTC, secops 03:43 UTC, CodeQL weekly (Monday 04:29 UTC). Only Semgrep's `sync`
and Dependabot open PRs; everything else reports to code scanning and the run summary.

**Not covered, and why.** Dart (`app/`): Semgrep's Dart support is experimental with no maintained
security rules in the pinned packs, and CodeQL has no Dart extractor; the app is covered by
`flutter analyze` (ci.yml), OSV-Scanner over `app/pubspec.lock` and review. The vendored Falcon C
(`core/pq-c/falcon`) is a byte copy of the node's PQClean code pinned by `SHA256SUMS`; it is scanned in
the node repositories, not here. The generated bridge (`core/src/frb_generated.rs`, `app/lib/src/rust/`)
is excluded from Semgrep and CodeQL: ci.yml regenerates it and fails on any difference, so a finding
there is fixed in `core/src/api.rs` or the codegen pin.

## YEW's own Semgrep rules

`contrib/semgrep/rules/yew.yaml` (tests in `yew.rs`):

| Rule | Invariant | Bucket |
|---|---|---|
| `yew.keys.non-crypto-rng` | seeds, keys and signing entropy come from `OsRng`/`getrandom`; no seedable or small RNG outside tests | critical |
| `yew.keys.secret-type-derives-debug` | a type named for secret material (seed, mnemonic, private/spending/signing key, WIF, entropy) never derives `Debug` | high |
| `yew.keys.secret-type-implements-display` | ... and never implements `Display` | high |
| `yew.keys.secret-logged` | no seed, mnemonic, key, WIF or passphrase in `println!`/`eprintln!`/`dbg!`/`panic!`/log macros | high |
| `yew.net.unwrap-on-server-response` | no `unwrap`/`expect` in the code that handles lightwalletd replies (`net/`, sync, shielded, gate, wallet) | medium |

## Accepting a finding

Fix it when you can. When a finding is a false positive or a risk taken knowingly, accept it with a
reason a reviewer can check, in the file for that tool:

- **Semgrep**: `contrib/semgrep/accepted.json` (by fingerprint, or a rule over paths), or
  `config.json` `exclude_rules` / `audit_rules` for a whole rule. See `contrib/semgrep/README.md`.
- **gitleaks**: `.gitleaksignore`, one fingerprint per line under a comment that says why
  (test vectors and public constants only; a real secret is rotated, never ignored).
- **OSV-Scanner**: `osv-scanner.toml` `[[IgnoredVulns]]` with `reason` and an `ignoreUntil` at most
  90 days out. cargo-audit's exceptions are `scripts/audit-exceptions.txt`; keep the two in step.
- **zizmor**: fix the workflow; an inline `# zizmor: ignore[<audit>]` with a reason only when the
  pattern is intended.
- **Code scanning (CodeQL and every SARIF upload)**: an entry in
  `contrib/secops/code-scanning-dismissals.json` (tool, rule, path glob, reason `false positive` /
  `won't fix` / `used in tests`, and a comment of at most 280 characters with the argument);
  `code-scanning.yml` dismisses the matching alerts on a push to `upgrade/vault` that changes the
  file and nightly, so the decision is in the history rather than only in the web UI.

## Devnet tiers (`devnet-nightly.yml`)

The devnet acceptance suites (`core/tests/devnet.rs`, `YEW_DEVNET=1`) are non-gating and never run on
a pull request.

| Job | When | Runner | What runs |
|---|---|---|---|
| `hosted` | nightly 03:17 UTC on `upgrade/vault`; dispatch `runner: hosted` from any branch | GitHub-hosted `ubuntu-22.04`, 60 min | node vectors, W1, W2, W4, `q_falcon_*`, `q_pqaddr_*` |
| `self-hosted` | dispatch `runner: self-hosted` on `upgrade/vault` only, no schedule | the owner's `yb-devnet` runner | W1, W2, W4, `q_falcon_*`, `q_pqaddr_*` against the owner's built workspace, no time budget |

Trust rules of the hosted job. `ycashd` is never built there: it is the `node-bin` artifact
(`node-bin.tar`) of a ycash-dd `yellowback-tests.yml` run on `upgrade/vault` whose event is `push`,
`schedule` or `workflow_dispatch` (never `pull_request`, never selected by branch name alone); a
typed `node_run_id` must be numeric and is checked against the same rule, and ycash-dd is checked
out at that run's head commit. The attest agent and lightwalletd-dd (at `proto/PIN`) are built in
the job and never cached. The only caches are the Sapling parameters (download.z.cash, the sha256
sums `zcutil/fetch-params.sh` pins, verified every run) and YEW's own build of the devnet test, each
saved right after the step that fills it and before any node, lightwalletd or test code runs.
Every suite runs against Falcon from the vault activation, as mainnet: W2 and W4 send YED to YEW's
Falcon holder addresses and assert one P2PKH send is refused (`bad-yed-holder`, TOK-PQ). A failure on `upgrade/vault` opens or comments on one issue labelled `devnet-nightly`.

## Repository settings (owner)

- Security → Code scanning must be enabled (free on public repositories) for the SARIF uploads.
- Semgrep `sync` opens its PRs with `GITHUB_TOKEN`: enable *Settings → Actions → General → Allow GitHub
  Actions to create and approve pull requests*; optionally add the secret `SEMGREP_PR_TOKEN`
  (fine-grained, contents + pull requests: write) so CI runs on those PRs.
- Dependabot security updates: *Settings → Code security → Dependabot security updates* on.
