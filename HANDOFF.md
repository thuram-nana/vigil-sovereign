# VIGIL — MASTER HANDOFF (end-to-end continuation doc)

_Written 2026-10-29 so a FRESH session (including a cloud session that has only this GitHub repo and
NOTHING of the local machine, memory, or chat history) can continue EVERYTHING that remains, with no
prior context. Read this top-to-bottom once, then work the Execute Order. Per-wave fix detail lives in the
companion `HANDOFF-enterprise-waves.md` on this same branch (`strix/handoff-20261029`)._

## 0. START HERE — how to continue (and from your phone)

- **The work is entirely on GitHub** (`thuram-nana/vigil-sovereign`): branches `strix/enterprise-*` +
  this `strix/handoff-20261029`, and PR **#974**. Pull locally with `git fetch origin`; nothing of value
  lives only on a local disk (see §5 for the one exception).
- **Continue in the cloud / from a phone:** open **claude.ai/code** (Claude Code on the web) in the phone
  browser, same account; connect GitHub to `thuram-nana/vigil-sovereign`; start a NEW cloud session on
  branch `strix/handoff-20261029`; tell it: *"Read HANDOFF.md and work the Execute Order."* A running LOCAL
  session CANNOT be migrated — you always start a new cloud one. If claude.ai shows no Code/cloud option at
  all, the account/plan does not have cloud Claude Code enabled (that is the thing to fix first).
- **Before running tests in a fresh env**, do the reproducible install in §2 (the local `graphify` venv in
  §2 does NOT exist in the cloud). **Red-pen is NON-NEGOTIABLE before any merge** (§3). **Merge on green
  only.** **No `Co-Authored-By` trailer, no robot PR footer** (§3). **Commit messages via `-F` a file, never
  `-m` with backticks** (§4).

## THE EXECUTE ORDER (what "everything left" means, in sequence)

1. **Unblock merges — bump `litellm`.** The A14 supply-chain gate is RED on `main` and every branch because
   Trivy flags `litellm` 1.90.1 (GHSA-g5ff-637f-6q2m, HIGH) in `vendor/strix/uv.lock`. Fix as its OWN small
   PR, merged FIRST: `cd vendor/strix && uv lock --upgrade-package litellm` (target >= 1.95.0), confirm
   `openai-agents[litellm]==0.14.6` permits it, re-run Trivy, land it. Policy = bump, not `.trivyignore`.
2. **Merge the foundation — PR #974.** Code is already red-pen-sound (2 LOW fixed, 44 tests). Once A14 is
   green it merges first (it is the shared `tenant_id` contract the other waves lean on).
3. **KB wave → PR → merge.** The HIGH cross-tenant symlink leak + the LOW schema-drift are ALREADY FIXED on
   `strix/enterprise-kb` (@ e34f5979, 16 tests). Re-run its red-pen (2 lenses), open the PR, merge on green.
4. **Ticketing wave → PR → merge.** Both MEDs ALREADY FIXED on `strix/enterprise-ticketing` (@ 8ee3386c,
   61 tests). Re-run its red-pen (2 lenses), open the PR, merge on green.
5. **Identity wave — fix the HIGH, then → PR → merge (do NOT rush).** `strix/enterprise-identity` has an
   open HIGH (prune-replay membership/org RESURRECTION — the anti-replay high-water is rebuilt only from
   `iter_records()` with NO SnapshotState seed, unlike `accounts._fold`; and the prune tripwire
   `prune.stranded_active_accounts` ignores `governor.org`/`governor.org_membership`) + a MED (revoke_org
   does not revoke memberships, so `revoke_org`→`create_org` on the same slug resurrects members). FIX:
   seed org + membership into SnapshotState + extend the prune tripwire to the two org signals + correct the
   OVERCLAIMING anti-replay docstring; for the MED, cascade-revoke or epoch-gate memberships to the org's
   current create-grant. Then re-run the HEAVIEST red-pen (3 lenses) and merge. See `HANDOFF-enterprise-waves.md`.
6. **Two product DECISIONS for the owner** (not code — decide, then implement): the **org-admin funnel**
   (who seats members without the trust-root owner key signing — `orgs.py` kept `owner` non-grantable
   per-org) and the **ticketing push RBAC tier** (owner vs operator).
7. **S5+ isolation/scale infra = the APPROVED hosting architecture** (§3): k8s control plane + Firecracker
   ephemeral per-engagement sandboxes + pinned/attestable egress + KMS/Enclave vault, DEFAULT AWS. Ship as a
   Terraform/Helm reference-arch so S5+ is deployable infra, not a design note. This is ALSO what a
   persistent cloud dev environment would be built on.
8. **Then the remaining Strix-shell waves** (continuous coverage, auto-fix, test users, asset discovery, UX)
   and the north-star (sovereign cyber-defense fabric). See §3.

---

## 1. Current VCS state

_As-of 2026-10-29 (after `git fetch origin --prune`). Repo: **`thuram-nana/vigil-sovereign`** (private, GitHub). Default branch: `main`. `gh` authenticated as `Water-Hacker` (scopes: repo, workflow, read:org). All 28 `vigil-wt-*` worktrees + the primary `/home/kali/vigil` checkout share one object store (`/home/kali/vigil/.git`)._

### 1.1 `origin/main` tip

```
999d6cc4d30cf96a0289d8d0afaaf48c9ff96917   (short: 999d6cc4)
2026-10-29 13:31 +0100  "Merge pull request #973 from thuram-nana/strix/repo-connect-s3c-helper"
```

All four enterprise-wave branches **and** the handoff branch were cut from this exact tip (`999d6cc4`) and are **0 commits behind** it — no rebase is needed before merging.

### 1.2 Remote branches under `strix/`

`git ls-remote --heads origin` returns exactly **7** refs under the `strix/` prefix. The four `strix/enterprise-*` branches + `strix/handoff-20261029` are the live enterprise-waves work; the two `strix/s*` are legacy rails.

| Branch | SHA | Merged to main? | One-line content |
|---|---|---|---|
| `strix/enterprise-tenantfound` | `da42abde` | **No** (ahead 1 / behind 0; **PR #974 open**) | **FOUNDATION** — fail-closed `tenant_id` reconciliation in the job gate (`org == tenant_id`). Red-pen sound (2 LOW fixed), 44 tests green. **Merge first on green.** |
| `strix/enterprise-identity` | `751f53e8` | **No** (ahead 1 / behind 0; no PR) | Owner-signed Org/Workspace + membership + `org→tenant_id` mapping (`apps/sigil/sigil/governor/orgs.py`). 28 tests green, FATAL-2 clean. **Open HIGH (prune-replay resurrection) + reactivation MED; red-pen must be re-run before PR.** |
| `strix/enterprise-kb` | `e34f5979` | **No** (ahead 2 / behind 0; no PR) | Per-org knowledge-base corpus (`engine/crucible/framework/v2/knowledge_base/`). Red-pen HIGH (cross-tenant symlink leak) + LOW (schema-drift) **already fixed** (+3 regression tests, 16 green, ruff clean). Needs re-red-pen → PR. |
| `strix/enterprise-ticketing` | `8ee3386c` | **No** (ahead 2 / behind 0; no PR) | Ticketing-out GitHub-Issues push (`engine/crucible/framework/v2/mcp/ticketing_{config,push}.py`). Red-pen 2 MED (credential echo, egress disjointness) **already fixed** (+4 tests, 61 green). Touches shared seam `vigil_core/rbac.py`. Needs re-red-pen → PR. |
| `strix/handoff-20261029` | `287c1903` | **No** (ahead 3 / behind 0; no PR) | **Handoff branch** — carries `HANDOFF-enterprise-waves.md` (full state + fix plan) plus the applied KB/ticketing red-pen fixes. Checked out at `/home/kali/vigil-wt-repoconnect`. |
| `strix/s1-runtime-classes` | `ad5e0464` | **No** (ahead 1 / behind 455 — stale legacy) | Legacy Strix rail W4 (wire path_traversal/lfi, exposure, ssi to the Strix→FACT arms). Not part of the enterprise waves. |
| `strix/s2-transport-intake` | `abcc2b56` | **Yes** (ancestor of main; behind 357) | Legacy; already folded into main. Tip is a merge of `origin/main`. |

### 1.3 Open PRs

`gh pr list --state open` returns **7** PRs, all targeting `main`:

| PR | Title | Branch | Merge/CI state |
|---|---|---|---|
| **#974** | enterprise-foundation: fail-closed `tenant_id` reconciliation in the job gate (org==tenant_id) | `strix/enterprise-tenantfound` | **UNSTABLE** — mergeable=MERGEABLE, **1 required check failing** |
| #964 | build(deps-dev): setuptools `>=84.0.0`→`>=84.2.1` in `/engine/crucible` | `dependabot/pip/engine/crucible/setuptools-gte-84.2.1` | UNKNOWN (not recomputed) |
| #963 | build(deps-dev): setuptools `>=84.0.0`→`>=84.2.1` in `/apps/sigil` | `dependabot/pip/apps/sigil/setuptools-gte-84.2.1` | UNKNOWN |
| #962 | build(deps): huggingface-hub `1.27.0`→`2.2.0` in `/apps/sigil` | `dependabot/pip/apps/sigil/huggingface-hub-2.2.0` | UNKNOWN |
| #961 | build(deps): bump the python-minor-and-patch group (2 dirs, 14 updates) | `dependabot/pip/apps/sigil/python-minor-and-patch-2cff36a756` | UNKNOWN |
| #960 | build(deps): pypa/gh-action-pypi-publish `1.14.2`→`1.14.3` | `dependabot/github_actions/pypa/gh-action-pypi-publish-1.14.3` | CLEAN |
| #959 | build(deps): actions/setup-python `7.0.0`→`7.1.0` | `dependabot/github_actions/actions/setup-python-7.1.0` | CLEAN |

Only **#974** is enterprise work; #959–#964 are routine Dependabot bumps (not part of the waves). The `UNKNOWN` states are PRs GitHub has not re-evaluated against the current `main` tip.

**Why PR #974 (foundation) is blocked — the A14 / litellm gate.** The branch is conflict-free (`mergeable = MERGEABLE`); the merge is held purely by one failing **required** check. Of 29 reported checks on #974, exactly one is red:

- ❌ **`A14 supply-chain gate` = FAILURE** — Trivy flags **`litellm` 1.90.1** (`GHSA-g5ff-637f-6q2m`, HIGH, arbitrary local file read; fixed in **1.95.0**) inside **`vendor/strix/uv.lock`** (vendored Strix, a `uv` lock — not pip). It is Trivy-DB-time-dependent, so it reds `main` and every wave branch. A14 is a required gate, so **nothing merges until litellm is bumped**. Repo doctrine is **bump, not suppress**: `cd vendor/strix && uv lock --upgrade-package litellm` (target ≥1.95.0), land as its own small supply-chain PR **first**, then #974 goes green.
- ✅ All other blocking checks pass — CRUCIBLE core, two-env boundary (P5), gateway egress (P6), SIGIL governor (P7), strix Claude-runtime (P8), WARDEN Rust kernel (A10), TLA+ formal (F1), lint-config, VSCP, loopback engagement, vigil_core, python-compat 3.12/3.13, "branch protection matches the committed policy", etc.
- ⏭️ The four `livefire … (nightly)` checks show SKIPPED (expected on a per-PR run); advisory checks (CodeQL, SAST, gitleaks, perf, pre-commit, scheduled supply-chain) pass but are non-blocking.

### 1.4 Uncommitted work across worktrees

**The five enterprise-wave worktrees are all CLEAN and fully pushed** (local HEAD == `origin/<branch>` tip, verified):

| Worktree | Branch | HEAD | Working tree |
|---|---|---|---|
| `/home/kali/vigil-wt-tenantfound` | `strix/enterprise-tenantfound` | `da42abde` | clean, in sync with origin |
| `/home/kali/vigil-wt-identity` | `strix/enterprise-identity` | `751f53e8` | clean, in sync with origin |
| `/home/kali/vigil-wt-kb` | `strix/enterprise-kb` | `e34f5979` | clean, in sync with origin |
| `/home/kali/vigil-wt-ticketing` | `strix/enterprise-ticketing` | `8ee3386c` | clean, in sync with origin |
| `/home/kali/vigil-wt-repoconnect` | `strix/handoff-20261029` | `287c1903` | clean, in sync with origin |

**However, a sweep of all 28 worktrees + the primary checkout found uncommitted work elsewhere** (unrelated to the enterprise waves, but flagged so nothing is lost in handoff):

- **Real uncommitted tracked-code edits (load-bearing):**
  - `/home/kali/vigil` (primary checkout, on branch `meridian-s5-expansion`) — modified `engine/crucible/framework/v2/console/actions.py`, `console/api.py`, and `packages/core/vigil_core/vigil_core/rbac.py` (+ untracked `docs/VPS-DEPLOYMENT-GUIDE.md`, a VULNLAB runbook, and engagement `targets/` dirs). Note the primary clone sits on `meridian-s5-expansion`, **not `main`**, with local edits to the shared `rbac.py` seam.
  - `/home/kali/vigil-wt-ev-moduleA` (`ev-build-moduleA`) — modified `intel/models.py`, `sensors/base.py`, and a staged new test `sensors/tests/test_evidence_observations.py`.
- **Untracked work-in-progress (not yet committed):**
  - `/home/kali/vigil-wt-release` (`iss-release-tooling-v`) — release tooling: `CHANGELOG.md`, `tools/gen_changelog.py`, `vigil_core/buildinfo.py`, and 4 per-component version tests.
  - `/home/kali/vigil-wt-home-paths` (`fix-crucible-root-escapes-to-home`) — 2 new path-containment test files.
- **Transient / disposable (safe to ignore):** `.scratch-*/` dirs (`-m21`, `-m3fix`, `-nuclei`), engagement artifact dirs `engine/crucible/targets/{meridian,thuramnana,127-0-0-1}/` and `.target-live/` (`-aegis`, `-waveA1-seal`, primary), and 4 `ci-nightly-*.txt` measurement outputs (`-ci-nightly`).

### 1.5 Branch protection / required checks

The GitHub REST protection API is **not readable** on this repo: `gh api repos/thuram-nana/vigil-sovereign/branches/main/protection` → **HTTP 403** ("Upgrade to GitHub Pro or make this repository public to enable this feature"). The authoritative required-check set therefore can't be pulled from the API here. Two things stand in for it:

1. CI carries a self-check — **`branch protection matches the committed policy`** (passing on #974) — i.e. the policy is committed in-repo and verified by CI rather than read from the API.
2. From the #974 check rollup, the **blocking** gates are the checks **not** suffixed `(advisory)` or `(nightly)` — including **`A14 supply-chain gate`** (the current blocker), the P5/P6/P7/P8 boundary gates, A10 WARDEN, F1 formal, CRUCIBLE core/eval, lint-config, VSCP, loopback engagement, vigil_core, and python-compat 3.12/3.13.

## 2. Environment, CI legs, and merge-seam guards

> Repo: `thuram-nana/vigil-sovereign`. Everything below is read verbatim from the working tree at
> `/home/kali/vigil-wt-repoconnect` (branch `strix/handoff-20261029`). All paths are repo-relative unless
> absolute. Python everywhere is **3.13** (the interpreter the committed hash-locks pin).

### 2.1 The CI workflow — `.github/workflows/ci.yml` (`vigil-ci`)

Triggers: `push` to `main` and `pull_request` to `main`. `permissions: contents: read`. PR runs are
cancel-in-progress. It contains **15 jobs**. The load-bearing distinction the whole two-env design turns on:

- **`engine/crucible/framework/v2/requirements.lock.txt` installs only THIRD-PARTY packages — it never
  installs the `framework` package itself.** So installing it does *not* make `framework` importable.
- **`framework` (the offense engine) is importable only when `engine/crucible` is on `PYTHONPATH`** (or the
  job runs with `working-directory: engine/crucible` + `PYTHONPATH=.`). That is the only thing that separates
  a **framework-PRESENT (offense) leg** from a **framework-ABSENT (sovereign) leg** — the same lock is
  installed in both. The sovereign process actively refuses to co-load `framework` (FATAL-2 / `assert_no_offense`).

The three-line install incantation used by almost every Python job (call it **the canonical install**):

```bash
pip install --require-hashes -r engine/crucible/framework/v2/requirements.lock.txt
pip install -e packages/core/vigil_core --no-deps
pip install --require-hashes -r infra/supply-chain/ci-tooling.lock.txt
```

| # | Job (`name:`) | Installs | Runs | Leg |
|---|---|---|---|---|
| 1 | **vigil-core** — `vigil_core — shared integrity substrate` | canonical install | `pytest packages/core/vigil_core/tests -q --cov=vigil_core --cov-branch …` then coverage ratchet `python tools/coverage/coverage_ratchet.py check --thresholds tools/coverage/coverage-thresholds.json --package vigil_core --report coverage-vigil_core.json` | sovereign (vigil_core only) |
| 2 | **briefing-completeness** — `the briefing explains every agent and capability` | `pip install --require-hashes -r infra/supply-chain/ci-tooling.lock.txt` (pytest only) | `pytest docs/tests -q` | neither domain (reads files) |
| 3 | **crucible-core** — `CRUCIBLE core on vigil_core` | canonical install | `cd engine/crucible` (`working-directory`), `PYTHONPATH=.`, `pytest framework/v2 --ignore=framework/v2/eval --ignore=framework/v2/console/tests/test_chat_inject.py -q` | **OFFENSE** (framework present) |
| 4 | **crucible-eval** — `CRUCIBLE eval + benchmark corpus` | canonical install | collect-guard, then `cd engine/crucible`, `PYTHONPATH=.`, `pytest framework/v2/eval -q` (env `CRUCIBLE_EVAL_SUITES=framework/v2/eval`) | **OFFENSE** |
| 5 | **loopback-engagement** — `loopback engagement (end-to-end + offline re-verify)` | canonical install (+ a 2nd CLEAN checkout at `_clean-reverify`) | `pytest tools/loopback-engagement/tests -q`, then `bash tools/loopback-engagement/run_loopback_engagement.sh` (scan loopback range → re-verify OFFLINE on the clean checkout → tamper → negative) | **OFFENSE** |
| 6 | **gateway** — `gateway egress gate (P6)` | `apt-retry.sh nftables` + canonical install | `PYTHONPATH=gateway python -m pytest gateway/tests -q`, then `VIGIL_GATEWAY_DOCKER_IT=1 PYTHONPATH=gateway python -m pytest -rA -v gateway/tests/test_docker_bringup.py::test_real_docker_build_and_fail_closed` | gateway (stdlib; framework deps installed but not on path) |
| 7 | **integration** — `integration two-env boundary (P5)` | canonical install (deliberately **NO** `pip install -e apps/sigil`) + `apt-retry.sh bubblewrap` + `sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` + `make -C tools/egress-guard` | **the two-env split — see 2.1.1** | **BOTH legs, in separate processes** |
| 8 | **strix-vigil** — `strix Claude-runtime (P8)` | `pip install --require-hashes -r infra/supply-chain/ci-tooling.lock.txt` + best-effort **unpinned** `pip install "openai-agents[litellm]" openai` | `PYTHONPATH=vendor/strix python -m pytest vendor/strix/tests_vigil -q` | vendored strix |
| 9 | **sigil-governor** — `SIGIL governor gates (P7 — offense gate + authn)` | canonical install (uses the *offense* lock deliberately as the light third-party closure — no framework pkg, FATAL-2 untouched) | `SIGIL_HOME=/tmp/sigil-ci`, `PYTHONPATH=apps/sigil:integration python -m pytest apps/sigil/tests/ -q`, then flake repeat-stress `tools/flake/run_and_record.py` | **sovereign** |
| 10 | **sigil-lint** — `SIGIL lint (ruff blocking + mypy can-complete)` | canonical install (ruff+mypy from ci-tooling lock) | `cd apps/sigil && ruff check sigil` (BLOCKING), then `bash tools/governance/mypy_ratchet.sh` (per-module ratchet, BLOCKING) | sovereign / lint |
| 11 | **formal-verification** — `formal (TLA+ core-invariant model check, F1)` | Java 21 (temurin) + cached pinned `tla2tools.jar` | `bash formal/check.sh` (TLC model-checks 4 core invariants + mutants) | formal |
| 12 | **warden-kernel** — `WARDEN Rust kernel (A10 durability)` | runner's stable Rust toolchain | `cd apps/sigil/kernel && cargo test && cargo build --release` | Rust kernel |
| 13 | **python-compat** — `python-compat` (matrix **3.12 + 3.13**) | `pip install --require-hashes -r infra/supply-chain/matrix-tooling.lock.txt` (universal-wheel pytest subset) | `PYTHONPATH=gateway python -m pytest -rA -v integration/tests/test_aegis_dockerfile_wired.py gateway/tests/test_env_gated_tests_run_in_ci.py` | cross-version stdlib guards — **ADVISORY, not a required check** |

Doctrine across jobs: **a skipped proof and a passing proof are the same colour on a dashboard** — committed
monorepo paths that go missing `exit 1` (RED) instead of skipping GREEN; `-rs` / `-rA` name every skip; env-gated
proofs (docker bring-up, bwrap isolation, egress guard) are forced to actually execute.

#### 2.1.1 The two-env boundary split inside the `integration` job (the headline framework-present/absent split)

The P5 job runs the integration suite **twice, in two separate processes**, because `framework` (offense) and
`sigil.governor` (sovereign) cannot co-load:

- **SOVEREIGN leg — framework ABSENT:**
  ```bash
  PYTHONPATH=integration:gateway python -m pytest -rs integration/tests \
    --ignore=integration/tests/test_oracle_adapter.py … (~90 framework-dependent files --ignore'd) \
    --junit-xml="${RUNNER_TEMP:-/tmp}/sovereign-junit.xml" -q -m "not volume"
  ```
  Files that hard-import `framework` are `--ignore`d here; files guarded by `importorskip("framework…")` would
  skip here. `gateway` is on the path so the SSRF pre-filter reuses `vigil_gateway.denylist`.

- **OFFENSE leg — framework PRESENT** (`engine/crucible` on `PYTHONPATH`):
  ```bash
  VIGIL_REQUIRE_FRONTIER_CHECK=1 \
  PYTHONPATH=integration:engine/crucible:gateway python -m pytest \
    docs/tests/test_out_of_scope_is_honest.py \
    integration/tests/test_oracle_adapter.py … (explicit ~150-file list) \
    engine/crucible/framework/v2/verify/tests/test_egress_pin.py … \
    engine/crucible/framework/v2/scanner/tests/test_websocket.py … -q -m "not volume"
  ```
  This is the only leg where framework-dependent tests execute.

- Then three assertions: `python .github/scripts/assert_boundary_proof_ran.py <junit>` (the boundary proof must
  have actually run, not skipped); the WS4 handover wrapper must fail closed on an unreachable target
  (`python -m vigil_integration.sovereign_deploy.acceptance --target-port 65000` → non-zero + `HANDOVER BLOCKED`);
  and a keyed-reachability collect-only guard.
- `-m "not volume"` on both legs: volume (statistical) tests run nightly in `soak.yml`, not on the PR path.

### 2.2 The A14 supply-chain gate (separate workflow — `.github/workflows/supply-chain.yml`)

**A14 is NOT in `ci.yml`.** It is its own workflow whose single job is named **`A14 supply-chain gate`**, and it
is a **required status check** on `main` — so it blocks every merge independently of the wave code. Pinned build
tooling (env block, exact-pinned): `PIP_TOOLS_VERSION="7.6.1"`, `CYCLONEDX_VERSION="7.3.1"`,
`TRIVY_VERSION="0.73.0"` with `TRIVY_SHA256="2edd39da482bb4e9831962487b68f68e3928ec3137794757f54d00383d79547b"`.
Install: `pip install "pip-tools==7.6.1" "cyclonedx-bom==7.3.1"` + the ci-tooling hash-lock (pytest). Three sub-gates:

1. **Trivy vulnerability GATE — HIGH + CRITICAL block.** Install trivy (version- *and* sha256-pinned), cache its
   DB, then `trivy fs --scanners vuln --severity HIGH,CRITICAL --ignorefile .trivyignore` — any HIGH or CRITICAL
   exits non-zero and **blocks the PR**. The BUILT gateway/Strix-sandbox image is also `trivy image`-scanned at
   the same threshold. Two **negative controls** prove the gate is not a no-op: a known-CRITICAL fixture must fail
   at `HIGH,CRITICAL`; a HIGH-only fixture (`pyasn1==0.6.3`) must fail at `HIGH,CRITICAL` **and** pass at
   `CRITICAL`-only (proving the raise to HIGH is enforced). Policy is **bump, not suppress** — `.trivyignore`
   exists but every entry must carry a written justification; the repo doctrine is no-suppression.
2. **Lock-staleness GATE.** Regenerate both Python locks with
   `pip-compile --quiet --generate-hashes --no-header --strip-extras` from each lock's **canonical CWD** (offense:
   `cd engine/crucible` from `framework/v2/requirements.in`; sovereign: repo root from
   `infra/supply-chain/sovereign.in`), seeded from the committed lock; then `bash bin/verify-supply-chain.sh`
   asserts **the lock is current w.r.t. the `.in`** (any diff ⇒ stale lock ⇒ RED). `pip install --require-hashes`
   must succeed for the offense, sovereign, ci-tooling and build-backends locks (`compare_resolved_to_lock.py`).
   Non-Python locks: `uv lock --check` on **`vendor/strix/uv.lock`** + a `Cargo.lock` regenerate-and-diff (W3-10).
3. **SBOM sub-gates.** `bin/verify-supply-chain.sh --sbom-out=…` cross-checks a per-run CycloneDX SBOM against each
   lock component-for-component; the committed offense SBOM is regenerated-and-checked via
   `python3 -m framework.v2.tools.gen_sbom --check`; the committed Strix sandbox **image** SBOM
   (`infra/supply-chain/sbom-strix-sandbox.cdx.json`) via `python3 infra/supply-chain/gen_image_sbom.py --check`
   (offline drift guard tying the SBOM to the Dockerfile hash + base-image digest); base images are digest-pinned
   with a drift negative control.

> **CURRENT A14 BLOCKER (as of handoff):** Trivy flags **`litellm` 1.90.1 → fixed 1.95.0** (GHSA-g5ff-637f-6q2m,
> HIGH, arbitrary local file read) inside **`vendor/strix/uv.lock`** (a `uv` lock, not pip). It is Trivy-DB
> time-dependent, so it reds `main` and every branch. A14 being required means **nothing merges until it is green.**
> Fix (its own small supply-chain PR, merged FIRST): `cd vendor/strix && uv lock --upgrade-package litellm`
> (target ≥1.95.0; confirm `openai-agents==0.14.6`'s litellm extra permits it), review the diff (a vendored
> `uv.lock` regen can move many transitive pins), re-run Trivy locally, land it, then rebase the waves.

### 2.3 Reproducible env for a FRESH cloud box (copy-paste)

A cloud session clones the repo into an empty box. Run exactly the CI install, then set `PYTHONPATH` per leg.
This is the portable recipe — **no local venv, no sovereign keys** (the TPM/vault keys are local by design and
are not in the cloud; anything needing a real signing key cannot run there).

```bash
# 1. Python 3.13. Then the canonical install (same three lines every CI job uses):
python -m pip install --upgrade pip
pip install --require-hashes -r engine/crucible/framework/v2/requirements.lock.txt
pip install -e packages/core/vigil_core --no-deps
pip install --require-hashes -r infra/supply-chain/ci-tooling.lock.txt

# 2. Optional, only for specific legs:
#    - gateway/integration legs: sudo apt-get install -y nftables bubblewrap ; make -C tools/egress-guard
#    - strix leg:               pip install "openai-agents[litellm]" openai   # best-effort, unpinned
#    - A14 gate:                pip install "pip-tools==7.6.1" "cyclonedx-bom==7.3.1"
```

`PYTHONPATH` is set **per leg** (there is no single global value in CI):

| Leg | PYTHONPATH (+ cwd) |
|---|---|
| crucible-core / crucible-eval | `PYTHONPATH=.` **with** `cd engine/crucible` |
| integration — sovereign (framework ABSENT) | `PYTHONPATH=integration:gateway` |
| integration — offense (framework PRESENT) | `PYTHONPATH=integration:engine/crucible:gateway` (+ `VIGIL_REQUIRE_FRONTIER_CHECK=1`) |
| gateway / python-compat | `PYTHONPATH=gateway` |
| sigil-governor | `PYTHONPATH=apps/sigil:integration` (+ `SIGIL_HOME=/tmp/sigil-ci`) |
| strix-vigil | `PYTHONPATH=vendor/strix` |

### 2.4 LOCAL-dev recipe actually used this session — **LOCAL-ONLY, will NOT work in the cloud**

For the record, the convenience recipe used on the Kali box this session:

```bash
# LOCAL-ONLY — this venv does not exist in the cloud:
PYTHONPATH=packages/core/vigil_core:gateway:engine/crucible:integration:. \
  /home/kali/graphify/venv/bin/python -m pytest <target>
# apps/sigil tests, locally:
PYTHONPATH=packages/core/vigil_core:apps/sigil:. \
  /home/kali/graphify/venv/bin/python -m pytest apps/sigil/tests/ -q
```

Caveats (all three matter):
- **The venv is local-only.** `/home/kali/graphify/venv/bin/python` exists only on this machine. A cloud box must
  use the fresh recipe in 2.3 instead.
- **A stale editable `vigil_core` finder points at ANOTHER checkout.** That venv carries
  `…/site-packages/_editable_impl_vigil_core.pth` whose single line is
  `/home/kali/vg36/484/packages/core/vigil_core` — a *different* repo checkout. So
  **`packages/core/vigil_core` must be FIRST on `PYTHONPATH`** or you silently test the wrong `vigil_core` tree.
  (The cloud `pip install -e packages/core/vigil_core --no-deps` installs the correct one and sidesteps this.)
- **apps/sigil tests** use `PYTHONPATH=packages/core/vigil_core:apps/sigil:.` locally (vigil_core first, for the
  same reason) — vs CI's `PYTHONPATH=apps/sigil:integration`.

### 2.5 Running each test leg locally (exact invocations)

CI form shown; locally prepend `packages/core/vigil_core:` to the `PYTHONPATH` (per 2.4) and use the graphify
python, or just use a clean 2.3 env.

```bash
# crucible-core suite (framework/v2 whole tree, framework PRESENT):
cd engine/crucible && PYTHONPATH=. python -m pytest framework/v2 \
  --ignore=framework/v2/eval \
  --ignore=framework/v2/console/tests/test_chat_inject.py -q

# crucible-eval (expensive corpus/baselines/soak):
cd engine/crucible && PYTHONPATH=. python -m pytest framework/v2/eval -q

# integration/tests — SOVEREIGN leg (framework ABSENT):
PYTHONPATH=integration:gateway python -m pytest -rs integration/tests \
  --ignore=integration/tests/test_oracle_adapter.py  # …(full ~90-file --ignore list, see ci.yml) \
  -q -m "not volume"

# integration/tests — OFFENSE leg (framework PRESENT; explicit file list in ci.yml):
VIGIL_REQUIRE_FRONTIER_CHECK=1 \
PYTHONPATH=integration:engine/crucible:gateway python -m pytest \
  docs/tests/test_out_of_scope_is_honest.py integration/tests/test_oracle_adapter.py  # …(full list) \
  -q -m "not volume"

# apps/sigil (SIGIL governor) suite:
SIGIL_HOME=/tmp/sigil-ci PYTHONPATH=apps/sigil:integration python -m pytest apps/sigil/tests/ -q

# the docs/feature-wiring + screen-count guards (stdlib, pytest only):
python -m pytest docs/tests -q
```

The two integration legs use file lists far too long to retype — **copy them verbatim from `ci.yml`** (sovereign
`--ignore` block starts at the `PYTHONPATH=integration:gateway … -rs integration/tests` step; offense explicit
list starts at the `VIGIL_REQUIRE_FRONTIER_CHECK=1 PYTHONPATH=integration:engine/crucible:gateway` step). The
`test_ci_framework_tests_run_in_offense_leg` guard (2.6) keeps those two lists honest.

### 2.6 Merge-seam guards — what any change must satisfy

Five registries behave as **set-equality seams**: a change on one side without the matching entry on the other
turns a required CI check RED. For each: the seam file, the rule, the enforcing test, and the CI job it runs in.

1. **`docs/features/wiring-status.json`** — every feature carries a status
   (`LIVE` / `OPT-IN` / `GATED` / `BUILT-NOT-WIRED` / `ORPHANED`) and a check kind. A `cli-native-verb`'s set must
   **equal** the real `sub.add_parser(...)` verbs in `integration/vigil_integration/cli.py`; a
   `cli-passthrough-verb`'s set must equal the `_ENV` table in `integration/vigil_integration/dispatch.py`; a
   `ui-screen`'s set must equal the NAV==route() set in `packages/vigil-ui/app.js`;
   `symbol-exists`/`stub-raises`/`scaffold-abc` anchors must resolve by AST. Add a verb/screen/subsystem (or a
   registry entry) without its counterpart ⇒ RED.
   **Enforced by:** `docs/tests/test_feature_wiring_status.py` — runs in job **briefing-completeness** (`pytest docs/tests -q`).

2. **`packages/vigil-ui/app.js`** — a UI screen must be **both** a `const NAV` id **and** a `route()` id, and the
   `ui-screen` set in `wiring-status.json` must equal that NAV==route() set. Add a screen to NAV without a route()
   case (or without the registry entry) ⇒ RED.
   **Enforced by:** `docs/tests/test_feature_wiring_status.py` (ui-screen set-equality) **and**
   `docs/tests/test_documented_commands_and_screen_count.py` (count) — both in **briefing-completeness**; also the
   S1 system-map drift gate `tools/system-map/generate.py`.

3. **README screen-count + `knowledge/system-map/system-map.json`** — the `"<N> screens"` claim in `README.md`
   (and `packages/vigil-ui/README.md`, `docs/FEATURES.md`) must EQUAL the NAV id count **derived** from
   `app.js` (**currently 35**), which must equal `system-map.json`'s `screens` (currently 35). The count is derived
   from NAV, never hard-coded — change NAV and the doc must move with it. The same test also asserts documented
   `vigil` commands actually exist (native verb vs a `crucible`-passthrough subcommand).
   **Enforced by:** `docs/tests/test_documented_commands_and_screen_count.py` — runs in **briefing-completeness**.

4. **`packages/core/vigil_core/vigil_core/rbac.py` → `OFFENSE_ACTION_PERM`** — every state-changing offense POST
   route (the console `framework.v2.console.server.do_POST` and the gated API `framework.v2.api.server.do_POST`)
   must be mapped to a permission here (exact key or wildcard pattern). An unmapped route resolves via
   `offense_perm_for(path)` → `None` → **default-deny ⇒ 403 for every role**. So a new offense POST route must
   register in this map or it is dead (403). (The `enterprise-ticketing` wave adds one such route — the only wave
   that edits this shared seam.)
   **Enforced by:** `engine/crucible/framework/v2/console/tests/test_offense_rbac.py` (incl.
   `test …unmapped route → default-deny 403`) and `engine/crucible/framework/v2/api/tests/test_api_rbac.py` — both
   run in job **crucible-core** (the whole `framework/v2` tree, framework present).

5. **`integration/tests/test_ci_framework_tests_run_in_offense_leg.py`** — the framework-leg honesty guard. Every
   integration test file that either (a) `pytest.importorskip("framework…")`s or (b) is `--ignore`d in the
   sovereign leg of `ci.yml` **must** appear in the offense-leg explicit file list in `ci.yml` — otherwise it
   *never runs in CI* (it skips in the sovereign leg and is absent from the offense leg). Add a framework-dependent
   integration test ⇒ you must add it to the offense list in `ci.yml`, or this goes RED.
   **Enforced by:** itself — it is framework-free and is collected in the **sovereign** leg of the **integration**
   job (`PYTHONPATH=integration:gateway python -m pytest integration/tests`); keep it OUT of the sovereign
   `--ignore` list.

## 3. Orientation, binding invariants, and the full remaining roadmap

> **Read this first — the memory does not travel.** A cloud or fresh session clones `thuram-nana/vigil-sovereign` and inherits the in-repo constitution **OBSIDIAN** (`engine/crucible/CLAUDE.md` — there is *no* root `CLAUDE.md` on the handoff branch) plus the repo README/docs. It does **not** inherit the operator's program memory (the SIGIL / CRUCIBLE / AEGIS / VIGIL topic files). Everything a continuing session needs to orient, stay sound, and know what is left is therefore carried *in this section*. When this section and the live code disagree, the code is the claim — verify, then fix the code or the claim, never the prose alone.

### 3.1 Orientation — what VIGIL is, and the two products

**VIGIL** is a fusion monorepo at `/home/kali/vigil` (GitHub `thuram-nana/vigil-sovereign`) that unifies four lineages — SIGIL (local-first orchestrator), CRUCIBLE (the offensive proving engine), AEGIS (CRUCIBLE's embeddable defensive dual), and a Strix-derived agentic shell — into **one control plane over two strongly-isolated process planes**. Its differentiator is **soundness**: a finding becomes a signed **FACT** only when a deterministic **oracle** re-fires over a VIGIL-owned out-of-band capture. An LLM (Claude/CVP) never promotes anything — it advises, hypothesizes, and plans; the **oracle plus the governance/authority layer are the sole security authority.** Near-zero false FACTs is the one property this product cannot lose.

**There are TWO products built from this one codebase. Do not conflate them — the key-custody and egress story is opposite in each:**

| | **Customer-SOVEREIGN** (the already-existing product) | **Strix-style WE-HOST** (the product THIS work builds — positioning per `sigilsovereign.com`) |
|---|---|---|
| Who runs it | The customer self-hosts, into their own cloud / on-prem | **We** host and operate it |
| Who holds keys | **The customer** holds their own keys (TPM-sealed vault, sovereign by design) | **We** hold the keys — per-tenant DEKs in cloud KMS/HSM behind confidential compute; "we hold the keys" is *our* assurance story |
| Ships as | A Terraform/Helm deployment into the customer's environment | A managed multi-tenant SaaS (k8s control plane + ephemeral per-engagement sandboxes) |
| Egress / offensive conduct | The customer's responsibility | **Our** responsibility (dedicated pinned/attributable egress, provider security-testing AUP settled early) |

The sovereignty / customer-key-custody concern belongs to the *first* product. In the *we-host* product the offensive egress and key custody are ours. The local single-tenant **Contabo VPS `13.140.225.65`** was adequate only for the earlier single-tenant stage; it is **not** the we-host topology.

**North star — the Sovereign National Cyber-Defense Fabric.** A program-of-programs, not one build. Its load-bearing invariant is the one already in VIGIL's spine: *capability ≠ authorization* — an operation does not exist until a signed **authority object** permits it, a deterministic safety kernel with no generative AI sits between reasoning and any actuator, and autonomy never reaches an unrestricted level. Every extension must stay inside "Claude advises; the oracle + governance decide." Sequence toward it; never claim the fabric before the deterministic layer enforces it.

### 3.2 Binding invariants and cadence — the rules a continuing session MUST follow

These are non-negotiable. Violating any of them ships the one defect the product cannot have, or breaks the operator's trust/authorship/safety guarantees.

1. **FATAL-2 — the two-environment boundary.** The repo runs as two planes that must never cross-contaminate:
   - **Offense/engine plane** may import `framework` (the CRUCIBLE engine under `engine/crucible/framework/v2/…`) and must be **keyless** — it holds no sovereign keys.
   - **Sovereign plane** must be **framework-free**: no `framework` import at module scope.
   - **`vigil_core`** (`packages/core/vigil_core/vigil_core`) is the shared library safe on both planes.
   - Any `framework` use in shared / sovereign-reachable code must be **lazy (function-local)** so the module stays importable with `framework` absent.
   - CI enforces this as the **P5 `test_two_env_boundary`** probe: the **sovereign leg** runs with `framework` ABSENT (`pytest integration/tests`, `PYTHONPATH=.`); the **offense leg** runs with it present. A test that imports `framework` must `importorskip` it (and be listed in the offense leg of `.github/workflows/ci.yml`), or it reds the sovereign leg.
   - **Faithfulness trap:** `framework` is often pip-importable in a local dev env, which *defeats* a local two-env/P5 repro and makes it falsely pass. Reproduce either by trusting **CI's sovereign leg**, or by blocking `framework*` with a `sys.meta_path` `ImportError` shim. Do not trust a bare local `PYTHONPATH` run for a FATAL-2 claim.

2. **Red-pen before every merge — NON-NEGOTIABLE.** The adversarial red-pen *is* the product's value. Each slice is: build in an **isolated worktree** → **adversarial red-pen** (run via the **Workflow tool**, multiple **disjoint lenses**, each objection either **refuted with a concrete repro** or fixed) → report only what survives. Never trade the red-pen for speed; never merge a wave whose red-pen was not (re-)run against the final tree. The heaviest, crypto-soundness waves get the heaviest red-pen.

3. **Cadence.** One wave at a time; slices within a wave built in parallel only when they touch **disjoint** code. Merge **sequentially and additively**: rebase each onto current `main`, resolve shared-registry conflicts by **union**, then re-verify the byte-identical gate and OracleKind counts on the merged tree. Bake each wave's lessons into the next wave's prompts. Default to continuing autonomously to completion, surfacing only genuine hard-stops and a summary at each **wave boundary**. ("Continue as before, it is more professional." — operator.)

4. **Authorship in this repo (operator override — it beats the harness default).** On `vigil-sovereign` the operator (@thuram-nana, *Junior Thuram Nana*) is the **sole contributor**. **Do NOT add a `Co-Authored-By: Claude` trailer** to commits, and **do NOT add a robot-generated PR footer** (no "🤖 Generated with Claude Code"). Keep authorship as the canonical `Junior Thuram Nana` identity. (A full history rewrite to strip the ~762 legacy trailers is **pending** and needs explicit go-ahead; it must **preserve** the Apache/NOTICE third-party Strix authors — do not collapse them.)

5. **Commits are signed; merge on green only.** All commits must be cryptographically **signed** (`main` branch protection requires **14 checks + strict + signed + `required_signatures`**). **Never merge on red, and never on a misleadingly "clean" state with no checks** (the 2026-10-27 GitHub Actions outage produced exactly that false-clean — the fix was to wait, re-trigger via close/reopen, and merge only when *genuinely* green). GitHub imposes a ~45-min job cap. A non-strict `main` lets two independently-green PRs land a red `main`, so keep merges strict/up-to-date.

6. **The SAFETY LINE (firm, repeatedly reaffirmed — the ANTIC decline).** Build the **vetted-enterprise shell over owner-authorized connected assets**, never the **open self-serve offensive portal**. **REFUSED:** public anonymous signup that hands anyone the autonomous offensive engine, and self-serve commercialization ($/seat + credits) of that access — a mass-targeting enabler regardless of framing. **BUILD INSTEAD:** SSO/SCIM + **admin-invited** accounts + email-verify + full tenant isolation, with VIGIL's per-target authorization **kept** (domain-ownership verification, connected-repo white-box authorization, never-liftable egress floor, categorical `.gov`/`.mil` block, no destruction) — never reduced to a one-click "I'm authorized."

7. **Oracle-authority / prove-don't-guess.** A FACT requires an oracle re-firing over a VIGIL-owned OOB capture — never a model's payload, never a third-party/MCP/ticket payload, never a substring match. `intel:` / MCP-evidence inputs are **LEADs** that the veracity firewall structurally blocks from FACT strength. A finding pushed **out** (ticketing) does not round-trip back as a FACT. "I confirmed it" requires a working repro; otherwise hedge honestly.

8. **Claim-discipline — raise the system, never lower the claim** (`docs/CLAIM-DISCIPLINE.md`, enforced by `engine/crucible/framework/v2/scanner/tests/test_claim_discipline.py`). When a red-pen finds an overclaim, do **not** soften the claim to match the code (a silent downgrade destroys the product). Either **build the capability up** so the claim becomes a verified FACT, or register the gap as named `blocking_work` in `docs/capability-matrix/evidence-branches.json`, enforced by a test — the target stands and the engineering comes up to meet it. Equally: never assert what is not established today.

**Soundness lessons the red-pen must apply (these won't travel in memory — apply them):**
- **Fake-fixture pattern:** check a fixture *has* the property, not that it *matches the detector* (a planted SQLi must run a real engine; a planted file-read must read a real file). When a *sound* detector refuses a long-green fixture, suspect the **fixture**, not the detector. A corpus that doesn't discriminate sound from unsound is only half a gate.
- **Measured-claim discipline:** every number beside code is a claim — commit a re-derivable harness or withdraw the number. Measure a *difference as a difference* (extract the pre-change tree and run both). Measure in **subprocesses** when anything could be process-local. Measure end-to-end through the real caller, not a standalone component.
- **Same-shape negative controls:** a control must exercise the *adversarial* same-shape as the payload (runtime-redrive minted false FACTs because its control wasn't same-shape); offline verify re-evaluates the predicate over the **frozen signed reduction**, not a re-reduction.
- **CLEAN-verdict soundness:** a CLEAN needs ≥1 observation of ≥1 *identified* peer — never silence-as-negative; it carries no signature.
- **Allowlist self-reference trap:** never re-derive an allowlist from the same untrusted lookup the target self-authorizes; use a Tier-1 *structural* predicate.
- **Demotion merge hazards:** a demotion must reach *every* render path; prefer two independent refusals, and when demoting a class name the sound producer that replaces it on every path.
- **Containment/symlink:** any disk reader under `targets/<slug>/` must gate on `_safe_target_dir`/`paths.is_within` (resolve + containment), and must not `iterdir()`-follow symlinks — this is exactly the KB wave's HIGH.

### 3.3 The shared contract for the enterprise waves

All enterprise waves obey one contract:

- **`org == tenant_id`.** The tenant id is the `CRUCIBLE_TENANT` env value, read fresh each call via `from framework.v2.common.paths import active_tenant` (`engine/crucible/framework/v2/common/paths.py:149`), validated fail-closed against `_TENANT_RE = [A-Za-z0-9][A-Za-z0-9._-]{0,63}` (`paths.py:146`); **`None` = the historical global/shared store**. Never accept a caller-supplied tenant that disagrees with the process env.
- **Key everything `(tenant_id, slug)`.** The tenant shard isolates only `.blackboard` (spine) + `.memory`; per-engagement artifacts (findings/reports/evidence/authority) live under `targets/<slug>/` where the slug is `repo-{stem}-{sha256(canonical_repo)[:12]}` — **repo-derived and tenant-blind**, so two orgs on the same repo URL collide unless they sit under different per-tenant `CRUCIBLE_ROOT`s.
- **Do NOT re-wrap `targets_root()` / `target_dir()`.** Per-engagement artifacts already sit under the per-tenant `CRUCIBLE_ROOT`; wrapping the root again double-prefixes. Key the KB/ticketing corpus on `(tenant_id, slug)` within that existing root instead.
- Isolation model is **process/root-per-tenant** (ephemeral isolated workers, one dedicated `CRUCIBLE_ROOT` per tenant) — forced both by the existing fail-closed `assert_tenant_fleet_isolated` guard and by the approved Firecracker hosting — **not** in-process many-orgs routing (which contradicts doctrine). The **foundation wave** closes the gap that no job-level `job.tenant_id == active_tenant()` reconciliation existed (the gate checked only the process env), and stops relying on the tenant-blind slug for separation.

### 3.4 The full remaining roadmap, in order

**Context — the repo-connect write path is COMPLETE and turnkey on `main`** (base `999d6cc4`): `vigil pr-bot --comment` (3b, **PR #966**) and `--fix-pr` (3c fix-PR worker **PR #971** → CLI arg **PR #972** → read-only provisioning helper `--print-fix-authorization` **PR #973**), both OFF by default, each write gated by the owner-signed repo-exact `GitWriteGrant` + WARDEN + m-of-n destruction quorum + signed audit. Everything below builds on that.

**Step 1 — Finish the enterprise parallel-3 waves.** Four branches pushed, all off `main 999d6cc4`. Execute strictly in this order (per-wave fix detail lives in the "RED-PEN FINDINGS + FIX PLAN" section of `HANDOFF-enterprise-waves.md` on branch `strix/handoff-20261029` — do not re-derive it):
  1. **Unblock the A14 supply-chain gate first (its own small PR).** Trivy flags **`litellm` 1.90.1 → fixed ≥1.95.0**, GHSA-g5ff-637f-6q2m (HIGH), in **`vendor/strix/uv.lock`** (a `uv` lock, not pip). It reds `main` and all branches, and A14 is required, so **nothing merges until it is fixed**. Doctrine is **bump, not suppress**: `cd vendor/strix && uv lock --upgrade-package litellm` (≥1.95.0; `uv` 0.11.29), confirm `openai-agents==0.14.6`'s litellm extra permits it, review the (possibly wide) transitive diff, re-run Trivy, land it, then rebase the waves.
  2. **Foundation** (`strix/enterprise-tenantfound` @ `da42abde`, **PR #974 OPEN**): fail-closed `job.tenant_id == active_tenant()` reconciliation in the job gate (org==tenant_id). **Code is clean** (red-penned sound, 2 LOW fixed, 44 tests green); its only red was the A14 gate. **Merge FIRST** once A14 is green.
  3. **KB** (`strix/enterprise-kb` @ `e34f5979`, `knowledge_base/aggregate.py`): HIGH cross-tenant symlink leak + LOW schema-drift already **FIXED and pushed** (+3 tests, 16 green). **Re-run the KB red-pen** (recover the 4th, lower-sev provenance finding), open PR, merge.
  4. **Ticketing-out** (`strix/enterprise-ticketing` @ `8ee3386c`, `mcp/ticketing_{config,push}.py`, GitHub Issues push): both MEDs (credential echo in `_parse_host`; unconditional `collector_scope_conflicts` disjointness) already **FIXED and pushed** (+4 tests, 61 green). Mirrors the MCP-evidence connector (operator-only allowlist, creds off-spine by env-var name, finding pushed out is LEAD-only). Edits the shared seam `vigil_core/rbac.py` (one `OFFENSE_ACTION_PERM` route) — reconcile at merge. **Re-run the red-pen**, open PR, merge.
  5. **Identity** (`strix/enterprise-identity` @ `751f53e8`, `apps/sigil/sigil/governor/orgs.py` — owner-signed Org/Workspace + membership + `org_tenant_id` mapping; the **heaviest** wave, a core redesign grafting org/membership onto the single-owner owner-signed account model). **HIGH still open — do NOT rush the crypto:** prune-replay membership/org resurrection — `_fold_orgs`/`_fold_memberships` rebuild the anti-replay high-water with **no `SnapshotState` seed** (unlike `accounts._fold`), the prune tripwire `prune.stranded_active_accounts` matches only `governor.account` (not `governor.org`/`governor.org_membership`), and `snapshot.py` carries no org rows → after an owner-gated hard prune a replayed owner-signed grant resurrects a revoked membership (fail-open), while the docstring overclaims it "cannot happen." **FIX before wiring `org_role_can` to any consumer:** seed org+membership into `SnapshotState`, extend the prune tripwire to both org signals, correct the docstring; also the MED org-reactivation→stale-membership-resurrection (cascade-revoke memberships on `revoke_org`, or epoch-gate membership to the org's current create-grant). Re-run the full (heaviest) red-pen, open PR, merge last.

  **Reproducible env (cloud/fresh box — NOT the local graphify venv).** Use the CI recipe: `pip install --require-hashes -r engine/crucible/framework/v2/requirements.lock.txt` ; `pip install -e packages/core/vigil_core --no-deps` ; `pip install --require-hashes -r infra/supply-chain/ci-tooling.lock.txt` ; then `PYTHONPATH=.` and run `pytest integration/tests` (sovereign leg, `framework` ABSENT) plus the offense-leg list from `ci.yml`. **The sovereign keys / TPM vault are local by design and are NOT in the cloud** — anything needing a real sovereign key cannot run there.

**Step 2 — S5+ isolation/scale infra = the APPROVED we-host hosting architecture** (approved 2026-10-27, "proceed with this approach when the time comes"). Ship it as a **Terraform/Helm reference-arch skeleton in the repo** so S5+ is deployable infra, not a design note:
  - **Control plane** (UI, queue, governance, signed spine, results): **managed Kubernetes** (ephemeral-worker orchestrator + autoscaling) wired to the S5+ `SecurityJob` queue.
  - **Execution plane**: **ephemeral, strongly-isolated microVM/container sandboxes — one per engagement, torn down after** (the direct analog of Strix's sandbox-per-scan).
  - **Egress**: dedicated, **published, pinned IPs** (NAT/BYOIP) so customers allowlist and traffic is attributable; **settle the provider security-testing AUP early** — it is a go-to-market gate, not a footnote.
  - **Keys (we hold them)**: cloud **KMS/HSM** (per-tenant DEKs) + **confidential compute** for the vault.
  - **Provider pick: DEFAULT = AWS** (best fit because of **Firecracker**): EKS (control plane) + Fargate/Firecracker (per-engagement sandboxes) + **Nitro Enclaves** (vault, host operator can't read keys) + KMS + BYOIP egress. **GCP** (GKE Autopilot + gVisor/GKE Sandbox) is a strong close alternative. **Azure** (AKS + Confidential Containers) if a **government** buyer appears. Not a single VPS (no isolation/autoscale/HA/confidential compute).
  - **Destruction note (carry it into the infra):** the m-of-n destruction/quorum `target` is the **ephemeral clone path** `<abspath(base_dir)>/codefix-prbot-<slug>-<pr>` (`codefix_runner._safe_workdir` prefixes `codefix-`); the GitHub **repo identity is bound separately** by the repo-exact `'pr'` `GitWriteGrant` + a grant-vs-clone-origin check. The deterministic remediation/action id is `pr-<rid>`, `rid = ap-<sha256(ref\x00spine_hash\x00evidence_ref)[:12]>`, so an operator can pre-authorize exactly one fix PR. The ephemeral sandbox IS this clone path's natural home.

**Step 3 — The two product DECISIONS deferred to the owner** (surface, do not decide unilaterally):
  - **(a) The org-admin funnel** — who seats members into an org *without the owner key signing each one*. `orgs.py` deliberately kept `owner` non-grantable per-org; the SAFETY LINE forbids open self-serve, so the admitted model is admin-invited. The open question is the delegation shape (an org-admin role with a bounded invite capability vs. owner-signed seating). 
  - **(b) The ticketing-push RBAC tier** — whether pushing a finding out to Jira/Slack/Issues is an **owner** capability or an **operator** capability (the one `OFFENSE_ACTION_PERM` route the ticketing wave adds must land at the chosen tier).

**Step 4 — The remaining Strix-shell waves** (from the competitive teardown roadmap; all inside the SAFETY LINE): **continuous coverage** (scheduled re-scan of connected assets), **auto-fix** (extend the PCR fix→retest→gated-PR loop into continuous remediation; Wave D Go+JVM and JS/TS remain in PCR), **test users** (seeded non-destructive accounts for authenticated scans), **asset discovery** (owner-authorized surface enumeration feeding the queue), and **UX** (the Claude-Code-class engagement console polish). Each is a wave: worktree → red-pen → merge.

**Step 5 — The north-star Sovereign Cyber-Defense Fabric** (§3.1): sequence the fabric planes/modules toward it only as each piece lands oracle-proven, red-penned, and operator-gated — the highest-leverage next strategic builds the operator named are the **Sovereign AI Gateway** (mandatory classify/minimize/authorize/route/provenance/audit chokepoint to any external model), the **separate-trust-domain OOB/recovery plane**, the **Cyber Digital Twin** (blast-radius simulation before any consequential containment), and **continuous control verification**. Never claim the fabric ahead of the deterministic layer that enforces it.

## 4. Load-bearing gotchas (do not re-learn these the hard way)

Every bullet here cost real time or a real incident at least once. Read this section before your first commit, your first test run, and your first merge — on a local host *and* in a cloud session. Each item is: **the trap → why it bites → how to stay out of it.**

**Shell, git, and merge hygiene**

- **Never `git commit -m` (or `gh ... --body`) with a backtick in the message — use `git commit -F <file>`.** Backticks inside a double-quoted bash string are command substitution, and the words you most want to backtick in a tooling commit are *tool names* — so this preferentially *runs* your scanners. On 2026-08-14 a message containing `` `nuclei` `` and `` `require` `` executed both: `nuclei` ran, phoned ProjectDiscovery, and pulled **84 MB / 13,841 templates** to `~/.local` — an egress event in the very commit that added the no-egress guard, and both words were eaten from the message. Apply: write the message with the Write tool, `git commit -F`; same for `gh pr create --body`/`gh issue` (use a body file). If inline is unavoidable, single-quote — but `-F` has no quoting hazard at all.
- **In `vigil-sovereign`, add NO `Co-Authored-By: Claude` / AI-attribution trailer.** House rule: the user is the sole contributor (`[[vigil-authorship-contributors]]`); commits are "signed, no trailer." This *overrides* the harness attribution reminder for this repo. Apply: sign commits (gpg — branch protection requires it), no AI trailers, `-F` message files.
- **Auto-merge is NOT enabled and branch protection is strict — merge by hand, one PR at a time, only on genuinely-green.** Merge with `gh pr merge --merge --delete-branch` once CI is clean; under strict/up-to-date protection each merge invalidates the others, so the rest must rebase → re-run CI → merge serially. Apply: never batch-merge; re-base and re-check each sibling PR after a merge lands.
- **`gh pr checks --watch` exit codes race / exit early on local network flakiness (DNS `EAI_AGAIN`).** The watch can return "done/clean" when checks are still pending or when the local link blipped — not a true verdict. Apply: always re-confirm with a plain `gh pr checks <pr>` (awk for any non-`pass` row) before trusting status or merging; do not trust the watch exit code.
- **A repo-wide CI outage looks exactly like your breakage.** During the 2026-10-27 GitHub Actions outage every branch (main included) failed at a common setup step in 2–5 s with 0 successes. Apply: if unrelated jobs (python-compat, branch-protection) fail identically and your diff is a valid single line, it is the platform, not you — do NOT merge on a misleading "CLEAN with no checks" and do NOT merge on red; wait for Actions, re-trigger (close/reopen the PR or push), merge when truly green.

**The two-plane / FATAL-2 test reality (this is where most wasted hours go)**

- **A LOCAL two-env / P5 / sovereign-leg / FATAL-2 repro is UNFAITHFUL — do not conclude soundness from it.** CI's keyless sovereign/P5 legs run with the offense `framework` package ABSENT; but every local venv here (incl. the `graphify` venv used to drive worktree tests) has `framework` pip-/editable-importable, so a local `PYTHONPATH`-only run both (a) *passes* tests CI fails with `ModuleNotFoundError: No module named 'framework'` and (b) *fails* the SIGIL-sovereignty tests CI passes (the 6 module-level meta-path FATAL-2 tests fail locally either way — known, confirmed pre-existing). Apply: to test framework-ABSENT faithfully, install a `sys.meta_path` finder whose `find_spec` raises `ModuleNotFoundError` for `framework`/`framework.*` (gateway left importable), then run pytest under it — or just trust CI's sovereign/P5 leg. Never ship a "faithful framework-absent" claim off a bare-venv run.
- **A framework-dependent test must module-level `pytest.importorskip("framework…")` BEFORE any framework import, AND be listed in the `ci.yml` offense leg.** `importorskip` only skips on `ModuleNotFoundError`, so it cleanly skips the sovereign/CRUCIBLE-core legs (where framework is absent) while the offense leg still runs and proves it — but *only if the file is on a real run-list line* in `ci.yml` (~L517+), not `--ignore`'d and not commented. The meta-guard `integration/tests/test_ci_framework_tests_run_in_offense_leg.py` greps for this and REDS P5 (~15 min) if you forget the listing. Watch the sharp edges: (i) **lazy** framework imports (inside a test body or a prod function like `queue.enqueue`→`EngagementScheduler`) still ERROR at *run* on the sovereign leg though the file collects clean — they need the guard too; (ii) `importorskip` the dep that is actually *absent* in the leg you must skip — the P5 sovereign pass has `vigil_gateway` PRESENT but `framework` ABSENT, so `importorskip("framework…")` must come FIRST (a bare `importorskip("vigil_gateway")` won't fire and the hard `from framework…` then errors collection). Apply: guard at module top (framework first), add the file to the offense-leg run-list, and run the meta-guard locally after adding any such test. A classifier blocks a `--ignore` edit as a CI-bypass; importorskip + the additive offense-leg line is the accepted equivalent.
- **The engine test suite honors `CRUCIBLE_ROOT` (and `CRUCIBLE_AGENT`/`TEST_PREFIX`/`OPSEC_POSTURE`) from the shell — and this shell exports `CRUCIBLE_ROOT=/home/kali/Music/PENTEST/crucible`.** So a bare `pytest` on `engine/crucible/framework/v2/**` writes its runtime state (`.blackboard`, `.authority*`, `.evidence-keys`, `targets/<slug>/*`, …) into *that* checkout, not the worktree under test, and provisions a test trust root there that then causes ~57 spurious `EntitlementMissing` failures on the next run. All runtime state (charters, kill-switch, authority roots) also lives under `CRUCIBLE_ROOT`, not the repo tree — reason about live state THERE. Apply: run engine pytest hermetically — CI-style `env -i HOME=<scratch> … PYTHONPATH=engine/crucible:packages/core/vigil_core:integration:gateway <venv>/python -m pytest …`, or at minimum `env -u CRUCIBLE_ROOT -u CRUCIBLE_AGENT -u CRUCIBLE_TEST_PREFIX -u CRUCIBLE_OPSEC_POSTURE`. Put this in every delegated agent's prompt too.
- **A fresh worktree has NO venv and the editable `vigil_core` finder is stale.** Apply: drive it with the graphify venv and an explicit path — `PYTHONPATH="packages/core/vigil_core:gateway:engine/crucible:integration:." /home/kali/graphify/venv/bin/python -m pytest …` (note `vigil_core` lives at `packages/core/vigil_core/vigil_core`, so the entry is `packages/core/vigil_core`, not `packages/core`). DROP `engine/crucible` from the path for a faithful framework-absent (sovereign-leg) run.

**Keys and the cloud boundary**

- **The sovereign keys, the TPM-sealed vault, and the API keys are LOCAL by design and are NOT in the cloud.** Sovereignty is the point: the offense plane is keyless by FATAL-2 and *cannot sign and must not forge*; a live-engage / live OOB FACT / any signing ceremony needs the owner root0 key (e.g. `root0 = MgZZY4QtFhsZKCMh3jx0P78AgnNdbuss0kYv5P7amI4=`) to sign the engagement authority, and the running offense model (Opus-4.8) is not available locally either. A cloud session clones the repo but starts empty and will NOT have these keys. Apply: a cloud/CI session can build, test, red-pen, and merge code, but it CANNOT do live-engage, minting, or any signed ceremony — route anything that needs a real key to a trusted host. (The *managed* Strix-style product's "we hold the keys" story is a future S5+ KMS/Nitro-Enclave design — distinct from today's customer-sovereign deployment; don't conflate them.)

**CI gates that go red on their own (time/env-driven, not your change)**

- **A14 is a FOUR-sub-gate supply-chain job and its Trivy leg is TIME-dependent — a newly-disclosed CVE reds A14 on main and *every* open branch with zero code change.** Trivy's DB updates daily and scans every `*.lock.txt` **and** `vendor/strix/uv.lock` (native uv analyzer; it does NOT scan `infra/supply-chain/strix.lock`). The current handoff task — bump `litellm` in `vendor/strix/uv.lock` to unblock A14 — is exactly this: a transitive CVE, not your bug. Apply: do NOT panic and do NOT `.trivyignore`-suppress (house bar: "really fixed end to end, not a way around"); bump the flagged dep for real with the pinned toolchain (python 3.13.14, uv 0.11.29, `pip-tools==7.6.1`) via `uv lock --upgrade-package <pkg>` (uv.lock) or `pip-compile --upgrade-package <pkg>` (pip locks, seeded from the committed lock, CWD = engine/crucible for offense / repo root for sovereign), fix the keystone on main and let the others clear on rebase. Remember the other three A14 sub-gates + two downstream guards: lock-staleness (byte-identical regen), committed offense SBOM (`python3 -m framework.v2.tools.gen_sbom` after any offense-lock bump), the image SBOM, the `test_shared_runtime_versions_agree_across_locks` cross-lock agreement, and the strix patch-series.
- **Any change under `vendor/strix/**` (uv.lock included) trips the patch-series drift guard `test_strix_patch_series.py` in the P5 leg.** The vendored tree must equal upstream base + `docs/strix-patches/*.patch` applied in order. Apply: after editing anything in `vendor/strix/`, run `python3 tools/vendoring/regen_strix_series.py`, commit the generated `series.json` + numbered patch, and confirm `--check` says "series is current."
- **Dependabot one-sided python-lock PRs for a SHARED dep can never go green.** The cross-lock agreement guard requires the offense and sovereign locks to agree on any shared package; Dependabot bumps one lock at a time. Apply: if the dep is shared-and-agreeing, `@dependabot close` it and bump it manually as a synced pair; only the offense-only / sovereign-absent / both-absent ones are mergeable solo. (github-actions and cargo Dependabot PRs touch no lock — clean serial merges.)
- **The `formal` (TLA⁺) gate reds when the tlaplus maintainers re-upload the mutable `tla2tools.jar` release asset in place** (done 4× now) — the pinned sha drifts and `formal/check.sh` fails closed. Apply: re-pin from GitHub's server-side digest (`gh api repos/tlaplus/tlaplus/releases/tags/v1.8.0 --jq '…digest'`), verify `sha256sum` + that TLC runs, update `TLA_SHA256` (check.sh:42) and the dated comment, and re-run `bash formal/check.sh` (4 specs HOLD + 4 mutants CAUGHT). Not your change either.
- **Do NOT run `packages/vigil-ui/sync.sh`.** Its targets wrongly include the two plane *cockpit* static dirs; vendoring the unified bundle over them breaks `apps/sigil/tests/test_ui*.py` (the SIGIL P7 REQUIRED job) and cost a red CI on #953. Apply: edit the unified UI only at `packages/vigil-ui/app.js` (the uiproxy serves straight from there). For a NEW screen, its id must match `[a-z]+` only (the docs NAV extractor regex — no hyphens; the API route may keep hyphens), and you must bump "N screens" across README / docs/FEATURES.md / vigil-ui README / wiring-status.json / the W04 doc-anchor test and regen the system-map + ui-wiring-matrix, or the briefing/feature-wiring/W04 gates red. A new `vigil` *arg* (not a subcommand) needs none of the wiring-status/CLI-REFERENCE churn; a new subcommand/native verb does (else the native-verb + docs-completeness guards red).

**Soundness laws (break one and you mint a false result — one line each)**

- **A same-shape negative control must exercise the ADVERSARIAL same-shape**, i.e. the benign input that most *resembles* the vuln's signature (e.g. a benign ≥2-element data array, not the trivial `count==0`) — else an unsound predicate re-verifies "clean" against the wrong thing.
- **A CLEAN must be derivable from a SINGLE observation of a SINGLE identified peer** — silence from a positive-only detector is not a negative, and a refusal on one TCP connection says nothing about the peer on another; a CLEAN carries no signature, only provenance-by-custody.
- **Check the fixture HAS the property, not that it matches the detector** — a planted SQLi must run a real engine, a planted file-read must read a real file; when a *sound* detector reds a long-green fixture, suspect the fixture (7 fake fixtures found in one session).
- **The oracle judges BYTES; the veracity firewall structurally blocks any `intel:`/model-supplied payload from FACT strength** — a FACT needs a CRUCIBLE-owned oracle re-firing over a trusted capture (OOB/signed collector), never the LLM's or a tool's say-so.
- **Offline FACT re-verification re-evaluates the predicate over the FROZEN signed reduction value + signature tamper-evidence — it does NOT re-run the reduction from bytes** — so a reduction may use per-probe live state, but never overclaim the cert as "re-derives from bytes."
- **An allowlist must be pinned in the SIGNED artifact (an IP literal), never re-derived at decision time from the same untrusted source as the target** — a self-referential lift always fires; and after writing a shared floor helper, grep for the *pattern* (resolve-then-connect), not the helper's name (the class bug reached 7 sites).
- **A sampling gate cannot decide a producer-authored predicate's value-dependence** — ACHIEVED_STATE needs a structural grammar + a provenance-bound ref; and any change to predicate-oracle firing must be mirrored in BOTH zero-VIGIL kernels.
- **Concurrency is for SEARCH, serial is for PROOF** — concurrent baseline/treatment alternation phase-locks across workers and mints fake timing FACTs.
- **When you demote a class, name the sound producer that replaces it on EVERY render/scan path** — or register a named capability loss; a sibling slice editing the same registry can silently re-arm a demotion on merge (prefer two independent refusals).
- **`nuclei` substring co-occurrence CANNOT soundly mint a FACT** — a benign page that *quotes* the resource is indistinguishable from the resource served; keep it LEAD-only (or structural parse-as-resource for the few structured classes).
- **An offense arm must not let the model forge a FACT** (corpus-provenance triple-lock): the router emits no corpus, the seam needs a trusted channel, and the LEAD-fallback omits the class.
- **A number beside code is a CLAIM** — commit the harness (subprocesses, validated counterfactual) or withdraw the number; and raise a dead footgun, don't leave it uncalled one import from the next author.

**The SAFETY LINE (carries into the parallel-3 enterprise waves)**

- **Build the vetted-enterprise shell, NOT an open self-serve offensive portal.** Firmly refused (twice): public anonymous signup that hands the autonomous offensive engine to anyone, and $/seat commercialization of that access. The tenancy/identity wave is admin-invited accounts + SSO/SCIM + org=workspace + RBAC with VIGIL's per-target authorization KEPT (domain-ownership verification, connected-repo whitebox, never-liftable egress floor, categorical .gov/.mil block, no destruction, role NEVER from an IdP claim) — never reduced to a one-click "I'm authorized." Apply: whoever continues the enterprise waves inherits this line; do not weaken an existing control to ship a feature.

---

## 5. What is deliberately LOCAL and CANNOT be handed off

By design (the sovereignty model), these never leave a trusted host and will NOT be in a cloud session:
- The **owner / governance Ed25519 keys**, the **TPM-sealed vault** (`~/.vigil`, `.authority-root`,
  `.evidence-keys`, the per-engagement `offense-spine.key`), and the **ANTHROPIC / GITHUB API keys**.
- Consequence: a cloud session can build, test (with the §2 recipe), red-pen, open PRs, and merge — but it
  CANNOT run anything that needs a real key (live `engage`, signing a destruction authorization, the
  provisioning ceremonies). Those stay on a trusted host. This is correct, not a limitation to "fix".
- The local `graphify` venv and the 28 local worktrees are conveniences, not state — the state is the git
  branches + this doc.

## 6. Companion docs & pointers
- `HANDOFF-enterprise-waves.md` (this branch) — the per-wave red-pen findings + exact file/line fixes.
- `engine/crucible/CLAUDE.md` — the OBSIDIAN constitution; ships in the repo so a cloud session inherits it (FATAL-2 / scope / destruction / safety rules). There is **no root `CLAUDE.md`** on this branch.
- The user's local memory (`/home/kali/.claude/.../memory/`) is the fuller record but is LOCAL; §3 inlines
  its load-bearing content so this doc stands alone.
- Non-enterprise uncommitted work found on the machine during this sweep (so it is not lost) is catalogued
  at the end of §1 — it belongs to OTHER branches (meridian-s5-expansion, ev-build-moduleA, release
  tooling, home-paths) and is unrelated to the enterprise waves.
