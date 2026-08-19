# Supply-chain hardening (A14)

Everything else in this repository is about proving that what the system *did* is true. This
document is about the other half of the problem: proving that what the system is *built from*
is what we chose. Those are the parts an attacker can change without ever touching this
repository — a retagged base image, a compromised transitive wheel, an action tag repointed at
a different commit.

The controls below are enforced by the **`A14 supply-chain gate`** job
(`.github/workflows/supply-chain.yml`) plus a set of network-free assertions in
`integration/tests/test_supply_chain.py` that also run in the ordinary `integration` job.

---

## 1. Base images are digest-pinned

A tag is a **mutable pointer**. `FROM python:3.13-slim` means "whatever the registry serves at
pull time", so a retag — benign or hostile — changes what ships with no diff, no review and no
signal. A digest is content-addressed: the daemon verifies it, or the pull fails.

| File | Image |
|---|---|
| `gateway/Dockerfile` (via `ARG PYTHON_BASE`) | `python:3.13-slim@sha256:ffb752e1…` |
| `engine/crucible/framework/v2/aegis/Dockerfile` | `python:3.11-slim@sha256:90744cff…` |
| `engine/crucible/framework/v2/eval/corpus_apps/_smoke/Dockerfile` | `node:22-bookworm@sha256:0557ac14…` |
| `engine/crucible/framework/v2/eval/corpus_apps/_cve/st-2014-3744/Dockerfile` | `node:22-bookworm@sha256:0557ac14…` |
| `vendor/strix/containers/Dockerfile` | `kalilinux/kali-rolling:latest@sha256:f4912486…` |
| `docker-compose.yml` → `qdrant` | `qdrant/qdrant:v1.19.0@sha256:057ee3a8…` |
| `docker-compose.yml` → `neo4j` | `neo4j:5-community@sha256:d9dd3dc7…` |
| `docker-compose.yml` → `otel-collector` | `otel/opentelemetry-collector:0.158.0@sha256:5b97e6e3…` |

Two exemptions, and they are rules rather than holes: `FROM scratch` (no content to pin) and
images **built from this tree** (`vigil-gateway:latest`, `vigil/strix-sandbox:local`) — there
is no upstream digest for something this repo produces. `integration/tests/test_supply_chain.py`
carries a negative control proving the checker still flags an unpinned image, and still ignores
a build-stage back-reference.

**The `${QDRANT_VERSION:-latest}` / `${OTEL_VERSION:-latest}` indirections were removed.** A
floating `latest` behind an environment variable is exactly the drift this section exists to
stop, and nothing in the repo ever set either variable. The pinned versions are byte-identical
to what `:latest` resolved to on 2026-08-12, so this is a no-op for behaviour.

### Re-pinning

```bash
bash infra/supply-chain/resolve-image-digests.sh          # drift report (advisory)
bash infra/supply-chain/resolve-image-digests.sh --check  # offline: is everything pinned?
```

Drift is **advisory** in CI. A tag moving upstream is not a defect in whatever change is under
review, and a gate that goes red for reasons the author cannot fix is a gate that gets switched
off. Re-pin deliberately, after reading the upstream changelog.

---

## 2. Dependencies are hash-locked — two locks, not one

`env-sovereign` and `env-offense` must never share an interpreter (FATAL-2, `envs/README.md`),
so they cannot share a resolution either.

| Env | Input | Lock |
|---|---|---|
| offense (`vigil_core` + `engine/crucible` + `gateway` + `integration`) | `engine/crucible/framework/v2/requirements.in` | `engine/crucible/framework/v2/requirements.lock.txt` |
| sovereign (`vigil_core` + `apps/sigil` + `integration`) | `infra/supply-chain/sovereign.in` | `infra/supply-chain/sovereign.lock.txt` |

Only **third-party** dependencies are locked. The first-party members are installed `-e` from
the tree and have no registry artifact to hash.

`sovereign.in` pulls `apps/sigil/requirements.txt` through `-r` rather than restating it, so
`apps/sigil` stays the single source of truth for its own runtime.

### What the gate proves

1. The `.in` resolves.
2. The lock exists, contains real `name==version` pins, and **every** pin carries
   `--hash=sha256:`. (`--require-hashes` is all-or-nothing: pip rejects the whole file if one
   line lacks a hash, so an unhashed line does not weaken the guarantee — it removes it.)
3. The lock is current with respect to its `.in`.
4. The lock pins every direct requirement named in the `.in` — a lock that silently dropped one
   would leave it installed unpinned.
5. `pip install --require-hashes -r <lock>` **actually succeeds** into a clean venv. A lock full
   of hashes that pip rejects is a document, not a control.

### Regenerating a lock

Under **Python 3.13**, and **from that lock's canonical directory**. Both constraints are real:
the lock is Python-minor specific, and pip-compile writes its `# via -r <path>` annotations
relative to the directory it ran in — so regenerating from elsewhere produces a byte-different
file and a staleness failure whose only diff is annotation paths.

```bash
pip install pip-tools==7.6.1

# offense — canonical CWD: engine/crucible
cd engine/crucible
pip-compile --generate-hashes --no-header --strip-extras \
            --output-file=framework/v2/requirements.lock.txt \
            framework/v2/requirements.in

# sovereign — canonical CWD: the repo root
cd <repo root>
pip-compile --generate-hashes --no-header --strip-extras \
            --output-file=infra/supply-chain/sovereign.lock.txt \
            infra/supply-chain/sovereign.in
```

`--no-header` matters: pip-compile's default header embeds the literal `--output-file` path, so
a lock generated with it can never be byte-compared against a regeneration into a temp file.
(That is the bug that kept `bin/verify-supply-chain.sh` from ever passing; the full story is in
that script's header.)

### Staleness semantics — deliberately narrow

The drift check **seeds** its temp file from the committed lock. Without `--upgrade`,
pip-compile keeps pins that still satisfy the input, so a failure means precisely:

> *the `.in` changed and the lock was not regenerated.*

It does **not** mean "someone published to PyPI today". The naive version of this check goes red
on an unrelated upstream release, forcing whoever is on shift to bump dependencies under time
pressure to get their build back — which is how a security gate gets disabled. Upgrade
availability is reported separately by `--report-upgrades`, advisory-only.

---

### vendor/strix's live-scan extras — a third lock, from `uv.lock` not pip-compile

`env-offense` also loads `vendor/strix` (the offense agent body), whose heavy live-scan deps —
`openai-agents[litellm]`, `litellm`, `openai`, `docker`, `textual`, `cvss`, `caido-sdk-client` and
their transitive closure — are deliberately **not** in the offense framework `.in`/lock. Before
[W3-6] they resolved **fresh from PyPI on every operator install** (`envs/build_envs.sh`) — the
largest unlocked surface in the product, and it co-loads with the offense engine.

They are now pinned in a dedicated lock, **`infra/supply-chain/strix.lock`**, and `build_envs.sh`
installs it under `--require-hashes` before installing `vendor/strix` itself editable `--no-deps`
on top, so a fresh machine reproduces the SAME closure and never re-resolves strix.

This lock is generated **differently** from the two pip-compile locks above: strix ships its own
upstream `uv` lock (`vendor/strix/uv.lock`), so the strix lock is *exported from it* — offline,
with `uv export --frozen` (no re-resolution) — rather than compiled from an `.in`. Regenerate
deterministically under Python 3.13 with:

```bash
bash infra/supply-chain/gen-strix-lock.sh
```

The strix lock is applied **before** the framework lock so the framework lock wins any
shared-dependency version — e.g. it keeps `cryptography>=50` (the CVE-2026-69247 fix) over strix's
older transitive pin. `integration/tests/test_supply_chain.py` asserts the lock is fully
hash-pinned, covers strix's declared runtime deps, and that no operator install path resolves
strix's extras unhashed; a hand-built-wheel negative control proves `--require-hashes` actually
rejects a corrupted or missing hash. It is **not** swept into trivy's `pip:.*\.lock\.txt$`
pattern (§4) because strix's closure is already scanned through `vendor/strix/uv.lock`.

### Fail-closed vs. degrade — the production posture

If a required lock is absent on a checkout, `build_envs.sh` does **not** silently fall back to a
fresh, unlocked resolution. With `VIGIL_POSTURE=production` (or `prod`) it **aborts** the build;
in any other posture (dev, the default) it prints a **loud** warning and degrades. Deployments set
`VIGIL_POSTURE=production` so a missing lock can never quietly re-open the unlocked surface. [W9-4]
builds on this posture.

---

## 3. SBOM

Each lock produces a CycloneDX 1.6 SBOM via `cyclonedx-bom==7.3.1`, uploaded by the gate as the
`a14-sbom-cyclonedx` artifact (`sbom-offense.cdx.json`, `sbom-sovereign.cdx.json`).

SBOMs are **generated, not committed**. They are derived from the lock, which is the committed
source of truth; a per-run regenerated artifact in git is churn that reviewers learn to ignore.
The gate cross-checks the generated SBOM against the lock component-for-component, so a
generator that silently dropped packages fails the build rather than producing a
confident-looking, wrong bill of materials.

---

## 4. Vulnerability scanning — threshold and triage policy

Scanner: **trivy**, pinned by version *and* by the sha256 of its release tarball. Installing a
security scanner via `curl | sh` from an unpinned URL would be its own supply-chain hole.

| Severity | Behaviour |
|---|---|
| **CRITICAL** | **Blocks.** The job exits non-zero and the pull request cannot merge. |
| **HIGH** | **Blocks.** Raised from advisory to blocking in W3-9 (issue #432) once the vendored HIGH backlog was cleared. |
| MEDIUM | Reported in full in the job log. Advisory. |
| LOW | Not surfaced by this gate. |

### What is scanned

`trivy fs` over the whole tree, with `--file-patterns 'pip:.*\.lock\.txt$'`. That flag is
load-bearing, not tuning: trivy's pip analyzer matches by **filename**, so by default it scans
`apps/sigil/requirements.txt` and **silently skips both `*.lock.txt` locks** — which is to say,
it skipped the two artifacts this gate exists to produce. A gate that does not scan what the
change adds is hollow.

Currently detected: `apps/sigil/kernel/Cargo.lock` (cargo), `apps/sigil/requirements.txt` (pip),
`vendor/strix/uv.lock` (uv), plus the two locks.

### The gate is proved to fire

The gate passes with an **empty** allow-list, because this tree has no HIGH or CRITICAL
findings. That is the right outcome — and it is also indistinguishable from a scanner that is
misconfigured into reporting nothing: a typo in a flag, a severity string that matches nothing,
an analyzer that found no files.

So the job runs a **negative control immediately before the gate**, and W3-9 extended it to
prove the *raise*, not just that the scanner fires. It uses two fixtures, both outside the repo:

1. a **known-CRITICAL** fixture (`pyyaml==5.3.1`, `pillow==8.2.0`) — the blocking configuration
   must *fail* on it, as it always did; and
2. a **HIGH-only** fixture (`pyasn1==0.6.3`: trivy reports 3 HIGH, 0 CRITICAL, fixed in 0.6.4 —
   exactly the class this change bumped out of `vendor/strix`). The gate severity
   (`HIGH,CRITICAL`) must *fail* on it, **and** the old `CRITICAL`-only severity must *pass* on
   it. That pair is the proof that a HIGH now blocks where it previously would not — a control
   that only fired on CRITICAL could not tell the two thresholds apart.

If any leg comes out the wrong way, the job errors out rather than shipping a green tick. A gate
that has never fired is not evidence of anything.

### Current findings: 0 CRITICAL, 0 HIGH

A `trivy fs` scan (v0.73.0) of the whole tree with the gate configuration reports **no HIGH or
CRITICAL findings** on any scanned target — the two `*.lock.txt` locks, `apps/sigil/requirements.txt`,
`apps/sigil/kernel/Cargo.lock` and `vendor/strix/uv.lock` all come back clean. The gate therefore
blocks HIGH and CRITICAL with an empty allow-list.

That was **not** true before W3-9. The measured HIGH backlog was **8 findings across 3 packages**,
all in the vendored strix lock (the first-party locks and `apps/sigil` had already been moved to
`cryptography>=50` in PR #295):

| Package | Where | Advisory | Was | Fixed in / bumped to |
|---|---|---|---|---|
| `cryptography` | `vendor/strix/uv.lock` | CVE-2026-69247, CVE-2026-69249, GHSA-537c-gmf6-5ccf | 46.0.7 | **50.0.0** (fixes at 50.0.0 / 49.0.0 / 48.0.1) |
| `aiohttp` | `vendor/strix/uv.lock` | GHSA-cq5v-8q36-5273 (OOB heap read, HIGH) | 3.14.1 | **3.14.3** |
| `pyasn1` | `vendor/strix/uv.lock` | CVE-2026-59884/59885/59886 (DoS, HIGH) | 0.6.3 | **0.6.4** |

W3-9 bumped all three in `vendor/strix/uv.lock` (hashes re-fetched from PyPI; `cffi` stayed at
2.0.0, which satisfies `cryptography 50.0.0`'s `cffi>=2.0.0`). The issue named only `aiohttp` and
`pyasn1`; `cryptography 46.0.7` was the third HIGH the scan surfaced once those two were cleared,
and it is bumped here too because the threshold cannot rise while any HIGH remains.

**Why HIGH now blocks.** Earlier revisions of this policy blocked on CRITICAL only, because a
known HIGH backlog sat in `vendor/strix` and a HIGH-blocking gate over it would have needed an
allow-list large enough that nobody reads it — and an allow-list nobody reads launders findings.
With the backlog cleared and the tree measured clean at HIGH, the gate blocks HIGH+CRITICAL and
the blocking set stays small enough that each future entry is a decision. Lowering the threshold
again means editing the severity in `supply-chain.yml` **and**
`integration/tests/test_supply_chain.py` (the gate-severity tests), which is deliberate: the
threshold should be a decision with a diff, not a drive-by.

### Suppressions

Suppressions live in `.trivyignore`. **Every entry must carry a justification comment directly
above it**, naming the id and one of:

| Reason | Means |
|---|---|
| `no-fix` | Upstream has published no fixed version. |
| `not-reachable` | The vulnerable code path is not reachable in how this repo uses the package. |
| `vendored-test-only` | Only present in vendored or test-fixture material, never in a shipped path. |
| `disputed` | The advisory is disputed upstream. |
| `false-positive` | The scanner has misidentified the component or version. |

`test_every_vulnerability_suppression_carries_a_justification` enforces this, and has a negative
control proving it rejects a bare id. The point of a scan gate is that ignoring a finding costs
a sentence of explanation; entries with no reason are how a gate quietly becomes a no-op.

---

## 5. GitHub Actions are SHA-pinned

`actions/checkout@v4` is a mutable tag on someone else's repository, executing with the
workflow's token. The A14 workflow pins every action to a full commit SHA, with the version in a
trailing comment, and a test asserts this stays true.

```bash
gh api repos/actions/checkout/git/ref/tags/v4 --jq .object.sha
```

### Honest scope

**The eight pre-existing jobs in `.github/workflows/ci.yml` are still tag-pinned.** Converting
them is a separate change with a wider blast radius — if a SHA is wrong, every job in the repo
fails at once — and it was kept out of this one deliberately rather than smuggled in. It is the
first follow-up below.

---

## 6. What this does NOT prove

Stated plainly, because a hardening document that only lists wins is a marketing document.

- **`ci.yml` still installs unpinned.** The jobs in `ci.yml` install loose ranges
  (`pip install "pydantic>=2.10,<3" …`) rather than the locks. So the locks are *verified* on
  every PR but are not yet what CI *tests against*. Switching those jobs onto the locks is the
  second follow-up; doing it in this change would have coupled an A14 failure to every unrelated
  test job.
- **The operator install path now installs from the locks — `ci.yml` is the remaining gap.**
  `bootstrap.sh` (the only documented install path) delegates to `envs/build_envs.sh`, which
  installs the third-party framework closure from the lock under `--require-hashes` and then the
  first-party `-e` members `--no-deps` on top (they have no registry artifact to hash). `vendor/strix`'s
  live-scan extras are installed the same way, from `infra/supply-chain/strix.lock` (§2). So an
  operator's install reproduces the locked closure, not a fresh PyPI resolution. What is **not** yet
  on the locks is `ci.yml` (first bullet): the test jobs still `pip install` loose ranges, so the
  tree CI *tests against* is not the locked tree. That switch is its own slice ([W3-2]) rather than
  a rider here.
- **Cargo / npm ecosystems are scanned but not locked by us.** `apps/sigil/kernel/Cargo.lock`
  and the corpus app's `package-lock.json` are their own upstream artifacts; trivy reads them, but
  this gate does not regenerate or hash-verify them. (`vendor/strix/uv.lock` used to be in this
  list. Its live-scan extras are now hash-locked *for install* — exported to
  `infra/supply-chain/strix.lock` and installed `--require-hashes`, see §2 — though the gate still
  does not *regenerate* the upstream `uv.lock` itself.)
- **No signature verification.** Hashes prove the artifact did not change between lock time and
  install time. They do not prove the artifact was published by whoever you think — that needs
  PEP 740 attestations / sigstore, which is not wired here.
- **Base-image digests are re-resolved against Docker Hub only.** An image on another registry
  would report `??` in the drift report rather than being checked.
- **Drift is advisory, and so are MEDIUM-and-below findings.** They are surfaced, not enforced.
  That is a deliberate trade (see above), not an oversight. HIGH and CRITICAL now block.

## Follow-ups

1. SHA-pin the actions in `.github/workflows/ci.yml`.
2. Install from the locks in `ci.yml` so the tested tree is the locked tree.
3. ~~**Install from the locks in `envs/build_envs.sh`** so the operator's install is the locked
   install, not only CI's~~ — **DONE.** `build_envs.sh` installs the framework closure and
   `vendor/strix`'s live-scan extras under `--require-hashes` ([W3-6]); the `-e` members go on
   `--no-deps`. The remaining reach is `ci.yml` (item 2).
4. ~~**Raise `cryptography` past the `<50` ceiling to take the CVE-2026-69247 fix**~~ — **DONE
   (PR #295).** Both environments now require `cryptography>=50`
   (`engine/crucible/framework/v2/requirements.in:46` pins `>=50,<51`,
   `infra/supply-chain/sovereign.in:40` pins `>=50`, `apps/sigil/requirements.txt:1` pins
   `==50.0.0`) and both locks were regenerated. ~~**Still open from that item:** bump `aiohttp`
   and `pyasn1` in `vendor/strix`, then raise the blocking threshold from CRITICAL to HIGH~~ —
   **DONE (W3-9, issue #432).** `vendor/strix/uv.lock` now pins `aiohttp==3.14.3`, `pyasn1==0.6.4`
   and `cryptography==50.0.0` (the scan surfaced `cryptography 46.0.7` in the vendored lock as the
   third HIGH once the first two were cleared), the tree scans clean at HIGH, and the gate blocks
   HIGH+CRITICAL (`supply-chain.yml`). See §4.
5. Add PEP 740 / sigstore attestation verification on top of the hashes.
