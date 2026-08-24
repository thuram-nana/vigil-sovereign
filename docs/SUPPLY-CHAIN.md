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
| `engine/crucible/framework/v2/aegis/Dockerfile` | `python:3.13-slim@sha256:ffb752e1…` |
| `engine/crucible/framework/v2/eval/corpus_apps/_smoke/Dockerfile` | `node:22-bookworm@sha256:0557ac14…` |
| `engine/crucible/framework/v2/eval/corpus_apps/_cve/st-2014-3744/Dockerfile` | `node:22-bookworm@sha256:0557ac14…` |
| `vendor/strix/containers/Dockerfile` | `kalilinux/kali-rolling:latest@sha256:f4912486…` |
| `docker-compose.yml` → `qdrant` | `qdrant/qdrant:v1.19.0@sha256:057ee3a8…` |
| `docker-compose.yml` → `neo4j` | `neo4j:5-community@sha256:d9dd3dc7…` |
| `docker-compose.yml` → `otel-collector` | `otel/opentelemetry-collector:0.158.0@sha256:5b97e6e3…` |

Two exemptions, and they are rules rather than holes: `FROM scratch` (no content to pin) and
images **built from this tree** (`vigil-gateway`, `vigil/strix-sandbox:local`) — there
is no upstream digest for something this repo produces. `integration/tests/test_supply_chain.py`
carries a negative control proving the checker still flags an unpinned image, and still ignores
a build-stage back-reference.

**The `${QDRANT_VERSION:-latest}` / `${OTEL_VERSION:-latest}` indirections were removed.** A
floating `latest` behind an environment variable is exactly the drift this section exists to
stop, and nothing in the repo ever set either variable. The pinned versions are byte-identical
to what `:latest` resolved to on 2026-08-12, so this is a no-op for behaviour.

### 1a. The gateway RUNTIME image is content-addressed (issue #511 / W5-6)

The scanner above sees only images the tree **declares** (`FROM`, compose `image:`). It cannot
see the image the gateway is **actually running**. That mattered: `ensure_image` returned early
when the `vigil-gateway:latest` tag existed, and `docker compose up -d` will not recreate an
unchanged tag — so after a `git pull`, `vigil services up` **silently kept running the old egress
gate**, with no diff and no signal.

The gateway image is now **content-addressed by its build context**. `vigil services up` hashes
the `gateway/` build context, tags the built image `vigil-gateway:ctx-<digest>` (plus a moving
`:latest` alias), and the compose file interpolates `${VIGIL_GATEWAY_IMAGE_TAG:-latest}` into the
`image:` line. A source change flips the tag, forcing a rebuild **and** a recreate; an unchanged
context yields the same tag and rebuilds nothing. This is *not* the `${…:-latest}` upstream
anti-pattern removed above: this image is first-party and the variable carries a **content
address**, so it forces recreate-on-change rather than masking upstream drift.

Two guards back it:

* **Fail-closed at bring-up.** After `docker compose up`, `compose_up` refuses (raises) if the
  running container's image content id is not the one it just built — a repointed tag or a
  hand-started stale container can never leave a silent, downgraded egress gate. It then records a
  runtime pin (`.vigil-live/gateway-image-pin.json`: the build-context digest + the built image
  id).
* **The A14 runtime check.** `python3 infra/supply-chain/image_pins.py --runtime-check` re-derives
  the current build-context digest, reads the pin, reads the running container's image id, and
  proves the running gateway is the image built from the **current** source. It is **loud** on a
  stale / mismatched / unproven runtime and **refuses (exits non-zero) in the production posture**
  (`VIGIL_POSTURE=production`, or `--production`); outside production it is advisory so a dev box
  without the gateway up is not a red build. The content-digest algorithm is duplicated in
  `gateway/vigil_gateway/docker.py` and here; a consistency test
  (`gateway/tests/test_docker_content_address.py::test_context_digest_matches_the_a14_checker`)
  pins the two together so a fresh build is never mis-flagged as stale.

The actual `docker build` is exercised opt-in
(`VIGIL_GATEWAY_DOCKER_IT=1 pytest gateway/tests/test_docker_bringup.py`); the digest-pinning,
rebuild-on-change (with an unchanged-context negative control), fail-closed-on-mismatch and
runtime-check **logic** are covered offline against a fake docker.

### Re-pinning

```bash
python3 infra/supply-chain/image_pins.py --drift          # drift report (resolvable drift is BLOCKING)
python3 infra/supply-chain/image_pins.py --check          # offline: is everything pinned?
```

**Drift is three-valued, and resolvable drift BLOCKS (W3-8, issue #431)** — except a documented, reasoned rolling-base allowlist (`_ADVISORY_ROLLING_DRIFT`, currently only `kalilinux/kali-rolling`) whose drift is advisory (surfaced, not blocking); every other resolvable drift blocks. The old check was
two-valued — a Docker Hub pin either matched or reported `??`, and `??` (any non-Hub registry, or a
network blip) was *presented as a pass*. It is now three-valued:

Resolvable base-image drift (a Docker Hub tag that has moved) BLOCKS the A14 gate under
`--fail-on-drift`; a pin on any registry the resolver cannot query is reported as an explicit
UNKNOWN — surfaced in the job summary, never a silent pass.

- **resolvable & moved** → the A14 gate runs `image_pins.py --drift --fail-on-drift` and this fails
  the job. Re-pinning is still a deliberate act (read the upstream changelog first), but it is now a
  *required* one, not an advisory nudge.
- **UNKNOWN (registry the resolver cannot query — anything but Docker Hub)** → written to
  `$GITHUB_STEP_SUMMARY` and counted, never a silent `??` pass. It does not block by default (a gate
  cannot honestly fail on a state it could not check); `--fail-on-unknown` makes it block for the
  strictest posture.
- **resolvable & up-to-date** → nothing to do.

A live negative control in the A14 job points the exact blocking config at a fixture with a
deliberately-wrong digest on Docker Hub and requires it to fail, so the gate is proven not a no-op;
the pure drift logic has an offline negative control in `integration/tests/test_supply_chain.py`.

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

### CI installs from the locks — the tested tree equals the locked tree (W3-2)

A lock nothing installs from is a document, not a control. Every CI job that runs the code
installs its **runtime** dependencies from a committed hash lock under `--require-hashes`, never as
a floating range:

```
pip install --require-hashes -r engine/crucible/framework/v2/requirements.lock.txt
pip install -e packages/core/vigil_core --no-deps
```

Before W3-2 six `ci.yml` jobs (plus `livefire.yml` and `pre-commit.yml`) installed
`cryptography>=42` while the project floor was `>=50` for **CVE-2026-69247** — CI could resolve
the vulnerable 42.x line and test against the version the repo claims to have left behind. The
runtime installs now come from the lock, so the resolved version **is** the pinned version by
construction, and `vigil_core` is installed `--no-deps` so its floors resolve to the already-locked
versions rather than fresh from PyPI.

Every job uses the **offense** framework lock for its third-party runtime subset — even the
sovereign-side pure-Python jobs (`SIGIL governor`, `SIGIL lint`). That is deliberate: it is the
light runtime closure (the sovereign lock drags in the `kuzu`/`onnxruntime`/`qdrant` ML stack those
jobs do not need), it holds **only third-party packages** — no `framework`/`sigil` module, so
FATAL-2 is untouched — and its shared-package versions are byte-identical to the sovereign lock
(`test_shared_runtime_versions_agree_across_locks` fails if they ever diverge). The full sovereign
environment is still exercised under `--require-hashes` by the A14 install proof.

The **CI/test toolchain** (`pytest`, `pytest-asyncio`, `ruff`, `mypy`) is not part of the shipped
tree, so it is kept out of both runtime locks; it has its own hash-locked subset,
`infra/supply-chain/ci-tooling.lock.txt`, which the jobs also install under `--require-hashes`. It
is generated with `uv pip compile --generate-hashes` (like `strix.lock`'s uv origin, unlike the two
pip-compile runtime locks) and its input is `infra/supply-chain/ci-tooling.in`. Every job that runs
`pytest`/`ruff`/`mypy` — including the advisory `lint-config.yml` job — installs the toolchain from
this lock under `--require-hashes`; none types `pip install "ruff==…" mypy pytest` inline, which
would pin only `ruff` and resolve `mypy`+`pytest` fresh from PyPI on every run.

| Lock | Covers | Generated with |
|---|---|---|
| `infra/supply-chain/ci-tooling.lock.txt` | CI/test toolchain — `pytest`, `pytest-asyncio`, `ruff`, `mypy` | `uv pip compile --generate-hashes` |

The A14 gate proves the ci-tooling lock installs under `--require-hashes` and, after each runtime
require-hashes install, **records** the resolved versions (`pip freeze`) and **compares** them to
the lock (`.github/scripts/compare_resolved_to_lock.py`) — a red build if the CI environment ever
diverges from the lock. `integration/tests/test_supply_chain.py` (a required check, in both the A14
gate and the `integration` job) asserts statically that **no** workflow installs a runtime range
below a lock floor, that every runtime dependency is installed under `--require-hashes`, and — a
separate class the runtime guards are blind to because the toolchain is in no runtime lock — that
**no** workflow installs a ci-tooling-locked tool (`pytest`/`ruff`/`mypy`) inline without
`--require-hashes` (`test_ci_installs_toolchain_only_under_require_hashes`).

The only deliberately-unpinned CI install that remains is `strix-vigil`'s best-effort live-scan SDK
(`openai-agents[litellm]`, `openai`): it is not part of the tested tree — the reasoning/dedup tests
`importorskip` it if it cannot resolve — and hash-locking it is [W3-6]'s `strix.lock` surface.

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

### 3a. The Strix sandbox CONTAINER image has its own SBOM (S5)

The two SBOMs above describe the Python **dependency** closure. They say nothing about the
container the offense agent actually runs targets in: `vigil/strix-sandbox:local`, built from
`vendor/strix/containers/Dockerfile` (`FROM kalilinux/kali-rolling`). That image carries ~1000
Debian packages plus a Go / npm / pip / pipx / standalone-binary toolchain, and had **no SBOM at
all**. Part III of the STRIX+HEXSTRIKE programme requires *dependency **and** container* SBOMs;
this section is the container half.

| Artifact | Generated by | Drift guard |
|---|---|---|
| `infra/supply-chain/sbom-strix-sandbox.cdx.json` (CycloneDX 1.5) | `infra/supply-chain/gen_image_sbom.py` | `gen_image_sbom.py --check` + `integration/tests/test_strix_image_sbom.py` |

**Measured, not fabricated.** The Dockerfile is *not* a faithful bill of materials: it installs
whole apt sets with no version pins and several tools at `@latest` / `go install …@latest` /
`nuclei -update-templates`, so what actually ships is only knowable from a **built image**. So the
generator introspects the built image's own package databases — the same sources `syft` reads, but
with **stdlib + docker only** (no `syft`/`trivy`/`cyclonedx-bom` on the host), for the same reason
`gen_sbom.py` is stdlib-only: a sovereign engine regenerates its own bill of materials with the
tools it already has. It reads `dpkg-query -W` (deb), the `/app/.venv` pip closure and each
`pipx` tool venv (pypi), `npm ls -g --depth=0` (npm), `go version -m` on each go binary (golang),
`<tool> --version` for the curl-installed binaries (gitleaks, trivy, trufflehog, caido-cli, uv),
and the pinned commit of each git-cloned tool (github).

**Committed, not per-run regenerated** — the opposite choice from the dependency SBOMs above, and
deliberately so. The image is ~7 GB and is **not** in git, and a PR runner cannot rebuild it, so
there is nothing for CI to regenerate against per-run. The committed SBOM is therefore the
artifact, and the drift guard is **offline**: `--check` re-hashes the committed Dockerfile and
re-reads the `STRIX_IMAGE` runtime default (via `image_pins.py`, the same source of truth § 1 uses),
and fails if the SBOM's recorded `dockerfile-sha256`, `base-image` or `sbom-target-image` no longer
match the tree. A Dockerfile change that is not accompanied by a regenerated SBOM fails the build —
the same discipline `gen_sbom --check` applies to the lock-derived SBOM.

Regenerate after any change to the sandbox Dockerfile (needs docker and the built image):

```bash
docker compose --profile strix build strix-sandbox        # (re)build the image
python3 infra/supply-chain/gen_image_sbom.py              # introspect it, rewrite the SBOM
```

**What this does NOT prove** (stated plainly): `--check` proves the SBOM is current *with respect
to the committed Dockerfile and runtime ref*; it does **not**, offline, re-introspect the image, so
it cannot detect a drift between the Dockerfile and a stale locally-built image — that is the job of
the opt-in live test (`VIGIL_STRIX_SBOM_DOCKER_IT=1`, which regenerates from the image and asserts
the component set matches). The generator records the built image's id + created time but cannot
cryptographically prove that image was built from exactly this Dockerfile (there is no
reproducible-build attestation for the sandbox image). npm is captured at `--depth=0` (the tools
installed), not the full `node_modules` transitive tree, and runtime-fetched data such as nuclei
templates is out of scope. The `compositions.aggregate` is marked `incomplete_first_party_only`
accordingly, rather than claiming completeness it does not have.

### 3b. A RELEASE carries a SIGNED SBOM, retrievable independently of CI retention (W3-5, #428)

The two dependency SBOMs above are, on push/PR, uploaded as the `a14-sbom-cyclonedx` CI artifact —
which expires with CI retention (90 days). That is fine for a PR gate, but it meant a **deployed**
artifact had no retrievable bill of materials once retention lapsed. `.github/workflows/release.yml`
(tag push only) closes that: for each shipped closure (offense + sovereign) it

- **generates + cross-checks** the SBOM with the SAME mechanism the A14 gate uses
  (`bin/verify-supply-chain.sh --sbom-out=…`) — so an SBOM that dropped a shipped component fails
  before it is signed;
- **signs** it with `cosign sign-blob` — the SAME keyless primitive the release wheel uses (a
  `vigil_core` Ed25519/DSSE signature would need a long-lived key on the runner, which keyless OIDC
  avoids), emitting an offline-verifiable `*.cosign.bundle`;
- **attaches** it to the **GitHub Release** (`gh release upload`) — a release asset does not expire
  with CI retention, so the signed SBOM is retrievable for as long as the release exists.

`.github/scripts/verify-release-artifacts.sh` re-runs the component cross-check
(`infra/supply-chain/sbom_crosscheck.py`) against the exact SBOM bytes about to be attached, verifies
each SBOM signature offline, refuses a release with no SBOM, and carries an **omit-a-component
negative control** (drop a component from a copy; the check must fail). The tag-triggered workflow's
shape and the cross-check behaviour are pinned offline by
`integration/tests/test_release_sbom.py` in the required *integration two-env boundary (P5)* job.

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

### 4a. The BUILT container images, not only the source tree (W3-7, #430)

`trivy fs` scans the source tree; it never sees a **built image**, so the OS-package layer of the
image that ships went unscanned, and the images carried mutable `:latest` tags (a stale image
indistinguishable from a fresh build). The A14 gate now also:

- **Builds the first-party gateway image** (`docker build ./gateway`) and tags it by its **content
  address** — `image_pins.py --context-tag` → `vigil-gateway:ctx-<digest16>`, a sha256 over the build
  context. A source change flips the tag; an unchanged context keeps it. So **a stale image is
  detectable by tag alone** (this is the same tag `vigil services up` writes and the #511 runtime
  check reads; a consistency test pins the two implementations together).
- **Scans the built image** with `trivy image` at the same `HIGH,CRITICAL` blocking threshold as the
  filesystem gate, with one deliberate difference — `--ignore-unfixed`: an *unfixable* upstream-base
  CVE is not a defect the author can remediate under a red build (that is how an image gate gets
  switched off), while a **fixable** HIGH/CRITICAL still blocks. A negative control builds a fixture
  image with a deliberately vulnerable layer and requires the blocking config to FAIL on it.
- **Scans the Strix sandbox layer via its committed SBOM** — `trivy sbom
  infra/supply-chain/sbom-strix-sandbox.cdx.json`. The ~7GB Kali image is too large to build on a PR
  runner, so it is not `trivy image`-scanned here; its committed CycloneDX SBOM enumerates the
  shipped OS-package layer and `trivy sbom` scans those purls. **Advisory** on purpose: a
  security-testing distro carries findings the author cannot fix, so blocking on it would switch the
  gate off.

**Residual — the live `trivy image` scan of the Strix sandbox (W3-7 residual, #653).** A live build +
`trivy image` scan of the ~7GB Strix sandbox cannot run on a GitHub-hosted PR runner. It is now
**scaffolded** as a dedicated workflow, `.github/workflows/strix-sandbox-image-scan.yml`, honestly
labelled as a self-hosted follow-up:

<!-- CLAIM:W3-7-strix-selfhosted -->
> **Registered claim:** A committed, dormant-by-design workflow scaffold builds and `trivy image`-scans the Strix sandbox image at the gateway image's exact threshold (HIGH,CRITICAL with --ignore-unfixed), advisory; it triggers only on schedule/workflow_dispatch and is guarded to a self-hosted `runs-on` label plus an opt-in repository variable, so it never runs on a pull request and stays inert until an operator provisions a self-hosted/large runner (a human/infra action); a required-CI guard pins its shape, and it is enumerated in KNOWN_NONPR_ADVISORY so it can never become a required check.

The scaffold triggers only on `schedule` + `workflow_dispatch`, its job `runs-on` a `[self-hosted,
linux, x64, large]` label (so GitHub only dispatches it to a large self-hosted runner), and it is
additionally gated on the `STRIX_SANDBOX_SCAN` repository variable — so every scheduled/dispatched run
is cleanly **skipped** until an operator both provisions such a runner and opts in. When it does run, it
builds `vigil/strix-sandbox:local` and `trivy image`-scans it at the gateway threshold, ADVISORY (a Kali
distro carries findings the author cannot fix). Its shape is pinned in required CI by
`docs/tests/test_strix_sandbox_image_scan_workflow.py`, and it is enumerated in `KNOWN_NONPR_ADVISORY`
(it never runs on a PR, so it can never be a required check). **The single human/infra action left is
registering that self-hosted runner** (and setting the opt-in variable); until then the SBOM scan above
remains the PR-CI proof of the Strix layer.

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
workflow's token. **Every action in every workflow** under `.github/workflows/` is pinned to a
full 40-char commit SHA, with the version kept in a trailing `# vX.Y.Z` comment, and a drift
check asserts this stays true across all of them (W3-3, #426).

```bash
gh api repos/actions/checkout/commits/v4 --jq .sha   # → the SHA to pin; keep `# v4.4.0` as a comment
```

### The drift check

`integration/tests/test_every_workflow_action_is_sha_pinned` (in
`integration/tests/test_supply_chain.py`) enumerates every `uses:` in every workflow file and
FAILS on any ref that is not a 40-hex commit SHA — a tag (`@v4`) or a branch (`@main`). Local
first-party actions (`uses: ./…`) are exempt (there is no upstream SHA to pin). It runs in the
required **A14 supply-chain gate** and **integration two-env boundary (P5)** jobs, so an unpinned
action cannot merge. Its negative control (`test_sha_pin_gate_rejects_a_tag_pinned_workflow`)
points the same detector at a throwaway workflow pinning `@v4` and asserts it is flagged, and at a
SHA-pinned twin and a local action and asserts neither is — proving the gate is not a no-op.

### Honest scope

- The check verifies the ref is a 40-hex SHA; it does not (and cannot, offline) re-resolve each
  SHA against its upstream tag. The pins were resolved once with `gh api …/commits/<tag>` and the
  trailing `# vX.Y.Z` comment records the human-readable version each SHA corresponded to at pin
  time. The comment is advisory — the SHA is the thing that binds.
- `github/codeql-action/*` carries its version as `# codeql-action v3 (codeql-bundle-…)` rather
  than a bare `# vX.Y.Z`; the drift check keys on the SHA, not the comment shape, so that is fine.

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
- **PEP 517 build backends are hash-locked, and the non-Python locks are verified (W3-10, #433).**
  The PEP 517 build backends are hash-locked and the non-Python locks (`uv.lock`, `Cargo.lock`) are
  verified against their manifests — regenerate-checked live in CI and consistency-checked offline;
  there is no first-party `package-lock.json`.
  Concretely: the build backends declared in every `pyproject [build-system].requires` (hatchling /
  setuptools + wheel / setuptools-rust) are pinned with hashes in
  `infra/supply-chain/build-backends.lock.txt`; `envs/build_envs.sh` installs that lock
  `--require-hashes` and builds every member with `--no-build-isolation`, so a backend is never
  fetched fresh under isolation. The non-Python locks are no longer merely *scanned*:
  `infra/supply-chain/verify_native_locks.py` checks OFFLINE (stdlib `tomllib`, in the required
  integration + A14 jobs) that every direct dependency in `vendor/strix/pyproject.toml` and
  `apps/sigil/kernel/Cargo.toml` is pinned in its lock, and the A14 job runs the LIVE
  regenerate-and-diff — `uv lock --check` (on a copy outside the uv workspace, the trick
  `gen-strix-lock.sh` uses) and `cargo metadata --locked` — each of which fails if regenerating the
  lock would change it. **`package-lock.json` honesty:** the acceptance criterion names it, but this
  repo ships *no first-party* `package-lock.json` — the only `package.json` in the tree is a
  deliberately-vulnerable CVE **test fixture** (`engine/crucible/.../corpus_apps/_cve/…`) that must
  NOT be locked or regenerated; a test enforces that no other `package.json` appears unverified.
- **Build signing — scoped to the release wheel.** Hashes prove an artifact did not change
  between lock time and install time; they do not prove *who* built it or *from what*. That gap
  is now closed for the one artifact this repo actually publishes: `.github/workflows/release.yml`
  (tag push only, `v*`) builds the `packages/core/vigil_core` wheel + sdist and attaches to each
  a Sigstore/cosign signature, an SLSA build-provenance attestation, and a PEP 740 attestation
  for the wheel; the same run also attaches the signed dependency SBOMs to the release (§3b, W3-5).
  See *What is signed, and by which identity* below. The boundary: this does not
  cover the editable `-e ./…` install path an operator runs via `bootstrap.sh` (there is no
  registry artifact to sign there), nor the third-party dependency layer, which is guarded by the
  hash locks above and not by these signatures.
- **Image scanning covers the gateway image live; the Strix sandbox via its SBOM only (W3-7, #430).**
  The gateway image is BUILT and `trivy image`-scanned in the required gate (§4a). The ~7GB Strix
  sandbox cannot be built on a PR runner, so its shipped layer is scanned through its committed
  CycloneDX SBOM (`trivy sbom`, advisory) rather than a live image build. A live `trivy image` of the
  Strix sandbox is now **scaffolded** as the self-hosted workflow
  `.github/workflows/strix-sandbox-image-scan.yml` (W3-7 residual, #653); it stays inert until a
  self-hosted/large runner is provisioned (a human/infra action) — see §4a.
- **Base-image digests are re-resolved against Docker Hub only.** An image on another registry
  cannot be resolved by the drift check, so it is reported as an explicit **UNKNOWN** in the drift
  report and the job summary (never a silent `??` pass, W3-8). Resolvable (Docker Hub) drift blocks;
  an UNKNOWN registry blocks only under `--fail-on-unknown`.
- **MEDIUM-and-below vulnerability findings are advisory.** They are surfaced, not enforced — a
  deliberate trade (see §4), not an oversight. HIGH and CRITICAL block; and resolvable base-image
  drift now blocks too (W3-8) — except the documented rolling-base allowlist (`_ADVISORY_ROLLING_DRIFT`, e.g. `kalilinux/kali-rolling`), whose drift is advisory.

## What is signed, and by which identity

The tag-triggered release workflow (`.github/workflows/release.yml`, `on: push: tags: [v*]`)
signs the release build. It runs only on a version-tag push, so it does not report on ordinary
pull requests; its shape is asserted offline on every PR by
`integration/tests/test_release_provenance.py` and `integration/tests/test_release_sbom.py` (which
run in the required *integration two-env boundary (P5)* job). The workflow is advisory — a
tag-triggered job cannot be a required PR check, and it is deliberately kept out of
`.github/required-status-checks.txt`.

For each artifact it builds (the `vigil-core` wheel and sdist):

- **Sigstore / cosign signature** — `cosign sign-blob` produces an offline-verifiable bundle
  (`*.cosign.bundle`) carrying the signing certificate, the signature, and the Rekor inclusion
  proof, so a third party can verify without calling home.
- **SLSA build provenance** — `actions/attest-build-provenance` binds an in-toto provenance
  statement to the sha256 of each artifact.
- **PEP 740 attestation** — `pypi-attestations` emits a `*.publish.attestation` for each wheel
  (and the sdist); when Trusted Publishing is enabled (`vars.PUBLISH_TO_PYPI == 'true'`),
  `pypa/gh-action-pypi-publish` also attaches attestations at upload time.

And, for the dependency SBOMs (W3-5, #428; §3b):

- **Signed CycloneDX SBOMs, attached to the release** — the offense + sovereign SBOMs are
  cross-checked against their locks, `cosign sign-blob`-signed (same keyless primitive), and attached
  to the GitHub Release with their `*.cosign.bundle`, so a deployed artifact has a signed, retrievable
  bill of materials independent of CI artifact retention.

**The identity.** All are keyless (Sigstore), so the signer is not a long-lived key but the
workflow's own GitHub OIDC identity:

```
issuer:   https://token.actions.githubusercontent.com
identity: https://github.com/<owner>/<repo>/.github/workflows/release.yml@refs/tags/<tag>
```

`verify-release-artifacts.sh` verifies each signature (wheels, sdist AND SBOMs) against exactly that
issuer and a `certificate-identity-regexp` pinned to this workflow at a tag ref, and carries two
negative controls that fail the job if they do not hold: it appends a byte to a copy of each artifact
and requires the tampered copy to be **rejected** by the same offline verify path; and it drops a
component from a copy of each SBOM and requires the component cross-check to **fail** — so neither a
tampered artifact nor an incomplete bill of materials can pass.

## Follow-ups

1. ~~SHA-pin the actions in `.github/workflows/ci.yml`~~ — **DONE (W3-3, #426).** Every `uses:`
   in every workflow (`ci.yml`, `livefire.yml`, `branch-protection-verify.yml` were the last
   tag-pinned holdouts — 32 refs) is now pinned to a full commit SHA, and a widened drift check
   in a required job (§5) fails on any future tag/branch ref.
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
5. ~~**Add PEP 740 / sigstore attestation verification on top of the hashes**~~ — **DONE (W3-4,
   #427).** `.github/workflows/release.yml` signs the release wheel/sdist with cosign, emits SLSA
   provenance, and produces PEP 740 attestations, then verifies them offline with a tamper
   negative control (`.github/scripts/verify-release-artifacts.sh`); the shape is pinned offline
   by `integration/tests/test_release_provenance.py`. Boundary: it covers the published
   `vigil-core` artifact only, not the editable install path — see the §6 bullet above.
