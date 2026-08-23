# W3-10 — Pin the PEP 517 build backends, and verify the non-Python locks

Issue: [#433](https://github.com/thuram-nana/vigil-sovereign/issues/433) ·
Milestone: W3 — SUPPLY CHAIN.

## The claim (registered in the claims registry, [W0-3] #398)

<!-- CLAIM:W3-10 -->
> The PEP 517 build backends are hash-locked and the non-Python locks (`uv.lock`, `Cargo.lock`) are verified against their manifests — regenerate-checked live in CI and consistency-checked offline; there is no first-party `package-lock.json`.

This claim is TRUE of the code as of W3-10.

## The defect

Two build-time supply-chain holes sat outside every lock:

1. **PEP 517 build backends were fetched fresh under build isolation.** Every first-party member is
   built through a backend declared in its `pyproject [build-system].requires` — hatchling
   (integration, gateway, vigil_core, vendor/strix), setuptools + wheel (engine/crucible), and
   setuptools + wheel + setuptools-rust (apps/sigil, the Rust WARDEN kernel). Under build isolation
   pip/uv fetch those backends **unpinned and unhashed** from the index, and the backend *executes*
   to produce the wheel. An unpinned build backend is as real a hole as an unpinned runtime dep.
2. **The non-Python locks were scanned but never verified.** `vendor/strix/uv.lock` and
   `apps/sigil/kernel/Cargo.lock` were read by trivy but never regenerated or diffed, so a
   dependency added to a manifest with the lock never regenerated would leave that dependency
   resolved by whatever the toolchain picked — not by the committed lock — with no signal.

## The fix

### 1. Hash-lock the build backends

`infra/supply-chain/build-backends.in` declares the backends; `build-backends.lock.txt` is the fully
resolved, hash-pinned closure (generated with `--generate-hashes --allow-unsafe`, so `setuptools`
itself is pinned). `envs/build_envs.sh` installs that lock FIRST under `--require-hashes` (which
refuses the whole file if a single line is unpinned/unhashed), then builds every member with
`--no-build-isolation`, so a backend is never fetched fresh under isolation. The only package shared
with the runtime locks is `packaging`, pinned identically, so the runtime closure is unperturbed
(`pip check` proves it). A hashed `PIP_CONSTRAINT` was rejected: any hash there flips the OUTER
editable install into require-hashes mode, which then refuses `-e` — pre-install + `--no-build-isolation`
pins the backends AND keeps editable installs.

### 2. Verify the non-Python locks

`infra/supply-chain/verify_native_locks.py` is fail-closed and has two modes:

- `--check` (default) — OFFLINE, stdlib `tomllib`: every direct dependency named in each manifest
  resolves to a `[[package]]` in its lock. Catches "a dep was added but the lock never regenerated".
  Runs in the required integration + A14 jobs with no network and no toolchain.
- `--regenerate-check` — LIVE (uv / cargo): `uv lock --check` (on a copy outside the uv workspace,
  the trick `gen-strix-lock.sh` uses) and `cargo metadata --locked` both exit non-zero if
  regenerating the lock would change it. Run by the A14 supply-chain gate.

The enforcing symbol is `check_lock_matches_manifest`. It is proven by, in
`integration/tests/test_supply_chain.py`:

- `test_build_backends_lock_covers_every_declared_backend` — every backend declared in any
  `pyproject [build-system].requires` is pinned+hashed in the build-backends lock.
- `test_build_envs_installs_backends_hashed_and_builds_without_isolation` — the build actually USES
  the lock (`--require-hashes` + `--no-build-isolation`).
- `test_native_locks_are_consistent_with_their_manifests` — the offline consistency check is clean
  on the committed tree.
- `test_native_lock_check_is_not_a_no_op` — the **negative control**: a manifest declaring a
  dependency its lock does not pin is flagged for BOTH ecosystems, and an empty/packageless lock is
  rejected, asserted in the same run.
- `test_no_first_party_package_lock_json_only_a_cve_fixture` — see honest scope below.
- `test_workflow_regenerate_checks_the_native_locks` — the A14 gate runs the live regenerate-and-diff.

These fail on a tree without the fix (`verify_native_locks.py` and the build-backends lock do not
exist). They run in the required **integration two-env boundary (P5)** job (which collects the whole
`integration/tests` tree).

## Honest scope — `package-lock.json`

The acceptance criterion names `package-lock.json`, but this repo ships **no first-party** one. The
only `package.json` in the tree is a deliberately-vulnerable CVE **test fixture**
(`engine/crucible/framework/v2/eval/corpus_apps/_cve/…`) with no lock, which must NOT be locked or
regenerated. `test_no_first_party_package_lock_json_only_a_cve_fixture` enforces that: if a real JS
component ever appears, the test fails until a `package-lock.json` pair is added to
`verify_native_locks.py` and the docs updated — so a real manifest can never ship unverified.

The `--regenerate-check` half needs `uv` and `cargo` and network; on a runner without them it is
skipped in favour of the offline consistency check, which the required jobs always run.
