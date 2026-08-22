# W3-2 — CI installs from the hash-locked files, so the tested tree equals the locked tree

Issue: [#425](https://github.com/thuram-nana/vigil-sovereign/issues/425) ·
Milestone: W3 — SUPPLY CHAIN.

## The claim (register in the claims registry, [W0-3] #398)

> Every CI job that runs the code installs its **runtime** dependencies from a committed hash lock
> under `pip install --require-hashes`, never as a floating range. No workflow admits a runtime
> version below the locked one — `cryptography>=42` against the `cryptography==50.0.0` lock (the
> CVE-2026-69247 floor) is rejected by a required check. The CI/test toolchain (`pytest`,
> `pytest-asyncio`, `ruff`, `mypy`) is likewise installed from a committed hash-locked subset,
> `infra/supply-chain/ci-tooling.lock.txt`, under `--require-hashes`.

This claim is TRUE of the code as of W3-2:

- **The defect** — before this slice, six `ci.yml` jobs plus `livefire.yml` and `pre-commit.yml`
  installed `"cryptography>=42"` (and `pydantic>=2.10,<3`, `structlog`, `httpx`, … as bare names)
  while both runtime locks pin `cryptography==50.0.0`. CI could resolve the vulnerable 42.x line and
  test against the version the repo claims to have left behind.
- **The fix (wiring, on the real CI path)** — every runtime-dependency install in
  `.github/workflows/{ci,livefire,pre-commit,bench-perf}.yml` and the A14 setup in
  `supply-chain.yml` now reads:
  ```
  pip install --require-hashes -r engine/crucible/framework/v2/requirements.lock.txt
  pip install -e packages/core/vigil_core --no-deps
  ```
  The offense framework lock is used for the third-party runtime subset in **all** test jobs — it is
  the light runtime closure, holds only third-party packages (no `framework`/`sigil` module, so
  FATAL-2 is untouched), and its shared versions are byte-identical to the sovereign lock. The heavy
  sovereign environment is still exercised under `--require-hashes` by the A14 install proof.
- **The toolchain lock** — `infra/supply-chain/ci-tooling.lock.txt` (input `ci-tooling.in`) pins
  `pytest`/`pytest-asyncio`/`ruff`/`mypy` with hashes; the jobs install it under `--require-hashes`.
  Generated with `uv pip compile --generate-hashes` (like `strix.lock`'s uv origin) and proven to
  install under `--require-hashes` by the A14 gate.
- **Resolved-vs-lock recording** — after each require-hashes install the A14 gate dumps `pip freeze`
  and compares it to the lock (`.github/scripts/compare_resolved_to_lock.py`); a divergence is a red
  build. `--require-hashes` already forces resolved == locked, so this is the explicit assertion of
  that invariant against a runner that ships a shadowing package.

Pinned by `integration/tests/test_supply_chain.py` (§5), which runs in **two** required checks — the
`A14 supply-chain gate` and the `integration two-env boundary (P5)` job. The new tests:

- `test_no_ci_pip_install_admits_a_version_below_a_lock_floor` — **FAILS on a tree without the fix**
  (the `cryptography>=42` installs), with an inline negative control that the detector flags
  `cryptography>=42` and passes `cryptography>=50` / the exact locked pin.
- `test_ci_installs_runtime_deps_only_under_require_hashes` — every runtime dependency in every
  workflow is installed under `--require-hashes`; negative control that an inline runtime install is
  flagged and a `--require-hashes` / first-party-editable install is not.
- `test_ci_tooling_lock_is_used_under_require_hashes`, `test_ci_tooling_lock_agrees_with_runtime_locks_on_shared_packages`,
  `test_shared_runtime_versions_agree_across_locks` — the toolchain lock is committed, hash-pinned,
  covers pytest/ruff/mypy, is installed under `--require-hashes`, and neither it nor the two runtime
  locks disagree on a shared package (which would break the sequential require-hashes installs).

## Honest scope

- The one remaining deliberately-unpinned CI install is `strix-vigil`'s best-effort live-scan SDK
  (`openai-agents[litellm]`, `openai`) — not part of the tested tree (those tests `importorskip` it),
  and hash-locking it is [W3-6]'s `strix.lock` surface, not this slice.
- The [W0-3] #398 claims registry is being built in the same tranche and is not yet on `main`; per
  the repo's prior-slice convention this decision record + the doc-truth assertions in
  `test_supply_chain.py` stand in for the registry entry until #398 lands, at which point this claim
  should be registered there.
