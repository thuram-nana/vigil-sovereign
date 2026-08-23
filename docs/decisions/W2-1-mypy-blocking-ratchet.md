# W2-1 — mypy is BLOCKING behind a per-module ratchet

Issue: [#418](https://github.com/thuram-nana/vigil-sovereign/issues/418) ·
Milestone: W2 — CODE QUALITY GATES.

## The claim (registered in the claims registry — [W0-3] #398, id `W2-1`)

<!-- CLAIM:W2-1 -->
> **Registered claim (W0-3 #398):** mypy runs blocking behind a committed per-module ratchet: a type error in any SIGIL module not on the not-yet-clean allowlist fails CI, and the allowlist can only shrink.

## Why this exists

mypy was **advisory**. The `sigil-lint` CI job ran `mypy sigil` and then `exit 0`, discarding the
exit code — real type errors shipped green. "A type checker that cannot fail is a type checker that is
not running." Turning it fully blocking in one step is impossible while the package still carries 93
type errors across 22 modules, so this is the middle path: a **per-module ratchet**.

## What is TRUE of the code as of W2-1

- **The allowlist.** `apps/sigil/mypy-ratchet.txt` lists the 22 modules that are NOT YET mypy-clean,
  plus a `ceiling:` that must equal the number of listed modules.
- **The gate.** The required `SIGIL lint (ruff blocking + mypy can-complete)` CI job runs
  `tools/governance/mypy_ratchet.sh`, which runs `mypy sigil` and hands the output to
  `tools/governance/mypy_ratchet.py`. Its `evaluate()` fails the build when:
  - a module with a type error is **not** on the allowlist (a previously-clean or new module
    regressed) — this is the whole point;
  - a module **on** the allowlist is now clean (the list must shrink — an improvement must be
    recorded, and the list can never be padded);
  - the committed `ceiling:` does not equal the number of listed modules.
- **The old swallow is gone.** The mypy step no longer ends in `exit 0`; mypy failing to run (exit 2,
  a parse/config abort, or an absent binary) still fails closed.
- **Loosening is explicit and CI-flagged.** Because the allowlist must equal the real failing set,
  adding a module requires raising `ceiling:` in the same commit; the guard fails until it is bumped,
  so a loosening is always an explicit, reviewable diff line. The list can only shrink over time.

## Honest limits

The ratchet is at **module granularity**, as the issue specifies: a listed ("not-yet-clean") module
may still accrue additional errors without tripping the guard. Its contract is that a **clean** module
never regresses to dirty and that the **set** of dirty modules only shrinks. The ceiling's
only-shrink monotonicity is a review-enforced high-water mark (like the perf gate and the coverage
floors), not a cryptographic one; what is enforced unconditionally every run is that no
un-allowlisted module carries a type error and that the allowlist equals the real failing set.

**Environment reference — where the failing set is measured.** The baseline the ratchet is
checked against is the set mypy reports in the *pinned CI toolchain environment*: the `SIGIL lint`
job's hash-locked install (the offense-framework runtime lock + editable `vigil_core` + the
CI-tooling lock), which is where the blocking gate actually runs. That environment deliberately
does not install SIGIL's optional heavy runtime deps (numpy, mcp, kuzu, qdrant-client, fastembed,
onnxruntime); under `ignore_missing_imports` they resolve to `Any`. One allowlisted module,
`sigil/voice/components.py`, is listed only because of this: with numpy absent, the `# type: ignore`
guarding its soft `import numpy` becomes an *unused* ignore (`warn_unused_ignores = true`) — a real
diagnostic in the gate's environment. A developer who runs `mypy_ratchet.sh` in a fuller local venv
(numpy present) will see that one module come up clean and the guard flag it STALE; the CI
environment is the source of truth for the baseline. The count above (93 errors / 22 modules) is
the CI-environment count.

**Operator note (required-check rename).** This job was renamed from `SIGIL lint (ruff blocking +
mypy can-complete)` to `SIGIL lint (ruff blocking + mypy can-complete)`. The committed source of truth
(`.github/required-status-checks.txt`), `docs/AS-BUILT.md`, and the offline canonical test are all
updated, but **live** branch protection must be re-synced with
`bash tools/governance/require-checks.sh --apply` (admin-only), and until then the owner's
attributable admin override lands this PR.

## Proof

`docs/tests/test_mypy_ratchet.py` (rides the required `the briefing explains every agent and
capability` job) exercises `evaluate()`'s regression / stale / ceiling controls in-process, checks
the committed ratchet is self-consistent, and asserts the CI step invokes the gate and no longer
carries the `exit 0` swallow.
