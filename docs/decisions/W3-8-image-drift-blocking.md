# W3-8 — Base-image drift is ADVISORY where resolvable (unpinned still blocks), and the registry limit is stated

Issue: [#431](https://github.com/thuram-nana/vigil-sovereign/issues/431) ·
Milestone: W3 — SUPPLY CHAIN.

> **Posture update.** W3-8 originally made resolvable drift *blocking*. It is now **advisory**: a digest
> pin already guarantees a reproducible build, so gating every PR on Docker's routine tag rebuilds was
> toil, not signal (it reddened all open PRs at once when `python:3.13-slim` moved). The real guarantee —
> an *unpinned* image blocks — is unchanged, and the `--fail-on-drift` blocking mechanism is retained and
> still proven live by the negative control. The claim below reflects the current (advisory) posture.

## The claim (registered in the claims registry, [W0-3] #398)

<!-- CLAIM:W3-8 -->
> Base-image drift is three-valued, and resolvable drift on an already-digest-pinned base is ADVISORY in the A14 gate — surfaced in the drift report and the job summary, but not blocking, because a digest pin already gives a reproducible build (a moved tag does not change the bytes that ship). What still BLOCKS is an UNPINNED image (the `--check` step). The `--fail-on-drift` mechanism is retained and still blocks resolvable drift when armed — proven live by the drift-gate negative control — and a documented, reasoned rolling-base allowlist (`image_pins.py::_ADVISORY_ROLLING_DRIFT`, currently `kalilinux/kali-rolling` and `library/neo4j`) is advisory too. A pin on any registry the resolver cannot query is reported as an explicit UNKNOWN — surfaced in the job summary, never a silent pass.

This claim is TRUE of the code as of the W3-8 posture update.

## The defect

`image_pins.py --drift` was two-valued: a Docker Hub pin either matched the live tag or reported
`??`, and the step in `supply-chain.yml` was `continue-on-error: true`. So two very different states
were both a green tick:

- a pin whose registry the resolver **could** query (Docker Hub) and which had **moved** — real,
  resolvable drift, silently tolerated; and
- a pin on a registry the resolver **cannot** query (anything but Docker Hub) — a genuine unknown,
  `??`, **presented as a pass**.

An unknown rendered as a pass is exactly the failure this programme keeps finding: the check runs,
goes green, and proves nothing.

## The fix

Drift is now three-valued (`infra/supply-chain/image_pins.py`):

- **resolvable & up-to-date** → nothing to do.
- **resolvable & MOVED** (`DRIFT_MOVED`) → real drift. The A14 gate runs `image_pins.py --drift`
  (WITHOUT `--fail-on-drift`), so this is **ADVISORY**: surfaced in the report and `$GITHUB_STEP_SUMMARY`,
  but `run_drift` exits 0 and the job stays green. A digest pin already guarantees a reproducible build, so
  re-pinning is a deliberate act on a cadence (read the upstream changelog first), not a per-PR block.
  `--fail-on-drift` still makes it BLOCK — retained for a strict operator and exercised by the live
  negative control below; and an UNPINNED image still blocks unconditionally via `--check`.
- **resolvable & MOVED for a documented rolling base** (`DRIFT_MOVED_ADVISORY`) → a repository in the
  reasoned `_ADVISORY_ROLLING_DRIFT` allowlist (currently only `kalilinux/kali-rolling`, the strix
  sandbox base — a rolling distro tracked-latest by design whose ~1000-package SBOM is regenerated
  deliberately, and which is already ADVISORY-vuln-scanned in this job). Its moved digest is SURFACED
  (`~~`, counted, written to the step summary) but does NOT block — gating every PR on a rolling
  tag's daily movement is a category error. Every *other* resolvable drift still blocks; the allowlist
  is exact-repository-keyed and each entry must carry a reason.
- **UNKNOWN** (`DRIFT_UNKNOWN_REGISTRY` for a registry the resolver cannot query — anything but
  Docker Hub — or `DRIFT_UNKNOWN_NETWORK` for a Hub tag that could not be reached) → surfaced to
  stdout AND written to `$GITHUB_STEP_SUMMARY`, and counted. It never renders as `??`-as-pass. It
  does not block by default (a gate cannot honestly fail on a state it could not check);
  `--fail-on-unknown` makes it block for the strictest posture.

The network lives only in `hub_resolver`; `evaluate_drift`/`run_drift` take the resolver as an
argument and are pure, so the gate can be driven OFFLINE by a stub resolver.

`run_drift` in `integration/tests/test_supply_chain.py` is the enforcement proven by:

- `test_resolvable_drift_blocks` — a Hub pin whose live digest moved fails under `--fail-on-drift`.
  **Fails on a tree without the fix** (`evaluate_drift`/`run_drift`/`Resolution` do not exist).
- `test_unresolvable_registry_is_explicit_unknown_not_a_pass` — a `ghcr.io` pin is an explicit
  UNKNOWN, not drift; it does not block unless `--fail-on-unknown`.
- `test_drift_gate_negative_control_can_fail` — the **negative control**: `run_drift` returns
  non-zero on a deliberately drifted resolvable pin AND zero when nothing moved, asserted in the
  same run, so the gate is neither a no-op nor stuck-on.
- `test_drift_summary_makes_unknowns_visible` — the UNKNOWN entry is named in the job-summary text.
- `test_workflow_drift_step_is_advisory_and_negative_control_still_blocks` — the real gate runs
  `--drift` (advisory, NOT armed with `--fail-on-drift`), while the drift-gate negative control and the
  unpinned `--check` step stay blocking and are not `continue-on-error`, so a future edit cannot silently
  re-arm a per-PR block on drift, drop the mechanism's live proof, or defeat the unpinned guarantee.

A live end-to-end negative control also runs in the A14 job: it points the exact blocking config at
a fixture with a deliberately-wrong digest on a resolvable (Docker Hub) registry and requires it to
fail. It runs in the required **integration two-env boundary (P5)** job (which collects the whole
`integration/tests` tree) and, redundantly, in the **A14 supply-chain gate** job.

## Honest scope

- **Rolling-base carve-out (W3-8 Option A):** drift of a documented, reasoned rolling base in
  `_ADVISORY_ROLLING_DRIFT` (currently only `kalilinux/kali-rolling`) is ADVISORY, not blocking — it
  is surfaced but does not fail the gate, because a rolling tag drifts by design and its committed
  SBOM is regenerated deliberately, not per-drift. The allowlist keys on **repository** (so any tag
  of that repo is advisory), matches exactly (no prefix/substring/case laundering), and requires a
  non-empty reason per entry; every non-allowlisted resolvable drift still BLOCKS. Proven by
  `test_allowlisted_rolling_drift_is_advisory_not_blocking`,
  `test_non_allowlisted_moved_digest_still_blocks_negative_control`,
  `test_reverting_the_allowlist_makes_the_rolling_drift_block`, and
  `test_every_rolling_drift_allowlist_entry_carries_a_reason`.
- The drift resolver queries **Docker Hub only** — the one registry with a stable, unauthenticated
  tag→digest endpoint this stdlib-only module uses. Every other registry is an honest UNKNOWN, not a
  pass. Widening the resolver to another registry is a deliberate follow-up (add a resolver and its
  host set), not a silent gap.
- The live drift and its negative control need network; on a runner with no egress a Hub tag is an
  UNKNOWN (network), which is surfaced, not a false pass. The pure classification is what the
  offline required-job tests exercise.
