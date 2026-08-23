# W3-8 — Base-image drift is BLOCKING where resolvable, and the registry limit is stated

Issue: [#431](https://github.com/thuram-nana/vigil-sovereign/issues/431) ·
Milestone: W3 — SUPPLY CHAIN.

## The claim (registered in the claims registry, [W0-3] #398)

<!-- CLAIM:W3-8 -->
> Resolvable base-image drift (a Docker Hub tag that has moved) BLOCKS the A14 gate under `--fail-on-drift`; a pin on any registry the resolver cannot query is reported as an explicit UNKNOWN — surfaced in the job summary, never a silent pass.

This claim is TRUE of the code as of W3-8.

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
- **resolvable & MOVED** (`DRIFT_MOVED`) → real drift. The A14 gate runs
  `image_pins.py --drift --fail-on-drift`, and `run_drift` returns a non-zero exit that BLOCKS the
  job. Re-pinning stays a deliberate act (read the upstream changelog first) but is now *required*,
  not advisory.
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
- `test_workflow_drift_step_blocks_and_is_not_advisory` — the real gate runs `--fail-on-drift` and
  is not `continue-on-error`, so a future edit cannot make it advisory again.

A live end-to-end negative control also runs in the A14 job: it points the exact blocking config at
a fixture with a deliberately-wrong digest on a resolvable (Docker Hub) registry and requires it to
fail. It runs in the required **integration two-env boundary (P5)** job (which collects the whole
`integration/tests` tree) and, redundantly, in the **A14 supply-chain gate** job.

## Honest scope

- The drift resolver queries **Docker Hub only** — the one registry with a stable, unauthenticated
  tag→digest endpoint this stdlib-only module uses. Every other registry is an honest UNKNOWN, not a
  pass. Widening the resolver to another registry is a deliberate follow-up (add a resolver and its
  host set), not a silent gap.
- The live drift and its negative control need network; on a runner with no egress a Hub tag is an
  UNKNOWN (network), which is surfaced, not a false pass. The pure classification is what the
  offline required-job tests exercise.
