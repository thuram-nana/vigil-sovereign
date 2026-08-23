# W11-7 — A chaos and failover suite for the single-writer sovereign spine

Issue: [#488](https://github.com/thuram-nana/vigil-sovereign/issues/488) ·
Milestone: W11 — RESILIENCE & CHAOS.
Interacts with [W7-5](https://github.com/thuram-nana/vigil-sovereign/issues/463) (freshness),
[W8-2](https://github.com/thuram-nana/vigil-sovereign/issues/468) (fork-detection SLA),
[W8-4](https://github.com/thuram-nana/vigil-sovereign/issues/469) (failover guard) and
[W8-1](https://github.com/thuram-nana/vigil-sovereign/issues/467) (alerting).

## The gap

Before W11-7 the only unit-tested piece of the HA path was the failover guard's **decision core**
(`apps/sigil/tests/test_ha_failover_guard.py`). There was no cohesive, explicitly-labelled suite that
exercises the four chaos classes the single-writer sovereign spine is built to survive — **network
partition, clock skew, a byzantine witness, and torn-page injection** — and asserts that in each case the
system's **documented** behaviour (`docs/architecture/HA-PROFILE.md`, the store's invariant-15 fail-closed
doctrine, and the transparency-log quorum-intersection rule) is what actually happens. Nor did any suite
run on a **cadence** so a chaos regression surfaced on its own, or **alert** when it failed.

## What ships

A cohesive suite, `apps/sigil/tests/test_chaos_failover.py`, with one test per chaos class and a negative
control in the **same run** for each, so no gate can be a green no-op:

| Chaos class | Documented behaviour asserted | Negative control (same run) |
|---|---|---|
| **Network partition** (split-brain) | A partition that defeats advisory fencing brings up a second writer; its same-height divergent owner-signed head is a **detectable fork** (`transparency.is_split`, HA-PROFILE §2/§4) and the failover guard **refuses to promote it** (`SAME-HEIGHT FORK`, exit 2). A partitioned/stale mirror below the anchor is refused (`ROLLBACK`). | A healthy single-writer extension (count 2→3) is **not** flagged as a fork and **does** promote. |
| **Clock skew** | A future-dated or stale off-box anchor is **refused fail-closed** (`future-skew` / `STALE ANCHOR`, HA-PROFILE §3.1, W7-5). | The **same** head with a **fresh** anchor **activates** (`freshness == "fresh"`). |
| **Byzantine witness** | In a strict-majority quorum an honest stateful witness **refuses to equivocate** on a second same-height fork (`transparency.py` non-equivocation contract). | **The required control:** a witness set that meets a signing quorum but **violates quorum-intersection** (sub-majority, or a duplicate/low-order key) is **rejected** by `is_split_view_resistant` / `verify_split_view_resistant`, while `verify_witnessed` is fooled — and a genuinely strict-majority set **is** accepted. |
| **Torn-page injection** | A torn **tail** from an interrupted write is **repaired**: reads skip it, the prefix verifies, an append after it is not lost (`store._last_valid_boundary`, BLOCK-1). | A torn **middle** line is a **chain break** `verify()` **fails** on — rejected, never a silent short-read (invariant 15). |

The suite also verifies the docs' HA claims are true of the code: it pins the load-bearing HA-PROFILE
non-claim string verbatim and asserts each cited mechanism symbol (`is_split`, `is_split_view_resistant`,
`evaluate_promotion`, `_last_valid_boundary`) and source file actually exists.

### Where it runs, and how failures alert

- **Required, per-PR.** The suite lives under `apps/sigil/tests/`, which the required **SIGIL governor
  gates (P7 — offense gate + authn)** CI job runs in whole; `test_ci_sigil_tests_all_run.py` guarantees a
  new file is auto-included and can never silently skip.
- **On a schedule, with alerting (#467).** `.github/workflows/scheduled-chaos-failover.yml` runs the suite
  nightly. When it fails it **opens a GitHub issue** — the alert. The alert **decision** is the pure,
  unit-tested `.github/scripts/chaos_alert.py` (`should_alert(exit) != 0`), so "failures alert" is
  falsifiable in code, not buried in an `if:` expression. The workflow is schedule/dispatch-only (never a
  PR check) and is recorded in the `KNOWN_NONPR_ADVISORY` ledger of `test_required_checks_canonical.py`.

### Honest split (heavy chaos)

The fast, deterministic, negative-controlled suite runs in the required job. The genuinely **heavier**
chaos — a real **multi-process** split-brain (`test_partition_multiprocess_split_brain_heavy`, deselected
on the PR runner and selected only when the scheduled workflow sets `VIGIL_CHAOS_HEAVY=1`) and the
**SIGKILL crash-fuzz** torn-page harness (`test_spine_crashfuzz.py`) — runs **only** in the scheduled
workflow's heavy leg, honestly labelled as such. Nothing claims the heavy legs run in per-PR CI.

## The claim (registered in the claims registry, [W0-3] #398, id `W11-7`)

<!-- CLAIM:W11-7 -->
> **Registered claim (W0-3 #398):** The chaos-and-failover suite proves the single-writer sovereign spine's DOCUMENTED behaviour under network partition, clock skew, a byzantine witness, and torn-page injection; in particular a byzantine witness set that meets a signing quorum but violates the strict-majority quorum-intersection rule is REJECTED by is_split_view_resistant, so verify_witnessed can pass while verify_split_view_resistant fails.

This claim is TRUE of the code as of W11-7:

- **The quorum-intersection rule is real and fail-closed.** `is_split_view_resistant`
  (`integration/vigil_integration/transparency.py`) returns True only for a strict majority
  (`2*threshold > n`) of **distinct** (decoded, canonical, non-low-order) keys; a sub-majority, a
  duplicate key, or a malformed/low-order key fails closed. `verify_split_view_resistant` conjoins it with
  the quorum signature, so a valid-quorum-but-not-strict-majority set (which `verify_witnessed` accepts) is
  rejected.
- **Each chaos behaviour matches the cited mechanism** (asserted per-scenario in the suite, table above).
- **It runs required per-PR and scheduled+alerting** (above), and the wiring is itself asserted
  (`test_chaos_suite_runs_on_a_schedule`, `test_scheduled_chaos_failure_alerts`).

## Honest scope (do not overclaim)

- This is a **test/CI + docs** deliverable; it adds no new enforcement engine. It pins EXISTING
  enforcement (`is_split`, `is_split_view_resistant`, `evaluate_promotion`, the store's torn-tail repair,
  the W7-5 freshness gate, the W8-2 SLA) as a named chaos suite and wires the cadence + alert.
- Independence strength is unchanged and remains the witnessed-floor doctrine's (HA-PROFILE §4): at the
  default owner-only, threshold-1 witness set the anchor is retention-based **detection**, not independent
  split-view **prevention**; strict-majority prevention needs ≥2 independent witness keys, a deployment
  property code cannot verify. The all-keys-compromised case (owner key + a witness quorum) is not closed
  here — no code can.
- The scheduled alert is a GitHub **issue** (the CI-native alert); the on-host runtime notifier is the
  separate W8-1 (#467) `Alarm`/`AlarmSink` path this work follows in spirit.

## Registration

`docs/claims/registry.json` id `W11-7`: `enforced_by` →
`integration/vigil_integration/transparency.py:is_split_view_resistant`, `proved_by` →
`apps/sigil/tests/test_chaos_failover.py`, `ci_job` → `SIGIL governor gates (P7 — offense gate + authn)`.
