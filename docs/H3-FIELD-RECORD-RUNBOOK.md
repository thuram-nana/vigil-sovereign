# H3 — field-record runbook (TRUTHENOVATION §4)

> **The honest residual, stated first.** A genuine *field record* — evidence that VIGIL finds real bugs on
> **diverse, real, authorized targets** — **accrues only over real authorized engagements**. It is **not
> manufacturable in a lab**, and no amount of code makes it true. This document does NOT claim a field
> record exists. It defines the **mechanism** VIGIL ships to *accrue* one honestly, and the exact bar an
> entry must clear to count. Until entries accrue, the honest state is: *the deterministic-scanner recall is
> MEASURED on a planted corpus (M1); LLM-`engage` recall on diverse real targets is the open piece.*

## What is BUILT (the mechanism)

H3's shippable mechanism is **the M1 recall harness + this runbook** — not a field record.

- **M1 recall harness** (`engine/crucible/framework/v2/eval/recall_baseline.py`): a deterministic, signed,
  offline-verifiable recall/precision/FN measurement of the **deterministic scanner** over a **planted
  loopback corpus**, with a committed accuracy-core baseline
  (`eval/baselines/recall-accuracy-core.json`) and a recall-floor gate (`eval/gate.py`, CI-gated). This is
  a **MEASURED** number — but its scope is the *deterministic scanner* on a *planted* corpus. See
  `docs/TRUTHENOVATION.md` (Truth 1 / M1).
- **Per-finding provenance**: every confirmed finding already retains a signed, replayable
  `oracle_context` (evidence layer) and, for hand-off, a reproducible **external-audit package** (H4,
  `evidence/audit_package.py`). These are the *units* a field record is assembled from.

## What a field-record ENTRY must clear to count (the honesty bar)

An engagement contributes to the field record **only** when all of the following hold. Anything short of
this is logged as a run, not as field evidence.

1. **Authorized + in-scope.** A signed engagement charter names the target and scope; the run stayed inside
   it. (No charter → not an entry, full stop.)
2. **Real, external target — not a plant.** The target was NOT constructed by us to contain the bug. A
   loopback/testbed run belongs to M1's *planted* corpus, never to the field record.
3. **Oracle-confirmed.** Each cited finding fired a deterministic oracle over real captured bytes (the
   oracle is the sole authority — an LLM lead alone never counts).
4. **Independently re-verifiable.** The finding ships as an H4 audit package whose `verify_offline.py`
   re-verifies SOUND offline (authenticity + binding + integrity + chain) AND whose oracle **reproduces**
   via `python3 -m framework.v2 evidence verify`.
5. **Outcome recorded honestly, both ways.** Record confirmed findings **and** what was missed when a miss
   later surfaced (a false negative is field data too — recall is only honest if misses are counted).
6. **PII/secret-minimized.** Only the minimum bytes needed to prove impact are retained; the rest is
   redacted before the entry is stored (constitution §II / §VII).

## Runbook — accruing an entry

1. Run the authorized engagement (`vigil engage …`) under its charter.
2. For each oracle-confirmed finding, build the reproducible audit package:
   `build_audit_package(out, findings=[…], signers=…, trust_root=…, evidence_root=…, scope=…, charter=…)`.
3. Re-verify it yourself, both layers:
   - offline, no VIGIL: `python3 verify_offline.py --package . --trust-root-fingerprint <pinned>`
   - reproduction: `python3 -m framework.v2 evidence verify --report reverifiable.json --bundle . …`
4. Append an entry to the field-record ledger with: target class (not identity, if the operator requires
   anonymization), charter reference, finding class(es), the package fingerprint, and the outcome
   (confirmed / later-found-missed). Keep it signed and append-only alongside the engagement's evidence
   chain.
5. Periodically re-run M1 to keep the planted-corpus recall number current, and state the field record and
   the planted-corpus number **separately** — they measure different things.

## The residual (unchanged, and irreducible)

- A field record is a **social/operational fact that accrues over time on real targets**, not a software
  artifact. The mechanism above lets it accrue *honestly*; it does not create it.
- Until a diverse body of entries exists, VIGIL claims **only** what M1 measures (deterministic-scanner
  recall on a planted corpus) and states LLM-`engage` recall on diverse real targets as the **open piece**.
- Do not word an accruing field record as completeness: even a strong record is *soundness evidence over
  the targets seen*, never proof that no bug was missed on targets not yet tested.
