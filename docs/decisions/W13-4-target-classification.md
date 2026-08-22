# W13-4 — target classification + a registered-asset store where UNKNOWN is never AUTHORIZED

Issue: [#497](https://github.com/thuram-nana/vigil-sovereign/issues/497) ·
Milestone: W13 — SOVEREIGN CONTROL PLANE (ANTIC programme) · Blocked by [W13-2] #495.

## The claim (register in the claims registry, [W0-3] #398)

> VIGIL classifies every target into a `TargetClass` taxonomy (`LOOPBACK`, `PRIVATE_NETWORK`, `OWN_INFRA`,
> `AUTHORIZED_THIRD_PARTY`, `PUBLIC_INTERNET`, `CRITICAL_INFRASTRUCTURE`, `OUT_OF_SCOPE`, and `UNKNOWN`) and
> resolves it through a registered-asset store keyed by normalized target, falling back to the **signed
> charter scope** as the source of truth. `UNKNOWN` is **never AUTHORIZED**: a target that is neither a
> registered asset nor in the charter scope resolves to `UNKNOWN` and is refused — it is never *defaulted*
> to authorized. The classification is **bound into the EXISTING gate decision** as the first leg of the
> `sovereign_bridge` facade (on by default), not a second policy engine: it only *reads* the asset store and
> the charter-scope predicate the caller derived from the signed authority, and the same downstream
> authority / WARDEN / sovereignty / entitlement gates still run. The registered-asset store **automates**
> authorization for owned targets without bypassing any gate. Deployment modes (`LOCAL_OFFLINE`,
> `LOCAL_LAB`, `STAGING`, `PRODUCTION`, `REVIEWER`) are enumerated. It is **fail-closed**: an
> empty/unparseable target, a raising scope predicate, and every non-authorized class are refused.

This claim is TRUE of the code as of W13-4:

- **The taxonomy + classifier** — `packages/core/vigil_core/vigil_core/target_classification.py`.
  `TargetClass` is the eight-value taxonomy; `AUTHORIZED_CLASSES` is the frozenset of the four owned/
  authorized classes (a single auditable membership predicate, `is_authorized()`); `classify_target()`
  resolves a target fail-closed: unparseable → `UNKNOWN`; registered → the registered class; in charter
  scope → a network-derived owned class; otherwise → `UNKNOWN`. It is a stdlib-only leaf (it reuses the
  sibling `hard_guardrail.normalize_domain`), so it loads in BOTH trust domains like `vigil_core.gate`.
- **UNKNOWN is never AUTHORIZED** — asserted directly (`is_authorized(TargetClass.UNKNOWN) is False`) and
  structurally (`AUTHORIZED_CLASSES` contains exactly the four owned classes) in
  `packages/core/vigil_core/tests/test_target_classification.py`.
- **The registered-asset store** — `RegisteredAssetStore`, keyed by `normalize_target()` (WHATWG host, port
  stripped, IP literals canonicalized), so `https://Host:8080/x` and `host` are the same asset. Registration
  can DENY as well as authorize: registering a target `OUT_OF_SCOPE` refuses it even under a permissive
  scope predicate (the negative control).
- **Bound into the existing gate decision, not a new one** — `build_offense_bridge()` prepends a
  `Gate("classification", …)` leg (on by default via `include_classification`). Its `in_scope` predicate is
  derived from the SIGNED charter scope via the EXISTING `framework...host_matches_scope` over the verified
  authority — the source of truth, not a re-implementation. `test_target_classification_gate.py` proves an
  `UNKNOWN` target is refused through the facade (attributed to `classification`), a registered asset is
  allowed AND the downstream authority gate is still traversed (a spy authority records the call), and a
  registered `OUT_OF_SCOPE` target is refused with a permissive scope.
- **No bypass flag** — turning the leg off is chain COMPOSITION at build time (`include_classification=False`
  isolates a downstream leg), never a per-request field; there is no runtime flag that authorizes an
  `UNKNOWN` target.
- **Deployment modes** — `DeploymentMode` enumerates `LOCAL_OFFLINE`, `LOCAL_LAB`, `STAGING`, `PRODUCTION`,
  `REVIEWER`; each has a test.

## The test that fails without this change (observed, not assumed)

`packages/core/vigil_core/tests/test_target_classification.py` imports `vigil_core.target_classification` at
module scope. On a tree without W13-4 that module does not exist, so the whole file ERRORs at collection.
Observed on this very tree by moving the module aside:

```
$ mv packages/core/vigil_core/vigil_core/target_classification.py /tmp/ ; \
  PYTHONPATH=packages/core/vigil_core .venv-sovereign/bin/python -m pytest -q \
    packages/core/vigil_core/tests/test_target_classification.py
E   ModuleNotFoundError: No module named 'vigil_core.target_classification'
!!!!!!!!!!!!!!!!!!!! Interrupted: 1 error during collection !!!!!!!!!!!!!!!!!!!!
1 error in 0.28s
```

Restoring the module returns the suite to green (22 passed).

## Where the tests run — a required CI job

- `packages/core/vigil_core/tests/test_target_classification.py` runs in the **required**
  `vigil_core — shared integrity substrate` job (`pytest packages/core/vigil_core/tests -q`).
- `integration/tests/test_target_classification_gate.py` is framework-free and runs in the SOVEREIGN leg of
  the **required** `integration two-env boundary (P5)` job (it is collected by that leg's
  `pytest integration/tests` run; it imports no `framework`, so the offense-leg guard does not apply to it).

## FATAL-2 (the two-env boundary)

`target_classification` is stdlib-only, so it loads in both processes. `build_offense_bridge` still imports
`framework` lazily (the classification leg's default scope predicate loads the verified authority inside a
closure). `test_target_classification_gate.py::test_classifier_and_facade_import_is_two_env_clean` re-proves
in an isolated subprocess that importing the classifier and the facade pulls in neither `framework`, `strix`,
nor `sigil`.

## Scope of this slice (blocking_work)

`RegisteredAssetStore` is an in-memory store hydrated from an explicit registration list (e.g. the signed
charter scope + a deployment's asset manifest). A DURABLE, signed-and-hash-chained on-disk asset store is
tracked as follow-up work; the classifier + the `UNKNOWN`-deny decision over the existing scope gate — the
safety-critical half named as the acceptable minimum in #497 — are implemented here now. Related: [W16-19]
#525 wires the categorical guardrail to a live call site (`build_offense_bridge` defaults the leg on, so a
call site inherits it).

> **Registration:** fold this claim into the claims registry when [W0-3] #398 lands; until then this decision
> record is the source of truth for the claim.
