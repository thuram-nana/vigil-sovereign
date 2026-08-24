# W13-3 — the signed EngagementAuthorization is the third leg, and the executor honours all four of its bounds

Issue: [#496](https://github.com/thuram-nana/vigil-sovereign/issues/496) ·
Milestone: W13 — SOVEREIGN CONTROL PLANE (ANTIC programme) · Blocked by [W13-2] #495.

## The claim (registered in the claims registry — [W0-3] #398, id `W13-3`)

<!-- CLAIM:W13-3 -->
> **Registered claim (W0-3 #398):** A threshold-signed EngagementAuthorization carries four enforcement bounds — a WARDEN danger ceiling, a validity window, a rate limit, and a concurrency limit — and the EngagementExecutor HONOURS all four: an action above the ceiling, outside the window, beyond the rate, or beyond the concurrency limit is refused with a distinct typed EthicsViolation (DangerCeilingExceeded / AuthorityExpired / RateLimitExceeded / ConcurrencyLimitExceeded), first-failure-wins and fail-closed. The danger ceiling reuses the ONE WARDEN classifier of record (no second danger taxonomy) and the signature reuses the entitlement layer's m-of-n threshold crypto and TrustRoot. The three legs of an engagement's authorization — the authorization-letter template (contract), the charter.md scope table (runtime), and the signed object (technical) — are cross-checked against each other on BOTH halves of the authorization: the in-scope host set (ScopeDrift on any divergence) AND the enforcement envelope — danger ceiling, validity window, rate, and concurrency, which the letter declares in a machine-checked ENVELOPE block compared field-by-field to the signed object (EnvelopeDrift on any mismatch); a missing or unparseable declaration or any empty leg is itself drift (fail-closed). The deployment class and lifecycle EXTEND the entitlement layer with NO duplicated capability policy: a signed DeploymentProfile reuses the one DeploymentMode taxonomy, names the entitlement it governs, and adds only a lifecycle gate (require_operable_deployment refuses any non-ACTIVE deployment), while WHICH capabilities may run stays the decision of entitlement.require_capability(). Enforcement at the executor is OPT-IN at this stage: the EngagementExecutor honours the four bounds wherever it is used, and threading it through every production caller so a production deployment REQUIRES it on every action is named follow-on work.

## Why this exists

An engagement's authorization has three legs. Two of them already existed as artifacts:

- the **contract** leg — the authorization *letter* the customer signs; and
- the **runtime** leg — the `charter.md` scope table the engine reads at gate time
  (`common.ethics.parse_scope`).

The **technical** leg — a machine-verifiable, threshold-signed object the executor can honour
byte-for-byte, and against which the other two are cross-checked — was missing. Contract, runtime,
and technical scope could therefore drift apart with nothing to catch it. This slice adds that third
leg and the cross-check that binds all three.

## This is NOT a second policy engine (the programme's HARD CONSTRAINT)

The `sovereign_bridge` discipline: the new objects add no parallel policy decision point.

- The **danger ceiling** is expressed in, and compared against, the ONE WARDEN classifier of record
  (`vigil_core.warden_tiers.classify` / `Tier`). There is no new danger taxonomy — an action's tier
  comes from the same classifier the kernel and the offense gate use.
- The **signature** reuses the entitlement layer's Ed25519 m-of-n threshold crypto and the SAME
  governance `TrustRoot` that signs entitlements and engagement authorities, with its own
  domain-separation tag so an authorization signature can never be replayed as any other kind.
- The **deployment class + lifecycle** EXTEND `entitlement/` and duplicate no policy: a
  `DeploymentProfile` reuses `vigil_core.target_classification.DeploymentMode` (re-exported as
  `DeploymentClass`, not re-minted), references the entitlement it governs by `entitlement_id`, and
  adds only a lifecycle gate. WHICH capabilities a deployment may run remains
  `entitlement.require_capability()`'s decision — composition (lifecycle ∧ capability), never a copy.

## The four bounds and their three mandatory negative controls

`authorize_engagement_action` (the pure gate) and `EngagementExecutor` (which tracks the sliding rate
window and the in-flight count) enforce, first-failure-wins:

1. **validity window** — an action before `not_before` or after `not_after` is refused (`expired`).
2. **danger ceiling** — an action whose WARDEN tier exceeds the ceiling is refused (`above_ceiling`).
3. **rate limit** — an action beyond `rate_limit` within `rate_window_seconds` is refused (`rate_limited`).
4. **concurrency limit** — an action beyond `concurrency_limit` in flight is refused (`concurrency_limited`).

The AC's three mandatory negative controls (an action outside the window, above the ceiling, or beyond
the rate limit is refused) are three separate assertions in
`framework/v2/authority/tests/test_engagement_authorization.py`, each paired with a positive control so
the gate is provably not a no-op (`test_ceiling_gate_is_not_a_no_op` proves the ceiling comparison
actually reads the ceiling: the same A2 action is refused under an A1 ceiling and allowed under an A2
ceiling). The fourth bound (concurrency) has its own negative control.

## The three-leg cross-check — scope AND envelope

Scope (WHICH hosts) is only half the authorization; the other half is the enforcement ENVELOPE (how
dangerous, how long, how fast, how many at once). `authority.crosscheck` checks **both**.

**Scope.** It extracts the in-scope host set from each leg — the letter (via `parse_scope_table`), the
charter (via `common.ethics.parse_scope`), and the signed object's `scope` list — normalises them and
requires all three to be identical. Any host present in one leg but missing from another is drift;
`assert_scope_consistent` raises `ScopeDrift`. An empty leg fails closed (an authorization that scopes
nothing cannot vacuously "agree" with another empty leg). The letter and the charter share the same
`## 2. In-scope systems` table format, parsed by the same row logic, so the two documents cannot express
scope in ways that only look equivalent; a shipped-template test pins that both templates keep that
header.

**Envelope.** The authorization letter declares its enforcement envelope in a machine-checked
`<!-- ENVELOPE:BEGIN -->…<!-- ENVELOPE:END -->` block (the human-readable §3 table is for the reader;
this block is what is compared). `parse_envelope_declaration` reads it, and `crosscheck_envelope` /
`assert_envelope_consistent` compare the letter's declared danger ceiling, both window endpoints, rate
limit + window, and concurrency limit **field-by-field** against the signed `EngagementAuthorization`,
raising `EnvelopeDrift` on any mismatch. This closes the gap where a customer could sign a tight envelope
(e.g. ceiling A1) while the signed object the executor honours carries a looser one (e.g. A3) — the exact
case `test_negative_control_letter_ceiling_A1_signed_A3_is_drift` pins. A **missing or unparseable**
declaration is itself drift (fail closed): a letter that omits the envelope, or the shipped template
whose values are still placeholders, cannot silently agree with any signed object.

## Where it is TRUE of the code

- **The signed object + executor** — `engine/crucible/framework/v2/authority/authorization.py`:
  `EngagementAuthorization` (the four bounds + scope), `SignedEngagementAuthorization`,
  `authorization_signing_bytes` (own domain tag), `sign_authorization` / `verify_authorization` (reuse
  the entitlement crypto), `authorize_engagement_action` (the pure four-bound gate), and
  `EngagementExecutor` (honours the bounds, tracking rate + concurrency state).
- **The three-leg cross-check (scope + envelope)** — `engine/crucible/framework/v2/authority/crosscheck.py`:
  `parse_scope_table`, `crosscheck_scope`, `assert_scope_consistent` (scope); `parse_envelope_declaration`,
  `crosscheck_envelope`, `assert_envelope_consistent` (envelope → `EnvelopeDrift`).
- **The deployment extension** — `engine/crucible/framework/v2/entitlement/deployment.py`:
  `DeploymentClass` (re-export), `DeploymentLifecycle`, `DeploymentProfileDocument`,
  `SignedDeploymentProfile`, `sign_deployment_profile` / `verify_deployment_profile`,
  `is_operable`, `require_operable_deployment`.
- **The letter template** — `engine/crucible/framework/templates/authorization-letter.md`.
- **Proof** — `framework/v2/authority/tests/test_engagement_authorization.py`,
  `framework/v2/authority/tests/test_authorization_crosscheck.py`,
  `framework/v2/entitlement/tests/test_deployment.py`.

## The test that fails without this change (observed, not assumed)

The three test files import `..authorization`, `..crosscheck`, and `..deployment` at module scope; on a
tree without W13-3 those modules do not exist and the files ERROR at collection. Observed on this very
tree by moving the modules aside:

```
$ mv framework/v2/authority/authorization.py framework/v2/authority/crosscheck.py \
     framework/v2/entitlement/deployment.py /tmp/ ; \
  PYTHONPATH=.:../../packages/core/vigil_core python3 -m pytest -q \
    framework/v2/authority/tests/test_engagement_authorization.py \
    framework/v2/entitlement/tests/test_deployment.py
E   ModuleNotFoundError: No module named 'framework.v2.entitlement.deployment'
```

Restoring the modules returns the suites to green (51 passed across the three files).

## Where the tests run — a required CI job

All three test files live under `engine/crucible/framework/v2/{authority,entitlement}/tests/`, executed
wholesale by the **required** check `CRUCIBLE core on vigil_core` (`pytest framework/v2` from
`engine/crucible`; `required-status-checks.txt`). They import no `integration`/`framework`-crossing
module, so no offense-leg listing is needed.

## Residual / follow-on (honest)

- **Making the executor MANDATORY on every action path.** The `EngagementExecutor` honours the four
  bounds wherever it is used; threading it through every production action caller — and a
  production-posture flag that makes an un-authorized action a refusal — is follow-on, exactly as
  W13-5's capability-token enforcement is opt-in at its stage. This is stated in the claim, not hidden.
- **A durable, signed on-disk store for the authorization + deployment profile** (mirroring the
  entitlement store) is follow-on; this slice ships the objects, their signing/verification, the
  executor, and the cross-check.
