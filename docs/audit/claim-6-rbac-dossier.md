# Claim 6 — Enforced Multi-User RBAC: Audit Dossier

> **Audience.** A third-party security auditor or a governance reviewer evaluating whether VIGIL's
> multi-user access-control claim is real, and how far it reaches. Every capability below is written to be
> **independently verifiable** — each section names the file, the test, or the command that proves it, and
> each honest limit is stated plainly rather than implied. This dossier makes no claim the code does not
> enforce; where a control is a foundation with residuals, it says so.

- **Subject:** Claim 6 — *enforced* multi-user role-based access control, plus the operational-integrity
  hardening that a production multi-user deployment depends on.
- **Primary design reference:** [`docs/CLAIM-6-RBAC.md`](../CLAIM-6-RBAC.md) (the design-invariant record).
- **Companion:** [`docs/pilot/claim-6-pilot-runbook.md`](../pilot/claim-6-pilot-runbook.md) — how to run a
  controlled multi-user pilot and reproduce the evidence.
- **Trust-root posture:** VIGIL remains **single-owner-key at the trust root**. RBAC is an *admission gate*
  in front of the owner-signing funnel — not a second key custody. This is a deliberate design choice, not
  a gap; see [§3](#3-trust-model--admission-not-custody).

---

## 1. What Claim 6 delivers (in one paragraph)

A non-owner user can be issued a bearer credential bound to a role (`viewer ⊂ analyst ⊂ operator`), and the
server enforces a role→permission check **before** it signs anything on that user's behalf. The owner
Ed25519 key stays the sole signer of every governance mutation; a viewer's request never produces an owner
signature because the admission check refuses first. Accounts are **owner-signed, append-only spine
grants** with per-username anti-replay, so a revoked account cannot be resurrected by replaying a captured
grant. The same enforcement now extends to the shareable command UI: the `vigil up` reverse proxy
authenticates every forwarded request per-user (fail-closed), and the owner credential it holds for the
offense backend never reaches the browser.

---

## 2. Scope of this dossier

**In scope (audited here):**

| Area | Where it lives |
|---|---|
| Role/permission model + enforcement hooks | `apps/sigil/sigil/governor/accounts.py`, `ui/actions.py` |
| Owner-signed account grants + anti-replay LWW | `governor/accounts.py` (`SIGNAL="governor.account"`) |
| Per-user command-UI boundary | `integration/vigil_integration/uiproxy.py` (PR #377) |
| Protected-domain safety guard (Claim 5) | `packages/core/vigil_core/vigil_core/hard_guardrail.py` |
| Operational integrity (fireteam replay, model sovereignty, signed floors, off-host backup) | PRs #373–#376 |

**Explicitly out of scope / deferred** (stated up front so this dossier cannot be read as claiming them —
see [§9](#9-honest-limitations--residuals)): SSO/OIDC/MFA/password flows; cryptographic per-user identities
(bearer tokens are the foundation); per-action RBAC *inside* the offense console; comprehensive per-button
gating on every screen; **synchronous multi-writer high availability of the sovereign spine** (an
**active-passive** failover profile with a witnessed-floor interlock *is* built — see [§9](#9-honest-limitations--residuals)
and `docs/architecture/HA-PROFILE.md`; synchronous multi-writer HA of a single-owner signed spine is a
detectable fork, not a missing feature).

---

## 3. Trust model — admission, not custody

The single most important property for an auditor to internalize:

- **The owner Ed25519 key (`governor/identity.py`) is the sole signer** of every governance mutation. A
  non-owner user never holds a key.
- **RBAC gates admission, not key access.** The permission check happens in `ui/actions.py::do_action`
  **before** `ensure_owner_keypair()` signs. An operator-approved ≤A2 action is signed by the *owner* key
  with the operator recorded as `approver`/`requested_by` — proving the role gated admission, not custody.
- **Accounts are owner-signed spine grants**, reusing the existing killswitch/capability/promotion
  governance-record idiom (`signed_payload`/`verify_signed`). No new trust primitive was introduced; a
  forged or unsigned grant never verifies in the fold.
- **Asymmetric authorization.** `create`/`assign_role` (the dangerous direction) are honored only if
  **owner-signed AND** their `issued_at` strictly exceeds the per-username high-water. `revoke` (the safe
  direction) is honored even unsigned, with `issued_at` fixed at `0.0` — you can always turn a user off.

*Auditor's takeaway:* the blast radius of the RBAC layer is bounded by design. Compromising a non-owner
bearer yields that user's role and nothing more; it cannot mint, escalate, or forge a governance signature.
The residual trust roots are the owner key and the local accounts store — unchanged by this claim, and
called out in [§9](#9-honest-limitations--residuals).

---

## 4. The RBAC model

### 4.1 Roles (cumulative)

`viewer ⊂ analyst ⊂ operator ⊂ owner`. **`owner` is not a grantable bearer role** — it is the trust root,
reached only by the owner key / the legacy owner shared token.

| role | adds |
|------|------|
| viewer | `read` |
| analyst | `queue_proposal` |
| operator | `run_engagement`, `approve_a2`, `toggle_guard`, `config_nonsecret` |
| owner | `approve_a3`, `kill_release`, `promote`, `secrets`, `offense_authority`, `manage_users`, `toggle_protected_guard` |

### 4.2 Enforcement hooks (control point → required permission)

The load-bearing subset (full table in [`docs/CLAIM-6-RBAC.md`](../CLAIM-6-RBAC.md)):

| control point | required |
|---|---|
| `do_action` (all mutations) | per-action (`PERMISSION_BY_ACTION`; **default-deny** — an unmapped action refuses) |
| kill-switch `release` | `kill_release` (owner) |
| `promote` / `revoke` promotion | `promote` (owner) |
| `set_secret` / `check_secret` | `secrets` (owner) |
| `offense_bind_authority` / `offense_approve` / `offense_deny` | `offense_authority` (owner) |
| approval resolve ≤A2 / A3 | `approve_a2` (operator+) / `approve_a3` (owner) |
| `create_account` / `assign_role` / `revoke_account` | `manage_users` (owner) |
| `set_config` where env is `VIGIL_ALLOW_PROTECTED_DOMAINS` | **`toggle_protected_guard` (owner-only)** |
| HTTP reads (`GET /api/*`) | authenticated (viewer+) |

*Verify:* the negative controls in the sovereign RBAC suite assert that a viewer/analyst/operator bearer is
refused the actions above its role, and that an unmapped action default-denies.

---

## 5. The command-UI boundary (`vigil up` / uiproxy) — PR #377

The `vigil up` reverse proxy is the single listener a browser points at. Claim 6 makes it a **per-user
authentication boundary** so the command UI is safely shareable. Four properties an auditor should check:

1. **No embedded owner credential.** `assemble_serve_dir` no longer writes the owner token into
   `index.html`; the served page carries no credential. The real entry is the SPA login gate
   (`POST /sovereign/api/login`), and the per-user bearer lives in `sessionStorage`.
2. **Every forwarded request is authenticated, fail-closed.** Past a tiny bootstrap allowlist
   (`/sovereign/api/whoami`, `/sovereign/api/login`), every `/sovereign/*` and `/offense/*` request must
   carry a bearer that resolves to a Principal — else **401, never forwarded**. Malformed/5xx/`authenticated:false`
   whoami, and blank/unknown bearers, all resolve to 401 (the proxy fails closed).
3. **Verification delegates to the authority, staying FATAL-2-clean.** The offense-side proxy must not
   import the sovereign `AccountsRegistry`. It delegates a loopback `GET 127.0.0.1:8733/api/whoami` carrying
   the bearer, trusting the plane that actually owns the owner-signed accounts spine. The proxy is pure
   stdlib (verified by `test_control_plane_boundary.py::test_uiproxy_is_pure_stdlib` and a subprocess
   FATAL-2 check).
4. **The owner credential is hop-only, enforced on the response.** After authenticating a request the proxy
   substitutes the offense console credential on the outbound hop, and **redacts that credential out of
   every relayed non-SSE response body** — because a backend serves its own token-embedding static index at
   `/`, and a plain relay would hand a mere viewer `data-token="<owner token>"` to replay as owner
   (RED-PEN BLOCK-1). The redactor scans cleartext, which the proxy guarantees by forcing
   `Accept-Encoding: identity` on the hop and, defense-in-depth, decoding a compressed body before scanning
   or failing closed (502) — with the decompression-bomb bound enforced *during* streaming inflate, not
   post-hoc (RED-PEN BLOCK-A + re-check).

*This boundary was hardened through three adversarial red-pen passes; see [§8](#8-assurance-process).*

---

## 6. The protected-domain safety guard (Claim 5) — a GLOBAL toggle, stated accurately

This section corrects a common misreading. The protected-domain guard is **not** a per-host, per-target
signed exception (e.g. "allow one `.gov.cm` host"). It is a **single global toggle**:

- **Mechanism.** `packages/core/vigil_core/vigil_core/hard_guardrail.py::protected_guard_enabled()` reads one
  environment variable, `VIGIL_ALLOW_PROTECTED_DOMAINS`. When it is **unset, empty, whitespace, or any
  non-affirmative value**, the guard is **ACTIVE** — the categorical `.gov` / `.gov.<cc>` / `.mil` / `.edu` /
  `.int` (+ IGO) pre-filter is enforced. The **only** OFF state is an explicit affirmative
  (`1`/`true`/`yes`/`on`, case/space-insensitive). It is **fail-safe ON**.
- **Scope of the toggle.** Turning it off lifts the categorical pre-filter for **all** protected classes at
  once — it is not scoped to a single domain or target. It is written **owner-signed** via
  `settings.set_config` and is **owner-only** to change (`toggle_protected_guard`); an operator cannot turn
  it off (negative control in the RBAC suite).
- **What it does *not* relax.** The toggle governs a **defense-in-depth pre-filter only**. The signed
  charter authority scope and the never-liftable egress floor remain in force **regardless** of the flag
  (see the `protected_guard_enabled` docstring, verbatim). Turning the pre-filter off does not authorize
  any target the charter does not already authorize, and does not open egress.

*Auditor's takeaway:* the guard is a coarse, categorical, owner-controlled, fail-safe-on pre-filter — a
belt over the suspenders of charter scope + egress floor. It is honest to describe it as such, and dishonest
to describe it as a fine-grained per-host exception mechanism, which it is not.

---

## 7. Operational integrity delivered alongside Claim 6

A multi-user production deployment depends on operational-integrity properties beyond the access model. The
following were built, adversarially reviewed, and merged as part of this work:

| # | Property | PR | One-line assurance |
|---|---|---|---|
| 1 | **Signed, atomic fireteam-escalation resolver** | #373 | A durable escalation approval is a *signed* object verified against a **pinned** approver key on replay, resolved via an O_EXCL atomic compare-and-set — a raw unsigned `approved:true` ledger line can no longer forge an approval. |
| 2 | **Per-session model sovereignty into Strix** | #374 | The chosen model/endpoint is pinned per session on **both** the launch and retry spawn paths; a "local" session cannot silently egress to a cloud model. |
| 3 | **Mandatory signed high-water floors (strict profile)** | #375 | In the strict production profile, an unsigned or stripped-to-unsigned high-water floor is **rejected**, not silently accepted. |
| 4 | **True off-host backup + staged unit-scoped restore + drills** | #376 | Encrypted, governance-signed, push-to-off-host backup; restore is staged + re-verified + swapped atomically, and a `--force` restore replaces **only** the captured units — it never deletes live, un-captured data (the CRUCIBLE code, sigil caches). Ciphertext-only push; automated recovery drill. |
| 5 | **Per-user command-UI authentication** | #377 | [§5](#5-the-command-ui-boundary-vigil-up--uiproxy--pr-377) above. |

Each of these closed a **verified, reproduced** defect (not a hypothetical). The forgeable-fireteam-replay,
the silent model egress, the strip-to-unsigned floor, the destructive `--force` blast radius, and the
viewer→owner token leak were each demonstrated against the real code before the fix, then re-verified closed.

---

## 8. Assurance process

Every slice in this work followed the same discipline, and an auditor can weigh the *process* as evidence:

- **Verify-before-fix.** Each reported defect was reproduced against the real code path before a line was
  changed. Reported issues that turned out to be already-mitigated were recorded as such rather than
  "fixed".
- **Adversarial red-pen before merge.** An independent reviewer tried to *break* each slice — construct a
  bypass, find a promoted-past-the-boundary claim, spot a green-washed test. Findings blocked the merge.
  This process caught, among others: the destructive `--force` blast radius (#376); the viewer→owner token
  leak, the gzip-blind redaction, and the unbounded decompression-bomb (#377). Each was fixed and
  **re-verified** — no fix was trusted on first green.
- **Honesty re-checks.** Where a fix's *documentation* overclaimed (e.g. "never deletes un-captured data"
  while a wholesale subtree swap does drop post-backup runs; an "unconditional" redaction invariant that a
  compressed body defeated), the overclaim itself was treated as a blocking finding and corrected to match
  what the code enforces.
- **Two-env boundary (FATAL-2) preserved.** The offense interpreter never co-loads a sovereign module;
  cross-plane trust flows over loopback HTTP / signed spine / subprocess, never a shared import — asserted
  by boundary tests.

---

## 9. Honest limitations & residuals

Stated plainly, because an assurance document that hides its edges is worthless:

- **Bearer tokens, not cryptographic identities.** The per-user credential is a bearer token (salted-hash
  stored, shown once). The stronger replacement — per-user keypairs + proof-of-possession
  (`vigil_core.delegation.DelegationCert` + `WielderProof`) — is the named next step, **not built**.
- **Coarse offense-plane floor.** The command-UI proxy enforces per-user auth + a **coarse** offense floor
  (read vs. `run_engagement`) and forwards `X-VIGIL-Role`, but the offense console does not yet map each of
  its own POST routes to a permission. Fine-grained per-action offense RBAC is the seam left open, **not
  built**. Owner-authority offense actions remain sovereign-gated.
- **Revocation lag.** A revoked bearer stays valid for at most the auth-cache TTL (≤30 s), and an
  already-open SSE stream is authenticated only at connect.
- **The proxy is a loopback / private-VIP listener, not a hardened public gateway.** Front it with the
  operator's TLS edge. It is not designed to be exposed raw to the public internet.
- **Single owner key / local accounts store are the residual trust roots.** A compromised owner key or a
  locally-writable accounts store is the pre-existing residual, unchanged by this claim.
- **No per-screen permission on all 30 screens.** Nav visibility + enforcement at the enumerated
  load-bearing actions + a demonstrated per-button gate exist; the **server is the enforcement of record**
  (every mutation is re-checked and 403s), but comprehensive per-button gating is not done.
- **Hard-prune fold.** The accounts fold is a genesis scan; a future cold-archive prune must extend the
  snapshot with an accounts seed + referential-floor assert.
- **Active-passive HA only — NOT synchronous multi-writer HA.** An active-passive failover profile *is* built
  (`docs/architecture/HA-PROFILE.md`, `infra/ha/`): the stateless proxy/otel tier is active-active, and the
  single-writer sovereign spine gets an **anti-rollback-safe** failover via a **witnessed-floor interlock**
  (`tools/ha/spine_failover_guard.py` / `sigil floor promote-passive`) that refuses to promote a stale, forged,
  or forked mirror. Honest limits, by construction: the spine is **single-writer** (a second concurrent writer
  is a *detectable fork*, not scale — HA-PROFILE.md §2), so there is **no automatic leader-election** —
  promotion requires the witnessed-floor check *plus* a **manual fence** of the old active; the passive holds an
  **out-of-band** mirror of `~/.sigil` (a signed-backup seed + `tools/ha/mirror-sync.sh` rsync delta), **not**
  synchronous replication; and witnesses remain **independent trust nodes, not failover**. Stateful backends
  (Neo4j community, embedded Qdrant) are **not** clustered — the profile documents the enterprise/server-mode
  upgrades and ships neither.
- **SSO / OIDC / MFA / password flows.** Not in scope.

---

## 10. Auditor's independent-verification checklist

Each row is a claim in this dossier and the concrete way to confirm it yourself (see the pilot runbook for
step-by-step commands):

| # | Claim | How to independently verify |
|---|---|---|
| 1 | A non-owner bearer cannot perform an above-role action | Provision a `viewer`; attempt an operator/owner action via the API → expect 403. |
| 2 | A revoked account cannot be replayed back | Create → revoke → replay the captured `active` grant → `resolve()` still denies. |
| 3 | The owner credential never reaches the browser via the proxy | As a `viewer`, `GET /offense/` through `vigil up`; grep the response body for the owner token → absent (redacted). |
| 4 | A compressed backend body cannot smuggle the credential | Point the proxy at a gzip-emitting backend; confirm the browser body carries no token (identity forced / decoded-then-redacted / 502). |
| 5 | The protected-domain guard is fail-safe ON and owner-only OFF | Unset `VIGIL_ALLOW_PROTECTED_DOMAINS` → guard active; try to toggle it as an operator → refused. |
| 6 | A `--force` restore does not delete un-captured data | Populate a crucible root with a non-captured file; `vigil restore --force`; confirm the file survives. |
| 7 | A fireteam approval cannot be forged in the ledger | Append a raw unsigned `approved:true` line; confirm replay does not resolve it as approved. |
| 8 | The offense interpreter loads no sovereign module | Run the FATAL-2 boundary test (subprocess `sys.modules` check). |

*Reproduction commands for rows 1–8 are in [`docs/pilot/claim-6-pilot-runbook.md`](../pilot/claim-6-pilot-runbook.md).*
