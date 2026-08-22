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
| Per-action offense-console RBAC (proxy-stamped HMAC hop-assertion) | `packages/core/vigil_core/vigil_core/rbac.py` (`OFFENSE_ACTION_PERM`/`role_can`), `framework/v2/console/server.py` (`_rbac_ok`/`_hop_assertion_valid`), `uiproxy.py` (PR #380) |
| Per-user cryptographic identities (keypair proof-of-possession) | `governor/accounts.py` (`enroll_pubkey`, `user_pubkey`), `ui/server.py` (`/api/login/challenge` + PoP), `ui/login_challenges.py` (PR #382) |
| MFA (TOTP second factor) + optional password login | `governor/totp.py`, `governor/accounts.py` (`enroll_totp`/`set_password`), `ui/server.py` (`/api/login`) (PR #387) |
| OIDC Relying Party — **OFF by default** | `apps/sigil/sigil/ui/oidc.py`, `config.oidc_enabled()`, `docs/OIDC-RP.md` (PR #388) |
| Hard-prune accounts fold | `spine/snapshot.py` (account seed), `governor/accounts.py::_fold`, `spine/prune.py` (referential floor) (PR #381) |
| Protected-domain safety guard (Claim 5) | `packages/core/vigil_core/vigil_core/hard_guardrail.py` |
| Operational integrity (fireteam replay, durable-commit, model sovereignty, signed floors, off-host backup, HA proxy-only, CI coverage guard) | PRs #373–#388 |

**Now built since the first cut of this dossier** (audited here with honest bounds in
[§9](#9-honest-limitations--residuals), not claimed as complete): **per-action RBAC inside the offense
console** (rides a proxy-stamped HMAC hop-assertion; a direct console-token holder is owner-equivalent by
construction); **per-user cryptographic identities** (keypair proof-of-possession — an *additional* login
method; the bearer stays the ongoing carrier); **MFA (TOTP)** + an optional password flow; and an **OIDC
Relying Party that ships DISABLED** (byte-identical when off; role always from an owner-signed grant, never
an OIDC claim).

**Still out of scope / deferred** (stated up front so this dossier cannot be read as claiming them — see
[§9](#9-honest-limitations--residuals)): comprehensive per-button gating on every one of the ~30 screens
(the server is the enforcement of record); the **OIDC UI session-adoption** step (PKCE + state-browser-binding
that a browser landing page needs *before* it may auto-adopt the returned bearer — required follow-on,
`docs/OIDC-RP.md`); and **synchronous multi-writer high availability of the sovereign spine** (an
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
| 2 | **Per-session model sovereignty into Strix** | #374 | A **local** model selection is pinned per session at its loopback endpoint on **both** the launch and retry spawn paths and enforced no-egress — a "local" session cannot silently egress to a cloud model (an indicated-but-unconfirmable pick **refuses** rather than fall back to the cloud default). Honest scope: a **cloud/global** selection uses the global `STRIX_LLM` default (the session's specific cloud model is not separately pinned) — the sovereignty guarantee is *local-never-leaks-to-cloud*, not per-session cloud-model selection. |
| 3 | **Mandatory signed high-water floors (strict profile)** | #375 | In the strict production profile, an unsigned or stripped-to-unsigned high-water floor is **rejected**, not silently accepted. |
| 4 | **True off-host backup + staged unit-scoped restore + drills** | #376 | Encrypted, governance-signed, push-to-off-host backup; restore is staged + re-verified + swapped atomically, and a `--force` restore replaces **only** the captured units — it never deletes live, un-captured data (the CRUCIBLE code, sigil caches). Ciphertext-only push; automated recovery drill. |
| 5 | **Per-user command-UI authentication** | #377 | [§5](#5-the-command-ui-boundary-vigil-up--uiproxy--pr-377) above. |
| 6 | **Per-action offense-console RBAC** | #380 | Every state-changing offense-console POST maps to a permission (`vigil_core.rbac.OFFENSE_ACTION_PERM`; two tiers — operator-tier `run_engagement`, owner-tier `offense_authority`; kill-switch *trip* is read-tier/protective, default-deny for any unmapped route). A proxy-forwarded per-user request carries a **constant-time HMAC hop-assertion** (`_hop_assertion_valid`, method+path+ts-bound) the console verifies before `role_can`; a forged `X-VIGIL-Role: owner` with no valid MAC never lifts the role. |
| 7 | **Hard-prune accounts fold** | #381 | `SnapshotState` now carries an account seed (per-username LWW state + high-water + cred), `_fold` seeds from the committed snapshot before folding the live window, and `spine/prune.py::stranded_active_accounts` fails a prune **closed** if a boundary would orphan an active account's only owner-signed grant. |
| 8 | **Per-user cryptographic identities** | #382 | Owner-bound `user_pubkey` in the conditional signed core (byte-identical grant when absent) + `enroll_pubkey`; `/api/login/challenge` mints a single-use CSPRNG nonce (`ChallengeLedger`, O_EXCL, atomic consume), and `/api/login`'s PoP branch verifies an Ed25519 signature over a domain-tagged challenge, then mints a session bearer. Keypair PoP is an **additional** login method; the bearer remains the ongoing carrier. |
| 9 | **MFA (TOTP) + optional password** | #387 | `governor/totp.py` (stdlib RFC-6238, no third-party dep); the secret is generated once, shown once in an `otpauth://` provisioning URI, and **sealed** via the owner vault before it lands on the spine. A TOTP-enrolled account requires a valid current code at `/api/login` on the session-bootstrapping methods (PoP / password / OIDC), fail-closed; the **bearer** branch is not gated by the enrolment (W17-1 #535 — a bearer is a possession credential and gating it would brick UI login), though a code supplied alongside a bearer is still validated. `set_password` adds an optional weaker salted-scrypt login (`scrypt$…`); keypair PoP stays the stronger path. |
| 10 | **OIDC Relying Party (OFF by default)** | #388 | `ui/oidc.py` + `config.oidc_enabled()`: when off the routes are **not registered** (byte-identical, no egress). When on it verifies `id_token` against JWKS **asymmetric-only** (`alg:none`/HS* are never even implemented — algorithm-confusion defence), enforces iss/aud/exp/iat/nbf and a single-use server `nonce` bound to a single-use `state`, and maps the verified identity to an owner-signed `governor.account` grant — **role from the grant, never a claim**; a verified identity with no owner-signed account is refused. |
| 11 | **Fireteam approval durable-before-actionable** | #384 | An escalation approval is committed durably (with fsync/liveness advisories) **before** it becomes actionable, closing the window where a crash could lose or double-apply a resolution. |
| 12 | **HA proxy-only + NetworkPolicy** | #386 | `vigil up --proxy-only` runs *only* the reverse proxy against configurable remote backends (spawns no sovereign writer), pod-IP-bound (the runtime's `bind_ok` refuses `0.0.0.0`); `infra/ha/k8s/networkpolicy.yaml` restricts the sovereign Service to `app: vigil-proxy` pods — **required, not optional**, because the cockpit serves its own token token-free at `GET /`, so any in-cluster workload reaching it directly could scrape the owner token. |
| 13 | **CI coverage-discovery guard** | #385 | The whole sovereign test directory is run and a guard trips on silently-skipped suites — no test can go dark unnoticed. |

Each of these closed a **verified, reproduced** defect (not a hypothetical) or delivered a named foundation
capability. The forgeable-fireteam-replay, the silent model egress, the strip-to-unsigned floor, the
destructive `--force` blast radius, the viewer→owner token leak, and the direct-to-cockpit owner-token leak
were each demonstrated against the real code before the fix, then re-verified closed.

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

Stated plainly, because an assurance document that hides its edges is worthless. Some items that were
"not built" in the first cut of this dossier are now **delivered** — written here with the honest bound they
carry, never as unqualified wins. The genuine residuals follow.

**Delivered since the first cut — with their honest bounds:**

- **Per-action offense-console RBAC (rides a proxy-stamped HMAC hop-assertion).** The offense console now
  maps each state-changing POST to a permission (`vigil_core.rbac.OFFENSE_ACTION_PERM`; owner-tier
  `offense_authority` on the dangerous host-exec / infra / authority / patch-apply routes, operator-tier
  `run_engagement` on ordinary run/edit/session routes, read-tier on the protective kill-switch *trip*,
  default-deny for any unmapped route). Enforcement (`server.py::_rbac_ok`) turns on a per-request
  **constant-time HMAC** the proxy stamps (`_hop_assertion_valid`, bound to principal+role+method+path+ts
  inside a freshness window). **Honest bound, by construction:** the assertion rides the proxy hop — a client
  that holds the **console token directly** (no role assertion) is treated as **owner-equivalent** and keeps
  full access. This is deliberate (the console token is the offense trust root), not a bypass, but it means
  the per-action gate protects the *proxy-forwarded per-user path*, not a direct console-token holder.
- **Per-user cryptographic identities (keypair proof-of-possession) — an *additional* login method.** An
  owner can bind an Ed25519 `user_pubkey` to an account (`enroll_pubkey`, owner-signed into the account
  grant, byte-identical when absent), and a user can log in by signing a single-use server challenge
  (`/api/login/challenge` → PoP branch of `/api/login`; replay-guarded by an O_EXCL single-use
  `ChallengeLedger`). **Honest bound:** the bearer token remains the ongoing session carrier after login, and
  the trust root is still the **owner-signed grant** — PoP proves possession of an owner-bound key, it does
  not remove the owner from the root.
- **MFA (TOTP) + optional password.** `governor/totp.py` is a stdlib RFC-6238 implementation; the secret is
  generated once, shown once in an `otpauth://` provisioning URI, and **sealed** via the owner vault before it
  is signed into the grant. A TOTP-enrolled account must present a valid current code at `/api/login` on the
  session-bootstrapping methods (PoP / password / OIDC), fail-closed; a stale code is refused. The **bearer**
  branch is not gated by the enrolment (W17-1 #535 — a bearer is a possession credential and gating it would
  brick UI login), though a code supplied alongside a bearer is still validated. `set_password` adds an
  *optional* weaker salted-scrypt password login; keypair PoP remains the stronger path.
- **OIDC Relying Party — ships DISABLED.** `config.oidc_enabled()` defaults **off**, and when off the OIDC
  routes are **not registered at all** — byte-identical to a build without OIDC, no egress. When on, the
  `id_token` is verified against JWKS (**asymmetric algs only**; `alg:none` / HS* are never implemented, an
  algorithm-confusion defence) with iss/aud/exp/iat/nbf + a single-use server `nonce` bound to a single-use
  `state`, and the verified identity is mapped to an owner-signed `governor.account` grant — **the role comes
  from the owner-signed grant, never from an OIDC claim**, and a verified identity with no owner-signed
  account is **refused**. **Honest bounds:** OIDC targets an **operator-run IdP on the private tunnel** — a
  public cloud IdP would break the air-gap; and the RP stops at returning the verified bearer as JSON: a UI
  landing page that auto-adopts that bearer **still needs `state`-browser-binding + PKCE** (see the new
  residual below and `docs/OIDC-RP.md`).
- **Hard-prune accounts fold.** `SnapshotState` now carries an account seed (per-username LWW state +
  high-water + cred), `_fold` seeds from the committed snapshot before folding the live window, and a future
  cold-archive prune is guarded by `spine/prune.py::stranded_active_accounts`, which fails a prune **closed**
  rather than orphan an active account whose only owner-signed grant sits below the boundary.

**Genuine residuals (unchanged — still true):**

- **Single owner key / local accounts store are the residual trust roots.** A compromised owner key or a
  locally-writable accounts store is the pre-existing residual, unchanged by this claim — the deliberate
  admission-not-custody design (see [§3](#3-trust-model--admission-not-custody)).
- **Revocation is immediate at the edge (W9-3/#436).** An edge revocation set is consulted on every decision
  before the bearer cache is trusted (fail-closed), the owner-only admin force-purge endpoint
  (`POST /__vigil/plane/auth/purge`, gated on `manage_users`) drops the cache entry on revoke, and a
  long-lived SSE stream is re-authenticated at most every ≤15 s and torn down at the next interval once the
  bearer no longer resolves. *Residual:* absent an explicit edge force-purge, a bearer already cached at the
  proxy stays valid until its ≤30 s cache entry expires (then whoami, which already denies a revoked account,
  is re-consulted).
- **The proxy is a loopback / private-VIP listener, not a hardened public gateway.** Front it with the
  operator's TLS edge. It is not designed to be exposed raw to the public internet.
- **No per-screen permission on all ~30 screens.** Nav visibility + enforcement at the enumerated
  load-bearing actions + a demonstrated per-button gate exist; the **server is the enforcement of record**
  (every mutation is re-checked and 403s), but comprehensive per-button gating is not done.
- **NEW — per-action offense RBAC rides the proxy hop-assertion.** As stated in the delivered item above:
  a **direct console-token holder is owner-equivalent** by construction. The fine-grained gate is real on the
  proxy-forwarded per-user path; it is not a second custody boundary in front of the console token.
- **NEW — the OIDC UI session-adoption step is a required follow-on.** Before any browser landing page may
  auto-adopt the OIDC-returned bearer into a session, **`state`-browser-binding + PKCE (S256)** are required
  (`docs/OIDC-RP.md`, "Required follow-on"). Until then OIDC login is an API-level identity proof, not a
  wired browser SSO landing.
- **Active-passive HA only — NOT synchronous multi-writer HA.** An active-passive failover profile *is* built
  (`docs/architecture/HA-PROFILE.md`, `infra/ha/`): the stateless proxy/otel tier is active-active, and the
  single-writer sovereign spine gets an **anti-rollback-safe** failover via a **witnessed-floor interlock**
  (`tools/ha/spine_failover_guard.py` / `sigil floor promote-passive`) that refuses to promote a stale, forged,
  or forked mirror. Honest limits, by construction: the spine is **single-writer** (a second concurrent writer
  is a *detectable fork*, not scale — HA-PROFILE.md §2), so there is **no automatic leader-election** —
  promotion requires the witnessed-floor check *plus* a **manual fence** of the old active; the passive holds an
  **out-of-band** mirror of `~/.sigil` (a signed-backup seed + `tools/ha/mirror-sync.sh` rsync delta), **not**
  synchronous replication; and witnesses remain **independent trust nodes, not failover**. In the k8s profile,
  the sovereign cockpit is deployed **proxy-only**: `vigil up --proxy-only` runs the reverse proxy against
  remote backends and spawns no writer, and `infra/ha/k8s/networkpolicy.yaml` restricting the sovereign
  Service to `app: vigil-proxy` pods is **REQUIRED, not optional** — the cockpit serves its own token
  token-free at `GET /`, so any in-cluster workload reaching it directly could scrape the owner token
  (the proxy→cockpit hop is itself cleartext — a documented MEDIUM residual). The **offense plane is not
  cross-pod clusterable** this way — the offense console token is owner-equivalent, so it stays a single
  proxy-fronted backend, not a horizontally-scaled tier. Stateful backends (Neo4j community, embedded Qdrant)
  are **not** clustered — the profile documents the enterprise/server-mode upgrades and ships neither.

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
| 9 | An operator (past the proxy floor) is refused an owner-tier offense action | As an `operator` through `vigil up` — the operator clears the coarse proxy floor because it holds `run_engagement` — POST an owner-tier offense route (e.g. `/api/authority/provision`) → **403**: the proxy stamps the hop-assertion, the console verifies it, and `role_can("operator", "offense_authority")` is **false**. (A `viewer`'s POST is refused one step earlier at the proxy floor, which requires `run_engagement` for any mutation — that 403 is the coarse floor, not the S1 console gate.) |
| 10 | A keypair PoP login works, and a replay is refused | `enroll_pubkey` a user's Ed25519 key; `POST /api/login/challenge`, sign it, `POST /api/login` (PoP) → session bearer minted; re-send the **same** `{username, challenge, signature}` → **401** (challenge already consumed). |
| 11 | A TOTP second factor is required on a session-bootstrapping login, and a stale code fails | `enroll_totp` a user (URI shown once); a **PoP / password** `POST /api/login` **without** a `totp` code → refused; with a **stale/old-window** code → **401**; with the current code → OK. The **bearer** branch is not gated by the enrolment (W17-1 #535), though a code supplied alongside a bearer is still validated. |
| 12 | OIDC is inert when off and sound when on | With `SIGIL_OIDC_ENABLED` unset → `GET /api/oidc/login` **404** (route not registered). With it on → an `id_token` with `alg:none`, a bad signature, or a bad/replayed `nonce` is **refused**, and a **verified** identity with **no owner-signed account** is **refused** (role never comes from a claim). |
| 13 | A hard-prune below the first grant keeps the account | With an active account whose only grant sits below a candidate prune boundary K, `stranded_active_accounts` is non-empty → the prune **fails closed**; a snapshot-seeded fold keeps the account **active** with its per-username high-water intact. |

*Reproduction commands for rows 1–12 are in [`docs/pilot/claim-6-pilot-runbook.md`](../pilot/claim-6-pilot-runbook.md). Row 13 (hard-prune fold) is verified at the unit level (`test_snapshot_fold_accounts.py`) — it has no operator runbook phase, because cold-archive prune is a future operator-facing feature (see §9).*
