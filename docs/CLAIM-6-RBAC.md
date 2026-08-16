# Claim 6 — Enforced Multi-User RBAC (foundation)

A real, **enforced** multi-user role-based access control layer, built as an **admission gate in front of
the owner-signing funnel**. VIGIL stays single-owner-key at the trust root: the owner Ed25519 key
(`governor/identity.py`) remains the **sole signer** of every governance mutation, and a non-owner user
never holds a key. RBAC inserts a role→permission check **before** the server signs on the caller's behalf,
and records the requesting principal for attribution.

## Design invariants (do not regress)

- **Admission, not custody.** The permission check happens in `ui/actions.py::do_action` **before**
  `ensure_owner_keypair()` signs. A viewer's request never produces an owner signature (the check refuses
  first). An operator-approved ≤A2 action is signed by the **owner** key with the operator recorded as
  `approver`/`requested_by` — proving roles gate admission, not key access.
- **Accounts are owner-signed spine grants.** `governor/accounts.py` reuses the killswitch/capability/
  promotion governance-record idiom (`SIGNAL="governor.account"`, `signed_payload`/`verify_signed`). No new
  trust primitive; a forged/unsigned grant never verifies in the fold.
- **Asymmetric auth.** `create`/`assign_role` are the dangerous direction — honored only if **owner-signed
  AND** their `issued_at` strictly exceeds the per-username high-water. `revoke` is the safe direction —
  honored even unsigned, `issued_at` fixed at `0.0`.
- **Per-username anti-replay LWW** (closes the known VIGIL LWW replay-resurrection HIGH): a revoked account
  cannot be resurrected by re-appending a captured owner-signed `active` grant. The fold is computed by one
  `_fold()` helper that **both** read paths (`resolve()` and `accounts()`) call, so the guard is present at
  both surfaces identically.
- **Default-deny.** An action absent from `PERMISSION_BY_ACTION` (or mapped to `None`) refuses.
- **FATAL-2.** `accounts.py` is sovereign-side, imports no `framework`/`strix` (`assert_no_offense` at
  import), crypto via `reuse`/`vigil_core` only.
- **Bootstrap lockout avoidance.** Fail-open is restricted to the **exact** legacy owner shared token
  (`server._principal_for_token`) → `OWNER_PRINCIPAL`; every other/unknown token is resolved through the
  fold or refused (401).

## Roles and permissions

`viewer ⊂ analyst ⊂ operator ⊂ owner` (cumulative). `owner` is **not** a grantable bearer role.

| role | adds |
|------|------|
| viewer | `read` |
| analyst | `queue_proposal` |
| operator | `run_engagement`, `approve_a2`, `toggle_guard`, `config_nonsecret` |
| owner | `approve_a3`, `kill_release`, `promote`, `secrets`, `offense_authority`, `manage_users`, `toggle_protected_guard` |

## Enforcement hooks {control point → required permission}

| control point | required |
|---|---|
| `do_action` (all mutations) | per-action (`PERMISSION_BY_ACTION`) |
| `kill` / kill-switch engage (safe) | `read` (any authenticated) |
| `release` / kill-switch un-halt | `kill_release` (owner) |
| `promote` / `revoke` (promotion) | `promote` (owner) |
| `queue_learn` | `queue_proposal` (analyst+) |
| `start_learn` | `run_engagement` (operator+) |
| capability toggles (`enable_*`/`disable_*`) | `toggle_guard` (operator+) |
| `set_model`/`set_effort`/`set_provider`/`set_config`/`set_cloud_config` | `config_nonsecret` (operator+) |
| `set_config` where env is `VIGIL_ALLOW_PROTECTED_DOMAINS` | **`toggle_protected_guard` (owner-only)** |
| `set_secret`/`check_secret(s)`/`set_cloud_file_secret` | `secrets` (owner) |
| `offense_bind_authority`/`offense_approve`/`offense_deny` | `offense_authority` (owner) |
| approval resolve ≤A2 | `approve_a2` (operator+) |
| approval resolve A3 / destructive | `approve_a3` (owner) |
| `create_account`/`assign_role`/`revoke_account` | `manage_users` (owner) |
| HTTP reads (`GET /api/*`) | authenticated (viewer+) |
| `GET /api/accounts` | `manage_users` (owner) |

### The `VIGIL_ALLOW_PROTECTED_DOMAINS` special case (Claim 5 reconciliation)

`set_config` is normally `config_nonsecret` (operator+). But turning off the categorical `.gov/.mil/.edu/
.int` safety floor is **owner-only**: `do_action` special-cases a `set_config` whose env is
`VIGIL_ALLOW_PROTECTED_DOMAINS` to require `toggle_protected_guard` (owner). Covered by a negative control
(an operator cannot turn the guard off; a normal `set_config` still works for an operator).

## Authentication carrier

The existing `X-SIGIL-Token` header (`?token=` for SSE/downloads) now bears **either** the legacy owner
shared token **or** a per-user bearer — zero change to the ~100 existing call sites. `POST /api/login`
verifies a candidate bearer; `GET /api/whoami` reports the current principal; the SPA keeps a per-user
bearer in `sessionStorage` (`ui.js` `token()` prefers it), with a login gate + current-user chip + real
nav/action gating via `V.can`.

## Deferred (honest scope — flagged, not built)

- **Per-screen permissions across all 30 screens.** The foundation covers nav visibility (`V.can`) + real
  enforcement at the enumerated load-bearing actions + a demonstrated per-button gate (Safety → Release).
  Comprehensive per-button gating on every screen is not done; the **server is the enforcement of record**
  (every mutation is re-checked and 403s).
- **Per-user offense-plane auth.** The offense read plane / gated API (8787/8799) and the uiproxy
  plane-control (start/stop offense) stay owner-boot-token gated. Owner-signed offense *mutations* ARE
  gated (`offense_authority`). Per-user proxy auth is a later upgrade.
- **Hard-prune fold.** The accounts fold is a genesis scan (byte-safe under the Slice-C empty snapshot). A
  future cold-archive prune must extend `SnapshotState` with an accounts seed (per-username LWW state +
  high-water) + a referential-floor assert, mirrored in `resolve()` and `accounts()`.
- **SSO / OIDC / MFA / password flows.** Not in scope.
- **Cryptographic per-user identities.** Bearer tokens are the foundation; the stronger replacement is
  per-user keypairs + proof-of-possession via `vigil_core.delegation.DelegationCert` +
  `vigil_core.capability.WielderProof` (owner-signed, expiring, role/scope-bound).
