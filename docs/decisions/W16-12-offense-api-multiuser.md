# W16-12 — The offense gated API gets distinct users, roles, sessions, and real operator identity

## Problem

The offense loopback API (`engine/crucible/framework/v2/api/`) had exactly ONE authentication path: an
OPTIONAL shared bearer (`CRUCIBLE_API_KEY`, `api/authn.py`), off by default. No users, no roles, no
sessions, no separation of duties — and no attribution of an action to a human. Operator identity elsewhere
in the stack is OS login + git config + hostname (`integration/vigil_integration/attestation/identity.py`),
which establishes the *box*, not *which authenticated human* drove an action.

## What already existed (verified before building)

The sovereign plane's **Claim 6 RBAC** (`docs/CLAIM-6-RBAC.md`, `apps/sigil/sigil/governor/accounts.py`)
is a real, enforced multi-user model: `viewer ⊂ analyst ⊂ operator ⊂ owner` over an **owner-signed
accounts spine**, per-user bearers/sessions, MFA/TOTP, keypair proof-of-possession, and an admission gate
before owner-signing. The role→permission vocabulary was promoted into the neutral shared core
(`packages/core/vigil_core/rbac.py`: `ROLES`, `PERMISSIONS`, `role_can`, `OFFENSE_ACTION_PERM`,
`offense_perm_for`) so BOTH trust domains import it. The offense **console**
(`framework.v2.console.server`) already does per-action RBAC (S1, #380) against a **hop-signed** role the
`vigil up` proxy stamps (`X-VIGIL-Principal/Role/Role-Sig/Role-Ts`, HMAC under a per-run
`VIGIL_CONSOLE_HOP_KEY`).

The **gated API** (`framework.v2.api`) was the one offense HTTP surface NOT wired to any of this: the proxy
already forwarded the stamped identity headers to it (`/offense/api/v1/*` → `127.0.0.1:8799`), but the API
**ignored them entirely**. This slice closes exactly that gap. It builds **no second model** — it consumes
the existing one.

## Design — reuse, do not duplicate

1. **One role model.** `api/server.py::_authorize` calls the SAME `role_can(role, offense_perm_for(path))`
   the console uses. The API's two POST routes were added to the ONE `OFFENSE_ACTION_PERM` map
   (`/api/v1/tool/invoke`, `/api/v1/import` → operator-tier `run_engagement`) — there is a single source
   of truth for "offense route → permission".
2. **One hop-assertion construction.** The proxy STAMP, the console VERIFY, and the api VERIFY are now the
   ONE function pair in `vigil_core.hopauth` (`stamp_hop_assertion` / `verify_hop_assertion`), so the byte
   format (`principal\nrole\nmethod\npath\nts`) cannot drift between the three sites. The proxy and console
   were refactored onto it; the api is the third caller.
3. **The hop key reaches the api child.** `vigil up` now hands `VIGIL_CONSOLE_HOP_KEY` to the offense-api
   child exactly as it does the console child (boot spawn + PlaneControl restart spec), so the api can
   verify the proxy's per-user role assertion. Without it the api fails **closed** (a stamped role is
   refused; only the direct credential-holder path stays open).
4. **Attribution.** A permitted action's response carries an `actor` object naming the AUTHENTICATED
   principal (`{principal, role, authenticated, via}`) and the action is logged against it
   (`crucible.api.authz`). A refusal is a `403` whose body NAMES the principal and the permission it
   lacked — the attributed negative control.

## Negative control

A validly hop-signed **viewer** (or analyst) POST to `/api/v1/tool/invoke` (which requires
`run_engagement`) is **refused with 403**, the refusal **names the principal**, and the tool **never runs**
(proved with a spy tool). A forged `X-VIGIL-Role: owner` with no valid MAC, a signature under the wrong
key, a stale timestamp, or a signature re-aimed at another path is likewise refused
(`test_api_rbac.py`).

## Residual — what identity does and does NOT establish (honest bound)

- **Establishes:** WHICH authenticated principal (username + role, from the owner-signed sovereign accounts
  spine) drove a **proxy-forwarded** action, and refuses-with-attribution a principal lacking the required
  role. Enforcement is fail-closed: an unverifiable/forged stamped role is refused.
- **Does NOT establish:**
  - **The direct on-host credential-holder is owner-equivalent.** A client reaching the loopback API and
    presenting NO role assertion (the local operator / the CLI / a legacy client, gated by loopback +
    same-origin + optional `CRUCIBLE_API_KEY`) keeps full access, attributed as `on-host-operator`
    (`authenticated: false`) — NOT a named human. This mirrors the console's documented bound: holding the
    on-host credential IS owner authority. The gate protects the proxy-forwarded per-user path, not a
    direct credential-holder.
  - **It does not prove the human at the keyboard.** Identity is only as strong as (a) the sovereign
    accounts spine's resolution of the session bearer and (b) the secrecy of the per-run hop key. A stolen
    bearer/session, or a leaked hop key, is that principal. "Sessions" are the sovereign per-user bearer
    sessions surfaced to the api via the proxy — the api itself manages no session store (it consumes the
    resolved principal), by FATAL-2 design (the offense api must not import the sovereign accounts spine).
  - The accounts' **trust root remains the owner-signed spine**; a compromised owner key or a
    locally-writable accounts store is the existing, unchanged residual.

## FATAL-2

`framework.v2.api` imports only the namespace-pure `vigil_core.rbac` / `vigil_core.hopauth` (pure stdlib,
no framework/strix/sigil) — proven by `test_importing_api_server_loads_no_sigil`. The uiproxy's reach into
`vigil_core.hopauth` is pinned + purity-checked by `test_control_plane_boundary.py`.

## Registered claim

<!-- CLAIM:W16-12 -->
The offense gated API (framework.v2.api) enforces per-action RBAC against the same owner-signed
multi-user model as the offense console: a proxy-forwarded per-user request carries a hop-signed role
(VIGIL_CONSOLE_HOP_KEY) that the API verifies and enforces via role_can(role, offense_perm_for(path)),
attributing each permitted action to the authenticated principal, and refusing-with-attribution a role that
lacks the required permission (fail-closed on a forged or unverifiable role assertion). Residual: a direct
on-host loopback credential-holder presenting no role assertion is owner-equivalent, and identity is only
as strong as the sovereign accounts resolution plus the hop-key secrecy.
