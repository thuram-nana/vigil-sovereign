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
bearer in `sessionStorage` (`ui.js` `token()` prefers it).

### Where per-user enforcement is real today (the honest boundary)

RBAC is enforced by the **server** for any client that presents **only** a bearer: the CLI
(`sigil accounts …`), the sovereign/offense HTTP API directly, and a browser session that has logged in
with a per-user bearer (no owner token present).

**The `vigil up` command UI (uiproxy) is now a per-user boundary too** — see
[Per-user auth at the command-UI boundary](#per-user-auth-at-the-command-ui-boundary-uiproxy) below. The
owner token is no longer embedded in `index.html`; the proxy authenticates every forwarded request per-user
(fail-closed) by delegating to the sovereign `/api/whoami`, and each user acts as their own Principal.
Owner-only actions stay owner-only via the same `role_can`. The residual is that the proxy is a loopback/VIP
listener (not a hardened public gateway) and the accounts' trust root remains the owner-signed spine.

## Per-user auth at the command-UI boundary (uiproxy)

The `vigil up` reverse proxy (`integration/vigil_integration/uiproxy.py`) is the single listener a browser
points at. This slice makes it a **per-user authentication boundary** so the command UI is safely shareable:
each user acts as **their own** RBAC Principal, and owner-only actions stay owner-only.

### What changed

1. **No embedded owner token.** `assemble_serve_dir` no longer writes the owner token into `index.html`
   (`__VIGIL_TOKEN__` → empty). The served page carries **no credential**; the SPA's existing login gate
   (`app.js renderLoginGate` → `POST /sovereign/api/login`) is the real entry, and the per-user bearer lives
   in `sessionStorage` (`ui.js token()`). The owner signs in with the token `vigil up` prints; a teammate
   signs in with the bearer the owner issued them (Users & Roles → Create account).
2. **The proxy verifies every forwarded request per-user, fail-closed.** Past a tiny bootstrap allowlist
   (`/sovereign/api/whoami`, `/sovereign/api/login`), every `/sovereign/*` and `/offense/*` request must
   carry a bearer that resolves to a Principal — else **401, never forwarded** (no unauthenticated
   fall-through to a backend, never acting as owner).
3. **Per-user identity reaches both planes.** The user's own bearer is forwarded to the sovereign plane
   (native `role_can`); the offense plane receives the resolved identity + a coarse role floor (below).

### Verification mechanism — DELEGATE to the sovereign whoami (FATAL-2-clean)

The proxy is offense-side and **must not** import the sovereign `AccountsRegistry` (FATAL-2: no
`sigil`/`apps.sigil`/`framework`-sovereign module in the offense interpreter). It therefore **delegates**
verification: a loopback `GET 127.0.0.1:8733/api/whoami` carrying the request's bearer as `X-SIGIL-Token`
returns the resolved Principal (`{authenticated, username, role, permissions}`). This is sound because the
sovereign plane is the **authority** on the owner-signed accounts spine — trusting its resolution trusts
exactly the right root — and the proxy stays **pure stdlib** (`http.client`, no cross-domain import).
`whoami` is token-optional and read-only (no side effect): an owner token resolves to `OWNER_PRINCIPAL`, a
per-user bearer to its Principal, anything else to `{authenticated:false}` → the proxy 401s. Results are
cached by `sha256(bearer)` with a short TTL (30 s; 5 s for negatives) so SSE/polling do not stampede whoami.

**Rejected alternative:** exporting an owner-signed accounts *snapshot* to the offense side and folding it
there — also sound, but it duplicates the fold + per-username anti-replay logic in a second interpreter and
adds an export/rotation surface. Delegation reuses the one authority with no new trust primitive.

### Enforcement hooks at the proxy {route → requirement}

| route | requirement |
|---|---|
| static bundle (`/`, `style.css`, `app.js`, …) | none (carries no secret) |
| `GET /sovereign/api/whoami`, `POST /sovereign/api/login` | none (login bootstrap) |
| every other `/sovereign/*` | authenticated (viewer+); user's **own** bearer forwarded → `role_can` |
| `/offense/*` reads (GET/HEAD/SSE) | authenticated (viewer+) |
| `/offense/*` mutations (POST/PUT/PATCH/DELETE) | `run_engagement` (operator+) |
| `/__vigil/plane/status`, `/__vigil/plane/version` | authenticated (viewer+) |
| `/__vigil/plane/offense/start`, `/stop` | `run_engagement` (operator+) |

### Offense credential handling (the owner token never leaves the proxy)

The offense console (8787) authenticates with the shared `VIGIL_CONSOLE_TOKEN` (= the owner boot token the
proxy holds as `self.server.token`); the offense gated api (8799) uses loopback + same-origin (+ optional
`CRUCIBLE_API_KEY`) and ignores the console token. After the proxy has authenticated a request via the
sovereign whoami, it **substitutes** the offense console credential on the outbound hop (the `X-SIGIL-Token`
header and any `?token=`), so the browser never holds it and an unauthenticated request never reaches a
backend. It also **strips** any client-supplied `X-VIGIL-*` header — by **class** (case- and
hyphen/underscore-normalised, so no `X_VIGIL_Role` variant survives) — and **stamps** the resolved
`X-VIGIL-Principal`/`X-VIGIL-Role` for attribution (and future per-action offense RBAC).

**Hop-only credential — enforced on the RESPONSE too (RED-PEN BLOCK-1).** Substituting the credential on the
*request* is not sufficient: a backend serves its **own** static `index.html` at `/` **token-free** with the
owner token spliced in (the console's `__CONSOLE_TOKEN__`, the cockpit's `__SIGIL_TOKEN__`), and
`route()` maps `/offense/` · `/offense/index.html` (and `/sovereign/`) to that backend `/`. A plain relay
would stream `data-token="<owner token>"` to a mere **viewer**, who could scrape it and replay it as owner.
So the proxy **redacts `self.server.token` out of every relayed NON-SSE response body** (`_relay_response` →
`_relay_redacting`), replacing any exact occurrence with an equal-length marker (Content-Length preserved;
a `len-1` carry catches a split across read boundaries).

The redactor is a **literal-byte** scan, so it works only on **cleartext** — which the proxy guarantees by
**mechanism** (RED-PEN BLOCK-A), not by assumption:

1. The proxy **forces `Accept-Encoding: identity` on the backend hop** (`_forward_request_headers`, stripping
   any client `Accept-Encoding`), so a backend it controls never compresses and the scan always sees
   cleartext. (An nginx *in front* of the proxy that gzips the proxy's **already-redacted** output is safe.)
2. **Defense-in-depth:** if a relayed non-SSE body nonetheless arrives with a `Content-Encoding` (a backend
   or middleware that ignored the identity request), the proxy **decodes it (gzip/deflate) before scanning**,
   or — for an encoding it cannot decode (brotli/zstd/unknown), a malformed body, or one over the
   decompression-bomb caps — **fails closed (502)** rather than relay an un-scannable, possibly token-bearing
   body (`_decode_and_redact`).

**SSE is the one exemption** — streamed as-is (a carry-window would break incremental delivery). That rests
on a checked property, not an assumption: no viewer-reachable SSE stream (offense `_sse`/`_sse_blackboard`,
cockpit `_sse`/`_hud`) emits the session token, pinned by a negative-control test so it cannot silently rot.

Net: **for every non-SSE body relayed to the browser, on any route/method/path, the redactor operates on
cleartext and the owner credential is removed — or the relay is refused.**

### Session hygiene

- **Forged/guessed session token** → the whoami resolution fails → 401, never forwarded.
- **Privilege escalation** — a viewer/analyst bearer resolves to its role: the sovereign plane refuses
  operator/owner actions via `role_can`, and the proxy floors offense mutations at `run_engagement`.
- **Owner-token leak** — the owner token is no longer in any served asset; the offense console credential is
  presented only on the proxy→backend loopback hop, and is **redacted out of every relayed non-SSE response
  body** so a backend's own token-embedding index can never hand it to the browser (RED-PEN BLOCK-1).
- The bearer is compared server-side against `sha256(salt+bearer)` (accounts store); the proxy never stores
  a plaintext bearer (its cache is keyed by `sha256(bearer)`).

### Honest limits

- The reverse proxy is **not** a hardened public gateway — it still binds loopback / a private VIP
  (`bind_ok`); front it with the operator's TLS edge as today.
- The accounts' **trust root is the owner-signed spine**; a compromised owner key or a locally-writable
  accounts store is the existing residual (unchanged by this slice).
- The offense-plane floor is **coarse** (read vs. `run_engagement`); the offense console does not yet do
  per-action RBAC internally — the fine-grained action→permission map remains on the sovereign plane, and
  the forwarded `X-VIGIL-Role` is the seam for a future offense-side per-action gate.
- **Revocation lag:** a bearer stays valid for at most the auth-cache TTL (≤30 s) after revocation, and an
  already-open SSE stream is authenticated only at connect.

## Deferred (honest scope — flagged, not built)

- **Per-screen permissions across all 30 screens.** The foundation covers nav visibility (`V.can`) + real
  enforcement at the enumerated load-bearing actions + a demonstrated per-button gate (Safety → Release).
  Comprehensive per-button gating on every screen is not done; the **server is the enforcement of record**
  (every mutation is re-checked and 403s).
- **Per-action offense-plane RBAC.** The command-UI proxy now enforces per-user auth + a coarse offense
  floor (read vs. `run_engagement`), and forwards `X-VIGIL-Role` — but the offense console (8787) does not
  yet map each of its own POST routes to a permission. Owner-authority offense actions (`offense_approve`/
  `offense_bind_authority`) remain sovereign-gated (`offense_authority`, owner).
- **Hard-prune fold.** The accounts fold is a genesis scan (byte-safe under the Slice-C empty snapshot). A
  future cold-archive prune must extend `SnapshotState` with an accounts seed (per-username LWW state +
  high-water) + a referential-floor assert, mirrored in `resolve()` and `accounts()`.
- **SSO / OIDC / MFA / password flows.** Not in scope.
- **Cryptographic per-user identities.** Bearer tokens are the foundation; the stronger replacement is
  per-user keypairs + proof-of-possession via `vigil_core.delegation.DelegationCert` +
  `vigil_core.capability.WielderProof` (owner-signed, expiring, role/scope-bound).
