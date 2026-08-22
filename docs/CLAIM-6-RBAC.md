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
  fold or refused (401). **W10-7 — gated out of production:** under `VIGIL_POSTURE=production` that shared
  token no longer resolves to owner (`vigil_core.posture.legacy_owner_token_grants_owner()` is `False`) —
  it falls through to the fold and is refused, so per-user proof-of-possession auth is required; the same
  applies to `_token_ok` (the `/api/ask` owner gate). It can also be opted out of outside production with
  `SIGIL_LEGACY_OWNER_TOKEN=0`. Provision per-user accounts offline with `sigil accounts create` (owner-key
  signed; no HTTP token needed). The refuse-to-start production gate (`vigil up` / `vigil engage`) also
  refuses while the shared token is left enabled.

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
per-user bearer to its Principal, anything else to `{authenticated:false}` → the proxy 401s. (Under
`VIGIL_POSTURE=production` the legacy shared owner token does **not** resolve to `OWNER_PRINCIPAL` — W10-7 —
so `whoami` reports `{authenticated:false}` for it and the login gate requires per-user PoP.) Results are
cached by `sha256(bearer)` with a short TTL (30 s; 5 s for negatives) so SSE/polling do not stampede whoami.
The cache is **not** a revocation-lag window (W9-3 / #436): an **edge revocation set** is consulted on every
decision *before* the cache is trusted (fail-closed), the admin **force-purge** endpoint invalidates the
cache entry on revoke, and long-lived SSE streams are **re-authenticated** periodically — so a revoke takes
effect at the decision edge, not at cache expiry (see *Revocation is immediate at the edge* below).

**Rejected alternative:** exporting an owner-signed accounts *snapshot* to the offense side and folding it
there — also sound, but it duplicates the fold + per-username anti-replay logic in a second interpreter and
adds an export/rotation surface. Delegation reuses the one authority with no new trust primitive.

### Enforcement hooks at the proxy {route → requirement}

| route | requirement |
|---|---|
| static bundle (`/`, `style.css`, `app.js`, …) | none (carries no secret) |
| `/sovereign/api/whoami`, `/sovereign/api/login`, `/sovereign/api/login/challenge`, `/sovereign/api/oidc/login`, `/sovereign/api/oidc/callback` | none (login bootstrap — exactly the sovereign's `BOOTSTRAP_PATHS`; W17-2/#536) |
| every other `/sovereign/*` | authenticated (viewer+); user's **own** bearer forwarded → `role_can` |
| `/offense/*` reads (GET/HEAD/SSE) | authenticated (viewer+) |
| `/offense/*` mutations (POST/PUT/PATCH/DELETE) | `run_engagement` (operator+) |
| `/__vigil/plane/status`, `/__vigil/plane/version` | authenticated (viewer+) |
| `/__vigil/plane/offense/start`, `/stop` | `run_engagement` (operator+) |
| `/__vigil/plane/auth/purge` (POST — admin force-purge / edge-revoke; W9-3/#436) | `manage_users` (**owner**) |

### Offense credential handling (the owner token never leaves the proxy)

The offense console (8787) authenticates with the shared `VIGIL_CONSOLE_TOKEN` (= the owner boot token the
proxy holds as `self.server.token`); the offense gated api (8799) uses loopback + same-origin (+ optional
`CRUCIBLE_API_KEY`) and ignores the console token. After the proxy has authenticated a request via the
sovereign whoami, it **substitutes** the offense console credential on the outbound hop (the `X-SIGIL-Token`
header and any `?token=`), so the browser never holds it and an unauthenticated request never reaches a
backend. It also **strips** any client-supplied `X-VIGIL-*` header — by **class** (case- and
hyphen/underscore-normalised, so no `X_VIGIL_Role` variant survives) — and **stamps** the resolved
`X-VIGIL-Principal`/`X-VIGIL-Role` (plus, as of S1, an unforgeable `X-VIGIL-Role-Sig` HMAC hop-assertion)
for attribution and the offense console's per-action RBAC gate (`_rbac_ok`).

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
   or — for an encoding it cannot decode (brotli/zstd/unknown), a malformed/truncated body, or a
   **decompression bomb** — **fails closed (502)** rather than relay an un-scannable, possibly token-bearing
   body (`_decode_and_redact`). The bomb bound is enforced **during** streaming inflate — the decoder emits at
   most one 1 MiB output step at a time and stops the instant the running decoded total would exceed the
   64 MiB cap (encoded reads are separately capped at 16 MiB), so a body that deflates ~1032:1 can never be
   fully materialised in memory. It is a real, tested bound, not a post-hoc size check.

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
- The offense console now does **per-action RBAC internally** (S1 — `vigil_core.rbac.OFFENSE_ACTION_PERM`,
  enforced in `framework.v2.console.server._rbac_ok` against a proxy-stamped **HMAC hop-assertion**). The
  honest bound: enforcement rides that hop-assertion, so a client holding the offense **console token
  directly** (no hop-signed role) is **owner-equivalent** by construction — the gate protects the
  proxy-forwarded per-user path, not a direct console-token holder.
- **Revocation is immediate at the edge (W9-3 / #436).** An **edge revocation set** is consulted on every
  decision *before* the bearer cache is trusted, fail-closed; the owner-only admin **force-purge** endpoint
  (`POST /__vigil/plane/auth/purge`, gated on `manage_users`) revokes a username/credential and drops its
  cache entry, so the very next decision is refused within the old TTL window — the sovereign
  `sigil accounts revoke` stays the authority, this makes it bite at the edge now. A long-lived **SSE**
  stream is **re-authenticated** at most every `_SSE_REAUTH_INTERVAL_S` (default 15 s, `VIGIL_SSE_REAUTH_INTERVAL_S`)
  and torn down at the next interval once the bearer no longer resolves. *Residual:* if a revoke does **not**
  call the force-purge endpoint, a bearer already cached at the proxy stays valid until its ≤30 s cache entry
  expires, after which whoami — which already denies a revoked account — is re-consulted; and a same-named
  account re-created on the sovereign becomes visible at the edge again only after the revocation-set
  retention window (`_REVOCATION_RETENTION_S`).
- **HA is active-passive, not synchronous multi-writer.** An active-passive failover profile *is* built
  (`docs/architecture/HA-PROFILE.md`, `infra/ha/`): the stateless `vigil up`/otel tier is active-active, and
  the single-writer sovereign spine gets an anti-rollback-safe failover gated by the **witnessed-floor
  interlock** (`tools/ha/spine_failover_guard.py` / `sigil floor promote-passive`). By construction it is
  **single-writer** (a second concurrent writer is a *detectable fork*, HA-PROFILE.md §2): there is **no
  automatic leader-election** — promotion needs the witnessed-floor check *plus* a **manual fence** of the old
  active; the passive holds an **out-of-band** `~/.sigil` mirror (signed-backup seed +
  `tools/ha/mirror-sync.sh` rsync delta), **not** synchronous replication; and witnesses are **independent
  trust, not failover**.

## Delivered since this foundation was written (with honest bounds)

Items flagged "deferred / not built" in the first cut of this record are now **merged**. They are written
here with the exact bound each carries — delivered, not soft-pedalled, and not overclaimed.

- **Per-action offense-plane RBAC (S1, #380).** The offense console maps every state-changing POST to a
  permission (`vigil_core.rbac.OFFENSE_ACTION_PERM`: owner-tier `offense_authority` on host-exec / infra /
  authority / patch-apply routes, operator-tier `run_engagement` on ordinary run/edit/session routes,
  read-tier on the protective kill-switch *trip*; default-deny for any unmapped route). Enforced in
  `framework.v2.console.server._rbac_ok` against a **constant-time HMAC hop-assertion** the proxy stamps
  (`_hop_assertion_valid`, bound to principal+role+method+path+ts in a freshness window). **Honest bound:** a
  client holding the console token **directly** (no hop-signed role) is **owner-equivalent** by construction.
- **Cryptographic per-user identities (S3, #382).** An owner can bind an Ed25519 `user_pubkey` to an account
  (`enroll_pubkey`, owner-signed into the grant, byte-identical when absent), via
  `sigil accounts enroll-pubkey <user> --pubkey <b64>|--pubkey-file <path>` (W17-3/#537), the `enroll_pubkey`
  action, or the **Enrol key** field on the Users & Roles screen — the private half never touches the host. A
  user logs in by signing a single-use server challenge (`/api/login/challenge` → PoP branch of `/api/login`;
  replay-guarded by an O_EXCL single-use `ChallengeLedger`). **Honest bound:** keypair PoP is an
  **additional** login method — the bearer stays the ongoing session carrier, and the trust root is still the
  **owner-signed grant**.
- **MFA (TOTP) + optional password (S4, #387).** `governor/totp.py` (stdlib RFC-6238); the secret is shown
  once as an `otpauth://` provisioning URI and **sealed** via the owner vault before it is signed into the
  grant. On the login methods that bootstrap a **fresh session from a first factor** — PoP, password, OIDC —
  a TOTP-enrolled account must present a valid current code at `/api/login` (fail-closed). The **bearer
  branch** is **not** gated by the enrolment (`_check_totp(..., require=False)`, W17-1 #535): a bearer is
  itself a possession credential and the SPA login gate posts `{token}` only, so gating there would
  permanently brick UI login — a code-less bearer login is allowed, while a `{totp}` code that **is** supplied
  alongside the bearer is still validated (a wrong one is refused, so the gate is not a no-op). The owner
  enrols via `sigil accounts enroll-totp <user>` (or the `enroll_totp` action / the Users-screen **Enrol
  TOTP** button, which shows the provisioning URI once) and **removes** a lost factor via
  `sigil accounts disable-totp <user>` (the documented recovery path). `set_password` adds an *optional*
  weaker salted-scrypt login — set via `sigil accounts set-password <user>` (prompted, never on argv;
  W17-3/#537), the `set_password` action, or the Users-screen **Set password** field; keypair PoP is the
  stronger path.
- **Login fix set — enrolment is reachable end-to-end (W17-3, #537).** W17-2 wired the login *gate* (the
  TOTP field, the **Sign in with SSO** button, and the pre-auth bootstrap routes through `vigil up`); W17-3
  completes the *enrolment* side so a fresh operator can go from "no accounts" to "logged in" without editing
  the spine by hand. The three enrolment factors are bindable from **both** surfaces: the CLI
  (`sigil accounts enroll-pubkey|enroll-totp|set-password <user>`) and the **Users & Roles** screen
  (per-account **Enrol key / Enrol TOTP / Set password** controls that post the same owner-signed
  `enroll_pubkey`/`enroll_totp`/`set_password` broker actions). Every enrolment action is **owner-only**
  (`manage_users`), checked at the funnel **before** the owner key signs — an unauthenticated or non-owner
  enrolment attempt is refused (`test_owner_only_actions_refuse_an_operator`/`_a_viewer`,
  `test_w173_end_to_end_enrol_pubkey_and_password_then_login_over_http`). `/api/accounts` additionally reports
  three **non-secret booleans** (`has_pubkey`/`has_totp`/`has_password`) so the UI shows which factors are
  bound without ever exposing a key, sealed blob or hash.
- **OIDC Relying Party — OFF by default (S5, #388).** `config.oidc_enabled()` defaults **off**; when off the
  routes are **not registered** (byte-identical, no egress). When on, the `id_token` is verified against JWKS
  (**asymmetric algs only**; `alg:none`/HS* never implemented) with iss/aud/exp/iat/nbf + a single-use `nonce`
  bound to a single-use `state`, and the verified identity is mapped to an owner-signed `governor.account`
  grant — **role from the grant, never a claim**; a verified identity with no owner-signed account is refused.
  **Honest bounds:** OIDC targets an operator-run IdP on the private tunnel (a public cloud IdP breaks the
  air-gap). `state`-browser-binding + PKCE (S256) are now **built and required** (W16-6/#512), and the
  browser SSO landing is **wired end-to-end through `vigil up`** (W17-2/#536): the proxy forwards the OIDC
  login/callback bootstrap routes, remounts the session cookie for the mount prefix, and the login gate's
  **Sign in with SSO** button adopts the minted bearer (`docs/OIDC-RP.md`).
- **Hard-prune accounts fold (S2, #381).** `SnapshotState` now carries an account seed (per-username LWW
  state + high-water + cred), `_fold` seeds from the committed snapshot before folding the live window
  (mirrored across `resolve()` and `accounts()`), and `spine/prune.py::stranded_active_accounts` fails a prune
  **closed** rather than orphan an active account whose only owner-signed grant sits below the boundary.

## Deferred (honest scope — flagged, not built)

- **Per-screen permissions across all 30 screens.** The foundation covers nav visibility (`V.can`) + real
  enforcement at the enumerated load-bearing actions + a demonstrated per-button gate (Safety → Release).
  Comprehensive per-button gating on every screen is not done; the **server is the enforcement of record**
  (every mutation is re-checked and 403s).
- ~~**OIDC UI session-adoption (PKCE + state-browser-binding).**~~ **DONE.** `state`-browser-binding + PKCE
  (S256) landed in W16-6/#512, and the browser SSO landing is wired end-to-end in W17-2/#536 (proxy
  bootstrap-forward + cookie remount + SSO button that adopts the minted bearer). See the OIDC bullet above
  and `docs/OIDC-RP.md` ("Reachable through `vigil up`"). Residual: a **browser-native keypair-PoP signer**
  (import an Ed25519 key + sign the challenge in-page) is not built — PoP is reachable through the product
  for a key-holding client (the `/api/login/challenge` bootstrap route is now forwarded), but the login
  gate itself offers bearer + SSO, not in-browser signing.
