# OIDC Relying Party (Slice S5) — SHIPPED OFF BY DEFAULT

The SIGIL cockpit can act as an **OpenID Connect Relying Party (RP)**: a user authenticates at an
operator-run Identity Provider (IdP) and the cockpit turns the resulting `id_token` into a session. This is
**disabled by default** and, when disabled, changes nothing about the cockpit.

## The sovereignty guarantee (OFF ⇒ byte-identical)

- With `SIGIL_OIDC_ENABLED` **unset / empty / non-affirmative**, the `/api/oidc/*` routes are **not
  registered at all**. `GET /api/oidc/login` is indistinguishable from any never-defined path (404 with a
  token; 401 at the shared `/api/` auth gate without one — exactly as any unknown `/api/*` path behaves).
- **No egress.** The RP makes an outbound request *only* when it is enabled **and** a callback is actually
  processed (the token exchange + the JWKS fetch). Off ⇒ no route, no surface, no network.
- This mirrors the `VIGIL_EGRESS_GUARD` precedent: opt-in by env, byte-identical unless asked.

Affirmative values for `SIGIL_OIDC_ENABLED`: `1`, `true`, `yes`, `on`, `enabled` (case-insensitive).

## The critical invariant: OIDC is *identity*, never *authority*

OIDC proves **who you are**. It **never** carries a role. On a verified `id_token`, the cockpit looks up an
**owner-signed `governor.account`** grant whose username matches the verified identity claim, and takes the
role **from that owner-signed grant** — *never* from any token claim.

- A verified OIDC identity with **no matching active owner-signed account is REFUSED** (401, no bearer).
- A token that asserts `role: owner` for an account the owner granted `viewer` still resolves to **viewer**.

This preserves the single-owner-key / nothing-self-authorizes doctrine: the IdP authenticates; the owner
still authorizes. A compromised or misconfigured IdP can assert an identity but cannot grant a role.

## `id_token` verification (what it rejects)

The `id_token` is verified by **re-executing** its signature against the IdP's published **JWKS**, then every
registered claim check — signature first, so an unverified payload is never trusted:

- **Signature** — RS256 / ES256 (RSA-PSS also supported) against the JWKS key selected by `kid`, binding the
  alg family to the JWK key type (RS*/PS* ⇒ RSA, ES* ⇒ EC).
- **`alg: none` is refused.** **Any symmetric alg (HS*) is refused** — there is no HMAC code path at all, and
  only the configured asymmetric algs are accepted, so the algorithm-confusion attack (submit `alg:HS256`,
  sign with the RSA *public* key as the HMAC secret) cannot land.
- **`iss`** equals the configured issuer; **`aud`** contains the configured client id (and `azp`, when
  present, equals it); **`exp`/`iat`/`nbf`** are within the configured clock skew.
- **`nonce`** is present and equals the single-use `nonce` minted at login (constant-time compare).

`state` and `nonce` are single-use, TTL-bounded, and **bound together** in a server-side ledger (the same
atomic `O_EXCL`/`unlink` discipline as the S3 login-challenge ledger): a replayed callback finds its `state`
already spent, and a `state`/`nonce` mix-and-match cannot pass.

## Honest bounds — private IdP only, egress posture

- **Target an operator-run IdP on the private tunnel.** The intended deployment reaches the IdP over
  loopback / RFC1918 / Tailscale-CGNAT / IPv6-ULA — the same ranges `bridge.daemon.bind_ok` allows for the
  cockpit itself. A **public cloud IdP breaks the air-gap posture and is NOT the default.**
- **`VIGIL_EGRESS_GUARD=require`** is incompatible with an OIDC RP whose IdP is *not* on the private tunnel:
  enabling OIDC means the callback will reach out to the IdP's token + JWKS endpoints. Keep the IdP private,
  or do not enable OIDC under a hard egress-deny posture.
- **A TOTP-enrolled account cannot complete via the redirect alone.** The OIDC redirect carries no place to
  submit a second-factor code, so a mapped account that has TOTP enrolled is **refused at the callback**
  (`second_factor_required`) — OIDC establishes the first factor only; that account uses the interactive
  `/api/login` path for its second factor. This is a deliberate, honest bound, not a bypass.
- The callback returns the minted bearer as JSON (`{ok, authenticated, username, role, bearer}`), the same
  shape as the S3/S4 logins. This slice ships the security core (id_token verification + owner-signed
  mapping); it does **not** auto-adopt the bearer into a browser session.
- **The `/api/oidc/login` state ledger is token-free** (it must be — it bootstraps a login for a caller
  with no bearer). It is bounded: capped at `max_outstanding` and self-healing via a per-mint TTL sweep, so
  a stale entry cannot accumulate. A direct client on the private tunnel could still *transiently* fill the
  live cap (the mint refuses with a retry hint until the TTL clears) — acceptable because the endpoint is
  opt-in and private-tunnel-only, but worth knowing.

## Required follow-on before a UI landing page adopts the bearer (NOT done here)

This slice deliberately stops at returning the verified bearer as JSON. **Before** any UI landing page
auto-adopts that bearer into the browser session, two things are REQUIRED — omitting them makes login-CSRF
/ authorization-code injection live:

1. **Bind `state` to the initiating browser session.** The single-use `state` currently proves the
   callback corresponds to a login *this server* minted; it does not yet prove it is the *same browser*
   that started the flow. The landing page must tie the `state` to the initiating session (e.g. a
   `HttpOnly; SameSite` session cookie set at `/api/oidc/login` and checked at the callback) so an
   attacker cannot feed a victim their own authorization response.
2. **Add PKCE** (`code_challenge`/`code_verifier`, S256). The verifier must be bound to the session and
   sent at token exchange, closing authorization-code injection/interception.

Until both land, treat the RP as a verification core to be driven by tests / a trusted local caller — not
as a browser-facing SSO endpoint.

## Configuration (only read when enabled)

| Env var | Meaning |
| --- | --- |
| `SIGIL_OIDC_ENABLED` | affirmative ⇒ RP on; otherwise off (routes unregistered) |
| `SIGIL_OIDC_ISSUER` | the IdP issuer identifier (must equal the `iss` claim) |
| `SIGIL_OIDC_CLIENT_ID` | this RP's client id (must be in the `aud` claim) |
| `SIGIL_OIDC_CLIENT_SECRET` | client secret for the token exchange (client_secret_post) |
| `SIGIL_OIDC_REDIRECT_URI` | the callback URL registered at the IdP |
| `SIGIL_OIDC_AUTHORIZE_ENDPOINT` | IdP authorize endpoint (the 302 target) |
| `SIGIL_OIDC_TOKEN_ENDPOINT` | IdP token endpoint (code → tokens) |
| `SIGIL_OIDC_JWKS_URI` | IdP JWKS URL (id_token signature keys) |
| `SIGIL_OIDC_SIGNING_ALGS` | asymmetric-only allowlist, default `RS256` (e.g. `RS256,ES256`) |
| `SIGIL_OIDC_USERNAME_CLAIM` | which verified claim maps to a `governor.account` username. **Prefer an IdP-guaranteed-unique, IMMUTABLE claim** (e.g. `sub`). `preferred_username`/`email` are MUTABLE at some IdPs — if a user can change theirs, the account mapping can drift or be steered onto another account. Default `preferred_username` for usability; set to `sub` (or an immutable unique claim) for the strongest binding. |
| `SIGIL_OIDC_CLOCK_SKEW_SECONDS` | exp/iat/nbf tolerance (default `60`) |

A configured `none`/`HS*` in `SIGIL_OIDC_SIGNING_ALGS`, or any missing endpoint, is refused at load — the RP
fails loud rather than half-enabling.
