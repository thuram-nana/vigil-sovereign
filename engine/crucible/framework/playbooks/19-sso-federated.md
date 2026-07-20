# Playbook 19 — SSO and federated identity

**Goal:** test single sign-on integrations — OAuth 2.0, OpenID
Connect, SAML — for the implementation-specific weaknesses that
make federated identity uniquely error-prone.

**Stage in lifecycle:** 4. Run if the target uses any external IdP
or acts as one.

**Standards:** RFC 6749 (OAuth 2.0), RFC 8252, RFC 7636 (PKCE),
SAML 2.0 spec, OpenID Connect Core; OWASP ASVS V3.

---

## 19.1 Identify the role

Is the target:
- An **OAuth client** (relies on Google/Facebook/etc. for login)?
- An **OAuth provider** (issues tokens to third-party apps)?
- A **SAML SP** (relies on customer's IdP)?
- A **SAML IdP** (issues SAML assertions to customers)?
- An **OIDC client** / **OIDC provider**?
- A **resource server** (consumes tokens issued by another)?

Each role has a different test surface. Most apps are clients
("login with Google/Github"). Larger enterprise SaaS often has a
SAML SP role for customer SSO. Identity-product or platform offerings
may be providers.

---

## 19.2 OAuth 2.0 / OIDC client testing

### Authorization request

When the user clicks "log in with Google", the app sends them to the
IdP with an authorization request. Inspect:

- `client_id` — who's requesting?
- `redirect_uri` — where does the IdP send the user back?
- `response_type` — `code` (Authorization Code flow) is correct;
  `token` (implicit flow) is deprecated.
- `scope` — what's requested? Often over-broad.
- `state` — random, bound to session, verified on callback?
- `nonce` (OIDC) — random, single-use, verified in ID token?
- `code_challenge` / `code_challenge_method` (PKCE) — present?
  PKCE is mandatory for public clients (mobile, SPA) and recommended
  for confidential clients.

### redirect_uri attacks

The most-attacked component.

- Wildcards in registered redirect_uri? `https://target.example/*`
  allows path traversal: `https://target.example/redirect?u=https://attacker`.
- Open redirector in target.example? If the app has an open
  redirect at a registered URI, OAuth code can be funneled to
  attacker.
- Redirect URI fragment manipulation —
  `https://target.example/cb?code=...#@attacker.com/`.
- IdP-side issues — does the IdP normalize URIs strictly?
- Sub-domain takeover on a valid redirect_uri target — chain to
  full account takeover.

### state / CSRF

- No `state` → CSRF login attack: attacker initiates auth flow,
  pauses at `code` callback, sends victim the callback URL → victim
  is logged in as attacker → attacker observes victim's actions.
- Static `state` → same.
- `state` not bound to session — attacker can steal it.

### Authorization code flow (PKCE)

- Code single-use? Re-using the code → 400.
- Code lifetime ≤ 1 minute?
- Code bound to client_id, redirect_uri, code_verifier (PKCE)?
- Code interception risk via Referer (`https://target.example/cb?code=...`
  → if cb page loads any third-party content, code leaks via
  Referer header).

### Token handling

- Access token stored where? `localStorage` is fine for browser if
  XSS is otherwise mitigated; `HttpOnly` cookie better for
  server-side token if same-origin.
- Refresh token treated as long-lived secret? Rotation on use?
- Token revocation endpoint working?
- Token includes audience claim? The app verifies `aud` matches
  itself?

### ID token validation (OIDC)

- Signature verified with IdP's JWKS (not skipped)?
- `iss` matches expected IdP?
- `aud` includes app's client_id?
- `exp` checked with clock skew tolerance ≤ 5 minutes?
- `nonce` matches the value sent in the auth request?
- `at_hash` / `c_hash` validated?

---

## 19.3 OAuth 2.0 / OIDC provider testing

If the target *is* an IdP:

- Are public clients distinguished from confidential? Public clients
  must use PKCE.
- Authorization codes single-use, short-lived, bound to the request?
- Refresh tokens rotated on each use, with reuse-detection (revoke
  the chain on detected reuse — sign of token theft)?
- Error responses don't leak whether an account exists.
- Consent screens clearly labeled (no "consent fatigue" + dark
  patterns).
- JWKS endpoint TLS-protected and uses signed key sets.
- Key rotation strategy in place (don't keep the same signing key
  forever; key compromise → token forgery).

---

## 19.4 SAML SP testing

If the target consumes SAML assertions from a customer's IdP:

### XML signature validation

- Signature verified before processing? (Many libraries default to
  insecure unless explicitly hardened.)
- Signature wrapping attacks (XSW) — assertion appears valid but
  signed envelope is for a different element.
- Signature exclusion — assertion accepted without `<Signature>`?
- Signature algorithm — accepts `none`? Accepts MD5/SHA-1?
- KeyInfo trust — does the SP trust any key in the response, or
  only the configured IdP cert?

### Assertion processing

- `Audience` restriction — assertion intended for *this* SP?
- `NotBefore` / `NotOnOrAfter` — checked?
- `InResponseTo` — matches a request the SP sent?
- `Recipient` matches the SP's ACS URL?
- `NameID` mapping — does the SP trust `NameID` to identify the
  user, or use a tamper-resistant mapping?

### XXE in SAML

SAML is XML. XXE applies — see playbook 08 §8.6. Specifically test
the assertion parser.

### Assertion replay

- Used assertion can be replayed within validity window?
- IdP issues unique `ID` per assertion; SP tracks seen IDs?

---

## 19.5 SAML IdP testing

If the target *issues* SAML assertions:

- Private signing key protection (HSM / KMS / encrypted).
- Audience scoping — IdP verifies the requesting SP is configured.
- IdP-initiated SSO — supported? Carries replay risk; SP-initiated
  preferred.
- Logout flow — Single Logout supported? Tested?

---

## 19.6 Account binding / linking attacks

If the app supports both local accounts and SSO, or multiple SSO
providers:

- Account takeover via email-binding: attacker registers local
  account with `victim@gmail.com`, then victim later uses "Login
  with Google" → does the system bind to the existing account
  without verification? If yes, attacker has password access to
  victim's account.
- Reverse: victim has Google login on `victim@gmail.com`. Attacker
  uses "register" flow with same email + password. If verification
  is missing, attacker now has both paths to victim's account.
- Multiple-IdP confusion: the same "verified email" claim from two
  different IdPs, but the app only checks the email — pre-existing
  user gets bound to attacker's IdP account.

---

## 19.7 Logout

- IdP logout doesn't invalidate the SP's session (so user thinks
  they logged out but the SP session persists)? Common.
- SP logout doesn't invalidate the IdP session (so next "login with
  X" silently re-establishes session)?
- Single Logout (SLO) implemented? Tested across all SPs?

---

## 19.8 JWT-specific (when SSO uses JWTs)

See `framework/knowledge-base/attack-techniques/jwt-attacks.md` for
the catalog. Quick checklist:

- `alg: none` — accepted?
- HS256 with RS256 public key as HMAC secret — accepted?
- Weak HMAC secret — crackable in seconds?
- `kid` injection — `kid` field path-traversed to a known file?
- JWK injection — `jwk` field accepted from token, used as the
  verifying key?
- `exp` / `nbf` / `iat` — checked with reasonable skew?
- `iss` / `aud` — checked against expected values?

`jwt_tool -t <token> -M at` runs the standard attack matrix.

---

## 19.9 Common findings to expect

| Finding | Severity | Defense |
|---------|---------:|---------|
| OAuth state missing or static | High | Random per-session state, server-side verify |
| OAuth redirect_uri uses wildcard | Critical | Strict equality |
| Authorization code re-usable | High | Single-use enforcement |
| ID token signature not verified | Critical | Use IdP JWKS; verify alg, aud, iss |
| SAML signature wrapping (XSW) accepted | Critical | Validate signed element identity |
| SAML XXE | Critical | Disable DTD/external entities in parser |
| Account linking via unverified email claim | High | Verify email or require re-auth |
| JWT `alg: none` accepted | Critical | Pin algorithm at verification |
| Refresh token doesn't rotate; theft persistent | Medium-High | Rotation + reuse detection |

---

## 19.10 Phase exit checklist

- [ ] SSO role identified (client/provider, OAuth/SAML/OIDC).
- [ ] Authorization-request parameters audited.
- [ ] redirect_uri / ACS URL handling tested for tricks.
- [ ] state / nonce / PKCE validation verified.
- [ ] Token / assertion validation chain audited (signature, iss,
       aud, exp, nbf, audience, recipient).
- [ ] Account binding flows abuse-tested.
- [ ] Logout / SLO tested.
- [ ] JWT attack matrix run if JWTs in use.
- [ ] Findings logged.
