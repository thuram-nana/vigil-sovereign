# Playbook 11 — Cryptography

**Goal:** find weak crypto, weak key management, leaked secrets,
broken signature/MAC verification, and mis-applied algorithms.

---

## 11.1 TLS / transport

```bash
# Cipher and protocol audit
nmap --script ssl-enum-ciphers,ssl-cert -p 443 <target>
testssl.sh --jsonfile out.json https://<target>/

# Certificate
openssl s_client -connect <target>:443 -showcerts < /dev/null
```

Findings:
- TLS 1.0/1.1 enabled.
- Weak ciphers (RC4, 3DES, EXPORT, NULL, anonymous).
- Forward secrecy missing (no ECDHE / DHE).
- Heartbleed (CVE-2014-0160), POODLE, BEAST on legacy systems.
- Cert expiring soon, weak key (RSA-1024), wrong SAN, wildcard
  misuse.
- HSTS missing or `max-age` < 1 year.
- HSTS preload list status.

---

## 11.2 Application-layer crypto patterns

Anywhere user/server crypto is visible (cookies, JWTs, password
reset tokens, signed URLs, API request signatures):

- **Custom crypto** = red flag. "We rolled our own" almost always
  means broken. Document and recommend standard library.
- **MD5 / SHA-1** for security purposes (not for fingerprinting / dedup).
- **Plain SHA-256 for passwords** (no salt, no work factor) —
  cracking with `hashcat` minutes.
- **Reversible obfuscation** as encryption (base64, hex, ROT13, XOR
  with static key).
- **ECB mode** block cipher (look for repeating ciphertext blocks).
- **CBC without HMAC** — padding oracle risk.
- **Static IVs / nonces**.
- **Predictable randomness** — `mt_rand`, `rand`, `Math.random()`,
  PHP `uniqid` for tokens. Use CSPRNG (`random_bytes`,
  `crypto.randomBytes`, `os.urandom`).

---

## 11.3 JWT specifics

```bash
TOKEN="<token>"

jwt_tool "$TOKEN"                       # decode
jwt_tool "$TOKEN" -X a                  # alg=none bypass
jwt_tool "$TOKEN" -X k                  # kid injection
jwt_tool "$TOKEN" -X i                  # null sig
jwt_tool "$TOKEN" -X s -pk public.pem   # algorithm confusion HS256 with public key
jwt_tool "$TOKEN" -C -d wordlist.txt    # crack secret offline
```

Findings:
- `alg: none` accepted.
- Weak HS256 secret (cracked offline → forge any token).
- HS256 / RS256 algorithm confusion: server validates using public
  key as HS256 secret.
- `kid` parameter SQLi / file inclusion — `kid: ../../etc/passwd`,
  `kid: '; DROP TABLE keys;--`.
- No expiry (`exp` missing).
- `exp` very long (1 year+).
- `aud`/`iss`/`nbf` not validated.
- Sensitive data in claims that's trusted server-side.
- JWT not bound to fingerprint (any device with token wins).

---

## 11.4 Password storage (white-box)

When source available, look at password hashing:

- **Bcrypt / Argon2id / scrypt** with reasonable cost = good.
- **PBKDF2 with ≥ 600k iterations (SHA-256)** = acceptable.
- **MD5 / SHA1 / SHA256(password)** = broken.
- **`md5(password.salt)`** = broken.
- **No salt** = broken.

---

## 11.5 Signature / MAC verification

For webhook callbacks, signed URLs, API request signatures:

```bash
# Replay test (no signature)
curl -sk -X POST "https://<target>/webhook/payment" -d '{"amount":100}'

# Signature with empty value
curl -sk -X POST "https://<target>/webhook/payment" \
  -H "X-Signature:" -d '{"amount":100}'

# Wrong signature
curl -sk -X POST "https://<target>/webhook/payment" \
  -H "X-Signature: invalid" -d '{"amount":100}'

# alg confusion if signature header contains alg
```

Findings:
- No signature verification.
- String comparison instead of `hash_equals` (timing attack — low
  practical impact, but flag).
- `md5(body+secret)` MAC pattern — length-extension attackable
  (use HMAC).
- Signature covers headers only, body trusted.
- Signature covers wrong-shape body (whitespace / ordering matters
  to signer but not verifier).

---

## 11.6 Secret discovery

In source / repos / responses / browser:

```bash
# Source code scan
gitleaks detect --source loot/source/ --report-format json --report-path gitleaks.json
trufflehog filesystem loot/source/ --json > trufflehog.json

# JS bundle scan
grep -ohE "(api[_-]?key|secret|password|token)[\"']?\s*[:=]\s*[\"'][^\"']+" all-js.txt
grep -ohE "AKIA[0-9A-Z]{16}" all-js.txt    # AWS access key
grep -ohE "AIza[0-9A-Za-z_-]{35}" all-js.txt    # Google API key
grep -ohE "ghp_[0-9a-zA-Z]{36}" all-js.txt   # GitHub token
grep -ohE "sk-[0-9a-zA-Z]{32,}" all-js.txt   # OpenAI / Stripe-like
```

Any hardcoded provider key, JWT signing secret, or DB credential
found is Critical. Surface immediately.

---

## 11.7 Random / nonce / token generation

For each token type (CSRF, password reset, session, API key, OAuth
state, OTP):

- Source: CSPRNG vs `mt_rand`/`rand`/`time()`.
- Length / entropy.
- Encoding (hex / base64 / base64url).
- Storage (plaintext / hashed in DB).
- Comparison (`==` vs `hash_equals`).
- Single-use enforcement.

---

## 11.8 Encryption of data at rest

If you can observe:
- DB columns marked encrypted that look like base64 of plaintext.
- Encryption with same key as auth (key compromise = data + auth
  loss).
- Field-level encryption inconsistently applied.

White-box only for definitive findings.

---

## 11.9 Output

Findings filed. Phase summary:
- TLS posture.
- Custom crypto findings (always significant).
- JWT findings.
- Hashing weaknesses.
- Signature / MAC findings.
- Hardcoded secrets count + categories.
