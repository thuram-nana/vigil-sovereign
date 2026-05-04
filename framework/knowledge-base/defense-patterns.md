# Defense patterns

The defensive patterns OBSIDIAN recommends when writing remediation
sections of findings. For each common bug class, this document
provides the canonical fix recipe in plain language.

When writing a remediation, reference this document rather than
re-deriving the recipe from scratch.

---

## SQL injection

**Pattern:** Always parameterize. Never concatenate user input into
queries. ORM is fine if used properly; raw queries must use placeholders.

```php
// BAD
$res = $db->query("SELECT * FROM orders WHERE id = $id");

// GOOD
$stmt = $db->prepare("SELECT * FROM orders WHERE id = ?");
$stmt->execute([$id]);

// Eloquent / ORM
Order::where('id', $id)->first();
```

For dynamic ORDER BY, use an allowlist:
```php
$validSorts = ['created_at', 'amount', 'status'];
$sort = in_array($_GET['sort'], $validSorts) ? $_GET['sort'] : 'created_at';
```

---

## XSS

**Pattern:** Escape on output; never trust input. Default-escape
templates. Set CSP. Use HttpOnly cookies for session.

```js
// BAD
element.innerHTML = userInput;

// GOOD
element.textContent = userInput;        // text-safe
element.setAttribute('data-x', userInput);  // attribute-safe
```

CSP minimum: `default-src 'self'; script-src 'self'; object-src
'none'; frame-ancestors 'none'; base-uri 'self';`. No
`unsafe-inline` or `unsafe-eval`.

---

## CSRF

**Pattern:** CSRF token on every state-changing request. Use
`SameSite=Lax` (or Strict) on session cookie. API endpoints using
`Authorization` header are CSRF-immune.

```php
// Server-side: validate on every POST/PUT/PATCH/DELETE
if (!hash_equals($_SESSION['csrf_token'], $_POST['_csrf'])) {
    http_response_code(403); exit;
}
```

---

## IDOR / BOLA

**Pattern:** authorization at the data-access layer, scoped to the
authenticated user. Never trust IDs from the request alone.

```php
// BAD
$order = Order::find($_GET['id']);

// GOOD
$order = Order::where('id', $_GET['id'])
              ->where('user_id', auth()->id())
              ->firstOrFail();

// Or via policy
$this->authorize('view', $order);
```

For multi-tenant: every query includes `tenant_id`. Consider DB-
level row-level security if available.

---

## Mass-assignment

**Pattern:** explicit allowlist of writable fields per model /
serializer. Deny by default.

```php
// Laravel
class User extends Model {
    protected $fillable = ['name', 'email'];   // role NOT here
}

// Django
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['name', 'email']    # role NOT here

// Rails
def user_params
  params.require(:user).permit(:name, :email)   # role NOT here
end
```

---

## SSRF

**Pattern:** never directly fetch user-supplied URLs. If you must
(e.g. avatar URL, webhook tester):

1. Parse the URL with a strict library.
2. Resolve hostname → IP.
3. Reject if IP is in private / link-local / metadata ranges
   (`127.0.0.0/8`, `10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12`,
   `169.254.0.0/16`, `::1/128`, `fc00::/7`, `fe80::/10`).
4. Reject if scheme is not http/https.
5. Make the request from an isolated network egress (no metadata
   reach).
6. Pin the resolved IP for the actual request to prevent DNS
   rebinding.

Allowlist preferred over blocklist when possible.

---

## File upload

**Pattern:**
1. Validate by content (libmagic), not extension.
2. Generate fresh random filename on storage.
3. Store outside webroot, OR serve via download script with auth.
4. Re-encode images via Imagick / GD to strip payloads.
5. Rate-limit per user.
6. Antivirus scan if your stack runs untrusted users' uploads.

---

## Authentication

**Pattern:**
- Argon2id / bcrypt for password storage.
- Server-side rate limiting (per-account AND per-IP, with
  exponential backoff).
- Have-I-Been-Pwned check on registration and change.
- 2FA available, optional default, enforced for admins.
- Session ID rotation on login / privilege change / password change.
- HttpOnly + Secure + SameSite=Lax cookies.
- Logout invalidates server-side session immediately.

---

## Password reset

**Pattern:**
- 32-byte random token from CSPRNG.
- Single-use, server-side enforced.
- Short expiry (~30 minutes).
- Bound to user (and ideally to fingerprint of requester).
- URL constructed without trusting Host header — use a fixed app
  base URL.
- Generic response regardless of email existence.
- Notification email to original address ("we received a reset
  request"; "your password was changed").

---

## JWT

**Pattern:**
- Algorithm pinned server-side (no `alg: none`, no algorithm
  confusion).
- Strong signing key (256-bit minimum for HS256; or RS256 with
  rotated keys).
- Short access token expiry (15 min); refresh token rotation on
  use; revocation on logout.
- `aud`, `iss`, `nbf`, `exp` validated.
- No sensitive claims trusted server-side beyond user_id.
- Bind to context (fingerprint, IP for sensitive ops) where
  possible.

---

## Race conditions

**Pattern:**
- Database row-level locks (`SELECT ... FOR UPDATE`) for state
  changes.
- Optimistic concurrency: version column, retry on conflict.
- Idempotency keys for client-initiated operations (payments,
  refunds): every key resolves to one outcome.
- Rate-limit per-user-per-action.
- For balance / inventory, atomic SQL operations
  (`UPDATE balance SET amount = amount - ? WHERE user_id = ? AND
  amount >= ?`).

---

## Webhook signature

**Pattern:**
- HMAC-SHA256 with shared secret (or asymmetric signing).
- Timestamped to prevent replay; reject older than ~5 min.
- Constant-time comparison (`hash_equals` / `crypto.timingSafeEqual`).
- Verify *before* parsing / acting on body.
- Idempotency to handle delivery retries.

---

## Rate limiting

**Pattern:** layered.
- Per-IP global rate limit at edge (CDN / WAF / API gateway).
- Per-account rate limit at app layer.
- Per-action limits (login, password reset, registration, sensitive
  operations stricter).
- Progressive backoff (exponential or step-up).
- Lockout messages indistinguishable for valid vs invalid users.

---

## Secrets management

**Pattern:**
- Never in code, never in env vars in git, never in CI logs.
- Use a secrets manager (AWS Secrets Manager, GCP Secret Manager,
  Azure Key Vault, HashiCorp Vault, Doppler, 1Password).
- Rotation on schedule and on incident.
- Least-privilege IAM for the principal that retrieves secrets.

---

## Logging

**Pattern:**
- Authentication events (success / failure) logged with user, IP,
  UA, time.
- Authorization decisions for sensitive endpoints (deny logs at
  least; allow logs for high-value).
- Admin / staff actions immutably logged.
- PII redacted from logs.
- Centralized + immutable + alerting.

---

## CORS

**Pattern:**
- Allowlist of trusted origins (no wildcard with credentials).
- Per-API decision: which origins, which methods, which headers.
- Credentials only when necessary.
- Preflight handled correctly.

---

## CSP

**Pattern:** start strict, relax only as required.

```
default-src 'self';
script-src 'self' 'nonce-<random>';
style-src 'self' 'nonce-<random>';
img-src 'self' data: https:;
connect-src 'self' https://api.example.com;
object-src 'none';
frame-ancestors 'none';
base-uri 'self';
form-action 'self';
upgrade-insecure-requests;
report-uri /csp-violation;
```

Iterate. Avoid `unsafe-inline` / `unsafe-eval`.

---

## TLS

**Pattern:**
- TLS 1.2 minimum, TLS 1.3 preferred.
- Cipher suites: forward secrecy, AEAD only.
- Certificate from public CA, monitored for expiry.
- HSTS with `includeSubDomains; preload; max-age=31536000`.
- CAA DNS records to constrain CA issuance.
