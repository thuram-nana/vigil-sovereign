# CSRF — technique reference

## 1. Mental model

CSRF = forcing a logged-in victim's browser to issue a state-changing
request to the target site, without their intent. The attacker doesn't
need to read the response — they only need the request to occur with
victim's authority (cookies, NTLM, etc.).

The defenses fall in two categories:

- **Origin-bound credentials** — `SameSite=Strict|Lax` cookies, custom
  authentication headers (Authorization: Bearer requires JS to add).
- **Anti-CSRF tokens** — synchronizer tokens, double-submit cookies,
  encrypted tokens.

CSRF lost much of its potency in modern browsers because `SameSite=Lax` is
default. But: many apps still vulnerable due to misconfiguration, missing
`SameSite` flag, exempted endpoints (`SameSite=None` for cross-site flows),
or token validation bugs.

## 2. Detection

For every state-changing endpoint:

- Inspect cookies: `Set-Cookie: session=...; SameSite=<?>`
- Inspect for CSRF token: hidden form field, header, query parameter
- Try cross-origin POST without token; succeed = vulnerable
- Try with `SameSite=None` (HTML form auto-submits include cookies if
  site lacks Strict/Lax)

Quick HTML PoC harness:

```html
<!DOCTYPE html>
<html><body>
<form action="https://target.tld/api/change-email" method="POST">
  <input name="email" value="attacker@evil.tld">
  <input type="submit">
</form>
<script>document.forms[0].submit();</script>
</body></html>
```

Open in attacker's browser while logged into target in same browser.
Request fired; if success: CSRF.

## 3. Token validation bypasses

Even when tokens present, common bugs:

| Bug | Test |
|-----|------|
| Token not validated for some methods | works on PUT/DELETE/PATCH but not POST? |
| Token validation if-present | omit `csrf_token` parameter entirely |
| Token validated only for known cookie | log out, send request without session, with arbitrary CSRF token |
| Token tied to session but not user | use attacker's CSRF token on victim's session (if shared session ID family) |
| Double-submit weakness | token in cookie + body must match — if `Set-Cookie` accepts cookie injection from subdomain, can set both |
| Token validation case-sensitive bug | upper/lower case bypasses some impl |
| Token via header but also via body | omit header, supply body — accepted? |

## 4. SameSite bypasses

| Defense state | Bypass |
|---------------|--------|
| `SameSite=Strict` | navigation-based attacks fail; iframe-embedding fails; only top-level user-initiated nav works |
| `SameSite=Lax` (default in Chrome) | top-level GET works cross-site; POST fails. So if app accepts state change on GET → CSRF still works. |
| `SameSite=Lax` 2-min window | Chrome allows POST cross-site for 2 min after cookie set on first-party context — narrow opportunity |
| No `SameSite` (legacy / default-None per server) | classic CSRF works |
| `SameSite=None; Secure` | classic CSRF works (intended for cross-site flows) |

GET-with-side-effects on `Lax` is a common bug: app uses GET for
`/admin/delete-user/123`. Attacker links victim → CSRF.

## 5. JSON & "preflight" considerations

A simple POST with `Content-Type: application/json` triggers a CORS
preflight (unless server returns `Access-Control-Allow-Origin: *` or
matching origin). Without CORS approval, browsers don't send the JSON.

But:

- `Content-Type: text/plain` → no preflight, body still sent
- Some apps accept `application/x-www-form-urlencoded` and parse JSON-shaped
  body → CSRF possible without preflight
- HTML form submission with `enctype=text/plain` → "name=value" body;
  some JSON parsers accept this if value looks like JSON

```html
<form action="https://target.tld/api" method="POST" enctype="text/plain">
  <input name='{"role":"admin","trash":"' value='"}'>
</form>
```

Submitted body: `{"role":"admin","trash":"=`"}`` — close enough to fool some
naive parsers.

## 6. Login CSRF

Force victim to log in as attacker. Subsequent actions taken by victim are
recorded against attacker's account → privacy / data leakage / supply
chain.

Defense: require CSRF token on login form, use `SameSite=Lax` minimum.

## 7. Logout CSRF

Force victim to log out (annoyance / DoS / setup for phishing relogin).
Lower severity but should be protected on principle.

## 8. CORS-based variants

Misconfigured CORS that reflects `Origin: <anything>` and allows credentials
turns "no preflight needed" into "preflight succeeds for attacker". Combined
with auth: attacker reads responses cross-origin too — pivots from CSRF
(blind write) to full data theft.

Test: set `Origin: https://attacker.tld` + `Cookie: session=...`, observe
response headers `Access-Control-Allow-Origin` and `Access-Control-Allow-
Credentials`.

## 9. CSRF in API tokens

Apps using `Authorization: Bearer ...` from JS are not CSRF-vulnerable in
the classic sense (header isn't auto-added by browsers). Cookies-with-
session ARE. Mixed apps (cookie-bearer fallback) need testing both ways.

## 10. Source-code review

```
# Frameworks with built-in CSRF: look for opt-out
grep -rEn "csrf_exempt|skip_before_action :verify_authenticity_token" --include='*.py' --include='*.rb'
grep -rEn "@CrossOrigin|@CrossOriginAttribute|disable.*csrf|csrf\(\)\.disable\(\)" --include='*.java' --include='*.cs'
grep -rEn "app\.use\(csurf\)" --include='*.js'   # then check absence
grep -rEn "useCsrfMiddleware|csrfProtection"

# State-changing GETs
grep -rEn "GET.*delete|GET.*remove|@GetMapping.*delete" --include='*.java'
grep -rEn "method:\s*['\"]GET['\"].*delete|router\.get.*remove" --include='*.js'

# JSON parsing of form bodies
grep -rEn "request\.form\[.*JSON|JSON\.parse\(req\.body\)"
```

## 11. Defenses (for remediation)

1. **`SameSite=Lax` (or `Strict`)** on all auth cookies — handle the
   minority of true cross-site flows explicitly.
2. **CSRF tokens** for any state-changing request that uses cookie auth;
   per-session or per-form.
3. **Origin / Referer header check** as defense-in-depth (not primary).
4. **No GET for state-changing actions.**
5. **Custom headers** for AJAX (e.g. `X-Requested-With`) — browsers
   require CORS preflight for non-simple requests, and attacker can't add
   these from cross-origin form.
6. **Re-auth for sensitive actions** — password change, email change,
   payment method change require current password.
7. **No `SameSite=None` without strong CSRF tokens** if you must allow
   cross-site usage.

## 12. CWE / standards mapping

- CWE-352 — CSRF
- OWASP WSTG WSTG-SESS-05
- OWASP ASVS V4.2
