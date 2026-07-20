# Threat model — `mrbeanpanel.com`

**Status:** DRAFT (URK fallback). Archetype: **PHP-Smarty SMM-panel fork** (`php-smarty-smm-panel-fork`).

URK was unavailable; this skeleton was synthesized from the archetype and the intake fingerprint. Refresh by hand or re-run with a live LLM.

## Archetype-derived top concerns

- webhook-forgery
- IDOR
- mass-assignment
- race
- SQLi
- vertical-privesc
- source-disclosure
- reset-token

## Fingerprint signals

```
target_url: https://mrbeanpanel.com
api: rest (0.70)
auth: php-session (0.98)
cdn_waf: hsts (1.00)
cms: perfect-panel (1.00)
framework: perfect-panel (0.99)
server: nginx (1.00)
security_headers: Strict-Transport-Security=max-age=31536000;, Content-Security-Policy=frame-ancestors 'self', frame-ancestors , X-Frame-Options=sameorigin, sameorigin
cookies: PHPSESSID, _csrf, _usid, _ppref, _csrf_admin
```
