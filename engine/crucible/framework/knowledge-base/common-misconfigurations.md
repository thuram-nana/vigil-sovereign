# Common misconfigurations

Patterns of environment, deployment, and code-level misconfiguration
that recur across engagements. When a target shows any of these,
the corresponding finding is fast to confirm.

---

## 1. Debug / development mode in production

| Sign | Stack |
|------|-------|
| `Whoops! There was an error.` page | Laravel, Symfony |
| Werkzeug interactive debugger | Flask, Django |
| Detailed React / Webpack source map errors | SPA |
| `error_reporting(E_ALL); ini_set('display_errors', 1);` | PHP |
| `DEBUG=True` env var | Django / Flask |
| `APP_ENV=local` or `APP_DEBUG=true` | Laravel |
| `RAILS_ENV=development` | Rails |
| Spring Boot Actuator exposing /env, /heapdump | Spring |
| Verbose Express stack traces | Node |

Always Critical / High when found in production.

---

## 2. Backup files in webroot

```text
.env, .env.bak, .env.local, .env.production
config.php.bak, config.bak, config.old
backup.zip, backup.tar.gz, site.zip, www.zip
db.sql, dump.sql, database.sql
.git/, .svn/, .hg/
*.swp (vim), *~ (gedit), *.orig (merge conflicts)
```

When `.git/` is accessible, dump the repo via `git-dumper` /
`gitdumper.sh`. Often yields full source.

---

## 3. Verbose error responses

- Stack traces in 500 responses.
- DB error messages disclosing table / column names.
- Internal file paths.
- Library versions in error pages.
- Different errors for "not found" vs "forbidden" enabling enum.

---

## 4. Default landing pages / dashboards

- Apache / Nginx / IIS default page on a subdomain → unused subdomain
  (often takeover candidate or staging).
- phpMyAdmin / Adminer reachable.
- Webmin / Plesk / cPanel exposed.
- Server-status / Server-info on Apache.
- nginx_status.

---

## 5. Cloud storage missetup

- S3 bucket public-readable / writable.
- GCS bucket `allUsers: roles/storage.objectViewer`.
- Azure Blob anonymous access.
- Backups stored in same public bucket.
- CORS allowing `*` on storage.

---

## 6. Permissive CORS

- `Access-Control-Allow-Origin: *` with credentials.
- Reflective `Access-Control-Allow-Origin` on any submitted Origin.
- `Access-Control-Allow-Credentials: true` paired with broad ACAO.
- Subdomain wildcards covering takeover-prone subs.

---

## 7. Missing security headers

- No HSTS, or short max-age.
- No CSP.
- No X-Frame-Options / frame-ancestors.
- No X-Content-Type-Options.
- No Referrer-Policy.
- No Permissions-Policy.

---

## 8. Cookie attribute gaps

- Session cookie without `HttpOnly`.
- Session cookie without `Secure`.
- Session cookie with broad `Domain=.example.com` to cover insecure
  subdomains.
- Missing `SameSite=Lax/Strict` on session cookie.

---

## 9. Permissive file upload

- Allowing any extension.
- Trusting `Content-Type` from client.
- Storing in webroot without execute prevention.
- Filename used as-is in URL, enabling XSS or path injection.
- No file-size limit.

---

## 10. Open admin / management interfaces

- `/admin/` reachable without IP allowlist.
- `/wp-admin/` without 2FA.
- `/_admin`, `/manager`, `/console`, `/cms` exposed.
- Spring Actuator open.
- Kibana / Grafana / Prometheus / RabbitMQ-mgmt open.
- Kubernetes dashboard open.

---

## 11. Misconfigured rate limiting

- Per-IP only, no per-account.
- Per-account only, no per-IP.
- 1-min sliding window with reset (very forgiving).
- Different limits across endpoints inconsistent.
- Rate-limit on UI form but not on equivalent API endpoint.

---

## 12. Misconfigured authentication

- 2FA optional on user accounts but mandatory marketed.
- 2FA bypassable via password reset → no 2FA gate on reset.
- Session not rotated on login.
- Concurrent sessions allowed without notification.
- Weak password policy (≥6 chars allowed, no breach check).

---

## 13. Missing webhook signature verification

- Webhook receiver accepts any POST without HMAC verification.
- Webhook signature uses `==` (timing) instead of `hash_equals`.
- Webhook signature uses MAC instead of HMAC (length-extension).

---

## 14. Cache misconfig

- `Cache-Control: public` on authenticated pages.
- CDN caches `Set-Cookie` responses.
- Cache key doesn't include `Authorization` header → cross-user
  leak.
- `Vary: User-Agent` (cache balloons; weak segregation) instead of
  `Vary: Cookie` or proper auth-aware caching.

---

## 15. Misconfigured DNS

- Wildcard A record on apex.
- SPF / DMARC absent or `p=none`.
- DKIM not set.
- CAA absent (any CA can issue).
- No DNSSEC.
- Internal hostnames in public DNS.
- Open zone transfer.

---

## 16. Server header disclosure

- `Server: Apache/2.4.41 (Ubuntu)` discloses version.
- `X-Powered-By: PHP/7.4.3`.
- `X-AspNet-Version`.
- Custom headers naming internal infrastructure.

---

## 17. CI/CD misconfig

- Workflow trusts pull-request title/body in shell commands.
- Self-hosted runner picks up forks.
- `pull_request_target` checking out PR.
- Secrets logged to build output.
- Long-lived service account keys instead of OIDC federation.

---

## 18. Container misconfig

- Image runs as root.
- `--privileged` flag.
- Docker socket mounted into container.
- `latest` tag used in production.
- Secrets in env vars / image layers.
- No read-only root filesystem.

---

## 19. K8s / orchestration misconfig

- Default service account auto-mounted with broad RBAC.
- Pod with `hostNetwork: true`, `hostPID: true`, `hostIPC: true`.
- `hostPath` mounting to sensitive paths.
- No NetworkPolicy → flat namespace.
- Anonymous API server access.

---

## 20. Cloud IAM overprovisioning

- Wildcards in IAM policies.
- Long-lived access keys (>90 days).
- No MFA on console / IAM users.
- Cross-account roles trusting overly broad principals.
- `iam:PassRole` with `Resource: *`.
