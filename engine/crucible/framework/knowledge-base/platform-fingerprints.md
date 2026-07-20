# Platform fingerprints

Common application stacks and platforms with their characteristic
fingerprints, security gotchas, and known issue classes. Used during
recon (Stages 2–3) to identify the target stack and prime
hypotheses for Stage 4.

---

## Identification cues

For any target, look at:
- HTTP response headers (`Server`, `X-Powered-By`).
- Cookie names (each framework has signature cookie names).
- Default error pages.
- URL patterns (`/wp-admin`, `/admin/index.php`, `/.well-known/`).
- HTML markers (generator meta, comment banners, asset paths).
- JS bundle filenames and content.
- Status codes for known paths (`/login.php` 200 vs 404).

---

## SMM panels (Social Media Marketing reseller panels)

### Perfect Panel

- Cookie: `PHPSESSID`, often `XSRF-TOKEN` and Laravel-shaped
  cookies.
- Asset CDN: `cdn.glycon.net`, `storage.perfectcdn.com`.
- Routes: `/services`, `/api/v2`, `/admin/services`,
  `/admin/orders`, `/api/v2/admin/orders`.
- Tech: PHP / Laravel.
- API: legacy `POST /api/v2` with `key` + `action` body params
  (older protocol).

Common issues seen:
- IDOR on order status endpoints.
- API rate-limit per-IP only.
- Mass-assignment on user profile updates.
- Webhook callback validation gaps for child-panel integrations.
- Refund-loop race conditions.
- Stored XSS in service-name / order-link fields visible in admin
  list.

### Smartpanel / Gainpanel / others

Similar API contract pattern (`POST /api/v2 + key + action`). Same
class of issues. Stack often PHP/MySQL. Test the same areas.

---

## CMSes

### WordPress

- Path: `/wp-admin/`, `/wp-content/`, `/wp-json/`.
- Cookie: `wordpress_*`, `wp-settings-*`.
- Markers: `<meta name="generator" content="WordPress">`.
- API: `/wp-json/wp/v2/users` — often public, leaks usernames.
- Plugins are the dominant attack surface; use `wpscan`.

### Drupal

- Path: `/user/`, `/admin/`, `/?q=node`.
- Cookie: `SESS<hash>`.
- Marker: `Drupal.settings`, `X-Generator: Drupal`.
- Drupal 7 vs 8/9/10 have different vuln classes.

### Joomla

- Path: `/administrator/`, `/components/`.
- Cookie: random + session.
- Marker: `Joomla! - Open Source Content Management`.

### Magento (e-commerce)

- Path: `/admin/`, `/index.php/admin/`, `/static/version<N>/`.
- Cookie: `frontend_*`.
- Magento 1 EOL (deprecated) but still seen.
- Common: payment integration weakness, IDOR on cart, admin enum.

---

## Web frameworks

### Laravel (PHP)

- Cookie: `XSRF-TOKEN`, `laravel_session`.
- Header: `X-Powered-By: PHP`, sometimes `Server: nginx`.
- Routes: `/sanctum/csrf-cookie`, common admin under
  `/nova/`, `/horizon/`, `/telescope/`.
- Stack hints: `php artisan` references in error pages, Symfony
  components, `Whoops!` debug page if APP_DEBUG=true (Critical
  if present).

Watch for:
- `APP_DEBUG=true` in production → full stack traces, env exposure.
- `.env` accessible at /.env (very common).
- Telescope / Nova / Horizon dashboards exposed.
- Mass-assignment without `$fillable` allowlist.
- Old custom validation rules.

### Django (Python)

- Cookie: `csrftoken`, `sessionid`.
- Header: `Server: WSGIServer/...`.
- Marker: default 404/500 pages, `Django administration` at
  `/admin/`.

Watch for:
- `DEBUG=True` in production (Werkzeug-style error pages).
- Django admin exposed without 2FA.
- Static / media misconfig.
- Old serializers without explicit fields.

### Ruby on Rails

- Cookie: `_<app>_session`.
- Marker: `<meta name="csrf-param">`, `Rails` in source comments
  if dev mode.
- Typical paths: `/users/sign_in` (Devise).

Watch for:
- Strong params not enforced (mass-assignment).
- Devise email enumeration.
- ActiveStorage / CarrierWave file upload gaps.

### Express / Node.js

- Cookie: varies by middleware (`connect.sid`, `session`).
- Header: often hidden, but `ETag` / cache headers can hint.
- Routes: framework-specific.

Watch for:
- Prototype pollution in deps.
- `helmet` not configured (no security headers).
- JWTs with weak secrets.
- Async race conditions in middleware ordering.

### ASP.NET / .NET Core

- Cookie: `.AspNetCore.*`, `.ASPXAUTH`.
- Header: `Server: Microsoft-IIS/...`, `X-Powered-By: ASP.NET`.
- Markers: `__VIEWSTATE` field on legacy WebForms, `RequestVerificationToken`.

Watch for:
- ViewState deserialization (legacy).
- Auth cookie tampering (encryption vs signing).
- Misconfigured CORS.

### Spring Boot (Java)

- Header: `Server: Apache-Coyote` or no header.
- Path: `/actuator/` Spring Boot Actuator.
- Markers: Tomcat / Jetty default error pages.

Watch for:
- Spring Boot Actuator endpoints (`/actuator/env`, `/actuator/heapdump`)
  exposing secrets.
- Spring4Shell-style injection.
- Misconfigured Spring Security antMatchers.

---

## Frontend stacks

### Next.js / Vercel / Nuxt

- Path: `/_next/static/`, `/__nuxt/`.
- Edge-config: API routes under `/api/`.

Watch for:
- API routes with weak auth (often more permissive than backend
  proper).
- SSR injection (XSS via stale cache).

### Single-page apps (React / Vue / Svelte / Angular)

- Asset paths reveal framework.
- Tokens often in localStorage (XSS reads them).
- Routes are client-side; backend API is the real surface.

---

## Cloud / hosting fingerprints

| Cloud | Cues |
|-------|------|
| AWS | IP in AWS ranges; `x-amz-cf-id`, `cloudfront.net`; `s3.amazonaws.com` for assets |
| GCP | `googleusercontent.com`, `storage.googleapis.com`; IP in GCP ranges |
| Azure | `azurewebsites.net`, `azureedge.net`, `core.windows.net` |
| Cloudflare | `cf-ray` header, `__cfduid` / `cf_clearance` cookies |
| Fastly | `x-served-by`, `x-cache`, `via: ... varnish` |
| DigitalOcean | IP in DO ranges; sometimes `digitaloceanspaces.com` |
| Heroku | `*.herokuapp.com` or origin headers `via: vegur` |
| Vercel | `x-vercel-id` header, `*.vercel.app` |
| Netlify | `x-nf-request-id` header |

---

## Database / cache fingerprints (in error messages)

| Engine | Error fragment |
|--------|----------------|
| MySQL | `You have an error in your SQL syntax`, `MySQL server version` |
| PostgreSQL | `PostgreSQL`, `pg_query()` |
| MS SQL | `Unclosed quotation mark`, `Microsoft OLE DB Provider` |
| SQLite | `SQLite/JDBCDriver`, `sqlite3.OperationalError` |
| MongoDB | `MongoDB`, `BSON` |
| Redis | `WRONGTYPE`, `MOVED`, `LOADING` |
| ElasticSearch | `elasticsearch_exception`, JSON-shaped errors |
| Oracle | `ORA-` codes |
| DB2 | `SQL0` codes |

---

## Generic anti-patterns common across stacks

- Debug mode left on in production.
- Default landing pages still served.
- Default credentials still active.
- Backups in webroot.
- `.git` directory accessible.
- Old API versions still routed.
- Test endpoints in production (`/test`, `/debug`, `/admin/test`).
- Source maps published (`.js.map`).
- `phpinfo()` test page.
