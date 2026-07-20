# Playbook 12 — Network and infrastructure

**Goal:** find non-application-layer issues — exposed services, weak
TLS, server misconfig, leaked admin paths, default credentials, DNS
hygiene gaps, email auth missing.

Most touched in playbook 02 (active recon); this playbook is the
deeper focused pass.

---

## 12.1 Exposed services

```bash
# Full TCP port scan (low rate)
nmap -sS -p- -T2 --max-retries 2 -oN nmap-allports.txt <target>

# UDP top 100
sudo nmap -sU --top-ports 100 -T2 -oN nmap-udp.txt <target>

# Service-version scan on what's open
nmap -sV -sC -p <ports> -oN nmap-versions.txt <target>
```

For every open port beyond 80/443:
- What service / version?
- Should it be public-facing?
- Default credentials? CVEs for that version?

Common bad finds:
- 6379 Redis — usually no auth in default config; remote code
  execution via SLAVEOF or module load.
- 9200 ElasticSearch — historically full DB read.
- 27017 MongoDB — historically full DB read.
- 3306 MySQL — credential brute-force.
- 5432 Postgres — credential brute-force.
- 11211 Memcached — sensitive cache read.
- 9000 PHP-FPM — RCE if reachable.
- 8080/8888/9090 — staging / admin panels.
- 22 SSH with password auth — brute force vector.
- 25/465/587 SMTP — open relay test (be careful).
- 2375/2376 Docker daemon — full container takeover.
- 10250 Kubelet — node takeover.
- 6443 Kubernetes API server — anonymous access?

For broad sweeps:
```bash
masscan -p1-65535 --rate=1000 <ip-range>     # carefully and rate-limited
naabu -host <target> -p - -rate 1000
```

---

## 12.2 Subdomain pass

For every in-scope subdomain:
- Is it production, staging, dev, or unused?
- Same nmap pass.
- Authentication on staging? Often left open.
- Different versions of the app?
- Internal-only services accidentally exposed?

---

## 12.3 Header hardening

| Header | Expected |
|--------|----------|
| `Strict-Transport-Security` | `max-age >= 31536000; includeSubDomains; preload` |
| `Content-Security-Policy` | scoped, no `unsafe-inline` |
| `X-Frame-Options` | `DENY` or `SAMEORIGIN` (or CSP frame-ancestors) |
| `X-Content-Type-Options` | `nosniff` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` or stricter |
| `Permissions-Policy` | restrict camera, geo, microphone |
| `Cache-Control` (auth pages) | `no-store` |
| `Server` | redacted or generic |
| `X-Powered-By` | absent |

---

## 12.4 DNS hygiene

```bash
dig +short txt <target>                       # SPF
dig +short txt _dmarc.<target>                # DMARC
dig +short txt default._domainkey.<target>    # DKIM
dig +short caa <target>                       # CAA
dig +short DS <target>                        # DNSSEC
dig +short ANY <target>
dnsx -d <target> -r 1.1.1.1 -wd               # wildcard
```

Findings:
- No SPF / `~all` softfail.
- No DMARC / `p=none`.
- No DKIM.
- No CAA (any CA can issue).
- Wildcard A records (cookie scope, takeover risk).
- Open DNS resolver / zone transfer (`dig AXFR @<ns> <target>`).

---

## 12.5 Email auth

Real ATO vector: phishing emails impersonating support. If DMARC
isn't `quarantine` or `reject`, attackers can spoof
`support@<domain>` with high deliverability.

Test by sending yourself a spoofed email (own server, set From to
target's domain) and check deliverability to your test mailbox.

---

## 12.6 Web server config

- Directory listing on uploads, static, backups (`Index of`).
- `TRACE` enabled (XST risk).
- Default error pages disclosing stack/version.
- `.htaccess` / `web.config` directly readable.
- `crossdomain.xml` permissive (legacy Flash).
- Server version banners.

---

## 12.7 Default / weak credentials

Carefully (with operator's lockout understanding):
- `admin/admin`, `admin/password`, `admin/12345`.
- Vendor defaults from `framework/knowledge-base/default-credentials.md`.

---

## 12.8 Database / cache exposure

If 3306 / 5432 / 6379 / 27017 / 9200 / 11211 are open:

```bash
# MySQL anonymous
mysql -h <target> -u root -p ''

# Postgres
psql -h <target> -U postgres

# Redis (no auth)
redis-cli -h <target> ping
redis-cli -h <target> info

# Mongo
mongosh "mongodb://<target>:27017"

# ES
curl -sk "http://<target>:9200/_cluster/health"
```

Anonymous read = Critical. Try carefully.

---

## 12.9 Cloud metadata

Already in playbook 08 (SSRF). Re-verify here that none of the
exposed services proxy to metadata.

---

## 12.10 Output

Findings filed. Phase summary:
- Open ports & services / versions.
- Subdomain risk inventory.
- Header / TLS gaps.
- Email auth posture.
- Default-cred findings.
- Database / cache exposure.
