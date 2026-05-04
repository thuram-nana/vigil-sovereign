# Playbook 02 — Active recon

**Goal:** lightly fingerprint in-scope hosts, confirm platform/version
hypotheses from passive recon, and surface obvious exposures. First
phase that sends packets to the target.

**Outputs:** `targets/<name>/recon/active/`.

Throttle. The operator's app has real users on it.

---

## 2.1 Live host probe

```bash
mkdir -p targets/<name>/recon/active && cd $_

cat ../passive/all-subdomains.txt \
  | httpx -silent -status-code -title -tech-detect -tls-probe \
          -follow-redirects -threads 5 -rate-limit 30 \
          -H "User-Agent: OBSIDIAN/1.0 (authorized owner-test)" \
  | tee httpx-results.txt
```

Cross-check every host against the charter's in-scope list. **Hosts
that respond but aren't in scope, do not test further.** Add to
`notes/scope-questions.md` for operator confirmation.

## 2.2 TLS / certificate hygiene

```bash
# Cipher suites, protocol versions, cert details
nmap --script ssl-enum-ciphers,ssl-cert -p 443 <target> -oN nmap-tls.txt

# Or testssl.sh for a deeper TLS audit
testssl.sh --jsonfile testssl-results.json https://<target>/

# Headers
curl -skI "https://<target>/" \
  -H "User-Agent: OBSIDIAN/1.0 (authorized owner-test)" \
  | tee headers-root.txt
```

Findings (typically Low/Info but worth a quick win bundle):
- TLS 1.0/1.1 enabled.
- Weak ciphers (RC4, 3DES, NULL, EXPORT, CBC modes with TLS<1.2).
- Cert expiring soon / wrong SAN / wildcard misuse.
- Missing `Strict-Transport-Security`.
- Missing `Content-Security-Policy`, `X-Frame-Options`,
  `Referrer-Policy`, `Permissions-Policy`.
- `Server:` header exposing version.
- `X-Powered-By:` leaking PHP / framework version.

## 2.3 Port scan (in-scope hosts only)

```bash
# Top 1000 TCP, low rate
nmap -sS -T3 --top-ports 1000 --max-retries 2 \
  -oN nmap-top1000.txt <target>

# Then, only ports that came back open: version detection
# Replace 80,443 with what's actually open
nmap -sV -sC -p 80,443 -oN nmap-versions.txt <target>

# UDP top 100 — slow but worth it
sudo nmap -sU --top-ports 100 -T2 -oN nmap-udp.txt <target>
```

Flags:
- Anything beyond 80/443 publicly exposed (3306 MySQL, 5432 Postgres,
  6379 Redis, 9200 ES, 27017 Mongo, 11211 Memcached, 9000 PHP-FPM,
  22 SSH with password auth, 8080/8888/9999/etc admin panels).
- Service version with known CVEs.
- Outdated OpenSSH, banners disclosing OS version.

For wider host ranges (entire ASN where applicable):
```bash
masscan -p1-65535 --rate=1000 <ip-range> -oG masscan.txt
naabu -host <target> -p - -rate 1000 -o naabu.txt   # alternative, rate-limited
```

## 2.4 Web server fingerprint

```bash
whatweb -a 3 "https://<target>/" | tee whatweb.txt
wappalyzer-cli "https://<target>/" > wappalyzer.json 2>/dev/null
```

Compare against passive-phase platform hypothesis. If platform is a
known stack (Perfect Panel, WooCommerce, etc.) version-pin and
cross-reference public changelogs for known issues since that
version.

Record to `platform-version.md`.

## 2.5 Initial nuclei sweep — low-noise templates

Do **not** run nuclei with all templates against production on first
pass. Start with curated low-noise sets:

```bash
# Exposures + misconfig + technologies — safe and high-signal
nuclei -u "https://<target>/" \
  -t exposures/ -t misconfiguration/ -t technologies/ \
  -severity info,low,medium,high,critical \
  -rate-limit 30 -c 10 -silent \
  -H "User-Agent: OBSIDIAN/1.0 (authorized owner-test)" \
  -o nuclei-exposures.txt
```

Review every hit manually; nuclei has false positives. Save the
exploit-template pass for after Stage 4 mapping when you understand
the surface.

## 2.6 robots.txt, sitemap, well-known

```bash
for path in robots.txt sitemap.xml sitemap_index.xml \
            .well-known/security.txt .well-known/openid-configuration \
            humans.txt ads.txt; do
  curl -s -o "${path//\//_}.txt" -w "$path %{http_code}\n" \
    "https://<target>/$path"
done
```

`robots.txt` Disallow entries are *always* candidates for content
discovery — listed there because the operator considered them
sensitive.

`.well-known/openid-configuration` exposes OAuth/OIDC endpoints if
the app uses federated auth.

## 2.7 The "obvious leaks" pass

Single most common critical finding on apps in this class:

```bash
PATHS=(
  ".env" ".env.bak" ".env.local" ".env.production" ".env.development"
  ".git/config" ".git/HEAD" ".git/index" ".git/logs/HEAD"
  ".svn/entries" ".hg/store"
  "config.php.bak" "config.bak" "config.old" "config.inc.php"
  "wp-config.php" "wp-config.bak"
  "backup.zip" "backup.tar.gz" "backup.sql" "dump.sql" "db.sql"
  "site.zip" "www.zip" "html.zip"
  ".DS_Store" ".idea/workspace.xml" ".vscode/settings.json"
  "phpinfo.php" "info.php" "test.php" "_phpinfo.php"
  "server-status" "server-info"
  "debug.log" "error.log" "laravel.log"
  "composer.json" "composer.lock" "package.json" "package-lock.json"
  "Dockerfile" "docker-compose.yml" "docker-compose.yaml"
  "yarn.lock" ".npmrc" ".yarnrc"
  "README.md" "CHANGELOG.md"
  "vendor/" "node_modules/"
  "storage/logs/laravel.log" "app/etc/env.php"
  ".aws/credentials" ".aws/config"
  ".kube/config"
  "id_rsa" "id_dsa" "id_ed25519"
  "deployment.yaml" "k8s/secrets.yaml"
)

UA="OBSIDIAN/1.0 (authorized owner-test)"
: > obvious-leaks.txt
for p in "${PATHS[@]}"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "User-Agent: $UA" --max-time 6 "https://<target>/$p")
  printf "%s  /%s\n" "$code" "$p" >> obvious-leaks.txt
done
```

Any 200 to one of these is critical. A 403 means file exists,
server denies — sometimes still leakable via path tricks. Verify
manually.

## 2.8 DNS hygiene

```bash
dig +short txt <target>                              # SPF
dig +short txt _dmarc.<target>                       # DMARC
dig +short txt default._domainkey.<target>           # DKIM (selector varies)
dig +short caa <target>                              # CAA
dig +short DS <target>                               # DNSSEC
dig +short ANY <target>                              # general
dnsx -d <target> -r 1.1.1.1 -wd -silent              # wildcard check
```

Findings:
- No SPF / `~all` softfail → spoofing easier.
- No DMARC / `p=none` → spoofing not actively blocked.
- No DKIM → email spoofing trivial.
- No CAA → any CA can issue certs for the domain.
- Wildcard A record (`*.<target> → IP`) → cookie scope risk and
  takeover risk.

Phishing impersonating support is a real "users getting hacked"
vector even when the app itself is hardened.

## 2.9 Cloud / hosting fingerprint

Look at IP ranges:
- AWS IP ranges (`https://ip-ranges.amazonaws.com/ip-ranges.json`)
- GCP, Azure, DigitalOcean, Cloudflare ranges similarly.

If hosted on a major cloud, note for cloud playbook (Stage 4 §13).
If behind Cloudflare / similar, the origin IP may be discoverable
via:
- Historical DNS (passive recon).
- SSL certificates indexed on shodan.io / censys.io.
- Subdomains that don't go through the proxy (`mail.`, `dev.`).
- Email headers from the operator's outbound mail.

Note origin discoverability as a finding if it was supposed to be
hidden.

## 2.10 Output

In `targets/<name>/recon/active/`:

- `httpx-results.txt`
- `nmap-top1000.txt`, `nmap-versions.txt`, `nmap-tls.txt`,
  `nmap-udp.txt`
- `headers-root.txt`, `whatweb.txt`, `wappalyzer.json`
- `nuclei-exposures.txt`
- `robots.txt`, `sitemap.xml`, `_well-known_*.txt`
- `obvious-leaks.txt`
- `dns-hygiene.txt`
- `platform-version.md`

Phase summary in `notes/engagement-log.md`:

1. Confirmed platform + version.
2. Hosts / ports in scope and live.
3. Immediate critical findings (exposed files, debug pages, weak TLS).
4. Hypotheses for Stage 3 mapping.

Ask operator to advance.
