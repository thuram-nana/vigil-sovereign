# Playbook 01 — Passive recon

**Goal:** gather everything observable about the target *without*
sending traffic to it. OSINT only.

**Stage in lifecycle:** 2.1.

**Outputs to:** `targets/<name>/recon/passive/`.

Why it matters: passive recon often surfaces forgotten subdomains,
old backups indexed by archive sites, leaked credentials in paste
sites, and exact platform versions — all without touching the live
system.

---

## 1.1 Domain and certificate intelligence

```bash
TARGET=<root.tld>
mkdir -p targets/<name>/recon/passive && cd $_

# Certificate transparency — finds subdomains operators forgot they own
curl -s "https://crt.sh/?q=%25.${TARGET}&output=json" \
  | jq -r '.[].name_value' | tr ',' '\n' | sed 's/^\*\.//' | sort -u \
  > crtsh.txt

# WHOIS / RDAP
whois "${TARGET}" > whois.txt 2>&1 || true

# Passive DNS via subfinder (uses many sources, no direct queries)
subfinder -d "${TARGET}" -all -silent > subfinder.txt
amass enum -passive -d "${TARGET}" 2>/dev/null > amass.txt || true

# ASN / IP space
asnmap -d "${TARGET}" -silent > asnmap.txt 2>/dev/null || true

cat crtsh.txt subfinder.txt amass.txt | sort -u > all-subdomains.txt
```

Look for:
- `staging.`, `dev.`, `test.`, `old.`, `beta.`, `qa.` — forgotten
  environments often retain old code with bugs.
- `admin.`, `panel.`, `api.`, `internal.`, `intranet.` — services
  meant to be private.
- Wildly different TLDs the operator forgot they owned.
- Hosts on shared IPs / ASNs that aren't theirs (third-party).

**Anything new** → ask the operator to confirm ownership before
adding to scope.

## 1.2 Wayback / archive

```bash
gau --subs "${TARGET}" --threads 5 > wayback-urls.txt 2>/dev/null
waybackurls < <(echo "${TARGET}") > waybackurls.txt 2>/dev/null

# Triage interesting URLs
grep -Ei 'token|key|secret|api_key|password|debug|test|admin|backup|\.env|\.git|\.bak|\.sql|\.zip' \
  wayback-urls.txt > wayback-interesting.txt
```

Old archived versions sometimes show:
- Endpoints that still exist but are no longer linked.
- Parameters removed from UI but still accepted.
- Leaked admin paths in old robots.txt or sitemap.xml.
- Tokens in URL parameters from old sessions (sometimes still valid).

## 1.3 Search engines and source repositories

Manual, in a browser (search engines block automation). Save
findings to `osint-search.md`.

- `site:${TARGET}` — what Google indexed.
- `site:${TARGET} inurl:admin` — exposed admin.
- `site:${TARGET} ext:sql OR ext:bak OR ext:log OR ext:env` — backups.
- `site:${TARGET} -site:${TARGET}/services` — non-public pages.
- `"${TARGET}" "Powered by"` web-wide — fingerprints platform.

GitHub:
- `"${TARGET}"` — leaked credentials, API keys, config in repos.
- `"${TARGET}" filename:.env`
- `"${TARGET}" filename:config.php`
- `"${TARGET}" filename:credentials`
- The operator's own old commits — diff history with `gitleaks` /
  `trufflehog` if you have access:
  ```bash
  trufflehog github --org=<org> --json > github-secrets.json 2>/dev/null
  gitleaks dir <local-path> --report-path gitleaks.json --report-format json
  ```

## 1.4 Paste / leak sites and credential corpora

- `intelx.io` (free tier limited) — search the domain and known
  emails.
- `haveibeenpwned.com` — for the operator's own email and any known
  support / admin emails. Don't paste real user emails (privacy).
- `dehashed.com`, `leakcheck.io`, `snusbase.com` — credential corpus
  searches by domain. Operator-only paid tiers; do this with
  operator's account or skip.
- `pastebin.com`, `ghostbin.com`, `gist.github.com` — search for
  domain and known internal terms.

If you find leaked credentials → `loot/leaked.md` (gitignored).
**Treat as Critical priority — surface to operator immediately.**

## 1.5 Asset and platform fingerprinting (passive)

From the homepage HTML and any pages already fetched, examine:

- Asset CDN hosts (`cdn.glycon.net`, `storage.perfectcdn.com`,
  `.s3.amazonaws.com`, `cloudfront.net`).
- JavaScript bundle filenames — sometimes contain version hashes.
- `<meta name="generator">` tags.
- `Set-Cookie` patterns (`PHPSESSID`, `XSRF-TOKEN`, `laravel_session`,
  `_csrf`, `connect.sid`).
- Inline JS variables exposing config.
- Source maps (`.js.map`) — these can leak full source.

Cross-reference platform fingerprints with public changelogs and
known CVEs:
- Perfect Panel, Smartpanel, Gainpanel (SMM panels)
- WordPress, Drupal, Joomla (CMS)
- Magento, Shopify, WooCommerce (e-commerce)
- Laravel, Django, Rails, Next.js, Nuxt, Spring (frameworks)

## 1.6 Public API documentation

Many apps expose API docs at `/api`, `/docs`, `/swagger`, `/redoc`,
`/api/docs`, `/api-docs`. Read carefully **before** sending requests.
Extract:

- All endpoints + methods.
- All parameters per endpoint.
- Auth scheme (key in body / header / URL).
- Rate-limit hints.
- Error response formats.
- Versioning hints (`v1`, `v2`).

Save to `api-endpoints.md`.

## 1.7 Mobile app discovery

If the operator has a mobile app:

- Find it on Play Store / App Store. Capture package name and
  version.
- Download the APK (Android) or IPA (iOS) for later static analysis
  (Stage 4, mobile playbook).
- Apkpure.com / apkmirror.com for older versions if version-skew
  matters.

Old mobile app versions often hard-code endpoints, keys, or use
removed-but-still-routed API surfaces.

## 1.8 Code repositories (if public)

```bash
# Find public repos owned by org / by domain in description
curl -s "https://api.github.com/search/repositories?q=user:<org>" | jq '.items[].full_name'

# Once you have repos, grep for secrets in commit history
trufflehog github --repo=https://github.com/<org>/<repo> --json
```

Check each repo's:
- `.env*` files committed in any commit.
- `config/` files with credentials.
- Issue tracker — sometimes operators paste secrets in issues.
- Wiki pages with internal docs.
- README with API examples and tokens.

## 1.9 Output

By end of Stage 2.1 you should have, in
`targets/<name>/recon/passive/`:

- `all-subdomains.txt` — every host associated with the org.
- `wayback-urls.txt` and `wayback-interesting.txt`.
- `osint-search.md` — Google / GitHub / paste-site findings.
- `api-endpoints.md` — extracted from public API docs.
- `platform-fingerprint.md` — best guess at platform + version + reasoning.
- `leaks.md` (or empty) — anything found in paste sites / GitHub.

Plus, if you found anything urgent (leaked credentials, exposed
backups, public repo with secrets), an immediate note to the
operator.

Append to `notes/engagement-log.md`:
- Subdomains discovered and which are in scope vs outside.
- Anything urgent for immediate operator action.
- Hypotheses to test in Stage 2.2 (active recon).

Ask operator to advance.
