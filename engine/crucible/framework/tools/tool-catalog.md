# Tool Catalog

> The OBSIDIAN agent uses tools as instruments, not crutches. Every tool listed
> here exists to accelerate a *reasoning step*, never to replace it. A tool that
> produces output OBSIDIAN cannot interpret is worse than no tool at all.

This catalog documents every external tool the CRUCIBLE framework expects to
have available, why it matters, what its output means, and what its known
failure modes are. Tools are grouped by the **playbook surface** they primarily
serve. The `install.sh` script in this directory installs every tool listed
here on a fresh Debian/Ubuntu system; `verify.sh` confirms each is callable.

If a tool is unavailable for any reason, OBSIDIAN must:
1. Note its absence in `engagement-log.md`.
2. Identify a substitute (manual technique or alternative tool).
3. Continue — never block on tooling.

---

## Convention

Each entry has:

- **Purpose** — what reasoning step it accelerates.
- **Install** — canonical install command (Go, pip, apt, etc.).
- **Invocation** — typical command for our use case.
- **Output interpretation** — what the result actually means.
- **Failure modes** — what makes the tool lie or miss.
- **Substitute** — what to use if it's unavailable.

---

# 1. Reconnaissance & Attack Surface

## subfinder
- **Purpose:** Passive subdomain enumeration via 30+ public sources (CT logs, PassiveDNS, search engines).
- **Install:** `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`
- **Invocation:** `subfinder -d example.com -all -silent -o subs.txt`
- **Output interpretation:** Each line is a subdomain *observed somewhere in the past*. Some may be dead, parked, or belong to former tenants. Always re-resolve with `dnsx`.
- **Failure modes:** Misses anything not indexed publicly. CT-only sources miss subdomains never given a TLS cert. Some sources rate-limit or require API keys (config at `~/.config/subfinder/provider-config.yaml`).
- **Substitute:** `amass enum -passive -d example.com`, manual CT search at `crt.sh`.

## amass
- **Purpose:** Deeper subdomain enumeration including active brute-forcing, ASN lookups, reverse DNS sweeps, and graph-style relationship discovery.
- **Install:** `go install -v github.com/owasp-amass/amass/v4/...@master`
- **Invocation:** `amass enum -d example.com -active -brute -w wordlist.txt -o amass.txt`
- **Output interpretation:** Slower but more thorough than subfinder. Emits relationships (which IP/ASN/org subdomains belong to). Useful for grouping infrastructure.
- **Failure modes:** Active mode is *noisy* — DNS brute-force is detectable. Default wordlists are mediocre; supply your own.
- **Substitute:** `subfinder` + `dnsx -ptr` for reverse lookups.

## assetfinder
- **Purpose:** Quick passive subdomain finder (smaller source set than subfinder, but useful as a cross-check).
- **Install:** `go install github.com/tomnomnom/assetfinder@latest`
- **Invocation:** `assetfinder --subs-only example.com`
- **Output interpretation:** Quick second opinion. Diff against subfinder output to catch sources one missed.
- **Failure modes:** Older, less complete than subfinder.
- **Substitute:** subfinder.

## dnsx
- **Purpose:** Mass DNS resolver and record probe.
- **Install:** `go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest`
- **Invocation:**
  - Resolve A: `cat subs.txt | dnsx -a -resp -silent`
  - Wildcard detection: `dnsx -d example.com -wd example.com`
  - CNAME chain: `cat subs.txt | dnsx -cname -resp`
- **Output interpretation:** Filters dead subdomains from a list. CNAME output reveals SaaS providers (Heroku, S3, Github Pages, Azure) — primary subdomain takeover signal.
- **Failure modes:** A single wildcard A record can make every brute-forced name appear alive. Always check for wildcards first.
- **Substitute:** `massdns`, `dig +short` in a loop.

## naabu
- **Purpose:** Fast SYN/CONNECT TCP port scanner.
- **Install:** `go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` (requires `libpcap-dev` for SYN mode).
- **Invocation:** `naabu -list ips.txt -top-ports 1000 -silent -o ports.txt`
- **Output interpretation:** Open TCP ports. Does *not* fingerprint services — chain into `httpx` or `nmap -sV`.
- **Failure modes:** Default rate is aggressive; can be dropped by IDS. SYN mode requires root.
- **Substitute:** `nmap -sS --top-ports 1000 -iL ips.txt`, `masscan`.

## nmap
- **Purpose:** Authoritative port scanning, service version detection, NSE script library.
- **Install:** `apt install nmap`
- **Invocation:**
  - Service detection: `nmap -sC -sV -p- -T4 target -oA nmap-full`
  - SSL audit: `nmap --script ssl-enum-ciphers,ssl-cert -p 443 target`
  - Vuln scripts: `nmap --script vuln target` (loud; use only with EMULATE-grade authorization)
- **Output interpretation:** `-sV` confidence drops to "tcpwrapped" or "unknown" on filtered/strange responses — investigate manually. NSE script output is variable in quality.
- **Failure modes:** Slow on full port range. Fingerprints can be wrong on custom services.
- **Substitute:** naabu + httpx + manual probing.

## masscan
- **Purpose:** Internet-scale port scanner. Use against /16+ ranges where naabu is too slow.
- **Install:** `apt install masscan`
- **Invocation:** `masscan -p1-65535 10.0.0.0/16 --rate=10000 -oG mass.gnmap`
- **Output interpretation:** Fast but can miss ports under high rate. Always re-verify with nmap before believing a port is closed.
- **Failure modes:** No service fingerprinting. Can DOS small networks; throttle in client environments.
- **Substitute:** nmap with `--min-rate`.

## httpx
- **Purpose:** HTTP/HTTPS prober — finds live web services on a list of hosts/ports, returns title, server, status, tech.
- **Install:** `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest`
- **Invocation:**
  - From subdomains: `cat subs.txt | httpx -title -tech-detect -status-code -follow-redirects -o live.txt`
  - With path probe: `cat subs.txt | httpx -path /admin,/api,/.git -mc 200,301,302,401,403`
- **Output interpretation:** Live HTTP services with metadata. Tech detection uses Wappalyzer fingerprints — useful but not authoritative; verify with manual inspection.
- **Failure modes:** WAFs may serve consistent 200s for everything. Cloudfront/Cloudflare hide origin.
- **Substitute:** `curl -sI` in a loop.

## katana
- **Purpose:** Modern web crawler with JS execution.
- **Install:** `go install github.com/projectdiscovery/katana/cmd/katana@latest`
- **Invocation:** `katana -u https://target.com -d 5 -jc -kf all -o crawl.txt`
- **Output interpretation:** URLs reachable from the seed. `-jc` parses JavaScript (catches API endpoints in SPA bundles). `-kf` follows known files (sitemap.xml, robots.txt).
- **Failure modes:** Headless browser is heavy; slow on large apps. SPAs with auth-gated routes need authenticated crawling.
- **Substitute:** `gospider`, manual browse + `mitmproxy` capture.

## gau / waybackurls
- **Purpose:** Fetch known URLs from Wayback Machine, Common Crawl, AlienVault OTX.
- **Install:** `go install github.com/lc/gau/v2/cmd/gau@latest`, `go install github.com/tomnomnom/waybackurls@latest`
- **Invocation:** `gau example.com | sort -u > historical-urls.txt`
- **Output interpretation:** *Historical* URLs. Many are dead, but reveals deleted endpoints, dev paths, exposed parameters, and deprecated APIs that may still respond.
- **Failure modes:** Pollution from spam crawls. Old URLs may be dead. Pipe through `httpx` to filter live.
- **Substitute:** Manual `curl https://web.archive.org/cdx/search/cdx?url=*.example.com`.

## ffuf
- **Purpose:** Fast HTTP fuzzer — directories, files, parameters, virtual hosts, headers.
- **Install:** `go install github.com/ffuf/ffuf/v2@latest`
- **Invocation:**
  - Directory: `ffuf -u https://target/FUZZ -w wordlist.txt -mc 200,301,401,403`
  - Parameter: `ffuf -u 'https://target/?FUZZ=test' -w params.txt -fs <baseline-size>`
  - VHost: `ffuf -u https://target/ -H 'Host: FUZZ.target' -w subs.txt -fs <baseline>`
- **Output interpretation:** Status code + size. Always set `-fs` (filter size) or `-fc` (filter code) against baseline; otherwise WAF/SPA noise drowns signal.
- **Failure modes:** Default wordlists miss app-specific paths. Rate limits trigger 429 floods; throttle with `-rate`.
- **Substitute:** `gobuster`, `feroxbuster`.

## feroxbuster
- **Purpose:** Recursive content discovery in Rust — faster than gobuster, smarter than ffuf for tree walks.
- **Install:** `apt install feroxbuster` or `cargo install feroxbuster`
- **Invocation:** `feroxbuster -u https://target -w wordlist.txt -d 4 -t 50 -x php,html,bak,old`
- **Output interpretation:** Tree of discovered paths. Recursion auto-explores 200/301 dirs.
- **Failure modes:** Recursion can spiral on dynamic apps; cap with `-d`.
- **Substitute:** ffuf with manual recursion.

## gobuster
- **Purpose:** Older content discovery tool, still useful for DNS subdomain busting and vhost mode.
- **Install:** `apt install gobuster`
- **Invocation:** `gobuster dns -d example.com -w subs-wordlist.txt -t 50`
- **Substitute:** ffuf.

## nuclei
- **Purpose:** Template-driven vulnerability scanner with 8000+ community templates.
- **Install:** `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && nuclei -update-templates`
- **Invocation:**
  - Default: `nuclei -l live.txt -severity medium,high,critical -o nuclei.txt`
  - Specific: `nuclei -l live.txt -t cves/ -t exposures/ -t default-logins/`
  - Custom template: `nuclei -l live.txt -t custom-templates/`
- **Output interpretation:** Each match links to its template. **Always read the template** before reporting — many are heuristic (e.g., string match on a body) and produce false positives. Severity in template ≠ severity in your context.
- **Failure modes:** Template churn — old templates can break or be removed. Some templates are too aggressive (post-exploitation actions); review `-t` paths. Out-of-date templates miss recent CVEs.
- **Substitute:** Manual checks per CVE, `metasploit auxiliary` modules.

## asnmap
- **Purpose:** ASN-to-CIDR lookup for scoping infrastructure.
- **Install:** `go install -v github.com/projectdiscovery/asnmap/cmd/asnmap@latest`
- **Invocation:** `asnmap -d example.com` or `asnmap -a AS13335`
- **Output interpretation:** CIDR ranges owned by an org. Useful for finding non-DNS-discoverable assets.
- **Failure modes:** ASN ownership data is ARIN/RIPE-published; cloud-hosted infra appears under the cloud provider, not the customer.
- **Substitute:** `whois`, `bgpview` API.

## tlsx
- **Purpose:** TLS data harvester — extracts certificate details, SAN entries, JARM fingerprints.
- **Install:** `go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest`
- **Invocation:** `cat ips.txt | tlsx -san -cn -silent`
- **Output interpretation:** SANs reveal additional hostnames sharing a cert (subdomain leakage). JARM fingerprints can identify C2 servers and SaaS providers.
- **Failure modes:** SNI-aware servers may serve different certs per Host header.
- **Substitute:** `openssl s_client -connect host:443 -servername host`, `nmap --script ssl-cert`.

## shuffledns / puredns
- **Purpose:** Mass DNS brute-forcers with wildcard detection.
- **Install:** `go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest`
- **Invocation:** `shuffledns -d example.com -w wordlist.txt -r resolvers.txt -o brute.txt`
- **Output interpretation:** Brute-forced subdomains, wildcard-filtered.
- **Failure modes:** Garbage resolvers produce garbage results. Use `dnsvalidator` to build a clean resolver list first.
- **Substitute:** Manual `dnsx -d example.com -w wordlist.txt`.

---

# 2. Web Application & API

## Burp Suite (Community / Pro)
- **Purpose:** *The* interactive HTTP proxy. Manual testing happens in Burp.
- **Install:** Download from PortSwigger. Pro is licensed; Community is free but rate-limited.
- **Invocation:** GUI. Configure browser/system to proxy through `127.0.0.1:8080`.
- **Output interpretation:** Repeater for manual replay; Intruder for fuzzing (Pro only at full speed); Decoder/Comparer for primitives; Collaborator for OOB callbacks (Pro only).
- **Failure modes:** Community lacks scanner, Collaborator, and full Intruder. JSON/binary payloads can be mangled by improper Content-Type handling.
- **Substitute:** ZAP (open-source), mitmproxy (CLI/Python).

## ZAP (Zed Attack Proxy)
- **Purpose:** Open-source HTTP proxy and scanner. Use when Burp Pro is unavailable.
- **Install:** `apt install zaproxy` or download from zaproxy.org
- **Invocation:** GUI or headless: `zap.sh -daemon -port 8090 -config api.disablekey=true`
- **Output interpretation:** Active scan flags issues by category. False positive rate higher than Burp Pro; verify each.
- **Failure modes:** UI is heavier than Burp. Active scan can break apps.
- **Substitute:** Burp Suite.

## mitmproxy
- **Purpose:** Scriptable HTTP proxy. Use when you need to programmatically rewrite traffic.
- **Install:** `pip install mitmproxy`
- **Invocation:**
  - Interactive: `mitmproxy -p 8080`
  - Web: `mitmweb -p 8080`
  - Scripted: `mitmdump -s rewrite.py`
- **Output interpretation:** All flows captured. Python addons can inject/modify/log requests.
- **Failure modes:** Cert install required for HTTPS. Can be slow on heavy apps.
- **Substitute:** Burp + custom extensions, `httptoolkit`.

## sqlmap
- **Purpose:** SQL injection automation.
- **Install:** `apt install sqlmap` or `pip install sqlmap`
- **Invocation:**
  - Basic: `sqlmap -u 'https://target/?id=1' --batch`
  - From request file: `sqlmap -r request.txt --level=5 --risk=3 --batch`
  - DBMS-specific: `sqlmap -u url --dbms=mysql --technique=BEUSTQ`
- **Output interpretation:** Confirms injection point and DBMS. `--dump` extracts data — *do not run* without explicit authorization.
- **Failure modes:** WAF bypass tampers (`--tamper=`) needed often. Time-based detection is unreliable on slow hosts. Will *not* find every injection — manual testing for second-order, blind, or unusual contexts (HTTP headers, JSON body, GraphQL variables) is essential.
- **Substitute:** Manual injection, `ghauri` (newer fork), `commix` for command injection.

## ghauri
- **Purpose:** Modern SQLi tool, sometimes succeeds where sqlmap fails (better WAF handling).
- **Install:** `pip install ghauri`
- **Invocation:** `ghauri -r request.txt --batch`
- **Substitute:** sqlmap.

## NoSQLMap
- **Purpose:** NoSQL injection (MongoDB-focused).
- **Install:** `git clone https://github.com/codingo/NoSQLMap.git && pip install -r requirements.txt`
- **Invocation:** `python NoSQLMap.py`
- **Failure modes:** Limited beyond MongoDB. Manual NoSQL testing is often more effective.
- **Substitute:** Manual `$ne`, `$gt`, `$where`, `$regex` payloads.

## commix
- **Purpose:** Command injection automation.
- **Install:** `apt install commix` or git clone.
- **Invocation:** `commix --url='https://target/?cmd=ls' --batch`
- **Failure modes:** Limited payload diversity for hardened targets.
- **Substitute:** Manual injection with OOB callbacks (Burp Collaborator, interactsh).

## XSStrike / dalfox
- **Purpose:** XSS automation.
- **Install:**
  - dalfox: `go install github.com/hahwul/dalfox/v2@latest`
  - XSStrike: `git clone https://github.com/s0md3v/XSStrike.git`
- **Invocation:**
  - dalfox: `dalfox url 'https://target/?q=test'`
  - dalfox pipe: `cat urls.txt | dalfox pipe`
- **Output interpretation:** Confirmed XSS payloads with context (HTML attribute, JS string, etc.).
- **Failure modes:** DOM XSS detection is limited; manual review of JS sinks needed. CSP bypass not always handled.
- **Substitute:** Manual payloads via Burp Repeater.

## tplmap
- **Purpose:** Server-side template injection automation (Jinja2, Twig, Velocity, ERB, etc.).
- **Install:** `git clone https://github.com/epinna/tplmap.git`
- **Invocation:** `python tplmap.py -u 'https://target/?name=test'`
- **Failure modes:** Detection on sandboxed templates is poor; manual probing often needed.
- **Substitute:** Manual `{{7*7}}` / `${7*7}` / `<%= 7*7 %>` probes.

## interactsh / Burp Collaborator
- **Purpose:** Out-of-band interaction server. Catches DNS/HTTP callbacks from blind injections (SSRF, blind XXE, blind SQLi, blind cmd injection, log4shell-style).
- **Install:** `go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest`
- **Invocation:** `interactsh-client -v` → use the issued domain in payloads.
- **Output interpretation:** A DNS hit confirms egress + payload reach; HTTP hit confirms callback execution. Inspect headers/body for context.
- **Failure modes:** Some egress-restricted environments block all outbound — absence of callback ≠ no vulnerability.
- **Substitute:** Burp Collaborator (Pro), self-hosted DNS server with `dnstwist`/custom listener.

## graphql-cop / graphqlmap / clairvoyance / inql
- **Purpose:** GraphQL-specific testing.
- **Install:**
  - graphql-cop: `pip install graphql-cop`
  - clairvoyance: `pip install clairvoyance`
  - inql: Burp extension via BApp Store
- **Invocation:**
  - Audit: `graphql-cop -t https://target/graphql`
  - Schema recovery (introspection off): `clairvoyance https://target/graphql -o schema.json`
- **Output interpretation:** graphql-cop checks introspection, batching, alias overload, depth limits. Clairvoyance recovers schema via field suggestions even when introspection is disabled.
- **Failure modes:** Auth-required GraphQL needs token in headers; not all tools handle this gracefully.
- **Substitute:** Manual introspection queries, custom Python with `gql` library.

## jwt_tool
- **Purpose:** JWT analysis and exploitation (alg=none, key confusion, weak secrets, kid traversal, JWKS spoofing).
- **Install:** `pip install jwt-tool` or `git clone https://github.com/ticarpi/jwt_tool.git`
- **Invocation:**
  - Decode/analyze: `jwt_tool <token>`
  - Tamper: `jwt_tool <token> -T`
  - Crack secret: `jwt_tool <token> -C -d wordlist.txt`
  - Forge: `jwt_tool <token> -X k -pk attacker.pem` (key confusion)
- **Output interpretation:** Reveals algorithm, claims, signs new tokens for testing. Crack mode is dictionary-based; weak HS256 secrets fall fast.
- **Failure modes:** Doesn't auto-detect *server-side* validation logic — a server may accept `alg=none` despite library defaults.
- **Substitute:** Manual encoding with `python -c "import jwt"`, `hashcat -m 16500` for HS256 cracking.

## hashcat / john
- **Purpose:** Password and hash cracking.
- **Install:** `apt install hashcat john`
- **Invocation:**
  - JWT HS256: `hashcat -a 0 -m 16500 hash.txt wordlist.txt`
  - Bcrypt: `hashcat -a 0 -m 3200 hash.txt wordlist.txt`
  - NTLM: `hashcat -a 0 -m 1000 hash.txt wordlist.txt`
- **Output interpretation:** Recovered plaintext or "exhausted." `--show` displays already-cracked.
- **Failure modes:** GPU required for serious cracking. Wordlist quality is everything (rockyou.txt is the floor).
- **Substitute:** john, online services (only with explicit authorization — never upload client hashes).

## hydra
- **Purpose:** Online password brute-force across many protocols (HTTP forms, SSH, FTP, RDP, etc.).
- **Install:** `apt install hydra`
- **Invocation:** `hydra -L users.txt -P passwords.txt target http-post-form '/login:username=^USER^&password=^PASS^:Invalid'`
- **Output interpretation:** Hits = (user, password) pairs that succeeded.
- **Failure modes:** Account lockout, rate limits, CAPTCHA. **Use with extreme caution** — easily violates rules of engagement.
- **Substitute:** ffuf with cluster bombing, custom Python.

## ssrfmap
- **Purpose:** SSRF exploitation framework with cloud-metadata, Redis/MySQL Gopher, file:// modules.
- **Install:** `git clone https://github.com/swisskyrepo/SSRFmap.git && pip install -r requirements.txt`
- **Invocation:** `python ssrfmap.py -r request.txt -p url -m readfiles,portscan,redis,gopher`
- **Output interpretation:** Each module probes a known SSRF impact path.
- **Failure modes:** Many modules assume internal services that may not exist.
- **Substitute:** Manual SSRF with payload list (see `framework/scripts/api/ssrf-probe.py`), interactsh.

## XXEinjector / oxml-xxe
- **Purpose:** XML External Entity exploitation.
- **Install:** `git clone https://github.com/enjoiz/XXEinjector.git`
- **Invocation:** `ruby XXEinjector.rb --host=target --file=req.txt --path=/etc/passwd`
- **Failure modes:** Many parsers ignore DTDs in 2024+ defaults; XXE is increasingly rare. OOB techniques needed for blind cases.
- **Substitute:** Manual payloads (`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`).

## arjun / paramspider
- **Purpose:** HTTP parameter discovery.
- **Install:** `pip install arjun`, `pip install paramspider`
- **Invocation:**
  - arjun: `arjun -u https://target/api/endpoint`
  - paramspider: `paramspider -d target.com`
- **Output interpretation:** Hidden parameters that change response (length/status). High false-positive rate; verify manually.
- **Failure modes:** Arjun fuzzes a wordlist; novel parameter names are missed. Paramspider uses Wayback (historical, possibly stale).
- **Substitute:** Manual wordlist via ffuf with parameter mode.

## kiterunner
- **Purpose:** API-aware content discovery — uses Swagger/OpenAPI corpus to find API endpoints with correct HTTP methods.
- **Install:** `go install github.com/assetnote/kiterunner@latest`
- **Invocation:** `kr scan https://target -A=apiroutes-210228 -x 50`
- **Output interpretation:** Endpoints respond differently than vanilla 404. Better than directory busting for APIs.
- **Failure modes:** Wordlist is dated; novel routes are missed.
- **Substitute:** ffuf with API-specific wordlists (SecLists `Discovery/Web-Content/api/`).

## crlfuzz
- **Purpose:** CRLF injection scanner.
- **Install:** `go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest`
- **Invocation:** `crlfuzz -u https://target/page`
- **Substitute:** Manual `%0d%0aSet-Cookie:...` probes.

---

# 3. Source Code & Supply Chain

## semgrep
- **Purpose:** Static analysis with custom rules. The tool for guided code review.
- **Install:** `pip install semgrep`
- **Invocation:**
  - Default registry: `semgrep --config auto src/`
  - Specific rulesets: `semgrep --config p/owasp-top-ten --config p/security-audit src/`
  - Custom rule: `semgrep --config rule.yaml src/`
- **Output interpretation:** Each match references a rule. False positives are the rule, not the exception — every finding requires manual confirmation. *Absence* of matches does not mean code is safe; rules cover known patterns.
- **Failure modes:** Misses any vulnerability not encoded in a rule. Generates noise on legitimate patterns. Rules vary in quality.
- **Substitute:** Manual review with grep, IDE search, language-specific linters (bandit for Python, brakeman for Rails, gosec for Go).

## bandit (Python)
- **Purpose:** Python-specific security linter.
- **Install:** `pip install bandit`
- **Invocation:** `bandit -r src/ -f json -o bandit.json`
- **Output interpretation:** Confidence + severity ratings. High-confidence "high" findings are usually real.
- **Substitute:** semgrep with python rules.

## brakeman (Rails)
- **Purpose:** Static analysis for Ruby on Rails.
- **Install:** `gem install brakeman`
- **Invocation:** `brakeman -A -o report.json`
- **Substitute:** semgrep with ruby rules.

## gosec (Go)
- **Purpose:** Go security linter.
- **Install:** `go install github.com/securego/gosec/v2/cmd/gosec@latest`
- **Invocation:** `gosec ./...`
- **Substitute:** semgrep with go rules.

## phpcs-security-audit (PHP)
- **Purpose:** PHP security CodeSniffer.
- **Install:** `composer require pheromone/phpcs-security-audit`
- **Invocation:** `phpcs --standard=Security src/`
- **Substitute:** semgrep with php rules, **rips** (older static analyzer).

## trufflehog
- **Purpose:** Secret scanning across git history, files, S3 buckets, Docker images.
- **Install:** `go install github.com/trufflesecurity/trufflehog/v3@latest`
- **Invocation:**
  - Repo: `trufflehog git file://./repo --only-verified`
  - GitHub org: `trufflehog github --org=target-org --only-verified`
  - Docker image: `trufflehog docker --image=registry/image:tag`
  - S3: `trufflehog s3 --bucket=target-bucket`
- **Output interpretation:** `--only-verified` confirms the secret actually authenticates against its provider — vastly reduces false positives.
- **Failure modes:** Verified mode requires network egress to provider. Some secret types lack verifiers.
- **Substitute:** gitleaks, manual `git log -p | grep -E '...'`.

## gitleaks
- **Purpose:** Git-history secret scanner.
- **Install:** `go install github.com/zricethezav/gitleaks/v8@latest`
- **Invocation:** `gitleaks detect --source=./repo --report-path=leaks.json`
- **Substitute:** trufflehog.

## detect-secrets
- **Purpose:** Yelp's secret-scanner with audit workflow.
- **Install:** `pip install detect-secrets`
- **Invocation:** `detect-secrets scan > .secrets.baseline && detect-secrets audit .secrets.baseline`
- **Substitute:** trufflehog.

## dependency-check
- **Purpose:** OWASP Dependency-Check — finds known-vulnerable libraries via NVD.
- **Install:** Download from owasp.org/projects/dependency-check
- **Invocation:** `dependency-check.sh --project name --scan ./repo --format ALL --out ./dc-report`
- **Output interpretation:** CVE-tagged vulnerable dependencies with CVSS. Slow first run (downloads NVD).
- **Failure modes:** False positives on misidentified components. Misses non-NVD'd vulns.
- **Substitute:** snyk, retire.js (JS), pip-audit (Python), bundler-audit (Ruby), `npm audit`, `yarn audit`.

## snyk
- **Purpose:** Dependency scanning + IaC + container scanning. Free tier limited.
- **Install:** `npm install -g snyk && snyk auth`
- **Invocation:** `snyk test --all-projects`
- **Substitute:** dependency-check + trivy.

## retire.js
- **Purpose:** JavaScript dependency scanner.
- **Install:** `npm install -g retire`
- **Invocation:** `retire --path src/`
- **Substitute:** snyk.

## pip-audit / safety
- **Purpose:** Python dependency vuln scanner.
- **Install:** `pip install pip-audit safety`
- **Invocation:** `pip-audit -r requirements.txt`, `safety check -r requirements.txt`
- **Substitute:** dependency-check.

## composer audit (PHP)
- **Purpose:** PHP dependency audit.
- **Invocation:** `composer audit`
- **Substitute:** local-php-security-checker.

---

# 4. Cloud, Container, Kubernetes

## scoutsuite
- **Purpose:** Multi-cloud security posture assessment (AWS, GCP, Azure, OCI, Aliyun).
- **Install:** `pip install scoutsuite`
- **Invocation:**
  - AWS: `scout aws --profile pentest`
  - GCP: `scout gcp --service-account key.json`
  - Azure: `scout azure --cli`
- **Output interpretation:** HTML report with categorized misconfigurations. Most useful for breadth — confirms public S3 buckets, open security groups, IAM over-permissioning.
- **Failure modes:** Read-only IAM required; many findings are advisory and need contextual judgment (a public bucket may be intentional).
- **Substitute:** Manual checks per service, CLI scripts.

## prowler
- **Purpose:** AWS/Azure/GCP/Kubernetes security best-practice scanner mapped to CIS/PCI/HIPAA.
- **Install:** `pip install prowler`
- **Invocation:**
  - AWS: `prowler aws -p pentest`
  - Specific check: `prowler aws --checks ec2_instance_public_ip`
- **Output interpretation:** Pass/fail per CIS control. Output mapped to compliance frameworks.
- **Substitute:** scoutsuite, cloudsploit.

## pacu
- **Purpose:** AWS exploitation framework. Modules for IAM enum, privesc, S3 enum, lateral movement.
- **Install:** `pip install pacu`
- **Invocation:**
  - `pacu` → interactive shell
  - `set_keys`, `run iam__enum_permissions`, `run iam__privesc_scan`
- **Output interpretation:** Pacu identifies known IAM privesc paths (22+ techniques cataloged).
- **Failure modes:** AWS regularly closes loopholes — modules can become outdated. Some modules touch resources (loud).
- **Substitute:** Manual IAM analysis with `aws iam` CLI + cloudsplaining.

## cloudsplaining
- **Purpose:** IAM policy audit — flags overpermissive policies.
- **Install:** `pip install cloudsplaining`
- **Invocation:** `cloudsplaining download && cloudsplaining scan --input-file *.json`
- **Substitute:** Manual review with `aws iam get-account-authorization-details`.

## kube-hunter
- **Purpose:** Kubernetes attack-surface scanner.
- **Install:** `pip install kube-hunter`
- **Invocation:**
  - External: `kube-hunter --remote target-master`
  - Internal pod: `kube-hunter --pod`
- **Output interpretation:** Categorized as Hunter (passive) and Active Hunter (changes state) findings.
- **Substitute:** Manual API probing with `kubectl`, kubeaudit.

## kubeaudit
- **Purpose:** Kubernetes manifest security linter.
- **Install:** `go install github.com/Shopify/kubeaudit@latest`
- **Invocation:** `kubeaudit all -f deployment.yaml`
- **Substitute:** kubesec, polaris.

## kubesec
- **Purpose:** Risk score for K8s manifests.
- **Install:** `go install github.com/controlplaneio/kubesec/v2@latest`
- **Invocation:** `kubesec scan deployment.yaml`
- **Substitute:** kubeaudit.

## peirates
- **Purpose:** Kubernetes attack tool, post-pod-compromise.
- **Install:** Download from github.com/inguardians/peirates
- **Invocation:** `./peirates`
- **Failure modes:** Loud — definitely AUDIT/EMULAT mode only.
- **Substitute:** Manual kubectl + service account abuse.

## trivy
- **Purpose:** Container image, IaC, filesystem vuln scanner.
- **Install:** `apt install trivy` or download from aquasec.
- **Invocation:**
  - Image: `trivy image registry/image:tag`
  - IaC: `trivy config ./terraform/`
  - Filesystem: `trivy fs --security-checks vuln,config,secret /path`
- **Output interpretation:** Vulns mapped to CVE; config issues to CIS/Hardening; secrets to provider.
- **Substitute:** grype, dive (image inspection), checkov (IaC).

## grype
- **Purpose:** Container vuln scanner (anchore).
- **Install:** `curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh`
- **Invocation:** `grype registry/image:tag`
- **Substitute:** trivy.

## checkov
- **Purpose:** IaC security scanner (Terraform, CloudFormation, Kubernetes, Helm, Dockerfile, ARM, Serverless).
- **Install:** `pip install checkov`
- **Invocation:** `checkov -d ./terraform`
- **Substitute:** tfsec, trivy config.

## tfsec
- **Purpose:** Terraform-specific security scanner.
- **Install:** `apt install tfsec` or `go install github.com/aquasecurity/tfsec/cmd/tfsec@latest`
- **Invocation:** `tfsec ./terraform`
- **Substitute:** checkov.

## dive
- **Purpose:** Inspect Docker image layers (find secrets, dev artifacts in layers).
- **Install:** `apt install dive`
- **Invocation:** `dive image:tag`
- **Substitute:** `docker history --no-trunc image:tag`, `skopeo inspect`.

## syft
- **Purpose:** SBOM generator. Inventories what's in a container/repo.
- **Install:** `curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh`
- **Invocation:** `syft registry/image:tag -o json`
- **Substitute:** trivy sbom, manual inspection.

---

# 5. Mobile

## apktool
- **Purpose:** Android APK decompile/reassemble.
- **Install:** `apt install apktool`
- **Invocation:** `apktool d app.apk -o app-decoded`
- **Output interpretation:** Yields smali, AndroidManifest.xml, resources. Smali is readable but not Java.
- **Substitute:** jadx-gui (better Java view).

## jadx
- **Purpose:** Android decompiler producing readable Java.
- **Install:** `apt install jadx` or download from github.
- **Invocation:**
  - GUI: `jadx-gui app.apk`
  - CLI: `jadx -d app-decoded app.apk`
- **Output interpretation:** Java-equivalent source. Some methods marked with errors when bytecode is obfuscated.
- **Substitute:** apktool + smali manual reading, ghidra.

## frida
- **Purpose:** Dynamic instrumentation — hook native or Java functions at runtime.
- **Install:** `pip install frida-tools` (host) + frida-server on device (rooted).
- **Invocation:** `frida -U -f com.target.app -l hook.js --no-pause`
- **Output interpretation:** Whatever `hook.js` logs. Standard hooks: SSL pinning bypass, root detection bypass, intercepting crypto calls.
- **Failure modes:** Anti-frida detection in modern apps (frida-server detection, port checks). Use frida-detector bypass scripts.
- **Substitute:** Xposed framework, objection (frida wrapper).

## objection
- **Purpose:** Frida wrapper — common iOS/Android pentesting actions without writing JS.
- **Install:** `pip install objection`
- **Invocation:** `objection -g com.target.app explore`
- **Output interpretation:** Interactive REPL. Commands: `android sslpinning disable`, `android root disable`, `memory list classes`.
- **Substitute:** raw frida.

## mobsf (Mobile Security Framework)
- **Purpose:** Static + dynamic analysis for Android/iOS.
- **Install:** Docker: `docker run -p 8000:8000 opensecurity/mobile-security-framework-mobsf`
- **Invocation:** Web UI at localhost:8000, upload APK/IPA.
- **Output interpretation:** Categorized findings — manifest, code, secrets, network. Many false positives; treat as hint list.
- **Failure modes:** Heuristic findings, mobile-specific severity often overstated.
- **Substitute:** apktool + jadx + manual review.

## drozer
- **Purpose:** Android IPC/component testing — exported activities, content providers, intents.
- **Install:** `apt install drozer`
- **Invocation:** Device-side agent + host CLI.
- **Output interpretation:** Reveals exported components callable without permission.
- **Substitute:** Manual `adb shell am start -n` + AndroidManifest review.

## class-dump (iOS)
- **Purpose:** Dump Objective-C class headers from Mach-O binary.
- **Install:** From github.com/nygard/class-dump
- **Invocation:** `class-dump -H Application -o headers/`
- **Substitute:** Hopper, IDA.

## otool / nm (iOS)
- **Purpose:** Mach-O inspection.
- **Invocation:** `otool -L Application` (linked libs), `otool -hv Application` (header), `nm Application | grep crypto`
- **Substitute:** lipo, file.

---

# 6. Wireless / Network (rarely in web-app pentest scope, included for completeness)

## aircrack-ng suite
- **Purpose:** WiFi auditing.
- **Install:** `apt install aircrack-ng`
- **Substitute:** kismet, hcxtools.

## responder
- **Purpose:** LLMNR/NBT-NS/MDNS poisoner — captures NetNTLM hashes on internal nets.
- **Install:** `apt install responder` or git clone.
- **Substitute:** inveigh.

## impacket suite
- **Purpose:** Python network protocols (SMB, MSRPC, Kerberos, LDAP).
- **Install:** `pip install impacket`
- **Invocation:** `secretsdump.py`, `psexec.py`, `getTGT.py`, `wmiexec.py`, etc.
- **Substitute:** Native protocol libraries, sysinternals (Windows).

## crackmapexec / netexec
- **Purpose:** Active Directory enumeration and attack swiss army knife.
- **Install:** `pip install crackmapexec` (or netexec, the maintained fork)
- **Invocation:** `nxc smb hosts.txt -u user -p pass`
- **Substitute:** impacket scripts, manual SMB enumeration.

---

# 7. Reporting & Evidence

## ghostwriter / dradis / serpico
- **Purpose:** Report generation platforms.
- **Substitute:** Markdown + pandoc → DOCX/PDF (the framework's preferred path).

## pandoc
- **Purpose:** Markdown → DOCX/PDF conversion.
- **Install:** `apt install pandoc texlive-xetex`
- **Invocation:**
  - DOCX: `pandoc report.md -o report.docx --reference-doc=template.docx`
  - PDF: `pandoc report.md -o report.pdf --pdf-engine=xelatex`

## asciinema
- **Purpose:** Record terminal sessions as evidence.
- **Install:** `apt install asciinema`
- **Invocation:** `asciinema rec output.cast`
- **Output interpretation:** Replayable terminal recording — preserves timing.
- **Substitute:** `script -t timing.log session.log`.

## ffmpeg / OBS Studio
- **Purpose:** Video evidence for browser-based PoCs.
- **Install:** `apt install ffmpeg obs-studio`

## httpie / curl
- **Purpose:** Manual HTTP request crafting.
- **Install:** `apt install httpie curl`

## jq / yq
- **Purpose:** JSON/YAML query and manipulation.
- **Install:** `apt install jq && pip install yq`

---

# 8. Wordlists (referenced but installed separately)

## SecLists
- **Purpose:** The canonical wordlist collection. Contains discovery wordlists, payload wordlists, common credentials.
- **Install:** `git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists`
- **Notable:**
  - `Discovery/Web-Content/raft-large-directories.txt`
  - `Discovery/Web-Content/api/objects.txt`
  - `Discovery/DNS/subdomains-top1million-110000.txt`
  - `Passwords/Common-Credentials/10-million-password-list-top-10000.txt`
  - `Fuzzing/SQLi/Generic-SQLi.txt`
  - `Fuzzing/XSS/XSS-Jhaddix.txt`

## PayloadsAllTheThings
- **Purpose:** Payload reference per vulnerability class.
- **Install:** `git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git`

## fuzzdb
- **Purpose:** Older but comprehensive fuzz/payload corpus.
- **Install:** `git clone https://github.com/fuzzdb-project/fuzzdb.git`

---

# 9. Browsers & Extensions (manual testing)

## Browser
- **Recommendation:** Firefox (developer edition) for testing, Chrome for parity testing.
- **Extensions:**
  - **Wappalyzer** — tech fingerprinting
  - **HackBar** — quick parameter manipulation
  - **Cookie Editor**
  - **EditThisCookie** (Chrome)
  - **FoxyProxy** — quick proxy switching
  - **User-Agent Switcher**
  - **Modify Header Value**

## Burp extensions (BApp Store)
- **Logger++** — comprehensive history with filtering
- **Autorize** — IDOR / authz testing automation
- **JWT Editor** (PortSwigger)
- **Param Miner** — hidden parameter discovery
- **Turbo Intruder** — high-speed Intruder replacement (race conditions)
- **Hackvertor** — encoding/transformation tag-based
- **HTTP Request Smuggler** (PortSwigger James Kettle)
- **Backslash Powered Scanner**
- **Active Scan++**
- **Reflector**
- **Upload Scanner**
- **GraphQL Raider** / **InQL**
- **SAML Raider**

---

# 10. Custom Scripts (in `framework/scripts/`)

The framework ships purpose-built scripts. See:

- `recon/leaks.sh` — git/GitHub/wayback secret hunting wrapper
- `recon/subdomain-takeover.sh` — CNAME chain analysis with provider matching
- `auth/auth-probe.py` — login surface enumeration and rate-limit detection
- `auth/idor-sweep.py` — sequential ID access-control probe across multiple users
- `auth/token-entropy.py` — session token entropy analysis
- `api/api-sweep.py` — multi-method endpoint discovery with auth-state diff
- `api/jwt-attack.py` — JWT vulnerability automation (alg=none, key confusion, weak HS)
- `api/ssrf-probe.py` — SSRF test orchestrator with cloud-metadata, file://, gopher payloads
- `api/webhook-probe.py` — webhook signature validation testing
- `race/race-balance.py` — financial race condition tester (refund/coupon/balance)

These scripts are *thin* — they prepare and dispatch reasoning-grade probes,
log structured output, and exit non-zero on confirmed findings. They expect a
human or LLM operator to read their output and decide next steps.

---

# Tool Failure Doctrine

A tool reporting "no findings" means *one* of three things:
1. There is no vulnerability of that class (rare).
2. The tool's heuristic/pattern missed it (common).
3. The tool was misconfigured (very common).

OBSIDIAN never accepts a single tool's silence as evidence of safety. For each
vulnerability class on a target, OBSIDIAN runs **at least one** automated probe
*and* performs **at least one** manual confirmation test, then critiques both
results before declaring the surface "explored."

When tools disagree, OBSIDIAN trusts manual verification.
When tools agree, OBSIDIAN still verifies with a third method before reporting.
