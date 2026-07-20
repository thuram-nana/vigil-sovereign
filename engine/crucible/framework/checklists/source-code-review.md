# Source Code Review Checklist

> Reference checklist for white-box / gray-box engagements where source code access is granted. Cross-reference with `playbooks/20-source-code-review.md`. The goal of source review is to find what black-box testing can't reach: deep logic flaws, dead code with privileged actions, time-bombed branches, dangerous comments, and full corroboration of suspected vulnerabilities.

---

## How to Use This Checklist

- This is a multi-pass review structure. Pass 1 is orientation; Pass 2 is hunt-driven; Pass 3 is targeted at specific suspect components; Pass 4 is correlation against findings.
- Each item: ✅ reviewed clean | ❌ vulnerable (open finding) | ⚠️ concerning (note for follow-up) | 🚫 N/A.
- **Authorization:** confirm that source access is in scope per `targets/<name>/charter.md`. Be especially careful about IP / NDA — source must not leave the engagement environment.
- A source review is not "read every line." It is reasoning-led navigation.

---

## Pass 0: Inventory & Orientation

### Repository Layout

- [ ] Languages by line count (`cloc`, `tokei`, `scc`).
- [ ] Frameworks identified (Express, Django, Rails, Spring, Laravel, ASP.NET, etc.).
- [ ] Build system (Maven, Gradle, npm, pip, composer, go.mod, Cargo).
- [ ] Test coverage (qualitative — "are there tests" — affects refactor safety hypotheses).
- [ ] CI/CD configuration (`.github/workflows/`, `.gitlab-ci.yml`, `Jenkinsfile`).
- [ ] Container build (`Dockerfile`, `docker-compose.yml`).
- [ ] IaC (Terraform, CloudFormation).
- [ ] Documentation (`README`, `ARCHITECTURE.md`, `docs/`).
- [ ] Monorepo vs polyrepo structure mapped.

### Configuration

- [ ] Environment variable usage and `.env` files.
- [ ] Default config values (`config.default.json`, `application.yml`).
- [ ] Per-environment configs (`development`, `staging`, `production`).
- [ ] Feature flags and how they're toggled.
- [ ] Hardcoded URLs, hostnames, IP addresses.
- [ ] Backup / debug / admin endpoints conditionally enabled.

### Entrypoints

- [ ] HTTP routes / controllers — full inventory:
  - [ ] Express: `app.METHOD()`, routers, middleware order.
  - [ ] Django: `urls.py`, viewsets, decorators.
  - [ ] Rails: `routes.rb`, controllers, before_actions.
  - [ ] Spring: `@RestController`, `@RequestMapping`, `@PreAuthorize`.
  - [ ] Laravel: `routes/web.php`, `routes/api.php`, middleware groups.
  - [ ] ASP.NET: attribute routing, `Startup.cs`/`Program.cs`.
  - [ ] Go: `http.HandleFunc`, gorilla/mux, gin/echo routes.
  - [ ] PHP plain: any `.php` file in webroot.
- [ ] CLI entrypoints (`main`, `cli.py`, custom commands).
- [ ] Worker / queue consumers (Sidekiq, Celery, Bull, Resque).
- [ ] Cron / scheduled tasks.
- [ ] Webhook handlers.
- [ ] WebSocket / Socket.IO handlers.
- [ ] gRPC / protobuf services.
- [ ] GraphQL resolvers.
- [ ] Admin / internal APIs.

## Pass 1: Cross-Reference Black-Box Findings

For each finding from black-box testing, find the corresponding code path. This corroborates findings, finds variants, and identifies root cause vs symptom.

- [ ] For each open finding in `targets/<name>/findings/`, link the source file(s) and line(s) to the finding.
- [ ] For each finding, identify variants (same vulnerable pattern elsewhere in codebase).
- [ ] For each finding, identify root cause (single shared function vs scattered duplication).
- [ ] Update `report-remediation-roadmap.md` with file/line references.

## Pass 2: Sink-Driven Hunt

> Search for dangerous "sinks" first; trace back to data flow.

### Command Execution Sinks

- [ ] Node.js: `child_process.exec`, `execSync`, `spawn` with `{shell: true}`.
- [ ] Python: `os.system`, `subprocess.call/.run/.Popen` with `shell=True`, `os.popen`.
- [ ] PHP: `system`, `exec`, `shell_exec`, `passthru`, `popen`, backticks `` `cmd` ``.
- [ ] Ruby: `system`, `exec`, `` `cmd` ``, `%x{}`, `IO.popen`, `Open3.popen`.
- [ ] Go: `exec.Command` with attacker-controlled args.
- [ ] Java: `Runtime.exec`, `ProcessBuilder`.
- [ ] .NET: `Process.Start`, `cmd /c`.

### File I/O Sinks (path traversal, arbitrary read/write)

- [ ] Node.js: `fs.readFile`, `fs.writeFile`, `fs.createReadStream` with user-controlled path.
- [ ] Python: `open()`, `os.path.join` with user input + lack of `os.path.abspath` confinement.
- [ ] PHP: `file_get_contents`, `fopen`, `include`, `require`.
- [ ] Ruby: `File.read`, `IO.read`, `send`-based dispatch.
- [ ] Java: `FileInputStream`, `Paths.get`.

### SQL Sinks (injection)

- [ ] String concatenation in queries (`"SELECT * FROM ... WHERE id = " + id`).
- [ ] f-strings / template literals into queries.
- [ ] Raw query builders (`db.raw(...)`, `connection.query(...)` with concat).
- [ ] ORM `.where("col = '" + x + "'")` patterns.
- [ ] Sequelize `Op.literal(...)`, Knex `.whereRaw`, ActiveRecord `find_by_sql`.
- [ ] LIKE patterns without escaping `%` and `_`.
- [ ] Stored procedures invoked with concatenated args.

### NoSQL Sinks

- [ ] MongoDB: `$where`, `$function`, `$accumulator` with user input.
- [ ] MongoDB query operator injection (`{ $ne: null }` from JSON body).
- [ ] CouchDB / N1QL / Cypher (Neo4j) similar patterns.

### Template / View Engine Sinks (SSTI, XSS)

- [ ] Jinja2: `render_template_string(user_input)`.
- [ ] Twig, Smarty, Mako, Velocity, Freemarker, Handlebars dynamic templates.
- [ ] EJS, Pug, Liquid: `{{ raw_html }}` patterns.
- [ ] React: `dangerouslySetInnerHTML`.
- [ ] Vue: `v-html`.
- [ ] Angular: `bypassSecurityTrustHtml`.
- [ ] Blazor: `MarkupString`.
- [ ] String interpolation of user input into HTML response.

### Deserialization Sinks

- [ ] Java: `ObjectInputStream.readObject` on untrusted input.
- [ ] PHP: `unserialize`.
- [ ] Python: `pickle.loads`, `yaml.load` (without `SafeLoader`), `marshal.loads`.
- [ ] Ruby: `Marshal.load`, YAML with non-safe loader.
- [ ] .NET: `BinaryFormatter`, `JavaScriptSerializer` with type names, `XmlSerializer` polymorphic.
- [ ] Node.js: `node-serialize`, `funcster`, custom JSON revivers calling functions.

### XXE Sinks

- [ ] XML parsers without external entity disabled (Java SAX/DOM, .NET XmlReader, libxml2).
- [ ] SOAP / SAML processors.

### URL/HTTP Sinks (SSRF)

- [ ] Server-side fetch with user-controlled URL: `axios.get(userUrl)`, `requests.get(userUrl)`, `curl_exec`, `URL().openConnection()`.
- [ ] Webhook outbound calls.
- [ ] Image / file download endpoints.
- [ ] PDF/screenshot generators.
- [ ] OAuth callbacks with redirect_uri stored without normalization.
- [ ] Open redirects (`Location:` header from user input).

### Crypto Sinks

- [ ] `Math.random` for security purposes.
- [ ] Static IVs / nonces.
- [ ] ECB mode (`AES/ECB/...`).
- [ ] MD5 / SHA-1 for security-sensitive hashing.
- [ ] PBKDF2 with low iteration count.
- [ ] Hardcoded keys / secrets.
- [ ] `unsafeRandomBytes`.

### Eval & Dynamic Code

- [ ] `eval`, `Function()` constructor (JS).
- [ ] `exec`, `eval`, `compile` (Python).
- [ ] `eval`, `instance_eval`, `class_eval`, `send`, `public_send` (Ruby).
- [ ] `eval`, `assert`, `create_function` (PHP).
- [ ] `ScriptEngine.eval` (Java Nashorn / GraalJS).
- [ ] Reflection-based method dispatch from user input.

### Authentication / Session Sinks

- [ ] Custom authentication code (vs framework-provided).
- [ ] Custom session token generation.
- [ ] Cookie set without `Secure`, `HttpOnly`, `SameSite`.
- [ ] JWT verification skipped or with `none` algorithm tolerated.
- [ ] Password comparison without timing-safe equal.

### Authorization Sinks

- [ ] Object access by user-supplied ID without ownership check.
- [ ] Role check via mutable client-controlled value.
- [ ] Admin paths protected only by URL obscurity.
- [ ] RBAC enforced inconsistently across endpoints.

### Logging & Info Disclosure

- [ ] Logging credentials, tokens, PII.
- [ ] Logging full requests including auth headers.
- [ ] Stack traces returned in error responses.
- [ ] Debug endpoints exposed in production builds.

## Pass 3: Source-Driven Hunt (Targeted Reviews)

### Authentication Module

- [ ] Login flow: brute force protection, rate limiting, CAPTCHA, account lockout.
- [ ] Password storage: bcrypt/argon2/scrypt with appropriate cost.
- [ ] Password reset: token generation entropy, expiry, single-use, account enumeration in response.
- [ ] Email verification: token entropy, expiry.
- [ ] MFA: enrollment, recovery, bypass for "remember device".
- [ ] Session creation: random token, fixation resistance.
- [ ] Logout: server-side invalidation, not just cookie clear.
- [ ] Concurrent session handling.
- [ ] OAuth integration: state parameter, PKCE for public clients, redirect_uri allow-list.

### Authorization Module

- [ ] Centralized authorization (middleware, policy classes) vs scattered.
- [ ] Default-allow vs default-deny.
- [ ] Resource ownership: every read/write of `Object` checks `Object.owner == currentUser`.
- [ ] Role hierarchy and inheritance.
- [ ] Tenant isolation (multi-tenant SaaS): every query has `WHERE tenant_id = ?`.
- [ ] Indirect authorization via foreign keys (e.g., comment belongs to post belongs to user).
- [ ] Privilege escalation paths via API parameters (`role`, `is_admin`, `tenant_id` accepted from client).

### Input Validation Module

- [ ] Validation library used (Joi, Yup, Zod, marshmallow, Pydantic, Bean Validation, FluentValidation).
- [ ] Validation runs **before** business logic.
- [ ] Type coercion behavior (string "1" vs int 1, array vs scalar).
- [ ] Mass assignment protection (Strong Parameters, allowlist DTOs).
- [ ] File upload: type sniffing, extension allow-list, content-type, magic bytes, size limits, AV scan.
- [ ] Encoding: where decoded, where re-encoded.

### Output Encoding

- [ ] Auto-escaping templates enforced.
- [ ] Raw / safe / unescape calls audited.
- [ ] JSON encoding of HTML (especially in script blocks: `<script>var x = {{user_input}};</script>`).
- [ ] Response headers (`Content-Type`, `Content-Disposition`, `X-Content-Type-Options`).

### Cryptography Module

- [ ] Centralized crypto helper (vs scattered).
- [ ] Algorithm selection.
- [ ] Key management: where stored, how rotated.
- [ ] Random source for tokens.

### Error Handling

- [ ] Global error handler exists.
- [ ] Error responses: production vs development output.
- [ ] Stack traces never returned to client.
- [ ] Error messages don't leak internal paths, queries, or other sensitive context.

### Background Jobs / Async

- [ ] Job arguments validated (jobs often skip middleware).
- [ ] Job authorization (jobs run as system; ensure they re-check permissions).
- [ ] Idempotency.

### File Upload / Download

- [ ] Upload destination not under webroot, or webroot not script-executable.
- [ ] Download path canonicalization.
- [ ] Signed URLs / expiring URLs.
- [ ] Direct object reference vs opaque token.

### Cache

- [ ] Cache key includes user ID / tenant ID where appropriate.
- [ ] Sensitive data in cache (Redis, Memcached, Varnish).
- [ ] Cache poisoning via input headers.

## Pass 4: Forensic / Suspicious Patterns

- [ ] `// TODO`, `// FIXME`, `// HACK`, `// XXX` comments — read every one for security implications.
- [ ] `if (user == 'admin')` / `if (user.email == 'specific@example.com')` — backdoor patterns.
- [ ] Hidden parameters (`debug=1`, `__internal=1`).
- [ ] Test mode toggles (`if (process.env.NODE_ENV !== 'production')`) gating sensitive features.
- [ ] Time-bombs (`if (Date.now() > 1234567890)`).
- [ ] Hardcoded test credentials still in code.
- [ ] Old / commented-out auth checks.
- [ ] `git log -p` for security-relevant past changes; check whether vulnerabilities ever existed.
- [ ] `git log --all --full-history` for deleted files (often where secrets live).
- [ ] Branches / tags other than `main` (release branches may have hotfixes not yet merged).
- [ ] Submodules and their pin commits.

## Pass 5: Dependency Review

- [ ] `package.json` / `requirements.txt` / etc. — known-vulnerable versions.
- [ ] Tools: `npm audit`, `pip-audit`, `bundler-audit`, `cargo audit`, `govulncheck`, `OWASP Dependency-Check`, `Snyk`, `Trivy`, `Grype`.
- [ ] Transitive dependencies (lockfile-aware scanning).
- [ ] Abandoned / archived upstream projects.
- [ ] Direct dependency on private / unmaintained forks.
- [ ] License compliance (incidental — flag only if charter requires).

## Pass 6: Static Analysis Tools (corroborative, not authoritative)

- [ ] `semgrep --config auto` (or curated rule packs per framework).
- [ ] CodeQL queries.
- [ ] Bandit (Python).
- [ ] Brakeman (Rails).
- [ ] PHPStan / Psalm + Phan with security rules.
- [ ] ESLint security plugins.
- [ ] gosec (Go).
- [ ] SpotBugs + Find Security Bugs (Java).
- [ ] Roslyn analyzers (C#).

> Treat tool output as **leads, not findings**. Each must be manually confirmed and contextualized.

## Pass 7: Cross-Reference & Reporting

- [ ] Each black-box finding linked to source file/line.
- [ ] New source-only findings filed (with PoC steps for how they would manifest).
- [ ] Variants: did fixing one site fix all? (Often a finding has 5+ near-identical sites.)
- [ ] Update `report-remediation-roadmap.md` with code-level fix recommendations.

## Common Critical Findings to Hunt in Source

- [ ] String-built SQL anywhere a parameter is concatenated with user input.
- [ ] `dangerouslySetInnerHTML` / `v-html` / `bypassSecurityTrustHtml` rendering server data without sanitization.
- [ ] OAuth `redirect_uri` matched by `startsWith` or `contains` (rather than equality / strict allow-list).
- [ ] `eval(req.body...)` or any dynamic code execution.
- [ ] JWT verification using HS256 with secret loaded from env that's also the public web URL or a constant.
- [ ] Password reset token generated by `Math.random()` / non-CSPRNG.
- [ ] Email enumeration in different responses for "user exists" vs "user doesn't exist".
- [ ] Direct object access by ID with no `where user_id = currentUser.id`.
- [ ] Mass assignment of `is_admin`, `role`, `tenant_id`.
- [ ] File upload that writes to webroot with attacker-controlled filename.
- [ ] SSRF in webhook / fetch helpers without IP allow-list.
- [ ] Hardcoded credentials in `config/`, `.env.example`, test fixtures.
- [ ] Disabled CSRF on routes that mutate state.

## Cross-References

- Playbook: `framework/playbooks/20-source-code-review.md`
- Knowledge base: `framework/knowledge-base/attack-techniques/*.md` for sink-specific patterns.
- OWASP Code Review Guide.
- The Tangled Web (Zalewski).
- Secure Coding in C and C++ (Seacord) — applicable beyond C/C++ for thinking.
