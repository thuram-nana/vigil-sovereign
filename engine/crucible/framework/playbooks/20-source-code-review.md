# Playbook 20 — Source code review

**Goal:** with source code in hand, verify black-box hypotheses,
discover bugs the black-box pass missed, and prepare patches.

**Stage in lifecycle:** 7. Triggered when the operator delivers
source to `targets/<name>/loot/source/`.

**Standards:** OWASP Code Review Guide v2.

---

## 20.1 Why white-box and when

Black-box testing finds bugs that show externally. Many real bugs
don't — they hide in code paths that aren't reachable from the public
surface, or in subtle conditional logic that black-box probes don't
trigger.

Source review is most efficient when done **after** a black-box pass
because:
- You have specific hypotheses to verify (`notes/hypotheses.md`).
- You know the surface that matters (where to focus reading).
- You can recognize "is this controller protected?" answers quickly.

If you start with source, you risk reviewing in a vacuum and missing
the user-reachable behaviors.

---

## 20.2 Initial orientation pass

Before deep reading, build a map. Spend 30-60 minutes on:

### Stack inventory

```bash
# What language(s) and framework(s)?
ls *.json *.toml *.lock *.gemspec *.csproj go.mod composer.json 2>/dev/null
file artifact-binaries

# LOC count for sizing
cloc .
```

### Directory map

A typical web app has: routes/, controllers/, services/ or models/,
views/, middlewares/, migrations/, tests/, infrastructure/.

Map which directory is which. Note deviations from convention —
custom directories often hide custom (and less-reviewed) logic.

### Routing entry points

The app's URL routing — usually in:
- `routes/web.php` + `routes/api.php` (Laravel)
- `urls.py` (Django)
- `app.js` / `routes/*.js` (Express)
- `config/routes.rb` (Rails)
- `*Controller.cs` with `[Route]` attributes (.NET)
- `*Controller.java` with `@RequestMapping` (Spring)

Cross-reference your endpoint inventory from Stage 3. Endpoints in
source but not in inventory are "dark routes" — unlinked endpoints
worth probing. Add to hypotheses.

### Auth / authz layer

- Where's the login controller?
- Where's the session middleware?
- Is there an auth-required middleware on routes? On every route, or
  only some?
- Is there a role/permission check primitive? How is it called?

This map answers many hypotheses at a glance.

### Dependencies

```bash
# Audit dependencies for known CVEs
# Node
npm audit
# Or, more thorough:
npx audit-ci

# Python
pip-audit
safety check

# Ruby
bundle audit

# Java
dependency-check --project app --scan .
```

Note transitive dependencies; vulnerabilities deep in the tree often
unfixable without major upgrades.

---

## 20.3 Hypothesis verification pass

For each open hypothesis in `notes/hypotheses.md`:

1. Find the relevant controller / handler in source.
2. Read the function end-to-end.
3. Confirm or refute the hypothesis from code.
4. Update the hypothesis status.

This is fast (minutes per hypothesis) once you have the orientation
map. It often closes 80% of hypotheses inside an hour and surfaces
3-5 confirmed findings the black-box pass had only suspected.

---

## 20.4 Targeted reads — the high-yield surfaces

After hypothesis verification, do focused reads of the surfaces most
likely to hide bugs:

### Authentication

- Login controller — what does the password check look like? Is the
  comparison constant-time? Is there session fixation? Is there
  rate limiting in code?
- Password reset controller — token generation, storage, lookup,
  use, invalidation.
- 2FA verify — exact check structure.
- Email change — re-auth requirement.

### Authorization

- For every route, is there an explicit auth/authz check, or is it
  inherited from middleware? If middleware: what's the middleware's
  check, exactly?
- For every IDOR-suspect endpoint: where's the ownership check?
  `if (resource.user_id != current_user.id) return 403;` — verify
  or note absence.
- Mass-assignment: check for `$fillable` (Laravel), `permit`
  (Rails), serializer declarations (DRF). If the model accepts
  arbitrary fields, mass-assignment is real.

### Money / business invariants

- Order placement: balance check + balance debit — atomic? In a
  DB transaction with row lock?
- Refund: idempotent? Locks the row?
- Webhook handlers: signature verify *before* parsing body (timing
  side channel), or after?
- Coupon redemption: marks redeemed in same transaction as applied?

### Input handling

- SQL: search for raw queries (`DB::raw`, `query()`,
  `connection.execute(`, `sequelize.query(`,
  `entityManager.createNativeQuery(`). Each is a candidate.
- Command exec: `exec(`, `system(`, `shell_exec(`,
  `subprocess.call(`, `Runtime.getRuntime().exec(`,
  `child_process.exec(`. Each is a candidate; check whether arg is
  user-influenceable.
- Deserialization: `unserialize(`, `pickle.loads(`,
  `ObjectInputStream`, `Marshal.load`. Where does the input come
  from?
- File operations: `fopen(`, `file_get_contents(`,
  `Path.Combine(`, `path.join(`. Path-traversal candidates.
- HTTP outbound: `curl_exec(`, `requests.get(`, `Http.fetch(`,
  `WebClient.GetAsync(`. SSRF candidates if URL is user-driven.
- Template rendering: where does the template engine evaluate user
  input?

### Crypto

- Random: `rand(`, `mt_rand(`, `Math.random(`. Token / secret
  generators must use `random_bytes`, `SecureRandom`,
  `crypto.randomBytes`, or `secrets`.
- Hashing: `md5(`, `sha1(` for password storage — finding.
- Symmetric: `mcrypt_*`, ECB mode, hardcoded IVs.
- Custom crypto — almost always a finding.

### Secrets

```bash
# Repo-wide secret scan
gitleaks detect --source .
trufflehog filesystem .
# Or:
grep -rE "(api[_-]?key|secret|password|token|access[_-]?key)" \
     --include="*.{php,py,js,ts,rb,java,go,cs,yaml,yml,env}" .
```

History matters too:
```bash
gitleaks detect --source . --log-opts="--all"
trufflehog git file://. --no-update
```

Old commits with rotated secrets are still findings if the rotation
isn't documented or if the commits are recent enough.

---

## 20.5 Semgrep — semantic patterns

`semgrep` runs predefined rules against source. Useful for:

- Common anti-patterns (unsafe SQL string interpolation, unsafe
  yaml.load, etc.).
- Custom rules for the project's specific invariants ("no controller
  may bypass middleware X").

```bash
semgrep --config p/security-audit .
semgrep --config p/owasp-top-ten .
semgrep --config p/<language> .
```

Run early, treat output as hypothesis fuel — most matches need human
verification.

---

## 20.6 CodeQL — deeper static analysis

For larger / longer-engagement projects:

- CodeQL builds a queryable database from the source.
- Existing query packs cover most CVE-patterns.
- Custom queries for project-specific checks ("which controllers
  call `executeRaw` with parameters from the request?").

CodeQL takes setup effort; deploy when the project is large enough
to justify (>50 KLOC, multi-month engagement).

---

## 20.7 Per-finding: file:line + minimal patch

For every finding (whether discovered black-box or in source review),
upgrade the finding doc with:

- `file:line` of the root cause.
- Quoted excerpt of the offending code.
- Proposed minimal patch (with the patch in a fenced code block).
- Explanation of why this patch fixes it AND why a simpler-looking
  alternative wouldn't.

Operators don't always have a security-savvy engineer reading the
report. The patch should be specific enough that a competent
generalist can apply and test it.

---

## 20.8 What the source pass typically finds

Common discoveries:

- Routes not in the inventory (admin tools, debug tools, API
  versions).
- Inconsistent middleware application (some routes covered, some
  forgotten).
- Mass-assignment risks on update endpoints not visible from
  outside.
- Race conditions visible from missing locks / transactions.
- Hardcoded secrets in code or configuration.
- Logging that includes sensitive data.
- TODO / FIXME comments naming known weaknesses left as-is.
- Authorization checks that are present but trivially bypassable
  (`if (request.role == 'admin')` where role is request-supplied).
- Test backdoors left in production code (`if ($_GET['debug']) {
  $authorized = true; }`).

---

## 20.9 Phase exit checklist

- [ ] Stack and structure inventoried.
- [ ] Route table cross-referenced against endpoint inventory; dark
       routes added to hypotheses.
- [ ] Each open hypothesis verified or refuted from source.
- [ ] Auth / authz layer audited.
- [ ] Money / business-invariant code paths read end-to-end.
- [ ] Input-handling sinks (SQL, exec, deserialization, fs, HTTP)
       enumerated.
- [ ] Crypto usage audited.
- [ ] Repo and history scanned for secrets.
- [ ] semgrep / CodeQL run; relevant findings triaged.
- [ ] Each finding upgraded with file:line + patch.
- [ ] Re-ranked findings in light of source.
