# MERIDIAN — the VIGIL cyber-range (deliberately-vulnerable test app)

**MERIDIAN** is a self-contained practice target that ships with VIGIL. It is a *fictional* **National
Permits & Licensing Authority** web application — a realistic government service (citizen front-office + a
five-role staff back office) that is **deliberately vulnerable on purpose**, so you can point VIGIL at it and
watch the whole engine work end to end: find real vulnerabilities, **prove** them, map them to compliance
frameworks, produce **auditor-verifiable evidence**, **detect** the same attacks in the logs, then **harden
and re-prove**.

It is the estate's own lab — in the spirit of OWASP Juice Shop / DVWA / WebGoat, but government-themed and
wired straight into VIGIL. It lives in [`range/`](../range/) and runs with one command, **`target up`**.

> ⚠ **Intentionally vulnerable — lab only.** MERIDIAN binds **loopback only**, holds **no real data** (only
> synthetic, tagged records), and every "leak" is a decoy (a path-traversal returns a fake passwd string, not
> a real file). It ships a persistent *"INTENTIONALLY VULNERABLE — LAB ONLY"* banner and a
> [`LAB-MANIFEST.json`](../range/LAB-MANIFEST.json). Do **not** deploy it, expose it to a network, or enter
> real data. It is authorized by [`targets/meridian/charter.md`](../targets/meridian/charter.md), which
> VIGIL's own scope gate accepts.

---

## What it is — two halves

| Half | Port | What it is |
|---|---|---|
| **MERIDIAN portal** (the target) | `19010` | The deliberately-vulnerable government service VIGIL scans. |
| **Range Control** (the cockpit) | `19011` | An operator console that drives the **real** VIGIL verbs against MERIDIAN and streams the results — a guided tour, a capability catalogue, and a tabbed results panel (Findings · Compliance · Business impact · Evidence). |

Range Control never bypasses a gate: it shells VIGIL's ordinary, charter-scoped CLI. It only ever runs a
**closed set** of verb templates with the target and slug fixed to loopback / `meridian` — no browser input
ever reaches a command line. The whole `range/` package is stdlib-only and never imports the offense engine,
so the two-env boundary is unaffected.

---

## How to run it

### 1 · One-time setup
```bash
make setup           # builds the two isolated venvs + kernel + services, and installs the `target` launcher
```
`make setup` installs `range/` into the offense environment and symlinks the **`target`** console-script onto
your `PATH` (`~/.local/bin/target`, alongside `vigil` and `sigil`).

### 2 · Bring the range up
```bash
target up            # starts MERIDIAN (:19010) + Range Control (:19011), loopback only
```
Then open **http://127.0.0.1:19011/** and click **“Run all ▸”**, or browse the vulnerable portal at
**http://127.0.0.1:19010/**.

### 3 · The full `target` command set
```bash
target up [--hardened] [--port 19010] [--control-port 19011] [--no-browser]
target down                  # stop the range
target status                # running state · mode (vuln|hardened) · ports
target harden on             # neutralize every planted sink LIVE (no restart) — for the re-prove demo
target harden off            # restore vulnerable mode
target seed                  # rebuild the synthetic database from scratch
target charter               # print the engagement charter that authorizes VIGIL against the range
```

### 4 · Drive VIGIL against it by hand (what Range Control runs for you)
All of these are loopback and safe. Run them from the repo root.
```bash
# Recon + confirm SQLi & reflected XSS as oracle FACTs (focused, ~1 min)
python3 -m framework.v2 scan "http://127.0.0.1:19010/records/search?q=test" \
    --max-pages 2 --max-depth 0 --format json --reverifiable-out /tmp/meridian.json

# Confirm IDOR / BOLA with two identities (attacker reads another citizen's PII)
python3 -m framework.v2 scan "http://127.0.0.1:19010/api/applications?id=2" \
    --access-control --ac-ref idor:id:2 --ac-victim-header "Cookie: session=<victim>" \
    --max-pages 2 --max-depth 0 --format json

# Confirm SSRF via an out-of-band callback
python3 -m framework.v2 scan "http://127.0.0.1:19010/documents/fetch?url=http://placeholder.test/" \
    --max-pages 2 --max-depth 0 --format json

# Re-verify every finding OFFLINE, with no trust in the scanner (prove-don't-guess)
python3 -m framework.v2 verify /tmp/meridian.json

# Export SARIF for your CI / security tooling
python3 -m framework.v2 scan "http://127.0.0.1:19010/records/search?q=test" \
    --max-pages 2 --max-depth 0 --format sarif

# Sign a hash-linked evidence bundle, then re-verify it OFFLINE (bundle SOUND)
python3 -m framework.v2 evidence keygen                      # → {public_key_b64, private_key_b64}
python3 -m framework.v2 evidence certify --report /tmp/meridian.json --slug meridian \
    --out /tmp/bundle --signer meridian-signer:<private_key_b64>
python3 -m framework.v2 evidence verify --report /tmp/meridian.json \
    --bundle /tmp/bundle --trust-root /tmp/trust-root.json

# The DEFENSIVE half — read MERIDIAN's own logs and detect the attack
vigil detect --access-log <logdir>/access.log --auth-log <logdir>/auth.log --conn-log <conn.log>

# The governed, gated engagement (charter-scoped, approve-then-run, mirrored on the event spine)
vigil engage http://127.0.0.1:19010/ --slug meridian --scope 127.0.0.1

# Harden every sink, then re-prove: the same scan now returns ZERO confirmed findings (a sound CLOSED negative)
target harden on
python3 -m framework.v2 scan "http://127.0.0.1:19010/records/search?q=test" --max-pages 2 --max-depth 0 --format json
target harden off
```

A step-by-step presenter script for a live demo is in [`range/DEMO.md`](../range/DEMO.md).

---

## What it tests — the 17 planted weaknesses

Each weakness is real and reachable at the endpoint shown. VIGIL does not *assert* it — a deterministic
**oracle** re-runs the exploit and confirms it as a **FACT** over data the live target produced. Every
weakness has a hardened twin (same route/param, sink neutralized), so `target harden on` turns each into a
sound CLOSED negative.

| # | Weakness | Where | How VIGIL confirms it |
|---|----------|-------|-----------------------|
| 1 | **SQL injection** (error + boolean) | `GET /records/search?q=` | real SQLite error signature + a boolean response differential — **oracle FACT** |
| 2 | **Reflected XSS** | `GET /records/search?q=` | canary lands unescaped in an executable position — **oracle FACT** |
| 3 | **Stored XSS** | `GET /track`, `/staff` | a stored note rendered unescaped on a later page |
| 4 | **Path traversal** | `GET /documents/download?file=` | a decoy `root:x:0:0:` signature on an escape — **oracle FACT** |
| 5 | **Open redirect** | `GET /auth/continue?next=` | a 30x `Location` to the attacker host |
| 6 | **Secret exposure** | `GET /.env`, `/actuator/env` | a known path returns a (fake) secret-bearing signature |
| 7 | **IDOR / BOLA** | `GET /api/applications/{id}` | two-identity: attacker reads the victim's PII verbatim — **oracle FACT** |
| 8 | **CORS misconfiguration** | `/api/*` (Origin) | reflects a hostile Origin + `Allow-Credentials: true` |
| 9 | **Host-header injection** | `GET /api/applications/{ref}/share` | the attacker Host becomes the authority of an emitted URL |
| 10 | **Broken access control** | `GET /staff` | the review queue (PII) is reachable with no session |
| 11 | **BFLA** (function-level) | `POST /staff/applications/{id}/approve` | any caller can approve — no function-level authz |
| 12 | **Privilege escalation** | `POST /admin/users/{id}/role` | any caller can elevate itself to administrator |
| 13 | **Business logic** (fee bypass) | `POST /api/applications/{id}/pay` | a `$0` / negative payment marks the fee PAID |
| 14 | **Weak authentication** | `POST /login` | no rate limit → drives the defensive brute-force detection — **detect FACT** |
| 15 | **SSRF** | `GET /documents/fetch?url=` | the server's outbound request lands on an OOB callback — **oracle FACT** |
| 16 | **XXE** | `POST /documents/import` | an external XML entity is resolved → the same OOB callback |
| 17 | **LLM prompt injection** | `GET /assistant?q=` | an injection makes the PermitBot assistant leak its system prompt + secret |

**And the defensive half:** VIGIL then reads MERIDIAN's own `access.log` / `auth.log` / `conn.log` and
**detects the attack** — 6 oracle-proven detections (forced-browsing, SQLi structure, path traversal,
command-injection structure, port-scan, brute-force) — exercising the control OWASP calls *A09: Security
Logging & Monitoring*.

---

## The compliance mapping (what a government buyer evaluates)

Range Control's **Compliance** tab maps every confirmed finding to the frameworks a government procures
against, and exports the findings as **SARIF**. The primary control per framework is shown (not exhaustive).

| Weakness | OWASP Top 10 (2021) | OWASP API (2023) | ASVS | NIST 800-53 | ISO 27001 | CIS v8 | ATT&CK |
|----------|---------------------|------------------|------|-------------|-----------|--------|--------|
| SQL injection | A03 Injection | — | V5.3.4 | SI-10 | A.8.28 | 16.11 | T1190 |
| Cross-site scripting | A03 Injection | — | V5.3.3 | SI-10 | A.8.28 | 16.11 | T1059.007 |
| IDOR / BOLA | A01 Broken Access Control | API1 BOLA | V4.1.1 | AC-3 | A.8.3 | 3.3 | T1213 |
| Access ctrl / BFLA / priv-esc | A01 Broken Access Control | API5 BFLA | V4.1.3 | AC-6 | A.8.3 | 6.8 | T1068 |
| SSRF | A10 SSRF | API7 | V12.6.1 | SC-7 | A.8.22 | 12.2 | T1090 |
| Path traversal | A01 Broken Access Control | — | V12.3.1 | AC-6 | A.8.3 | 3.3 | T1083 |
| Open redirect | A01 Broken Access Control | — | V5.1.5 | SI-10 | A.8.28 | 16.11 | T1204 |
| Secret exposure | A05 Misconfiguration | API8 | V14.3.2 | IA-5 | A.8.24 | 3.11 | T1552.001 |
| CORS misconfiguration | A05 Misconfiguration | API8 | V14.5.3 | AC-4 | A.8.22 | 12.2 | T1190 |
| Host-header injection | A05 Misconfiguration | — | V5.1.1 | SI-10 | A.8.28 | 16.11 | T1190 |
| Business logic (fee) | A04 Insecure Design | API6 | V11.1.1 | SI-10 | A.8.26 | 16.10 | T1499 |
| Weak authentication | A07 Authn Failures | API2 | V2.2.1 | IA-2 | A.8.5 | 6.3 | T1110 |
| XXE | A05 Misconfiguration | — | V5.5.2 | SI-10 | A.8.28 | 16.11 | T1059 |
| LLM prompt injection | LLM01 (LLM Top 10) | — | LLM01 | SI-10 | A.8.28 | 16.11 | AML.T0051 |
| Missing logging / detection | A09 Logging & Monitoring | — | V7.1.1 | AU-6 | A.8.15 | 8.11 | — |

Frameworks: **OWASP Top 10** (web), **OWASP API Security Top 10** (APIs), **OWASP ASVS** (verification
requirements — Level 2 is the usual government bar), **OWASP LLM Top 10** (AI), **NIST SP 800-53** (US
federal / FedRAMP / ATO), **ISO/IEC 27001** (international ISMS), **CIS Controls v8** (prioritised
remediation), **MITRE ATT&CK** (real adversary techniques).

---

## The end-to-end demo (what “Run all ▸” walks through)

1. **Recon** — crawl the portal, map every endpoint/form/param.
2. **Confirm SQLi + XSS** — the oracle proves both as FACTs. *(OWASP A03 · ASVS V5.3)*
3. **Confirm IDOR / BOLA** — one citizen reads another's identity record. *(A01 · API1 · NIST AC-3)*
4. **Confirm SSRF** — the server is made to call attacker infrastructure. *(A10 · API7 · SC-7)*
5. **Verify offline** — re-prove every finding from evidence, no trust in the tool.
6. **Export SARIF** — the format your CI / tooling ingests.
7–8. **Sign & verify evidence** — a signed bundle an auditor re-checks **offline** (“bundle SOUND”).
9. **Detect** — read the logs and detect the attack. *(A09 · NIST AU-6)*
10–12. **Harden → re-prove → restore** — fix the flaws; the re-scan returns **0 findings on a live check** —
a Certificate of Non-Exploitability, not just silence.

---

## Where the code is

```
range/
  vigil_range/
    cli.py · launcher.py · apps.py         # the `target` command + loopback launcher + app registry
    meridian/                              # the deliberately-vulnerable application
      app.py · router.py · config.py · logs.py · theme.py · db.py · seed.py · auth.py
      handlers/                            # base · portal · records · api · staff (+ admin console) · documents · assistant · discovery · authroutes
      vulns/registry.py                    # the single source of truth for every planted weakness
    rangecontrol/                          # the Range Control cockpit
      console.py · runner.py (closed-set) · catalog.py · compliance.py · impact.py
  meridian_target.py                       # standalone launcher registered in the loopback-range manifest
  tests/                                   # 52 stdlib tests (bind guard, vuln/hardened, logs, charter, compliance, evidence)
  README.md · DEMO.md · LAB-MANIFEST.json
targets/meridian/charter.md                # the authorization VIGIL's scope gate accepts
tools/livefire/range_targets.json          # the loopback-range registry entry (kind: process, port 19010)
```

See also: [`range/README.md`](../range/README.md) (quick start), [`range/DEMO.md`](../range/DEMO.md)
(presenter script), and [CLI-REFERENCE.md](CLI-REFERENCE.md) (every `vigil` verb the range drives).
