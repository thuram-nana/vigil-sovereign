# CRUCIBLE — Operator's Guide

Practical, end-to-end guide to running CRUCIBLE v2 against systems **you own and
are authorized to test**. If you want to know *how it works inside*, read
[ARCHITECTURE.md](./ARCHITECTURE.md). If you want to *add coverage* without
touching engine code, read [CHECK-AUTHORING.md](./CHECK-AUTHORING.md).

This document is subordinate to the OBSIDIAN constitution
(`/home/kali/Pictures/PENTEST-main/CLAUDE.md`). Where the two conflict, the
constitution wins — especially on authorization, scope, and honesty.

---

## 1. What CRUCIBLE is

CRUCIBLE is an autonomous web-pentest engine built on one invariant:

> **Prove, don't guess.** A finding is `confirmed` for exactly one reason — a
> deterministic *oracle* fired at or above threshold over data a real target
> actually produced. There is no assertion-only path to a confirmed finding.

Concretely:

- **Oracle-anchored.** Every confirmation is discharged by a pure, deterministic
  function in `verify/oracles.py` (a response differential, a Mann-Whitney timing
  test, an SPRT boolean inference, a real DOM-execution signal, an out-of-band
  callback, a datastore error signature, an evaluated-expression check, ...). The
  LLM never gets a vote on whether a bug is real.
- **Near-zero false positives, by construction.** The oracles are written to
  *refuse* the cases DAST tools over-report: an HTML-encoded XSS reflection is
  inert (parsed, not substring-matched); a "significant but tiny" latency shift
  is network jitter, not SQLi; a raw template that survives verbatim was
  reflected, not evaluated. When an oracle cannot prove it, CRUCIBLE reports a
  *candidate*, not a finding.
- **Re-verifiable certificates.** Each confirmed finding carries its serialized
  oracle context, so anyone can re-run the verdict offline with
  `python3 -m framework.v2 verify` — no network, no trust in the tool's say-so.

CRUCIBLE will happily tell you it found nothing. That is the point.

---

## 2. Install and prerequisites

CRUCIBLE runs on **Python 3** (3.11+). The analysis core is deliberately
light-weight: crawling, fingerprinting, DOM-XSS static analysis and every oracle
use only the standard library (`html.parser`, `hashlib`, `statistics`, `re`) —
no BeautifulSoup, no numpy, no z3. The dependencies that *are* required are data
and transport libraries.

```bash
# from the repository root
bash bin/init.sh                                              # one-time setup
pip install --break-system-packages -r framework/v2/requirements.txt
python3 -m framework.v2 status                               # sanity check
```

`requirements.txt` pulls `pydantic` (all schemas), `httpx` (the gated executor's
HTTP client), `structlog` (structured logging), plus `requests`, `PyYAML`,
`Jinja2`. The loopback `scan` client itself uses `urllib` from the stdlib; the
authorized-remote `engage` executor uses `httpx`.

**Optional — the browser path.** `--browser-xss` and `--spa` drive a real
headless **Chromium/Chrome** over the Chrome DevTools Protocol. If no browser
binary is found the dynamic path is skipped cleanly (a browser check never
guesses). Any recent Chromium/Chrome on `PATH` works; nothing else is needed.

`status` prints the resolved `CRUCIBLE_ROOT`, the memory DB path, and which
optional LLM backends are reachable. The scanner and oracles do **not** need an
LLM to run.

---

## 3. Authorization — you must be authorized

CRUCIBLE enforces authorization in code, not in a README warning. Two entry
points, two authorization models:

| Command | Reaches | Authorization |
|---------|---------|---------------|
| `scan`  | **loopback only** (`127.0.0.1` / `localhost` / `::1`) | Refuses any non-loopback host outright. |
| `engage`| an authorized **remote** target | Charter + scope + kill-switch, enforced on every request. |

### The charter is binding

An `engage` run is keyed by an engagement **slug** and reads
`targets/<slug>/charter.md`. Before any traffic, `engage` runs a **preflight**
that fails closed:

1. **Kill-switch.** If `targets/<slug>/` has a tripped kill-switch, the
   engagement is refused before a single byte leaves the host.
2. **Scope.** The seed URL's host is validated against the charter's in-scope
   list. Out of scope → refused with a legible reason.
3. **OOB relay hosts.** Any callback base you advertise (`--oob-relay`) or poll
   (`--oob-relay-url`) must *itself* be on the charter allowlist, or the
   engagement is refused.

The charter also declares the **posture** in its § 7 checkbox block
(`[x] **TEST**` / `[x] **AUDIT**` / `[x] **EMULATE**`), which sets rate limits
and the User-Agent (see §7). Default posture is `TEST`.

If the charter is not filled or the operator-attestation is missing, do not
proceed — fill it first. "Just to check" is the phrase that precedes an incident.

---

## 4. Quickstart — the loopback `scan`

`scan` runs the full arsenal — crawl → passive analysis → active audit (per-point
checks + request-level CORS/host-header/JWT/GraphQL checks) → oracle-confirmed
report — against a **loopback** target. It issues traffic through a plain local
`urllib` client and **refuses any non-loopback host** by design; a remote target
must go through `engage` (§6).

```bash
# minimal — crawl and audit a local app
python3 -m framework.v2 scan http://127.0.0.1:8000/
```

### Flags that matter

| Flag | Effect |
|------|--------|
| `--max-pages N` | Crawl budget (default 100). |
| `--max-depth N` | Crawl depth (default 6). |
| `--max-audit-requests N` | Cap total active requests (`0` = unbounded, the default). |
| `--targeted` | Prioritise checks per insertion point by parameter fingerprint (orders effort; never drops a check). |
| `--domxss` | Also emit **static** DOM-XSS source→sink leads. These are *candidates*, not confirmed. |
| `--browser-xss` | Confirm DOM-XSS by **real execution** in headless Chromium. Needs a browser. Loopback-only. |
| `--spa` | Run the SPA crawler to capture `fetch`/XHR endpoints. Needs a browser. Loopback-only. |
| `--no-oob` | Disable the loopback out-of-band receiver. |
| `--bandit-file PATH` | Persist / warm-start the self-learning check-ordering bandit here. |
| `--bandit-context KEY` | Archetype key the bandit keys its posteriors on (default `default`). |

### Real command lines

```bash
# targeted sweep + static DOM-XSS leads
python3 -m framework.v2 scan http://localhost:3000/ --targeted --domxss

# confirm DOM-XSS by execution and discover the SPA's real fetch/XHR surface
python3 -m framework.v2 scan http://127.0.0.1:8000/ --browser-xss --spa

# bound the active traffic and let the bandit learn per-archetype ordering
python3 -m framework.v2 scan http://127.0.0.1:8080/ \
    --max-audit-requests 500 \
    --bandit-file /home/kali/.crucible/bandit.json --bandit-context wordpress
```

The data-driven check library (see [CHECK-AUTHORING.md](./CHECK-AUTHORING.md)) is
selected automatically: CRUCIBLE fingerprints the target from the crawl and runs
only the library entries whose `applies_when` predicate matches the detected
stack, so a WordPress payload never fires at a Spring app.

---

## 5. Reading results

Both `scan` and `engage` print the same shape:

```
scan http://127.0.0.1:8000/
  pages crawled     : 12
  requests audited  : 34 (128 sent)
  confirmed findings: 2
    [differential_response] boolean_sqli @ query_value:id (conf 0.94)
    [reflection_context] xss @ query_value:q (conf 0.95)
  passive findings  : 5
  dom-xss leads     : 1 (candidates, not confirmed)
  spa endpoints     : 3 discovered
    GET http://127.0.0.1:8000/api/users
    ...
```

Read it in four tiers, strongest first:

- **confirmed findings** — the only oracle-proven results. The tag in brackets is
  the **oracle** that carried the confirmation (`differential_response`,
  `timing`, `boolean_inference`, `reflection_context`, `evaluation`,
  `error_signature`, `dom_execution`, `oob_callback`, `achieved_state`,
  `side_effect`, `sanitizer_signal`). `conf` is calibrated confidence. Under
  `engage` each line also shows `/cert` when the finding carries a re-verifiable
  oracle certificate.
- **passive findings** — observations from response analysis (headers, cookies,
  disclosures). Informational; not oracle-confirmed exploits.
- **dom-xss leads** — static source→sink flows (only with `--domxss`). Leads to
  chase, explicitly *not* confirmed. To confirm one, use `--browser-xss`, which
  promotes an executed payload into a confirmed finding with a `dom_execution`
  certificate.
- **discovered endpoints** — the `fetch`/XHR surface the SPA crawler saw (only
  with `--spa`). Feed these back in as new seeds.

### Re-verify a certificate offline

A confirmed finding's certificate re-checks without any network:

```bash
python3 -m framework.v2 verify /path/to/report-or-finding.json
```

It reproduces each oracle verdict from the stored context and reports
`OK`/`BAD` per certificate and whether it still matches its original claim. This
is how you (or a reviewer) audit a finding without re-running the scan.

---

## 6. The authorized-remote `engage` runner

`engage` runs the **same Wave-1 arsenal** as `scan`, but every request flows
through the fail-closed safety stack in `agents/http_executor.py`. The scanner's
injected `send` *is* the gated executor (`HttpExecutor.gated_fetch`) — so the
"every request is gated" claim is literally true, not aspirational.

```bash
python3 -m framework.v2 engage <slug> https://authorized-target.example/seed
```

### Setup

1. Scaffold the engagement and fill the charter at `targets/<slug>/charter.md`
   (target hosts, operator-attestation, hard/soft limits, posture § 7). CRUCIBLE
   reads scope and posture from it.
2. Confirm scope covers the seed host, and any OOB relay host you plan to use.
3. Run `engage`. Preflight refuses a tripped kill-switch, an out-of-scope seed,
   or a non-allowlisted relay host *before* any traffic.

### Flags

| Flag | Effect |
|------|--------|
| `--request-budget N` | Total HTTP requests allowed for the whole engagement (default 200). Exhaustion refuses further actions. |
| `--max-pages N` | Crawl budget (default 100). |
| `--max-audit-requests N` | Cap active audit requests (`0` = unbounded). |
| `--domxss` | Emit static DOM-XSS leads (candidates). |
| `--bandit-file PATH` | Persist / warm-start the check-ordering bandit (context is the slug). |
| `--oob-relay URL` | Operator-hosted, charter-allowlisted OOB callback base URL to **advertise** (tunnel model; hits delivered to a loopback receiver). |
| `--oob-relay-url URL` | Operator-hosted OOB **collaborator** relay to poll (run `collaborator serve`); unlocks blind confirmation on remote targets. |
| `--oob-relay-secret S` | Shared secret for the collaborator relay's poll endpoint. |

Note: `--browser-xss` and `--spa` are **not** exposed on `engage` — the browser
path is loopback-only for now (see §8 and the ARCHITECTURE limitations).

### The gated executor — what every request passes

Per action, in this order, none bypassable without a code change:

1. **Authority / kill-switch** — re-read from disk **every action**, so a trip
   from anywhere (the CLI, another process) halts at the very next request.
2. **Scope gate** — the target host must be in charter scope. Redirects are
   re-gated per hop, so an in-scope URL cannot bounce you to cloud metadata.
3. **Destructive-confirm** — a destructive method/URL prompts the operator and
   **default-denies** on timeout or a non-tty.
4. **Per-engagement budget** — the `--request-budget` ceiling.
5. **Posture rate-limit** — TEST/AUDIT/EMULATE pacing (see §7).
6. **Egress allowlist** (when configured) — a belt-and-braces backstop that
   refuses a non-allowlisted host before bytes leave the machine.

Every request and response is archived to `targets/<slug>/evidence/<action_id>/`
and a structured event is written to the engagement log.

```bash
# a bounded AUDIT-posture engagement with static DOM-XSS leads
python3 -m framework.v2 engage acme-2026 https://app.acme.example/ \
    --request-budget 300 --max-audit-requests 400 --domxss
```

---

## 7. Posture, rate limits, and correlatability

Posture comes from the charter § 7 checkbox and drives pacing + identity so the
operator can find CRUCIBLE's traffic in their own logs:

| Posture | Min gap between requests | Jitter | User-Agent |
|---------|--------------------------|--------|------------|
| `TEST`  | 0.2 s | none | `OBSIDIAN/1.0 (authorized owner-test <date>)` |
| `AUDIT` | 1.0 s | none | `... ; control-test` |
| `EMULATE` | 5.0 s | up to 3 s | realistic browser string |

In `TEST`/`AUDIT` the User-Agent is deliberately **correlatable** — you are not
evading the operator, you want them to grep their logs and find you. `EMULATE` is
for authorized adversary emulation only.

---

## 8. Out-of-band (OOB) confirmation

Blind classes — SSRF, blind XXE, OOB SQLi, deserialization/JNDI, blind command
injection — are confirmed by an inbound interaction on a per-finding unique token
(near-unforgeable evidence). Three modes:

- **Loopback (`scan`, default).** A loopback `OOBReceiver` confirms blind classes
  only when the target is co-resident on the same host. `--no-oob` disables it.
- **`engage --oob-relay <base>`** — advertise a charter-allowlisted callback base
  (tunnel model); hits are delivered to a loopback receiver.
- **`engage --oob-relay-url <base> --oob-relay-secret <s>`** — poll an
  operator-hosted **collaborator** relay. This is what unlocks blind confirmation
  against a genuinely remote target.

### Hosting the collaborator relay

Run it on a host **you own and have put on the charter allowlist**:

```bash
python3 -m framework.v2 collaborator serve --host 0.0.0.0 --port 8080
```

It prints its listen URL, the poll **secret** (mint or pass your own with
`--secret`), the callback URL shape (`http://<this-host>:8080/<token>`), and the
authenticated poll endpoint. Keep the secret; pass it to `engage` as
`--oob-relay-secret`. The relay authenticates polling (constant-time secret
compare) so no third party can read your interactions, and it sends no traffic of
its own beyond a 1-byte 200 to let the triggering fetch complete.

```bash
# on the operator's allowlisted relay host
python3 -m framework.v2 collaborator serve --host 0.0.0.0 --port 8080
# → secret: 9f3c...   callbacks: http://relay.op.example:8080/<token>

# on the scanning host
python3 -m framework.v2 engage acme-2026 https://app.acme.example/ \
    --oob-relay-url http://relay.op.example:8080 --oob-relay-secret 9f3c...
```

**Scope of OOB:** HTTP callbacks (and anything that resolves to an HTTP fetch of
the callback URL — most SSRF, JNDI-over-LDAP-referral-to-HTTP, webhook gadgets).
A **DNS-only** interaction (a `nslookup`/`dig` with no HTTP fetch) needs a
DNS-capable relay, which is a documented future extension, not silently implied.

---

## 9. The kill-switch — the absolute stop

The off-switch is always present. Every `engage` auto-wires a kill-switch bound
to the slug; it is a **file on disk**, so it survives a process restart and a trip
from any source halts the next action immediately.

```bash
# stop an engagement right now (checked before the very next request)
python3 -m framework.v2 authority halt --slug acme-2026 --reason "5xx storm on /search"

# inspect state
python3 -m framework.v2 authority status --slug acme-2026

# deliberately lift the halt (logged, with attribution)
python3 -m framework.v2 authority clear --slug acme-2026 --by operator-jane
```

Trip it the moment you see 5xx storms, sustained latency, signs of degradation,
evidence of a prior compromise, or any doubt about authorization. Clearing it is
a deliberate, attributed act — never automatic.

Engagement authority (scope window, environment TWIN/STAGING/LIVE, action budget)
can also be signed with the entitlement layer's Ed25519 threshold crypto; when a
trust root is configured the executor requires a *verified* authority document
and fails closed if it is missing or badly signed.

---

## 10. A sane first session

1. `python3 -m framework.v2 status` — confirm the environment resolves.
2. Stand up (or point at) a **loopback** copy of the target.
3. `python3 -m framework.v2 scan http://127.0.0.1:<port>/ --targeted` — get a
   confirmed-findings baseline with zero authorization risk.
4. Add `--domxss`, then `--browser-xss --spa` if a browser is available.
5. `python3 -m framework.v2 verify <report.json>` — prove the certificates
   reproduce.
6. Only once the charter is filled and scope is confirmed, move to `engage`
   against the authorized remote — starting in `TEST` or `AUDIT` posture with a
   conservative `--request-budget`.
7. Keep `authority halt` one command away the whole time.

---

## See also

- [ARCHITECTURE.md](./ARCHITECTURE.md) — the prove-don't-guess invariant, the
  oracle layer, the pipeline, the safety stack, the browser/OOB subsystems.
- [CHECK-AUTHORING.md](./CHECK-AUTHORING.md) — add a new bug class as one JSON
  file, no engine change.
- `/home/kali/Pictures/PENTEST-main/CLAUDE.md` — the OBSIDIAN constitution
  (authorization, ROE, documentation discipline).
