# CRUCIBLE — Architecture

The design of CRUCIBLE v2: what makes a finding trustworthy, how the pipeline
turns a seed URL into oracle-confirmed findings, and how the safety stack keeps an
autonomous engine inside its authorization. For running it see
[OPERATOR-GUIDE.md](./OPERATOR-GUIDE.md); for extending coverage see
[CHECK-AUTHORING.md](./CHECK-AUTHORING.md).

---

## 1. The prove-don't-guess invariant

CRUCIBLE is organised around a single load-bearing rule:

> A finding is `confirmed` for exactly one reason — a **deterministic oracle
> fired** at or above threshold over data a **real target actually produced**.

Everything else is subordinate. The LLM may *propose* where to look and what to
try; it never decides whether a bug is real. That decision belongs to the oracle
layer, which is pure, deterministic, and re-runnable.

The type system encodes the rule. `verify/confirmation.py` defines
`ConfirmedFinding` — and an instance **only ever exists** when at least one oracle
fired at ≥ threshold. `confirm_finding(...)` returns `None` otherwise. There is no
assertion-only constructor. As its docstring puts it: *the type is the proof.*

---

## 2. The oracle layer — the confirmation authority

`verify/oracles.py` is a set of pure functions. Each takes **already-observed**
data (responses, latencies, captured output, inbound hits) and returns an
`OracleSignal`: did a real signal fire, with what calibrated confidence, and the
evidence that justifies it. Oracles do no I/O, read no clock, draw no randomness —
same inputs, same verdict, every time.

The families (from `verify/models.py :: OracleKind`):

| Oracle | Fires on | Guard against false positives |
|--------|----------|-------------------------------|
| `DIFFERENTIAL_RESPONSE` | boolean/logic divergence (status/length/lexical/structural) | AST-structural diff is invariant to CSRF/nonce/timestamp noise |
| `TIMING` | delay-injected requests are stochastically slower | Mann-Whitney U + Hodges-Lehmann effect floor + optional dose-response scaling |
| `BOOLEAN_INFERENCE` | repeated true≠false with a stable false control | Wald SPRT; a page that changes every request trips the control, not the signal |
| `REFLECTION_CONTEXT` | a marker reached an **executable** HTML/JS position | response is *parsed*; an HTML-encoded/inert reflection does not fire |
| `EVALUATION` | an injected expression was **evaluated** server-side | requires the computed result present AND the raw expression absent |
| `ERROR_SIGNATURE` | an engine-specific datastore/parser error a payload provoked | known signatures only; control must not contain the same error |
| `DOM_EXECUTION` | injected JS actually ran in a real DOM | canary arrives via a CDP binding only the driver registered — near-unforgeable |
| `OOB_CALLBACK` | an inbound interaction on a per-finding unique token | token uniqueness makes a hit near-unforgeable |
| `ACHIEVED_STATE` | a dangerous **condition** holds over raw observed values | predicate evaluated over the actual values, not a rubber-stamped boolean |
| `SIDE_EFFECT` | a unique marker surfaced in a sink it should never reach | marker must be non-trivial (≥ 4 chars) |
| `SANITIZER_SIGNAL` | ASAN/UBSAN/panic/abort/traceback in captured output | strongest match wins; a bare traceback fires only at moderate confidence |

`verify/verifier.py :: OracleVerifier.confirm(context)` is the dispatcher. It reads
the finding's `bug_class`, selects the applicable oracle kinds from
`BUG_CLASS_ORACLES`, runs each **only if its inputs are present**, and confirms
when at least one fired at ≥ `HIGH_CONFIDENCE` (0.70). The combine policy is
**safety-monotone**: one high-confidence fired oracle is sufficient, and a
non-firing oracle **cannot veto** it (absence of a signal is not evidence of
absence). A disagreeing oracle that ran is recorded as *dissent*, never a
refutation.

### The re-verifiable certificate

A confirmed finding carries its serialized oracle context (`oracle_context` /
`FindingContext`). Because the oracles are pure and the context is plain data,
anyone can reconstruct the verdict offline:

```bash
python3 -m framework.v2 verify <report-or-finding.json>
```

This re-runs each certificate's oracle from stored evidence and reports whether it
still reproduces and still matches its original claim. A finding is not "trust the
tool" — it is a portable, checkable proof.

---

## 3. The pipeline

`scanner/campaign.py :: WebScanCampaign.run(seed_url)` is the crawl→confirm loop as
a single product. The same campaign runs under both entrypoints; only the injected
`send` differs (a plain loopback client for `scan`, the gated executor for
`engage`).

```
  seed URL
     │
     ▼
┌─────────────┐   crawl the app (bounded by max-pages / max-depth);
│  CRAWL /    │   passively analyse every response (headers, cookies,
│  DISCOVERY  │   disclosures) → passive_findings.
└─────┬───────┘   optional: SPA crawler (headless browser) captures
      │           fetch/XHR endpoints a static crawl can't see.
      ▼
┌─────────────┐   FINGERPRINT the crawled responses → a flat token set
│ FINGERPRINT │   (server/language/framework/cms/cdn/waf/...). Pure,
│  (scoping)  │   deterministic, stdlib-only classification.
└─────┬───────┘
      ▼
┌─────────────┐   decompose each request into INSERTION POINTS (query
│  INSERTION  │   value/name, body form, JSON leaf/key, cookie, header,
│   POINTS    │   whole body, path segment).
└─────┬───────┘
      ▼
┌─────────────┐   select library entries whose applies_when matches the
│   CHECKS    │   fingerprint tokens; compile to point-level + request-
│ (built-in + │   level checks (split_checks). A contextual bandit ORDERS
│  library)   │   effort per archetype (never drops a check).
└─────┬───────┘
      ▼
┌─────────────┐   each check produces OBSERVED evidence; the matching
│   ORACLES   │   ORACLE adjudicates. Confirmed → AuditFinding with a
│  (confirm)  │   re-verifiable certificate. Not proven → candidate.
└─────┬───────┘
      ▼
┌─────────────┐   confirmed findings + endpoints written into the
│ WORLD-MODEL │   WorldModel as ENDPOINT / FINDING nodes (EVIDENCES
│ / CHAINING  │   edges), so the planner can reason over and chain them.
└─────┬───────┘
      ▼
┌─────────────┐   ScanReport: pages_crawled, requests_audited/sent,
│   REPORT    │   active_findings (confirmed, with oracle + certificate),
│             │   passive_findings, dom_xss_candidates, discovered
└─────────────┘   endpoints, fingerprint, library_checks_run.
```

Key properties:

- **Data-driven checks.** New coverage is a JSON `LibraryEntry`
  (`scanner/library_entries/`), not a code change — see
  [CHECK-AUTHORING.md](./CHECK-AUTHORING.md). Built-in Python checks and library
  checks are adjudicated by the *same* oracles, so precision is identical.
- **Fingerprint scoping.** `select_entries(entries, fp.tokens)` runs only the
  entries relevant to the detected stack. A WordPress payload never fires at a
  Spring app — precision, not just less noise.
- **One shared budget.** A single `AuditEngine` spans the campaign, so its request
  counter enforces one active-traffic budget across all endpoints.
- **Self-learning order.** A contextual bandit (`scanner.learning`) keys posteriors
  on an archetype and can be persisted/warm-started (`--bandit-file`). It only
  orders effort; it never drops a check, so coverage is unaffected.

---

## 4. The fail-closed safety / authority stack

The loopback `scan` client is loopback-only by refusal. Everything that can touch
an authorized **remote** target goes through `agents/http_executor.py ::
HttpExecutor`, whose `gated_fetch` **is** the scanner's `send` under `engage`. Six
gates run per action, order load-bearing, none bypassable without a code change:

```
  every action
      │
      ▼
  1. AUTHORITY / KILL-SWITCH   ← re-read from disk EVERY action; a trip anywhere
      │                          (CLI, another process) halts the next request.
      ▼
  2. SCOPE GATE                ← target host must be in charter scope; redirects
      │                          re-gated per hop (no in-scope→metadata bounce).
      ▼
  3. DESTRUCTIVE-CONFIRM       ← destructive method/URL prompts the operator;
      │                          default-DENY on timeout or non-tty.
      ▼
  4. PER-ENGAGEMENT BUDGET     ← the request ceiling for the whole engagement.
      │
      ▼
  5. POSTURE RATE-LIMIT        ← TEST / AUDIT / EMULATE pacing + jitter.
      │
      ▼
  6. EGRESS ALLOWLIST          ← (when set) SovereignHttpxTransport refuses a
      │                          non-allowlisted host before bytes leave the box.
      ▼
   issue → archive request+response to evidence/ → structured log event
```

Design stance — the opposite of an unstoppable weapon:

- **The kill-switch is absolute and persistent.** It is a file on disk, re-read
  every action, so it survives a process restart and halts the next request
  immediately (`authority halt --slug ...`). It works even without a full
  authority object; every engagement auto-wires one.
- **Authority is narrow and signable.** `EngagementAuthority` carries in-scope
  hosts, a validity window, the target environment (TWIN / STAGING / LIVE),
  whether destructive actions are permitted, and an action budget. It can be
  signed with the entitlement layer's **Ed25519** m-of-n threshold crypto; when a
  trust root is configured, the executor loads a *verified* authority and fails
  closed on a missing or badly-signed document.
- **Preflight fails closed.** `engage` refuses a tripped kill-switch, an
  out-of-scope seed, or a non-allowlisted OOB relay host *before any traffic* —
  and the per-request gates still enforce all of it on every hop.
- **Refusals are evidence.** A gate refusal is a recorded outcome, not a crash;
  the framework preserves that it chose *not* to act.

---

## 5. The browser / DOM subsystem

DOM-XSS is confirmed by **execution**, not reflection. `scanner/cdp.py` is a
minimal Chrome DevTools Protocol driver that speaks CDP over the scanner's own
RFC-6455 WebSocket client (`scanner/websocket.py`) — pure stdlib plus that client,
no third-party browser-automation dependency. It launches headless Chromium
(`--headless=new`, an OS-assigned debug port, sandbox-tolerant flags), and the
context manager tears down the process, the temp user-data dir, and the WS
connection.

The load-bearing primitive is `Runtime.addBinding`: the driver registers
`window.__crucible_xss(...)`, a callback **only it** could have registered.
`scanner/browser_xss.py` injects payloads that — *if they execute* — call that
binding with a unique canary. The `DOM_EXECUTION` oracle fires only when the
browser actually invoked the binding carrying the canary. That is the strongest
XSS evidence there is: real JavaScript execution observed in a real DOM, and it
lands in `active_findings` with a `dom_execution` certificate like any other
confirmed finding. If no browser is found, the dynamic path is skipped cleanly — a
browser check never guesses.

The same driver powers the `--spa` crawler, which records the `fetch`/XHR
endpoints an SPA only exposes after interaction.

---

## 6. The out-of-band collaborator

Blind classes (SSRF, blind XXE, OOB SQLi, deserialization/JNDI, blind command
injection) confirm on an inbound interaction against a per-finding unique token.
`verify/oob.py :: OOBReceiver` binds loopback only, so it works when the target is
co-resident. For a genuinely remote target, `verify/collaborator.py` is a
**self-hostable** relay — a collaborator you *host*, not one you rent:

- `RelayServer` runs on a host the operator owns and has put on the charter
  allowlist. It records every inbound interaction keyed by the token in the first
  path segment and exposes an **authenticated** poll endpoint (shared secret,
  constant-time compared). It emits no traffic of its own beyond a 1-byte 200 so
  the triggering fetch completes. Run it with
  `python3 -m framework.v2 collaborator serve`.
- `RelayClient` is the scanner-side half. It mints tokens whose callback URL points
  at the relay and polls the authenticated endpoint, exposing the exact
  `register_token()` / `poll()` surface of the loopback receiver — so it drops into
  the OOB check path unchanged. A poll error yields an empty list; a transient
  fault never crashes a scan or fabricates a hit.

Because the operator hosts the relay on an allowlisted host, the scanner's only
egress is to that allowlisted relay — the sovereignty/egress doctrine holds, and
`engage` refuses a relay host not in charter scope.

---

## 7. The coverage architecture (Milestone-1 spine)

Coverage is designed to scale to thousands of checks without diluting precision:

- **Declarative library.** `scanner/library.py` turns a check into data: a
  `LibraryEntry` carrying a payload, an `OracleSpec` (which of the concrete check
  shapes runs it), and an `applies_when` predicate. `load_library` validates every
  `*.json` under `library_entries/` at load — a typo, a bad predicate, a missing
  `{marker}`/`{callback}`, or a duplicate id is a **load-time error**, never a
  silent no-op.
- **Fingerprint scoping.** `scanner/fingerprint.py` classifies the crawl into a
  token set; predicates gate entries against it (`{"tech": ...}`, `{"category":
  ...}`, `any`/`all`/`not`). Framework/CMS detections imply their runtime language
  so gating works even when no banner leaked.
- **The benchmark spine.** The comparative harness (`eval/validation.py`) is the
  scoring core: one normalized finding shape every tool speaks, a precision/recall
  `Scoreboard` paired with a `RunMetrics` cost record, and a greedy
  `(bug_class family, path+param)` matcher — **including safe controls a precise
  scanner must leave alone**, so off-manifest detections are false positives by
  construction. It runs CRUCIBLE against the labelled in-process app
  (`eval/benchmark_run.py`) and against the dockerized multi-app corpus
  (`eval/corpus_run.py`, neutral OWASP-Benchmark truth via `eval/owasp_benchmark.py`),
  and `eval/gate.py` turns a committed baseline into a zero-tolerance regression gate
  (`make gate`) — a new library entry must add recall without costing precision. The
  full methodology is `docs/BENCHMARK.md`. (`scanner/benchmark.py` is an older
  WAVSEP-style single-app harness kept for its local checks; new work targets the
  `eval/` spine.) `verify/confirmation.py` carries the same discipline
  at the unit level: a `DifferentialDemoHandler` that must confirm and a
  `SafeDemoHandler` twin that must return `None` — the negative control proving the
  authority does not rubber-stamp.

Every layer routes back to §1: an entry is only ever confirmed by a deterministic
oracle, so adding coverage cannot add false positives.

---

## 8. Honest current limitations

- **The browser path is loopback-only.** `--browser-xss` and `--spa` are exposed on
  `scan` (loopback) but **not** on `engage`. A remote browser path is pending a CDP
  request-allowlist so the headless browser's own egress can be gated the way the
  HTTP executor gates the scanner's.
- **OOB is HTTP-only; DNS-only interactions are not covered.** The collaborator
  relay records HTTP fetches of the callback. A DNS-only interaction (a
  `nslookup`/`dig` with no HTTP fetch) needs a DNS-capable relay — a documented
  future extension, not silently implied.
- **`bug_class` routing has a permissive fallback.** An unrecognised `bug_class`
  falls back to trying every oracle rather than failing; it can still confirm via
  whichever oracle its check fed, but the intent is implicit. New classes should be
  routed explicitly in `verifier.BUG_CLASS_ORACLES` (see
  [CHECK-AUTHORING.md](./CHECK-AUTHORING.md) §4).
- **The favicon fingerprint table is a stub.** Favicon hashing is wired and real,
  but the known-favicon table is illustrative; header/body signatures do the real
  work.
- **This is a foundation, not a frontier autonomy loop.** Per the top-level v2
  README, the long-horizon autonomous campaign planner and multi-agent
  orchestration are deferred subsystems; v2 today scaffolds engagements and runs the
  oracle-anchored scan/engage arsenal. Without a reachable LLM backend the reasoning
  layer runs in DryRun mode — the scanner and oracles do not need one.

---

## See also

- [CRUCIBLE-AI.md](./CRUCIBLE-AI.md) — the AI's guide to the system: agents, the immutable
  event spine, the veracity (anti-hallucination) layer, the learning/metacognition core, and
  the safety stack (paired with the loadable `/.claude/skills/crucible/SKILL.md`).
- [OPERATOR-GUIDE.md](./OPERATOR-GUIDE.md) — install, authorization, running
  `scan`/`engage`, OOB, the kill-switch.
- [CHECK-AUTHORING.md](./CHECK-AUTHORING.md) — add a bug class as one JSON file.
- `/home/kali/Pictures/PENTEST-main/CLAUDE.md` — the OBSIDIAN constitution.
