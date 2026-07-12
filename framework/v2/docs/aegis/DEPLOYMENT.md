# AEGIS Gateway — deploying the Provable Firewall in front of your app

AEGIS Gateway is an **inline runtime protection layer**: it sits in front of your web app and blocks a
request **only when a deterministic oracle proves it is an attack**, attaching a **re-runnable
certificate** to every block. Because it blocks on *proof* — not on regex signatures or an ML score —
it has **near-zero false positives** (it will not break a real user) and an **auditable reason** for
every decision.

## The honest promise (read this first)

**No firewall "totally" protects an app, and AEGIS does not claim to.** What it gives you:

- **Provable blocks, near-zero false positives.** A request is blocked only when a re-runnable oracle
  fires (a certificate you or an auditor can re-verify offline). A benign apostrophe (`O'Brien`), an
  `AT&T`, an HTML‑encoded reflection — none of these are ever blocked.
- **Fail-open, always.** Any inspection error, a tripped kill-switch, or an unproven request lets
  traffic through. An upstream that is down returns an honest `502`, never a block. **The firewall
  never takes your app down.**
- **Honest coverage.** It blocks the attack classes it has oracles for (below), logs suspicious-but-
  unproven traffic as leads, and never pretends the list is complete. Coverage is measured and grows.

If you need "block everything that looks suspicious," AEGIS is the wrong tool — that posture breaks
real users and is exactly what every WAF does badly. AEGIS blocks what it can *prove*.

## What it blocks today (each with a re-runnable certificate)

| Class | Proved by | Seen from |
|-------|-----------|-----------|
| `sqli_attempt` | the value provably breaks out of a SQL string literal into query structure, anchored at the break-out (a self-tautology `OR 1=1` / `UNION SELECT` / a full stacked statement `; DROP TABLE`) | the request alone |
| `command_injection_attempt` | a dangerous command invoked with a shell argument, inside a substitution (`$(cat /etc/passwd)`) or after a real separator (`; cat /etc/passwd`, `\| nc <ip>`) | the request alone |
| `automated_access` | a fetch of a seeded honeypot path no human UI links | the request alone |
| `xss` (reflected) | a request value reflected **verbatim** whose executable token reached a live executable HTML context (an HTML‑encoded reflection is **not** blocked) | the app's response |
| `ssti` | a request value carried a template-wrapped arithmetic expression (`{{7*7}}`, `${7*7}`, `#{7*7}`, `<%= 7*7 %>`, `*{7*7}`, `@(7*7)`) that the server **evaluated** — the ≥2-digit result appears at a digit boundary and the raw template is gone (a **reflected** template is **not** blocked) | the app's response |
| `path_traversal` | a request value walked the path toward a sensitive file (a real `../`-style traversal indicator) **and** a strict `/etc/passwd`-signature line surfaced in the response — and the value is **not** merely reflected verbatim (a docs/search page echoing `/etc/passwd` is **not** blocked) | the app's response |

The two request-side classes prove a **structured attack attempt**; the three response-side classes
(`xss`, `ssti`, `path_traversal`) prove **exploitation** — the app actually reflected the payload,
evaluated the expression, or leaked the file. The oracles are deliberately conservative — a benign
apostrophe (`O'Brien`), a comparison (`id > 1000`), a tool string (`python-requests/2.28.1`), delimited
data (`Name \| Age`), a pasted SQL query, a coincidental `49` beside a reflected `{{ 7 * 7 }}`, a page
that documents `/etc/passwd`, or a prose em-dash never trip a block. Request-side oracles inspect the
query string **and** header/cookie values (bounded to a safe surface). **Note for code-accepting apps**
(paste bins, dev Q&A, bug trackers): user content that *is* attack syntax (a shared `$(cat ...)`
snippet, a pasted injection payload) will be flagged — run such apps in `observe` and review before
enforcing.

**Graduated challenge / throttle (per-actor belief, entitlement-gated).** Beyond the proof-backed
blocks, an actor that *sustains* suspicious-but-unproven behavior — repeated SSRF/XXE-shaped leads, or
repeated confirmed attacks — earns a **soft, retryable** response short of a block: first `challenge`,
then (higher sustained belief) `throttle` (both HTTP 429). This rides the per-actor Beta belief's
**lower** credible bound *and* mean, so it needs genuinely sustained, suspicion-dominant evidence — a
single hit, or one lead amid benign traffic, never escalates, and a benign actor is never even tracked.
A hard block is **never** belief-driven (prove-don't-guess: only a fired oracle's certificate blocks),
and it is gated behind the `AEGIS_RESPOND` entitlement. A legitimate user caught in a burst simply
retries.

Roadmap (not yet on the block path): **all SSRF** and **all XXE** (in-band file-disclosure *and*
blind/out-of-band) — these need **out-of-band** confirmation (a callback proving the server made the
request / resolved the entity), which a single inline response cannot supply. In-band XXE looks
inline-provable (a `/etc/passwd` line in the response) but is **not**: that line can be *reflected*
user content — a security-KB / paste / code-review page that documents an XXE example and echoes a
sample root line — so blocking it false-positives on benign content and the "proof" is a generic
marker read back out of the same response (a circular self-proof). So today all SSRF/XXE raise
per-actor belief as **leads** and the OOB-hook (a passive correlation on a token the app already
carried) is the documented block path. **Error-based SQLi** likewise needs a differential/OOB
confirmation (a single inline response cannot prove a datastore error was *caused* by the payload
rather than merely displayed near it), so it too stays off the block path.

## Three ways to add it

### 1. Reverse-proxy gateway (any app, any language — no code changes)

Put the gateway in front of your app and point your DNS / load-balancer at it.

```
python3 -m framework.v2 aegis gateway \
    --upstream http://127.0.0.1:3000 \      # your app
    --host 0.0.0.0 --port 8080 \            # where clients connect
    --mode observe                          # start read-only; flip to enforce when ready
```

- **Always start in `--mode observe`.** It inspects and forwards, blocking nothing, and logs a verdict
  (JSON, to stderr / your `on_verdict` sink) for every proven attack it *would* block. Watch it for a
  while, confirm zero false positives against your real traffic, then switch to `--mode enforce`.
- Add `--honeypot /path` (repeatable) to seed tripwire paths (e.g. `/.git/config`, `/wp-admin.bak`) —
  a fetch of one proves automation.
- `--slug <name>` names the gateway for the kill-switch and the audit trail.

The gateway forwards only the request's path+query to the fixed `--upstream` host (no forward-SSRF),
strips hop-by-hop headers, and adds `X-Forwarded-For`.

### 2. Sidecar detect API (any language — your app enforces)

Your app POSTs a description of each incoming request and gets a verdict it acts on itself. Wire
`aegis.middleware.inspect_http` into an endpoint of your choice:

```python
from framework.v2.aegis.middleware import inspect_http

status, verdict = inspect_http(request_json, enforce=True, honeypot_paths=["/.git/config"])
# request_json = {"method": "...", "path": "/x?q=...", "headers": {...}, "body": "..."}
if verdict["action"] == "block":
    return 403, verdict           # AEGIS PROVED an attack; verdict["certificate"] re-runs offline
```

`decision == "clear"` means *nothing was proven*, not *safe*. Malformed input fails closed (`400`).

### 3. In-process WSGI middleware (Python apps — lowest latency)

Wrap your WSGI app; a proven attack is blocked before your app ever sees it. The request body is
buffered and restored, so your app reads it normally.

```python
from framework.v2.aegis.middleware import AegisEnforceMiddleware
from framework.v2.aegis.models import AegisConfig

app = AegisEnforceMiddleware(app, AegisConfig(deployment_secret="<random>", mode="enforce"),
                             on_verdict=my_logger)   # on_verdict is optional (audit/metrics)
```

## Operating it safely

- **Roll out observe → enforce.** Observe first; only enforce once you've confirmed no false positives
  on your traffic.
- **The kill-switch is your instant off-ramp.** Tripping the kill-switch for the gateway's `--slug`
  drops it to pass-through **without taking your app down**. Use it the moment enforcement misbehaves.
- **Enforcement is entitlement-gated in a governed deployment.** Active blocking needs the
  `AEGIS_RESPOND` capability. An ungoverned deployment permits it (flagged); a governed one without the
  grant runs observe-only and logs why. (Detection is always available; only *blocking* is gated.)
- **Every block is audited.** The structured log and the `on_verdict` sink record the attack class,
  the client, and the re-runnable certificate id for each block — a complete, provable enforcement
  trail. Re-verify any certificate offline: `CertRef(**verdict["certificate"]).reverify()`.
- **Data plane is public-facing by design.** Unlike the loopback-only `api`/`console` servers, the
  gateway must sit in the request path. Its compensating controls are the untrusted-input hardening,
  the `AEGIS_RESPOND` entitlement, and the kill-switch. Keep any control plane (config, certs) off the
  data port.

## What AEGIS will never do

Defensive only. It protects **your own** app; it never attacks anyone, never evades a defender, and is
not a stealth tool. It blocks on proof or it forwards — there is no third, guess-based behavior.
