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

## Install

AEGIS ships inside CRUCIBLE and runs locally (loopback) — no cloud, no telemetry, no external calls.

- **pip.** From the repo root, `pip install .` delivers the importable `framework.v2` package plus two
  console entry points: `aegis` (== `python3 -m framework.v2 aegis`) and `crucible`. No install is
  required to try it from a source checkout — the `python3 -m framework.v2 aegis …` form works as-is.
- **Docker sidecar.** [`framework/v2/aegis/Dockerfile`](../../aegis/Dockerfile) packages the gateway on
  `python:3.11-slim` (non-root, `ENTRYPOINT python3 -m framework.v2 aegis gateway`, default
  `CMD --mode observe`). Build it from the **repo root** so the context sees `pyproject.toml` + `framework/`:
  `docker build -f framework/v2/aegis/Dockerfile -t aegis-gateway .`
- **Five-minute walkthrough.** [`framework/v2/aegis/QUICKSTART.md`](../../aegis/QUICKSTART.md) takes you
  from `aegis demo` (offline, prints a confirmed verdict + a re-runnable certificate), to an observe-mode
  gateway in front of the bundled demo target (`python3 -m framework.v2.aegis.demo_app`) or your own app,
  to flipping `--mode enforce` once you have confirmed zero false positives.

## What it blocks today (each with a re-runnable certificate)

| Class | Proved by | Seen from |
|-------|-----------|-----------|
| `sqli_attempt` | the value provably breaks out of a SQL string literal into query structure, anchored at the break-out (a self-tautology `OR 1=1` / `UNION SELECT` / a full stacked statement `; DROP TABLE`) | the request alone |
| `command_injection_attempt` | a dangerous command invoked with a shell argument, inside a substitution (`$(cat /etc/passwd)`) or after a real separator (`; cat /etc/passwd`, `\| nc <ip>`) | the request alone |
| `nosql_injection_attempt` | a **known** MongoDB query operator (`$ne`/`$gt`/`$where`/`$regex`/`$in`/`$or`…) injected as a **key** where a scalar was expected — a bracket/dot param name (`user[$ne]=1`, `q[$gt]=0`, `user.$ne`) or a JSON-object value/body (`{"$ne":null}`, `{"user":{"$in":[1,2]}}`). The EJSON/JSON-Schema/DBRef `$`-keys (`$oid`, `$date`, `$schema`, `$ref`) and a `$`-prefixed **value** (`$5.00`, `["$ne"]`) are **not** blocked | the request alone |
| `automated_access` | a fetch of a seeded honeypot path no human UI links | the request alone |
| `xss` (reflected) | a request value reflected **verbatim** whose executable token reached a live executable HTML context (an HTML‑encoded reflection is **not** blocked) | the app's response |
| `ssti` | a request value carried a template-wrapped arithmetic expression (`{{7*7}}`, `${7*7}`, `#{7*7}`, `<%= 7*7 %>`, `*{7*7}`, `@(7*7)`) that the server **evaluated** — the ≥2-digit result appears at a digit boundary and the raw template is gone (a **reflected** template is **not** blocked) | the app's response |
| `path_traversal` | a request value walked the path toward a sensitive file (a real `../`-style traversal indicator) **and** a strict `/etc/passwd`-signature line surfaced in the response — and the value is **not** merely reflected verbatim (a docs/search page echoing `/etc/passwd` is **not** blocked) | the app's response |

The three request-side classes prove a **structured attack attempt**; the three response-side classes
(`xss`, `ssti`, `path_traversal`) prove **exploitation** — the app actually reflected the payload,
evaluated the expression, or leaked the file. The oracles are deliberately conservative — a benign
apostrophe (`O'Brien`), a comparison (`id > 1000`), a tool string (`python-requests/2.28.1`), delimited
data (`Name \| Age`), a pasted SQL query, a price `$5.00`, a Mongo-export `{"$oid": …}` / `{"$date": …}`
body, an operator named as a data **value** (`["$ne"]`), a coincidental `49` beside a reflected
`{{ 7 * 7 }}`, a page that documents `/etc/passwd`, or a prose em-dash never trip a block. Request-side oracles inspect the
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

## Passive OOB belief elevation (opt-in, canary-based) — `--oob-canary`

SSRF and blind/OOB XXE cannot be *proven* from a single inline request/response, so AEGIS emits them
as **leads** (belief-raising, never a block). This opt-in feature lets an **operator-planted canary**
turn a real out-of-band interaction into a stronger — but still belief-only — signal, so a genuinely
exploited SSRF/XXE actor escalates faster toward the graduated challenge/throttle.

How it works, honestly:

1. **You plant a STATIC canary.** Pick a host you control that (a) an app's server-side fetch can
   reach and which you tunnel back to a **loopback** receiver (e.g. an SSH reverse-forward — your
   charter's responsibility), and (b) trips AEGIS's SSRF/XXE lead when referenced (an internal /
   RFC1918 / metadata-style host for SSRF; any external `SYSTEM`/`PUBLIC` host works for XXE). Run:
   `aegis gateway --upstream … --mode enforce --oob-canary http://10.20.30.40/oob-beacon`.
2. **AEGIS never touches the canary or the traffic.** It does **not** inject, advertise, or plant the
   canary into any request — it is a *translator*, forwarding every inbound request byte-for-byte.
   When an attacker's *own* payload references your canary host and trips the SSRF/XXE lead, AEGIS
   records a bounded pending correlation (reading only the attacker's bytes).
3. **A real callback elevates belief — never blocks.** If something server-side actually dereferences
   the canary, the loopback receiver logs the unsolicited hit; AEGIS correlates it to the pending
   observation and **elevates that actor's per-actor Beta belief** toward the *existing* graduated
   challenge/throttle (a soft, retryable **429**). It **never** produces a block or a `confirmed`
   verdict — a hard block still rides only a fired oracle certificate (prove-don't-guess).

Guarantees (all tested): the receiver binds **loopback only**; the feature is **default-off** (no
`--oob-canary` → no receiver, byte-identical behaviour) and **entitlement-gated** (`AEGIS_RESPOND`,
like the rest of the response layer); it is **fail-open** (any error forwards, never blocks); and it
adds **no new oracle** and **never mutates an inbound request**.

Honest caveats: coverage is **narrow** — it fires only when an attacker actually targets your canary
host with a payload that trips the lead *and* the app dereferences it back to the receiver. Correlation
is by **canary host** (the primary, high-confidence signal); there is no timing/source fallback (it
would be far harder to keep near-zero-FP). If several actors target the canary before a hit lands, the
hit elevates all of them — each already sent an SSRF/XXE payload at the trap host, and elevation only
ever raises belief toward a soft challenge, never a block.

## What AEGIS will never do

Defensive only. It protects **your own** app; it never attacks anyone, never evades a defender, and is
not a stealth tool. It blocks on proof or it forwards — there is no third, guess-based behavior. The
`--oob-canary` correlation is passive and belief-only: AEGIS never injects a callback/token into
traffic, and an out-of-band hit escalates only to a soft, retryable challenge/throttle — never a block.
