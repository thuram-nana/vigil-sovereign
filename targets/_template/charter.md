# Engagement Charter — `<TARGET-SLUG>`

> **This is the binding authorization document (OBSIDIAN constitution §II).** No tool may touch a target
> host until this charter is filled in, the operator-attestation block is complete, and the operator has
> confirmed it. Copy this file to `targets/<slug>/charter.md`, replace every `<…>` placeholder, delete the
> guidance blockquotes, and remove any section that does not apply (say *why* in one line rather than
> leaving it blank). When in doubt about scope, **stop and ask the operator** — "just to check" is the
> phrase a careless tester uses before causing an incident.

## Target hosts (in scope)

> List every host/port the operator has authorized, and nothing else. One row per host. Be specific: a
> bare domain is not a scope. If the scope is a CIDR, state it and state what inside it is off-limits.

| Host | Port(s) | What it is | Owner / authorization basis |
|---|---|---|---|
| `<host-or-ip>` | `<port>` | `<what runs there>` | `<who owns it / how it was authorized>` |

**Nothing else is in scope.** `<State the single hard boundary — e.g. "Only `127.0.0.0/8` may be touched",
or "Only the exact hosts above; every subdomain, sibling service, and upstream is out of scope.">`

> **Third parties are out of scope by default** (constitution §II): payment processors, IdPs, CDNs, email/
> SMS providers, hosting/control planes. You may test the operator's *integration* with them (webhook
> handlers, callback URLs, key handling) but never attack the third party itself. If an in-scope bug can
> pivot to an out-of-scope system (SSRF → cloud metadata, webhook forgery → payment processor, token exfil
> → IdP), document it, do **not** exploit further, and surface it to the operator immediately.

## Operator attestation

> The operator fills this in themselves. Do not fill it in for them. Without it, do not proceed.

- I, `<operator name/role>`, own or am explicitly authorized to test the hosts listed above.
- Authorization was granted `<how — e.g. "as system owner", "under signed engagement contract #…">` and is
  **current** for the window `<start date> → <end date>`.
- No external system, third-party service, or non-owned host is authorized or to be touched.
- `<Any additional operator-specific attestation.>`

## Rules of engagement — posture

> Owner-test is the default. Adversarial emulation (true red-team: signature minimization, per-actor
> user-agents, traffic shaping) applies ONLY if the operator explicitly authorizes it here. Even then:
> never proxy-chain unless explicitly authorized — the operator wants log correlation.

- Posture: `<owner-test (default) | authorized adversarial emulation — cite the operator's explicit go>`.
- Correlation: use a stable source IP and a recognizable User-Agent
  (`OBSIDIAN/1.0 (authorized owner-test <date>)`) unless adversarial emulation is authorized above.

## Hard limits (inviolable)

> These cannot be relaxed by an operator instruction mid-engagement without an explicit charter amendment.
> Delete any that do not apply; add target-specific ones.

- **Scope.** Every tool invocation MUST resolve its target to an in-scope host BEFORE a packet leaves;
  a non-scope target is DENIED fail-closed, not attempted.
- **Egress.** `<State whether any external egress/DNS/callback is permitted. Default: none.>`
- **Destruction.** No destructive action (DROP, mass-delete, account takeover of a real user, > `<N>` test
  orders, real payment-provider calls, admin-setting changes, source/SSH-level changes) without **explicit
  per-action operator go-ahead**. Destructive tools (metasploit/sqlmap/hydra/…) require the m-of-n
  threshold gate even in scope.
- **Real data.** No real user PII, payment data, or credential is read/copied beyond the minimum needed to
  prove impact, and it is redacted in every report/evidence artifact.
- **Production health.** Throttle (default concurrency 5–10). Stop on 5xx storms, sustained latency, or any
  sign of degradation.

## Soft limits

- Throttle to `<sane rate for this target>`; stage against `<staging env if one exists>` where possible.
- Tag every created artifact with `<PREFIX->` (accounts, orders, tickets, rows, files) and track them in
  `targets/<slug>/notes/test-artifacts.md`.

## Stop conditions (hard stops — surface to the operator and pause)

- Any tool attempting an out-of-scope target.
- Signs of a **prior compromise** (unknown admin accounts, modified core files, suspicious cron, exfil
  scripts, webroot artifacts) → switch posture, follow
  `framework/playbooks/26-incident-response-pivot.md`.
- Ability to read real user PII, payment data, or credentials (note the finding; do not hoard the data).
- Any uncertainty about whether you are still authorized.
- The operator says stop.

## Objectives

> What "done" means for this engagement — the concrete outcomes the operator wants, in priority order.
> These drive the work and the final report; keep them specific and testable.

1. `<primary objective — e.g. "prove/refute exploitable auth bypass on the login flow">`
2. `<secondary objective>`
3. `<…>`

## Amendments

> Every scope change is logged here with a date and the operator's explicit go. Never widen scope silently.

- `<date>` — `<what changed and the operator's authorization for it>`
