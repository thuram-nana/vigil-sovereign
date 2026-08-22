# W6-3 — OpenMetrics `/metrics` per plane: RED + process + domain counters (stdlib-only)

Issue: [#454](https://github.com/thuram-nana/vigil-sovereign/issues/454) ·
Milestone: W6 — OBSERVABILITY & HEALTH · Feeds [W8-1] #467 (alerting) and [W6-7] #458.

## The defect

There was **no metrics exposition of any kind** — no Prometheus/OpenMetrics endpoint, no metrics client in
either hash lock, and no RED/USE signals (rate, errors, duration, memory, FDs). The only thing that existed
was a business-counter **JSON snapshot** (`vigil_integration.telemetry.collect_snapshot`, a one-way
projection of the signed spine). An operator could not scrape latency, error rate, saturation, or the
security-relevant domain counters, so nothing downstream (dashboards, alerting) could be built.

## What shipped

A **stdlib-only** OpenMetrics/Prometheus text-format exposition — a small formatter plus a
`MetricsRegistry` — in the neutral shared core `vigil_core.metrics`, and a `/metrics` route on each plane's
server that renders it. **No new dependency**, so neither hash lock changes (the constraint the issue set).

- **RED** — `vigil_requests_total` (by method + status class), `vigil_request_errors_total` (5xx / handler
  crash), and the `vigil_request_duration_seconds` histogram (cumulative buckets + `_sum`/`_count`),
  recorded by a per-request timing wrapper on each server.
- **process** — `vigil_process_resident_memory_bytes`, `vigil_process_open_fds`,
  `vigil_process_uptime_seconds`, `vigil_process_start_time_seconds`, read at scrape time from
  `/proc/self` with total, never-raising fallbacks.
- **domain** — the four counters the plan names: `vigil_facts_total`, `vigil_leads_total`,
  `vigil_refusals_total` (folded from the existing business-counter JSON snapshot via
  `MetricsRegistry.update_domain_from_snapshot`) and `vigil_gate_denials_total` — a live counter the
  authorization edge bumps through `record_gate_verdict` on a DENY. Every series is labelled
  `plane="sovereign"|"offense"`.

The registry is **emit-only**: nothing here returns or influences an allow/deny verdict;
`record_gate_verdict` merely COUNTS a `GateVerdict` a gate already produced and returns it unchanged, and
every method is total (a telemetry error never breaks a request or a scrape).

## The claim (registered in the claims registry — [W0-3] #398, id `W6-3`)

<!-- CLAIM:W6-3 -->
> **Registered claim (W0-3 #398):** Each VIGIL plane server exposes a `/metrics` OpenMetrics endpoint — rendered by `vigil_core.metrics.MetricsRegistry` with ZERO new dependency (stdlib text-format exposition, so neither hash lock changes) — carrying RED request metrics (rate/errors/a duration histogram), process metrics (resident memory, open file descriptors, uptime), and the four domain counters facts/leads/refusals/gate-denials; the facts/leads/refusals counters are folded from the signed-spine business snapshot and `vigil_gate_denials_total` is incremented by `record_gate_verdict` on every authorization-gate DENY.

## Exposure and authentication posture

`/metrics` is **UNAUTHENTICATED and Host-ungated — the SAME probe posture as `/healthz` + `/readyz`**
([W6-1] #452): it is matched before the auth / anti-rebinding gate so a scraper that presents no session
token and not the operator's Host can reach it. That is safe because each plane server **binds loopback or a
private (WireGuard/Tailscale) address only** — never `0.0.0.0` / a public address (enforced by the same
`bind_ok` the health probes rely on); a public serve goes behind the operator's TLS reverse proxy, which is
where scrape-side authentication (mTLS / bearer) is applied. The response body carries **no token, path, or
backend address** — only aggregate counters. An operator who wants to restrict the endpoint further scopes
it at that reverse proxy / their network policy, exactly as for `/healthz`+`/readyz`.

## Artifacts shipped with the product

- `infra/observability/vigil-alerts.yml` — example Prometheus alert rules over these series (a request
  error-rate rule, a p99 latency rule, **`VigilGateDenialSpike`** on `increase(vigil_gate_denials_total[5m])
  > 0`, a no-confirmed-FACTs rule, and an open-FD saturation rule), a starting point for [W8-1] #467.
- `infra/observability/vigil-dashboard.json` — an example Grafana dashboard (RED, the four domain counters,
  and the process metrics), templated by `plane`.

## Negative control

`packages/core/vigil_core/tests/test_metrics.py` drives a **forced gate DENY through the real
gate-of-record** (`vigil_core.gate.conjunctive_decide`), asserts `vigil_gate_denials_total` increments and
the render reflects it, and — via a small harness that reads the shipped `vigil-alerts.yml` — asserts the
`VigilGateDenialSpike` rule **fires** on the observed increase while a non-deny verdict (allow / queue) does
**not** increment the counter and does **not** fire the alert. The endpoint suites
(`integration/tests/test_metrics_endpoint.py`, `apps/sigil/tests/test_metrics_endpoint.py`) prove each
plane's `/metrics` returns valid OpenMetrics (terminated by `# EOF`) with RED + process + the four domain
series, that the domain counters are folded from the JSON snapshot, and that a real offense-gate DENY is
reflected on the offense `/metrics`.
