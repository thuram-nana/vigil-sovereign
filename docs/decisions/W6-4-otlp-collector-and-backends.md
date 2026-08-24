# W6-4 — a real OTLP collector profile, supported backends, and a VISIBLE unreachable-backend failure

Issue: [#455](https://github.com/thuram-nana/vigil-sovereign/issues/455) ·
Milestone: W6 — OBSERVABILITY & HEALTH · Depends on [#539] (the `OTLPSink` had zero callers; spans now
reach the sink) and builds on the F11 observability plane.

## The defect

After #539, a span the engine emits actually reaches `live.otel_export.OTLPSink` and is exported over
OTLP/HTTP to the collector. But two gaps remained:

- **Traces terminated in stdout.** The only shipped collector config (`infra/sidecars/otel-config.yaml`)
  wired the OTLP receiver to the `debug` exporter — i.e. the collector's own stdout. Nothing was retained
  or queryable; there was no profile that forwarded spans to a real, queryable tracing backend.
- **An unreachable backend was a SILENT drop.** `OTLPSink` swallows every export failure into a `dropped`
  counter (by design: a telemetry outage must never deny cognition). But a down collector produced no
  operator-visible signal at all — just an integer someone had to call `.stats()` to read.

## The claim (registered in the claims registry — [W0-3] #398, id `W6-4`)

<!-- CLAIM:W6-4 -->
> **Registered claim (W0-3 #398):** VIGIL ships a real OTLP collector profile that forwards every received span to a real OTLP-compatible backend (`infra/sidecars/otel-config-backend.yaml` defines an `otlp/backend` exporter with an endpoint and wires it into the traces pipeline, not only the stdout `debug` exporter), selectable in `docker-compose.yml` via `OTEL_CONFIG`; and an UNREACHABLE backend is made VISIBLE rather than silently dropped — `live.otel_export.probe_collector` actively preflights the collector (loopback-pinned, stdlib-only) and, when it is down, returns `reachable=False` with a human-readable detail AND logs a WARNING, so a down telemetry backend never disappears into a silent per-span drop. Both the collector profile and the visible-unreachable preflight are exercised in the required P5 CI leg; the stronger OTLPSpanExporter real-span-arrival e2e is otel-gated and SKIPS in CI (opentelemetry is absent from the runtime locks), so it is NOT claimed as exercised here.

## What changed

| Piece | Before | After |
|---|---|---|
| `infra/sidecars/otel-config-backend.yaml` | (absent) | NEW profile: OTLP receiver → **`otlp/backend`** (a real backend) **and** `debug` (stdout), with retry + a bounded sending queue so a down backend is retried and its drops are logged by the collector |
| `docker-compose.yml` (`otel-collector`) | mounts `otel-config.yaml` (stdout only) | mounts `${OTEL_CONFIG:-./infra/sidecars/otel-config.yaml}` — set `OTEL_CONFIG` to the backend profile to forward to a real backend; no new (unpinnable) image is added |
| `live/otel_export.py` | export failure = silent `dropped++` | `+ probe_collector()` (the reachability preflight — the VISIBLE-error surface) and a one-time WARNING when the sink's circuit breaker latches |
| `live/wiring.py` (`_build_emit`) | wired the sink blindly | PREFLIGHTS the collector once at wiring time and logs the result (WARNING if unreachable) |

## Supported backends

The collector is the trust boundary that fans telemetry out to a backend, so VIGIL supports **any
OTLP-compatible tracing backend**. `OTLP_EXPORT_ENDPOINT` (host:port, OTLP/gRPC `4317` by default) selects it:

| Backend | Notes |
|---|---|
| **Jaeger** (all-in-one ≥ v1.35) | OTLP-native. One-liner: `docker run -d --name jaeger -p 127.0.0.1:16686:16686 -p 127.0.0.1:4317:4317 jaegertracing/all-in-one`. UI at `http://127.0.0.1:16686`. |
| **Grafana Tempo** | OTLP-native; point `OTLP_EXPORT_ENDPOINT` at the Tempo distributor's OTLP port. |
| **Grafana Cloud / Honeycomb / New Relic / Datadog Agent** | OTLP endpoints; set `OTLP_EXPORT_INSECURE=false` and add the vendor's OTLP headers/TLS in `otel-config-backend.yaml`. |
| **A second OpenTelemetry Collector** | tiered/aggregating collector topologies. |
| **stdout (`debug`)** | the zero-dependency default (`otel-config.yaml`) — traces terminate in the collector's logs. |

Egress stays pinned: VIGIL's `OTLPSink` only ever egresses telemetry to **loopback** (`127.0.0.0/8` / `::1`);
the collector — trusted host infrastructure, host-bound to `127.0.0.1:4318` — is what reaches the backend.

## How the unreachable-backend failure is made visible

Two layers, matching the two places a backend can be down:

1. **Engine → collector (VIGIL side).** `probe_collector(endpoint)` opens a real loopback HTTP connection to
   the collector's `/v1/traces` route: any HTTP response ⇒ reachable; a refused/timed-out connection ⇒
   `reachable=False` **with a logged WARNING**. `_build_emit` runs it once when an engagement wires telemetry,
   so an operator sees an unreachable collector at start. The hot-path sink additionally logs one WARNING when
   its consecutive-failure breaker latches. Neither denies cognition — telemetry is best-effort by contract.
2. **Collector → backend (collector side).** `otel-config-backend.yaml`'s `otlp/backend` exporter enables
   `retry_on_failure` + a bounded `sending_queue`; the collector retries a down backend and logs the drop at
   WARN (`docker logs otel-collector`).

## Tests

- `integration/tests/test_otlp_collector_backend.py` — **framework-free and otel-free**, so it runs in the
  REQUIRED sovereign CI leg (`pytest integration/tests`, "integration two-env boundary (P5)"): a minimal
  in-test OTLP receiver proves a live loopback endpoint is reachable; **the load-bearing negative control**
  proves an unreachable backend surfaces a returned error + a logged WARNING (not a silent drop); and the
  backend profile is asserted to route its traces pipeline to a real `otlp` exporter (with the default
  stdout-only profile as the contrast control).
- `integration/tests/test_live_otel_export.py` — **otel-gated, and it SKIPS in CI**: `opentelemetry` is
  absent from both P5 runtime locks, so this module `pytest.importorskip`s and **does not run in any CI job
  today**. Where otel *is* installed it proves the stronger property — a real span, through the real
  `OTLPSpanExporter`, over real HTTP, arrives at an in-test loopback OTLP endpoint's `/v1/traces` route (plus
  the circuit-breaker-latch WARNING and its healthy-collector control) — but that proof is **not claimed as
  exercised in CI**. The load-bearing, CI-run guarantees are the two bullets above (the config profile + the
  visible-unreachable preflight), which are deliberately otel-free.

## Residual (honest scope)

1. **The real-`OTLPSpanExporter` span-arrival e2e is not exercised in CI.** It lives in the otel-gated
   `test_live_otel_export.py`, which module-skips because `opentelemetry` is not in the runtime locks. Wiring
   it to run would need the `opentelemetry-*` packages added to the framework runtime lock (a lockfile change
   with network/hash resolution out of this sandbox's reach). Until then only the otel-free
   `test_otlp_collector_backend.py` guarantees are CI-enforced.
2. **A live EXTERNAL backend is not stood up.** The CI-run tests exercise the export destination against a
   **loopback** endpoint (an in-test receiver); standing up a real Jaeger/Tempo/Grafana-Cloud instance and
   running a full engagement against it needs Docker + network + that backend running — it cannot execute in
   the sandboxed PR runner and is **not** claimed to. The live-external bring-up is the operator step
   documented above.
