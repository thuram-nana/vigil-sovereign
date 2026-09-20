# Phase 4 (P4) — AEGIS gateway external verdict sink

## Context

AEGIS is the defensive dual: an inline reverse-proxy "provable firewall" in front of the operator's app
that blocks a request only when a deterministic oracle proves it is an attack. The gateway already streams
verdicts to the UI (a JSONL the loopback console tails) and to stderr. The one named BUILT-NOT-WIRED gap
(the P4 wave) was the **external verdict sink**: the operator had `GatewaySettings.on_verdict`, but nothing
delivered verdicts to a SIEM / webhook / Slack for a real defensive deployment.

## Decision

Wire an optional outbound verdict sink, reusing the report layer's bounded sender.

<!-- CLAIM:PHASE4-1 -->
The AEGIS gateway can ALSO POST each verdict to an operator-configured outbound sink (webhook / Slack) via a
bounded, redirects-disabled sender (http(s) only, hard timeout); the posted body is the SAME browser-safe
verdict projection the file sink emits (no oracle-context or internal-only field), the auth header comes from
an environment variable (never the argv / process list), and a send failure is FAIL-OPEN — it is swallowed
and never reaches the request/data plane.

Concretely:
- `aegis/cli.py::_make_webhook_verdict_sink` builds the `on_verdict` sink; it uses
  `report.push.push_via_urllib` (the same bounded, no-redirect-to-internal-SSRF POST the report delivery
  uses), reuses `_ui_safe_verdict` for the body, and reads `AEGIS_VERDICT_WEBHOOK_AUTHORIZATION` from the env.
- `_compose_verdict_sinks` fans a verdict out to the file/log sink AND the webhook, each isolated.
- CLI: `aegis gateway --verdict-webhook URL [--verdict-sink webhook|slack]`.
- Console: `aegis_setup` validates + threads `verdict_webhook` / `verdict_sink` to the child (the URL is
  non-secret config on the argv; the auth header stays in the inherited env), and surfaces it read-only.

## Honest scope

The verdict sink is NOTIFICATION — it fires on every verdict the gateway emits, in observe AND enforce mode,
and is orthogonal to the enforcement gate (blocking stays doubly gated by the `AEGIS_RESPOND` entitlement +
the kill-switch, unchanged). Delivering to an operator-configured URL is operator-trusted egress; the sink
does not itself add SSRF protection beyond the bounded no-redirect sender (the URL is the operator's own,
from their config, not an attacker input). Native SIEM/Jira/ServiceNow/Splunk/syslog/SMTP connectors and TLS
termination on the gateway remain deferred-and-named.
