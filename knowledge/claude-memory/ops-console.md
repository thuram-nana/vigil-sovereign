---
name: ops-console
description: "CRUCIBLE Ops Console — the loopback operator UI (branch ops-console / PR #30)"
metadata:
  node_type: memory
  type: project
  originSessionId: 7758e121-f349-47d5-886b-6bb5a1d60e27
---

Branch **ops-console** (off [[credibility-program]]'s credibility-eval-platform), PR #30 → credibility-eval-platform. A decoupled, read-only, loopback-only operator UI at `framework/v2/console/`. HARD CONSTRAINT (operator): must not affect scan efficiency in any way — so it READS artifacts the framework already writes + TAILS the structlog JSONL; the engine never imports it. **Stdlib-only** (http.server + sqlite3 + urllib + vanilla JS; no new deps, no build, no CDN). Registered as the `console` subcommand; `make console`.

**Architecture:** `console/{cli,server,api,sse,actions}.py` + `console/static/{index.html,app.js,graph.js,styles.css}`. server.py = ThreadingHTTPServer bound 127.0.0.1 ONLY (refuses routable hosts), static serving with traversal guard, read-only /api/* JSON, SSE `/api/events?run=|slug=` tailing the JSONL. api.py = pure resilient readers reusing report.build_report / memory.Store / KillSwitch / kernel.probe_all / worldmodel+pathsearch.choke_points — never raises on a fresh tree. actions.py = 3 SAFE actions only (launch scan subprocess / reverify / killswitch-trip); NO clear/scope/destructive route.

**The ONE engine touch:** `scanner/progress.py` (ProgressSink protocol + JsonlSink) + `WebScanCampaign(progress=None)` — default None → literal no-op, guarded on rare phase/finding events (never per-request). Verified byte-identical off (findings 9==9). `scan --progress-log PATH` wires it. engage already streams (no change).

**19 screens** (app.js SCREENS registry): Overview/LiveRun/Engagements/Findings/AttackGraph/Coverage (ops); ReasoningBrain/Planner/Memory/Kernel (intel); Benchmark/Analysis/Improve/Intake (assurance); Authority&Safety/Defender/SocialDefense/Reports/Status (gov). graph.js = hand-rolled force-directed SVG (nodes by kind, attack-path edges highlighted, choke-points dashed). Rich screens: Findings(+cert+evidence+reverify), AttackGraph(worldmodel reconstructed by re-chaining a saved run — pure), Benchmark(committed benchmark-results.json + gate), Memory(Beta priors). On-demand subsystems (defender/socialdef/analysis/improve/intake) = honest info panels (role+CLI+produces).

**GOTCHAS:**
- `paths.v2_root()` resolves via CRUCIBLE_ROOT sentinel to a DIFFERENT checkout here (/home/kali/Music/PENTEST/crucible), NOT the Pictures repo. So runtime artifacts (runs, memory, targets) read from there; committed PACKAGE data (benchmark-results.json, baseline) MUST be read `__file__`-relative.
- WorldModel `node_count`/`edge_count` are PROPERTIES not methods (no parens).
- `scan --format json` (build_report) STRIPS oracle_context → not re-verifiable. Fixed: added `scan --reverifiable-out PATH` (dumps report.model_dump_json with certs); reverify_document reads `doc["active_findings"]`. Verified reverify 4/4.
- Console runtime dir `.console/` (launched runs) is gitignored (root .gitignore, next to .memory/.authority/.blackboard).
- Don't run the full v2 suite + Chromium + file writes concurrently (see [[crucible-testing-and-gotchas]]).

Console suite: `framework/v2/console/tests/test_console.py` (loopback bind, traversal block, no-destructive-route, tailer, launch→report→reverify, worldmodel reconstruction, resilient readers). Green. Built in 5 phases, committed per phase (33c850e / 90f3bce / 398d996).
