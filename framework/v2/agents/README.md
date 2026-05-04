# agents/ — MAO, the Multi-Agent Orchestration layer

Decomposes OBSIDIAN into specialised sub-agents that communicate
through a shared, append-only blackboard. The blackboard is the
single source of truth for engagement state; every agent reads from
it, writes to it, and is gated by the typed event-kind contracts in
`models.py`.

## Pipeline (one engagement)

```
recon-agent ──► observation ──┐
                              ▼
                     hypothesis-agent ──► hypothesis (5 per observation, doctrine)
                                       ─────────►
                                                  exploit-agent ──► plan, action, result, finding (pending)
                                                                  ─────────►
                                                                            critique-agent ──► critique + supersede(finding, status=confirmed|objections)
                                                                                            ─────────►
                                                                                                      reporter-agent ──► targets/<slug>/reports/technical.md
                                                                                                      memory-agent ──► MLS recorder (cross-engagement priors)
```

Every event carries provenance: `parent_id` links each event to the
event it derives from, so a confirmed Finding walks back through
Result → Action → Plan → Hypothesis → Observation in the blackboard
log.  This is enforced at the Pydantic and the SQL layers; an
`UPDATE` or `DELETE` against the events table is refused by trigger.

## Files

| Module | Purpose |
|---|---|
| `models.py` | Pydantic types for the eight event kinds and the `BlackboardEvent` wrapper. |
| `schema.sql` | SQLite schema (version 1) with append-only triggers. |
| `blackboard.py` | `Blackboard` class — the only write surface is `post()` / `supersede()`. |
| `base.py` | `Agent` ABC: `should_run()` + `step()` + cursor helpers. |
| `coordinator.py` | Boots agents, schedules ticks, terminates on quiet / wall-clock / external stop. |
| `executor_proto.py` | `Executor` protocol + `DeterministicExecutor` (fixture lookup, tests). |
| `realistic_executor.py` | `RealisticExecutor` — substantive synthetic evidence per scenario; satisfies live URK critique. |
| `http_executor.py` | `HttpExecutor` — bounded live-HTTP with the six-gate safety stack. |
| `scope_gate.py` | `validate_action()` — charter signature + scope + destructive classifier. |
| `recon_agent.py` | Probes paths via UTI's Fetcher; posts Observations. |
| `hypothesis_agent.py` | Reads Observations; calls URK.hypothesize(); posts ≥5 Hypotheses per observation. |
| `exploit_agent.py` | Claims open Hypotheses; posts Plan/Action/Result/Finding chain; supersedes hypothesis status. |
| `critique_agent.py` | Reads pending Findings; calls URK.critique(); supersedes Finding with critique_status. |
| `reporter_agent.py` | Renders `targets/<slug>/reports/technical.md` from confirmed Findings. |
| `memory_agent.py` | Mirrors blackboard events to MLS recorder for cross-engagement learning. |

## Append-only invariants

- `events.id` is monotonic; the blackboard never re-uses ids.
- A revision is a new row with `supersedes_id` pointing at the old.
  Reads default to excluding superseded rows; pass
  `include_superseded=True` to see history.
- The new row inherits `parent_id` from the superseded row by
  default, so provenance chains survive edits.
- SQL triggers `bb_events_no_update` and `bb_events_no_delete`
  refuse direct mutation; the Python API does not expose `update`
  or `delete`.

## The three executors

The exploit-agent does not call tools directly. It accepts an
`Executor`, defined as a protocol in `executor_proto.py`. Three
implementations ship side-by-side; pick by what the engagement is:

| Executor | When to use | What it returns |
|---|---|---|
| `DeterministicExecutor` | Unit + simulated tests. Maps `(bug_class, surface)` to a fixed `ExecutionOutcome`. | Whatever the test put in the lookup table. |
| `RealisticExecutor` | Integration tests under live URK. Three pre-baked scenarios (strong / weak / mixed) producing rich evidence chains. | Substantive synthetic outcomes that a senior critique-agent will accept or reject *for the right reason*. |
| `HttpExecutor` | Real engagements. Issues bounded HTTP/HTTPS through the six-gate safety stack. | Actual HTTP response (status, body excerpt, evidence dir, timing) — never auto-claims `success=True`; the exploit-agent decides. |

### HttpExecutor's six safety gates

Live-HTTP is the first v2 component that can take real action against
real targets, so the gates here are load-bearing. Each is called per-
action; none is bypassable without a code change. If any gate
refuses, the request never goes out and an `ExecutionOutcome` with
`success=False` and a refusal note is returned for the blackboard.

1. **Charter file present** — `targets/<slug>/charter.md` must exist.
2. **Charter signature** — the `Signed:` line must contain a non-
   placeholder operator name. UTI's draft charter is not enough.
3. **Scope** — the action's host must match the charter's § 2 scope
   table (literal hosts and `*.suffix` wildcards supported).
4. **Destructive-action confirmation** — POST/PUT/DELETE/PATCH and
   any URL containing destructive path tokens (`/admin`, `/delete`,
   `/upload`, `/payment/`, ...) prompt the operator on stderr with a
   30-second timeout. Default-deny on no answer or non-TTY stdin.
5. **Per-engagement request budget** — counted across the executor's
   lifetime. Default 100; configurable. Exhaustion halts cleanly.
6. **Posture-aware rate limit + UA** — TEST is aggressive (5 req/s,
   identifiable UA); AUDIT is moderate (1 req/s, control-test UA);
   EMULATE is slow + jittered (0.2 req/s + up to 3 s jitter, realistic
   browser UA). Read from charter § 7 unless overridden.

Plus full evidence capture: every request → `targets/<slug>/evidence/<action_id>/{request,response}.http` and the raw body archived as `response.body`. Every action → a structured event in `targets/<slug>/.crucible-v2.log`.

The unit tests at `tests/test_http_executor.py` exercise each gate
against a `pytest-httpserver` fixture — never against a real network.
Live exercise is opt-in via `CRUCIBLE_LIVE_HTTP=<url>`; see
`framework/v2/planner/tests/test_full_integration.py::test_full_pipeline_url_to_report_live_http`.

## Critique-agent gate

Per FORGE PROTOCOL § 3.4 the critique-agent is **non-optional**.
Every Finding posted by the exploit-agent has
`critique_status='pending'`. Only after the critique-agent supersedes
it with `critique_status='confirmed'` does the reporter-agent emit
it and the memory-agent forward it to MLS. Findings flagged with
`'objections'` or `'more_evidence_needed'` stay on the blackboard
for review but do not appear in the report.

This is the guard against confident hallucination. The
`test_mao_end_to_end_against_fixture_target` integration test
exercises both paths: a confident Finding that critique confirms,
and a hedged Finding that critique blocks.

## CLI

MAO has no dedicated CLI in this session — it is driven by the
planner (`framework/v2/planner/`). For an ad-hoc run, see the
integration test at `tests/test_mao_integration.py` for the
canonical wiring.

## Status

| Component | Code complete | Live-path verified |
|---|---|---|
| Blackboard | yes | n/a — no LLM dependency |
| Coordinator | yes | n/a |
| Recon agent | yes | yes (against UTI Fetcher fixture) |
| Hypothesis agent | yes | **no** — calls URK.hypothesize() in DryRun only |
| Exploit agent | yes | yes against DeterministicExecutor only |
| Critique agent | yes | **no** — calls URK.critique() in DryRun only |
| Reporter agent | yes | yes (renders to disk) |
| Memory agent | yes | yes (mirrors to MLS) |

The "live-path verified" gaps are inherited from the unexercised
URK paths.  See `V2-LIMITATIONS.md` § "Inherited unexercised-LLM
path risk" for the explicit verification checklist.
