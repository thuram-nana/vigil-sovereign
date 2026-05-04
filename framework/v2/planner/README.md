# planner/ — ACP, the Autonomous Campaign Planner

Owns the engagement loop. Best-first search over a goal tree with
budget enforcement, branch pruning, watchdog-bounded execution, and
60-second checkpoints to disk so a kill-and-resume across processes
loses no progress.

## Pipeline (one engagement, one process)

```
                ┌─────────────────────────────────────────────┐
                │   seed_tree(archetype, surfaces, MLS)       │
                │   → root → goals → leaves (bug_class,surface)│
                └────────────────┬────────────────────────────┘
                                 │
                  ┌──────────────▼──────────────┐
                  │  Planner.step()             │
                  │  1. watchdog.check          │
                  │  2. budget.exhausted?       │
                  │  3. pruner.prune            │
                  │  4. tree.best_open_leaf     │
                  │  5. ethics.require_in_scope │
                  │  6. dispatch_leaf → BB      │  ◄── posts Hypothesis
                  │  7. coordinator.tick × N    │  ◄── MAO processes it
                  │  8. resolve_leaf ← BB       │
                  │  9. tree.mark_status        │
                  │ 10. budget.charge           │
                  │ 11. checkpoint?             │
                  └─────────────────────────────┘
```

Loop terminates when (a) the tree has no more open leaves, (b) the
budget is exhausted, (c) the watchdog halts, (d) `max_steps` /
`max_seconds` is reached, or (e) the operator calls `stop()`.

## Files

| Module | Purpose |
|---|---|
| `goal_tree.py` | `GoalTree` — mutable, prunable, serialisable (resume). `GoalNode` carries prior, value, costs, status. |
| `budget.py` | `Budget` — three concurrent budgets (request / token / wall-clock), fail-closed `can_charge()` pre-check. |
| `pruner.py` | `Pruner` — kills branches on excessive failures, cost overrun, or precondition failure. |
| `watchdog.py` | `Watchdog` — halts the planner on thrashing / scope drift / error-rate / budget. The planner has no API to clear the halt. |
| `executor.py` | `dispatch_leaf` posts a Hypothesis to MAO; `resolve_leaf` walks the result back. |
| `seed.py` | `seed_tree(archetype, surfaces, mls_store)` — builds initial tree from a UTI archetype + MLS priors. |
| `resume.py` | `snapshot()` / `restore_*()` — JSON checkpoints to `targets/<slug>/.planner-state.json`. |
| `planner.py` | `Planner.run()` — the search loop. |
| `tests/` | unit + ACP integration + full UTI→ACP→MAO→reports pipeline. |

## Budgets

Three caps enforced concurrently:

- **Request budget** (default 1000 per engagement, configurable).
- **Token budget** (default 50 000, a rough proxy for ~$50 of model spend).
- **Wall-clock budget** (default 8 hours).

Plus a soft per-minute rate cap (`rate_requests_per_min=60`).
`Budget.exhausted()` returns `(True, reason)` on any breach.
`Budget.can_charge(...)` is the fail-closed pre-check the planner
runs before dispatching the next leaf.

## Watchdog authority

Per FORGE PROTOCOL § 3.3 the watchdog has authority to halt the
planner; the planner does NOT have authority to disable the
watchdog. Concretely:

- `Watchdog.halted` is a read-only property from the planner's POV.
- `Watchdog._halt(reason)` is called from inside `Watchdog.check()`.
- The Planner has no method named `clear_watchdog`, `unhalt`, or
  similar (verified by `test_watchdog_halt_authority`).

The watchdog halts on:

- Budget exhaustion.
- Thrashing (last 30 steps touched fewer than 3 unique nodes).
- Error rate ≥ 50% over the last 50 steps.
- Scope drift (a step would send traffic to a host outside the
  signed charter).

## Resume

The planner checkpoints to `targets/<slug>/.planner-state.json`
every 60 seconds (configurable). The checkpoint carries the goal
tree, the budget counters (used / remaining), and the blackboard
cursor. On restart, `restore_tree()` and `restore_budget()` rebuild
the state. Wall-clock is reset on restore so paused time doesn't
count against the budget.

## Status

| Component | Code complete | Live-path verified |
|---|---|---|
| Budget | yes | yes |
| Goal tree | yes | yes |
| Pruner | yes | yes |
| Watchdog | yes | partial (scope-drift via charter is exercised; thrash + error-rate via injected halt only) |
| Executor router | yes | yes (against `DeterministicExecutor`) |
| Resume / checkpoint | yes | yes |
| Planner core | yes | **partial** — search exercised against the deterministic harness only; URK rollout policy is DryRun |
| Live target | n/a | **no** — Juice Shop / DVWA path designed but not invoked in this session |

The integration tests in `tests/test_acp_integration.py` and
`tests/test_full_integration.py` exercise every component end to
end against fixture-replay. See `V2-LIMITATIONS.md` § "Inherited
unexercised-LLM path risk" for what an unexercised live URK
implies for ACP's `autonomous` claim.
