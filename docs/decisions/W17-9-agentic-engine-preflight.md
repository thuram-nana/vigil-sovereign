# W17-9 — Surface the agentic engine's TRIPLE-CONJUNCTION gate BEFORE Send

Issue: [#543](https://github.com/thuram-nana/vigil-sovereign/issues/543) ·
Milestone: W17 — FINISH THE HALF-BUILT (feature-wiring audit).

## The claim (registered in the claims registry — [W0-3] #398, id `W17-9`)

<!-- CLAIM:W17-9 -->
> **Registered claim (W0-3 #398):** The New-Assessment preflight states which engine will run and, when the agentic engine will not, names the unmet conjunct (no session, a remote target, or vigil not on PATH) before the operator clicks Send.

## Why it is TRUE of the code

The agentic (integration `vigil engage`) engine runs ONLY under a triple conjunction plus a resolvable
entrypoint: `(agentic|graph_backed) AND session_id AND is_loopback AND _vigil_bin()`
(`framework/v2/console/actions.py`, the `launch_assessment` URL-family branch). When any conjunct is
unmet, the launch used to fall through SILENTLY to the plain offense engine — and, when `vigil` was off
PATH, it said nothing at all; the operator learned which engine actually ran only from a post-launch
toast, or not at all.

`engine_plan` (`framework/v2/console/actions.py`) is the PRE-Send preflight. It routes the SAME wizard
body the launch does, WITHOUT spawning anything, and returns which engine will run and — via
`_agentic_unmet_reason` — the FIRST unmet conjunct as a distinct, visible reason:

- `no_session` — the agentic engine needs a session to attach to;
- `remote_target` — the agentic engine is loopback-only;
- `vigil_not_on_path` — the `vigil` entrypoint did not resolve (`$VIGIL_BIN` or PATH).

`""` means every conjunct is met (the agentic engine WILL run). The console exposes it read-only at
`/api/launch/preview`; the UI (`packages/vigil-ui/app.js`) shows the engine and the unmet reason in the
New-Assessment summary card before the Launch button. The runtime `launch_assessment` response also now
carries an `engine_note` when it falls through, so there is no silent fall-through at run time either.

The plan cannot drift from the run: a source/logic guard asserts that when `engine_plan` says the
agentic engine will run, `launch_assessment` spawns `engine:"integration"`, and when it names an unmet
reason it does not.

## Enforced by

`framework/v2/console/actions.py::engine_plan` (and `_agentic_unmet_reason`).

## Proved by

`engine/crucible/framework/v2/console/tests/test_engine_plan_w17_9.py` — each conjunct yields a
distinct reason, a positive control (all met → agentic runs), a negative control (`vigil` off PATH →
not routed to the agentic engine), and the plan↔run no-drift guard. Runs in the required
`CRUCIBLE core on vigil_core` CI job (`pytest framework/v2`).
