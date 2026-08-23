<!-- CLAIM:W15-2 -->
# The VIGIL feature-wiring completeness audit (W15-2 #394)

**Registered claim (W0-3 #398):** Every feature in the wiring-status registry carries a machine-readable status, each status is verified against the code, and the declared CLI-verb set must equal the parser's own contract or the build goes red.

"Others run VIGIL" means a built-not-wired feature is **either shipped or removed**, not left ambiguous.
This audit lands the answer, per feature, to *is it actually wired?* `wiring-status.json` assigns every
covered feature a status; `../tests/test_feature_wiring_status.py` is the guard that keeps the status
honest, and it runs in the **required** `the briefing explains every agent and capability` CI job.

## The five statuses

| status | meaning |
|--------|---------|
| `LIVE` | Shipped and unconditionally invokable; produces its effect on the default path. |
| `OPT-IN` | Shipped but off by default; the operator turns it on explicitly. |
| `GATED` | Shipped but its effect is behind an authorization / approval / quorum gate, or is deploy-gated on infrastructure. |
| `BUILT-NOT-WIRED` | The symbol exists (interface / stub / scaffold) but no runtime reaches it: a stub that raises `NotImplementedError`, or an abstract interface only. |
| `ORPHANED` | A registered surface (e.g. a console read route) that nothing consumes. Detection is enforced by the **W17-14 orphan-route guard**; **no feature is ORPHANED today**. |

## What is covered (and what is covered elsewhere)

This audit covers the **enumerable, machine-checkable surface**:

- **every `vigil` native CLI verb** (41) — `cli-native-verb`, anchored to its handler in
  `integration/vigil_integration/cli.py`;
- **every subsystem passthrough verb** (5: `sigil`, `crucible`, `aegis`, `strix`, `gateway`) —
  `cli-passthrough-verb`, anchored to the dispatcher's hardcoded `_ENV` table;
- **the deferred-infra subsystems** (4) — the TEE attestation stub, the symbolic crash-repair stub, the
  deploy-gated Neo4j store, and the pluggable agent-body scaffold.

Two surfaces are already guarded and are **referenced, not duplicated**:

- **UI screens** — the system-map drift invariant (`tools/system-map/generate.py --check`) already enforces
  `screens.yaml` ids == the UI `NAV` ids == the UI `route()` ids. This audit extends *that* discipline to
  the CLI surface.
- **Console read routes** — the **W17-14** orphan-route guard already asserts every registered console read
  route is consumed by the shipped UI or listed as a documented programmatic endpoint, and a new orphan
  turns the required CRUCIBLE-core job red.

## `vigil posture` is LIVE (a stale report, refuted)

An older audit note reported `vigil posture` as "unwired as a dispatch verb". That is **false of the
current code**: `posture` is a registered native verb (`sub.add_parser("posture")` +
`set_defaults(func=_cmd_posture)` in `cli.py`), dispatched in-process — it is not a subsystem passthrough
verb and needs no `_ENV` entry. The audit records it `LIVE`, and
`test_posture_is_live_not_a_stale_unwired_report` pins that fact against the code.

## What the guard checks (and why it is not advisory)

`../tests/test_feature_wiring_status.py`, stdlib-only (`json`, `ast`, `pathlib`):

1. **schema + enums** — every feature has every field; status and check are valid;
2. **status agrees with code, per check kind**:
   - `cli-native-verb` — the verb is a real top-level `sub.add_parser` verb, the handler resolves by AST,
     and the status is a wired status (LIVE / OPT-IN / GATED);
   - `cli-passthrough-verb` — the verb is a key of `dispatch._ENV`;
   - `stub-raises` — the anchored function actually raises `NotImplementedError` (BUILT-NOT-WIRED / GATED);
   - `scaffold-abc` — the anchor is an abstract (ABC / `@abstractmethod`) class (BUILT-NOT-WIRED);
3. **coverage (the drift extension)** — the SET of declared native verbs EQUALS the set the parser
   registers, and the passthrough set EQUALS `_ENV` — so a new verb with no registry entry, or a registry
   verb removed from the parser, turns CI red;
4. **registered** — the behaviour is in the claims registry (this claim, `W15-2`);
5. **negative controls** — a LIVE feature for a non-existent verb, a stub that no longer raises, a
   status/check mismatch, a concrete class declared a scaffold, an ORPHANED feature without the
   orphaned-route check, and a simulated coverage drop are each rejected in the same run.

## Filing the unfinished items into W17

The three BUILT-NOT-WIRED features and the deploy-gated Neo4j store are the audit's unfinished items;
filing each as a W17-milestone issue is a bulk, owner-reviewed operation. The registry is the source of
truth those issues are filed from, and the guard keeps it honest whether or not the issues are open yet.

## How to add / change a feature's status

1. Land (or identify) the feature and the code fact that fixes its status.
2. Add/update the `wiring-status.json` entry (pick the honest status + the `check` that verifies it).
3. Run `python -m pytest docs/tests/test_feature_wiring_status.py -q` — green before you commit.
