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

This audit covers the **enumerable, machine-checkable surface** (87 features, `audit_version: 2`):

- **every `vigil` native CLI verb** (41) — `cli-native-verb`, anchored to its handler in
  `integration/vigil_integration/cli.py`;
- **every subsystem passthrough verb** (5: `sigil`, `crucible`, `aegis`, `strix`, `gateway`) —
  `cli-passthrough-verb`, anchored to the dispatcher's hardcoded `_ENV` table;
- **every unified-UI screen** (32) — `ui-screen`, each pinned to a real `NAV` id **and** a real `route()`
  id in `packages/vigil-ui/app.js`. This is the system-map drift invariant (`NAV == route() ==
  screens.yaml`) re-derived from `app.js` (via `tools/system-map/generate.py`'s own extraction) and pinned
  into the registry — so the dedicated `defense` (AEGIS), `chat`, `brain`, `mcp`, and `strix` screens each
  carry a status;
- **the subsystem seams** (5) — `symbol-exists`, anchored to a real symbol: the `chat` orchestrator
  (`/api/chat/send`, LIVE), the `fireteam` fan-out (`run_fireteam`, GATED on an approved deploy), the
  `--brain hexstrike` planner (OPT-IN), the MCP tool-governance boundary (`authorize_tool_call`, LIVE), and
  the **not-yet-wired** live external-MCP-server client (`to_client_config`, BUILT-NOT-WIRED — see below);
- **the deferred-infra subsystems** (4) — the TEE attestation stub, the symbolic crash-repair stub, the
  deploy-gated Neo4j store, and the pluggable agent-body scaffold.

One surface is already guarded and is **referenced, not duplicated**:

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
   - `ui-screen` — the `screen` is a real `NAV` id **and** a real `route()` id in `app.js`, status wired;
   - `symbol-exists` — the anchored subsystem symbol resolves by AST (no phantom subsystem);
   - `stub-raises` — the anchored function actually raises `NotImplementedError` (BUILT-NOT-WIRED / GATED);
   - `scaffold-abc` — the anchor is an abstract (ABC / `@abstractmethod`) class (BUILT-NOT-WIRED);
3. **coverage (the drift extension)** — the SET of declared native verbs EQUALS the set the parser
   registers, the passthrough set EQUALS `_ENV`, and the declared `ui-screen` set EQUALS the app.js `NAV ==
   route()` set — so a new verb/screen with no registry entry, or a registry verb/screen removed from the
   code, turns CI red;
4. **the MCP live-client seam** — `test_mcp_live_client_seam_is_still_unwired` asserts `to_client_config`
   has zero runtime call-sites, enforcing the `BUILT-NOT-WIRED` status; wiring a live client fails the test
   until the status is updated;
5. **registered** — the behaviour is in the claims registry (`W15-2` for the CLI/deferred surface, `W15-2b`
   for the UI-screen + subsystem-seam coverage);
6. **negative controls** — a LIVE feature for a non-existent verb, a phantom UI screen, a symbol-exists seam
   on a non-existent symbol, a stub that no longer raises, a status/check mismatch, a concrete class
   declared a scaffold, an ORPHANED feature without the orphaned-route check, and simulated verb/screen
   coverage drops are each rejected in the same run.

## Filing the unfinished items into W17

The audit's unfinished items are the **four BUILT-NOT-WIRED features** — the TEE attestation stub, the
symbolic crash-repair stub, the pluggable agent-body scaffold, and the **live external-MCP-server client**
(`mcp.server_client`: the manifest + governance are built, but nothing consumes `to_client_config` yet) —
plus the **deploy-gated Neo4j store** (GATED on infra). Filing each as a W17-milestone issue is a bulk,
owner-reviewed operation; the proposed W17 items are enumerated in the *"Unfinished features → proposed W17
milestones"* section below. The registry is the source of truth those issues are filed from, and the guard
keeps it honest whether or not the issues are open yet.

## Unfinished features → proposed W17 milestones

Every non-`LIVE`/non-`OPT-IN` feature that is not simply operator-gated is listed here with a proposed
milestone for the orchestrator to file (no network from this worktree, so these are enumerated, not filed):

| feature id | status | proposed W17 milestone |
|------------|--------|------------------------|
| `mcp.server_client` | BUILT-NOT-WIRED | **W17-MCP-1** — wire the live MCP client (bind the Claude-Agent-SDK MCP client to consume `to_client_config`), behind the existing `tools.governance` phase/tier gate; flip `mcp.server_client` to GATED. |
| `attest.tee` | BUILT-NOT-WIRED | **W17-TEE-1** — land a real SEV-SNP/TDX attestation provider (hardware-gated); flip to GATED-on-silicon. |
| `remediation.symbolic` | BUILT-NOT-WIRED | **W17-CRS-1** — implement the general native-patch synthesiser (`SymbolicCrashRepairTier.synthesize_patch`) or formally descope it. |
| `agent_body.pluggable` | BUILT-NOT-WIRED | **W17-BODY-1** — ship (or descope) a next-gen agent body behind the `AgentBody` ABC; Strix remains the one shipping body. |
| `graph.neo4j` | GATED (infra) | **W17-GRAPH-1** — document + smoke the deploy-gated Neo4j path in a scheduled (non-PR) job; `EmbeddedGraphStore` stays the default. |

The 14 `GATED` CLI verbs (destruction quorum, engage, patch, remediate, terminal, sandbox, …) are
**operator-gated by design**, not unfinished — no milestone.

<!-- CLAIM:W15-2b -->
**Registered claim (W15-2b, W0-3 #398):** The wiring-status registry also covers every unified-UI screen (each a real NAV id and route() id in app.js), the chat, fireteam and brain subsystems, the MCP tool-governance boundary and the not-yet-wired MCP live-client seam; the declared UI-screen set must equal the UI's NAV == route() set, and a subsystem seam anchored to a phantom symbol turns the build red.

## How to add / change a feature's status

1. Land (or identify) the feature and the code fact that fixes its status.
2. Add/update the `wiring-status.json` entry (pick the honest status + the `check` that verifies it).
3. Run `python -m pytest docs/tests/test_feature_wiring_status.py -q` — green before you commit.
