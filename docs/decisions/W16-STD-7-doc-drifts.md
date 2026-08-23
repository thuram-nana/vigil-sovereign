<!-- CLAIM:W16-STD-7-drift -->
# W16-STD-7 (#533) — the §16 doc-vs-code drift batch

**Registered claim (W16-STD-7 #533):** The §16 doc-vs-code drifts named in the limitations inventory are
corrected to match the code, and a required test fails the build if any of them re-opens — a forbidden
false phrase returns, a corrected anchor is silently reverted, or a code fact a correction cites stops
being true in-tree.

## Context

The limitations inventory §16 re-verified a set of documentation claims that had fallen behind the code at
the audited HEAD. Several were **underclaims** — a doc calling a shipped capability absent — which is the
dangerous kind, because it sends a reader (or a procurement reviewer) away believing the product does less
than it does. Each was re-verified against the current source before correction; the ones the inventory
listed that were already closed at this HEAD (16.1 CONTINUATION, 16.9 SYSTEM-STATE, 16.10 SECURITY,
16.17 CLAIM-6-RBAC, 16.19 AS-BUILT Strix gate) were left alone, and two the inventory flagged that are in
fact accurate deferrals (16.12 the witness live co-sign transport, 16.13 the oracle-adapter live re-drive)
were deliberately **not** "corrected", because a wrong correction is itself a drift.

## Decision

Correct the still-open §16 drifts against the code and pin them:

| # | Doc | Was | Now (true of the code) |
|---|-----|-----|------------------------|
| 16.2 / 16.16 | DEVELOPER-HANDOFF.md §3, AS-BUILT.md §7 | "CI runs six / 6 jobs" | 12 jobs in `ci.yml` (full table); required set is the 14 in `.github/required-status-checks.txt` |
| 16.3 | FEATURES.md | `k8s_workload_posture_oracle` "is NOT wired into `verifier._run`" | it **is** wired (`verifier.py:854-858`), firing on the `k8s_workload_control` ctx key |
| 16.4 | FEATURES.md | `crucible-blackboard-chain` "owner_rooted=False AND file_backed=False — NOT wired" | `owner_rooted=True, file_backed=True`, wired + offline-verified (`spine_domains.py`, `live/wiring.py`, `live/spine_verify.py`) |
| 16.5 / 16.8 | AS-BUILT.md, AS-BUILT-LIVE.md, FEATURES.md | `Neo4jGraphStore` "[SCAFFOLD] (every method raises)" | a real client body issuing MERGE/read Cypher (`store.py:315-420`); only construction without a driver raises |
| 16.6 | AS-BUILT-LIVE.md | signed per-action approval token "genuinely not built" | **built** — `live/approval_token.py` + `live/approval_broker.py` + `vigil approve` |
| 16.7 | FEATURES.md | DEFERRED-INFRA.md "contains only G1/X1/X2/X3" | it contains G1, X1, X2, X3, H3, H4, R4, E and a Phase-0.2 section |
| 16.14 | scanner/campaign.py | remote-engage browser path "deferred until a CDP request-allowlist gates that egress" | that allowlist ships (`cdp.py: enable_request_allowlist`) and is wired; the egress is now gated |
| 16.15 | improve/patcher.py | referenced `framework/playbooks/03-surface-mapping.md` (does not exist) | `framework/playbooks/03-attack-surface-mapping.md` (the real file) |
| bonus | ci.yml comment | a stale required-check count (13) | corrected to 14 (matches the canonical file) |

## Enforcement

`docs/tests/test_w16_std7_doc_drifts_corrected.py` is the guard. It fails four ways — a forbidden false
phrase returns, a corrected anchor is gone, a cited code fact is not true in-tree, or a negative control
shows the checker went no-op — and runs in the required `the briefing explains every agent and capability`
CI job. It is registered in the claims registry (`docs/claims/registry.json`), folding W16-STD-7 into
W0-3 (#398).
