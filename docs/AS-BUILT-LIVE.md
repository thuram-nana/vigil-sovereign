# VIGIL-LIVE — AS-BUILT (honest, live vs deferred)

This records what the VIGIL-LIVE program (§12 of the fusion plan) actually built and validated **live**
against the loopback target, and — with equal care — what is **LEAD-only** or **deferred**. Nothing
here is claimed beyond what the deterministic layer enforces. Everything below was exercised end-to-end
on `127.0.0.1` on 2026-07-21.

The governing invariant is unchanged going live: **the LLM/tools only PROPOSE; only the CRUCIBLE oracle
mints a signed FACT; only the conjunctive gate authorizes an action; only the loopback egress pin lets a
packet out.**

---

## 1. What is LIVE (validated end-to-end)

### The unified engine (`vigil engage`) — one attestation-first OODA loop
`integration/vigil_integration/live/engine.py` + `live/wiring.py` + `cli.py`. A single loop wires the F2
ReAct core through EVERY subsystem and the **real** sovereign seams (no thunks): attest → think → parse
fail-closed → classify+authorize the edge → execute → oracle re-fire → sign FACT (else LEAD) → project →
govern → observe → checkpoint → loop; then the Detection Mirror. A real live run:

```
$ vigil engage http://127.0.0.1:18080/search?q=1 --approve-offense \
      --access-log .../access.log --auth-log .../auth.log
attestation      : 2ad99e97f1c69fded…                 # WS-6 usage record minted BEFORE any action
iterations       : 3   decisions: use_tool, use_tool, complete
tool calls       : 2  (ran=2, denied=0)               # both ran through the REAL gate chain
FACTS (oracle-confirmed, signed): 1                   # SQLi confirmed by boolean_inference over context
LEADS (proposals, unconfirmed)  : 0
detection mirror : facts=7  leads=1                   # 7 signed detection certs over the REAL logs
checkpoints      : 2                                  # state snapshotted to the signed spine
```

Proven live (both by the run above and by `tests/test_engine_live.py`, which runs in CI's
offense process):

| Property | Enforced by | Evidence |
|---|---|---|
| **Attestation-first (WS-6)** — no attestation → no run | `attestation.ledger.require_attestation` | `engage` refuses with an empty run if the ledger cannot be minted+durably written |
| **Real gate (F2/F3)** — in-scope 127.0.0.1 is IN-ENVELOPE, out-of-scope is a hard DENY | `conjunctive_gate.build_offense_gate` over a signed CRUCIBLE authority | `gate("httpx","127.0.0.1")→queue (crucible_allowed=True)`; `gate("httpx","example.com")→deny (crucible_allowed=False)` |
| **No auto-fire of offense tools** — an autonomous agent may never auto-run an A2+ tool | WARDEN (`AUTO_BAR=A1`, offense floor `A2`) | every offense tool QUEUES; it runs only with the operator's `--approve-offense` (the human leg) |
| **Oracle mints the FACT, not the LLM (F2)** — a claimed exploit is a LEAD until the deterministic oracle re-fires | `oracle_adapter.confirm_and_certify` → `boolean_inference` | a firing SQLi `oracle_context` → 1 signed FACT; a non-firing context → stays a LEAD |
| **Scope can't be widened by approval** | `_approval_gate` upgrades only WARDEN `queue`, never a CRUCIBLE `deny` | out-of-scope stays denied even with `--approve-offense` |
| **Signed spine checkpoint (F2b)** | `live.spine_vigilcore.VigilCoreSpine.write_state` | 2 append-only, hash-chained, Ed25519-signed snapshots per run |

### The deep-core usage ledger (WS-6) — WHO / WHEN / WHAT, non-repudiable
`vigil ledger who|when` and `vigil verify-ledger`. The ledger is the signed spine (kind
`usage_attestation`); it verifies across multiple engagements as one unbroken chain:

```
$ vigil ledger who
  seq=0  os=kali  git=Water Hacker  host=kali  key=349311e69bf1f574…  did=engage → http://127.0.0.1:18080/…  (phase=informational)
  seq=1  os=kali  git=Water Hacker  host=kali  key=349311e69bf1f574…  did=engage → http://127.0.0.1:18080/…  (phase=informational)
$ vigil ledger when
  seq=0  at=2026-07-21T22:27:23…  monotonic=1  (TPM-anchored)
  seq=1  at=2026-07-21T22:27:24…  monotonic=2  (TPM-anchored)
$ vigil verify-ledger
  ledger: 2 records — VERIFIED: link, sign, and never back-date (monotonic non-decreasing)
```

The time is **TPM-anchored** (the box has a TPM; the monotonic counter is hardware-grounded), so a
record cannot be back-dated; it degrades to the software hash-chain when the TPM op is unavailable
(never weaker than the chain).

### The AEGIS Detection Mirror (WS-4) — dual certs over the target's own telemetry
`detection/`. Run over the loopback app's real `access.log` + `auth.log`, the edge-plane oracles minted
**7 signed detection FACTs + 1 LEAD** (sqli/xss/path-traversal/cmd structure, forced-browsing,
scanner-fingerprint, brute-force/spray), each with a re-verifiable PCF certificate and a mandatory
passing benign twin. This closes the self-proving loop: one run produces an **offense FACT** (the SQLi
the engine confirmed) paired with **detection FACTs** (what that class of attack looks like defensively).

### Live substrate (WS-0)
`infra/loopback/vulnapp.py` (a genuine controlled-SQLi/XSS/traversal target on `127.0.0.1:18080` writing
CLF access + auth logs), `targets/loopback/charter.md` (scope `127.0.0.1` only), the OTel sidecar config.

### The six live binders (WS-1) + phase 32 auto-patch (WS-3)
Merged in PR #29 and wired into the engine: the governed loopback-pinned executor, the projection-only
Neo4j writer, the garak/PyRIT subprocess adapter, the OTLP exporter, the live Claude think-step, the real
`vigil_core` spine checkpointer, and the AIxCC auto-patch loop (finding→patch→gated PR→fix-verification
oracle; timeout → REJECT).

---

## 2. What is LEAD-only (honest, by design)

- **Detection telemetry/egress planes** (C2, identity-graph, cloud, session-phish): we do not have the
  DC/CloudTrail/NetFlow logs these need, so they are **LEAD-only / deferred** exactly as the AEGIS doc
  §7 states. Only the edge plane (recon + injection + credential) mints FACTs here.
- **`judge_llm` AI-Gauntlet ASR** (F8): a non-deterministic LLM-judge result **never** auto-promotes to a
  FACT; it stays a LEAD until a deterministic `oracle_kind` reconfirms.
- **Cognition governors** (F5): re-rank/defer only — they never gate a finding's truth.

---

## 3. What is DEFERRED to further owner infra (pure logic + wiring built; live sidecar not exercised here)

- **Live Neo4j / OTel collector**: the binders (`live/graph_neo4j.py`, `live/otel_export.py`) are wired
  and unit-proven; a running Neo4j/OTLP endpoint was not stood up for this validation (the engine
  degrades these seams to no-op without affecting the run's truth).
- **Live Claude think-step**: exercised in **replay** (keyless) mode here (no `ANTHROPIC_API_KEY`); the
  live path (`live/think_claude.think`) builds a real client when a key is present. The provable layer
  never depends on the model.
- **Live garak/PyRIT execution** (F8), **live subprocess Kali tools** end-to-end: the executor ran real
  `nmap`/`httpx` invocations gated + pinned; the deterministic echo runner is used in the CI test so the
  gate/oracle/spine wiring is validated without requiring the binaries. The gate/oracle/egress checks are
  byte-identical either way.
- **Signed per-action operator approval token**: `--approve-offense` encodes the operator's *standing*
  approval for their own chartered loopback. The cryptographic per-action signed-approval mechanism
  (the I4 destruction-gate quorum) plugs into the same seam unchanged.
- **TEE/FROST** (I4): out of scope for this program.

---

## 4. How to run it

```bash
# 1. provision a signed CRUCIBLE authority for the loopback slug (scope = literal 127.0.0.1)
PYTHONPATH=integration:engine/crucible:gateway vigil provision --slug loopback --scope 127.0.0.1

# 2. run an engagement (keyless replay; --approve-offense = the operator's human leg)
vigil engage http://127.0.0.1:18080/search?q=1 --approve-offense \
    --replay decisions.json --access-log <access.log> --auth-log <auth.log>

# 3. prove who used the tool, when, against what — and verify the chain
vigil ledger who ; vigil ledger when ; vigil verify-ledger
```

CI validates the whole loop: the injected-seam engine tests run in the main integration process
(`test_engine.py`, 17 tests), and the live validation over the REAL gate + oracle runs in the offense
process (`test_engine_live.py`, 5 tests, `PYTHONPATH=integration:engine/crucible:gateway`).
