# The CRUCIBLE offense engine (`engine/crucible/framework/v2`)

## 1. What it is

CRUCIBLE is VIGIL's **offense plane**: the whole scan → engage → verify → report arsenal
that actually touches targets and turns raw target behaviour into graded findings. It runs
**keyless**, in `.venv-offense`, alongside `vendor/strix`, `gateway`, and `integration`. Its
one job is to make the platform's headline promise true — *the machine cannot lie about a
finding*. An LLM (Strix, the URK kernel, critics, RL) may propose where to look and what a
result might mean, but **only a fired deterministic oracle over target-produced, non-LLM bytes
mints a signed FACT**. Everything else is a LEAD. `framework/v2` is the *executable* layer;
`framework/v1` is the frozen doctrine canon it wraps (see [`README.md`](../../engine/crucible/framework/v2/README.md)).
This page is the map: the module layout, the OODA loop, and exactly how a finding is graded
FACT / LEAD / CLEAR. Prose companion to the system model in [`architecture.md`](architecture.md).

## 2. Module map — the authoritative code paths

Root: `engine/crucible/framework/v2/`. Every path below is relative to it unless noted.

| Subsystem | Path / symbol | Job |
|---|---|---|
| **CLI dispatcher** | `__main__.py` — `_DISPATCH` (~line 216), `main()` | `python3 -m framework.v2 <subcommand>`: `scan` / `engage` / `verify` / `report` / `intel` / `knowledge` / `evidence` / `benchmark` / `status` / … Each subcommand is imported lazily inside its handler. |
| **Ethics gates** | `common/ethics.py` — `require_charter_signed`, `require_in_scope`, `require_authorized_intake`, `host_matches_scope`, `parse_scope` | Non-negotiable authorization. Raise `EthicsViolation`; **no subsystem catches it** — it halts the CLI. |
| **URK (kernel)** | `kernel/` — `hypothesize.py`, `critique.py`, `pivot.py`, `llm.py`, `backends/` | Wraps v1 cognitive prose as typed callables. **Advisory only.** No key, no Ollama → DryRun deterministic stubs to `.dryrun/`. |
| **MLS (memory)** | `memory/` — `store.py`, `recall.py`, `priors.py` | Cross-engagement priors/recall. A prior is a LEAD, never a fact. |
| **UTI (intake)** | `intake/` — `intake.py`, `stack_classifier.py`, drafters | URL → scaffolded engagement (charter/threat-model drafts). Gated by `require_authorized_intake`. |
| **Agents (MAO)** | `agents/` — `blackboard.py`, `base.py`, `coordinator.py`, executors, `critique_agent.py` | Multi-agent OODA over an **append-only blackboard**. See [`agents/README.md`](../../engine/crucible/framework/v2/agents/README.md). |
| **Scanner** | `scanner/` — `insertion.py` (`RequestTemplate`), `checks.py` (`Check`), `engine.py` (`AuditEngine.audit`) | Burp-parity crawl→scan engine driven by the planner. Emits evidence into N insertion points; **confirmation stays with the oracle layer**. |
| **Verify (oracles)** | `verify/oracles.py`, `verify/models.py` (`OracleKind`, `OracleSignal`, `VerificationResult`), `verify/verifier.py` (`OracleVerifier`, `BUG_CLASS_ORACLES`, `is_known_bug_class`), `verify/confirmation.py` (`confirm_finding`), `verify/oob.py`, `verify/reverify.py` | The **KEYSTONE**: the deterministic confirmation authority. Pure, offline, no clock/RNG. |
| **Oracle adapter** | `integration/vigil_integration/oracle_adapter.py` — `confirm_and_certify()` (line 81), `certify_to_scitt()` | The no-hallucinated-findings bridge: drives verify + evidence, applies the honesty + provenance gates, mints signed `SignedEvidence`. Lives in `integration` (installed in both venvs); `framework.v2` imports are **lazy**. |
| **Evidence** | `evidence/certify.py` — `build_certificate` (53), `sign_certificate` (111), `verify_certificate` (171); `canonical.py`, `manifest.py`, `chain.py`, `pcf.py`, `poc.py` | Turns a replayable finding into a **proof-carrying, offline-verifiable** certificate. |
| **Report** | `report/generate.py` (three renderers), `report/grounding.py` (`admit_for_report` → FACT/DEMOTED/LEAD), `report/priority.py`, `report/standards.py` | Deterministic Markdown: executive / technical / remediation. **Re-grades at render time.** |
| **Intel** | `intel/` — `promote.py` (the DISCOVERER keystone), `collectors/`, `ingest.py`, `fuse.py`, `infer.py`, `predict.py`, `resolve.py`, `learn.py` | Reason-over-intel recon feed. Projects assets → world-model. See §5 gotcha on `promote`. |
| **Knowledge engine** | `knowledge_engine/` — `proposals.py` (`draft_proposals`), `deeplearn.py`, `evolve.py`, `retrieve.py` | Offense half of the Knowledge Engine (K2+). **Pure ranking over intel-tier leads; authorizes nothing.** |
| **World-model** | `worldmodel/` — `models.py` (`classify_provenance`, `NodeKind`) | Typed attack graph; the chaining substrate. One-way projected to Neo4j; never a source of truth. |
| **Live seam** | offense entry: `engage.py` `run_engagement()` (613) + `engage_autonomous.py` `run_autonomous_cycle()` (1180). Unified live engine: `integration/vigil_integration/live/engine.py` `VigilEngine.engage()` (168), wired by `live/wiring.py`, executed by `live/executor.py` `execute()` (610) | Where the engine actually fires tools and folds results. See §3. |

## 3. The OODA loop — two entry points, one doctrine

CRUCIBLE runs the OBSERVE → ORIENT → HYPOTHESIZE → TEST → UPDATE cycle in two places. Both
route every target-touching action through the gate and every claim through the oracle.

**(a) The authoritative engagement — `engage.py:run_engagement()` (613).**
The batch scan→confirm→chain pipeline. `preflight(slug, seed_url)` runs the ethics gates
(refusal recorded on the spine, then raised as `EngagementRefused`); the scanner crawls and
fires checks into insertion points; each candidate goes through the **oracle layer**, and only
oracle-confirmed findings are written into the world-model, where the technique operators run to
a fixpoint to extract attacker→crown-jewel attack paths (`enable_chaining`, sends no traffic).
Returns an `EngagementResult` (the confirmed `ScanReport` + reasoning). An **opt-in** autonomous
OODA cycle (`--autonomous`, `engage.py:1031` → `engage_autonomous.run_autonomous_cycle()`) can
re-orient the planner over the world-model for a bounded number of cycles; **default OFF → the
run is byte-identical without it.** Its probe-leaves come *only* from url-bearing
`NodeKind.ENDPOINT` nodes (see §5).

**(b) The unified live engine — `live/engine.py:VigilEngine.engage()` (168).**
The pure OODA loop over a set of **injected seams** (stateless between engagements; state lives
in `AgentState` + the signed spine). Per iteration:
1. `_attest_run` FIRST — no usage attestation → the whole run refuses (never crashes).
2. `_drain_operator` folds queued operator instructions (advisory).
3. `_think` proposes an action (LLM/planner — advice).
4. `authorize_edge(...)` → the gate. `allow` (A0/A1 auto) runs; `queue` needs a **signed**
   operator approval (approve-then-run); anything else is a recorded refusal → **pivot, never
   give up the run** (constitution §IX).
5. `_run_tool` → `live/executor.py:execute()` — the governed, loopback-pinned subprocess runner.
6. **Oracle intake** (the load-bearing anti-hallucination seam): `intake_result(raw, …, oracle=…)`
   turns the LLM's `exploit_succeeded` into LEADs; only the oracle re-firing over the **raw tool
   output** promotes to a signed FACT. Then `_project` / `_govern` / `_emit` / `_checkpoint`.

`live/wiring.py` binds those seams to the real machinery — `attestation.ledger`, the offense gate
(`conjunctive_gate.build_offense_gate`), `live.executor.execute`, and
`oracle_adapter.confirm_and_certify` as the `oracle` seam. All `framework.v2.*` imports there are
**lazy, function-local** — the module stays import-clean and never co-loads the sovereign env.

## 4. How a finding is graded — FACT / LEAD / CLEAR

This is the whole moat. Grading happens in the oracle layer, is sealed by the adapter, and is
**re-checked at report time**.

**Step 1 — deterministic confirmation (`verify/`).** `OracleVerifier.confirm()`
(`verifier.py:557`) runs the oracles selected by `bug_class` (`BUG_CLASS_ORACLES`,
`verifier.py:33`; unknown class → the frozen 15-member `_ALL_ORACLES` fallback at
`verifier.py:445`, running only oracles whose inputs are present). Each oracle is a pure function
over already-observed data returning an `OracleSignal(fired, kind, confidence, …)`. A result is
`confirmed` **iff at least one oracle fired at ≥ `HIGH_CONFIDENCE` = 0.7** (`verifier.py:25`).
Combine policy is `any_high_confidence_fired` (safety-monotone: a non-firing oracle cannot veto a
fired one, but is recorded as `dissent`). Confidence is noisy-OR clamped to 0.99 — a deterministic
oracle never claims certainty it cannot have. `confirm_finding()` (`confirmation.py:102`) returns
**`None`** when nothing fires: **there is no assertion-only path to confirmation.**

**Step 2 — the sealing gates (`oracle_adapter.confirm_and_certify`, line 81).** Three
demote-before-sign gates, each producing a LEAD if it fails:
- **fired?** `confirm_finding` returned `None` → LEAD ("oracle did not fire").
- **known class?** `is_known_bug_class(confirmed_class)` — a generic-oracle fire on a class with
  no deterministic mapping stays a **labelled LEAD**, never signed.
- **reproduced provenance?** `provenance ∈ {"reproduced", "live_redrive"}`. The **default is
  `"llm"`** — a context the model emitted (its `extracted_info`) is demoted to a LEAD *even when
  the oracle fires*, because a crafted-but-firing context is an LLM-influenced route to a FACT
  (audit gate G4). Only executor-captured raw bytes or a live re-drive back a FACT.

Only if all three pass does it `build_certificate` + `sign_certificate` (m-of-n governance
signers, required — zero signers raises) → `AdapterResult(status="fact", signed=SignedEvidence)`.
That `SignedEvidence` is what later crosses the inert file seam to the sovereign spine.

**The three grades:**
- **FACT** — oracle fired ≥0.7 **and** class is oracle-mapped **and** context is reproduced from a
  non-LLM channel **and** the certificate is signed. Rendered with its re-runnable certificate
  digest (`python3 -m framework.v2 verify`). A `verify_certificate` (`evidence/certify.py:171`)
  proves four independent things — **authenticity** (m-of-n sig), **binding** (`oracle_context_digest`),
  **artifact integrity** (manifest hashes), **reproduction** (pure oracle re-fires) — so a third
  party trusts the finding with zero trust in the tool.
- **LEAD** — anything the model advised but the oracle did not seal: not fired, fired-but-unmapped,
  or fired-but-LLM-provenanced. Also **DEMOTED** — recorded confirmed but the retained proof does
  **not** re-fire at report time (`report/grounding.py:admit_for_report` re-executes the
  `oracle_context` via the veracity firewall). A LEAD is retained, honest, replayable — never
  asserted as a thing an attacker *can* do.
- **CLEAR** — a surface was tested and produced no fact and no lead (`report/standards.py`:
  `CELL_TESTED_CLEAR = "tested_clear"`). The negative-control discipline: `verify/confirmation.py`
  ships a deliberately-vulnerable loopback target **and its safe twin**, and the scanner e2e
  confirms findings on the vulnerable parameter and **CLEAR on the safe one** — proving the oracle
  does not fire on benign input.

## 5. How to extend it safely

**Add a new bug class the oracles already cover.** Declare a `Check` in `scanner/checks.py`
(`DifferentialCheck` or `MarkerReflectionCheck`) that places a payload into one insertion point
and shapes the responses into a `verify.FindingContext`. **No new oracle needed.** The check emits
evidence; the oracle decides. Add an e2e in `scanner/tests/` that confirms on a vulnerable
loopback param and CLEAR on a safe one.

**Add a genuinely new oracle.** Add a pure function to `verify/oracles.py` (no I/O, no clock, no
`random`), a member to `OracleKind` in `verify/models.py`, a `BUG_CLASS_ORACLES` row in
`verifier.py`, and a dispatch arm in `OracleVerifier._run`. **Do not add it to `_ALL_ORACLES`**
unless it is safe under the unknown-class fallback — keep the fallback frozen at its 15 web/infra
members; AEGIS/posture oracles reach the verifier *only* via their explicit `BUG_CLASS_ORACLES`
rows keyed on a ctx field no scan/engage finding carries. Add unit tests that assert it **fires on
a real signal and does not fire on the negative control**, plus a round-trip through
`confirm_and_certify` asserting a signed FACT for a reproduced context and a LEAD for
`provenance="llm"`.

**Wire a new tool into the live loop.** Add it behind `live/executor.py:execute()` so it inherits
the gate + loopback pin + spine signer; return its raw stdout for oracle intake. Never let a tool
self-claim success — the executor returns evidence, the oracle grades it.

**Copy the intel/knowledge pattern for anything "learned".** A recon/intel/proposal write is a
LEAD/prior/proposal, stamped by `worldmodel/models.py:classify_provenance` as `intel`/`ungrounded`
(never `grounded`). `knowledge_engine.draft_proposals` shows the shape: pure ranking, touches no
oracle/gate/graph, and an accepted proposal authorizes *learning*, never fact-minting.

## 6. Invariants this engine must preserve (and why)

1. **Oracle authority is absolute.** Only `confirm_and_certify` with a fired oracle over reproduced
   non-LLM bytes returns a FACT. URK, critics, RL, memory, reflection, `draft_proposals` — all
   advisory. *Why:* the anti-hallucination guarantee is the product. The old critique-agent gate is
   now advisory; `verify/` **replaces** it as the confirmation authority.
2. **Provenance gate (`provenance="llm"` default → LEAD).** A crafted context that fires the oracle
   must not mint a FACT. *Why:* it is the LLM's last route to fabricating a "proof."
3. **Two-env boundary.** CRUCIBLE never co-loads the sovereign env (`FATAL-2`). `oracle_adapter` and
   `live/wiring` touch `framework.v2` **only through lazy, function-local imports**; planes bridge by
   subprocess or a signed inert file. *Why:* the owner key must never share an interpreter with
   offense code. Keep any new `framework.v2` import lazy.
4. **Gate of record on every target-touching action.** `run_engagement` preflight + the live loop's
   `authorize_edge`/`build_offense_gate` run the conjunctive chain (WARDEN → signed-scope → egress
   floor → kill-switch → capability latch → owner approval → m-of-n if destructive), first-failure-
   wins, and a signed redacted `ExecRecord` lands on the spine. *Why:* nothing self-authorizes; a
   refusal pivots, never crashes and never silently proceeds.
5. **Determinism + append-only.** No wallclock/RNG in oracle, grading, report, or priority math
   (`report/*` renders byte-identically unless `ReportMeta.generated_at` is passed explicitly); the
   blackboard and evidence chain refuse UPDATE/DELETE. *Why:* a proof you cannot re-run is not a proof.

## 7. Gotchas

- **DryRun by default.** No `ANTHROPIC_API_KEY` / reachable Ollama → URK returns deterministic stubs
  to `.dryrun/`. The engine runs offline; **reasoning quality is bounded and several "live-path
  verified" boxes in `agents/README.md` are `no`** (inherited unexercised-LLM-path risk). Do not
  read a green DryRun run as a live-LLM validation.
- **Discovery is inert until promotion.** Recon (crt.sh/DoH/RDAP collectors, `AssetPredictor`)
  projects DOMAIN/HOST/SERVICE facts into the world-model, but the autonomous loop only probes
  url-bearing `NodeKind.ENDPOINT` nodes. `intel/promote.py` is the single edge that turns an
  in-scope asset into a probeable `intel:promote:` ENDPOINT — written as a **LEAD, never a fact**,
  in-scope by construction (`host_matches_scope`) yet **still re-gated fail-closed** at every probe.
  Adding a minting site that writes url-bearing ENDPOINTs elsewhere silently widens the attack loop —
  don't, without the same scope predicate.
- **`OracleKind` is `(str, Enum)`, not `StrEnum`.** `str(kind)` yields `'OracleKind.X'`, which the
  reproduction/`verify_certificate` layer rejects as tampered. Always store `kind.value` (see
  `oracle_adapter._kind_str`).
- **Signers are mandatory for a FACT.** `confirm_and_certify` **raises** on zero signers rather than
  labelling an unsigned certificate a fact — fail-closed. Live-fire needs the operator to provision
  the m-of-n governance keys.
- **`certify_to_scitt` refuses a lead.** Only a FACT has a signed certificate to express as an
  OpenVEX `affected` statement; passing a lead raises (fail-closed honesty).
- **Report grading can DEMOTE.** A finding recorded `confirmed` yesterday renders as a LEAD today if
  its retained `oracle_context` no longer re-fires (altered evidence, relabelled class, dry-run
  stub). Trust the re-grade, not the record.
