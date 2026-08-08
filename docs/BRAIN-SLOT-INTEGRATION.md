# The "Better Brain" Slot — hexstrike-ai integration (step by step)

VIGIL's agent-body socket (`engine/crucible/framework/v2/agent_body/interface.py :: AgentBody`,
`think→propose→gate→execute→learn`, `run_cycle` structurally enforces gate-before-execute) was a
research-gated **scaffold**: the only real body was the *borrowed* Strix runtime. This program fits a
**homegrown brain** into that slot, driven by hexstrike-ai's deterministic decision model — **behind all
of VIGIL's invariants**, never as an ungated offense path.

Every step was designed against a gate-marshal red-pen (verdict **BUILD-WITH-FIXES**; its fixes are folded
in below and are non-negotiable).

## The non-negotiable invariants (why this is safe)
1. **Oracle authority** — the brain only PROPOSES (LEADs); a finding becomes a FACT only when a
   deterministic VIGIL oracle fires. The brain computes zero facts.
2. **Gate-before-execute** — every proposal crosses the conjunctive gate (`vigil_core/gate.py`) + egress
   gate + charter scope; `run_cycle` reaches `execute` only when `decision.authorized` is True.
3. **FATAL-2** — the brain is stdlib-only, keyless-offense-loadable; framework imports are function-local;
   the offense worker never holds the owner key.
4. **No offense drift** — no evasion/stealth/IP-rotation/WAF-tamper/credential-poisoning/live-exploit.
   Correlatable, authorized owner-testing only.

## Status
- **Slice 1 — DONE** (`vendor/hexstrike-ai/` + `integration/vigil_integration/brains/`): hexstrike-ai
  vendored **non-runnable** (MIT, attribution verbatim, pinned `d689933`); a clean-room, drift-free,
  propose-only `HexstrikeBrain` reimplementing its decision model. 7/7 tests.

## Steps (each: build → red-pen → CI → merge)

1. **Vendor non-runnably (DONE).** `.reference` blobs (never importable/executable), `.git`/assets
   stripped, `UPSTREAM.md` + this attribution. *Red-pen HIGH-1 fix: the runnable Flask server must never
   be on an import/exec path.* CI guard: `grep -r 'import hexstrike'` over VIGIL source = 0; `vendor/`
   never on PYTHONPATH.
2. **Clean drift-free brain (DONE).** Reimplement the decision model, curated to recon/assessment; a
   runtime `DriftError` guard rejects any evasion knob. *Red-pen HIGH-2 fix: reimplement, don't
   copy-then-strip; drop responder/exploit/stealth by construction.*
3. **`HexstrikeAgentBody(AgentBody)` (NEXT).** `think` builds a `TargetProfile` from VIGIL sensor/oracle
   observations (not URL guesses); `propose` = `brain.create_attack_chain` steps as `ProposedAction`s;
   `gate` delegates to `build_offense_gate` (QUEUE ⇒ authorized=False); `execute` runs ONLY via
   `run_external_tool`; `learn` re-ranks/defers only. Inherits `run_cycle`'s gate guard. Tests: a DENY/
   QUEUE never reaches execute; `learn` calls no oracle/promotion/scope API.
4. **Runner-owned provenance (red-pen HIGH-3).** A `ToolSpec` / the body must be **structurally unable**
   to supply `provenance` or a pre-built `oracle_context`; `run_external_tool` owns an independent
   re-drive + context builder per bug_class. Any class without a runner-owned re-drive stays a **LEAD**.
   Test: a ToolSpec cannot reach `confirm_and_certify` with a tool-sourced context marked
   `reproduced`/`live_redrive`.
5. **WARDEN tiering (red-pen MEDIUM).** Keep the **A2 floor** on any live target (nothing auto-fires);
   recon-auto only in STAGING/TWIN; asset-enum tools that call third-party APIs (crt.sh/VT) run ONLY
   through the egress-gated Docker topology, never `LocalSubprocessBackend`. Unknown/denylisted names ⇒
   DENY.
6. **Converge one gated executor (red-pen MEDIUM).** Wire the body's proposals into the proven live loop
   with a single gated executor+oracle (`seams.run_tool = run_external_tool` or prove parity), and route
   think tokens through `kernel/llm.py get_backend()` (closing the `think_claude` BYO-bypass) together
   with the Anthropic price-table fix so the budget governor arms.
7. **CI + honest docs.** Offline unit tests + skip-marked live-fire (angr/selenium/mitmproxy/fastmcp do
   not install here — a marked residual, never a faked capability). Mark the brain BUILT(propose-only)
   and live-fire a tooling residual.

## The other documented gaps (prioritized roadmap)
From the system's own honesty ledger (V2-LIMITATIONS / DEFERRED-INFRA / TRUTHENOVATION):

| Priority | Gap | Approach |
|---|---|---|
| HIGH | R4 LLM-red-team tools (garak/PyRIT/promptfoo) unexercised | add a `ToolSpec` + bug-class→oracle per tool through `run_external_tool`; provision the image behind the pinned `vigil_sandbox` net (needs network) |
| HIGH | Recall/discovery on real targets UNMEASURED (soundness proven, completeness not) | extend `eval/recall_baseline.py` + a recall/FN harness for the LLM-driven planner; the real-target number is bound to H3 (social) |
| HIGH | At-scale autonomous discovery loop not default | promote the goal-tree planner toward default with reviewed depth; feed it the new brain's proposals; gate each pivot behind the oracle |
| HIGH (phased) | Whole surfaces absent as active v2 code (mobile, K8s-runtime, mesh, SSO/SAML, post-ex, exfil) | per surface: ship a deterministic oracle FIRST, then gated active capability |
| MEDIUM | A2 "continuously re-proven" not enabled; A3 witnesses not independently deployed; H2 Neo4j/OTLP not provisioned | operate the shipped systemd timer; deploy N witness instances (independence is social); provision Neo4j + flip the live call site |
| MEDIUM | A1 external time anchor self-signed; Z1 producer-unforgeability a mechanism | wire a third-party RFC3161 / OpenTimestamps; integrate a real zkTLS/MPC-TLS + third-party notary (needs network + a third party) |
| MEDIUM | Standalone verifier never re-fires the oracle (H4/Truth 4) | ship the oracle inside the audit package so Step-1 re-derives verdicts (makes it no-longer-VIGIL-free); "be the third party" is irreducible |
| MEDIUM | General binary auto-patch synthesis stubbed (R3/X2) | symbolic/concolic localiser (angr — installable with network); crash already confirmed OOB; never fabricate a patch |
| MEDIUM | Live-Claude budget-governor bug (no Anthropic price table ⇒ meter=0 ⇒ governor disarms) | add the price table (folded into step 6) |
| IRREDUCIBLE | Hardware TEE confidentiality (H1); genuine field record (H3); VIGIL cannot BE the third-party auditor (H4) | provision SEV-SNP/TDX silicon; accrue a real-engagement record; engage an external audit team |

## Honest residuals (marked, not hidden)
- The upstream server/MCP + heavy deps (angr/pwntools/selenium/mitmproxy/fastmcp) **do not install
  offline**; hexstrike live-fire cannot be validated here — a **tooling residual**, never a present FACT.
- Only tool-output classes with a runner-owned oracle re-drive can mint FACTs; content-discovery / asset-
  enum / CMS-enum / generic misconfig outputs remain **LEADs**.
- `run_external_tool` has no production caller yet and `AgentBody` wires no engine — the live-loop wiring
  (steps 3–6) is unbuilt work, not an existing capability.
