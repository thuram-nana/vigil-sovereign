---
name: vigil-posture-and-brain-slot
description: VIGIL Proof-of-Posture (Certificate of Non-Exploitability) + Authority-Envelope twin + the homegrown brain slot (hexstrike-ai) — all MERGED to main
metadata: 
  node_type: memory
  type: project
  originSessionId: 7758e121-f349-47d5-886b-6bb5a1d60e27
  modified: 2026-08-08T12:06:54.772Z
---

VIGIL (repo thuram-nana/vigil-sovereign, @ /home/kali/vigil). Three flagship capabilities built +
tested + live-proven + **MERGED to main via PR #240** (all 7 CI jobs green; the new suites run in the
framework-inclusive integration leg). The world-first thesis came from an end-to-end field-research
workflow: **no system produces a sound, portable, third-party-offline-re-verifiable proof of the
NEGATIVE** ("this attack class is provably CLOSED, here's the coverage denominator, verify it yourself").

**1. Proof of Posture — the Certificate of Non-Exploitability (P0–P6).** `integration/vigil_integration/
posture/`: `certificate.py` projects the M2 coverage oracle into CLOSED (clean+conclusive) / OPEN
(finding) / UNPROVEN (inconclusive/not-reached) per (surface,param,class), bound to an owner-signed
`IdentityAttestation` (closes target-swap), with the coverage denominator + honest residual IN the signed
bytes; freshness (A1 time anchor) + witnesses are bundle sidecars (cert stays byte-deterministic).
`bundle.py` (portable dir + shipped `verify_offline.py`), `series.py` (anti-rollback attestation series on
vigil_core chain), `reprove.py` (continuous re-proof loop, injectable clock), `endpoint.py` (read-only,
`bind_ok`-gated queryable endpoint), `cli.py` (`python -m vigil_integration.posture attest|verify|
endpoint`). The standalone VIGIL-free verifier is `docs/proof-carrying-finding/verify_vf.py` — a new
`posture` bundle component (+ byte-parity differential): re-checks m-of-n sig + OOB authorizer-fingerprint
pin + the coverage-projection binding (a forged/false-CLOSED is refused) + owner target-binding, OFFLINE
with no VIGIL. Verification TIERS honestly marked: **binding** (shipped — re-checks the signed verdict;
re-firing needs VIGIL, the H4 residual) vs **re-executable** (marked enhancement — embed raw bytes + a
pinned oracle kernel so the verifier re-derives the negative producer-independently). Live-proven:
`test_posture_live.py` mints a real cert over the benchmark app and re-verifies SOUND in a clean env with
NO VIGIL on the path; tamper → NOT SOUND. systemd `vigil-posture.{service,timer}`. Docs: `docs/POSTURE.md`
+ TRUTHENOVATION Phase P.

**2. Authority-Envelope twin ("prove the AI stayed in bounds").** `posture/authority.py`: an owner-signed
envelope (engagement + scope hosts + action allowlist + window) + the run's action ledger + a re-derivable
CONFORMANCE proof (every EXECUTED action inside the envelope). Standalone `verify_vf.py` `authority`
component (+ differential): a forged "conformant" verdict or an out-of-envelope executed action is refused.
Residual: proves conformance over the append-only RECORDED ledger — tamper-evident, not omniscient capture.

**3. The "better brain" slot — hexstrike-ai (design credit Muhammad Osama/0x4m4, MIT).** The empty
`engine/crucible/framework/v2/agent_body/interface.py::AgentBody` socket (think→propose→gate→execute→learn;
run_cycle structurally enforces gate-before-execute) is FILLED. hexstrike-ai cloned + vendored
**NON-RUNNABLE** under `vendor/hexstrike-ai/` (`.reference` blobs — the upstream Flask server is a full
ungated offense framework; a quarantine tripwire `test_vendor_hexstrike_quarantine.py` proves nothing
imports it). Its brain is 100% deterministic heuristics (NO LLM; "AI-powered" is marketing) — reimplemented
CLEAN-ROOM + drift-free in `integration/vigil_integration/brains/hexstrike_brain.py` (propose-only; no
evasion/stealth/responder-poisoning/exploit-chains/DNS; a runtime `DriftError` guard). `hexstrike_body.py`
`HexstrikeAgentBody` is fully wired: real WARDEN **A2-floor** gate (nothing autos on a live target; recon
autos only in staging/twin; active always queues) + real R4 gated execution (`run_external_tool` owns the
per-class re-drive + provenance — the body supplies NONE, red-pen HIGH-3) + a **live nmap FACT** proof.
`engine_think.py::BrainThink` drives the PRODUCTION engine (`EngineConfig.brain`, wired in
`live/wiring.py` think_seam) — one gated executor, oracle-authoritative; operator-invokable via
`vigil engage --brain hexstrike <target>`. Frontends (Proof-of-Posture + Brain screens) built by a
specialized UI agent + merged (system-map parity green, 26 screens). Gate-marshal red-pen verdict
BUILD-WITH-FIXES — all applied (HIGH-1 non-runnable vendor + tripwire; HIGH-2 reimplement-clean not
copy-then-strip; HIGH-3 runner-owned provenance; MEDIUM A2-floor + one-gated-executor). Docs:
`docs/BRAIN-SLOT-INTEGRATION.md`.

**KEY LESSONS.** (a) A field-research workflow (parallel domain surveys → proposers → adversarial judge)
found the world-first gap (the sound negative) — unanimous across offense/CTEM/formal/crypto/GRC. (b) The
gate-marshal red-pen caught real offense-drift before build: an external offensive framework must be
vendored NON-RUNNABLE, its brain REIMPLEMENTED clean (not copy-then-strip — the stealth/exploit is in the
tables), and a ToolSpec must be STRUCTURALLY unable to supply provenance. (c) NEW framework-dependent tests
MUST be added to BOTH the ci.yml framework-inclusive integration leg (include) AND the sovereign leg
(--ignore) or CI passes without running them. (d) Network is intermittently down; `git push`/`gh` work with
`dangerouslyDisableSandbox`; `git clone` of a 5MB repo works in the background with a long timeout.
**Remaining (honest residuals, not partial code):** hexstrike heavy tools don't install offline (live-fire
tooling-gated); tools beyond nmap mint FACTs only as each gets an oracle-mapped ToolSpec + a runner-owned
per-class re-drive; the re-executable posture tier; the budget Anthropic-price-table gap (Claude think
path, not the LLM-free brain). Builds on [[vigil-truthenovation-program]]. Repo policy: NO
`Co-Authored-By: Claude` ([[vigil-authorship-contributors]]).
