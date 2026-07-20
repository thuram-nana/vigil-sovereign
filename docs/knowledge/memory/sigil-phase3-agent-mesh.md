---
name: sigil-phase3-agent-mesh
description: "SIGIL Phase 3 — the agent mesh (ARCHIVIST/SENTINEL/STEWARD/ENVOY), morning brief + inbox triage"
metadata: 
  node_type: memory
  type: project
  originSessionId: 7758e121-f349-47d5-886b-6bb5a1d60e27
---

**SIGIL Phase 3 (AGENT MESH v1) — BUILT** at **`/home/kali/sigil/sigil/agents/`** (Python). Continues [[sigil-phase2-voice]]. SIGIL §4. Acceptance ("unprompted morning brief worth reading + inbox triage") **MET on the real 43k spine**.

**Framework (`base.py`):** each `Agent` has a MANDATE + AUTONOMY CEILING (`Tier` IntEnum A0-A3, mirrors WARDEN §5). Everything is a `Proposal(kind,payload,tier)`; `_dispatch` gate = a proposal AUTO-APPLIES (written to spine, source=`agent`) only if `tier<=ceiling AND tier<=AUTO_BAR(A1)`, else it's QUEUED (`decision:queued, status:awaiting-approval`) for human approval — never auto-executed. **Doctrine is STRUCTURAL, not disciplinary.**

**Agents:** `ARCHIVIST`(§4.2, A1) wraps the Phase-0 consolidation + emits a `finding`. `SENTINEL`(§4.3, A1) = pluggable watchers (`SpineActivityWatcher` commit-burst/contradiction, `SystemHealthWatcher` disk) → SALIENCE floor + ALERT BUDGET (top-N by salience) → `event` records. `STEWARD`(§4.7, A2) = **the morning BRIEF** (`compose_brief`): due commitments + open threads + flagged contradictions + SENTINEL alerts + recent-activity, all from GROUNDED consolidation queries, cited by seq. `ENVOY`(§4.6, A2 HARD) = inbox triage (`triage`: urgent/normal/fyi/spam keyword classifier) + `draft_reply` → **DRAFTS ONLY**: interaction notes A1-auto, replies A2-QUEUED; **NO send()/transmit() method exists — outbound is human-only forever**. Pluggable `FileInbox` (JSON; IMAP optional). `runner.py`: `morning`(SENTINEL→STEWARD), `triage`(ENVOY), `run_all`(ARCHIVIST→SENTINEL→STEWARD→ENVOY). CLI: `sigil agents brief|triage|sentinel|run`.

**Tested/proven: 5/5 (`tests/test_agents.py`)** — ceiling gate (A1 auto / A2-A3 queued), ENVOY drafts-only + no-send-path + triage, STEWARD grounded+sectioned brief, SENTINEL salience-floor+budget, agent-record provenance. **Real demo:** `sigil agents brief` → cited morning brief (0 due, 8 open threads, activity summary); `sigil agents triage` → 4 msgs, investor(urgent)+review(normal) drafted A2-queued, github(fyi)+crypto(spam) skipped. New spine KINDS: event/finding/interaction/draft.

**HONEST NOTES:** the brief's "open threads" surface the NOISY Haiku-extracted decisions from the Phase-0 consolidation (status-updates mislabeled as decisions) — a data-quality issue in [[sigil-phase0-memory-loop]] extraction (fix = Sonnet/Opus or tighter prompt), NOT an agent bug. Live sources (IMAP IDLE, CalDAV) are pluggable stubs, not built. Agent actions write to the spine but are NOT yet logged to the Rust WARDEN signed action-log (unifying the two audit trails = integration TODO).

**REVIEW (1 round, 8 findings; ALL FIXED). 6/6 tests.** Confirmed NO doctrine break — no ENVOY send path, no A2/A3 auto-run (the security-critical property holds). Findings were robustness + TEST-HONESTY: (HIGH) tests checked the in-memory `res.queued` but never the DURABLE spine record's `status:awaiting-approval/decision:queued` → now read the draft record back; (MED) `test_ceiling_gate` A3 queued via the AUTO_BAR not the ceiling → added an A0-ceiling agent + A1 proposal that queues for a CEILING reason (isolates the two gates); SENTINEL under-counted suppressed (below-floor drops uncounted) → honest `len(candidates)-len(kept)`; SENTINEL crashed on a watcher dict missing summary/kind, `FileInbox` crashed on malformed JSON → both now defensive; brief test lacked an ungrounded negative control + which-survived assertion → added. **LESSON: a passing test suite proved the in-memory API but not the DURABLE doctrine contract; the review's value here was test-honesty, not new code bugs.**

**NEXT:** Phase 4 (ARTIFICER background Claude-Code coding + SCHOLAR research, reuse veracity/reverify); Phase 5 (perception + BASTION defensive own-infra); wire agent actions through WARDEN's signed log; live IMAP/CalDAV. Roadmap SIGIL.md §11.
