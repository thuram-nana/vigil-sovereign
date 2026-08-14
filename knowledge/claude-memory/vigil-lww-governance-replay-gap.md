---
name: vigil-lww-governance-replay-gap
description: "Pre-existing HIGH — signed LWW governance records have no nonce/epoch, so a revoked grant is replay-resurrectable"
metadata: 
  node_type: memory
  type: project
  originSessionId: 7758e121-f349-47d5-886b-6bb5a1d60e27
  modified: 2026-08-12T15:08:29.242Z
---

Surfaced by the independent red-pen on PR #282 (agent-promotions UI, 2026-08-12). Applies to the whole SIGIL sovereign governance layer, NOT just promotions.

**The gap:** the signed core of LWW governance records carries no nonce/epoch/seq. For promotions, `_CORE = ("signal","state","agent","scope")` in `apps/sigil/sigil/governor/promotion.py`. So a genuine owner-signed `grant`, once `revoke`d, can be **replayed** by any spine writer (exactly the prompt-injected-agent-with-store-access adversary the signing defends against) to flip enforcement back on. Replay is NOT forgery — the signature is genuine, `verify_signed` passes, the hash chain stays valid, and LWW-by-seq picks the replayed grant as the latest write. Confirmed by probe: grant→True, revoke→False, REPLAY(grant)→True (revocation undone). This resurrects the ENFORCED A2 auto-approval (`governor/core.py`), not just the UI display.

**Same shape in every LWW governance fold:** kill-switch release, mesh device authz, capability enable/disable — all fold signed records by (key)→latest-state with no anti-replay token.

**Why PR #282 did NOT fix it:** pre-existing + systemic; the red-pen explicitly said don't block the promotions PR on it. Fixing it is a cross-cutting change to the signed-core schema across promotion/killswitch/capability, so it belongs in its own hardening slice.

**How to apply (the fix when taken):** mirror it in BOTH `is_promoted` AND `state_all` (the mint-gate-must-be-mirrored-at-the-read-surface invariant — the SAME lesson that produced the `state_all` denylist fix in #282). Add a replay negative-control test. Relates to [[vigil-truthenovation-program]] (prove-by-re-execution).

**DESIGN FINDING (2026-08-12, deferred implementation attempt — operator DEFERRED again; do A14+E1-Slice3 first):** *signature-consume/dedup does NOT work.* Ed25519 signing here is DETERMINISTIC (verified: two identical `grant(agent,scope)` → byte-identical `sig`), so a legitimate RE-TOGGLE (re-enable a capability, re-release the kill-switch, re-grant a promotion) is byte-identical to the original and a dedup-by-signature fold wrongly skips it as a replay — a showstopper (capability toggles are common). **The ONLY correct fix is the `issued_at` varying-signed-field approach** — exactly why `governor/offense_gate.py` already uses `_CORE=(...,"issued_at")` + a `max_issued` high-water rejecting any record whose issued_at ≤ the highest seen. Apply that to `killswitch.py` `_CORE=("signal","state")`, `capability.py` `("signal","capability","state")`, `promotion.py` `("signal","state","agent","scope")`. **Backward-compat is the real work:** adding `issued_at` to `_CORE` breaks verification of every EXISTING governance record on a deployed spine (signed without it) → would reset live kill-switch/capability/promotion state. Handle via VERSIONED verify (record WITH issued_at → v2 core; WITHOUT → legacy core, LWW baseline; once a key has a v2 record, ignore later legacy records for it) + for full soundness a deploy-time re-affirm (append a fresh v2 record per active grant/enable/engage). Source issued_at as strictly-increasing (spine-max-for-signal + 1, seeded at wall-clock), NOT bare `time.time()` (same-tick collisions get wrongly rejected). `SnapshotState.load()` returns the empty identity (base_seq=0) universally today (no prune ships) so all folds are genesis scans (snapshot seed dormant); a future hard-prune D/E must carry the per-key high-water forward. **DELICATE + kill-switch-touching → red-pen hard.**
