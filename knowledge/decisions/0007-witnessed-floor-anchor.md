# ADR 0007 — Witnessed-checkpoint anti-rollback floor anchor (closing the same-host head+floor co-rewrite)

- **Status:** Accepted
- **Scope:** VIGIL (`/home/kali/vigil`, repo `thuram-nana/vigil-sovereign`) — Claim 6 "state-root residuals", slice C-S4
- **Affects:** new `integration/vigil_integration/witnessed_anchor.py` (shared, plane-neutral),
  new `apps/sigil/sigil/spine/floor_witness.py` (sovereign), new `integration/vigil_integration/floor_witness.py`
  (offense), the `sigil floor witness|verify-witnessed` and `vigil floor witness|verify-witnessed` CLI verbs,
  and the two `test_floor_witness.py` suites. Builds on C-S1 (ADR 0006) and C-S2/C-S3 (signed floors).

## Context — the residual C-S2/C-S3 explicitly deferred

The anti-rollback floor is now SIGNED on both planes (sovereign `spine/floor.py`, offense
`vigil_core/highwater.py`). Signing closes two cases for a verifier holding the trust anchor: tampering with
a *signed* floor's content (breaks the signature) and — for an out-of-band verifier that retained a signed
floor — a strip-to-unsigned downgrade. It does **not** close the case both floor docstrings call out as
their HONEST LIMIT:

> a SAME-HOST attacker with the owner/root UID rewrites `head.json` AND `floor.json` together (or strips the
> signed floor back to unsigned), and a purely **LOCAL** verify re-reads BOTH from that same
> attacker-controlled disk — so it cannot catch the rollback.

The rollback replays a *genuinely-old, validly-signed* head + its matching floor. Both verify in-band; the
local verifier has no newer reference to know the spine was ever higher. This is undetectable to a local
verifier by construction — and was explicitly deferred to this slice.

## Decision — witness the floor's head off-box, and require the local head+floor to be at/above it

A `transparency.Checkpoint` already commits `last_seq`/`entry_count`/`head_hash` and (post-C-S1) the prune
boundary `base_seq`/`base_count`. A witness-cosigned checkpoint of the head, **retained off-box**, is
therefore an out-of-band commitment to the floor's height (the floor's monotonic fields are a copy of the
head's). So:

1. **Emit-on-advance.** When the floor advances to a just-committed head, also emit a `Checkpoint`, get it
   witness-cosigned, and PERSIST it to a stable path the verifier retains **off-box** (`emit_witnessed` →
   `sigil floor witness --retain`, `vigil floor witness --retain`). The emit first asserts floor⇔head
   coherence so a mismatched pair is never witnessed.
2. **Anchor-on-verify.** `verify_floor_against_witnessed` / `verify_highwater_against_witnessed` REQUIRE the
   local head AND the local floor to be consistent with the **highest** retained witnessed checkpoint.

How the anchor catches a head+floor co-rewrite (the cited check): `anchor_head` builds the current checkpoint
LINKED to the retained one and reuses `transparency.consistent`, which inherits (a) the C-S1 prune-boundary
monotonic guards (`base_seq`/`base_count` may not shrink) and (b) the `is_split` rule (same `entry_count`,
different `head_hash` ⇒ fork). A rolled-back head (lower `entry_count`/`last_seq`) or a same-height fork
fails it. The floor-side check (`_anchor_floor` / `_anchor_highwater`) additionally refuses a floor whose own
`entry_count`/`last_seq`/`base_*` sit below the retained height, or a floor stripped/removed while a
checkpoint above genesis was retained. The anchor is a copy the attacker never touched (it lives off-box),
so it is **not** re-read from the rolled-back disk — which is exactly why it closes the case the local floor
cannot.

**Two-plane discipline (FATAL-2).** The anchor logic is single-sourced in `witnessed_anchor.py`
(`vigil_core` + `transparency` only). The offense floor witness signs with the offense **GOVERNANCE** key
(owner-tied via the `OFFENSE_GOVERNANCE_ROLE` delegation), never an owner key, and imports no `sigil`/
`apps.sigil`/`framework`. The witnessed checkpoint is INERT JSON bytes a public-key-only verifier reads
out-of-band — never a cross-plane in-process co-load.

## The irreducible limit — do NOT overclaim (risk #13)

At the default owner-only / governance-only witness set (`threshold == 1`), this is retention-based
**DETECTION**, not prevention. The producer signs its OWN anchor: a self-witness is not independence, even
though `2*1 > 1` is arithmetic strict-majority. What each layer closes, precisely:

- the **signature** closes the strip-of-a-signed-floor tamper and the downgrade for a verifier holding the
  key;
- the retained **witnessed checkpoint** closes the same-host head+floor **co-rewrite / rollback** for a
  verifier that retained an off-box copy;
- **neither** closes the *fully-dishonest-producer-owns-all-keys* case. A producer that also controls the
  witness quorum can mint a consistent low anchor. Only **INDEPENDENT** witnesses — a strict majority of
  distinctly-keyed witnesses held by independent parties — upgrade this to (conditional) split-view
  PREVENTION, and that independence is a **deployment property code cannot verify**.

Therefore `guarantee_label` (shared by both planes) returns `"rollback DETECTION only …"` for a solo set and
NEVER prints `"independent"` / `"split-view-resistant"` / `"split-view prevention"` for it — it says so only
for a ≥2-key strict-majority set, and even then only "prevention **IF** the witness keys are held by
independent parties (independence is not checkable here)". The acceptance suites assert both the solo→
DETECTION label and the strict-majority→conditional-prevention label so a future edit cannot silently sell
a self-witness as independence.

## Non-goals / fidelity

- The anchor does **not** replace the local floor and does not change the local verify happy path: with no
  retained checkpoint supplied, the verify functions return the local-only guarantee unchanged (no false
  refusal). The floor check itself is byte-identical to pre-C-S4.
- The light floor anchor checks head+floor *height* (it needs only the head summary). The sovereign
  `witness.verify_against_external` remains the complementary heavy check that additionally proves
  byte-identity of the retained prefix via the hash-chained live entries; both anchor to the same retained
  checkpoint.
