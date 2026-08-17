"""floor_witness — wire the SOVEREIGN anti-rollback floor to the retained witnessed-checkpoint anchor (C-S4).

``floor.py`` documents its HONEST LIMIT: a same-host attacker with the owner UID rewrites ``head.json`` AND
``floor.json`` together (or strips the SIGNED floor back to unsigned), and a purely LOCAL verify re-reads
both from that same attacker-controlled disk — so it cannot catch the rollback. The named successor is an
OUT-OF-BAND, retained witnessed checkpoint (``witness.py`` provides the head-side machinery). This module
adds the FLOOR-side of that anchor:

  * :func:`emit_floor_witness` — emit-on-advance: after the floor advances to a just-committed head, witness
    that head (which the floor now tracks EXACTLY) and PERSIST the witnessed checkpoint off-box. Because the
    floor's monotonic quantities are a copy of the head's, a witnessed checkpoint of the head IS a witnessed
    commitment of the floor's height; the emit first asserts floor⇔head coherence so a mismatched pair is
    never witnessed.
  * :func:`verify_floor_against_witnessed` — anchor-on-verify: REQUIRE the local head AND the local floor to
    be consistent with the HIGHEST retained witnessed checkpoint. A local head/floor rolled back below the
    retained height (a co-rewrite), forked at it, or a floor stripped/removed below it, is REFUSED. This is
    the check the LOCAL floor cannot make on its own, because the anchor is a copy the attacker never touched.

Boundary-safe: reuses the plane-neutral ``vigil_integration.witnessed_anchor`` (``vigil_core`` +
``transparency`` only) — the same pattern as ``witness.py`` reusing ``transparency``.

HONEST LIMIT (do NOT overclaim — mirrors ``floor.py`` §1.3, ``witness.guarantee_label``): the anchor is
retention-based DETECTION at the default owner-only (threshold==1) witness set — the owner signs its OWN
anchor, which is NOT independence. It closes the same-host head+floor co-rewrite / strip-to-unsigned case
FOR A VERIFIER THAT RETAINED AN OFF-BOX COPY, and nothing more. Split-view PREVENTION needs a strict
majority of INDEPENDENT witness keys held by independent parties (a deployment property code cannot verify);
a fully-dishonest producer that ALSO controls the witness quorum is NOT closed. The label
(:func:`witnessed_anchor.guarantee_label`) NEVER prints 'independent'/'split-view-resistant' for a solo set.
"""
from __future__ import annotations

from typing import Iterable, Optional

from vigil_integration import witnessed_anchor as WA
from vigil_integration.transparency import Witness

from .floor import Floor


class FloorWitnessError(Exception):
    """A floor⇔head incoherence at emit time, or an un-usable anchor at verify time. Fail-closed."""


def _assert_floor_matches_head(floor: Optional[Floor], head) -> None:
    """A witnessed checkpoint of ``head`` only commits the FLOOR's height if the floor actually tracks that
    head. ``advance_floor`` sets the floor's monotonic fields FROM the head, so at emit time (right after an
    advance) they must be equal; a mismatch means we were asked to witness a head the floor does not track —
    refuse, rather than persist an anchor that misrepresents the floor."""
    if floor is None:
        raise FloorWitnessError("cannot witness the floor: no durable floor is present (advance it first)")
    for field in ("entry_count", "last_seq", "base_seq", "base_count"):
        fv, hv = getattr(floor, field), int(getattr(head, field, 0))
        if int(fv) != hv:
            raise FloorWitnessError(
                f"refusing to witness an incoherent floor⇔head pair: floor.{field}={fv} != head.{field}={hv} "
                f"(advance the floor to this head before witnessing it)")


def emit_floor_witness(head, floor: Optional[Floor], witnesses: "list[Witness]", *,
                       retain_path, scope: str):
    """Emit + persist a witnessed checkpoint of the just-advanced floor's head, off-box at ``retain_path``.
    Asserts floor⇔head coherence first (see :func:`_assert_floor_matches_head`). Returns the
    :class:`WitnessedCheckpoint`. ``retain_path`` is a path the verifier RETAINS OFF-BOX — a copy kept only
    inside ``SIGIL_HOME`` is rolled back with the spine and adds nothing over the local floor."""
    _assert_floor_matches_head(floor, head)
    return WA.emit_witnessed(head, witnesses, retain_path=retain_path, scope=scope)


def _anchor_floor(floor: Optional[Floor], retained) -> tuple[bool, str]:
    """The FLOOR-side of the anchor: the local floor may not have rolled back below the retained witnessed
    checkpoint. Catches a co-rewritten floor (dropped alongside the head) AND a floor stripped/removed below
    a height we witnessed. A stripped-to-UNSIGNED floor still present at/above the retained height is caught
    separately by ``check_floor``/``verify_floor_signature`` on the local path; here we catch the ROLLBACK of
    the floor's committed height, which the signature check alone cannot (a genuinely-old signed floor is a
    valid signature)."""
    rc = retained
    if floor is None:
        if rc.entry_count > 0:
            return False, (f"FLOOR STRIPPED: no local floor is present, but a witnessed checkpoint at "
                           f"entry_count {rc.entry_count} was retained — the floor was rolled back/removed "
                           f"below a height it was witnessed at")
        return True, "no local floor and nothing witnessed above genesis"
    if int(floor.entry_count) < rc.entry_count:
        return False, (f"FLOOR ROLLBACK: local floor entry_count {floor.entry_count} < retained witnessed "
                       f"entry_count {rc.entry_count} (the floor was co-rewritten below a witnessed height)")
    if int(floor.last_seq) < rc.last_seq:
        return False, (f"FLOOR ROLLBACK: local floor last_seq {floor.last_seq} < retained witnessed last_seq "
                       f"{rc.last_seq} (the floor was co-rewritten below a witnessed height)")
    if int(floor.base_seq) < rc.base_seq:
        return False, (f"FLOOR UN-PRUNE: local floor base_seq {floor.base_seq} < retained witnessed base_seq "
                       f"{rc.base_seq} (older-snapshot replay of the floor)")
    if int(floor.base_count) < rc.base_count:
        return False, (f"FLOOR UN-PRUNE: local floor base_count {floor.base_count} < retained witnessed "
                       f"base_count {rc.base_count} (older-snapshot replay of the floor)")
    return True, "local floor is at/above the retained witnessed checkpoint"


def verify_floor_against_witnessed(head, floor: Optional[Floor], sources: Iterable[str], *,
                                   scope: str, trust_root) -> tuple[bool, str, str]:
    """Anchor the LOCAL head + floor against the HIGHEST retained witnessed checkpoint. Returns
    ``(ok, message, guarantee_label)``. Fail-closed:

      * a supplied anchor that is malformed / wrong-scope / not signed by a trusted witness quorum → REFUSE
        (``select_highest_witnessed`` raises; a bad anchor never falls through to a pass);
      * the local HEAD rolled back below / forked at the retained height → REFUSE (``anchor_head`` reuses
        ``transparency.consistent`` + ``is_split`` — the C-S1 boundary fields and the same-height fork rule);
      * the local FLOOR rolled back / stripped below the retained height → REFUSE (:func:`_anchor_floor`).

    An EMPTY ``sources`` (the verifier retained nothing) returns ``(True, "…anchor skipped…", label)`` — no
    off-box copy means exactly today's local-only guarantee, neither widened nor narrowed."""
    label = WA.guarantee_label(trust_root)
    try:
        retained = WA.select_highest_witnessed(sources, scope=scope, trust_root=trust_root)
    except WA.AnchorError as e:
        return False, f"CANNOT VERIFY (refused): {e}", label
    if retained is None:
        return True, "no retained witnessed checkpoint supplied — off-box anchor skipped (local-only)", label
    ck = retained.checkpoint
    ok_h, why_h = WA.anchor_head(head, retained=ck)
    if not ok_h:
        return False, why_h, label
    ok_f, why_f = _anchor_floor(floor, ck)
    if not ok_f:
        return False, why_f, label
    return True, (f"local head+floor anchored to the retained witnessed checkpoint (count {ck.entry_count}, "
                  f"last_seq {ck.last_seq}): no rollback below it, no fork at its height. {label}"), label
