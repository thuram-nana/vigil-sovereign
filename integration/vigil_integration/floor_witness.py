"""floor_witness (OFFENSE) — wire the offense anti-rollback HIGH-WATER floor to the retained
witnessed-checkpoint anchor (Claim 6, C-S4 offense parity).

``vigil_core.highwater`` is the offense twin of the sovereign ``floor.py``. C-S2/C-S3 brought it to
signing parity (the floor is GOVERNANCE-signed), but its docstring keeps the same HONEST residual: a
same-host attacker who rewrites the log/head AND the high-water floor together (or strips the signed
floor back to unsigned) defeats the LOCAL verify, which re-reads both from that same disk. This module
closes it OUT-OF-BAND, exactly as the sovereign ``sigil.spine.floor_witness`` does, by re-using the
plane-neutral :mod:`vigil_integration.witnessed_anchor`:

  * :func:`emit_highwater_witness` — emit-on-advance: after the high-water floor advances to a
    just-committed head, witness that head (which the floor now tracks) and PERSIST the witnessed
    checkpoint off-box.
  * :func:`verify_highwater_against_witnessed` — anchor-on-verify: REQUIRE the local head AND the local
    high-water floor to be consistent with the HIGHEST retained witnessed checkpoint. A co-rewrite (both
    rolled back below the retained height), a fork at that height, or a floor stripped/removed below it is
    REFUSED.

FATAL-2 boundary (LOAD-BEARING): the offense witness signs with the offense GOVERNANCE key
(``live.governance_identity``), NEVER an owner key — the offense side holds no owner key by construction.
This module imports ``vigil_core`` + ``vigil_integration.witnessed_anchor``/``.transparency`` ONLY; it does
NOT import ``apps.sigil``/``sigil`` (the sovereign path stays sovereign-side). The witnessed checkpoint is
persisted as INERT bytes a public-key-only verifier reads out-of-band — never a cross-plane in-process
co-load. The governance key's OWNER tie is the existing ``OFFENSE_GOVERNANCE_ROLE`` delegation, not the
owner key directly.

HONEST LIMIT (do NOT overclaim — mirrors ``vigil_core.highwater`` §, ``witnessed_anchor.guarantee_label``,
the ``reprove`` self-witness label): at the default governance-only (threshold==1) witness set this is
retention-based DETECTION — the offense producer signs its OWN anchor, which is NOT independence. Only
INDEPENDENT witnesses held by independent parties upgrade it to (conditional) split-view PREVENTION (a
deployment property); a fully-dishonest producer that ALSO controls the witness quorum is NOT closed.
:func:`offense_guarantee_label` NEVER prints 'independent'/'split-view-resistant' for a solo self-witness.
"""
from __future__ import annotations

from typing import Iterable, Optional

from vigil_core import AuthorizerKey, TrustRoot

from . import witnessed_anchor as WA
from .transparency import Witness

# The stable key_id the offense GOVERNANCE self-witness co-signs under (and the trust-root authorizer id the
# anchor verifies against). Its pubkey is owner-tied out-of-band via the OFFENSE_GOVERNANCE_ROLE delegation.
OFFENSE_WITNESS_KEY_ID = "offense-governance"


class OffenseFloorWitnessError(Exception):
    """A high-water⇔head incoherence at emit time, or an un-usable anchor at verify time. Fail-closed."""


def offense_witness_trust_root(governance_pub_b64: str) -> TrustRoot:
    """The (default, solo) trust root the offense witnessed checkpoint verifies against: the offense
    GOVERNANCE key alone at threshold 1. Adding INDEPENDENT witness keys to reach a strict majority is what
    upgrades DETECTION to (conditional) prevention — see :func:`offense_guarantee_label`."""
    return TrustRoot(threshold=1, authorizers=[AuthorizerKey(
        key_id=OFFENSE_WITNESS_KEY_ID, name="offense governance self-witness",
        public_key_b64=governance_pub_b64)])


def offense_governance_witness(governance_kp) -> Witness:
    """A :class:`transparency.Witness` that co-signs with the offense GOVERNANCE key (``governance_kp`` is a
    ``vigil_core.crypto.KeyPair``). FATAL-2: this is the ONLY key the offense side signs the anchor with —
    never an owner key."""
    return Witness(OFFENSE_WITNESS_KEY_ID, governance_kp.private_key_b64)


def _assert_highwater_matches_head(hw: Optional[dict], head) -> None:
    """A witnessed checkpoint of ``head`` only commits the FLOOR's height if the floor tracks that head.
    ``advance_highwater`` sets the floor's monotonic fields FROM the head, so at emit time they must be
    equal; a mismatch means we were asked to witness a head the floor does not track — refuse."""
    if hw is None:
        raise OffenseFloorWitnessError(
            "cannot witness the high-water floor: none is present (advance it first)")
    for field in ("entry_count", "last_seq"):
        hv = int(hw.get(field)) if hw.get(field) is not None else None
        cv = int(getattr(head, field, 0))
        if hv != cv:
            raise OffenseFloorWitnessError(
                f"refusing to witness an incoherent high-water⇔head pair: highwater.{field}={hv} != "
                f"head.{field}={cv} (advance the floor to this head before witnessing it)")


def emit_highwater_witness(head, hw: Optional[dict], witnesses: "list[Witness]", *,
                           retain_path, scope: str, now=None):
    """Emit + persist a witnessed checkpoint of the just-advanced high-water floor's head, off-box at
    ``retain_path``. Asserts high-water⇔head coherence first. ``witnesses`` are GOVERNANCE-keyed
    :class:`transparency.Witness` objects (build via :func:`offense_governance_witness`). Returns the
    :class:`WitnessedCheckpoint`. ``retain_path`` is a path the verifier RETAINS OFF-BOX — a copy kept only
    under ``--base-dir`` is rolled back with the spine and adds nothing over the local floor.

    W7-5 (#463): ``now`` (unix seconds) stamps the anchor's emission timestamp so a verifier can REFUSE a
    STALE anchor. A SCHEDULED emitter passes ``now`` (the CLI/timer path does); a caller that passes none
    keeps the legacy un-timestamped envelope (a freshness gate then treats it as un-dated → fail-closed)."""
    _assert_highwater_matches_head(hw, head)
    return WA.emit_witnessed(head, witnesses, retain_path=retain_path, scope=scope, now=now)


def _anchor_highwater(hw: Optional[dict], retained) -> tuple[bool, str]:
    """The FLOOR-side of the anchor: the local high-water floor may not have rolled back below the retained
    witnessed checkpoint. Catches a co-rewritten floor (dropped with the head) AND a floor stripped/removed
    below a witnessed height. The high-water floor commits only entry_count/last_seq (the head carries the
    prune boundary, checked by :func:`witnessed_anchor.anchor_head`)."""
    rc = retained
    if hw is None:
        if rc.entry_count > 0:
            return False, (f"FLOOR STRIPPED: no local high-water floor is present, but a witnessed checkpoint "
                           f"at entry_count {rc.entry_count} was retained — the floor was rolled back/removed "
                           f"below a height it was witnessed at")
        return True, "no local high-water floor and nothing witnessed above genesis"
    ec = int(hw.get("entry_count")) if hw.get("entry_count") is not None else -1
    ls = int(hw.get("last_seq")) if hw.get("last_seq") is not None else -1
    if ec < rc.entry_count:
        return False, (f"FLOOR ROLLBACK: local high-water entry_count {ec} < retained witnessed entry_count "
                       f"{rc.entry_count} (the floor was co-rewritten below a witnessed height)")
    if ls < rc.last_seq:
        return False, (f"FLOOR ROLLBACK: local high-water last_seq {ls} < retained witnessed last_seq "
                       f"{rc.last_seq} (the floor was co-rewritten below a witnessed height)")
    return True, "local high-water floor is at/above the retained witnessed checkpoint"


def offense_guarantee_label(trust_root: TrustRoot) -> str:
    """The HONEST guarantee label — delegates to :func:`witnessed_anchor.guarantee_label` so both planes
    speak with one voice. A solo governance-only (threshold==1) witness is labelled 'rollback DETECTION
    only', NEVER independent/split-view-resistant (C-S4 risk #13)."""
    return WA.guarantee_label(trust_root)


def verify_highwater_against_witnessed(head, hw: Optional[dict], sources: Iterable[str], *,
                                       scope: str, trust_root: TrustRoot, now=None,
                                       warn_after_s=None, refuse_after_s=None) -> tuple[bool, str, str]:
    """Anchor the LOCAL head + high-water floor against the HIGHEST retained witnessed checkpoint. Returns
    ``(ok, message, guarantee_label)``. Fail-closed, mirroring the sovereign
    :func:`sigil.spine.floor_witness.verify_floor_against_witnessed`:

      * a supplied anchor that is malformed / wrong-scope / not signed by a trusted GOVERNANCE quorum →
        REFUSE (``select_highest_witnessed`` raises);
      * W7-5 (#463): when ``now`` is given, the SELECTED (highest) anchor is checked for FRESHNESS — an
        anchor older than the refusal bound (or un-dated, or future-dated past the skew tolerance) → REFUSE.
        The scheduled off-box emitter has stopped and the rollback window is silently widening. ``now=None``
        skips the freshness gate (a library/legacy caller keeps the pre-W7-5 behaviour);
      * the local HEAD rolled back below / forked at the retained height → REFUSE (``anchor_head``);
      * the local FLOOR rolled back / stripped below the retained height → REFUSE (:func:`_anchor_highwater`).

    An EMPTY ``sources`` returns ``(True, "…skipped…", label)`` — nothing retained means today's local-only
    guarantee, unchanged."""
    label = offense_guarantee_label(trust_root)
    try:
        picked = WA.select_highest_witnessed_with_age(sources, scope=scope, trust_root=trust_root)
    except WA.AnchorError as e:
        return False, f"CANNOT VERIFY (refused): {e}", label
    if picked is None:
        return True, "no retained witnessed checkpoint supplied — off-box anchor skipped (local-only)", label
    retained, emitted_at = picked
    ck = retained.checkpoint
    if now is not None:
        fv = WA.freshness_verdict(emitted_at, now=now, warn_after_s=warn_after_s, refuse_after_s=refuse_after_s)
        if fv.refuse:
            return False, f"STALE ANCHOR (refused): {fv.detail}", label
    ok_h, why_h = WA.anchor_head(head, retained=ck)
    if not ok_h:
        return False, why_h, label
    ok_f, why_f = _anchor_highwater(hw, ck)
    if not ok_f:
        return False, why_f, label
    return True, (f"local head+high-water anchored to the retained witnessed checkpoint (count "
                  f"{ck.entry_count}, last_seq {ck.last_seq}): no rollback below it, no fork at its height. "
                  f"{label}"), label
