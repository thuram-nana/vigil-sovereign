"""W17-7 (#541) — the sovereign Tier-B escalation RESOLVE LOOP is wired to a production caller.

Before this change the :class:`ConfirmationRegistry` could only leave an over-cap member escalation PENDING
in its durable ledger: nothing in production ever CALLED its signed-only ``resolve()``, so every over-cap
escalation could ONLY auto-REJECT at its ``deadline_seq``. :mod:`vigil_integration.fireteam.resolver` is the
missing wiring — a signed-approval inbox + a resolve loop a production caller drives.

These tests run against the REAL durable ledger + registry + inbox (no framework, no network — the P5
sovereign leg), and pin the four-part bar:

  (1) OPERATOR DECISION REACHED (fail-without-fix) — a pending escalation + a sovereign-signed approval in
      the inbox → ``resolve_pending`` drives it to APPROVED, durably committed (a FRESH registry over the
      same ledger re-verifies APPROVED). Without the resolver module + the production caller this behaviour
      does not exist (the whole module is the fix).
  (2) NEGATIVE CONTROL — NO decision → the escalation STILL fails closed at the deadline: ``resolve_pending``
      with no envelope and ``now_seq`` past the deadline auto-REJECTS (EXPIRED). The safe default is
      PRESERVED, not replaced.
  (3) NEGATIVE CONTROL — the gate is not a no-op: a FORGED / UNTRUSTED-key / cross-ENGAGEMENT / LATE approval
      never reaches APPROVED (degrades to REJECTED / EXPIRED). If it did, the loop would be laundering a
      forged allow.
  (4) VISIBLE-BEFORE-EXPIRY — within the deadline and with no decision the escalation stays PENDING and is
      surfaced (``pending_escalations`` + a ``fireteam.escalation.pending`` live-feed event with a positive
      ``ticks_remaining``), so the operator can still decide.

Plus a WIRING guard: the live engine's ``deploy_fireteam`` actually CALLS ``resolve_pending`` (the production
caller), and the stale "remaining wiring step" comment is gone (docs-true-of-code).
"""

from __future__ import annotations

import json
import pathlib

from vigil_core import generate_keypair

from vigil_integration.fireteam import (
    ConfirmationOutcome,
    ConfirmationRegistry,
    EscalationLedger,
    EscalationRequest,
    escalation_ledger_path,
    find_signed_approval,
    open_registry,
    pending_escalations,
    resolve_pending,
    sign_escalation_approval,
    signed_inbox_dir,
    write_signed_approval,
)

_SLUG = "eng-541"
_DEADLINE = 600  # CONFIRMATION_DEADLINE_TICKS — an escalation at seq S expires at S + 600


# --- helpers ------------------------------------------------------------------------------------------


def _identity(key_id: str = "owner"):
    kp = generate_keypair()
    return key_id, kp.public_key_b64, kp.private_key_b64


def _esc(seq=1, *, wave="w1", member="m1", tool="sqlmap", tier="A3", target="", reason=""):
    return EscalationRequest(wave_id=wave, member_id=member, seq=seq, tool_name=tool,
                             requested_tier=tier, target=target, reason=reason)


def _register(base, slug, esc, *, trusted=None):
    """Register an escalation durably (its ledger line), the way a wave does."""
    reg = ConfirmationRegistry(ledger=EscalationLedger(str(escalation_ledger_path(base, slug))),
                               trusted_approvers=trusted, engagement=slug)
    key = reg.register(esc)
    return key


class _Feed:
    """Capture (kind, payload) live-feed emissions the resolve loop makes."""

    def __init__(self):
        self.events: list[tuple[str, dict]] = []

    def __call__(self, kind, payload):
        self.events.append((kind, dict(payload)))


# --- (1) OPERATOR DECISION REACHED — the fail-without-fix behaviour ------------------------------------


def test_signed_operator_approval_reaches_approved_via_resolve_loop(tmp_path):
    """A pending over-cap escalation + a sovereign-signed approval in the inbox → the resolve loop drives it
    to APPROVED, durably committed. This is the whole point: an operator DECISION, not an auto-reject."""
    base = str(tmp_path)
    kid, pub, priv = _identity()
    trusted = {kid: pub}
    key = _register(base, _SLUG, _esc(seq=5), trusted=trusted)

    # SOVEREIGN signs the approval (engagement-bound) and drops it in the inbox.
    envelope = sign_escalation_approval(priv, key_id=kid, key=key, engagement=_SLUG)
    path = write_signed_approval(base, _SLUG, key, envelope)
    assert pathlib.Path(path).exists()
    assert find_signed_approval(base, _SLUG, key) is not None

    # OFFENSE drives the resolve loop (within the deadline: now_seq=5 < 5+600).
    reg = open_registry(base, _SLUG, trusted_approvers=trusted)
    assert reg.pending_keys() == [key]
    applied = resolve_pending(reg, base_dir=base, slug=_SLUG, now_seq=5)

    assert len(applied) == 1
    assert applied[0].outcome == ConfirmationOutcome.APPROVED and applied[0].approved is True

    # DURABLE: a FRESH registry over the same ledger re-verifies the APPROVED terminal (not just in-memory).
    fresh = open_registry(base, _SLUG, trusted_approvers=trusted)
    res = fresh.resolution(key)
    assert res is not None and res.approved is True and res.outcome == ConfirmationOutcome.APPROVED
    assert fresh.pending_keys() == []   # no longer pending — decided


# --- (2) NEGATIVE CONTROL — no decision → fail-closed at the deadline (safe default PRESERVED) ---------


def test_no_decision_still_fails_closed_at_deadline(tmp_path):
    """With NO operator decision and now_seq PAST the deadline, the resolve loop auto-REJECTS (EXPIRED). The
    fail-closed timeout behaviour is preserved, not replaced by the new operator-decision path."""
    base = str(tmp_path)
    kid, pub, _priv = _identity()
    trusted = {kid: pub}
    key = _register(base, _SLUG, _esc(seq=3), trusted=trusted)
    assert find_signed_approval(base, _SLUG, key) is None   # no approval was ever signed

    reg = open_registry(base, _SLUG, trusted_approvers=trusted)
    applied = resolve_pending(reg, base_dir=base, slug=_SLUG, now_seq=3 + _DEADLINE + 1)  # past deadline

    assert len(applied) == 1
    assert applied[0].outcome == ConfirmationOutcome.EXPIRED and applied[0].approved is False

    fresh = open_registry(base, _SLUG, trusted_approvers=trusted)
    res = fresh.resolution(key)
    assert res is not None and res.approved is False and res.outcome == ConfirmationOutcome.EXPIRED
    assert fresh.pending_keys() == []


def test_no_decision_within_deadline_stays_pending_and_is_visible(tmp_path):
    """VISIBLE-BEFORE-EXPIRY: within the deadline, with no decision, the escalation stays PENDING, is listed
    by ``pending_escalations``, and is surfaced to the live feed with a POSITIVE ticks_remaining."""
    base = str(tmp_path)
    kid, pub, _priv = _identity()
    trusted = {kid: pub}
    key = _register(base, _SLUG, _esc(seq=10, target="http://h/x", reason="over cap"), trusted=trusted)

    reg = open_registry(base, _SLUG, trusted_approvers=trusted)
    feed = _Feed()
    applied = resolve_pending(reg, base_dir=base, slug=_SLUG, now_seq=10, feed=feed)  # 10 < 10+600

    assert applied == []                          # nothing resolved — still pending
    assert reg.pending_keys() == [key]            # STILL pending (not prematurely rejected)

    rows = pending_escalations(reg, now_seq=10)
    assert len(rows) == 1 and (rows[0]["wave_id"], rows[0]["member_id"], rows[0]["seq"]) == key
    assert rows[0]["ticks_remaining"] == 10 + _DEADLINE - 10 == _DEADLINE   # window still open

    # the live UI feed saw the pending escalation (so the operator can decide before it expires)
    pend = [p for (k, p) in feed.events if k == "fireteam" and p.get("kind") == "fireteam.escalation.pending"]
    assert len(pend) == 1 and pend[0]["ticks_remaining"] > 0


# --- (3) NEGATIVE CONTROL — the gate is not a no-op: a forged / late / cross-engagement allow never wins --


def test_forged_untrusted_key_approval_never_approves(tmp_path):
    """An approval signed by an UNTRUSTED key must never reach APPROVED — the resolve loop only verifies
    against the pinned trusted approver. If this passed, the loop would launder a forged allow."""
    base = str(tmp_path)
    kid, pub, _priv = _identity()          # the TRUSTED owner key
    _akid, _apub, attacker_priv = _identity("attacker")  # an untrusted key
    trusted = {kid: pub}
    key = _register(base, _SLUG, _esc(seq=7), trusted=trusted)

    # attacker signs with kid="owner" but the WRONG private key → signature won't verify against pub
    forged = sign_escalation_approval(attacker_priv, key_id=kid, key=key, engagement=_SLUG)
    write_signed_approval(base, _SLUG, key, forged)

    reg = open_registry(base, _SLUG, trusted_approvers=trusted)
    applied = resolve_pending(reg, base_dir=base, slug=_SLUG, now_seq=7)
    assert len(applied) == 1
    assert applied[0].approved is False and applied[0].outcome == ConfirmationOutcome.REJECTED

    fresh = open_registry(base, _SLUG, trusted_approvers=trusted)
    assert fresh.resolution(key).approved is False


def test_late_valid_approval_expires_not_approves(tmp_path):
    """A GENUINE signed approval that arrives PAST the deadline must EXPIRE, not approve — the deadline beats
    a late signature (enforced inside resolve() via the seq we pass)."""
    base = str(tmp_path)
    kid, pub, priv = _identity()
    trusted = {kid: pub}
    key = _register(base, _SLUG, _esc(seq=2), trusted=trusted)
    write_signed_approval(base, _SLUG, key, sign_escalation_approval(priv, key_id=kid, key=key, engagement=_SLUG))

    reg = open_registry(base, _SLUG, trusted_approvers=trusted)
    applied = resolve_pending(reg, base_dir=base, slug=_SLUG, now_seq=2 + _DEADLINE + 1)  # LATE
    assert len(applied) == 1
    assert applied[0].outcome == ConfirmationOutcome.EXPIRED and applied[0].approved is False


def test_cross_engagement_approval_does_not_approve(tmp_path):
    """An approval signed for engagement A must not approve the SAME bare key in engagement B — the engagement
    is bound into the signed bytes and sourced from the verifier's own config."""
    base = str(tmp_path)
    kid, pub, priv = _identity()
    trusted = {kid: pub}
    # register the same bare key under engagement B's ledger
    slug_b = "eng-OTHER"
    key = _register(base, slug_b, _esc(seq=1), trusted=trusted)
    # sovereign signs for engagement A, but drops it in B's inbox
    envelope_for_a = sign_escalation_approval(priv, key_id=kid, key=key, engagement="eng-A")
    write_signed_approval(base, slug_b, key, envelope_for_a)

    reg = open_registry(base, slug_b, trusted_approvers=trusted)
    applied = resolve_pending(reg, base_dir=base, slug=slug_b, now_seq=1)
    assert len(applied) == 1
    assert applied[0].approved is False and applied[0].outcome == ConfirmationOutcome.REJECTED


def test_no_trust_root_cannot_approve(tmp_path):
    """With NO pinned trusted approver, even a real signed envelope cannot verify (fail-closed) — a durable
    allow is impossible without a trust root."""
    base = str(tmp_path)
    kid, _pub, priv = _identity()
    key = _register(base, _SLUG, _esc(seq=1))   # registry with NO trusted approvers
    write_signed_approval(base, _SLUG, key, sign_escalation_approval(priv, key_id=kid, key=key, engagement=_SLUG))

    reg = open_registry(base, _SLUG, trusted_approvers=None)   # no trust root
    applied = resolve_pending(reg, base_dir=base, slug=_SLUG, now_seq=1)
    assert len(applied) == 1
    assert applied[0].approved is False and applied[0].outcome == ConfirmationOutcome.REJECTED


# --- inbox hygiene ------------------------------------------------------------------------------------


def test_inbox_refuses_a_non_envelope_and_is_path_safe(tmp_path):
    """write_signed_approval fail-closes on a value that is not a signed envelope; find_signed_approval is
    total (None on absent). The signed file lives under the per-engagement inbox dir."""
    import pytest

    base = str(tmp_path)
    key = ("w1", "m1", 1)
    assert find_signed_approval(base, _SLUG, key) is None      # absent → None (total)
    with pytest.raises(ValueError):
        write_signed_approval(base, _SLUG, key, {"not": "an envelope"})
    # a real envelope lands under <base>/approvals/fireteam/<slug>/signed
    kid, _pub, priv = _identity()
    p = write_signed_approval(base, _SLUG, key, sign_escalation_approval(priv, key_id=kid, key=key, engagement=_SLUG))
    assert pathlib.Path(p).parent == signed_inbox_dir(base, _SLUG)


# --- WIRING guard: the production caller exists + the stale comment is gone (docs-true-of-code) --------


def _wiring_src() -> str:
    return (pathlib.Path(__file__).resolve().parents[1]
            / "vigil_integration" / "live" / "wiring.py").read_text(encoding="utf-8")


def test_deploy_fireteam_calls_the_resolve_loop():
    """The live engine's deploy_fireteam is a PRODUCTION CALLER of resolve_pending — not a library nobody
    calls. Removing the call reddens this guard."""
    src = _wiring_src()
    assert "from ..fireteam.resolver import resolve_pending" in src
    assert "resolve_pending(fireteam_registry" in src


def test_remaining_wiring_step_comment_is_gone():
    """The '... is the remaining wiring step' claim must be removed — it is DONE (this issue)."""
    src = _wiring_src()
    assert "remaining wiring step" not in src
