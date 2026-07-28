"""A2b — the SOVEREIGN learn-grant producer (`sigil.knowledge.learn_grant`).

Doctrine under test:
  * a signed inert ``learn_grant`` is exported ONLY for an owner-APPROVED learn-proposal — a forged / non-owner
    / replayed approval never produces a grant (the sole trust op is the owner signature);
  * the grant's (slug, vuln_id) are JOINED from the queued proposal the approval's ``target_seq`` points at,
    and are cryptographically bound (tamper the slug → the offense verifier rejects it);
  * FAIL-CLOSED — export produces NOTHING when the kill-switch is engaged OR autolearn is disabled;
  * IDEMPOTENT — an already-exported approval is skipped.

Run: SIGIL_HOME=$(mktemp -d) PYTHONPATH=apps/sigil:integration python -m pytest tests/test_learn_grant.py -q
"""

import json
import tempfile
from pathlib import Path

import pytest

from sigil.agents.approvals import _approval_message
from sigil.governor import CapabilityGate, KillSwitch
from sigil.governor.authn import verify_signed
from sigil.knowledge import export_approved_grants
from sigil.knowledge.learn_grant import GRANT_CORE_FIELDS
from sigil.reuse import generate_keypair, sign
from sigil.spine.store import SpineStore
from sigil.ui import actions

OWNER = generate_keypair()
_PROP = {"vuln_id": "CVE-2024-0001", "slug": "loopback", "rank": 1, "exploit_known": True,
         "severity": "CRITICAL", "rationale": "known-exploited"}


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


@pytest.fixture
def owner(monkeypatch):
    import sigil.governor.identity as idmod
    monkeypatch.setattr(idmod, "ensure_owner_keypair", lambda: OWNER)
    monkeypatch.setattr(idmod, "owner_keypair", lambda: OWNER)
    monkeypatch.setattr(idmod, "owner_pubkey", lambda: OWNER.public_key_b64)
    return OWNER


def _incoming(spool: Path) -> list[dict]:
    return [json.loads(p.read_text()) for p in sorted((spool / "incoming").glob("*.json"))]


def _queue_and_approve(s):
    seq = actions.do_action("queue_learn", _PROP, store=s)["recorded_seq"]
    actions.do_action("approve", {"seq": seq, "reason": "accept"}, store=s)
    return seq


def test_export_signs_a_bound_grant_for_an_approved_proposal(owner, tmp_path):
    s = _store()
    seq = _queue_and_approve(s)
    out = export_approved_grants(s, spool_dir=tmp_path, owner_key=OWNER)
    assert out == {"exported": 1, "skipped": 0, "gated": None}
    grants = _incoming(tmp_path)
    assert len(grants) == 1
    g = grants[0]
    assert g["kind"] == "learn_grant" and g["vuln_id"] == "CVE-2024-0001" and g["slug"] == "loopback"
    assert g["approval_seq"] == seq
    # the grant verifies under the OWNER pubkey via the exact logic the offense consumer will use…
    assert verify_signed(g, GRANT_CORE_FIELDS, OWNER.public_key_b64) is True
    assert verify_signed(g, GRANT_CORE_FIELDS, generate_keypair().public_key_b64) is False   # wrong key
    # …and the signature BINDS the slug — tampering it invalidates the grant.
    tampered = {**g, "slug": "evil-scope"}
    assert verify_signed(tampered, GRANT_CORE_FIELDS, OWNER.public_key_b64) is False


def test_export_is_gated_by_killswitch(owner, tmp_path):
    s = _store()
    _queue_and_approve(s)
    KillSwitch(s, owner_key=OWNER).engage(reason="stop")
    out = export_approved_grants(s, spool_dir=tmp_path, owner_key=OWNER)
    assert out["gated"] == "kill-switch" and out["exported"] == 0
    assert _incoming(tmp_path) == []                       # nothing crossed the seam


def test_export_is_gated_by_autolearn_disabled(owner, tmp_path):
    s = _store()
    _queue_and_approve(s)
    CapabilityGate(s, owner_key=OWNER).disable("autolearn", reason="off")
    out = export_approved_grants(s, spool_dir=tmp_path, owner_key=OWNER)
    assert out["gated"] == "autolearn-disabled" and out["exported"] == 0
    assert _incoming(tmp_path) == []


def test_export_ignores_a_forged_approval(owner, tmp_path):
    s = _store()
    seq = actions.do_action("queue_learn", _PROP, store=s)["recorded_seq"]   # queued, NOT owner-approved
    # a forged, non-owner "approval" over the proposal seq must not mint a grant.
    att = generate_keypair()
    s.append(kind="event", source="governor", actor="ATTACKER",
             payload={"signal": "governor.approval", "approval": "approved", "target_seq": seq,
                      "approver": "attacker", "pubkey": att.public_key_b64,
                      "sig": sign(att.private_key_b64, _approval_message(seq, "approved", "attacker")),
                      "tier": "A0", "decision": "auto"})
    out = export_approved_grants(s, spool_dir=tmp_path, owner_key=OWNER)
    assert out["exported"] == 0 and _incoming(tmp_path) == []


def test_export_sanitizes_a_raw_injected_hostile_slug(owner, tmp_path):
    # Defense in depth: a raw spine-write can bypass the enqueue sanitizer. The mint must re-sanitise the
    # slug it OWNER-SIGNS (it becomes an offense `--slug` argv / IntelStore key / KillSwitch path token).
    s = _store()
    hostile = "../../../../etc/cron.d/pwn ; rm -rf /"
    seq = s.append(kind="event", source="knowledge", actor="attacker",
                   payload={"signal": "knowledge.learn_proposal", "decision": "queued",
                            "status": "awaiting-approval", "tier": "A2", "vuln_id": "CVE-2024-9999",
                            "slug": hostile, "subject": "x"})
    actions.do_action("approve", {"seq": seq, "reason": "accept"}, store=s)
    export_approved_grants(s, spool_dir=tmp_path, owner_key=OWNER)
    g = _incoming(tmp_path)[0]
    assert g["slug"] != hostile                                 # NOT the raw injected value
    assert all(c.isalnum() or c in "-_." for c in g["slug"])    # only path-safe chars survive
    assert "/" not in g["slug"] and " " not in g["slug"] and ";" not in g["slug"]
    assert verify_signed(g, GRANT_CORE_FIELDS, OWNER.public_key_b64) is True   # signed over the SAFE slug


def test_export_is_idempotent(owner, tmp_path):
    s = _store()
    _queue_and_approve(s)
    assert export_approved_grants(s, spool_dir=tmp_path, owner_key=OWNER)["exported"] == 1
    second = export_approved_grants(s, spool_dir=tmp_path, owner_key=OWNER)
    assert second == {"exported": 0, "skipped": 1, "gated": None}    # already-exported → skipped
    assert len(_incoming(tmp_path)) == 1                            # still exactly one grant
