"""K4-5b — the keyless engagement-completion settle signal (producer side).

``emit_completion_signal`` signs an ``EngagementCompletion{slug, nonce, outcome}`` with the owner-delegated
offense-governance signers and spools it to the cross-plane settle spool. These pin: a signal signs + spools
as a verifiable, slug/nonce/outcome-bound envelope; the flat-per-run metric; signers required (fail-closed).
The envelope carries NO amount (the sovereign drain derives consumed from the owner-signed lease).

Producer needs only vigil_core (the shared signed-record) + the finding_spool seam — no framework — so it
runs on the integration leg: PYTHONPATH=integration.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from vigil_core import (
    AuthorizerKey, SignedEngagementCompletion, EngagementCompletion, TrustRoot,
    generate_keypair, verify_engagement_completion,
)
from vigil_integration.jobs.completion_signal import (
    COMPLETION_SEAM_SCHEMA, consumed_flat_per_run, emit_completion_signal,
)

SLUG, NONCE = "cust_abc123", "n1"


def _incoming(spool):
    return sorted(Path(spool, "incoming").glob("*.json"))


def test_completed_signal_signs_and_spools_a_verifiable_envelope():
    gov = generate_keypair()
    root = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="gov", name="gov", public_key_b64=gov.public_key_b64)])
    spool = tempfile.mkdtemp()
    path = emit_completion_signal(engagement_slug=SLUG, nonce=NONCE, outcome="completed",
                                  signers=[("gov", gov.private_key_b64)], spool_dir=spool)
    files = _incoming(spool)
    assert len(files) == 1 and str(files[0]) == str(path)
    env = json.loads(files[0].read_text(encoding="utf-8"))
    assert env["schema"] == COMPLETION_SEAM_SCHEMA
    assert env["document"] == {"engagement_slug": SLUG, "nonce": NONCE, "outcome": "completed"}  # NO amount
    signed = SignedEngagementCompletion(
        document=EngagementCompletion.model_validate(env["document"]), signatures=env["signatures"])
    ok, reason = verify_engagement_completion(signed, root)      # the spooled envelope verifies under gov
    assert ok, reason


@pytest.mark.parametrize("outcome,reserved,expected", [
    ("completed", 30, 30), ("canceled", 30, 0), ("failed", 30, 0)])
def test_consumed_flat_per_run(outcome, reserved, expected):
    assert consumed_flat_per_run(outcome, reserved) == expected


def test_signers_required_fail_closed():
    with pytest.raises(ValueError):
        emit_completion_signal(engagement_slug=SLUG, nonce=NONCE, outcome="completed",
                               signers=[], spool_dir=tempfile.mkdtemp())


def test_unknown_outcome_is_rejected():
    gov = generate_keypair()
    with pytest.raises(ValueError):   # EngagementOutcome(...) refuses an unknown terminal state
        emit_completion_signal(engagement_slug=SLUG, nonce=NONCE, outcome="bogus",
                               signers=[("gov", gov.private_key_b64)], spool_dir=tempfile.mkdtemp())
