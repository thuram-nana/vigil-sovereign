"""VF-1a — the ``vigil remediate --prove`` protocol orchestrator (prove_driver), offline against a fake adapter.

Exercises the FOUR-STATE machine and the brief's adversarial matrix without a live target: the live side is
behind LiveTargetAdapter, so a configurable fake produces each state and each failure. The oracle re-fire is
REAL (framework reverify) — a REMEDIATED verdict requires genuine oracle silence over the fake's benign
contexts and a firing positive control, exactly like the base RemediationCertificate.

Needs framework (reverify + the controlled mint) → PYTHONPATH=integration:engine/crucible:gateway.
"""
from __future__ import annotations

import pytest

from vigil_core import (
    generate_keypair, identity_digest, prove_wielder, sign_capability, sign_identity_attestation,
)
from vigil_integration.remediation import prove_driver as pd
from vigil_integration.remediation.prove_driver import (
    ControlObservation, Freshness, ProvePolicy, Reason, State, TrialObservation,
    prove_remediation, verify_prove_certificate,
)

OWNER = generate_keypair()
WIELDER = generate_keypair()
ATTACKER = generate_keypair()

ENG = "acme"
NOW = 1_000
BUG = "error_based_sqli"
POLICY = {"host": ["shop.acme.test"]}
SAMPLE = {"host": "shop.acme.test"}
PUBKEYS = {"gov0": OWNER.public_key_b64}
SIGNERS = [("gov0", OWNER.private_key_b64)]

_SQL_ERROR = b"HTTP/1.1 500\r\n\r\nYou have an error in your SQL syntax near ''"
_BENIGN = b"HTTP/1.1 200\r\n\r\n{\"results\": []}"


def _context(body: bytes) -> dict:
    from framework.v2.evidence.poc import CapturedExchange
    from framework.v2.verify.poc_translate import context_from_exchanges
    ex = CapturedExchange(channel="error_signature", role="mutated", response_bytes_ref="resp")
    ctx = context_from_exchanges([ex], bug_class=BUG, resolve=lambda r: body)
    assert ctx is not None
    return ctx.model_dump(mode="json")


class FakeAdapter:
    """A configurable LiveTargetAdapter. Trials return SILENT (benign) contexts by default → REMEDIATED path;
    knobs flip individual behaviours to drive each other state."""

    def __init__(self, *, bug_class=BUG, oracle_family=BUG, destructive=False, identity=None,
                 trial_fires=False, trial_valid=True, trial_reachable=True, nonce_echoed=True,
                 trial_freshness=Freshness.F2_PATH_TRAVERSED, control_fires=True, control_reachable=True,
                 drift_identity_after=None, raise_on_trial=False, spend_per_call=1):
        self.bug_class = bug_class
        self.oracle_family = oracle_family
        self.oracle_id = "oracle:error_based_sqli"
        self.oracle_version = "1.0"
        self.original_probe_recipe_digest = "sha256:probe"
        self.execution_profile_digest = "sha256:profile"
        self.destructive = destructive
        self._identity = identity or dict(SAMPLE)
        self._trial_fires = trial_fires
        self._trial_valid = trial_valid
        self._trial_reachable = trial_reachable
        self._nonce_echoed = nonce_echoed
        self._trial_freshness = trial_freshness
        self._control_fires = control_fires
        self._control_reachable = control_reachable
        self._drift_after = drift_identity_after
        self._raise_on_trial = raise_on_trial
        self._spend = spend_per_call
        self._id_calls = 0

    def identity_sample(self):
        self._id_calls += 1
        if self._drift_after is not None and self._id_calls > self._drift_after:
            return {"host": "different.host"}
        return dict(self._identity)

    def run_positive_control(self, *, challenge, auth, budget):
        budget.spend(self._spend)
        ctx = _context(_SQL_ERROR) if self._control_fires else _context(_BENIGN)
        return ControlObservation(reachable=self._control_reachable, channel_alive=self._control_fires,
                                  oracle_context=ctx, freshness_level=self._trial_freshness,
                                  definition_digest="sha256:control")

    def run_exploit_trial(self, *, challenge, trial_index, auth, budget):
        budget.spend(self._spend)
        if self._raise_on_trial:
            raise RuntimeError("collector boom")
        ctx = _context(_SQL_ERROR) if self._trial_fires else _context(_BENIGN)
        return TrialObservation(reachable=self._trial_reachable, valid=self._trial_valid, oracle_context=ctx,
                                freshness_level=self._trial_freshness, nonce_echoed=self._nonce_echoed)


def _identity_att(policy=None, not_after=9_000):
    return sign_identity_attestation(OWNER, engagement=ENG, policy=(policy or POLICY), not_after=not_after)


def _cap(*, id_digest=None, classes=None, not_before=0, not_after=9_000, rate_limit=10, revocation_id="rev-1",
         audience=None):
    ident = _identity_att()
    return sign_capability(OWNER, engagement=ENG, identity_digest=(id_digest or identity_digest(ident)),
                           class_allowlist=(classes or [BUG]), not_before=not_before, not_after=not_after,
                           rate_limit=rate_limit, revocation_id=revocation_id,
                           audience=(audience or WIELDER.public_key_b64))


def _run(adapter, *, identity=None, capability=None, wielder_proof="auto", pop_challenge="pop-1",
         policy=ProvePolicy(), revoked_ids=frozenset(), requested_min_freshness=None, now=NOW):
    ident = identity or _identity_att()
    cap = capability or _cap(id_digest=identity_digest(ident))
    if wielder_proof == "auto":
        wielder_proof = prove_wielder(WIELDER, challenge=pop_challenge, capability=cap)
    return prove_remediation(
        adapter=adapter, identity=ident, capability=cap, wielder_proof=wielder_proof,
        trusted_owner_pubkey=OWNER.public_key_b64, engagement=ENG, finding_id="errsqli-1",
        original_certificate_digest="sha256:orig", signers=SIGNERS, now=now, run_id="run-1",
        pop_challenge=pop_challenge, freshness_nonce="fresh-nonce-xyz", revoked_ids=revoked_ids,
        policy=policy, requested_min_freshness=requested_min_freshness)


# ============================ happy paths ============================
def test_remediated_and_certificate_reexecutes():
    out = _run(FakeAdapter())
    assert out.state == State.REMEDIATED, out
    assert out.reason_code == Reason.ORACLE_SILENT_ACROSS_TRIALS
    assert out.trials_valid == 3 and out.achieved_freshness == Freshness.F2_PATH_TRAVERSED
    ok, reason = verify_prove_certificate(out.certificate, signer_pubkeys=PUBKEYS)
    assert ok, reason
    # the embedded controlled remediation cert is present and the causal chain is recorded
    assert out.certificate["evidence"]["embedded_remediation_cert"] is not None
    assert out.certificate["execution"]["freshness_challenge"]
    assert out.certificate["target"]["target_identity_digest"]


def test_still_vulnerable_when_oracle_fires():
    out = _run(FakeAdapter(trial_fires=True))
    assert out.state == State.STILL_VULNERABLE and out.reason_code == Reason.ORACLE_FIRED
    ok, _ = verify_prove_certificate(out.certificate, signer_pubkeys=PUBKEYS)
    assert ok
    assert out.certificate["verdict"]["oracle_fired"] is True


# ============================ REFUSED (authorization) ============================
def test_refused_expired_capability():
    out = _run(FakeAdapter(), capability=_cap(not_after=NOW - 1))
    assert out.state == State.REFUSED and out.reason_code == Reason.EXPIRED_CAPABILITY


def test_refused_revoked_capability():
    out = _run(FakeAdapter(), capability=_cap(revocation_id="rev-boom"), revoked_ids=frozenset({"rev-boom"}))
    assert out.state == State.REFUSED and out.reason_code == Reason.REVOKED_CAPABILITY


def test_refused_unauthorized_bug_class():
    out = _run(FakeAdapter(), capability=_cap(classes=["reflected_xss"]))
    assert out.state == State.REFUSED and out.reason_code == Reason.UNAUTHORIZED_BUG_CLASS


def test_refused_identity_policy_mismatch():
    out = _run(FakeAdapter(identity={"host": "evil.host"}))
    assert out.state == State.REFUSED and out.reason_code == Reason.IDENTITY_POLICY_MISMATCH


def test_refused_proof_of_possession_failure():
    # a wielder proof by the WRONG key (thief) for a pinned capability
    cap = _cap()
    bad = prove_wielder(ATTACKER, challenge="pop-1", capability=cap)
    out = _run(FakeAdapter(), capability=cap, wielder_proof=bad)
    assert out.state == State.REFUSED and out.reason_code == Reason.POP_FAILURE


def test_refused_destructive_recipe_under_nondestructive_capability():
    out = _run(FakeAdapter(destructive=True))
    assert out.state == State.REFUSED and out.reason_code == Reason.DESTRUCTIVE_UNDER_NONDESTRUCTIVE


def test_refused_budget_exhausted_precheck():
    # rate_limit below 1 control + 3 trials
    out = _run(FakeAdapter(), capability=_cap(rate_limit=2))
    assert out.state == State.REFUSED and out.reason_code == Reason.BUDGET_EXHAUSTED


def test_refused_downgrade_requested_below_floor():
    out = _run(FakeAdapter(), requested_min_freshness=Freshness.F0_NONCE_GENERATED,
               policy=ProvePolicy(minimum_freshness_level=Freshness.F2_PATH_TRAVERSED))
    assert out.state == State.REFUSED and out.reason_code == Reason.DOWNGRADE_REQUESTED


def test_refused_downgrade_missing_pop_for_pinned_cap():
    out = _run(FakeAdapter(), wielder_proof=None)
    assert out.state == State.REFUSED and out.reason_code == Reason.DOWNGRADE_REQUESTED


# ============================ INCONCLUSIVE (testing occurred) ============================
def test_inconclusive_control_failed():
    out = _run(FakeAdapter(control_fires=False))
    assert out.state == State.INCONCLUSIVE and out.reason_code == Reason.CONTROL_FAILED


def test_inconclusive_target_unavailable_for_control():
    out = _run(FakeAdapter(control_reachable=False))
    assert out.state == State.INCONCLUSIVE and out.reason_code == Reason.TARGET_UNAVAILABLE


def test_inconclusive_freshness_echo_missing():
    out = _run(FakeAdapter(nonce_echoed=False))
    assert out.state == State.INCONCLUSIVE and out.reason_code == Reason.FRESHNESS_ECHO_MISSING


def test_inconclusive_insufficient_freshness_level():
    out = _run(FakeAdapter(trial_freshness=Freshness.F1_TARGET_ECHOES),
               policy=ProvePolicy(minimum_freshness_level=Freshness.F3_BOUND_TO_EVIDENCE))
    assert out.state == State.INCONCLUSIVE and out.reason_code == Reason.INSUFFICIENT_FRESHNESS


def test_inconclusive_identity_changed_mid_run():
    # first sample (pre-exec) matches; drift on the 2nd sample (continuity #2 before trials)
    out = _run(FakeAdapter(drift_identity_after=1))
    assert out.state == State.INCONCLUSIVE and out.reason_code == Reason.IDENTITY_CHANGED


def test_inconclusive_rate_limit_interrupted_by_invalid_trials():
    # rate_limit exactly covers 1 control + 3 trials, but invalid trials burn budget → interrupted
    out = _run(FakeAdapter(trial_valid=False, spend_per_call=1), capability=_cap(rate_limit=4))
    assert out.state == State.INCONCLUSIVE and out.reason_code == Reason.RATE_LIMIT_INTERRUPTED


def test_inconclusive_collector_failed():
    out = _run(FakeAdapter(raise_on_trial=True))
    assert out.state == State.INCONCLUSIVE and out.reason_code == Reason.COLLECTOR_FAILED


def test_inconclusive_statistical_family_not_yet_provable():
    out = _run(FakeAdapter(oracle_family="timing_sqli"), capability=_cap(classes=[BUG]))
    assert out.state == State.INCONCLUSIVE and out.reason_code == Reason.STATISTICAL_RULE_UNIMPLEMENTED


# ============================ certificate tampering ============================
def test_tampered_state_fails_verification():
    out = _run(FakeAdapter())
    out.certificate["state"] = State.STILL_VULNERABLE
    ok, reason = verify_prove_certificate(out.certificate, signer_pubkeys=PUBKEYS)
    assert not ok


def test_tampered_reason_code_fails_verification():
    out = _run(FakeAdapter(control_fires=False))    # INCONCLUSIVE / CONTROL_FAILED
    out.certificate["verdict"]["reason_code"] = Reason.ORACLE_SILENT_ACROSS_TRIALS
    ok, _ = verify_prove_certificate(out.certificate, signer_pubkeys=PUBKEYS)
    assert not ok


def test_wrong_pinned_key_fails_verification():
    out = _run(FakeAdapter())
    ok, _ = verify_prove_certificate(out.certificate, signer_pubkeys={"gov0": ATTACKER.public_key_b64})
    assert not ok


def test_stripped_embedded_cert_fails_remediated_verification():
    out = _run(FakeAdapter())
    out.certificate["evidence"]["embedded_remediation_cert"] = None
    ok, _ = verify_prove_certificate(out.certificate, signer_pubkeys=PUBKEYS)
    assert not ok   # signature breaks (embedded cert is signed into the whole cert) → fail-closed


def test_relabelled_verdict_state_split_brain_fails():
    out = _run(FakeAdapter())
    out.certificate["verdict"]["remediation_state"] = State.INCONCLUSIVE
    ok, _ = verify_prove_certificate(out.certificate, signer_pubkeys=PUBKEYS)
    assert not ok
