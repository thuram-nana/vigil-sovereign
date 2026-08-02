"""VF-1a — the ``vigil remediate --prove`` protocol orchestrator (prove_driver), offline against a fake adapter.

Exercises the FOUR-STATE machine and the brief's adversarial matrix without a live target: the live side is
behind LiveTargetAdapter, so a configurable fake produces each state and each failure. The oracle re-fire is
REAL (framework reverify) — a REMEDIATED verdict requires genuine oracle silence over the fake's benign
contexts and a firing positive control, exactly like the base RemediationCertificate. Includes the red-pen
regressions: policy keyed on the AUTHORIZED bug_class (timing/race + unknown families non-certifiable),
bearer-voids-PoP downgrade closed, PoP checked before the first target touch, orchestrator-owned budget bounds
the loop, and F2 freshness is VERIFIED from the retained evidence (not trusted from the adapter).

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
    prove_remediation, repeat_policy_for, verify_prove_certificate,
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
    """A configurable LiveTargetAdapter. Trials return SILENT (benign) contexts by default → REMEDIATED; knobs
    flip individual behaviours to drive each other state. The orchestrator owns the budget, so the adapter does
    NOT spend. When echoing at F2+, the fake embeds the challenge into the response body so the core can VERIFY
    freshness from the retained evidence."""

    def __init__(self, *, bug_class=BUG, destructive=False, identity=None, trial_fires=False, trial_valid=True,
                 trial_reachable=True, nonce_echoed=True, trial_freshness=Freshness.F2_PATH_TRAVERSED,
                 embed_challenge=True, embed_in_unjudged_field=False, control_fires=True, control_reachable=True,
                 drift_identity_after=None, raise_on_trial=False):
        self.bug_class = bug_class
        self.oracle_family = bug_class
        self.oracle_id = "oracle:" + bug_class
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
        self._embed = embed_challenge
        self._embed_unjudged = embed_in_unjudged_field
        self._control_fires = control_fires
        self._control_reachable = control_reachable
        self._drift_after = drift_identity_after
        self._raise_on_trial = raise_on_trial
        self.id_calls = 0

    def identity_sample(self):
        self.id_calls += 1
        if self._drift_after is not None and self.id_calls > self._drift_after:
            return {"host": "different.host"}
        return dict(self._identity)

    def run_positive_control(self, *, challenge, auth):
        ctx = _context(_SQL_ERROR if self._control_fires else _BENIGN)
        return ControlObservation(reachable=self._control_reachable, channel_alive=self._control_fires,
                                  oracle_context=ctx, freshness_level=self._trial_freshness,
                                  definition_digest="sha256:control")

    def run_exploit_trial(self, *, challenge, trial_index, auth):
        if self._raise_on_trial:
            raise RuntimeError("collector boom")
        base = _SQL_ERROR if self._trial_fires else _BENIGN
        if self._embed and self._nonce_echoed and self._trial_freshness >= Freshness.F2_PATH_TRAVERSED:
            base = base + b" echo=" + challenge.encode()   # the challenge is now IN the retained body (judged)
        ctx = _context(base)
        if self._embed_unjudged:
            ctx["discriminator"] = {"unjudged_note": challenge}   # present in the dict but NOT an oracle-judged field
        return TrialObservation(reachable=self._trial_reachable, valid=self._trial_valid,
                                oracle_context=ctx, freshness_level=self._trial_freshness,
                                nonce_echoed=self._nonce_echoed)


def _identity_att(policy=None, not_after=9_000):
    return sign_identity_attestation(OWNER, engagement=ENG, policy=(policy or POLICY), not_after=not_after)


def _run(adapter, *, policy=ProvePolicy(), revoked_ids=frozenset(), requested_min_freshness=None, now=NOW,
         audience="wielder", classes=None, not_after=9_000, rate_limit=10, revocation_id="rev-1",
         wielder_proof="auto", pop_challenge="pop-1"):
    ident = _identity_att()
    aud = {"wielder": WIELDER.public_key_b64, "bearer": "*", "attacker": ATTACKER.public_key_b64}.get(audience)
    cap = sign_capability(OWNER, engagement=ENG, identity_digest=identity_digest(ident),
                          class_allowlist=(classes or [adapter.bug_class]), not_before=0, not_after=not_after,
                          rate_limit=rate_limit, revocation_id=revocation_id, audience=aud)
    if wielder_proof == "auto":
        wielder_proof = None if aud == "*" else prove_wielder(WIELDER, challenge=pop_challenge, capability=cap)
    return prove_remediation(
        adapter=adapter, identity=ident, capability=cap, wielder_proof=wielder_proof,
        trusted_owner_pubkey=OWNER.public_key_b64, engagement=ENG, finding_id="errsqli-1",
        original_certificate_digest="sha256:orig", signers=SIGNERS, now=now, run_id="run-1",
        pop_challenge=pop_challenge, freshness_nonce="fresh-nonce-xyz", revoked_ids=revoked_ids,
        policy=policy, requested_min_freshness=requested_min_freshness)


# ============================ happy paths ============================
def test_remediated_silent_caps_at_f1_reflection_is_not_sink_traversal():
    # VF-1a.3 corrected semantics: the default FakeAdapter REFLECTS the fresh nonce into the SILENT response
    # body (embed_challenge=True) — yet a remediation caps at F1, because reflection into a silent response is
    # not sink-traversal (an echoing app / interposing edge can produce it). F2 is reserved for a FIRING trial.
    out = _run(FakeAdapter())
    assert out.state == State.REMEDIATED, out
    assert out.reason_code == Reason.ORACLE_SILENT_ACROSS_TRIALS
    assert out.trials_valid == 3 and out.achieved_freshness == Freshness.F1_TARGET_ECHOES
    ok, reason = verify_prove_certificate(out.certificate, signer_pubkeys=PUBKEYS)
    assert ok, reason
    assert "cross-bound" in reason
    assert out.certificate["evidence"]["embedded_remediation_cert"] is not None


def test_remediated_under_f2_floor_is_inconclusive_sink_traversal_unprovable():
    # VF-1a.3: a verifier that DEMANDS F2 for a remediation gets INCONCLUSIVE — honestly, because sink-traversal
    # is unprovable once the sink is fixed (the default FakeAdapter reflects the nonce into the silent body, but
    # that only earns F1). This is the corrected behaviour: never a falsely-strong REMEDIATED@F2.
    out = _run(FakeAdapter(), policy=ProvePolicy(minimum_freshness_level=Freshness.F2_PATH_TRAVERSED))
    assert out.state == State.INCONCLUSIVE and out.reason_code == Reason.INSUFFICIENT_FRESHNESS


def test_still_vulnerable_reaches_genuine_f2_via_firing_sink():
    # VF-1a.3: the F2 case that IS sound — a FIRING trial whose oracle-judged bytes embed the fresh nonce (it
    # came back INSIDE the sink's firing signature) → genuine F2 (the vulnerable path ran this run).
    out = _run(FakeAdapter(trial_fires=True))
    assert out.state == State.STILL_VULNERABLE and out.reason_code == Reason.ORACLE_FIRED
    assert out.achieved_freshness == Freshness.F2_PATH_TRAVERSED
    ok, _ = verify_prove_certificate(out.certificate, signer_pubkeys=PUBKEYS)
    assert ok and out.certificate["verdict"]["oracle_fired"] is True


def test_still_vulnerable_firing_without_nonce_in_judged_bytes_is_f1():
    # A firing trial whose fresh nonce is NOT in the judged bytes (no payload_template echo) → STILL_VULNERABLE
    # but only F1 (can't prove THIS nonce traversed the sink) — F2 needs the nonce inside the firing signature.
    out = _run(FakeAdapter(trial_fires=True, embed_challenge=False))
    assert out.state == State.STILL_VULNERABLE and out.reason_code == Reason.ORACLE_FIRED
    assert out.achieved_freshness == Freshness.F1_TARGET_ECHOES


def test_bearer_capability_allowed_only_when_pop_not_required():
    out = _run(FakeAdapter(), audience="bearer", policy=ProvePolicy(require_proof_of_possession=False))
    assert out.state == State.REMEDIATED, out


# ============================ BLOCK-1 regression: statistical / unknown families are non-certifiable ============
def test_repeat_policy_is_a_failclosed_deterministic_allowlist():
    # NON-certifiable: sampled-campaign statistical (timing/credstuff), probabilistic phenomena (race +
    # request_smuggling desync), stochastic LLM channels (prompt_injection / system_prompt_disclosure), and
    # oracle-KIND names / unknown classes (canonical None).
    for bc in ("time_based_sqli", "time_based", "time_based_command_injection", "request_race",
               "credential_stuffing", "account_takeover", "password_spraying",
               "request_smuggling", "prompt_injection", "system_prompt_disclosure",
               "error_signature", "differential_response", "oob_callback", "some_brand_new_class"):
        assert repeat_policy_for(bc).certifiable_by_silence is False, bc
    # CERTIFIABLE: every oracle deterministic-per-observation over a reliable channel. boolean_sqli stays
    # certifiable (SPRT bounds only rounds; the per-round signal is deterministic).
    for bc in ("error_based_sqli", "reflected_xss", "boolean_sqli", "sqli", "ldap_injection", "ssrf"):
        assert repeat_policy_for(bc).certifiable_by_silence is True, bc


def test_refused_credential_stuffing_sampled_campaign():
    out = _run(FakeAdapter(bug_class="credential_stuffing"))
    assert out.state == State.REFUSED and out.reason_code == Reason.STATISTICAL_RULE_UNIMPLEMENTED


def test_refused_request_smuggling_desync_phenomenon():
    # BLOCK-2 regression: deterministic oracle over a non-deterministically-reproducible desync → non-certifiable.
    out = _run(FakeAdapter(bug_class="request_smuggling"))
    assert out.state == State.REFUSED and out.reason_code == Reason.STATISTICAL_RULE_UNIMPLEMENTED


def test_refused_llm_stochastic_channel_classes():
    # BLOCK-3 regression: prompt_injection / system_prompt_disclosure judge a STOCHASTIC LLM output → non-cert.
    for bc in ("prompt_injection", "system_prompt_disclosure"):
        out = _run(FakeAdapter(bug_class=bc))
        assert out.state == State.REFUSED and out.reason_code == Reason.STATISTICAL_RULE_UNIMPLEMENTED, bc


def test_liveness_is_target_answer_not_connection_failure_dict():
    # MEDIUM-C / LOW-D + BLOCK-1: liveness detects TARGET-produced answers (observed_state / observed_evidence /
    # oob_hits / error_observed) and must NOT be asserted by producer-set fields, an empty context, OR a
    # connection-FAILURE dict ({connected: False} / {status: None}) — those keys are excluded from the set.
    from vigil_integration.remediation.remediation_cert import _has_live_response
    assert _has_live_response({"observed_state": {"row": 1}})
    assert _has_live_response({"observed_evidence": {"leak": "x"}})
    assert _has_live_response({"oob_hits": ["cb"]})
    assert _has_live_response({"error_observed": "SQL error"})
    assert not _has_live_response({"expected_state": {"row": 1}, "predicate": {"p": 1}, "marker": "m"})
    assert not _has_live_response({})
    # BLOCK-1: connection-style failure dicts must NOT read as "the target answered"
    assert not _has_live_response({"tls": {"connected": False, "error": "refused"}})
    assert not _has_live_response({"anon_get": {"status": None, "error": "gate refusal"}})
    assert not _has_live_response({"handshake": {"connected": False}})


def test_refused_statistical_timing_family():
    out = _run(FakeAdapter(bug_class="time_based_sqli"))
    assert out.state == State.REFUSED and out.reason_code == Reason.STATISTICAL_RULE_UNIMPLEMENTED


@pytest.mark.parametrize("kind_name", ["error_signature", "differential_response", "oob_callback"])
def test_refused_oracle_kind_name_masquerading_as_bug_class(kind_name):
    # BLOCK-1 regression: an oracle-KIND name is unknown to the vocabulary → cannot be certified (previously
    # these fell into a private table and a timing exploit so-labelled reached REMEDIATED).
    out = _run(FakeAdapter(bug_class=kind_name))
    assert out.state == State.REFUSED and out.reason_code == Reason.UNPROVABLE_ORACLE_FAMILY


def test_refused_request_race_probabilistic():
    out = _run(FakeAdapter(bug_class="request_race"))
    assert out.state == State.REFUSED and out.reason_code == Reason.STATISTICAL_RULE_UNIMPLEMENTED


def test_refused_unknown_family():
    out = _run(FakeAdapter(bug_class="totally_new_class"))
    assert out.state == State.REFUSED and out.reason_code == Reason.UNPROVABLE_ORACLE_FAMILY


# ============================ BLOCK-2 regression: bearer must not void require_proof_of_possession ============
def test_refused_bearer_under_require_pop():
    out = _run(FakeAdapter(), audience="bearer")   # default policy require_proof_of_possession=True
    assert out.state == State.REFUSED and out.reason_code == Reason.DOWNGRADE_REQUESTED


# ============================ REFUSED (authorization) ============================
def test_refused_expired_capability():
    out = _run(FakeAdapter(), not_after=NOW - 1)
    assert out.state == State.REFUSED and out.reason_code == Reason.EXPIRED_CAPABILITY


def test_refused_revoked_capability():
    out = _run(FakeAdapter(), revocation_id="rev-boom", revoked_ids=frozenset({"rev-boom"}))
    assert out.state == State.REFUSED and out.reason_code == Reason.REVOKED_CAPABILITY


def test_refused_unauthorized_bug_class():
    out = _run(FakeAdapter(), classes=["reflected_xss"])
    assert out.state == State.REFUSED and out.reason_code == Reason.UNAUTHORIZED_BUG_CLASS


def test_refused_identity_policy_mismatch():
    out = _run(FakeAdapter(identity={"host": "evil.host"}))
    assert out.state == State.REFUSED and out.reason_code == Reason.IDENTITY_POLICY_MISMATCH


def test_refused_pop_failure_and_no_target_touch():
    # a wielder proof by the WRONG key; PoP is checked BEFORE the first identity probe (LOW-1)
    adapter = FakeAdapter()
    ident = _identity_att()
    cap = sign_capability(OWNER, engagement=ENG, identity_digest=identity_digest(ident), class_allowlist=[BUG],
                          not_before=0, not_after=9_000, rate_limit=10, revocation_id="rev-1",
                          audience=WIELDER.public_key_b64)
    bad = prove_wielder(ATTACKER, challenge="pop-1", capability=cap)
    out = prove_remediation(adapter=adapter, identity=ident, capability=cap, wielder_proof=bad,
                            trusted_owner_pubkey=OWNER.public_key_b64, engagement=ENG, finding_id="errsqli-1",
                            original_certificate_digest="sha256:orig", signers=SIGNERS, now=NOW, run_id="run-1",
                            pop_challenge="pop-1", freshness_nonce="n")
    assert out.state == State.REFUSED and out.reason_code == Reason.POP_FAILURE
    assert adapter.id_calls == 0   # NO target touch before authorization completed


def test_refused_destructive_recipe():
    out = _run(FakeAdapter(destructive=True))
    assert out.state == State.REFUSED and out.reason_code == Reason.DESTRUCTIVE_UNDER_NONDESTRUCTIVE


def test_refused_budget_exhausted_precheck():
    out = _run(FakeAdapter(), rate_limit=2)   # below 1 control + 3 trials
    assert out.state == State.REFUSED and out.reason_code == Reason.BUDGET_EXHAUSTED


def test_refused_downgrade_below_floor():
    out = _run(FakeAdapter(), requested_min_freshness=Freshness.F0_NONCE_GENERATED,
               policy=ProvePolicy(minimum_freshness_level=Freshness.F2_PATH_TRAVERSED))
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
               policy=ProvePolicy(minimum_freshness_level=Freshness.F2_PATH_TRAVERSED))
    assert out.state == State.INCONCLUSIVE and out.reason_code == Reason.INSUFFICIENT_FRESHNESS


def test_inconclusive_adapter_lies_about_freshness_core_caps_it():
    # adapter CLAIMS F2 but the run cannot earn it — the core caps from the bytes, never the self-report. Here
    # the trial is silent AND the challenge is not embedded, so F2 fails on BOTH counts (silence can't be F2,
    # and the nonce isn't in the judged bytes) → capped to F1 → INSUFFICIENT under an F2 floor.
    out = _run(FakeAdapter(trial_freshness=Freshness.F2_PATH_TRAVERSED, embed_challenge=False),
               policy=ProvePolicy(minimum_freshness_level=Freshness.F2_PATH_TRAVERSED))
    assert out.state == State.INCONCLUSIVE and out.reason_code == Reason.INSUFFICIENT_FRESHNESS


def test_inconclusive_challenge_in_unjudged_field_does_not_count_as_f2():
    # LOW-3 regression: the challenge rides an UNJUDGED field (not the response the oracle adjudicates) → the
    # core scopes the F2 check to the judged evidence → caps to F1 → INSUFFICIENT under an F2 floor.
    out = _run(FakeAdapter(trial_freshness=Freshness.F2_PATH_TRAVERSED, embed_challenge=False,
                           embed_in_unjudged_field=True),
               policy=ProvePolicy(minimum_freshness_level=Freshness.F2_PATH_TRAVERSED))
    assert out.state == State.INCONCLUSIVE and out.reason_code == Reason.INSUFFICIENT_FRESHNESS


def test_inconclusive_requested_freshness_above_floor_is_enforced():
    # policy floor F1, but the caller REQUESTS F2 and the adapter only proves F1 → enforced → INCONCLUSIVE.
    out = _run(FakeAdapter(trial_freshness=Freshness.F1_TARGET_ECHOES),
               requested_min_freshness=Freshness.F2_PATH_TRAVERSED)
    assert out.state == State.INCONCLUSIVE and out.reason_code == Reason.INSUFFICIENT_FRESHNESS


def test_inconclusive_identity_changed_mid_run():
    out = _run(FakeAdapter(drift_identity_after=1))
    assert out.state == State.INCONCLUSIVE and out.reason_code == Reason.IDENTITY_CHANGED


def test_inconclusive_rate_limit_interrupted_by_invalid_trials():
    # rate_limit covers 1 control + 3 trials, but the orchestrator spends per iteration and invalid trials
    # never count → the budget is exhausted before 3 VALID trials → interrupted.
    out = _run(FakeAdapter(trial_valid=False), rate_limit=4)
    assert out.state == State.INCONCLUSIVE and out.reason_code == Reason.RATE_LIMIT_INTERRUPTED


def test_inconclusive_collector_failed():
    out = _run(FakeAdapter(raise_on_trial=True))
    assert out.state == State.INCONCLUSIVE and out.reason_code == Reason.COLLECTOR_FAILED


# ============================ certificate tampering ============================
def test_tampered_state_fails_verification():
    out = _run(FakeAdapter())
    out.certificate["state"] = State.STILL_VULNERABLE
    ok, _ = verify_prove_certificate(out.certificate, signer_pubkeys=PUBKEYS)
    assert not ok


def test_tampered_reason_code_fails_verification():
    out = _run(FakeAdapter(control_fires=False))
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
    assert not ok


def test_relabelled_verdict_state_split_brain_fails():
    out = _run(FakeAdapter())
    out.certificate["verdict"]["remediation_state"] = State.INCONCLUSIVE
    ok, _ = verify_prove_certificate(out.certificate, signer_pubkeys=PUBKEYS)
    assert not ok
