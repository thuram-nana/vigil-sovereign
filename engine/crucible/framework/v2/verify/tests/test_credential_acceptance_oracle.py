"""M-11.3 — the deterministic credential-ACCEPTANCE oracle (OracleKind.CREDENTIAL_ACCEPTANCE).

The oracle CONFIRMS, from TWO VIGIL-captured auth attempts, that a target auth ACCEPTED a credential the
operator-planted TEST policy marks should-be-REJECTED — proven by a SAME-SHAPE DIFFERENTIAL (the planted
success marker PRESENT in the weak-credential capture AND ABSENT in a same-shape negative-credential baseline),
re-derived offline from the retained record so a FACT re-verifies with no network.

These tests plant the TRUE positive (the weak credential treated differently from a known-bad baseline), and
then assert the MANDATORY safe controls that disarm the red-pen false FACTs:
  * the EXACT red-pen cases — a 401 "Invalid credentials" rejection whose body contains the NON-EXCLUSIVE
    markers "Dashboard" / "session" => must NOT fire;
  * a (strong) marker present in BOTH legs => must NOT fire (a coincidental substring cancels);
  * a low-entropy marker => a LEAD, never a FACT;
  * a rejecting (401/403) weak leg whose marker coincidentally differs => must NOT fire (post-state veto);
  * no same-shape negative baseline => REFUSE.
They also keep the hard precondition (no planted test corpus => never a FACT), prove no real-user secret is
read/retained, and prove the verdict re-derives byte-identically over the retained context (offline
re-verification + the verifier routing).
"""
from __future__ import annotations

from framework.v2.verify import OracleVerifier
from framework.v2.verify.models import OracleKind
from framework.v2.verify.oracles import credential_acceptance_oracle

_CORPUS = "OBSIDIAN-TEST-corpus-7"
# A STRONG success_marker (33 chars, ~3.9 bits/char) — clears the discriminator floor, so firing is governed
# by the SAME-SHAPE DIFFERENTIAL, not by the marker's strength.
_MARKER = "Set-Cookie: session=authenticated"
_POLICY = {
    "corpus_id": _CORPUS,
    "should_reject": ["admin:admin", "root:toor", "guest:guest"],
    "success_marker": _MARKER,
}

# The SAME-SHAPE NEGATIVE-credential baseline: a known-bad credential the target correctly REJECTS. It carries
# NO authenticated session cookie, so the strong marker is absent from it. Every record ships this baseline.
_NEGATIVE_BASELINE = {"status": 401, "body": "Invalid credentials",
                      "headers": {"Set-Cookie": "session=deleted"}}


def _accepted_leg():
    """An auth response that genuinely ACCEPTED the credential: 200 + the authenticated-session cookie."""
    return {"status": 200, "body": "Welcome back", "headers": {"Set-Cookie": "session=authenticated"}}


def _rejected_leg():
    """An auth response that correctly REJECTED the credential: 401 + no authenticated-session cookie."""
    return {"status": 401, "body": "Invalid credentials", "headers": {"Set-Cookie": "session=deleted"}}


def _record(*, credential_id="admin:admin", accepted=True, corpus_id=_CORPUS, policy=None,
            weak_leg=None, baseline_leg=None):
    """A full oracle record: the planted corpus/policy, the attempted WEAK credential's capture, and the
    same-shape NEGATIVE-credential baseline capture."""
    rec = {
        "corpus_id": corpus_id,
        "credential_id": credential_id,
        "policy": _POLICY if policy is None else policy,
        "auth_response": weak_leg if weak_leg is not None else (_accepted_leg() if accepted else _rejected_leg()),
        "baseline_response": baseline_leg if baseline_leg is not None else dict(_NEGATIVE_BASELINE),
    }
    return rec


# -- TRUE POSITIVE: a planted weak credential ACCEPTED (the differential holds) --------------------------
def test_an_accepted_planted_weak_credential_fires():
    sig = credential_acceptance_oracle(_record(credential_id="admin:admin", accepted=True))
    assert sig.kind is OracleKind.CREDENTIAL_ACCEPTANCE
    assert sig.fired and sig.confidence >= 0.95, sig.evidence
    assert sig.observed["credential_in_should_reject"] is True
    assert sig.observed["marker_in_weak_leg"] is True
    assert sig.observed["marker_in_negative_baseline"] is False
    assert sig.observed["differential"] is True


# -- SAFE NEGATIVE: the SAME weak credential REJECTED (marker absent from the weak leg) -> NO fire --------
def test_a_rejected_planted_weak_credential_does_not_fire():
    sig = credential_acceptance_oracle(_record(credential_id="admin:admin", accepted=False))
    assert not sig.fired, sig.evidence
    assert sig.observed["marker_in_weak_leg"] is False
    assert sig.observed["differential"] is False


# -- RED-PEN false-FACT #1: a 401 "Invalid credentials" rejection whose body contains "Dashboard" ---------
def test_red_pen_401_rejection_with_dashboard_marker_does_not_fire():
    # The EXACT shape red-pen minted a false ACCEPTED FACT on: a correctly-REJECTING target (HTTP 401,
    # "Invalid credentials") whose nav body coincidentally contains the NON-EXCLUSIVE marker "Dashboard".
    policy = dict(_POLICY, success_marker="Dashboard")
    weak = {"status": 401, "body": "Invalid credentials — <nav>Dashboard</nav>", "headers": {}}
    base = {"status": 401, "body": "Invalid credentials — <nav>Dashboard</nav>", "headers": {}}
    sig = credential_acceptance_oracle(_record(policy=policy, weak_leg=weak, baseline_leg=base))
    assert not sig.fired, sig.evidence
    # "Dashboard" is caught by the discriminator floor (too short) — a LEAD, never a FACT; it would ALSO be
    # cancelled by the same-shape differential (present in both legs).
    assert "LEAD" in sig.evidence


# -- RED-PEN false-FACT #2: a 401 rejection whose body contains "session" in "your session expired" -------
def test_red_pen_401_rejection_with_session_marker_does_not_fire():
    policy = dict(_POLICY, success_marker="session")
    weak = {"status": 401, "body": "Invalid credentials. Also: your session expired.", "headers": {}}
    base = {"status": 401, "body": "Invalid credentials. Also: your session expired.", "headers": {}}
    sig = credential_acceptance_oracle(_record(policy=policy, weak_leg=weak, baseline_leg=base))
    assert not sig.fired, sig.evidence
    assert "LEAD" in sig.evidence


# -- DIFFERENTIAL mechanism (isolated): a STRONG marker present in BOTH legs -> cancels -> NO fire ---------
def test_a_strong_marker_present_in_both_legs_does_not_fire():
    # The marker clears the discriminator floor, so this isolates the SAME-SHAPE DIFFERENTIAL: a coincidental
    # substring present in BOTH the weak leg and the same-shape negative baseline CANCELS and does not fire.
    weak = {"status": 200, "body": "page for " + _MARKER, "headers": {}}
    base = {"status": 200, "body": "page for " + _MARKER, "headers": {}}   # same-shape, marker in BOTH
    sig = credential_acceptance_oracle(_record(weak_leg=weak, baseline_leg=base))
    assert not sig.fired, sig.evidence
    assert sig.observed["marker_in_weak_leg"] is True
    assert sig.observed["marker_in_negative_baseline"] is True
    assert sig.observed["differential"] is False
    assert "BOTH" in sig.evidence


# -- ENTROPY floor (isolated): a 12-char BUT low-entropy marker -> a LEAD, never a FACT -------------------
def test_a_low_entropy_marker_is_a_lead_not_a_fact():
    # "aaaaaaaaaaaa" clears the LENGTH floor (12 chars) but is 0 bits/char — it cannot be a reliable
    # discriminator even though it is present in the weak leg and absent in the baseline. LEAD, not a FACT.
    low = "aaaaaaaaaaaa"
    policy = dict(_POLICY, success_marker=low)
    weak = {"status": 200, "body": "welcome " + low, "headers": {}}
    base = {"status": 401, "body": "Invalid credentials", "headers": {}}   # marker absent -> would differ
    sig = credential_acceptance_oracle(_record(policy=policy, weak_leg=weak, baseline_leg=base))
    assert not sig.fired, sig.evidence
    assert "LEAD" in sig.evidence
    assert sig.observed["marker_entropy_bits_per_char"] == 0.0


# -- POST-STATE veto: a 401 weak leg whose marker coincidentally differs -> must NOT fire -----------------
def test_a_rejection_status_on_the_weak_leg_vetoes_a_coincidental_differential():
    # The strong marker is PRESENT in the weak leg and ABSENT in the baseline (the differential holds), BUT the
    # weak leg answered 401 — the post-state CONTRADICTS acceptance (the red-pen "status=401 while asserting
    # acceptance" smell). Must not fire.
    weak = {"status": 401, "body": "Invalid credentials", "headers": {"Set-Cookie": "session=authenticated"}}
    base = {"status": 401, "body": "Invalid credentials", "headers": {"Set-Cookie": "session=deleted"}}
    sig = credential_acceptance_oracle(_record(weak_leg=weak, baseline_leg=base))
    assert not sig.fired, sig.evidence
    assert sig.observed["differential"] is True
    assert sig.observed["weak_status_contradicts_acceptance"] is True


# -- HARD PRECONDITION: REFUSE without the same-shape negative baseline -----------------------------------
def test_refuses_without_the_negative_baseline():
    rec = _record()
    rec.pop("baseline_response")
    sig = credential_acceptance_oracle(rec)
    assert not sig.fired
    assert "REFUSED" in sig.evidence and "baseline" in sig.evidence.lower()
    # positive control: WITH the baseline the SAME record fires, so the refusal is the missing baseline.
    assert credential_acceptance_oracle(_record()).fired


# -- a degenerate (empty) baseline is not a sound negative -> REFUSE --------------------------------------
def test_refuses_when_a_leg_captured_no_response():
    sig = credential_acceptance_oracle(_record(baseline_leg={}))
    assert not sig.fired and "REFUSED" in sig.evidence


# -- a credential NOT in the planted should-be-rejected set never fires (real/legit credential) ----------
def test_a_credential_outside_the_planted_set_does_not_fire():
    sig = credential_acceptance_oracle(_record(credential_id="realuser:correcthorse", accepted=True))
    assert not sig.fired
    assert sig.observed["credential_in_should_reject"] is False


# -- HARD PRECONDITION: REFUSE without the operator-planted test corpus ----------------------------------
def test_refuses_without_the_planted_corpus():
    rec = _record()
    rec.pop("corpus_id")
    sig = credential_acceptance_oracle(rec)
    assert not sig.fired
    assert "REFUSED" in sig.evidence and "corpus" in sig.evidence.lower()
    # positive control: WITH the corpus the SAME record fires, so the refusal is the missing corpus.
    assert credential_acceptance_oracle(_record()).fired


def test_refuses_when_policy_does_not_bind_the_corpus():
    rogue = dict(_POLICY, corpus_id="some-other-corpus")
    sig = credential_acceptance_oracle(_record(policy=rogue))
    assert not sig.fired and "REFUSED" in sig.evidence


def test_refuses_without_a_success_marker():
    nomarker = {"corpus_id": _CORPUS, "should_reject": ["admin:admin"]}
    sig = credential_acceptance_oracle(_record(policy=nomarker))
    assert not sig.fired and "REFUSED" in sig.evidence and "success_marker" in sig.evidence


def test_missing_or_malformed_inputs_do_not_fire():
    assert not credential_acceptance_oracle(None).fired
    assert not credential_acceptance_oracle({}).fired
    assert not credential_acceptance_oracle({"corpus_id": _CORPUS}).fired          # no policy
    assert not credential_acceptance_oracle({"corpus_id": _CORPUS, "policy": {}}).fired  # empty policy


# -- NO REAL-USER SECRET is read or retained ------------------------------------------------------------
def test_the_oracle_never_reads_or_retains_a_secret():
    # even if the capture carries a secret/password field, the oracle must not read it into its observed output.
    rec = _record()
    rec["credential"] = {"username": "admin", "password": "SUPER-SECRET-REAL-PASSWORD"}
    rec["auth_response"]["body"] = "Welcome back SUPER-SECRET-REAL-PASSWORD"  # even if echoed, not our field
    sig = credential_acceptance_oracle(rec)
    assert sig.fired
    import json
    blob = json.dumps(sig.observed) + sig.evidence
    assert "SUPER-SECRET-REAL-PASSWORD" not in blob, "a secret leaked into the oracle output"


# -- OFFLINE RE-DERIVATION: the FACT re-verifies byte-identically over the retained context --------------
def test_the_verdict_re_derives_identically_over_the_retained_context():
    rec = _record()
    a = credential_acceptance_oracle(rec)
    b = credential_acceptance_oracle(dict(rec))
    assert a.fired and b.fired
    assert a.observed == b.observed


# -- ROUTING: the verifier selects CREDENTIAL_ACCEPTANCE only via the fresh ctx key ----------------------
def test_the_verifier_confirms_only_via_the_credential_acceptance_ctx_key():
    rec = _record()
    v = OracleVerifier()
    good = v.confirm({"bug_class": "credential_acceptance", "credential_acceptance": rec})
    assert good.confirmed, good.rationale
    # the SAME record under a DIFFERENT class's keys draws no credential-acceptance oracle (wrong key) ...
    assert not v.confirm({"bug_class": "credential_stuffing", "credential_acceptance": rec}).confirmed
    # ... and the ctx key with an unknown class is fail-closed (never a FACT).
    assert not v.confirm({"credential_acceptance": rec, "bug_class": "not_a_known_class"}).confirmed
    # no FACT without the planted corpus even via the verifier (the hard precondition holds end-to-end).
    norec = dict(rec)
    norec.pop("corpus_id")
    assert not v.confirm({"bug_class": "credential_acceptance", "credential_acceptance": norec}).confirmed
    # no FACT without the same-shape negative baseline, either (the differential precondition holds end-to-end).
    nobase = dict(rec)
    nobase.pop("baseline_response")
    assert not v.confirm({"bug_class": "credential_acceptance", "credential_acceptance": nobase}).confirmed


# -- a RELABELLED certificate (wrong corpus binding) refuses to re-confirm --------------------------------
def test_a_relabelled_certificate_refuses_to_re_confirm():
    # re-aim the planted policy at a DIFFERENT corpus than the record's: the certificate no longer binds and
    # cannot re-confirm (the corpus must authorise the capture).
    rec = _record()
    rec["corpus_id"] = "a-different-corpus-than-the-policy-binds"
    sig = credential_acceptance_oracle(rec)
    assert not sig.fired and "REFUSED" in sig.evidence


# -- the credential-acceptance kind is NOT in the frozen unknown-class fallback (gate byte-identical) ----
def test_the_kind_is_held_out_of_the_frozen_fallback():
    from framework.v2.verify.verifier import _ALL_ORACLES
    assert len(_ALL_ORACLES) == 15
    assert OracleKind.CREDENTIAL_ACCEPTANCE not in _ALL_ORACLES
