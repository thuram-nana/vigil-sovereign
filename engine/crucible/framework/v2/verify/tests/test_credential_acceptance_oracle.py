"""M-11.3 — the deterministic credential-ACCEPTANCE oracle (OracleKind.CREDENTIAL_ACCEPTANCE).

The oracle CONFIRMS, from a VIGIL-captured auth-attempt record, that a target auth ACCEPTED a credential the
operator-planted TEST policy marks should-be-REJECTED — re-derived offline from the retained record, so a FACT
re-verifies with no network. These tests plant the positive (a weak credential accepted), present the SAFE
negative (the same weak credential REJECTED — the planted success marker absent), prove the oracle REFUSES
without the planted test corpus (the hard precondition), prove a real/legitimate credential (not in the planted
should-be-rejected set) never fires, prove no real-user secret is read/retained, and prove the verdict
re-derives byte-identically over the retained context (offline re-verification + the verifier routing).
"""
from __future__ import annotations

from framework.v2.verify import OracleVerifier
from framework.v2.verify.models import OracleKind
from framework.v2.verify.oracles import credential_acceptance_oracle

_CORPUS = "OBSIDIAN-TEST-corpus-7"
_POLICY = {
    "corpus_id": _CORPUS,
    "should_reject": ["admin:admin", "root:toor", "guest:guest"],
    "success_marker": "Set-Cookie: session=authenticated",
}


def _record(*, credential_id="admin:admin", accepted=True, corpus_id=_CORPUS, policy=None):
    body = "Welcome back" if accepted else "Invalid credentials"
    headers = {"Set-Cookie": "session=authenticated"} if accepted else {"Set-Cookie": "session=deleted"}
    rec = {
        "corpus_id": corpus_id,
        "credential_id": credential_id,
        "policy": _POLICY if policy is None else policy,
        "auth_response": {"status": 200 if accepted else 401, "body": body, "headers": headers},
    }
    return rec


# -- POSITIVE: a planted weak credential ACCEPTED --------------------------------------------------------
def test_an_accepted_planted_weak_credential_fires():
    sig = credential_acceptance_oracle(_record(credential_id="admin:admin", accepted=True))
    assert sig.kind is OracleKind.CREDENTIAL_ACCEPTANCE
    assert sig.fired and sig.confidence >= 0.95
    assert sig.observed["credential_in_should_reject"] is True
    assert sig.observed["success_marker_present"] is True


# -- SAFE NEGATIVE: the SAME planted weak credential REJECTED (marker absent) -> NO fire -----------------
def test_a_rejected_planted_weak_credential_does_not_fire():
    sig = credential_acceptance_oracle(_record(credential_id="admin:admin", accepted=False))
    assert not sig.fired, sig.evidence
    assert sig.observed["success_marker_present"] is False


# -- a credential NOT in the planted should-be-rejected set never fires (real/legit credential) ----------
def test_a_credential_outside_the_planted_set_does_not_fire():
    # a legitimate credential VIGIL happened to re-drive is NOT in the planted corpus's should-reject set,
    # so even with a successful response the oracle does not speak to it (it only confirms PLANTED weak creds).
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
    # a policy whose own corpus_id names a DIFFERENT corpus cannot authorise a verdict over this record.
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


# -- the credential-acceptance kind is NOT in the frozen unknown-class fallback (gate byte-identical) ----
def test_the_kind_is_held_out_of_the_frozen_fallback():
    from framework.v2.verify.verifier import _ALL_ORACLES
    assert len(_ALL_ORACLES) == 15
    assert OracleKind.CREDENTIAL_ACCEPTANCE not in _ALL_ORACLES
