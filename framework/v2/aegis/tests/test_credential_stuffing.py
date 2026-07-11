"""
Credential stuffing / ATO — the DEFENSIVE dual proved, not guessed.

The credential_stuffing oracle reuses the SAME Wald SPRT as boolean_inference (``_sprt_decision``)
over each source's UNSEEN-(account, source) auth SUCCESS stream, with a Holm-Bonferroni family-wise
correction across the distinct source identities. It CONFIRMS only when the SPRT crosses AND the
source survives the family-wise control.

Coverage:
  * SPRT confirms a real stuffing pattern (breadth of unseen-account successes from one source).
  * The MECE benign twin — a NAT/CGNAT failed-only burst — stays a LEAD, never confirmed.
  * A benign returning-user window is CLEAR (not "safe"); an allowlisted egress source REFUTES.
  * The Holm family-wise control withholds a MARGINAL single-source hit among many identities.
  * The confirmed certificate re-verifies offline; a tampered one does not.
  * The certificate carries NO raw username/IP (keyed-HMAC pseudonyms only).
  * A hallucinated attack_class is parse-rejected; the verdict is deterministic.
"""

from __future__ import annotations

import json

from framework.v2.aegis import Aegis, ActorRef, AegisConfig, AuthEvent, Surface, Verdict
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.confirmation import confirm_finding
from framework.v2.verify.oracles import credential_stuffing_oracle
from framework.v2.verify.reverify import reverify_context
from framework.v2.verify.verifier import normalize_bug_class


def _aegis() -> Aegis:
    return Aegis(AegisConfig(deployment_secret="test-secret"))


def _events(pairs):
    """pairs: iterable of (account, source, success)."""
    return [{"account": a, "source": s, "success": ok} for a, s, ok in pairs]


# --- oracle-level (pure, deterministic) -----------------------------------------------


def test_sprt_confirms_real_stuffing_pattern():
    # one source succeeds on 6 distinct never-before-seen accounts -> unseen-pair-success run.
    evts = _events((f"acct{i}", "srcA", True) for i in range(6))
    sig = credential_stuffing_oracle(evts)
    assert sig.fired and sig.confidence >= 0.7
    assert sig.observed["confirmed_sources"] == ["srcA"]


def test_failed_only_burst_never_confirms():
    # NAT/CGNAT benign twin: many failures, no successes -> zero SPRT rounds -> non-fire.
    evts = _events((f"acct{i}", "natIP", False) for i in range(50))
    sig = credential_stuffing_oracle(evts)
    assert not sig.fired
    assert sig.observed["families"][0]["decided"] == "inconclusive"


def test_benign_returning_user_refutes():
    # one account, repeated successes from one source -> the SPRT drifts to the refute boundary.
    evts = _events(("me", "home", True) for _ in range(8))
    sig = credential_stuffing_oracle(evts)
    assert not sig.fired
    assert sig.observed["families"][0]["decided"] == "refute"


def test_single_new_device_login_does_not_confirm():
    # one unseen-pair success is NOT enough to cross — a returning user's new device is benign.
    sig = credential_stuffing_oracle(_events([("me", "phone", True)]))
    assert not sig.fired


def test_allowlisted_source_refutes():
    evts = _events((f"acct{i}", "sso-gw", True) for i in range(6))
    sig = credential_stuffing_oracle(evts, benign_sources=["sso-gw"])
    assert not sig.fired
    assert sig.observed["families"][0]["decided"] == "allowlisted"


def test_holm_family_wise_control_withholds_a_marginal_hit():
    # A MARGINAL stuffer (exactly 4 unseen-account successes, p~0.0016) alone confirms; but placed
    # among 6 other benign identities it must NOT survive the Holm family-wise control (0.01/7).
    marginal = _events((f"m{i}", "attacker", True) for i in range(4))
    alone = credential_stuffing_oracle(marginal)
    assert alone.fired, "the marginal source confirms on its own (SPRT crossed)"

    padding = _events((f"f{j}", f"benign{j}", False) for j in range(6))
    together = credential_stuffing_oracle(marginal + padding)
    assert not together.fired, "Holm withholds the marginal hit among 7 identities (family-wise control)"
    fam = {f["source"]: f for f in together.observed["families"]}
    assert fam["attacker"]["decided"] == "confirm"   # SPRT still crossed...
    assert "attacker" not in together.observed["confirmed_sources"]  # ...but Holm withheld it.


def test_strong_stuffer_survives_holm_among_many_identities():
    # A STRONG stuffer (6 unseen successes, p~6.4e-5) survives the same family-wise correction.
    strong = _events((f"s{i}", "attacker", True) for i in range(6))
    padding = _events((f"f{j}", f"benign{j}", False) for j in range(6))
    sig = credential_stuffing_oracle(strong + padding)
    assert sig.fired and sig.observed["confirmed_sources"] == ["attacker"]


def test_oracle_is_deterministic():
    evts = _events((f"acct{i}", "srcA", True) for i in range(6))
    a = credential_stuffing_oracle(evts)
    b = credential_stuffing_oracle(evts)
    assert a.model_dump() == b.model_dump()


# --- verify-layer (confirmation + offline reverify) -----------------------------------


def test_findingcontext_confirms_and_reverifies_offline():
    evts = _events((f"acct{i}", "srcA", True) for i in range(6))
    fc = FindingContext.from_auth_activity(evts)
    cf = confirm_finding({"bug_class": "credential_stuffing"}, fc)
    assert cf is not None and cf.confirmed_by.value == "credential_stuffing"
    oc = fc.to_verifier_context()
    r = reverify_context(oc, bug_class="credential_stuffing",
                         claimed_confirmed_by="credential_stuffing",
                         claimed_confidence=cf.confidence, verifier=None)
    assert r.ok and r.reproduced and r.matches_claim


def test_tampered_context_does_not_reverify():
    evts = _events((f"acct{i}", "srcA", True) for i in range(6))
    oc = FindingContext.from_auth_activity(evts).to_verifier_context()
    tampered = dict(oc)
    tampered["auth_events"] = [{"account": "acct0", "source": "srcA", "success": False}]
    r = reverify_context(tampered, bug_class="credential_stuffing", verifier=None)
    assert not r.ok


def test_ato_aliases_fold_onto_credential_stuffing():
    for alias in ("account_takeover", "ato", "cred_stuffing", "password_spraying"):
        assert normalize_bug_class(alias) == "credential_stuffing"


# --- pipeline-level (the AEGIS facade) ------------------------------------------------


def test_pipeline_confirms_stuffing_with_certificate():
    a = _aegis()
    stuffer = [AuthEvent(account=f"v{i}@corp.test", success=True) for i in range(6)]
    v = a.observe_auth(ActorRef(ip="203.0.113.7"), stuffer)
    assert v.decision == "confirmed"
    assert v.attack_class == "credential_stuffing"
    assert v.certificate is not None and v.certificate.reverify()
    assert v.provenance == "grounded:aegis:credential_stuffing"


def test_pipeline_failed_burst_stays_a_lead():
    a = _aegis()
    fails = [AuthEvent(account=f"u{i}@corp.test", success=False) for i in range(40)]
    v = a.observe_auth(ActorRef(ip="198.51.100.9"), fails)
    assert v.decision == "lead"
    assert v.certificate is None
    assert v.attack_class == "credential_stuffing"


def test_pipeline_benign_returning_user_is_clear():
    a = _aegis()
    benign = [AuthEvent(account="me@corp.test", success=True) for _ in range(6)]
    v = a.observe_auth(ActorRef(ip="192.0.2.44"), benign)
    assert v.decision == "clear"  # "clear" is NOT "safe" — no oracle fired, signals below band.
    assert v.certificate is None


def test_certificate_carries_no_raw_pii():
    a = _aegis()
    stuffer = [AuthEvent(account=f"victim{i}@corp.test", source="203.0.113.7", success=True)
               for i in range(6)]
    v = a.observe_auth(ActorRef(ip="10.0.0.1"), stuffer)
    assert v.decision == "confirmed"
    blob = json.dumps(v.certificate.oracle_context)
    assert "victim0" not in blob and "corp.test" not in blob   # accounts are HMAC pseudonyms
    assert "203.0.113" not in blob                              # source IP is coarsened+HMAC'd


def test_verdict_is_deterministic_same_cert_id():
    stuffer = [{"account": f"v{i}@corp.test", "source": "203.0.113.7", "success": True}
               for i in range(6)]
    a1, a2 = _aegis(), _aegis()
    v1 = a1.observe_auth(ActorRef(ip="10.0.0.1"), stuffer, seq=1)
    v2 = a2.observe_auth(ActorRef(ip="10.0.0.1"), stuffer, seq=1)
    assert v1.certificate.cert_id == v2.certificate.cert_id
    assert v1.model_dump() == v2.model_dump()


def test_hallucinated_attack_class_is_parse_rejected():
    import pytest
    with pytest.raises(Exception):
        Verdict(decision="clear", attack_class="ai_credential_mind_reader")
