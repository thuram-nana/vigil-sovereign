"""M-11.3 — the ACHIEVED-STATE credential-ACCEPTANCE oracle (OracleKind.CREDENTIAL_ACCEPTANCE).

Three prior versions tried to prove "weak credential ACCEPTED" by matching LOGIN-response BYTES, and all three
failed the red-pen: a coincidental marker present on every response + a differently-shaped baseline (404/500/302/
301/307/204/plain-text) kept minting a false ACCEPTED FACT on a target that actually REJECTED the credential.
Byte-diffing a login response cannot soundly distinguish accepted from rejected. This rebuild proves acceptance by
an UNFORGEABLE ACHIEVED EFFECT instead: the weak-credential session SUCCESSFULLY ACCESSES an AUTHENTICATED
PROTECTED RESOURCE that a KNOWN-BAD (or no) session is DENIED. The discriminator is the PROTECTED-RESOURCE ACCESS
OUTCOME (same url+method, differing only in the session), re-derived offline from the retained record.

These tests plant the TRUE positive (the weak session reaches a resource the denied baseline cannot) and assert
the MANDATORY must-not-fire controls:
  * (a) a NON-auth-gated resource that returns 2xx to BOTH sessions => no differential => REFUSE;
  * (b) a REJECTING login (the weak credential gets no session, so weak_access is itself a denial) => no fire;
  * (c) a coincidental authenticated-marker without a denied baseline => REFUSE;
  * (d) a mis-shaped / different-endpoint baseline => REFUSE;
  * (e) a baseline that is NOT denied => REFUSE.
The MANDATORY true positive (weak_access authenticated — 2xx + attested signal — and baseline_access denied — 401
or a login redirect — on the SAME resource) fires @ high confidence, re-verifies offline, and is tamper-rejected.
They also keep the hard preconditions (no planted corpus / no protected-resource attestation => never a FACT),
prove no real-user secret is read/retained, and prove the verdict re-derives byte-identically over the ctx.
"""
from __future__ import annotations

from framework.v2.verify import OracleVerifier
from framework.v2.verify.models import OracleKind
from framework.v2.verify.oracles import credential_acceptance_oracle

_CORPUS = "OBSIDIAN-TEST-corpus-7"
_RESOURCE_URL = "https://app.example/account/settings"
# A STRONG authenticated-content signal (>= 12 chars, >= 2.5 bits/char): a post-login account sentinel that the
# operator attests appears ONLY in an authenticated view of the resource (not in its login page / denial page).
_AUTHED_SIGNAL = 'data-account-id="acct_9f3kz7"'
_POLICY = {"corpus_id": _CORPUS, "should_reject": ["admin:admin", "root:toor", "guest:guest"]}
_DESCRIPTOR = {
    "url": _RESOURCE_URL,
    "method": "GET",
    "authenticated_signal": _AUTHED_SIGNAL,
    "login_redirect_locations": ["https://app.example/login"],
}


def _authed_access():
    """A protected-resource read that ACHIEVED authenticated access: 200 carrying the attested authed signal."""
    return {"status": 200, "body": f"<main {_AUTHED_SIGNAL}>Your account settings</main>",
            "headers": {}, "url": _RESOURCE_URL, "method": "GET"}


def _denied_access():
    """The SAME protected-resource request DENIED to the session: 401, no authed signal."""
    return {"status": 401, "body": "Authentication required", "headers": {}, "url": _RESOURCE_URL, "method": "GET"}


def _login_redirect_access():
    """The SAME protected-resource request DENIED via a 302 redirect to the attested login page."""
    return {"status": 302, "body": "", "headers": {"Location": "https://app.example/login?next=/account/settings"},
            "url": _RESOURCE_URL, "method": "GET"}


def _served_access():
    """The SAME request SERVED a 2xx to a known-bad/no session (a NON-auth-gated resource — no denial)."""
    return {"status": 200, "body": "<main>Public settings help page</main>",
            "headers": {}, "url": _RESOURCE_URL, "method": "GET"}


def _record(*, credential_id="admin:admin", corpus_id=_CORPUS, policy=None, descriptor=None,
            weak_access=None, baseline_access=None, accepted=True, baseline_denied=True):
    """A full achieved-state oracle record: the planted corpus/policy, the operator-attested protected-resource
    descriptor, the weak-credential session's read of the resource, and the known-bad/no session's read of the
    SAME resource."""
    return {
        "corpus_id": corpus_id,
        "credential_id": credential_id,
        "policy": _POLICY if policy is None else policy,
        "protected_resource": _DESCRIPTOR if descriptor is None else descriptor,
        "weak_access": weak_access if weak_access is not None else (_authed_access() if accepted else _denied_access()),
        "baseline_access": baseline_access if baseline_access is not None
        else (_denied_access() if baseline_denied else _served_access()),
    }


# == TRUE POSITIVE: the weak session ACHIEVED access the denied baseline could not =========================
def test_weak_credential_that_achieves_protected_access_fires():
    sig = credential_acceptance_oracle(_record(credential_id="admin:admin", accepted=True, baseline_denied=True))
    assert sig.kind is OracleKind.CREDENTIAL_ACCEPTANCE
    assert sig.fired and sig.confidence >= 0.95, sig.evidence
    assert sig.conclusive is True
    assert sig.observed["credential_in_should_reject"] is True
    assert sig.observed["same_shape"] is True
    assert sig.observed["baseline_is_denial"] is True
    assert sig.observed["weak_is_denial"] is False
    assert sig.observed["weak_is_authenticated_success"] is True
    assert sig.observed["signal_in_weak"] is True
    assert sig.observed["signal_in_baseline"] is False
    # the discriminator is the ACHIEVED ACCESS outcome, not the login response: "ACHIEVED STATE" is cited.
    assert "ACHIEVED STATE" in sig.evidence


def test_fires_when_the_baseline_is_denied_via_a_login_redirect():
    # the no-session baseline is DENIED not with a 401 but with a 302 redirect to the attested login page —
    # still a denial, so the weak session's 2xx authenticated read fires.
    sig = credential_acceptance_oracle(_record(baseline_access=_login_redirect_access()))
    assert sig.fired, sig.evidence
    assert sig.observed["baseline_is_denial"] is True
    assert sig.observed["baseline_status"] == 302


# == MANDATORY must-not-fire controls =====================================================================
# -- (a) a NON-auth-gated resource that returns 2xx to BOTH sessions => no differential => REFUSE ----------
def test_a_non_auth_gated_resource_served_to_both_sessions_does_not_fire():
    # Both the weak session AND the known-bad/no session get a 2xx — the resource is not auth-gating, so there is
    # no differential: a resource that serves everyone proves nothing. REFUSE, never a FACT.
    sig = credential_acceptance_oracle(_record(accepted=True, baseline_denied=False))
    assert not sig.fired, sig.evidence
    assert "REFUSED" in sig.evidence and "not" in sig.evidence.lower() and "denial" in sig.evidence.lower()
    assert sig.observed["baseline_is_denial"] is False


# -- (b) a REJECTING login: the weak cred gets no session, so weak_access is itself a denial => no fire ----
def test_a_rejecting_login_whose_weak_access_is_itself_denied_does_not_fire():
    # The target correctly REJECTED the weak credential: no session was issued, so the weak session's read of the
    # protected resource is DENIED (401) exactly like the known-bad baseline. No achieved state => no fire.
    sig = credential_acceptance_oracle(_record(weak_access=_denied_access(), baseline_access=_denied_access()))
    assert not sig.fired, sig.evidence
    assert sig.observed["weak_is_denial"] is True
    assert sig.observed["weak_is_authenticated_success"] is False
    assert "rejecting login" in sig.evidence


# -- (c) a coincidental authenticated-marker WITHOUT a denied baseline => no fire --------------------------
def test_a_coincidental_authed_marker_without_a_denied_baseline_does_not_fire():
    # The attested signal is PRESENT in the weak 2xx read, but the baseline ALSO gets a 2xx carrying it (the
    # resource is not auth-gating / the marker is non-exclusive). Without a denied baseline there is no
    # differential — the exact byte-marker false-FACT shape, now disarmed. REFUSE.
    served_with_marker = {"status": 200, "body": f"<p>{_AUTHED_SIGNAL}</p>", "headers": {},
                          "url": _RESOURCE_URL, "method": "GET"}
    sig = credential_acceptance_oracle(_record(weak_access=_authed_access(), baseline_access=served_with_marker))
    assert not sig.fired, sig.evidence
    assert "REFUSED" in sig.evidence
    assert sig.observed["baseline_is_denial"] is False


# -- (d) a mis-shaped / different-endpoint baseline => REFUSE ----------------------------------------------
def test_a_different_endpoint_baseline_is_not_same_shape_and_is_refused():
    # The baseline reads a DIFFERENT url than the attested resource the weak session read — the two legs are not
    # the SAME request, so the "differential" is meaningless. REFUSE (the mis-shaped-baseline red-pen shape).
    other = {**_denied_access(), "url": "https://app.example/somewhere-else"}
    sig = credential_acceptance_oracle(_record(weak_access=_authed_access(), baseline_access=other))
    assert not sig.fired, sig.evidence
    assert "REFUSED" in sig.evidence and "same request" in sig.evidence
    assert sig.observed["same_shape"] is False


def test_a_provenance_less_baseline_is_not_same_shape_and_is_refused():
    # A leg that carries no request provenance (no url) cannot be proven to be the same protected-resource
    # request, so same-shape fails. REFUSE.
    no_prov = {"status": 401, "body": "Authentication required", "headers": {}}
    sig = credential_acceptance_oracle(_record(weak_access=_authed_access(), baseline_access=no_prov))
    assert not sig.fired and "REFUSED" in sig.evidence
    assert sig.observed["same_shape"] is False


# -- (e) a baseline that is NOT denied => REFUSE (explicit: a 200 that merely lacks the signal) ------------
def test_a_baseline_that_is_not_denied_is_refused():
    plain_200 = {"status": 200, "body": "<main>welcome, everyone</main>", "headers": {},
                 "url": _RESOURCE_URL, "method": "GET"}
    sig = credential_acceptance_oracle(_record(weak_access=_authed_access(), baseline_access=plain_200))
    assert not sig.fired, sig.evidence
    assert "REFUSED" in sig.evidence and "auth-gating" in sig.evidence
    assert sig.observed["baseline_is_denial"] is False


# -- the DECISIVE guard: the attested signal present in BOTH legs CANCELS (no differential) ----------------
def test_the_signal_present_in_both_a_denied_baseline_and_the_weak_read_cancels():
    # Even with a genuinely DENIED baseline (401), if the denial body coincidentally carries the attested signal
    # the signal is not exclusive to the authenticated view — the differential CANCELS and does not fire.
    denied_with_signal = {"status": 401, "body": f"Access denied {_AUTHED_SIGNAL}", "headers": {},
                          "url": _RESOURCE_URL, "method": "GET"}
    sig = credential_acceptance_oracle(_record(weak_access=_authed_access(), baseline_access=denied_with_signal))
    assert not sig.fired, sig.evidence
    assert sig.observed["baseline_is_denial"] is True
    assert sig.observed["signal_in_weak"] is True
    assert sig.observed["signal_in_baseline"] is True
    assert "BOTH" in sig.evidence


# -- a 2xx weak read that LACKS the attested signal (an inlined login page) does not fire ------------------
def test_a_weak_2xx_without_the_attested_signal_does_not_fire():
    # Some apps serve HTTP 200 with the login page inline (no redirect) to an unauthenticated session. The 2xx
    # alone is not acceptance — the attested signal is ABSENT, so the weak session did not reach an authenticated
    # view. No fire (a bare 2xx is not an achieved authenticated state).
    inline_login = {"status": 200, "body": "<form action='/login'>Please sign in</form>", "headers": {},
                    "url": _RESOURCE_URL, "method": "GET"}
    sig = credential_acceptance_oracle(_record(weak_access=inline_login, baseline_access=_denied_access()))
    assert not sig.fired, sig.evidence
    assert sig.observed["signal_in_weak"] is False
    assert sig.observed["weak_is_authenticated_success"] is False


# == DISCRIMINATOR floor: a weak authenticated_signal is a LEAD, never a FACT ==============================
def test_a_low_entropy_authenticated_signal_is_a_lead_not_a_fact():
    low = "aaaaaaaaaaaa"  # 12 chars (clears the length floor) but 0 bits/char — not a reliable discriminator
    desc = dict(_DESCRIPTOR, authenticated_signal=low)
    weak = {"status": 200, "body": f"welcome {low}", "headers": {}, "url": _RESOURCE_URL, "method": "GET"}
    sig = credential_acceptance_oracle(_record(descriptor=desc, weak_access=weak, baseline_access=_denied_access()))
    assert not sig.fired, sig.evidence
    assert "LEAD" in sig.evidence
    assert sig.observed["signal_entropy_bits_per_char"] == 0.0


def test_a_too_short_authenticated_signal_is_a_lead_not_a_fact():
    desc = dict(_DESCRIPTOR, authenticated_signal="Sign out")  # 8 chars < the length floor
    weak = {"status": 200, "body": "<a>Sign out</a>", "headers": {}, "url": _RESOURCE_URL, "method": "GET"}
    sig = credential_acceptance_oracle(_record(descriptor=desc, weak_access=weak, baseline_access=_denied_access()))
    assert not sig.fired and "LEAD" in sig.evidence


# == HARD PRECONDITIONS ===================================================================================
def test_refuses_without_the_protected_resource_attestation():
    rec = _record()
    rec.pop("protected_resource")
    sig = credential_acceptance_oracle(rec)
    assert not sig.fired
    assert "REFUSED" in sig.evidence and "protected-resource attestation" in sig.evidence
    # positive control: WITH the attestation the SAME record fires.
    assert credential_acceptance_oracle(_record()).fired


def test_refuses_without_a_resource_url():
    desc = {k: v for k, v in _DESCRIPTOR.items() if k != "url"}
    sig = credential_acceptance_oracle(_record(descriptor=desc))
    assert not sig.fired and "REFUSED" in sig.evidence and "no url" in sig.evidence


def test_refuses_without_an_authenticated_signal():
    desc = {k: v for k, v in _DESCRIPTOR.items() if k != "authenticated_signal"}
    sig = credential_acceptance_oracle(_record(descriptor=desc))
    assert not sig.fired and "REFUSED" in sig.evidence and "authenticated_signal" in sig.evidence


def test_refuses_without_both_access_legs():
    rec = _record()
    rec.pop("baseline_access")
    sig = credential_acceptance_oracle(rec)
    assert not sig.fired and "REFUSED" in sig.evidence and "baseline_access" in sig.evidence
    rec2 = _record()
    rec2.pop("weak_access")
    assert not credential_acceptance_oracle(rec2).fired
    # positive control: WITH both legs the SAME record fires.
    assert credential_acceptance_oracle(_record()).fired


def test_refuses_when_a_leg_captured_no_response():
    sig = credential_acceptance_oracle(_record(baseline_access={}))
    assert not sig.fired and "REFUSED" in sig.evidence


def test_a_credential_outside_the_planted_set_does_not_fire():
    sig = credential_acceptance_oracle(_record(credential_id="realuser:correcthorse", accepted=True))
    assert not sig.fired
    assert sig.observed["credential_in_should_reject"] is False


def test_refuses_without_the_planted_corpus():
    rec = _record()
    rec.pop("corpus_id")
    sig = credential_acceptance_oracle(rec)
    assert not sig.fired
    assert "REFUSED" in sig.evidence and "corpus" in sig.evidence.lower()
    assert credential_acceptance_oracle(_record()).fired


def test_refuses_when_policy_does_not_bind_the_corpus():
    rogue = dict(_POLICY, corpus_id="some-other-corpus")
    sig = credential_acceptance_oracle(_record(policy=rogue))
    assert not sig.fired and "REFUSED" in sig.evidence


def test_refuses_without_a_should_reject_set():
    nolist = {"corpus_id": _CORPUS}
    sig = credential_acceptance_oracle(_record(policy=nolist))
    assert not sig.fired and "REFUSED" in sig.evidence and "should_reject" in sig.evidence


def test_missing_or_malformed_inputs_do_not_fire():
    assert not credential_acceptance_oracle(None).fired
    assert not credential_acceptance_oracle({}).fired
    assert not credential_acceptance_oracle({"corpus_id": _CORPUS}).fired          # no policy
    assert not credential_acceptance_oracle({"corpus_id": _CORPUS, "policy": {}}).fired  # empty policy


# == NO REAL-USER SECRET is read or retained =============================================================
def test_the_oracle_never_reads_or_retains_a_secret():
    # even if the capture carries a secret/password field and the resource body echoes it, the oracle must not
    # read it into its observed output or its evidence (it reads only identifiers + access outcomes, no body).
    rec = _record()
    rec["credential"] = {"username": "admin", "password": "SUPER-SECRET-REAL-PASSWORD"}
    rec["weak_access"]["body"] = f"<main {_AUTHED_SIGNAL}>Welcome SUPER-SECRET-REAL-PASSWORD</main>"
    sig = credential_acceptance_oracle(rec)
    assert sig.fired
    import json
    blob = json.dumps(sig.observed) + sig.evidence
    assert "SUPER-SECRET-REAL-PASSWORD" not in blob, "a secret leaked into the oracle output"


# == OFFLINE RE-DERIVATION + TAMPER REJECTION ============================================================
def test_the_verdict_re_derives_identically_over_the_retained_context():
    rec = _record()
    a = credential_acceptance_oracle(rec)
    b = credential_acceptance_oracle(dict(rec))
    assert a.fired and b.fired
    assert a.observed == b.observed


def test_a_tampered_certificate_no_longer_re_fires():
    # the retained ctx re-fires exactly; tamper it and the achieved-state proof collapses.
    assert credential_acceptance_oracle(_record()).fired
    # (1) tamper the weak read to drop the attested signal => no authenticated state => no re-fire.
    t1 = _record()
    t1["weak_access"] = {"status": 200, "body": "<main>no sentinel here</main>", "headers": {},
                         "url": _RESOURCE_URL, "method": "GET"}
    assert not credential_acceptance_oracle(t1).fired
    # (2) tamper the baseline to a served 200 (pretend the resource is not gated) => no denial => REFUSE.
    t2 = _record()
    t2["baseline_access"] = _served_access()
    assert not credential_acceptance_oracle(t2).fired


# == ROUTING: the verifier selects CREDENTIAL_ACCEPTANCE only via the credential_acceptance ctx key =======
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
    # no FACT without the protected-resource attestation, either (the achieved-state precondition holds e2e).
    noattest = dict(rec)
    noattest.pop("protected_resource")
    assert not v.confirm({"bug_class": "credential_acceptance", "credential_acceptance": noattest}).confirmed
    # no FACT without a denied baseline, either (a non-auth-gated resource proves nothing end-to-end).
    nogate = dict(rec)
    nogate["baseline_access"] = _served_access()
    assert not v.confirm({"bug_class": "credential_acceptance", "credential_acceptance": nogate}).confirmed


# == a RELABELLED certificate (wrong corpus binding) refuses to re-confirm ================================
def test_a_relabelled_certificate_refuses_to_re_confirm():
    # re-aim the planted policy at a DIFFERENT corpus than the record's: the certificate no longer binds and
    # cannot re-confirm (the corpus must authorise the capture).
    rec = _record()
    rec["corpus_id"] = "a-different-corpus-than-the-policy-binds"
    sig = credential_acceptance_oracle(rec)
    assert not sig.fired and "REFUSED" in sig.evidence


# == the credential-acceptance kind is NOT in the frozen unknown-class fallback (gate byte-identical) =====
def test_the_kind_is_held_out_of_the_frozen_fallback():
    from framework.v2.verify.verifier import _ALL_ORACLES
    assert len(_ALL_ORACLES) == 15
    assert OracleKind.CREDENTIAL_ACCEPTANCE not in _ALL_ORACLES
