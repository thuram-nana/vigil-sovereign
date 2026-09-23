"""
Two-identity access control — STD-WIRING (Wave 3.1): admission -> certify_admitted -> offline re-verify
-> tamper reject, over the registered idor/bola/bfla/mass_assignment ACHIEVED_STATE evidence branches.

This is the claim-discipline half of slice 3.1: a two-identity achieved cross-read (or a persisted
mass-assignment state change) is minted ONLY through the admission choke (``verdict.admit`` -> the
FACT-capable ``*.cross_identity_read`` / ``mass_assignment.persisted_state_change`` branch ->
``oracle_adapter.certify_admitted(provenance="live_redrive")``), the offline ``framework.v2 verify`` path
re-fires the retained ``oracle_context``, and a tampered value is rejected. An LLM-provenanced context is
demoted to a LEAD (audit G4). A conclusive non-fire is INCONCLUSIVE, never CLEAN.

The victim-UNIQUE discriminator is what makes the confirmation sound (bola/idor were once reverted as
UNSOUND for a whole-body containment that false-positived on shared boilerplate): the finding here is
built from an IdorCheck probe that reaches a per-identity marker, so a stub with only shared boilerplate
never produces a firing context.
"""

from __future__ import annotations

import sys
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

_ROOT = Path(__file__).resolve().parents[2]
for _p in (str(_ROOT / "engine" / "crucible"), str(_ROOT / "integration"),
           str(_ROOT / "packages" / "core" / "vigil_core")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from framework.v2.scanner.access_control import AccessControlConfig, CrossAccessSpec, build_access_control_checks
from framework.v2.scanner.access_control import access_control_finding
from framework.v2.scanner.insertion import HttpRequest, InsertionKind, RequestTemplate
from framework.v2.verify.models import OracleKind
from framework.v2.verify.reverify import reverify_finding
from framework.v2.verify.verifier import OracleVerifier

from vigil_integration.live.access_control_redrive import _BRANCH_FOR
from vigil_integration.live.verdict import Verdict, admit, branch_ids
from vigil_integration.live.wiring import _redrive_branch_for
from vigil_integration.oracle_adapter import certify_admitted

_VICTIM_SECRET = "SECRET-BOB-INVOICE-#2-total=$9001-acct=bob@example.test"
_VICTIM_REF = "2"
_ATTACKER_OWN_REF = "1"   # the attacker's OWN object — the mandatory negative control
_BRANCH = "idor.cross_identity_read"


def _req_id(req: HttpRequest) -> str:
    return (parse_qs(urlsplit(req.url).query).get("id") or [""])[0]


def _signers():
    from vigil_core import generate_keypair
    kp = generate_keypair()
    return [("gov0", kp.private_key_b64)]


def _make_cross_target():
    def victim_send(req: HttpRequest) -> dict:
        return {"status": 200, "body": _VICTIM_SECRET}

    def attacker_send(req: HttpRequest) -> dict:
        # vulnerable cross-read of bob's ref (id=2): attacker reaches bob's private record (the unique
        # discriminator). Reading the attacker's OWN object (id=1, the negative control) returns a benign
        # body WITHOUT bob's marker — proving the discriminator is victim-specific, not shared boilerplate.
        if _req_id(req) == _VICTIM_REF:
            return {"status": 200, "body": f"<html><nav>Home</nav>{_VICTIM_SECRET}<footer>Acme</footer></html>"}
        return {"status": 200, "body": "<html><nav>Home</nav>alice-own-account-0001<footer>Acme</footer></html>"}

    def nocred_send(req: HttpRequest) -> dict:
        # logged-out baseline: authentication is required, so bob's private record is never served (round-2
        # authorization-gated proof) — the marker is absent, so the attacker's read WAS unauthorized.
        return {"status": 403, "body": "<html><nav>Home</nav>login required<footer>Acme</footer></html>"}

    return attacker_send, victim_send, nocred_send


def _confirmed_finding(bug_class: str = "idor") -> dict:
    attacker_send, victim_send, nocred_send = _make_cross_target()
    cfg = AccessControlConfig(
        victim_send=victim_send, nocred_send=nocred_send,
        cross_specs=(CrossAccessSpec(bug_class=bug_class, ref_param="id", victim_ref=_VICTIM_REF,
                                     victim_discriminator=_VICTIM_SECRET, control_ref=_ATTACKER_OWN_REF),),
    )
    (check,) = build_access_control_checks(cfg, enabled=True)
    tmpl = RequestTemplate(HttpRequest(method="GET", url="http://target.test/obj?id=1"))
    point = next(p for p in tmpl.insertion_points(kinds=(InsertionKind.QUERY_VALUE,)) if p.name == "id")
    ctx = check.probe(tmpl, point, attacker_send)
    assert ctx is not None, "the sound cross-read did not produce a firing context"
    return access_control_finding(ctx, check_id=f"ac:{bug_class}:0", insertion_point="query:id")


def test_the_branches_are_registered_and_classes_map_to_them() -> None:
    for cls, branch in _BRANCH_FOR.items():
        assert branch in branch_ids(), f"{branch} not registered"
        assert _redrive_branch_for(cls) == branch
    # aliases resolve to the same branch
    assert _redrive_branch_for("broken_object_level_authorization") == "bola.cross_identity_read"
    assert _redrive_branch_for("broken_function_level_authorization") == "bfla.cross_identity_read"


def test_admitted_live_redrive_mints_a_signed_fact() -> None:
    finding = _confirmed_finding()
    assert OracleVerifier().confirm(finding["oracle_context"]).confirmed
    admitted = admit(_BRANCH, fired=True, conclusive=True, observed={"channel_established": True})
    assert admitted.verdict is Verdict.FACT
    res = certify_admitted(finding, admitted, engagement_slug="alpha",
                           signers=_signers(), provenance="live_redrive")
    assert res.is_fact, res.reason
    assert res.confirmed_by == OracleKind.ACHIEVED_STATE.value
    assert res.signed is not None


def test_llm_provenanced_context_is_demoted_to_a_lead() -> None:
    finding = _confirmed_finding()
    admitted = admit(_BRANCH, fired=True, conclusive=True, observed={"channel_established": True})
    res = certify_admitted(finding, admitted, engagement_slug="alpha",
                           signers=_signers(), provenance="llm")
    assert not res.is_fact
    assert res.signed is None


def test_offline_reverify_re_fires_and_rejects_tamper() -> None:
    finding = _confirmed_finding()
    finding["confirmed_by"] = OracleKind.ACHIEVED_STATE.value
    finding["confidence"] = 0.9
    good = reverify_finding(finding)
    assert good.reproduced and good.matches_claim is not False

    # tamper: strip the discriminator out of the attacker's body -> the predicate no longer holds
    octx = finding["oracle_context"]
    tampered_ev = {**octx["observed_evidence"], "attacker_body": "<html><nav>Home</nav><footer>Acme</footer></html>"}
    tampered = {**finding, "oracle_context": {**octx, "observed_evidence": tampered_ev}}
    bad = reverify_finding(tampered)
    assert not bad.reproduced or bad.matches_claim is False


def test_a_non_firing_cross_read_is_not_clean_only_inconclusive_or_lead() -> None:
    # These branches may never assert absence: a conclusive non-fire is INCONCLUSIVE, never CLEAN.
    admitted = admit(_BRANCH, fired=False, conclusive=True, observed={"channel_established": True})
    assert admitted.verdict is Verdict.INCONCLUSIVE
