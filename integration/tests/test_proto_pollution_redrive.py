"""
Client-side prototype pollution — STD-WIRING (Wave 2.2): admission → certify_admitted →
offline re-verify → tamper reject, over the registered ``prototype_pollution.achieved_state``
evidence branch.

This is the claim-discipline half of slice 2.2: a browser-confirmed prototype pollution is
minted ONLY through the admission choke (``verdict.admit`` → the FACT-capable
``prototype_pollution.achieved_state`` branch → ``oracle_adapter.certify_admitted(
provenance="live_redrive")``), the offline ``framework.v2 verify`` path re-fires the retained
``oracle_context``, and a tampered value is rejected. An LLM-provenanced context is demoted to
a LEAD (audit G4). A conclusive non-fire is INCONCLUSIVE, never CLEAN.
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
for _p in (str(_ROOT / "engine" / "crucible"), str(_ROOT / "integration"),
           str(_ROOT / "packages" / "core" / "vigil_core")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from framework.v2.scanner.proto_pollution import confirm_proto_pollution, proto_pollution_finding
from framework.v2.verify.models import OracleKind
from framework.v2.verify.reverify import reverify_finding
from framework.v2.verify.verifier import OracleVerifier

from vigil_integration.live.verdict import Verdict, admit, branch_ids
from vigil_integration.live.wiring import _redrive_branch_for
from vigil_integration.oracle_adapter import certify_admitted

_BRANCH = "prototype_pollution.achieved_state"


# -- a stub browser modelling an ACHIEVED pollution readback (no real browser needed) --


class _StubSession:
    def __init__(self) -> None:
        self._calls: list[str] = []

    def add_binding(self, name: str) -> None:
        return None

    def navigate(self, url: str, *, settle: float = 0.4, timeout: float = 15.0) -> None:
        return None

    def evaluate(self, expression: str, **_kw):
        import json
        import re
        keys = re.findall(r'"(cpp_[0-9a-f]{12}|benign_[0-9a-f]{12})"', expression)
        if len(keys) < 2:
            return None
        key, benign = keys[0], keys[1]
        val = f"ppv_{key[len('cpp_'):]}"
        self._calls.append(json.dumps({"polluted_key": key, "polluted_val": val,
                                       "benign_key": benign, "benign_key_undefined": True}))
        return None

    def binding_calls(self, name: str) -> list[str]:
        return list(self._calls)


class _StubBrowser:
    def start(self) -> "_StubBrowser":
        return self

    def session(self) -> _StubSession:
        return _StubSession()

    def stop(self) -> None:
        return None


def _signers():
    from vigil_core import generate_keypair
    kp = generate_keypair()
    return [("gov0", kp.private_key_b64)]


def _confirmed_finding() -> dict:
    results = confirm_proto_pollution("http://127.0.0.1:9/proto", browser=_StubBrowser(), settle=0.0)
    fired = [r for r in results if r.polluted]
    assert fired, "stub readback should have reported achieved pollution"
    return proto_pollution_finding(fired[0])


# ---------------------------------------------------------------------------


def test_the_branch_is_registered_and_class_maps_to_it() -> None:
    assert _BRANCH in branch_ids()
    assert _redrive_branch_for("prototype_pollution") == _BRANCH
    assert _redrive_branch_for("client_side_prototype_pollution") == _BRANCH


def test_admitted_live_redrive_mints_a_signed_fact() -> None:
    finding = _confirmed_finding()
    assert OracleVerifier().confirm(finding["oracle_context"]).confirmed
    admitted = admit(_BRANCH, fired=True, conclusive=True, observed={"channel_established": True})
    assert admitted.verdict is Verdict.FACT
    res = certify_admitted(finding, admitted, engagement_slug="alpha",
                           signers=_signers(), provenance="live_redrive")
    assert res.is_fact, res.reason
    assert res.confirmed_by == OracleKind.PROTOTYPE_POLLUTION.value
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
    finding["confirmed_by"] = OracleKind.PROTOTYPE_POLLUTION.value
    finding["confidence"] = 0.96
    good = reverify_finding(finding)
    assert good.reproduced and good.matches_claim is not False

    tampered = {**finding, "oracle_context": {**finding["oracle_context"],
                                              "proto_pollution": {**finding["oracle_context"]["proto_pollution"],
                                                                  "polluted_val": "ppv_000000000000"}}}
    bad = reverify_finding(tampered)
    assert not bad.reproduced or bad.matches_claim is False


def test_a_non_firing_readback_is_not_clean_only_inconclusive_or_lead() -> None:
    # A prototype-pollution branch may never assert absence: a conclusive non-fire is
    # INCONCLUSIVE (clean_capable=false), never CLEAN.
    admitted = admit(_BRANCH, fired=False, conclusive=True, observed={"channel_established": True})
    assert admitted.verdict is Verdict.INCONCLUSIVE
