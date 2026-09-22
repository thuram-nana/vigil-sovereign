"""
Stored / second-order XSS — STD-WIRING (Wave 2.1): admission → certify_admitted →
offline re-verify → tamper reject, over the registered ``stored_xss.dom_execution``
evidence branch.

This is the claim-discipline half of slice 2.1: a browser-confirmed stored-XSS is
minted ONLY through the admission choke (``verdict.admit`` → the FACT-capable
``stored_xss.dom_execution`` branch → ``oracle_adapter.certify_admitted(
provenance="live_redrive")``), the offline ``framework.v2 verify`` path re-fires the
retained ``oracle_context``, and a tampered canary is rejected. An LLM-provenanced
context is demoted to a LEAD (audit G4).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
for _p in (str(_ROOT / "engine" / "crucible"), str(_ROOT / "integration"),
           str(_ROOT / "packages" / "core" / "vigil_core")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from framework.v2.scanner.stored_xss import confirm_stored_xss, stored_xss_finding
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.models import OracleKind
from framework.v2.verify.reverify import reverify_finding
from framework.v2.verify.verifier import OracleVerifier

from vigil_integration.live.verdict import Verdict, admit, branch_ids
from vigil_integration.live.wiring import _redrive_branch_for
from vigil_integration.oracle_adapter import certify_admitted

_BRANCH = "stored_xss.dom_execution"


# -- stubs modelling an executing render surface B (no real browser needed) --


class _Store(dict):
    last: str = ""


def _gated_write(store: _Store):
    def gw(url: str, payload: str) -> bool:
        store[url] = payload
        store.last = payload
        return True
    return gw


class _StubSession:
    def __init__(self, store: _Store) -> None:
        self._store = store

    def add_binding(self, name: str) -> None:
        return None

    def navigate(self, url: str, *, settle: float = 0.4, timeout: float = 15.0) -> None:
        return None

    def binding_calls(self, name: str) -> list[str]:
        import re
        m = re.search(r"sxss[0-9a-f]{16}", self._store.last)
        return [m.group(0)] if m else []


class _StubBrowser:
    def __init__(self, store: _Store) -> None:
        self._store = store

    def start(self) -> "_StubBrowser":
        return self

    def session(self) -> _StubSession:
        return _StubSession(self._store)

    def stop(self) -> None:
        return None


def _signers():
    from vigil_core import generate_keypair
    kp = generate_keypair()
    return [("gov0", kp.private_key_b64)]


def _confirmed_finding() -> dict:
    store = _Store()
    results = confirm_stored_xss(
        "http://127.0.0.1:9/guestbook",
        "http://127.0.0.1:9/guestbook/view?name=guest",
        gated_write=_gated_write(store),
        browser=_StubBrowser(store),
        settle=0.0,
    )
    fired = [r for r in results if r.executed]
    assert fired, "stub render should have executed the persisted payload"
    return stored_xss_finding(fired[0])


# ---------------------------------------------------------------------------


def test_the_branch_is_registered_and_class_maps_to_it() -> None:
    assert _BRANCH in branch_ids()
    assert _redrive_branch_for("stored_xss") == _BRANCH
    assert _redrive_branch_for("second_order_xss") == _BRANCH


def test_admitted_live_redrive_mints_a_signed_fact() -> None:
    finding = _confirmed_finding()
    # the oracle fires over the retained context BEFORE any certificate exists
    assert OracleVerifier().confirm(finding["oracle_context"]).confirmed
    admitted = admit(_BRANCH, fired=True, conclusive=True,
                     observed={"channel_established": True})
    assert admitted.verdict is Verdict.FACT
    res = certify_admitted(finding, admitted, engagement_slug="alpha",
                           signers=_signers(), provenance="live_redrive")
    assert res.is_fact, res.reason
    assert res.confirmed_by == OracleKind.DOM_EXECUTION.value
    assert res.signed is not None


def test_llm_provenanced_context_is_demoted_to_a_lead() -> None:
    finding = _confirmed_finding()
    admitted = admit(_BRANCH, fired=True, conclusive=True,
                     observed={"channel_established": True})
    res = certify_admitted(finding, admitted, engagement_slug="alpha",
                           signers=_signers(), provenance="llm")
    assert not res.is_fact          # a crafted-but-firing LLM context never mints a FACT
    assert res.signed is None


def test_offline_reverify_re_fires_and_rejects_tamper() -> None:
    finding = _confirmed_finding()
    finding["confirmed_by"] = OracleKind.DOM_EXECUTION.value
    finding["confidence"] = 0.97
    good = reverify_finding(finding)
    assert good.reproduced and good.matches_claim is not False

    tampered = {**finding, "oracle_context": {**finding["oracle_context"],
                                              "dom_canary": "sxss" + "0" * 16}}
    bad = reverify_finding(tampered)
    assert not bad.reproduced or bad.matches_claim is False


def test_a_non_firing_render_is_not_clean_only_inconclusive_or_lead() -> None:
    # A stored-XSS branch may never assert absence: a conclusive non-fire is
    # INCONCLUSIVE (clean_capable=false), never CLEAN.
    admitted = admit(_BRANCH, fired=False, conclusive=True,
                     observed={"channel_established": True})
    assert admitted.verdict is Verdict.INCONCLUSIVE
