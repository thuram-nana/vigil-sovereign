"""
HTTP request smuggling — STD-WIRING (Wave 4.2): admission -> certify_admitted -> offline re-verify ->
tamper reject, over the registered ``request_smuggling.differential_desync`` DIFFERENTIAL_RESPONSE branch,
PLUS the gated raw-socket re-drive driven end-to-end against the planted desync fixture and its benign twin.

This retires audit A12 (#269): request_smuggling is no longer a TIMING LEAD. It is minted ONLY through the
admission choke (``verdict.admit`` -> the FACT-capable ``request_smuggling.differential_desync`` branch ->
``oracle_adapter.certify_admitted(provenance="live_redrive")``), the offline ``framework.v2 verify`` path
re-fires the retained ``oracle_context``, and a tampered value is rejected. An LLM-provenanced context is
demoted to a LEAD (audit G4). A conclusive non-fire is INCONCLUSIVE, never CLEAN.

The differential is what makes it sound (timing was demoted precisely because a normal origin awaiting an
incomplete declared body delays identically): a UNIQUE per-probe canary VIGIL embeds in the smuggled prefix
must be ECHOED in VIGIL's OWN second-request response on the CONFLICT connection AND ABSENT from an identical
WELL-FORMED control connection's second response. The benign twin (a well-behaved / anti-smuggling back-end)
never leaks the canary, so it must NEVER be flagged. The raw-socket path is re-gated through
``validate_action`` + DNS-pin before any byte leaves the box (a raw socket bypassing the sovereign transport
would be an egress hole).
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
for _p in (str(_ROOT / "engine" / "crucible"), str(_ROOT / "integration"),
           str(_ROOT / "packages" / "core" / "vigil_core")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import pytest

from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.models import OracleKind
from framework.v2.verify.reverify import reverify_finding
from framework.v2.verify.verifier import OracleVerifier

from vigil_integration.live.smuggling_redrive import _BRANCH_FOR, smuggling_redrive
from vigil_integration.live.verdict import Verdict, admit, branch_ids
from vigil_integration.live.wiring import _redrive_branch_for
from vigil_integration.oracle_adapter import certify_admitted

_BRANCH = "request_smuggling.differential_desync"
_CANARY = "vgsmug" + "a1b2c3d4e5f6a7b8c9d0"


def _signers():
    from vigil_core import generate_keypair
    kp = generate_keypair()
    return [("gov0", kp.private_key_b64)]


def _confirmed_ctx(*, conflict_body=None, control_body="vigil-follow ok"):
    if conflict_body is None:
        conflict_body = f"HTTP/1.1 200 OK\r\n\r\nreflected c={_CANARY}"
    return FindingContext.from_smuggling_desync(
        canary=_CANARY, technique="CL.TE",
        conflict_second={"channel": True, "status": 200, "reason": "OK", "body": conflict_body},
        control_second={"channel": True, "status": 200, "reason": "OK", "body": control_body},
    ).to_verifier_context()


def _finding(ctx):
    return {"check_id": f"smug:CL.TE#{_BRANCH}", "bug_class": "request_smuggling",
            "insertion_point": "request:CL.TE", "oracle_context": ctx}


# -- STD-WIRING (hermetic) -----------------------------------------------------------------------------

def test_the_branch_is_registered_and_the_class_maps_to_it() -> None:
    assert _BRANCH in branch_ids()
    assert _BRANCH_FOR["request_smuggling"] == _BRANCH
    assert _redrive_branch_for("request_smuggling") == _BRANCH
    assert _redrive_branch_for("http_request_smuggling") == _BRANCH


def test_admitted_live_redrive_mints_a_signed_fact() -> None:
    ctx = _confirmed_ctx()
    assert OracleVerifier().confirm(ctx).confirmed
    admitted = admit(_BRANCH, fired=True, conclusive=True,
                     observed={"channel_established": True,
                               "conflict_and_control_second_requests_captured": True,
                               "unique_canary_minted": True, "raw_socket_action_validated": True})
    assert admitted.verdict is Verdict.FACT
    res = certify_admitted(_finding(ctx), admitted, engagement_slug="alpha",
                           signers=_signers(), provenance="live_redrive")
    assert res.is_fact, res.reason
    assert res.confirmed_by == OracleKind.DIFFERENTIAL_RESPONSE.value
    assert res.signed is not None


def test_llm_provenanced_context_is_demoted_to_a_lead() -> None:
    ctx = _confirmed_ctx()
    admitted = admit(_BRANCH, fired=True, conclusive=True,
                     observed={"channel_established": True,
                               "conflict_and_control_second_requests_captured": True,
                               "unique_canary_minted": True, "raw_socket_action_validated": True})
    res = certify_admitted(_finding(ctx), admitted, engagement_slug="alpha",
                           signers=_signers(), provenance="llm")
    assert not res.is_fact
    assert res.signed is None


def test_offline_reverify_re_fires_and_rejects_tamper() -> None:
    finding = _finding(_confirmed_ctx())
    finding["confirmed_by"] = OracleKind.DIFFERENTIAL_RESPONSE.value
    finding["confidence"] = 0.95
    good = reverify_finding(finding)
    assert good.reproduced and good.matches_claim is not False

    # tamper: strip the canary out of the conflict leg's second response -> the differential no longer holds
    octx = finding["oracle_context"]
    sd = octx["smuggling_desync"]
    tampered = {**finding, "oracle_context": {**octx, "smuggling_desync": {
        **sd, "conflict": {**sd["conflict"], "body": "HTTP/1.1 200 OK\r\n\r\nno canary here"}}}}
    bad = reverify_finding(tampered)
    assert not bad.reproduced or bad.matches_claim is False


def test_a_non_firing_desync_is_not_clean_only_inconclusive_or_lead() -> None:
    # This branch may never assert absence: a conclusive non-fire is INCONCLUSIVE, never CLEAN.
    admitted = admit(_BRANCH, fired=False, conclusive=True,
                     observed={"channel_established": True,
                               "conflict_and_control_second_requests_captured": True,
                               "unique_canary_minted": True, "raw_socket_action_validated": True})
    assert admitted.verdict is Verdict.INCONCLUSIVE
    # a canary that ALSO echoes in the control -> not attributable -> INCONCLUSIVE (fired False, non-conclusive)
    benign = _confirmed_ctx(control_body=f"reflected c={_CANARY}")
    assert not OracleVerifier().confirm(benign).confirmed


# -- LIVE gated raw-socket re-drive against the planted fixture + benign twin --------------------------

def _isolate(tmp_path, monkeypatch):
    from framework.v2 import entitlement
    from framework.v2.common import paths
    monkeypatch.setattr(paths, "killswitch_path", lambda slug: tmp_path / f"{slug}.halt")
    monkeypatch.setattr(paths, "target_dir", lambda slug: tmp_path / slug)
    monkeypatch.setattr(paths, "charter_path", lambda slug: tmp_path / slug / "charter.md")
    monkeypatch.setattr(entitlement, "require_capability", lambda cap: None)


def _charter(tmp_path, host, slug="alpha"):
    d = tmp_path / slug
    d.mkdir(parents=True, exist_ok=True)
    (d / "charter.md").write_text(
        f"# Engagement charter — `{slug}`\n\n**Status:** Final\n\n## 1. Operator attestation\n\n"
        f"Signed: `tester`     Date: `2026-09-24`\n\n## 2. In-scope systems\n\n"
        f"| Host | Notes | Auth |\n|---|---|---|\n| `{host}` | Host | Yes |\n\n"
        f"## 7. Posture\n\n- [x] **TEST**\n", encoding="utf-8")


def test_live_redrive_mints_a_fact_against_the_desync_fixture(tmp_path, monkeypatch) -> None:
    from framework.v2.eval.benchmark_app import serve_smuggling_desync
    _isolate(tmp_path, monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    with serve_smuggling_desync() as url:
        res = smuggling_redrive(url, slug="alpha", engagement_slug="alpha", signers=_signers(), timeout=4.0)
    assert not res.refused, res.notes
    assert res.n_facts == 1, f"expected a desync FACT; notes={res.notes} admissions={res.admissions}"
    fact = res.facts[0]
    assert fact.is_fact and fact.confirmed_by == OracleKind.DIFFERENTIAL_RESPONSE.value
    assert fact.signed is not None


def test_live_redrive_never_flags_the_benign_twin(tmp_path, monkeypatch) -> None:
    from framework.v2.eval.benchmark_app import serve_smuggling_benign
    _isolate(tmp_path, monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    with serve_smuggling_benign() as url:
        res = smuggling_redrive(url, slug="alpha", engagement_slug="alpha", signers=_signers(), timeout=4.0)
    assert res.n_facts == 0, f"benign twin was flagged: {res.admissions}"
    assert not res.leads, "a well-behaved server produced a LEAD-worthy signal (it should not)"


def test_live_redrive_never_flags_the_reflect_on_error_twin(tmp_path, monkeypatch) -> None:
    # RED-PEN REGRESSION: a benign server that rejects the ambiguous conflict framing with a 400 whose body
    # ECHOES the request (canary and all), yet answers the well-formed control cleanly. The echoed canary lives
    # ONLY in the FIRST response; VIGIL's GENUINE second (follow-up) request response carries none — so the
    # differential must NOT hold. The retired lexical-split hack mis-split the 400 body into a fake "second
    # response" and minted a FALSE desync FACT here; the real second-request re-drive must never fire.
    from framework.v2.eval.benchmark_app import serve_smuggling_reflect_error
    _isolate(tmp_path, monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    with serve_smuggling_reflect_error() as url:
        res = smuggling_redrive(url, slug="alpha", engagement_slug="alpha", signers=_signers(), timeout=4.0)
    assert res.n_facts == 0, f"reflect-on-error twin was flagged as a desync FACT: {res.admissions}"
    assert not res.leads, "the reflect-on-error twin produced a LEAD-worthy desync signal (it should not)"


def test_live_redrive_refuses_without_a_signed_charter(tmp_path, monkeypatch) -> None:
    # The raw-socket burst is gated: with no charter (validate_action refuses) no byte leaves the box.
    from framework.v2.eval.benchmark_app import serve_smuggling_desync
    _isolate(tmp_path, monkeypatch)   # patches charter_path at an EMPTY tmp dir — no charter written
    with serve_smuggling_desync() as url:
        res = smuggling_redrive(url, slug="alpha", engagement_slug="alpha", signers=_signers(), timeout=4.0)
    assert res.refused
    assert res.n_facts == 0
