"""APEX PR-3 Deliverable 1 — chaining-to-DEMONSTRATED-impact (``framework.v2.apex_impact``).

Two layers:
  * unit — ``pursue_impact`` over synthetic paths: a hop is DEMONSTRATED only when its anchoring finding
    RE-FIRES (oracle re-execution — real and injected), the terminal impact is classified from the crown-jewel,
    and the ONLY target-touching arm (the live prover) runs ONLY after the injected gate ALLOWS it.
  * engage integration — a real loopback engagement proves the wire is flag-gated: flag OFF ⇒
    ``result.impact_report is None`` (byte-identical, the field keeps its default); flag ON ⇒ an ``ImpactReport``
    over the SAME oracle-confirmed findings, minting nothing.

Loopback pytest-httpserver only; nothing leaves the host. PYTHONPATH=engine/crucible:...
"""
from __future__ import annotations

from pathlib import Path

import pytest
from pytest_httpserver import HTTPServer
from werkzeug.wrappers import Response

from framework.v2.apex_impact import ImpactReport, apex_impact_enabled, pursue_impact
from framework.v2.common import paths as _paths
from framework.v2.engage import run_engagement
from framework.v2.scanner.campaign import ScanReport
from framework.v2.scanner.engine import AuditFinding
from framework.v2.scanner.orchestrator import AttackPath, AutonomousCampaign, ChainedConclusion
from framework.v2.worldmodel.graph import WorldModel

_SQL_ERROR = b"HTTP/1.1 500\r\n\r\nYou have an error in your SQL syntax near ''"
_BENIGN = b"HTTP/1.1 200\r\n\r\n{\"results\": []}"


def _context(body: bytes) -> dict:
    from framework.v2.evidence.poc import CapturedExchange
    from framework.v2.verify.poc_translate import context_from_exchanges
    ex = CapturedExchange(channel="error_signature", role="mutated", response_bytes_ref="resp")
    ctx = context_from_exchanges([ex], bug_class="error_based_sqli", resolve=lambda r: body)
    assert ctx is not None
    return ctx.model_dump(mode="json")


def _finding(param: str, body: bytes) -> AuditFinding:
    return AuditFinding(check_id=f"errsqli-{param}", bug_class="error_based_sqli",
                        insertion_point=f"query_value:{param}", param=param, confidence=0.9,
                        confirmed_by="error_signature", oracle_context=_context(body))


def _path_to(dst: str, src: str = "attacker:self", edge: str = "REACHED",
             technique: str = "finding:error_based_sqli") -> AttackPath:
    return AttackPath(steps=[ChainedConclusion(src=src, edge=edge, dst=dst, technique=technique)])


class _V:
    def __init__(self, allowed, reason=""):
        self.allowed, self.reason = allowed, reason


# =====================================================================================================
# unit — DEMONSTRATED requires a real oracle RE-FIRE
# =====================================================================================================


def test_real_reverify_marks_foothold_demonstrated():
    report = ScanReport(target="http://t/", active_findings=[_finding("q", _SQL_ERROR)])
    rep = pursue_impact(report, WorldModel(), [_path_to("endpoint:q")], slug="x")
    assert isinstance(rep, ImpactReport) and len(rep.demonstrations) == 1
    d = rep.demonstrations[0]
    assert d.demonstrated and d.foothold_findings == ["errsqli-q"]
    assert rep.demonstrated_paths == 1


def test_non_reproducing_finding_stays_reasoned():
    # the SAME endpoint, but the retained context is benign ⇒ the oracle does NOT re-fire ⇒ REASONED, not demonstrated
    report = ScanReport(target="http://t/", active_findings=[_finding("q", _BENIGN)])
    rep = pursue_impact(report, WorldModel(), [_path_to("endpoint:q")], slug="x")
    d = rep.demonstrations[0]
    assert not d.demonstrated and d.foothold_findings == [] and rep.demonstrated_paths == 0


def test_injected_reverify_controls_the_demonstrated_flag():
    report = ScanReport(target="http://t/", active_findings=[_finding("q", _BENIGN)])

    class _RR:
        def __init__(self, ok):
            self.reproduced = ok
    rep = pursue_impact(report, WorldModel(), [_path_to("endpoint:q")], slug="x",
                        reverify=lambda ctx, **_k: _RR(True))
    assert rep.demonstrations[0].demonstrated


# =====================================================================================================
# unit — terminal impact classified from the crown jewel; mints nothing
# =====================================================================================================


def test_terminal_impact_classified_from_datastore_path():
    # a confirmed IDOR chains (orchestrator._establish_topology) to a backing DATASTORE crown jewel
    report = ScanReport(target="http://t/", active_findings=[
        AuditFinding(check_id="idor-1", bug_class="idor", insertion_point="query_value:id", param="id",
                     confidence=0.9, confirmed_by="achieved_state",
                     oracle_context=_context(_SQL_ERROR))])
    result = AutonomousCampaign(lambda req: {"status": 200, "body": ""}).chain_findings(report)
    assert result.attack_paths, "the IDOR finding should chain to a datastore crown jewel"
    rep = pursue_impact(report, result.world, result.attack_paths, slug="x",
                        reverify=lambda ctx, **_k: type("R", (), {"reproduced": True})())
    # every path reaching the backing datastore is classified data_access
    assert any(d.terminal_impact == "data_access" for d in rep.demonstrations), \
        [d.terminal_impact for d in rep.demonstrations]


# =====================================================================================================
# unit — the gate is the ONLY authorizer of live pursuit (the one target-touching arm)
# =====================================================================================================


def test_gate_deny_keeps_demonstration_reasoned_only():
    report = ScanReport(target="http://t/", active_findings=[_finding("q", _SQL_ERROR)])
    pursued = {"n": 0}

    def _prover(_f):
        pursued["n"] += 1
        return True
    rep = pursue_impact(report, WorldModel(), [_path_to("endpoint:q")], slug="x",
                        gate=lambda *a, **k: _V(False, "out of scope"), live_prover=_prover)
    d = rep.demonstrations[0]
    assert d.authorization.startswith("denied:") and not d.live_demonstrated
    assert pursued["n"] == 0 and rep.live_pursued == 0   # the prover is NEVER called when the gate denies


def test_gate_allow_and_prover_marks_live_demonstrated():
    report = ScanReport(target="http://t/", active_findings=[_finding("q", _SQL_ERROR)])
    rep = pursue_impact(report, WorldModel(), [_path_to("endpoint:q")], slug="x",
                        gate=lambda *a, **k: _V(True, "allow"), live_prover=lambda _f: True)
    d = rep.demonstrations[0]
    assert d.authorization == "allowed" and d.live_demonstrated and rep.live_pursued == 1


def test_no_gate_is_unchecked_offline_only():
    report = ScanReport(target="http://t/", active_findings=[_finding("q", _SQL_ERROR)])
    rep = pursue_impact(report, WorldModel(), [_path_to("endpoint:q")], slug="x")   # no gate, no prover
    d = rep.demonstrations[0]
    assert d.authorization == "unchecked" and not d.live_demonstrated and rep.live_pursued == 0


def test_raising_gate_fails_closed_to_denied():
    report = ScanReport(target="http://t/", active_findings=[_finding("q", _SQL_ERROR)])

    def _boom(*_a, **_k):
        raise RuntimeError("gate blew up")
    rep = pursue_impact(report, WorldModel(), [_path_to("endpoint:q")], slug="x",
                        gate=_boom, live_prover=lambda _f: True)
    assert rep.demonstrations[0].authorization.startswith("denied:gate-error")
    assert not rep.demonstrations[0].live_demonstrated


def test_flag_default_off():
    import os
    os.environ.pop("VIGIL_APEX_IMPACT", None)
    assert apex_impact_enabled() is False


# =====================================================================================================
# engage integration — the wire is flag-gated; OFF is byte-identical (impact_report stays None)
# =====================================================================================================

_CHARTER = """\
# Engagement charter — `{slug}`

**Status:** Final

## 1. Operator attestation

Signed: `tester`     Date: `2026-05-04`

## 2. In-scope systems

| Host / Surface | Notes | Auth |
|----------------|-------|------|
| `{host}` | Test app | Yes |

## 3. Out of scope

- Anything not listed above.

## 7. Posture

- [x] **TEST**
- [ ] **AUDIT**
- [ ] **EMULATE**
"""


@pytest.fixture()
def isolated_engagement(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    targets_root = tmp_path / "targets"
    targets_root.mkdir()

    def build(slug: str, host: str) -> Path:
        td = targets_root / slug
        td.mkdir(parents=True, exist_ok=True)
        (td / "charter.md").write_text(_CHARTER.format(slug=slug, host=host), encoding="utf-8")
        return td

    monkeypatch.setattr(_paths, "target_dir", lambda s: targets_root / s)
    monkeypatch.setattr(_paths, "charter_path", lambda s: targets_root / s / "charter.md")
    monkeypatch.setattr(_paths, "killswitch_path", lambda s: targets_root / s / ".halt")
    return build


def _root(request) -> Response:
    return Response('<a href="/search?q=hi">search</a>', status=200, mimetype="text/html")


def _search(request) -> Response:
    q = request.args.get("q", "")
    if "'1'='1" in q or "1=1" in q:
        body = "echo:" + q + "\n" + "".join(f"user{i}:secret{i}\n" for i in range(40))
    else:
        body = "echo:" + q
    return Response(body, status=200, mimetype="text/html")


def _deny(_q: str, _t: float) -> bool:
    return False


def test_engage_impact_report_flag_off_is_none(isolated_engagement, httpserver: HTTPServer,
                                               monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("VIGIL_APEX_IMPACT", raising=False)
    port = httpserver.port
    isolated_engagement("offa", "127.0.0.1")
    httpserver.expect_request("/").respond_with_handler(_root)
    httpserver.expect_request("/search").respond_with_handler(_search)
    result = run_engagement("offa", f"http://127.0.0.1:{port}/", max_pages=5, enable_oob=False,
                            prompt_callback=_deny)
    assert result.report.active_findings, "engage confirmed nothing against a vulnerable target"
    # flag OFF ⇒ the impact pass never runs ⇒ the field keeps its None default (byte-identical)
    assert result.impact_report is None


def test_engage_impact_report_flag_on_is_populated(isolated_engagement, httpserver: HTTPServer,
                                                   monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("VIGIL_APEX_IMPACT", "1")
    port = httpserver.port
    isolated_engagement("ona", "127.0.0.1")
    httpserver.expect_request("/").respond_with_handler(_root)
    httpserver.expect_request("/search").respond_with_handler(_search)
    result = run_engagement("ona", f"http://127.0.0.1:{port}/", max_pages=5, enable_oob=False,
                            prompt_callback=_deny)
    assert result.report.active_findings
    # flag ON ⇒ a demonstrated-impact report is produced over the confirmed findings (mints nothing)
    assert isinstance(result.impact_report, ImpactReport)
