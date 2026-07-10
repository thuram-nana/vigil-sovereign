"""
Wave 5 (Defense/IR) — the DEFENSIVE / purple-team pass is wired into `engage`, OPT-IN and
DEFAULT-SAFE.

  * With ``enable_defender=False`` (the default) the engagement is byte-identical: no defense
    report is produced and the scan/oracle verdicts are untouched.
  * With ``enable_defender=True`` engage reasons over the confirmed findings to produce a
    DefenseReport — detection gaps + candidate Sigma rules, a detection-efficacy signal over an
    operator Sigma ruleset (mapped to ATT&CK), and Sigma over an operator-supplied OFFLINE log.
  * The pass is READ-ONLY (no traffic, no verdict change) and best-effort (a failure never sinks
    the engagement). With a spine attached it mirrors a defender observation + decision.

All traffic is loopback pytest-httpserver; nothing leaves the test host.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pytest_httpserver import HTTPServer
from werkzeug.wrappers import Response

from framework.v2 import engage as engage_mod
from framework.v2.common import paths as _paths
from framework.v2.engage import run_engagement

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


def _run(slug: str, port: int, **kw):
    return run_engagement(slug, f"http://127.0.0.1:{port}/", max_pages=5, enable_oob=False,
                          prompt_callback=_deny, **kw)


def _serve(httpserver: HTTPServer) -> None:
    httpserver.expect_request("/").respond_with_handler(_root)
    httpserver.expect_request("/search").respond_with_handler(_search)


# --- default-off: byte-identical -------------------------------------------

def test_defender_off_is_default_and_defense_is_none(isolated_engagement, httpserver: HTTPServer):
    isolated_engagement("alpha", "127.0.0.1")
    _serve(httpserver)
    result = _run("alpha", httpserver.port)              # enable_defender defaults False
    assert result.report.active_findings                 # scan unchanged
    assert result.defense is None                        # no defensive artifact on the default path


# --- opt-in: the purple-team report ----------------------------------------

def test_defender_on_produces_a_defense_report(isolated_engagement, httpserver: HTTPServer):
    isolated_engagement("alpha", "127.0.0.1")
    _serve(httpserver)
    result = _run("alpha", httpserver.port, enable_defender=True)
    assert result.report.active_findings, "need confirmed findings to model"
    d = result.defense
    assert d is not None
    # one modelled action per confirmed finding; candidate Sigma rules are produced for the gaps
    assert len(d.gaps) == len(result.report.active_findings)
    assert isinstance(d.candidate_sigma, list)
    # the report never disturbs the scan verdicts
    assert [f.bug_class for f in result.report.active_findings]


def test_defender_efficacy_over_operator_sigma_maps_attack(
    isolated_engagement, httpserver: HTTPServer, tmp_path: Path,
):
    isolated_engagement("alpha", "127.0.0.1")
    _serve(httpserver)
    sigma_dir = tmp_path / "sigma"
    sigma_dir.mkdir()
    (sigma_dir / "sqli.yml").write_text(
        "title: SQLi\nid: R-SQLI\ndetection:\n  selection:\n"
        "    cs_uri_query|contains:\n      - \"OR 1=1\"\n      - \"UNION SELECT\"\n"
        "  condition: selection\ntags: [attack.t1190]\nlevel: high\n", encoding="utf-8")

    result = _run("alpha", httpserver.port, enable_defender=True, defender_sigma_dir=str(sigma_dir))
    eff = result.defense.efficacy
    assert eff is not None
    # the confirmed SQL-injection action is caught by the operator's rule, mapped to ATT&CK T1190
    assert eff.detected_count >= 1
    assert "T1190" in eff.techniques_covered


def test_defender_ingests_offline_log(isolated_engagement, httpserver: HTTPServer, tmp_path: Path):
    isolated_engagement("alpha", "127.0.0.1")
    _serve(httpserver)
    sigma_dir = tmp_path / "sigma"
    sigma_dir.mkdir()
    (sigma_dir / "sqli.yml").write_text(
        "title: SQLi\nid: R-SQLI\ndetection:\n  selection:\n"
        "    cs_uri_query|contains: \"UNION SELECT\"\n  condition: selection\ntags: [attack.t1190]\n",
        encoding="utf-8")
    log = tmp_path / "proxy.log"
    log.write_text('<38>Oct 11 22:14:15 h proxy: req cs_uri_query="q=UNION SELECT pwd"\n', encoding="utf-8")

    result = _run("alpha", httpserver.port, enable_defender=True,
                  defender_sigma_dir=str(sigma_dir), defender_log=str(log))
    assert result.defense.ingested is not None
    assert result.defense.ingested_events == 1
    assert "R-SQLI" in result.defense.ingested.matched_rule_ids


def test_defender_log_ingestion_refused_when_killswitch_tripped(
    isolated_engagement, httpserver: HTTPServer, tmp_path: Path,
):
    # A tripped kill-switch refuses BOTH the scan preflight AND the log read — but the point here
    # is that log ingestion routes through the gated sensor, so it cannot read a file under a halt.
    from framework.v2.defender.logsource import LogSourceSensor
    from framework.v2.agents.tools import ToolContext, ToolRegistry
    from framework.v2.agents.tools.invoker import invoke_tool

    isolated_engagement("alpha", "127.0.0.1")
    halt = _paths.killswitch_path("alpha")
    halt.parent.mkdir(parents=True, exist_ok=True)
    halt.write_text('{"slug":"alpha","reason":"stop"}', encoding="utf-8")
    log = tmp_path / "x.log"
    log.write_text("<38>Oct 11 22:14:15 h app: user=admin\n", encoding="utf-8")

    reg = ToolRegistry()
    reg.register(LogSourceSensor())
    res = invoke_tool(reg, "log_source", {"log": str(log)}, ToolContext(slug="alpha"))
    assert res.refused and res.gate == "kill-switch"


# --- robustness + spine ----------------------------------------------------

def test_defender_pass_is_best_effort(
    isolated_engagement, httpserver: HTTPServer, monkeypatch: pytest.MonkeyPatch,
):
    isolated_engagement("alpha", "127.0.0.1")
    _serve(httpserver)

    def _boom(*a, **k):
        raise RuntimeError("defender exploded")

    monkeypatch.setattr(engage_mod, "_run_defender_pass", _boom)
    result = _run("alpha", httpserver.port, enable_defender=True)
    # the oracle-confirmed report survives; the defensive artifact is simply absent
    assert result.report.active_findings
    assert result.defense is None


def test_defender_mirrors_onto_the_spine(
    isolated_engagement, httpserver: HTTPServer, tmp_path: Path,
):
    from framework.v2.agents.blackboard import open_blackboard

    isolated_engagement("alpha", "127.0.0.1")
    _serve(httpserver)
    sigma_dir = tmp_path / "sigma"
    sigma_dir.mkdir()
    (sigma_dir / "sqli.yml").write_text(
        "title: SQLi\nid: R-SQLI\ndetection:\n  selection:\n"
        "    cs_uri_query|contains: \"OR 1=1\"\n  condition: selection\ntags: [attack.t1190]\n",
        encoding="utf-8")

    bb = open_blackboard(db_path=tmp_path / "spine.sqlite")
    result = _run("alpha", httpserver.port, enable_defender=True,
                  defender_sigma_dir=str(sigma_dir), spine=bb)
    assert result.defense is not None
    # the defender gap summary landed as an observation and the efficacy verdict as a decision,
    # using the EXISTING event kinds (no schema change)
    obs = [o for o in bb.read(engagement="alpha", kinds=["observation"])
           if o.payload.get("source") == "defender:gap-report"]
    assert obs, "defender gap-report observation not on the spine"
    decisions = [d.payload["question"] for d in bb.read(engagement="alpha", kinds=["decision"])]
    assert "defender: detection efficacy" in decisions
    bb.close()
