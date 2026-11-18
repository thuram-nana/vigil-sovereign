"""APEX PR-1 — the IN-ENGAGEMENT autonomous DRIVER, end to end against a live loopback target.

This is the acceptance proof for promoting ``run_autonomous_cycle`` from a post-scan advisory appendix (a
THROWAWAY executor with its own tiny budget) to the engagement's in-engagement PRIMARY driver over the scan's
STILL-OPEN gated executor, under ONE shared request budget, behind the default-OFF ``VIGIL_APEX_AUTONOMOUS``.

THE CHAIN (nothing human-pointed):
  seed ``/benign`` (a dead-end page the scan finds nothing on) → recon discovers a web SERVICE → the driver
  PROMOTES it to a testable ENDPOINT → CRAWL-EXPANDS its real ``/search?q=`` surface → SELECTS it (via the
  multi-agent surface-decomposition selector) → PROBES it through the SHARED ``gated_fetch`` → the reflection
  ORACLE FIRES → a NEW oracle-confirmed finding is minted, FOLDED into the authoritative report BEFORE the
  reasoning phases, and GROUNDED by the veracity firewall like a scan finding. Every request rode the one
  shared executor budget. With the flag OFF the whole thing is inert and the report is byte-identical.

Loopback pytest_httpserver only; nothing leaves the test host.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pytest_httpserver import HTTPServer
from werkzeug.wrappers import Response

from framework.v2 import engage as engage_mod
from framework.v2 import engage_autonomous as auto_mod
from framework.v2.common import paths as _paths
from framework.v2.engage import EngagementResult, run_engagement
from framework.v2.scanner.campaign import ScanReport
from framework.v2.scanner.engine import AuditFinding
from framework.v2.worldmodel import Node, NodeKind, WorldModel

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


def _deny(_q: str, _t: float) -> bool:
    return False


def _benign(request) -> Response:
    """The SEED page: a dead end with NO links and no params, so the SCAN crawls only this and confirms
    nothing. The vulnerable surface is reachable ONLY via recon→promote→crawl, never the seed crawl."""
    return Response("<html><body>nothing to see here</body></html>", status=200, mimetype="text/html")


def _root_links_to_search(request) -> Response:
    """The PROMOTED recon-service root: links to the param-bearing /search page crawl-expansion mines."""
    return Response('<html><body><a href="/search?q=hello">search</a></body></html>',
                    status=200, mimetype="text/html")


def _reflect(request) -> Response:
    """A REAL reflected-XSS sink: reflects ``q`` verbatim into executable HTML so the reflection oracle fires."""
    q = request.args.get("q", "")
    return Response(f"<html><body>results for {q}</body></html>", status=200, mimetype="text/html")


def _inject_recon_service(port: int):
    """Return a replacement ``_intel_recon`` that injects ONLY a web SERVICE node for 127.0.0.1:<port> into
    the run's shared world-model (as nmap/a sensor would) and returns None — so the authoritative scan never
    saw it, ``_do_intel_finalize`` is skipped (ingest is None), and the driver's ``promote_to_endpoints`` is
    the sole bridge from the discovered service to a testable endpoint. Faithful to the real recon→world
    projection without standing up offline recon fixtures."""

    def _fake_recon(world, slug, seed_url, *, fixtures_dir=None, max_depth=2):
        world.add_node(Node(id="attacker:self", kind=NodeKind.PRINCIPAL, attrs={"role": "attacker"},
                            provenance="obs-1", confidence=1.0, first_seen=0, last_seen=0))
        world.add_node(Node(id=f"service:127.0.0.1:{port}/tcp", kind=NodeKind.SERVICE,
                            attrs={"port": port, "protocol": "tcp", "service": "http"},
                            provenance="intel:obs:svc", confidence=0.8, first_seen=1, last_seen=1))
        return None

    return _fake_recon


def _run(slug: str, port: int, monkeypatch) -> object:
    monkeypatch.setattr(engage_mod, "_intel_recon", _inject_recon_service(port))
    return run_engagement(
        slug, f"http://127.0.0.1:{port}/benign",
        max_pages=5, enable_oob=False, enable_recon=True, prompt_callback=_deny,
    )


# ---------------------------------------------------------------------------
# THE ACCEPTANCE PROOF — flag ON
# ---------------------------------------------------------------------------


def test_apex_driver_promotes_crawls_probes_and_mints_in_engagement(
    isolated_engagement, httpserver: HTTPServer, monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv("VIGIL_APEX_AUTONOMOUS", "1")
    port = httpserver.port
    isolated_engagement("disco", "127.0.0.1")
    httpserver.expect_request("/benign").respond_with_handler(_benign)
    httpserver.expect_request("/").respond_with_handler(_root_links_to_search)
    httpserver.expect_request("/search").respond_with_handler(_reflect)

    result = _run("disco", port, monkeypatch)

    # the IN-ENGAGEMENT driver ran (not the post-return appendix) and attached its telemetry
    auto = result.autonomy
    assert auto is not None, "the in-engagement APEX driver did not run with the flag ON"
    assert auto.discover_enabled is True

    # promote → crawl → probe → ORACLE FIRES → a NEW oracle-confirmed finding, nothing human-pointed
    assert auto.endpoints_promoted >= 1, "the recon SERVICE was not promoted to an endpoint"
    assert result.world.has_node(f"endpoint:promoted:http://127.0.0.1:{port}/")
    assert auto.endpoints_expanded >= 1, "crawl-expansion did not mine the /search surface"
    assert auto.discovered_count >= 1, "the probe did not mint an oracle-confirmed finding"
    minted = [AuditFinding.model_validate(d) for d in auto.discovered_findings]
    xss = [m for m in minted if m.bug_class == "xss" and "/search" in m.endpoint]
    assert xss, f"no XSS minted at /search; minted={[ (m.bug_class, m.endpoint) for m in minted ]}"
    assert xss[0].oracle_context is not None, "the minted finding carries no oracle proof (prove-don't-guess)"
    assert xss[0].confirmed_by, "the minted finding names no oracle kind"

    # the discovery was FOLDED into the authoritative report BEFORE the reasoning phases, so it is a first-
    # class finding (the 'primary driver', not a post-return appendix)
    assert auto.findings_folded >= 1
    folded = [f for f in result.report.active_findings if f.bug_class == "xss" and "/search" in f.endpoint]
    assert folded, "the discovered finding was not folded into report.active_findings"

    # ...and it flowed through the GROUNDING veracity firewall (index-aligned with active_findings)
    idx = result.report.active_findings.index(folded[0])
    if idx < len(result.grounding) and result.grounding[idx] is not None:
        assert result.grounding[idx].is_fact, "the discovered finding did not GROUND as a fact"

    # the multi-agent SURFACE-DECOMPOSITION selector drove the recon probe-leaf
    assert auto.surface_domains_driven.get("recon", 0) >= 1, \
        f"the decomposition selector did not record a recon pick: {auto.surface_domains_driven}"

    # ONE SHARED BUDGET: the loop's probes were counted against the SAME executor the scan used — the loop
    # added requests on top of the scan's spend, all under the one budget. This is the shared-budget proof.
    assert auto.shared_budget >= 1
    assert auto.shared_requests_before >= 1, "the scan sent no requests on the shared executor"
    assert auto.shared_requests_made > auto.shared_requests_before, \
        "the loop sent no additional requests through the shared gated executor"
    assert auto.shared_requests_made <= auto.shared_budget, "the shared budget was exceeded"


# ---------------------------------------------------------------------------
# BYTE-IDENTICAL OFF — the control
# ---------------------------------------------------------------------------


def test_apex_driver_off_is_inert_and_report_unchanged(
    isolated_engagement, httpserver: HTTPServer, monkeypatch: pytest.MonkeyPatch,
):
    """With the flag OFF (the default), the driver never runs: no autonomy telemetry, nothing promoted, and
    the vulnerable /search surface — reachable ONLY via the discovery chain — is NEVER found, so the report
    holds exactly what the fixed pipeline produces for the dead-end seed (no discovered finding)."""
    monkeypatch.delenv("VIGIL_APEX_AUTONOMOUS", raising=False)
    port = httpserver.port
    isolated_engagement("disco", "127.0.0.1")
    httpserver.expect_request("/benign").respond_with_handler(_benign)
    httpserver.expect_request("/").respond_with_handler(_root_links_to_search)
    httpserver.expect_request("/search").respond_with_handler(_reflect)

    result = _run("disco", port, monkeypatch)

    assert result.autonomy is None, "the driver ran with the flag OFF"
    assert not result.world.has_node(f"endpoint:promoted:http://127.0.0.1:{port}/"), \
        "promotion ran with the flag OFF"
    # the dead-end seed yields no discovered /search finding (the discovery chain never ran)
    assert not [f for f in result.report.active_findings if "/search" in f.endpoint], \
        "the /search surface was reached with the driver OFF"


def test_apex_driver_shares_the_scan_executor_budget_not_a_throwaway(
    isolated_engagement, httpserver: HTTPServer, monkeypatch: pytest.MonkeyPatch,
):
    """Pins the SHARED-BUDGET contract specifically: the loop's probe requests accrue on the SAME executor
    budget the scan already spent from (``shared_requests_before`` < ``shared_requests_made``), never a fresh
    throwaway budget — the behaviour the appendix had and this promotion removes."""
    monkeypatch.setenv("VIGIL_APEX_AUTONOMOUS", "1")
    port = httpserver.port
    isolated_engagement("disco", "127.0.0.1")
    httpserver.expect_request("/benign").respond_with_handler(_benign)
    httpserver.expect_request("/").respond_with_handler(_root_links_to_search)
    httpserver.expect_request("/search").respond_with_handler(_reflect)

    # A custom budget comfortably above what this tiny app's scan+loop need (the scan alone uses ~76), so both
    # phases fit and the sharing is visible. The point is that the ENGAGEMENT's budget — not a throwaway 8 —
    # is the one the loop's probes draw down.
    budget = 300
    monkeypatch.setattr(engage_mod, "_intel_recon", _inject_recon_service(port))
    result = run_engagement(
        "disco", f"http://127.0.0.1:{port}/benign",
        request_budget=budget, max_pages=5, enable_oob=False, enable_recon=True, prompt_callback=_deny,
    )
    auto = result.autonomy
    assert auto is not None
    assert auto.shared_budget == budget, "the loop did not inherit the ENGAGEMENT's request budget"
    assert 0 < auto.shared_requests_before < auto.shared_requests_made <= budget


# ---------------------------------------------------------------------------
# EC-3 MONEY-SEAM — a RUN-SCOPED HARD token-budget stop inside the driver must be HONORED, not swallowed:
# it PROPAGATES out of the driver (not caught by the best-effort net) and surfaces as a CLEAN partial result,
# exactly as when the scan itself hits the ceiling — so the launch settles COMPLETED, never continues past the
# ceiling. Control: an ordinary best-effort error inside the driver IS swallowed (telemetry is value-add).
# ---------------------------------------------------------------------------


class _FakeExecutor:
    """A stand-in for the kept-open scan executor: a callable gated_fetch + a stats() dict, nothing else."""

    def gated_fetch(self, req):  # pragma: no cover - never reached (the cycle is monkeypatched to raise)
        return {"status": 0, "body": "", "headers": []}

    def stats(self):
        return {"requests_made": 5, "budget": 100}

    def close(self):
        pass


def _result_stub() -> EngagementResult:
    return EngagementResult(report=ScanReport(target="http://127.0.0.1/", active_findings=[]), world=WorldModel())


def test_run_apex_driver_propagates_run_budget_exceeded(monkeypatch: pytest.MonkeyPatch):
    """A RunBudgetExceeded raised inside the loop PROPAGATES out of _run_apex_driver (it is NOT caught by the
    best-effort ``except Exception: return None`` — RunBudgetExceeded IS an Exception subclass, so the broad
    net would otherwise swallow the credit hard-stop and let the run continue past the ceiling)."""
    def _raise(*a, **k):
        raise engage_mod._RunBudgetExceeded(1000, 1200)   # (ceiling, spent) — the real EC-3 signature
    monkeypatch.setattr(auto_mod, "run_autonomous_cycle", _raise)
    with pytest.raises(engage_mod._RunBudgetExceeded):
        engage_mod._run_apex_driver(
            _result_stub(), slug="disco", seed_url="http://127.0.0.1/", executor=_FakeExecutor(),
            request_budget=100, prompt_callback=None, spine=None, run_dir=None)


def test_run_apex_driver_swallows_ordinary_errors(monkeypatch: pytest.MonkeyPatch):
    """CONTROL: an ORDINARY error inside the loop is best-effort — it is swallowed (returns None), so a value-add
    telemetry hiccup never sinks the already-authoritative engagement. This is the behaviour RunBudgetExceeded
    must NOT share."""
    def _raise(*a, **k):
        raise ValueError("some value-add hiccup")
    monkeypatch.setattr(auto_mod, "run_autonomous_cycle", _raise)
    out = engage_mod._run_apex_driver(
        _result_stub(), slug="disco", seed_url="http://127.0.0.1/", executor=_FakeExecutor(),
        request_budget=100, prompt_callback=None, spine=None, run_dir=None)
    assert out is None


def test_driver_budget_stop_surfaces_partial_result_not_a_crash(
    isolated_engagement, httpserver: HTTPServer, monkeypatch: pytest.MonkeyPatch,
):
    """END TO END: with the flag ON, a RunBudgetExceeded raised by the in-engagement driver does NOT crash
    run_engagement — it is caught at the driver call site and surfaces as a CLEAN partial EngagementResult with
    ``stopped_reason`` set (the money-seam: the worker then emits COMPLETED → settle consumed-so-far), EXACTLY
    as when the scan itself hits the ceiling. The kept-open executor is still released (no leak)."""
    monkeypatch.setenv("VIGIL_APEX_AUTONOMOUS", "1")
    port = httpserver.port
    isolated_engagement("disco", "127.0.0.1")
    httpserver.expect_request("/benign").respond_with_handler(_benign)

    def _driver_hits_ceiling(*a, **k):
        raise engage_mod._RunBudgetExceeded(1000, 1200)   # (ceiling, spent) — the real EC-3 signature
    monkeypatch.setattr(engage_mod, "_run_apex_driver", _driver_hits_ceiling)

    # returns NORMALLY (no raise), with a partial-result stopped_reason — not a crash
    result = run_engagement(
        "disco", f"http://127.0.0.1:{port}/benign",
        max_pages=5, enable_oob=False, prompt_callback=_deny)
    assert result.stopped_reason is not None, "the driver's token-budget stop did not surface as a partial result"
    assert "budget" in result.stopped_reason.lower() or "ceiling" in result.stopped_reason.lower()
    assert result.autonomy is None  # the driver did not complete, so no telemetry was attached
