"""
Wave 2 — the live, gated HttpExecutor emits oracle_context.

The heart of "prove-don't-guess on live targets": HttpExecutor.execute_differential
issues a benign baseline and a boolean probe THROUGH the full safety stack, and
attaches the two real responses as a serialized FindingContext. The deterministic
differential oracle — re-run here exactly as the critique-agent and the Wave-3
re-verifier will — decides confirmation. Against a boolean-divergent target it
confirms; against a safe twin it does not; and a tripped kill-switch refuses every
probe before any bytes leave (the gate is not bypassed by the new path).

All traffic is loopback pytest-httpserver; nothing leaves the test host.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pytest_httpserver import HTTPServer
from werkzeug.wrappers import Response

from framework.v2.agents import HttpExecutor
from framework.v2.agents.models import HypothesisPayload, PlanPayload
from framework.v2.authority.killswitch import KillSwitch
from framework.v2.common import paths as _paths
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.confirmation import confirm_finding
from framework.v2.verify.verifier import OracleVerifier

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


def _hyp(surface: str) -> HypothesisPayload:
    return HypothesisPayload(
        handle="H-1", surface=surface, bug_class="boolean_sqli",
        given="x", if_action=surface, then_observation="y",
        because_model="z", refute_on="n/a", cheap_test="one curl",
    )


_PLAN = PlanPayload(plan_id="P-1", targets_hypothesis="H-1", next_action="probe")


def _deny(_q: str, _t: float) -> bool:
    return False


def _vuln_handler(request) -> Response:
    """A boolean differential: a tautology dumps the table; benign returns one line."""
    q = request.args.get("q", "")
    if "'1'='1" in q or "1=1" in q:
        body = "echo:" + q + "\n" + "".join(f"user{i}:secret{i}\n" for i in range(40))
    else:
        body = "echo:" + q
    return Response(body, status=200, mimetype="text/plain")


def _safe_handler(request) -> Response:
    """No injection: the response is identical regardless of the query value."""
    return Response("static content, nothing reflected, no divergence", status=200)


def _reverify(oracle_context: dict) -> bool:
    """Re-run the deterministic oracle over the retained context, exactly as the
    critique-agent / re-verifier will. Returns whether it confirms."""
    ctx = FindingContext.model_validate(oracle_context)
    confirmed = confirm_finding(
        finding={"bug_class": "boolean_sqli", "title": "t", "severity": "High",
                 "surface": "s", "summary": "x"},
        context=ctx, verifier=OracleVerifier(),
    )
    return confirmed is not None


def test_differential_emits_confirming_oracle_context(isolated_engagement, httpserver: HTTPServer):
    port = httpserver.port
    isolated_engagement("alpha", "127.0.0.1")
    httpserver.expect_request("/search").respond_with_handler(_vuln_handler)

    ex = HttpExecutor(engagement_slug="alpha", base_url=f"http://127.0.0.1:{port}/", prompt_callback=_deny)
    out = ex.execute_differential(
        _hyp("/search"), _PLAN, param="q",
        baseline_value="crucible-benign-term", probe_value="x' OR '1'='1",
    )
    ex.close()

    assert out.success and out.oracle_context is not None
    assert out.finding is not None and out.finding.bug_class == "boolean_sqli"
    # the retained evidence independently re-confirms via the pure oracle
    assert _reverify(out.oracle_context)
    # exactly two probes reached the target, both through the gate (no bypass)
    assert ex.stats()["requests_made"] == 2
    assert ex.stats()["scope_violations"] == 0
    assert [r[0].path for r in httpserver.log].count("/search") == 2


def test_differential_does_not_confirm_on_safe_twin(isolated_engagement, httpserver: HTTPServer):
    port = httpserver.port
    isolated_engagement("alpha", "127.0.0.1")
    httpserver.expect_request("/search").respond_with_handler(_safe_handler)

    ex = HttpExecutor(engagement_slug="alpha", base_url=f"http://127.0.0.1:{port}/", prompt_callback=_deny)
    out = ex.execute_differential(
        _hyp("/search"), _PLAN, param="q",
        baseline_value="crucible-benign-term", probe_value="x' OR '1'='1",
    )
    ex.close()

    # a candidate was produced, but the oracle refuses it — prove-don't-guess
    assert out.oracle_context is not None
    assert not _reverify(out.oracle_context)


def test_differential_refused_when_killswitch_tripped(isolated_engagement, httpserver: HTTPServer):
    port = httpserver.port
    isolated_engagement("alpha", "127.0.0.1")
    httpserver.expect_request("/search").respond_with_handler(_vuln_handler)

    ks = KillSwitch("alpha")
    ks.trip("operator stop")
    ex = HttpExecutor(engagement_slug="alpha", base_url=f"http://127.0.0.1:{port}/",
                      prompt_callback=_deny, killswitch=ks)
    out = ex.execute_differential(
        _hyp("/search"), _PLAN, param="q",
        baseline_value="crucible-benign-term", probe_value="x' OR '1'='1",
    )
    ex.close()

    # halted before any I/O: no finding, no oracle_context, nothing contacted
    assert out.success is False and out.oracle_context is None
    assert "kill-switch" in out.note
    assert ex.stats()["requests_made"] == 0
    assert "/search" not in [r[0].path for r in httpserver.log]
