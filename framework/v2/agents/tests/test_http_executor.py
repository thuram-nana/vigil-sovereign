"""
Tests for HttpExecutor + scope_gate.

Strategy: every scenario runs against a `pytest-httpserver` instance
on localhost. No request ever leaves the test host. The Executor's
charter / scope / destructive / budget / rate-limit / posture gates
are exercised by writing a synthetic charter in tmp_path, monkey-
patching `paths.target_dir` (and friends) to point there, and asserting
on the side-effects: counters on the executor, log lines, evidence
dirs, refusal notes.

The tests are deliberately strict about the gates — these are the
load-bearing safety primitives for any live-HTTP run.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from pytest_httpserver import HTTPServer

from framework.v2.agents import (
    HttpExecutor,
    ScopeDecision,
    parse_posture,
    user_agent_for,
    validate_action,
)
from framework.v2.agents.executor_proto import Executor
from framework.v2.agents.models import HypothesisPayload, PlanPayload
from framework.v2.common import paths as _paths


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


_SIGNED_CHARTER_TEMPLATE = """\
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

- [{test_mark}] **TEST**
- [{audit_mark}] **AUDIT**
- [{emulate_mark}] **EMULATE**
"""


def _write_charter(
    *,
    target_dir: Path, slug: str, host: str,
    posture: str = "TEST",
    signed: bool = True,
) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)
    template = _SIGNED_CHARTER_TEMPLATE.format(
        slug=slug, host=host,
        test_mark="x" if posture == "TEST" else " ",
        audit_mark="x" if posture == "AUDIT" else " ",
        emulate_mark="x" if posture == "EMULATE" else " ",
    )
    if not signed:
        template = template.replace("Signed: `tester`", "Signed: `<name>`")
    (target_dir / "charter.md").write_text(template, encoding="utf-8")


@pytest.fixture()
def isolated_engagement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    """Provision an isolated targets/<slug>/ for the test, monkey-patch
    paths so the executor's charter / evidence / log writes all land
    under tmp_path. Returns a small builder closure tests can use to
    write whichever flavour of charter they need."""
    targets_root = tmp_path / "targets"
    targets_root.mkdir()

    # We'll capture the slug + host the test wants and produce a
    # build_charter() the test calls to materialise the charter file.
    state: dict[str, str] = {}

    def build_charter(slug: str, host: str, *, posture: str = "TEST",
                       signed: bool = True) -> Path:
        state["slug"] = slug
        state["host"] = host
        td = targets_root / slug
        _write_charter(target_dir=td, slug=slug, host=host,
                       posture=posture, signed=signed)
        return td

    monkeypatch.setattr(_paths, "target_dir", lambda s: targets_root / s)
    monkeypatch.setattr(
        _paths, "charter_path",
        lambda s: targets_root / s / "charter.md",
    )
    return build_charter


@pytest.fixture()
def hyp_get():
    return HypothesisPayload(
        handle="H-001", surface="/api/orders/1",
        bug_class="IDOR",
        given="standard low-priv session",
        if_action="GET /api/orders/1",
        then_observation="other user's order body returned",
        because_model="endpoint authenticates session but not ownership",
        refute_on="response is 403 or empty",
        cheap_test="single curl",
    )


@pytest.fixture()
def plan_one():
    return PlanPayload(
        plan_id="P-001", targets_hypothesis="H-001",
        next_action="GET /api/orders/1",
    )


def _allow_callback(_q: str, _t: float) -> bool:
    return True


def _deny_callback(_q: str, _t: float) -> bool:
    return False


# ---------------------------------------------------------------------------
# scope_gate primitives
# ---------------------------------------------------------------------------


def test_scope_decision_passes_for_in_scope_signed_charter(isolated_engagement):
    isolated_engagement("alpha", "alpha.example")
    d = validate_action(
        slug="alpha", method="GET",
        target_url="https://alpha.example/users",
    )
    assert d.allowed is True
    assert d.refusal_kind == ""
    assert d.is_destructive is False


def test_scope_decision_refuses_unsigned_charter(isolated_engagement):
    isolated_engagement("alpha", "alpha.example", signed=False)
    d = validate_action(
        slug="alpha", method="GET",
        target_url="https://alpha.example/users",
    )
    assert d.allowed is False
    assert d.refusal_kind == "charter_unsigned"


def test_scope_decision_refuses_missing_charter(isolated_engagement):
    # Note: do NOT call build_charter — directory exists but charter doesn't.
    d = validate_action(
        slug="missing-target", method="GET",
        target_url="https://elsewhere.example/",
    )
    assert d.allowed is False
    assert d.refusal_kind == "charter_missing"


def test_scope_decision_refuses_out_of_scope_host(isolated_engagement):
    isolated_engagement("alpha", "alpha.example")
    d = validate_action(
        slug="alpha", method="GET",
        target_url="https://evil.example/",
    )
    assert d.allowed is False
    assert d.refusal_kind == "out_of_scope"


def test_scope_decision_marks_post_as_destructive(isolated_engagement):
    isolated_engagement("alpha", "alpha.example")
    d = validate_action(
        slug="alpha", method="POST",
        target_url="https://alpha.example/api/users",
    )
    assert d.allowed is True
    assert d.is_destructive is True


def test_scope_decision_marks_admin_path_as_destructive(isolated_engagement):
    isolated_engagement("alpha", "alpha.example")
    d = validate_action(
        slug="alpha", method="GET",
        target_url="https://alpha.example/admin/dashboard",
    )
    assert d.allowed is True
    assert d.is_destructive is True


# ---------------------------------------------------------------------------
# posture parsing + UA
# ---------------------------------------------------------------------------


def test_posture_defaults_to_test_when_no_charter(isolated_engagement):
    assert parse_posture("does-not-exist") == "TEST"


def test_posture_reads_emulate_from_charter(isolated_engagement):
    isolated_engagement("alpha", "alpha.example", posture="EMULATE")
    assert parse_posture("alpha") == "EMULATE"


def test_user_agent_test_posture_is_identifiable():
    ua = user_agent_for("TEST")
    assert ua.startswith("OBSIDIAN/1.0")


def test_user_agent_emulate_posture_is_realistic():
    ua = user_agent_for("EMULATE")
    assert "OBSIDIAN" not in ua
    assert "Mozilla" in ua


def test_user_agent_audit_includes_control_test_marker():
    ua = user_agent_for("AUDIT")
    assert "control-test" in ua


# ---------------------------------------------------------------------------
# HttpExecutor — the six gates against pytest-httpserver
# ---------------------------------------------------------------------------


def _executor(httpserver: HTTPServer, slug: str = "alpha", **kwargs) -> HttpExecutor:
    return HttpExecutor(
        engagement_slug=slug,
        base_url=httpserver.url_for("/"),
        prompt_callback=kwargs.pop("prompt_callback", _deny_callback),
        **kwargs,
    )


def test_executor_satisfies_protocol():
    """Runtime-checkable Protocol assertion lives in tests, not at
    import time, so we don't accidentally bind_engagement on a sentinel."""
    e = HttpExecutor(
        engagement_slug="<unused>",
        base_url="https://unused.example",
        dry_run=True,
    )
    assert isinstance(e, Executor)


def test_in_scope_get_succeeds_and_captures_response(
    isolated_engagement, httpserver: HTTPServer, hyp_get, plan_one,
):
    isolated_engagement("alpha", httpserver.host)
    httpserver.expect_request("/api/orders/1").respond_with_data(
        '{"order_id": 1, "user_id": 2, "amount": "100.00"}',
        status=200, content_type="application/json",
    )

    ex = _executor(httpserver)
    out = ex.execute(hyp_get, plan_one)
    ex.close()

    assert out.status_code == 200
    assert "order_id" in out.body_excerpt
    # HttpExecutor never auto-claims success — that's the exploit-agent.
    assert out.success is False
    assert "in scope" not in out.note  # gate decision is logged, not in note
    # evidence captured
    evidence_root = _paths.target_dir("alpha") / "evidence"
    assert evidence_root.exists()
    captured = list(evidence_root.iterdir())
    assert captured, "expected at least one evidence/<action_id>/ dir"
    files = {p.name for p in captured[0].iterdir()}
    assert {"request.http", "response.http", "response.body"} <= files


def test_out_of_scope_action_refused_no_request_made(
    isolated_engagement, httpserver: HTTPServer, plan_one,
):
    isolated_engagement("alpha", "alpha.example")  # in-scope is alpha.example
    # Hypothesis points at the local httpserver, which is NOT alpha.example
    hyp_other = HypothesisPayload(
        handle="H-other", surface="/whatever",
        bug_class="probe",
        given="x", if_action="GET /whatever",
        then_observation="response", because_model="check",
        refute_on="—", cheap_test="curl",
    )

    ex = _executor(httpserver, slug="alpha")
    # The base_url IS the httpserver, but charter scope is alpha.example.
    # → scope_gate refuses before any request goes out.
    out = ex.execute(hyp_other, plan_one)
    ex.close()

    assert out.status_code == 0
    assert "REFUSED" in out.note
    assert "out_of_scope" in out.note
    assert ex.stats()["scope_violations"] == 1
    assert ex.stats()["requests_made"] == 0
    # httpserver should have received zero requests
    assert len(httpserver.log) == 0


def test_unsigned_charter_blocks_active_request(
    isolated_engagement, httpserver: HTTPServer, hyp_get, plan_one,
):
    isolated_engagement("alpha", httpserver.host, signed=False)
    httpserver.expect_request("/api/orders/1").respond_with_data("ok")

    ex = _executor(httpserver)
    out = ex.execute(hyp_get, plan_one)
    ex.close()

    assert out.status_code == 0
    assert "REFUSED" in out.note
    assert "charter_unsigned" in out.note
    assert ex.stats()["scope_violations"] == 1
    assert len(httpserver.log) == 0


def test_destructive_action_prompts_and_respects_deny(
    isolated_engagement, httpserver: HTTPServer, plan_one,
):
    isolated_engagement("alpha", httpserver.host)
    httpserver.expect_request("/admin").respond_with_data("ok")

    hyp_admin = HypothesisPayload(
        handle="H-admin", surface="GET /admin",  # destructive by path
        bug_class="auth-bypass",
        given="x", if_action="GET /admin",
        then_observation="—", because_model="—",
        refute_on="—", cheap_test="curl",
    )

    ex = _executor(httpserver, prompt_callback=_deny_callback)
    out = ex.execute(hyp_admin, plan_one)
    ex.close()

    assert "destructive" in out.note.lower()
    assert ex.stats()["destructive_refusals"] == 1
    assert ex.stats()["requests_made"] == 0
    assert len(httpserver.log) == 0


def test_destructive_action_proceeds_when_operator_allows(
    isolated_engagement, httpserver: HTTPServer, plan_one,
):
    isolated_engagement("alpha", httpserver.host)
    httpserver.expect_request("/admin", method="POST").respond_with_data(
        '{"ok": true}', status=200, content_type="application/json",
    )

    hyp_admin = HypothesisPayload(
        handle="H-admin", surface="POST /admin",
        bug_class="csrf",
        given="x", if_action="POST /admin",
        then_observation="—", because_model="—",
        refute_on="—", cheap_test="curl",
    )

    ex = _executor(httpserver, prompt_callback=_allow_callback)
    out = ex.execute(hyp_admin, plan_one)
    ex.close()

    assert out.status_code == 200
    assert ex.stats()["destructive_refusals"] == 0
    assert ex.stats()["requests_made"] == 1


def test_request_budget_exhaustion_halts_cleanly(
    isolated_engagement, httpserver: HTTPServer, hyp_get, plan_one,
):
    isolated_engagement("alpha", httpserver.host)
    httpserver.expect_request("/api/orders/1").respond_with_data("ok")

    ex = _executor(httpserver, request_budget=2)
    # First two requests succeed, third is budget-refused.
    o1 = ex.execute(hyp_get, plan_one)
    o2 = ex.execute(hyp_get, plan_one)
    o3 = ex.execute(hyp_get, plan_one)
    ex.close()

    assert o1.status_code == 200
    assert o2.status_code == 200
    assert o3.status_code == 0
    assert "REFUSED" in o3.note
    assert "budget" in o3.note.lower()
    assert ex.stats()["requests_made"] == 2
    assert ex.stats()["budget_refusals"] == 1


def test_rate_limit_enforced_for_audit_posture(
    isolated_engagement, httpserver: HTTPServer, hyp_get, plan_one,
):
    """AUDIT posture floor is 1 second between requests."""
    import time as _time
    isolated_engagement("alpha", httpserver.host, posture="AUDIT")
    httpserver.expect_request("/api/orders/1").respond_with_data("ok")

    ex = _executor(httpserver)
    t0 = _time.perf_counter()
    ex.execute(hyp_get, plan_one)
    ex.execute(hyp_get, plan_one)
    elapsed = _time.perf_counter() - t0
    ex.close()

    # Two requests with a 1.0s floor between → second request must
    # have waited at least ~1 second after the first.
    assert elapsed >= 0.9, f"AUDIT rate limit didn't kick in (elapsed={elapsed:.2f}s)"


def test_emulate_jitters_measurably_more_than_test(
    isolated_engagement, httpserver: HTTPServer, hyp_get, plan_one,
):
    """EMULATE posture jitters; TEST posture does not. Three requests
    in EMULATE should take meaningfully longer than three in TEST."""
    import time as _time
    httpserver.expect_request("/api/orders/1").respond_with_data("ok")

    # TEST run (0.2s floor, no jitter → 3 requests ≈ 0.4s+).
    isolated_engagement("alpha-test", httpserver.host, posture="TEST")
    ex_test = HttpExecutor(
        engagement_slug="alpha-test",
        base_url=httpserver.url_for("/"),
        prompt_callback=_deny_callback,
        request_budget=10,
    )
    t0 = _time.perf_counter()
    for _ in range(3):
        ex_test.execute(hyp_get, plan_one)
    test_elapsed = _time.perf_counter() - t0
    ex_test.close()

    # EMULATE run (5.0s floor + up to 3s jitter → 3 requests ≈ 10s+).
    # We use a lower posture floor here so the test doesn't wait the
    # full real-world cadence — the JITTER comparison is what matters.
    # We monkeypatch _RATE_PROFILES to 0.2 floor + 0.5 jitter for the
    # purpose of this test (operationally EMULATE stays slow; this
    # just compresses the test).
    from framework.v2.agents import http_executor as _he
    saved = _he._RATE_PROFILES["EMULATE"]
    _he._RATE_PROFILES["EMULATE"] = (0.2, 0.5)
    try:
        isolated_engagement("alpha-emulate", httpserver.host, posture="EMULATE")
        ex_emul = HttpExecutor(
            engagement_slug="alpha-emulate",
            base_url=httpserver.url_for("/"),
            prompt_callback=_deny_callback,
            request_budget=10,
        )
        t0 = _time.perf_counter()
        for _ in range(3):
            ex_emul.execute(hyp_get, plan_one)
        emul_elapsed = _time.perf_counter() - t0
        ex_emul.close()
    finally:
        _he._RATE_PROFILES["EMULATE"] = saved

    # EMULATE should take noticeably longer due to jitter.
    assert emul_elapsed > test_elapsed, (
        f"EMULATE ({emul_elapsed:.2f}s) should jitter more than TEST "
        f"({test_elapsed:.2f}s)"
    )


def test_user_agent_set_correctly_per_posture(
    isolated_engagement, httpserver: HTTPServer, hyp_get, plan_one,
):
    isolated_engagement("alpha", httpserver.host)
    httpserver.expect_request("/api/orders/1").respond_with_data("ok")

    ex = _executor(httpserver)
    ex.execute(hyp_get, plan_one)
    ex.close()

    # pytest-httpserver records the request; check the UA
    received_uas = [r[0].headers.get("User-Agent", "") for r in httpserver.log]
    assert received_uas, "expected at least one logged request"
    assert any("OBSIDIAN" in ua for ua in received_uas), (
        f"expected OBSIDIAN UA in TEST posture, got {received_uas}"
    )


def test_dry_run_does_not_hit_network(
    isolated_engagement, httpserver: HTTPServer, hyp_get, plan_one,
):
    isolated_engagement("alpha", httpserver.host)
    httpserver.expect_request("/api/orders/1").respond_with_data("ok")

    ex = HttpExecutor(
        engagement_slug="alpha",
        base_url=httpserver.url_for("/"),
        prompt_callback=_deny_callback,
        dry_run=True,
    )
    out = ex.execute(hyp_get, plan_one)
    ex.close()

    assert out.status_code == 0
    assert "dry_run" in out.note
    assert len(httpserver.log) == 0
