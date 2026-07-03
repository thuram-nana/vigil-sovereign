"""
Tests for the egress guard wiring + redirect re-gate (SSRF hardening).

Every scenario runs against localhost `pytest-httpserver`; no request
ever leaves the test host. These cover the audit's egress/SSRF findings:

  - a 30x redirect to an out-of-scope host is re-gated and refused —
    the redirect host is never contacted;
  - the sovereign egress transport is installed on the httpx client
    when an allowlist is supplied;
  - under strict sovereign mode a non-allowlisted host is refused (as a
    graceful refusal outcome, not a crash).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pytest_httpserver import HTTPServer

from datetime import datetime, timedelta, timezone

from framework.v2.agents import HttpExecutor
from framework.v2.agents.egress_guard import EgressAllowlist, SovereignHttpxTransport
from framework.v2.agents.models import HypothesisPayload, PlanPayload
from framework.v2.authority.models import EngagementAuthority
from framework.v2.authority.store import save_authority
from framework.v2.common import paths as _paths
from framework.v2.kernel import sovereignty


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

    def build_charter(slug: str, host: str) -> Path:
        td = targets_root / slug
        td.mkdir(parents=True, exist_ok=True)
        (td / "charter.md").write_text(
            _CHARTER.format(slug=slug, host=host), encoding="utf-8",
        )
        return td

    monkeypatch.setattr(_paths, "target_dir", lambda s: targets_root / s)
    monkeypatch.setattr(
        _paths, "charter_path", lambda s: targets_root / s / "charter.md",
    )
    return build_charter


def _hyp(surface: str) -> HypothesisPayload:
    return HypothesisPayload(
        handle="H-1", surface=surface, bug_class="probe",
        given="x", if_action=surface, then_observation="y",
        because_model="z", refute_on="n/a", cheap_test="one curl",
    )


_PLAN = PlanPayload(plan_id="P-1", targets_hypothesis="H-1", next_action="probe")


def _deny(_q: str, _t: float) -> bool:
    return False


# ---------------------------------------------------------------------------
# redirect re-gate
# ---------------------------------------------------------------------------


def test_redirect_to_out_of_scope_host_is_refused_and_never_contacted(
    isolated_engagement, httpserver: HTTPServer,
):
    """The initial in-scope URL returns a 302 whose Location points at an
    out-of-scope host. The re-gate must refuse it and the redirect target
    must never be contacted.

    Trick: the *same* server is addressed by two names — `127.0.0.1`
    (in charter scope) and `localhost` (NOT in scope). The initial hop
    uses the in-scope name; the redirect Location uses the out-of-scope
    name pointing at `/pwned` on the very same server. If the re-gate
    failed to fire, the server would log a `/pwned` request.
    """
    port = httpserver.port
    isolated_engagement("alpha", "127.0.0.1")  # only 127.0.0.1 is in scope

    httpserver.expect_request("/start").respond_with_data(
        "", status=302,
        headers={"Location": f"http://localhost:{port}/pwned"},
    )
    # If ever reached, this would show up in httpserver.log.
    httpserver.expect_request("/pwned").respond_with_data("SECRET-INTERNAL")

    ex = HttpExecutor(
        engagement_slug="alpha",
        base_url=f"http://127.0.0.1:{port}/",
        prompt_callback=_deny,
    )
    out = ex.execute(_hyp("/start"), _PLAN)
    ex.close()

    # The redirect was refused, not followed.
    assert "REFUSED redirect" in out.note
    assert "out_of_scope" in out.note
    assert ex.stats()["scope_violations"] == 1

    # The out-of-scope host was never contacted.
    contacted = [r[0].path for r in httpserver.log]
    assert "/start" in contacted
    assert "/pwned" not in contacted


def test_in_scope_redirect_is_followed(
    isolated_engagement, httpserver: HTTPServer,
):
    """A redirect that stays on the in-scope host is followed normally —
    the re-gate must not break legitimate same-host redirects."""
    port = httpserver.port
    isolated_engagement("alpha", "127.0.0.1")

    httpserver.expect_request("/start").respond_with_data(
        "", status=302, headers={"Location": f"http://127.0.0.1:{port}/final"},
    )
    httpserver.expect_request("/final").respond_with_data("landed", status=200)

    ex = HttpExecutor(
        engagement_slug="alpha",
        base_url=f"http://127.0.0.1:{port}/",
        prompt_callback=_deny,
    )
    out = ex.execute(_hyp("/start"), _PLAN)
    ex.close()

    assert out.status_code == 200
    assert "landed" in out.body_excerpt
    assert ex.stats()["scope_violations"] == 0
    contacted = [r[0].path for r in httpserver.log]
    assert "/start" in contacted and "/final" in contacted


# ---------------------------------------------------------------------------
# egress guard wiring
# ---------------------------------------------------------------------------


def test_egress_allowlist_installs_sovereign_transport(
    isolated_engagement, httpserver: HTTPServer,
):
    isolated_engagement("alpha", httpserver.host)
    allowlist = EgressAllowlist(target_hosts=(httpserver.host,))
    ex = HttpExecutor(
        engagement_slug="alpha",
        base_url=httpserver.url_for("/"),
        prompt_callback=_deny,
        egress_allowlist=allowlist,
    )
    client = ex._client()
    assert isinstance(client._transport, SovereignHttpxTransport)
    ex.close()


def test_no_allowlist_uses_plain_transport(
    isolated_engagement, httpserver: HTTPServer,
):
    """Backward compat: with no allowlist, no sovereign transport is
    installed (existing behaviour)."""
    isolated_engagement("alpha", httpserver.host)
    ex = HttpExecutor(
        engagement_slug="alpha",
        base_url=httpserver.url_for("/"),
        prompt_callback=_deny,
    )
    client = ex._client()
    assert not isinstance(client._transport, SovereignHttpxTransport)
    ex.close()


def test_strict_egress_refuses_non_allowlisted_host_gracefully(
    isolated_engagement, httpserver: HTTPServer,
):
    """Under strict sovereign mode, a host that passes the scope gate but
    is absent from the egress allowlist is refused by the transport — and
    the executor turns that into a graceful refusal outcome (not a crash),
    contacting nothing."""
    isolated_engagement("alpha", httpserver.host)
    httpserver.expect_request("/probe").respond_with_data("ok")

    # Allowlist that permits nothing (no target/llm/extra hosts).
    empty = EgressAllowlist(target_hosts=(), llm_hosts=(), extra_hosts=())
    prev = sovereignty._active_policy
    sovereignty.set_policy(sovereignty.SovereigntyPolicy(strict=True))
    try:
        ex = HttpExecutor(
            engagement_slug="alpha",
            base_url=httpserver.url_for("/"),
            prompt_callback=_deny,
            egress_allowlist=empty,
        )
        out = ex.execute(_hyp("/probe"), _PLAN)
        ex.close()
    finally:
        sovereignty.set_policy(prev)

    assert "egress guard" in out.note
    assert out.success is False
    assert len(httpserver.log) == 0
    assert ex.stats()["scope_violations"] == 1


# ---------------------------------------------------------------------------
# optional engagement-authority plumbing
# ---------------------------------------------------------------------------


def test_auto_load_authority_expired_window_refuses(
    isolated_engagement, httpserver: HTTPServer, monkeypatch,
):
    """With `auto_load_authority=True`, a persisted authority whose
    validity window has passed causes the authority gate to refuse the
    action before any network I/O."""
    td = isolated_engagement("alpha", httpserver.host)
    httpserver.expect_request("/probe").respond_with_data("ok")
    monkeypatch.setattr(_paths, "authority_path", lambda s: td / "authority.json")

    now = datetime.now(timezone.utc)
    expired = EngagementAuthority(
        engagement_slug="alpha",
        environment="staging",
        scope=[httpserver.host],
        not_before=now - timedelta(days=2),
        not_after=now - timedelta(days=1),  # window already closed
    )
    save_authority(expired, path=td / "authority.json")

    ex = HttpExecutor(
        engagement_slug="alpha",
        base_url=httpserver.url_for("/"),
        prompt_callback=_deny,
        auto_load_authority=True,
    )
    assert ex.authority is not None  # hydrated from disk
    out = ex.execute(_hyp("/probe"), _PLAN)
    ex.close()

    assert "authority refused" in out.note
    assert len(httpserver.log) == 0


def test_auto_load_authority_absent_document_is_noop(
    isolated_engagement, httpserver: HTTPServer, monkeypatch,
):
    """Fail-closed but quiet: with no authority document on disk,
    `auto_load_authority=True` leaves `authority` None and behaviour is
    unchanged (a normal in-scope request proceeds)."""
    td = isolated_engagement("alpha", httpserver.host)
    httpserver.expect_request("/probe").respond_with_data("ok")
    monkeypatch.setattr(_paths, "authority_path", lambda s: td / "authority.json")

    ex = HttpExecutor(
        engagement_slug="alpha",
        base_url=httpserver.url_for("/"),
        prompt_callback=_deny,
        auto_load_authority=True,
    )
    assert ex.authority is None
    out = ex.execute(_hyp("/probe"), _PLAN)
    ex.close()
    assert out.status_code == 200
