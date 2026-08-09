"""
Tests for the Track B cloud-native scope gate (:mod:`vigil_integration.live.cloud_scope`).

The gate authorises by cloud IDENTITY (provider + account), NOT by a URL host, and
is FAIL-CLOSED: unknown/empty scope, wildcard tenants, and a tripped kill-switch all
refuse. These tests are hermetic — the charter path and kill-switch path are
monkeypatched into a tmp dir, exactly as the Track A runner tests do.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from vigil_integration.live.cloud_scope import (
    CaptureScope,
    CharterCloudScopeSource,
    CloudScopeEntry,
    CloudScopeGate,
    StaticCloudScopeSource,
    parse_cloud_scope,
)


# --- isolate charter + kill-switch paths (framework is only touched inside authorize) ------
@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    pytest.importorskip("framework.v2.authority", reason="CRUCIBLE not importable here")
    from framework.v2.common import paths
    monkeypatch.setattr(paths, "killswitch_path", lambda slug: tmp_path / f"{slug}.halt")
    monkeypatch.setattr(paths, "target_dir", lambda slug: tmp_path / slug)
    monkeypatch.setattr(paths, "charter_path", lambda slug: tmp_path / slug / "charter.md")


def _static_gate(entries: list[CloudScopeEntry], slug: str = "alpha") -> CloudScopeGate:
    return CloudScopeGate(scope=StaticCloudScopeSource(entries), engagement_slug=slug)


AWS = CloudScopeEntry(provider="aws", account="123456789012", region="us-east-1", resource="*")


# ===========================================================================
# 1. in-scope allow
# ===========================================================================
def test_in_scope_identity_is_allowed() -> None:
    gate = _static_gate([AWS])
    ok, reason = gate.authorize("aws", "123456789012", region="us-east-1", resource="bucket/logs")
    assert ok, reason
    assert "authorised by signed charter" in reason


def test_provider_and_account_match_is_case_insensitive() -> None:
    gate = _static_gate([CloudScopeEntry(provider="AWS", account="AbCdEf")])
    ok, _ = gate.authorize("aws", "abcdef")
    assert ok


# ===========================================================================
# 2. wrong account refuse
# ===========================================================================
def test_wrong_account_is_refused() -> None:
    gate = _static_gate([AWS])
    ok, reason = gate.authorize("aws", "999999999999", region="us-east-1")
    assert not ok
    assert "not in the signed charter cloud scope" in reason


def test_wrong_provider_is_refused() -> None:
    gate = _static_gate([AWS])
    ok, _ = gate.authorize("gcp", "123456789012", region="us-east-1")
    assert not ok


# ===========================================================================
# 3. wildcard-account refuse (a tenant must be named EXPLICITLY)
# ===========================================================================
def test_wildcard_account_entry_authorizes_nothing() -> None:
    # A charter row with a "*" tenant is inert — it must not authorise any account.
    gate = _static_gate([CloudScopeEntry(provider="aws", account="*", region="", resource="*")])
    ok, reason = gate.authorize("aws", "123456789012")
    assert not ok
    assert "no explicit cloud scope" in reason  # the inert row leaves the allow-set empty


def test_wildcard_account_in_the_request_is_refused() -> None:
    gate = _static_gate([AWS])
    ok, reason = gate.authorize("aws", "*")
    assert not ok
    assert "wildcard account" in reason


def test_glob_account_entry_does_not_expand() -> None:
    # "12345678*" would authorise a whole family of accounts — must be inert.
    gate = _static_gate([CloudScopeEntry(provider="aws", account="12345678*")])
    ok, _ = gate.authorize("aws", "123456789012")
    assert not ok


# ===========================================================================
# 4. kill-switch engaged -> refuse-all
# ===========================================================================
def test_tripped_killswitch_refuses_all(tmp_path: Path) -> None:
    from framework.v2.authority import KillSwitch
    KillSwitch("alpha").trip("red-pen: halt")
    gate = _static_gate([AWS])
    ok, reason = gate.authorize("aws", "123456789012", region="us-east-1", resource="bucket/x")
    assert not ok
    assert "kill-switch tripped" in reason


def test_killswitch_check_error_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    import framework.v2.authority as authority

    class _Boom:
        def __init__(self, slug):  # noqa: D401
            pass

        def is_tripped(self):
            raise RuntimeError("halt store unreadable")

    monkeypatch.setattr(authority, "KillSwitch", _Boom)
    gate = _static_gate([AWS])
    ok, reason = gate.authorize("aws", "123456789012")
    assert not ok
    assert "fail-closed" in reason


def test_empty_engagement_slug_is_refused() -> None:
    gate = _static_gate([AWS], slug="")
    ok, reason = gate.authorize("aws", "123456789012")
    assert not ok
    assert "engagement slug" in reason


# ===========================================================================
# 5. empty scope -> refuse
# ===========================================================================
def test_empty_scope_is_refused() -> None:
    gate = _static_gate([])
    ok, reason = gate.authorize("aws", "123456789012")
    assert not ok
    assert "no explicit cloud scope" in reason


# ===========================================================================
# 6. region / resource glob match + mismatch
# ===========================================================================
def test_region_glob_match_and_mismatch() -> None:
    gate = _static_gate([CloudScopeEntry(provider="gcp", account="proj", region="us-*", resource="")])
    ok, _ = gate.authorize("gcp", "proj", region="us-central1")
    assert ok
    ok2, reason = gate.authorize("gcp", "proj", region="eu-west1")
    assert not ok2
    assert "not in the signed charter cloud scope" in reason


def test_region_constraint_refuses_an_empty_requested_region() -> None:
    gate = _static_gate([CloudScopeEntry(provider="gcp", account="proj", region="us-*")])
    ok, reason = gate.authorize("gcp", "proj")   # no region supplied
    assert not ok
    assert "constrains region" in reason


def test_blank_region_entry_allows_any_region() -> None:
    gate = _static_gate([CloudScopeEntry(provider="gcp", account="proj", region="")])
    ok, _ = gate.authorize("gcp", "proj", region="anywhere-1")
    assert ok


def test_resource_glob_match_and_mismatch() -> None:
    gate = _static_gate([CloudScopeEntry(provider="k8s", account="prod", region="", resource="ns/payments/*")])
    ok, _ = gate.authorize("k8s", "prod", resource="ns/payments/api-7f")
    assert ok
    ok2, _ = gate.authorize("k8s", "prod", resource="ns/admin/root")
    assert not ok2


def test_resource_constraint_refuses_an_empty_requested_resource() -> None:
    gate = _static_gate([CloudScopeEntry(provider="k8s", account="prod", resource="ns/payments/*")])
    ok, reason = gate.authorize("k8s", "prod")
    assert not ok
    assert "constrains resource" in reason


# ===========================================================================
# 7. R4 lesson — the gate never self-authorizes the requested identity.
# ===========================================================================
def test_gate_does_not_self_authorize_the_target_identity() -> None:
    # Scope names a DIFFERENT tenant; the requested identity must not authorise itself.
    gate = _static_gate([CloudScopeEntry(provider="aws", account="111111111111")])
    ok, _ = gate.authorize("aws", "222222222222")
    assert not ok


# ===========================================================================
# 8. charter parsing (the documented schema addition) + CharterCloudScopeSource
# ===========================================================================
_CHARTER = """# Engagement charter — `alpha`

## 2. In-scope systems

| Host | Notes | Auth |
|---|---|---|
| `app.example.com` | Web | Yes |

## 2b. Cloud scope (Track B — cloud / Kubernetes)

| Provider | Account / Project / Subscription | Region | Resource (glob) |
|----------|----------------------------------|--------|-----------------|
| `aws`    | `123456789012`                   | `us-east-1` | `*`        |
| `gcp`    | `my-prod-project`                | `*`    | `bucket/app-*`  |
| `k8s`    | `prod-cluster`                   |        | `ns/payments/*` |

## 3. Out of scope

Nothing.
"""


def test_parse_cloud_scope_reads_the_table() -> None:
    entries = parse_cloud_scope(_CHARTER)
    assert len(entries) == 3
    aws = entries[0]
    assert (aws.provider, aws.account, aws.region, aws.resource) == (
        "aws", "123456789012", "us-east-1", "*")
    k8s = entries[2]
    assert k8s.region == "" and k8s.resource == "ns/payments/*"


def test_parse_returns_empty_when_section_absent() -> None:
    assert parse_cloud_scope("# charter\n\n## 2. In-scope systems\n\n| Host |\n|---|\n| a |\n") == []


def test_charter_cloud_scope_source_end_to_end(tmp_path: Path) -> None:
    d = tmp_path / "alpha"
    d.mkdir(parents=True, exist_ok=True)
    (d / "charter.md").write_text(_CHARTER, encoding="utf-8")
    gate = CloudScopeGate(scope=CharterCloudScopeSource("alpha"), engagement_slug="alpha")
    ok, _ = gate.authorize("aws", "123456789012", region="us-east-1", resource="bucket/logs")
    assert ok
    ok2, _ = gate.authorize("gcp", "my-prod-project", region="anything", resource="bucket/app-7")
    assert ok2
    ok3, _ = gate.authorize("gcp", "my-prod-project", region="x", resource="secrets/root")
    assert not ok3            # resource glob mismatch
    ok4, _ = gate.authorize("aws", "999999999999")
    assert not ok4            # wrong tenant


def test_charter_missing_file_fails_closed(tmp_path: Path) -> None:
    gate = CloudScopeGate(scope=CharterCloudScopeSource("ghost"), engagement_slug="ghost")
    ok, reason = gate.authorize("aws", "123456789012")
    assert not ok
    assert "no explicit cloud scope" in reason


# ===========================================================================
# 9. CaptureScope — bounded honesty for Track B certs.
# ===========================================================================
def test_capture_scope_complete_is_conclusive() -> None:
    cs = CaptureScope(requested=["a", "b"], returned=["b", "a"], truncated=False)
    assert cs.conclusive
    assert cs.completeness() == "complete"
    assert cs.missing == []
    assert cs.to_dict() == {"completeness": "complete",
                            "requested": ["a", "b"], "returned": ["a", "b"]}


def test_capture_scope_truncated_is_bounded_not_conclusive() -> None:
    cs = CaptureScope(requested=["a", "b"], returned=["a", "b"], truncated=True)
    assert not cs.conclusive
    assert cs.completeness() == "bounded"
    assert cs.to_dict()["truncated"] is True


def test_capture_scope_partial_reports_missing() -> None:
    cs = CaptureScope(requested=["a", "b", "c"], returned=["a"])
    assert not cs.conclusive
    assert cs.missing == ["b", "c"]
    assert cs.completeness() == "bounded"


def test_capture_scope_empty_is_not_conclusive() -> None:
    cs = CaptureScope()
    assert not cs.conclusive
    assert cs.completeness() == "empty"
    assert cs.to_dict() == {"completeness": "empty"}


def test_resource_path_traversal_segment_is_refused_fail_closed() -> None:
    """RED-PEN D5-LOW: fnmatch '*' spans '/', so a charter glob 'ns/payments/*' would otherwise also match
    'ns/payments/../admin/root'. A requested resource carrying a '..' segment is refused fail-closed, so a
    downstream path-normalizer cannot escape the scoped prefix. A canonical resource still authorizes."""
    gate = _static_gate([CloudScopeEntry(provider="k8s", account="prod", region="", resource="ns/payments/*")])
    ok, reason = gate.authorize("k8s", "prod", resource="ns/payments/../admin/root")
    assert ok is False and "traversal" in reason
    # the legitimate canonical resource under the same glob still authorizes
    assert gate.authorize("k8s", "prod", resource="ns/payments/svc-a")[0] is True
