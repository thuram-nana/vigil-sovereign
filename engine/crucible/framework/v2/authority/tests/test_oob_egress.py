"""VF-2b OOB egress gate (FACT-coverage Wave 1.2).

The OOB collaborator relay is an EGRESS destination the operator hosts, not a scan TARGET. It is
authorized through a DEDICATED ``EngagementAuthority.oob_relay_host`` field and a SEPARATE gate
(``authorize_oob_egress``) — never through the general host-scope matcher, so authorizing the relay does
NOT widen the scan scope. These tests pin that separation and the fail-closed default.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ..gate import authorize_action, authorize_oob_egress
from ..models import ActionRequest, EngagementAuthority, TargetEnvironment

_NOW = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)


def _authority(**kw: object) -> EngagementAuthority:
    base = dict(
        engagement_slug="eng",
        environment=TargetEnvironment.TWIN,
        scope=["app.example.com"],
        not_before=_NOW - timedelta(hours=1),
        not_after=_NOW + timedelta(hours=1),
    )
    base.update(kw)
    return EngagementAuthority(**base)  # type: ignore[arg-type]


def test_oob_egress_authorized_only_for_the_named_relay_host() -> None:
    auth = _authority(oob_relay_host="relay.op.example")
    assert authorize_oob_egress(auth, "relay.op.example") is True
    assert authorize_oob_egress(auth, "https://relay.op.example/_poll/x") is True   # URL form → host extracted
    assert authorize_oob_egress(auth, "other.op.example") is False


def test_oob_egress_fail_closed_without_a_signed_relay_host() -> None:
    # no oob_relay_host in the signed authority → nothing is an authorized OOB egress
    auth = _authority()
    assert auth.oob_relay_host == ""
    assert authorize_oob_egress(auth, "relay.op.example") is False
    assert authorize_oob_egress(auth, "") is False


def test_relay_host_is_not_a_scan_target_via_the_general_scope_gate() -> None:
    """The relay host must NOT become a scannable target just because it is an authorized OOB egress: it
    lives in the dedicated field, not in ``scope``, so the general action gate still denies it out-of-scope."""
    auth = _authority(scope=["app.example.com"], oob_relay_host="relay.op.example")
    d = authorize_action(auth, ActionRequest(target="https://relay.op.example/x"), now=_NOW)
    assert d.allowed is False and d.denial_code == "out_of_scope"
    # the real in-scope target is still authorized
    assert authorize_action(auth, ActionRequest(target="https://app.example.com/x"), now=_NOW).allowed is True


def test_collector_pubkey_field_defaults_empty_and_is_carried() -> None:
    auth = _authority(oob_relay_host="relay.op.example", oob_collector_pubkey="cGtiNjQ=")
    assert auth.oob_collector_pubkey == "cGtiNjQ="
    assert _authority().oob_collector_pubkey == ""
