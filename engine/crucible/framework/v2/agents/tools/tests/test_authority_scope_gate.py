"""red-pen #7 — the OWNER-SIGNED engagement authority's scope binds EVERY host-acting tool/sensor op, not
just HTTP.

``_authority_scope_gate`` mirrors ``HttpExecutor._authority_gate``: it fires ONLY when a deployment trust
root is pinned (a governed / remote engagement), SKIPS otherwise (the unsigned / loopback / dev mode — so no
existing loopback tool flow changes), and fails CLOSED where a signed authority is expected (absent /
expired / out-of-scope / destructive-not-allowed).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from framework.v2.agents.tools.invoker import _authority_scope_gate
from framework.v2.authority.store import save_signed_authority
from framework.v2.entitlement.provision import write_trust_root
from vigil_core import (
    AuthorizerKey, EngagementAuthority, TargetEnvironment, TrustRoot, generate_keypair,
    sign_engagement_authority,
)

_SLUG = "gov-target"


def _crucible_root(tmp_path, monkeypatch):
    root = tmp_path / "cruc"
    (root / "framework" / "v2").mkdir(parents=True)
    (root / "CLAUDE.md").write_text("# crucible\n", encoding="utf-8")
    monkeypatch.setenv("CRUCIBLE_ROOT", str(root))
    return root


@pytest.fixture()
def signed_env(tmp_path, monkeypatch):
    """A pinned owner trust root + an owner-signed authority for _SLUG scoped to apme.cm, staging, in-window."""
    _crucible_root(tmp_path, monkeypatch)
    owner = generate_keypair()
    ts = datetime.now(timezone.utc)
    doc = EngagementAuthority(
        engagement_slug=_SLUG, environment=TargetEnvironment.STAGING, scope=["apme.cm"],
        not_before=ts - timedelta(minutes=1), not_after=ts + timedelta(hours=8), issued_by="owner")
    write_trust_root(TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=owner.public_key_b64)]))
    save_signed_authority(sign_engagement_authority(doc, {"owner": owner.private_key_b64}))
    return owner


def test_skips_when_no_trust_root_pinned(tmp_path, monkeypatch):
    """Backward-compat: with NO trust root, the gate is inert (unsigned/loopback/dev), even for any target."""
    _crucible_root(tmp_path, monkeypatch)   # crucible root, but no trust root written
    assert _authority_scope_gate("anyslug", "http://whatever.example/x", False) is None


def test_in_scope_target_is_allowed(signed_env):
    assert _authority_scope_gate(_SLUG, "http://apme.cm/login", False) is None


def test_out_of_scope_target_is_refused(signed_env):
    r = _authority_scope_gate(_SLUG, "http://evil.example/", False)
    assert r is not None and r[0] == "authority"


def test_absent_authority_falls_back_to_charter_not_a_false_refusal(signed_env):
    """ENFORCE-IF-PRESENT: a trust root is pinned but there is no authority for THIS slug — the tool gate
    SKIPS (returns None), it does NOT fail-closed. This is the correct division of duty: an ambient/foreign
    trust root on disk must never spuriously refuse a charter-only tool op; the fail-closed-on-expected-but-
    absent guarantee lives in the launch gate (_has_verified_authority) and HttpExecutor._authority_gate,
    which have the explicit auto_load signal the tool gate lacks. The charter-scope check (gate 3) still runs."""
    assert _authority_scope_gate("no-such-slug", "http://apme.cm/", False) is None


def test_destructive_refused_when_authority_forbids_it(signed_env):
    """Scope covers the host, but the authority is non-destructive by default — a destructive op is refused."""
    r = _authority_scope_gate(_SLUG, "http://apme.cm/", True)
    assert r is not None and r[0] == "authority"


def test_expired_authority_is_refused(tmp_path, monkeypatch):
    _crucible_root(tmp_path, monkeypatch)
    owner = generate_keypair()
    ts = datetime.now(timezone.utc)
    expired = EngagementAuthority(
        engagement_slug=_SLUG, environment=TargetEnvironment.STAGING, scope=["apme.cm"],
        not_before=ts - timedelta(hours=2), not_after=ts - timedelta(hours=1), issued_by="owner")
    write_trust_root(TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=owner.public_key_b64)]))
    save_signed_authority(sign_engagement_authority(expired, {"owner": owner.private_key_b64}))
    r = _authority_scope_gate(_SLUG, "http://apme.cm/", False)
    assert r is not None and r[0] == "authority"
