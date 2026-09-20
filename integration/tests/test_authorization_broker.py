"""The target-authorization seam broker (vigil_integration.live.authorization_broker).

The import-clean transport both planes agree on: the sovereign cockpit writes an owner-signed bundle, the
offense console reads it back. These lock the write/read/list round-trip, path-safety (an unsafe slug is
refused, never joined into a path), and fail-closed parsing (a malformed/foreign file reads as None, never
a partial-trust default). It carries only public material and makes no trust decision — verification is the
reader's job — so this is transport correctness + safety, not the crypto (that is test_authority).
"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

from vigil_core import (
    AuthorizerKey, EngagementAuthority, TargetEnvironment, TrustRoot, generate_keypair,
    sign_engagement_authority, verify_engagement_authority,
)
from vigil_integration.live import authorization_broker as B


def _signed(host="apme.cm", slug="apme.cm"):
    kp = generate_keypair()
    ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
    doc = EngagementAuthority(engagement_slug=slug, environment=TargetEnvironment.STAGING, scope=[host],
                              not_before=ts, not_after=ts + timedelta(hours=8), issued_by="owner")
    signed = sign_engagement_authority(doc, {"owner": kp.private_key_b64})
    tr = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=kp.public_key_b64)])
    return signed, tr


def test_write_read_round_trip_and_verifies():
    base = tempfile.mkdtemp()
    signed, tr = _signed()
    path = B.write_authorization(base, "apme.cm", signed, tr)
    assert path.is_file()
    got = B.read_authorization(base, "apme.cm")
    assert got is not None and got.slug == "apme.cm"
    ok, reason = verify_engagement_authority(got.signed_authority, got.trust_root)
    assert ok, reason
    # only public material on disk — STRUCTURAL allowlist (every key at every level is public), not a
    # substring scan (which a renamed/encoded secret would evade).
    d = json.loads(path.read_text(encoding="utf-8"))
    assert d["kind"] == "vigil-target-authorization-v1"
    assert "priv" not in path.read_text(encoding="utf-8").lower()
    public = {
        "": {"schema_version", "kind", "slug", "signed_authority", "trust_root"},
        "signed_authority": {"document", "signatures"},
        "signed_authority.document": {"engagement_slug", "environment", "scope", "not_before", "not_after",
                                      "allow_destructive", "live_destructive_acknowledged", "max_actions",
                                      "issued_by", "note"},
        "signed_authority.signatures[]": {"key_id", "signature_b64"},
        "trust_root": {"schema_version", "threshold", "authorizers"},
        "trust_root.authorizers[]": {"key_id", "name", "public_key_b64"},
    }

    def _walk(node, p=""):
        if isinstance(node, dict):
            assert p in public, f"unexpected object at {p!r}: {sorted(node)}"
            assert set(node) <= public[p], f"non-public key(s) at {p!r}: {sorted(set(node) - public[p])}"
            for k, v in node.items():
                _walk(v, f"{p}.{k}" if p else k)
        elif isinstance(node, list):
            for it in node:
                _walk(it, f"{p}[]")

    _walk(d)


def test_list_returns_every_readable_bundle():
    base = tempfile.mkdtemp()
    for slug in ("apme.cm", "app.apme.cm"):
        s, tr = _signed(host=slug, slug=slug)
        B.write_authorization(base, slug, s, tr)
    slugs = sorted(ta.slug for ta in B.list_authorizations(base))
    assert slugs == ["apme.cm", "app.apme.cm"]


@pytest.mark.parametrize("bad", ["../escape", "a/b", "a\\b", "..", "with\nnewline", "", "  "])
def test_unsafe_slug_is_refused_on_write_and_read(bad):
    base = tempfile.mkdtemp()
    signed, tr = _signed()
    with pytest.raises(ValueError):
        B.write_authorization(base, bad, signed, tr)
    assert B.authorization_path(base, bad) is None
    assert B.read_authorization(base, bad) is None


def test_malformed_or_foreign_file_reads_as_none():
    base = tempfile.mkdtemp()
    root = B.authorizations_root(base)
    root.mkdir(parents=True, exist_ok=True)
    (root / "garbage.json").write_text("not json{", encoding="utf-8")
    (root / "foreign.json").write_text(json.dumps({"kind": "something-else"}), encoding="utf-8")
    assert B.read_authorization(base, "garbage") is None
    assert B.read_authorization(base, "foreign") is None
    # a malformed file never appears in the list, and never raises
    assert B.list_authorizations(base) == []


def test_read_of_absent_bundle_is_none():
    assert B.read_authorization(tempfile.mkdtemp(), "nope") is None


def test_broker_imports_no_offense_engine():
    import sys
    for m in [m for m in list(sys.modules) if m.startswith(("framework", "strix"))]:
        sys.modules.pop(m, None)
    from vigil_integration.live import authorization_broker  # noqa: F401
    assert not any(m == "framework" or m.startswith("framework.") or m == "strix" or m.startswith("strix.")
                   for m in sys.modules), "the broker dragged the offense engine into the sovereign process"
