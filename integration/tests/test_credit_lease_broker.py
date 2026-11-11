"""The credit-launch-lease seam broker (vigil_integration.live.credit_lease_broker, Slice K transport).

The import-clean twin of authorization_broker: the sovereign provisioner writes an owner-signed
CreditLaunchLease bundle under cust_<slug>, the keyless offense driver reads it back and verifies it against
the pinned owner key before any traffic. These lock the write/read/list round-trip, path-safety (an unsafe
slug is refused, never joined into a path), and fail-closed parsing (a malformed/foreign file reads as None,
never a partial-trust default). It carries only public material and makes NO trust decision — verification is
the reader's job — so this is transport correctness + safety, not the crypto (that is test_credit_lease).
"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

from vigil_core import (
    AuthorizerKey, CreditLaunchLease, TrustRoot, generate_keypair,
    sign_credit_launch_lease, verify_credit_launch_lease,
)
from vigil_integration.live import credit_lease_broker as B


def _signed(slug="cust_abc123", org="org_a", host="apme.cm", units=10, nonce="n1"):
    kp = generate_keypair()
    ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
    doc = CreditLaunchLease(engagement_slug=slug, org_id=org, scope_host=host, units_reserved=units,
                            not_before=ts, not_after=ts + timedelta(hours=8), nonce=nonce, issued_at=ts.timestamp())
    signed = sign_credit_launch_lease(doc, {"owner": kp.private_key_b64})
    tr = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=kp.public_key_b64)])
    return signed, tr


def test_write_read_round_trip_and_verifies():
    base = tempfile.mkdtemp()
    signed, tr = _signed()
    path = B.write_credit_lease(base, "cust_abc123", signed, tr)
    assert path.is_file()
    got = B.read_credit_lease(base, "cust_abc123")
    assert got is not None and got.slug == "cust_abc123"
    ok, reason = verify_credit_launch_lease(got.signed_lease, got.trust_root)
    assert ok, reason
    assert got.signed_lease.document.scope_host == "apme.cm" and got.signed_lease.document.org_id == "org_a"
    assert got.signed_lease.document.units_reserved == 10


# --- K4-1 / K5 close-out: settlement markers + tombstones ---------------------------------------------
def test_settlement_marker_record_is_idempotent_and_checked():
    base = tempfile.mkdtemp()
    assert B.is_lease_settled(base, "cust_abc123", "n1") is False     # absent -> not settled
    B.record_lease_settlement(base, "cust_abc123", "n1")
    B.record_lease_settlement(base, "cust_abc123", "n1")              # idempotent re-record
    assert B.is_lease_settled(base, "cust_abc123", "n1") is True
    assert B.is_lease_settled(base, "cust_abc123", "n2") is False     # a DIFFERENT nonce (re-lease) is not settled
    assert B.list_credit_leases(base) == []                          # the sibling marker dir never pollutes the leases glob


def test_tombstone_removes_the_published_bundle():
    base = tempfile.mkdtemp()
    signed, tr = _signed()
    B.write_credit_lease(base, "cust_abc123", signed, tr)
    assert B.read_credit_lease(base, "cust_abc123") is not None
    assert B.tombstone_credit_lease(base, "cust_abc123") is True
    assert B.read_credit_lease(base, "cust_abc123") is None           # no longer a runnable bearer capability
    assert B.tombstone_credit_lease(base, "cust_abc123") is False     # idempotent: no file -> False, never raises


def test_tombstone_nonce_matched_never_clobbers_a_newer_re_lease():
    # K4-1 red-pen LOW: settling an OLD lease (nonce n1) must not remove a concurrently-published NEWER
    # re-lease's bundle (same slug, nonce n2). The old lease's own (slug,nonce) settlement marker still
    # revokes it; the newer bundle stays a runnable bearer capability (only an availability footgun avoided).
    base = tempfile.mkdtemp()
    s2, t2 = _signed(nonce="n2")                                      # the NEWER re-lease is what is published
    B.write_credit_lease(base, "cust_abc123", s2, t2)
    assert B.tombstone_credit_lease(base, "cust_abc123", expect_nonce="n1") is False  # old nonce -> no clobber
    assert B.read_credit_lease(base, "cust_abc123") is not None       # the n2 bundle survives
    assert B.tombstone_credit_lease(base, "cust_abc123", expect_nonce="n2") is True   # matching nonce -> removed
    assert B.read_credit_lease(base, "cust_abc123") is None


def test_settlement_unsafe_slug_is_fail_closed():
    base = tempfile.mkdtemp()
    with pytest.raises(ValueError):
        B.record_lease_settlement(base, "../evil", "n1")
    assert B.is_lease_settled(base, "../evil", "n1") is False          # unsafe slug -> False, never joined into a path


def test_only_public_material_on_disk():
    base = tempfile.mkdtemp()
    signed, tr = _signed()
    path = B.write_credit_lease(base, "cust_abc123", signed, tr)
    raw = path.read_text(encoding="utf-8")
    d = json.loads(raw)
    assert d["kind"] == "vigil-credit-launch-lease-seam-v1"
    assert "priv" not in raw.lower()                      # no private key material ever
    # STRUCTURAL allowlist (every top-level key is public), not a substring scan a renamed secret would evade.
    assert set(d.keys()) == {"schema_version", "kind", "slug", "signed_lease", "trust_root"}
    assert set(d["signed_lease"].keys()) == {"document", "signatures"}


@pytest.mark.parametrize("bad", ["../escape", "a/b", "a\\b", "..", "", "   ", "has\x00nul", "ctrl\x01x"])
def test_unsafe_slug_refused_nothing_written(bad):
    base = tempfile.mkdtemp()
    signed, tr = _signed()
    with pytest.raises(ValueError):
        B.write_credit_lease(base, bad, signed, tr)
    assert B.lease_path(base, bad) is None                # no path derived for an unsafe slug
    assert B.read_credit_lease(base, bad) is None
    # nothing escaped the leases dir (only the dir itself may exist, and only direct *.json children under it)
    import os
    root = B.leases_root(base)
    if os.path.isdir(root):
        assert all(os.path.dirname(os.path.realpath(os.path.join(root, f))) == os.path.realpath(str(root))
                   for f in os.listdir(root))


def test_malformed_and_foreign_files_read_as_none():
    base = tempfile.mkdtemp()
    root = B.leases_root(base)
    root.mkdir(parents=True, exist_ok=True)
    (root / "bad.json").write_text("{ not json", encoding="utf-8")                 # malformed
    (root / "foreign.json").write_text(json.dumps({"kind": "something-else"}), encoding="utf-8")  # wrong kind
    assert B.read_credit_lease(base, "bad") is None
    assert B.read_credit_lease(base, "foreign") is None
    assert B.read_credit_lease(base, "absent") is None                            # absent -> None


def test_list_credit_leases_skips_unreadable():
    base = tempfile.mkdtemp()
    s1, t1 = _signed(slug="cust_one", nonce="n1")
    s2, t2 = _signed(slug="cust_two", nonce="n2")
    B.write_credit_lease(base, "cust_one", s1, t1)
    B.write_credit_lease(base, "cust_two", s2, t2)
    (B.leases_root(base) / "junk.json").write_text("nope", encoding="utf-8")       # unreadable -> skipped
    got = sorted(b.slug for b in B.list_credit_leases(base))
    assert got == ["cust_one", "cust_two"]
