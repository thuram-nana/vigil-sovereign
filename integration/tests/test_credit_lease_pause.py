"""The reversible, nonce-scoped pause-marker seam (vigil_integration.live.credit_lease_pause, pause/resume PR-1).

The sibling of the settlement marker, with the OPPOSITE purpose (reversible halt, not one-way close-out) and
the OPPOSITE failure mode (fail-CLOSED, not fail-open). These lock: the record→resume round-trip, idempotency
on both sides, nonce-scoping and slug-scoping (one pause never bleeds to another nonce or another slug), the
DELIBERATE fail-closed inversion (an existing-but-unreadable marker reads as PAUSED so a paused run never
proceeds), path-containment (an unsafe slug is refused and never escapes the base), and the atomic-write
guarantee (a mid-write failure leaves no partial marker). Default-OFF + money-doctrine-neutral are pinned too.
"""

from __future__ import annotations

import json
import tempfile

import pytest

from vigil_integration.live import credit_lease_pause as P


def _nonces_on_disk(path) -> list:
    return json.loads(path.read_text(encoding="utf-8"))["nonces"]


def test_record_then_paused_true_clear_then_false():
    base = tempfile.mkdtemp()
    assert P.is_lease_paused(base, "cust_abc123", "n1") is False   # DEFAULT-OFF: nothing paused before a record
    P.record_lease_pause(base, "cust_abc123", "n1")
    assert P.is_lease_paused(base, "cust_abc123", "n1") is True    # recorded -> paused
    P.clear_lease_pause(base, "cust_abc123", "n1")
    assert P.is_lease_paused(base, "cust_abc123", "n1") is False   # cleared -> resumed (REVERSIBLE)


def test_double_record_and_double_clear_are_idempotent():
    base = tempfile.mkdtemp()
    p1 = P.record_lease_pause(base, "cust_abc123", "n1")
    p2 = P.record_lease_pause(base, "cust_abc123", "n1")           # idempotent re-record -> same single entry
    assert p1 == p2
    assert P.is_lease_paused(base, "cust_abc123", "n1") is True
    assert _nonces_on_disk(p1) == ["n1"]                           # not duplicated into ["n1", "n1"]
    P.clear_lease_pause(base, "cust_abc123", "n1")
    P.clear_lease_pause(base, "cust_abc123", "n1")                 # idempotent double-clear -> stays empty
    assert P.is_lease_paused(base, "cust_abc123", "n1") is False
    assert _nonces_on_disk(p1) == []


def test_nonce_scoped_pause_isolates_nonces_within_a_slug():
    # NONCE-SCOPED: pausing nonce A must leave nonce B (same slug) unpaused. This is the guard the second
    # mutation breaks (is_lease_paused ignoring the nonce / True for any nonce once any is recorded).
    base = tempfile.mkdtemp()
    P.record_lease_pause(base, "cust_abc123", "nonceA")
    assert P.is_lease_paused(base, "cust_abc123", "nonceA") is True    # A is paused
    assert P.is_lease_paused(base, "cust_abc123", "nonceB") is False   # B (same slug) is NOT paused
    # the two nonces move independently: pause B too, clear A, and only B stays paused.
    P.record_lease_pause(base, "cust_abc123", "nonceB")
    P.clear_lease_pause(base, "cust_abc123", "nonceA")
    assert P.is_lease_paused(base, "cust_abc123", "nonceA") is False   # A resumed
    assert P.is_lease_paused(base, "cust_abc123", "nonceB") is True    # B still paused
    assert sorted(_nonces_on_disk(P.pause_path(base, "cust_abc123"))) == ["nonceB"]


def test_slug_scoped_pause_does_not_bleed_across_slugs():
    # SLUG-scoped: a pause on one tenant's slug must never pause another tenant's slug (tenant isolation).
    base = tempfile.mkdtemp()
    P.record_lease_pause(base, "cust_one", "n1")
    assert P.is_lease_paused(base, "cust_one", "n1") is True
    assert P.is_lease_paused(base, "cust_two", "n1") is False          # a DIFFERENT slug is unaffected
    assert not P.pause_path(base, "cust_two").is_file()                # and no marker file was created for it


def test_unreadable_or_corrupt_marker_fails_closed_to_paused():
    # THE deliberate inversion vs is_lease_settled (which fails OPEN to False): an EXISTING marker that cannot
    # be read cleanly must read as PAUSED (True), so a run that should be paused never proceeds. This is the
    # guard the first mutation breaks (except-branch returning False instead of True).
    base = tempfile.mkdtemp()
    root = P.pauses_root(base)
    root.mkdir(parents=True, exist_ok=True)
    marker = root / "cust_abc123.json"

    marker.write_text("{ this is not valid json", encoding="utf-8")                         # corrupt JSON
    assert P.is_lease_paused(base, "cust_abc123", "n1") is True
    marker.write_text(json.dumps({"kind": "something-else", "nonces": ["n1"]}), encoding="utf-8")  # foreign kind
    assert P.is_lease_paused(base, "cust_abc123", "n1") is True
    marker.write_text(json.dumps({"kind": P._PAUSE_SCHEMA, "nonces": "n1"}), encoding="utf-8")      # malformed set
    assert P.is_lease_paused(base, "cust_abc123", "n1") is True

    # the inversion's safety boundary — the ONLY two False states:
    marker.write_text(json.dumps({"kind": P._PAUSE_SCHEMA, "nonces": []}), encoding="utf-8")  # clean, nonce ABSENT
    assert P.is_lease_paused(base, "cust_abc123", "n1") is False
    assert P.is_lease_paused(base, "cust_absent", "n1") is False                              # no marker at all


@pytest.mark.parametrize("bad", ["../evil", "a/b", "a\\b", "..", "", "   ", "p\x00q", "ctrl\x01x"])
def test_path_containment_unsafe_slug_refused_and_never_escapes(bad):
    # An unsafe slug is REFUSED by the writers (ValueError) and never joined into a path; the reader
    # fails CLOSED (True) without touching the filesystem, so nothing can escape the pauses dir.
    base = tempfile.mkdtemp()
    with pytest.raises(ValueError):
        P.record_lease_pause(base, bad, "n1")
    with pytest.raises(ValueError):
        P.clear_lease_pause(base, bad, "n1")
    assert P.pause_path(base, bad) is None                            # no path derived for an unsafe slug
    assert P.is_lease_paused(base, bad, "n1") is True                 # fail-CLOSED: unresolvable identity -> halt
    # nothing escaped the pauses dir (only direct *.json children of it may exist, and here none should)
    import os
    root = P.pauses_root(base)
    if os.path.isdir(root):
        for f in os.listdir(root):
            real = os.path.realpath(os.path.join(root, f))
            assert os.path.dirname(real) == os.path.realpath(str(root))


def test_atomic_write_leaves_no_partial_file_on_midwrite_failure():
    # The broker's _atomic_write_json writes a tmp file then os.replace()s it into place. Simulate a crash
    # BEFORE the atomic rename: the target marker must NOT exist and no tmp must be left behind.
    base = tempfile.mkdtemp()
    import vigil_integration.live.credit_lease_broker as B

    def _boom(*_a, **_k):
        raise OSError("simulated mid-write crash before the atomic rename")

    original_replace = B.os.replace
    B.os.replace = _boom
    try:
        with pytest.raises(OSError):
            P.record_lease_pause(base, "cust_abc123", "n1")
    finally:
        B.os.replace = original_replace

    assert P.pause_path(base, "cust_abc123") is not None
    assert not P.pause_path(base, "cust_abc123").is_file()            # no partial target file was published
    root = P.pauses_root(base)
    leftovers = sorted(p.name for p in root.iterdir()) if root.is_dir() else []
    assert leftovers == [], f"left a partial/tmp file behind: {leftovers}"   # the finally-unlink cleaned the tmp
    # and the primitive is not globally broken — a real record now succeeds and reads back paused.
    P.record_lease_pause(base, "cust_abc123", "n1")
    assert P.is_lease_paused(base, "cust_abc123", "n1") is True


def test_marker_on_disk_is_pause_only_and_money_doctrine_neutral():
    # MONEY-DOCTRINE-NEUTRAL: the marker carries ONLY the pause set — no credit / amount / catalog / signature
    # field. Pausing moves no money; it only flips a reversible halt flag for a nonce.
    base = tempfile.mkdtemp()
    path = P.record_lease_pause(base, "cust_abc123", "n1")
    d = json.loads(path.read_text(encoding="utf-8"))
    assert set(d.keys()) == {"schema_version", "kind", "slug", "nonces"}
    assert d["kind"] == "vigil-credit-lease-pause-v1"
    assert d["slug"] == "cust_abc123" and d["nonces"] == ["n1"]
    # The structural key allowlist above is the real guarantee (no money field can hide in it). This scan is
    # belt-and-braces for amount/secret leakage — "credit" is excluded, it is the module's own domain name.
    raw = path.read_text(encoding="utf-8").lower()
    for forbidden in ("units", "amount", "price", "catalog", "signature", "priv"):
        assert forbidden not in raw


def test_pauses_dir_is_a_sibling_that_never_pollutes_the_leases_glob():
    # The pauses dir is a sibling of the leases dir, so writing a pause never shows up as a lease bundle.
    base = tempfile.mkdtemp()
    import vigil_integration.live.credit_lease_broker as B
    P.record_lease_pause(base, "cust_abc123", "n1")
    assert B.list_credit_leases(base) == []                          # the pauses marker is not a lease bundle
    assert P.pauses_root(base) != B.leases_root(base)
    assert P.pauses_root(base) != B.settlements_root(base)
