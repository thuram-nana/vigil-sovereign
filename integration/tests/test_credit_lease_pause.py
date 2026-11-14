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
    # (the writer's own `<slug>.json.lock` is a deliberate transient — E3bc's cross-process marker lock — not a
    # partial marker: the `*.json` readers never match it and the backups skip `*.lock`)
    leftovers = sorted(p.name for p in root.iterdir() if not p.name.endswith(".json.lock")) if root.is_dir() else []
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


def test_is_file_raising_fails_closed_reader_is_total_not_just_on_corrupt_content(monkeypatch):
    """[red-pen MED fold] The reader is documented TOTAL ('never raises') + fail-CLOSED. The corrupt-CONTENT
    case is covered above; this pins the stat() case. ``Path.is_file()`` swallows ENOENT but NOT EACCES, so on
    the KEYLESS plane a sovereign-written marker under a DIFFERENT uid makes stat() raise PermissionError. The
    probe must sit INSIDE the fail-closed try so that raise is CAUGHT -> True (halt), never propagated — a pause
    reader that threw would crash the gate rather than halt. (Move is_file() back OUTSIDE the try and
    ``is_lease_paused`` RAISES here instead of returning True.)"""
    import pathlib
    base = tempfile.mkdtemp()
    P.record_lease_pause(base, "cust_abc123", "n1")                 # a real marker exists on disk

    def _boom(self):
        raise PermissionError(13, "Permission denied (simulated EACCES on stat)")

    monkeypatch.setattr(pathlib.Path, "is_file", _boom)
    # is_file() raising is "cannot positively read 'not paused'" -> HALT, for BOTH a recorded and an
    # unrecorded nonce; and it must RETURN (total), never propagate the PermissionError.
    assert P.is_lease_paused(base, "cust_abc123", "n1") is True
    assert P.is_lease_paused(base, "cust_abc123", "nonce-not-recorded") is True


# ---------------------------------------------------------------------------------------------------
# base_dir=None — the pause substrate resolves the DEFAULT seam base exactly as the lease reader does
# ---------------------------------------------------------------------------------------------------
#
# The lease verify (framework.v2.launch_lease) accepts ``base_dir=None`` and resolves it to ``VIGIL_BASE_DIR``
# (else ``.vigil-live``); every launch-runner factory defaults ``base_dir=None``. The pause reader used to raise
# ``TypeError`` on that same None, which the launch gate swallowed as "not paused" — so a paused, queued launch
# was classified TERMINAL and stranded. These pin that None is resolved, one way, at the path chokepoint.
# (The equality with the engine's own resolver is pinned where ``framework`` is importable, in
# test_launch_pause_redrive_gate.py.)


def test_none_base_dir_reads_the_default_seam_base(monkeypatch, tmp_path):
    seam = tmp_path / "seam"
    monkeypatch.setenv("VIGIL_BASE_DIR", str(seam))
    assert P.pauses_root(None) == P.pauses_root(str(seam))
    assert P.pause_path(None, "cust_abc123") == P.pause_path(str(seam), "cust_abc123")
    assert P.is_lease_paused(None, "cust_abc123", "n1") is False       # answers (no TypeError); DEFAULT-OFF
    P.record_lease_pause(str(seam), "cust_abc123", "n1")               # the sovereign writer names the seam ...
    assert P.is_lease_paused(None, "cust_abc123", "n1") is True        # ... and a None-default reader SEES the pause
    assert P.is_lease_paused(None, "cust_abc123", "other") is False    # still nonce-scoped through the default
    assert dict(P.paused_launches(None)) == {"cust_abc123": ["n1"]}
    P.clear_lease_pause(None, "cust_abc123", "n1")                     # the writers resolve None identically
    assert P.is_lease_paused(str(seam), "cust_abc123", "n1") is False


def test_none_base_dir_falls_back_to_dot_vigil_live_when_the_env_is_unset_or_empty(monkeypatch, tmp_path):
    from pathlib import Path
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("VIGIL_BASE_DIR", raising=False)
    assert P.pauses_root(None) == Path(".vigil-live") / "credit-lease-pauses"
    monkeypatch.setenv("VIGIL_BASE_DIR", "")                           # empty counts as unset (``or``), as for the lease
    assert P.pauses_root(None) == Path(".vigil-live") / "credit-lease-pauses"
    P.record_lease_pause(str(tmp_path / ".vigil-live"), "cust_abc123", "n1")
    assert P.is_lease_paused(None, "cust_abc123", "n1") is True


def test_only_none_is_defaulted_an_explicit_base_is_used_as_given(monkeypatch, tmp_path):
    # ``is not None`` — the SAME test the lease reader applies — so an explicit base (even "") is never silently
    # redirected to the env default: a caller that names a seam reads THAT seam.
    from pathlib import Path
    env_seam, explicit = tmp_path / "env-seam", tmp_path / "explicit"
    monkeypatch.setenv("VIGIL_BASE_DIR", str(env_seam))
    P.record_lease_pause(str(env_seam), "cust_abc123", "n1")
    assert P.is_lease_paused(str(explicit), "cust_abc123", "n1") is False   # the explicit seam has no pause
    assert P.pauses_root(str(explicit)) == explicit / "credit-lease-pauses"
    assert P.pauses_root("") == Path("") / "credit-lease-pauses"            # "" is NOT defaulted


# ---------------------------------------------------------------------------------------------------
# unreadable_pause_markers — the holds the fail-open projection cannot see (what `vigil doctor` reports)
# ---------------------------------------------------------------------------------------------------


def _seed_marker_zoo(base):
    """One readable pause, one readable-but-empty marker, and three markers the halt reader cannot read."""
    P.record_lease_pause(base, "cust_ok", "n1")
    root = P.pauses_root(base)
    (root / "cust_empty.json").write_text(json.dumps({"kind": P._PAUSE_SCHEMA, "nonces": []}), encoding="utf-8")
    (root / "cust_corrupt.json").write_text("{ this is not valid json", encoding="utf-8")
    (root / "cust_foreign.json").write_text(json.dumps({"kind": "something-else", "nonces": ["n1"]}),
                                            encoding="utf-8")
    (root / "cust_badset.json").write_text(json.dumps({"kind": P._PAUSE_SCHEMA, "nonces": "n1"}), encoding="utf-8")
    (root / "notes.txt").write_text("not a marker", encoding="utf-8")
    return root


def test_unreadable_pause_markers_lists_exactly_the_slugs_the_reader_halts_on(tmp_path):
    base = str(tmp_path)
    assert P.unreadable_pause_markers(base) == []                       # DEFAULT-OFF: no pauses dir at all
    assert P.unreadable_pause_markers(str(tmp_path / "nope")) == []     # absent base: total, never raises
    _seed_marker_zoo(base)
    got = P.unreadable_pause_markers(base)
    assert got == ["cust_badset", "cust_corrupt", "cust_foreign"]       # sorted; slug only
    # The listing IS the halt predicate: a slug is listed iff the fail-CLOSED reader holds a nonce that was
    # NEVER recorded for it (i.e. it halts every launch of the slug, not just a paused one).
    for slug in ("cust_ok", "cust_empty", "cust_corrupt", "cust_foreign", "cust_badset"):
        assert (slug in got) == P.is_lease_paused(base, slug, "a-nonce-never-recorded"), slug
    # ... and it is exactly what the fail-open projection hides (why a separate probe is needed).
    assert [s for s, _ in P.paused_launches(base)] == ["cust_ok"]


def test_unreadable_pause_markers_reports_a_permission_denied_marker(monkeypatch, tmp_path):
    # The keyless-plane case: the marker exists but cannot be READ (EACCES). The reader halts on it, so it is a hold.
    import pathlib
    base = str(tmp_path)
    P.record_lease_pause(base, "cust_denied", "n1")
    P.record_lease_pause(base, "cust_fine", "n1")
    real = pathlib.Path.read_text

    def _read_text(self, *a, **k):
        if self.name == "cust_denied.json":
            raise PermissionError(13, "Permission denied (simulated EACCES on read)")
        return real(self, *a, **k)

    monkeypatch.setattr(pathlib.Path, "read_text", _read_text)
    assert P.is_lease_paused(base, "cust_denied", "nonce-not-recorded") is True
    assert P.unreadable_pause_markers(base) == ["cust_denied"]


def test_unreadable_pause_markers_reports_a_marker_that_resolves_outside_the_pauses_dir(tmp_path):
    # A marker that is a symlink out of the pauses dir fails the reader's containment barrier, so the reader
    # halts on it even though its TARGET parses cleanly. Listing by the reader's own read (not a second parse of
    # the globbed file) is what keeps the two in agreement here.
    base = str(tmp_path / "base")
    outside = tmp_path / "elsewhere.json"
    outside.write_text(json.dumps({"kind": P._PAUSE_SCHEMA, "nonces": []}), encoding="utf-8")
    root = P.pauses_root(base)
    root.mkdir(parents=True)
    (root / "cust_link.json").symlink_to(outside)
    assert P.is_lease_paused(base, "cust_link", "nonce-not-recorded") is True
    assert P.unreadable_pause_markers(base) == ["cust_link"]


def test_unreadable_pause_markers_never_echoes_a_non_canonical_file_name(tmp_path):
    # A file whose stem is not a canonical safe slug component is not ANY slug's marker (no lookup resolves to
    # it), so it holds nothing — and its name (which could carry terminal control bytes) is never echoed onto an
    # operator surface.
    base = str(tmp_path)
    root = P.pauses_root(base)
    root.mkdir(parents=True)
    (root / "ctrl\x1b[31mx.json").write_text("{ corrupt", encoding="utf-8")
    (root / " padded.json").write_text("{ corrupt", encoding="utf-8")
    (root / "cust_real.json").write_text("{ corrupt", encoding="utf-8")
    assert P.unreadable_pause_markers(base) == ["cust_real"]


# ---------------------------------------------------------------------------------------------------
# pause_store_unreadable — the pauses DIRECTORY itself cannot be read (the all-tenant form of an unreadable
# marker). Root bypasses permission bits, so the deterministic tests simulate the two errno classes the kernel
# returns; the real-permission test runs wherever the suite is not root.
# ---------------------------------------------------------------------------------------------------


def _deny(monkeypatch, root, *, lookup: bool, listing: bool):
    """Make ``root`` behave like a directory this uid cannot search (``lookup``) and/or cannot list (``listing``),
    the way a root-owned 0700 restore does for the service uid: stat of a child raises EACCES, scandir raises
    EACCES. Everything outside ``root`` is untouched."""
    import os as _os
    real_stat, real_scandir = _os.stat, _os.scandir
    root_s = str(root)

    def _stat(path, *a, **k):
        if lookup and _os.fspath(path).startswith(root_s + _os.sep):
            raise PermissionError(13, "Permission denied (simulated: directory not searchable)")
        return real_stat(path, *a, **k)

    def _scandir(path=".", *a, **k):
        if listing and _os.fspath(path) == root_s:
            raise PermissionError(13, "Permission denied (simulated: directory not listable)")
        return real_scandir(path, *a, **k)

    monkeypatch.setattr(_os, "stat", _stat)
    monkeypatch.setattr(_os, "scandir", _scandir)


def test_pause_store_unreadable_is_none_by_default_and_for_a_healthy_store(tmp_path):
    base = str(tmp_path)
    assert P.pause_store_unreadable(base) is None                        # DEFAULT-OFF: no pauses dir at all
    assert P.pause_store_unreadable(str(tmp_path / "nope")) is None      # absent base: total, never raises
    _seed_marker_zoo(base)                                               # a healthy dir (unreadable FILES are
    assert P.pause_store_unreadable(base) is None                        # reported per slug, not as the store)
    (tmp_path / "f").write_text("x", encoding="utf-8")                   # a base that is a FILE: lookups answer
    assert P.is_lease_paused(str(tmp_path / "f"), "cust_x", "n") is False   # "no marker", so nothing is held ...
    assert P.pause_store_unreadable(str(tmp_path / "f")) is None         # ... and the store is not reported


def test_an_unsearchable_pause_store_holds_every_slug_and_is_reported_as_a_lookup_failure(monkeypatch, tmp_path):
    base = str(tmp_path)
    P.record_lease_pause(base, "cust_other", "n-other")                  # one clean marker for ANOTHER slug
    _deny(monkeypatch, P.pauses_root(base), lookup=True, listing=True)
    # the halt reader fails CLOSED for a slug that was never paused (unchanged, and why this is an all-tenant hold);
    # on a real permission failure the per-file listings are blind too (pathlib's glob swallows the error — pinned
    # by the real-permission test below, since the glob binds its own scandir), so the store probe reports it
    assert P.is_lease_paused(base, "cust_never_paused", "n1") is True
    assert P.pause_store_unreadable(base) == P.STORE_LOOKUP_FAILS == "lookup"


def test_a_searchable_but_unlistable_pause_store_is_reported_as_a_listing_failure(monkeypatch, tmp_path):
    base = str(tmp_path)
    P.record_lease_pause(base, "cust_other", "n-other")
    _deny(monkeypatch, P.pauses_root(base), lookup=False, listing=True)
    assert P.is_lease_paused(base, "cust_never_paused", "n1") is False   # lookups still answer, but the store
    assert P.is_lease_paused(base, "cust_other", "n-other") is True      # cannot be enumerated
    assert P.pause_store_unreadable(base) == P.STORE_LISTING_FAILS == "listing"


@pytest.mark.skipif(not hasattr(__import__("os"), "geteuid") or __import__("os").geteuid() == 0,
                    reason="root bypasses directory permission bits")
def test_pause_store_unreadable_on_real_directory_permissions(tmp_path):
    import os as _os
    base = str(tmp_path)
    P.record_lease_pause(base, "cust_other", "n-other")
    root = P.pauses_root(base)
    try:
        _os.chmod(root, 0o000)                                           # neither listable nor searchable
        assert P.is_lease_paused(base, "cust_never_paused", "n1") is True
        assert P.paused_launches(base) == [] and P.unreadable_pause_markers(base) == []   # the listings are blind
        assert P.pause_store_unreadable(base) == "lookup"
        _os.chmod(root, 0o400)                                           # listable, not searchable
        assert P.pause_store_unreadable(base) == "lookup"
        _os.chmod(root, 0o100)                                           # searchable, not listable
        assert P.is_lease_paused(base, "cust_never_paused", "n1") is False
        assert P.pause_store_unreadable(base) == "listing"
    finally:
        _os.chmod(root, 0o700)
    assert P.pause_store_unreadable(base) is None
