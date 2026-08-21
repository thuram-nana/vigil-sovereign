"""W10-5 (#477) — `vigil panic` trips the real, persistent kill-switch path for EVERY engagement.

Panic's hard-stop has two halves: the process/unit containment (framework-free, covered in
test_down_contains.py) and the GATE-level stop tested here — tripping the persistent, fail-closed
kill-switch for every engagement the offense engine knows, so any in-flight or later-launched gated
action is DENIED even for a process panic does not track.

This half needs the offense engine (`framework.v2.authority.KillSwitch`), so it runs ONLY in the CI
offense leg — `pytest.importorskip("framework...")` skips it cleanly in the sovereign leg (where
`framework` is not importable), and the file is listed in the offense leg of .github/workflows/ci.yml.

Run: PYTHONPATH=integration:engine/crucible:gateway python -m pytest integration/tests/test_panic.py -q
"""
from __future__ import annotations

import pytest

pytest.importorskip("framework.v2.authority.killswitch")

from framework.v2.authority.killswitch import KillSwitch  # noqa: E402
from framework.v2.common import paths  # noqa: E402

from vigil_integration import cli  # noqa: E402


@pytest.fixture()
def isolated_authority(tmp_path, monkeypatch):
    """Point the authority dir + kill-switch path resolution at a private tmp tree."""
    adir = tmp_path / ".authority"
    adir.mkdir()
    monkeypatch.setattr(paths, "authority_dir", lambda: adir)
    monkeypatch.setattr(paths, "killswitch_path", lambda slug: adir / f"{slug}.halt")
    # secure_dir/secure_write chmod the tmp tree; harmless. Return the dir for the test to seed slugs.
    return adir


def _seed_engagement(adir, slug: str) -> None:
    (adir / f"{slug}.authority.json").write_text('{"slug": "%s"}' % slug, encoding="utf-8")


def test_panic_trips_the_killswitch_for_every_known_engagement(isolated_authority):
    _seed_engagement(isolated_authority, "alpha")
    _seed_engagement(isolated_authority, "beta")

    tripped = cli._trip_all_killswitches(reason="vigil panic")

    assert sorted(tripped) == ["alpha", "beta"]
    assert KillSwitch("alpha").is_tripped()
    assert KillSwitch("beta").is_tripped()
    assert KillSwitch("alpha").reason() == "vigil panic"


def test_panic_does_not_trip_an_unknown_engagement(isolated_authority):
    # NEGATIVE CONTROL: the trip is scoped to engagements that actually exist — it is NOT a blind
    # trip-all-names. A slug with no authority file is left CLEAR (a false "everything halted" that
    # hid a still-live engagement would be worse than useless).
    _seed_engagement(isolated_authority, "alpha")
    tripped = cli._trip_all_killswitches(reason="vigil panic")
    assert tripped == ["alpha"]
    assert not KillSwitch("gamma").is_tripped()  # never seeded → never tripped


def test_panic_preserves_an_existing_killswitch_reason(isolated_authority):
    # Idempotent: an engagement already halted for a specific cause keeps that cause — panic re-affirms
    # the stop without overwriting why it first fired.
    _seed_engagement(isolated_authority, "alpha")
    KillSwitch("alpha").trip("operator hit stop during recon")

    cli._trip_all_killswitches(reason="vigil panic")

    assert KillSwitch("alpha").is_tripped()
    assert KillSwitch("alpha").reason() == "operator hit stop during recon"


def test_panic_finds_a_halt_only_engagement(isolated_authority):
    # A slug present only as a `.halt` (no authority json) is still enumerated and re-affirmed, so a
    # second panic never quietly drops a prior halt.
    (isolated_authority / "delta.halt").write_text('{"slug": "delta", "reason": "prior"}', encoding="utf-8")
    tripped = cli._trip_all_killswitches(reason="vigil panic")
    assert "delta" in tripped
    assert KillSwitch("delta").is_tripped()


def test_no_engagements_trips_nothing_but_does_not_error(isolated_authority):
    # A clean gate (no engagements) trips nothing — panic still hard-stops the process/unit surface
    # (tested elsewhere); this half is honestly a no-op, never a crash.
    assert cli._trip_all_killswitches(reason="vigil panic") == []
