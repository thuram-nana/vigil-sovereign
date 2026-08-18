"""W10-3 #475 — the MONOTONIC anchor must survive ``rm -rf <base>``.

``live.wiring`` used to co-locate the monotonic-counter file at ``<base>/attest-anchor.json`` — inside the
SAME engagement base dir as the usage ledger. So a single ``rm -rf <base>`` erased the ledger AND its
monotonic counter together: deletion stopped being detectable, and a fresh (reset-to-0) counter would let a
rollback re-attest under a LOWER value. The fix moves the counter to a HOST-LEVEL location
(``attestation.anchor.DEFAULT_STATE_DIR``) that lives outside any base dir, with an additive migration that
adopts a legacy in-base counter WITHOUT ever lowering the host floor.

Fail-before / pass-after is provable by reverting the wiring hunk (anchor back inside base): the post-wipe
"host counter still exists" assertion then fails, because the counter went down with the base dir.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from vigil_integration.attestation import anchor as _anchor
from vigil_integration.attestation import read_monotonic_anchor


# ============================ migration semantics (pure, no framework) ============================


def test_default_counter_path_tracks_the_redirectable_state_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(_anchor, "DEFAULT_STATE_DIR", tmp_path / "host")
    p = _anchor.default_counter_path()
    assert p == tmp_path / "host" / "monotonic.counter"     # host-level, read at call time


def test_in_base_anchor_migrates_to_host_and_never_resets(tmp_path, monkeypatch):
    monkeypatch.setattr(_anchor, "DEFAULT_STATE_DIR", tmp_path / "host")
    old = tmp_path / "base" / "attest-anchor.json"
    old.parent.mkdir(parents=True)
    old.write_text("500")                                   # a legacy in-base counter at 500
    host = _anchor.default_counter_path()
    assert not host.exists()

    assert _anchor.migrate_floor(old, host) is True         # adopted
    assert host.exists() and int(host.read_text()) == 500   # host floor seeded to the legacy value

    # a subsequent attest CONTINUES above the migrated floor — it never resets to 1 (which would let a
    # rollback re-attest under a smaller counter).
    a = read_monotonic_anchor(state_path=str(host), tpm_probe=lambda: None)
    assert a.value == 501 and a.grounded == "software"


def test_migration_never_lowers_a_higher_host_floor(tmp_path, monkeypatch):
    # multi-engagement safety: the host counter is shared. A later engagement carrying a LOWER legacy
    # counter must NOT regress the host floor another engagement already advanced.
    monkeypatch.setattr(_anchor, "DEFAULT_STATE_DIR", tmp_path / "host")
    host = _anchor.default_counter_path()
    host.parent.mkdir(parents=True)
    host.write_text("900")                                  # host already at 900

    low = tmp_path / "base2" / "attest-anchor.json"
    low.parent.mkdir(parents=True)
    low.write_text("300")
    assert _anchor.migrate_floor(low, host) is False        # 300 < 900 → no change
    assert int(host.read_text()) == 900                     # never lowered

    high = tmp_path / "base3" / "attest-anchor.json"
    high.parent.mkdir(parents=True)
    high.write_text("1200")
    assert _anchor.migrate_floor(high, host) is True        # 1200 > 900 → raised
    assert int(host.read_text()) == 1200


def test_migration_is_a_noop_without_a_legacy_anchor(tmp_path, monkeypatch):
    monkeypatch.setattr(_anchor, "DEFAULT_STATE_DIR", tmp_path / "host")
    host = _anchor.default_counter_path()
    absent_old = tmp_path / "base" / "attest-anchor.json"   # never existed
    assert _anchor.migrate_floor(absent_old, host) is False
    assert not host.exists()                                # a fresh install creates nothing here


# ============================ end-to-end: the anchor survives a base-dir wipe ============================


def test_anchor_survives_rm_rf_of_the_base_dir(tmp_path, monkeypatch):
    """The core W10-3 guarantee, through the REAL build_engine wiring: after an engage writes an
    attestation, ``rm -rf <base>`` erases the ledger but the host-level monotonic counter SURVIVES with its
    value intact, and the next attest continues strictly above it (never resets below the prior value)."""
    pytest.importorskip("framework.v2.authority.charter", reason="CRUCIBLE (offense) not importable here")

    from types import SimpleNamespace

    from framework.v2.agents import blackboard as _bb
    from vigil_integration.agent.state import ActionType, LLMDecision
    from vigil_integration.live.think_claude import ReplayThinker
    from vigil_integration.live.wiring import EngineConfig, build_engine, provision_authority

    # isolate the CRUCIBLE blackboard + authority store to throwaway dirs (mirrors test_engine_live).
    monkeypatch.setenv("CRUCIBLE_ROOT", str(tmp_path / "crucible-root"))
    db = tmp_path / "bb.sqlite"
    monkeypatch.setattr(_bb, "open_blackboard", lambda **_kw: _bb.Blackboard(db_path=db))

    # pin the host attestation dir to a KNOWN location OUTSIDE the engagement base (overrides the autouse
    # isolation fixture, which lands elsewhere) so the test can inspect it after the wipe.
    host_dir = tmp_path / "host-attest"
    monkeypatch.setattr(_anchor, "DEFAULT_STATE_DIR", host_dir)
    host_counter = _anchor.default_counter_path()

    def _echo_runner(argv, *, timeout=0, output_cap=1 << 20):
        return SimpleNamespace(exit_code=0, stdout="ok", stderr="", timed_out=False, truncated=False)

    base = tmp_path / "live"
    prov = provision_authority(slug="loopback", scope=["127.0.0.1"])
    cfg = EngineConfig(slug="loopback", base_dir=str(base), replay=ReplayThinker([
        LLMDecision(action=ActionType.COMPLETE, summary="done")]), provisioned=prov,
        runner=_echo_runner, max_iterations=4, owner_approves_offense=True)
    report = build_engine(cfg).engage("http://127.0.0.1:18080/search?q=1", objective="smoke")
    assert report.attestation_ref                            # an attestation was minted (attestation-first)

    # the anchor lives HOST-LEVEL, OUTSIDE base — and NOT in the old in-base location.
    assert host_counter.exists() and str(host_dir) not in str(base)
    assert not (base / "attest-anchor.json").exists()        # nothing durable left inside base for the anchor
    v1 = int(host_counter.read_text())
    assert v1 >= 1

    # the destructive act: wipe the whole engagement base dir (ledger + spine + everything).
    shutil.rmtree(base)
    assert not base.exists()

    # the monotonic counter SURVIVED with its value intact — this is the assertion that fails if the anchor
    # is put back inside base (it would have gone down with the wipe).
    assert host_counter.exists(), "the monotonic anchor must survive `rm -rf <base>` (host-level, not in base)"
    assert int(host_counter.read_text()) == v1

    # a fresh attest continues strictly ABOVE the prior value — a rollback cannot re-attest under a reset 0.
    a = read_monotonic_anchor(state_path=str(host_counter), tpm_probe=lambda: None)
    assert a.value > v1
