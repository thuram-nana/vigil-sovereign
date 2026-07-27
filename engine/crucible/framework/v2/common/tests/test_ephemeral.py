"""
Phase D2 — the ephemeral / ZDR session.

Three guarantees, each tested directly: (1) the tmpfs write-root is created, the per-
engagement write sinks (evidence archive, audit log) re-root under it, and it is PURGED —
its absence VERIFIED — on exit; (2) the sovereignty ZDR/local tier is FORCED for the
session (consumer Anthropic + Claude Code refused) and restored afterwards; (3) everything
restores exactly, so a persisting run in the same process afterward is byte-identical.
"""

from __future__ import annotations

import os

import pytest

from framework.v2.common import ephemeral, paths
from framework.v2.common.errors import EphemeralPurgeError, SovereigntyViolation
from framework.v2.kernel import sovereignty


# ---- tmpfs + purge ----------------------------------------------------------


def test_write_sinks_reroot_under_tmpfs_and_purge_on_exit() -> None:
    assert paths.ephemeral_write_root() is None          # default: persisting
    with ephemeral.ephemeral_session() as sess:
        base = sess.base_dir
        assert base.is_dir()
        assert paths.ephemeral_write_root() == sess.targets_root
        # the two default-path write sinks now live under the tmpfs base, NOT the repo targets/
        ev = paths.evidence_dir("demo", "H-1")
        log = paths.crucible_v2_log("demo")
        assert base in ev.parents and base in log.parents
        # actually write something under the base to prove it is purged even when non-empty
        ev.mkdir(parents=True, exist_ok=True)
        (ev / "response.body").write_text("secret cookie=abc", encoding="utf-8")
    # exit: purged AND verified gone; redirect cleared
    assert not base.exists()
    assert paths.ephemeral_write_root() is None
    # default sinks are back on the real targets/ root
    assert "evidence" in str(paths.evidence_dir("demo", "H-1"))


def test_default_paths_are_byte_identical_without_a_session() -> None:
    # no session active: evidence + log root under the real targets/ tree (unchanged behaviour)
    ev = paths.evidence_dir("slugX", "H-9")
    assert ev == paths.targets_root() / "slugX" / "evidence" / "H-9"
    assert paths.crucible_v2_log("slugX") == paths.targets_root() / "slugX" / ".crucible-v2.log"


def test_purge_failure_raises_fail_closed(monkeypatch) -> None:
    import shutil as _shutil

    real_rmtree = _shutil.rmtree
    leaked = {}

    def _noop_rmtree(path, *a, **k):
        leaked["path"] = path  # refuse to remove -> residual remains

    monkeypatch.setattr(ephemeral.shutil, "rmtree", _noop_rmtree)
    with pytest.raises(EphemeralPurgeError):
        with ephemeral.ephemeral_session():
            pass
    # cleanup the residual the stub refused to remove, with the real rmtree
    if leaked.get("path"):
        real_rmtree(leaked["path"], ignore_errors=True)
    # the redirect + tier were still restored despite the purge failure
    assert paths.ephemeral_write_root() is None
    assert not ephemeral.is_active()


# ---- ZDR / local tier -------------------------------------------------------


def test_session_forces_zdr_tier_and_refuses_public_vendors() -> None:
    prev_tier = sovereignty.current().tier
    with ephemeral.ephemeral_session() as sess:
        assert sess.forced_tier == "TRUSTED_CLOUD"
        pol = sovereignty.current()
        assert pol.tier is sovereignty.Tier.TRUSTED_CLOUD
        assert os.environ.get("CRUCIBLE_SOVEREIGNTY_TIER") == "TRUSTED_CLOUD"
        # the whole point: direct consumer Anthropic + Claude Code are refused at construction
        with pytest.raises(SovereigntyViolation):
            pol.assert_permitted("anthropic")
        with pytest.raises(SovereigntyViolation):
            pol.assert_permitted("claude-code")
        # ZDR + local backends are permitted
        pol.assert_permitted("anthropic-zdr")
        pol.assert_permitted("ollama")
        # and is_sovereign_mode() (what the egress guard reads) is now on
        assert sovereignty.is_sovereign_mode()
    # restored: tier back to what it was, env cleared
    assert sovereignty.current().tier == prev_tier
    assert os.environ.get("CRUCIBLE_SOVEREIGNTY_TIER") is None


def test_air_gapped_override(monkeypatch) -> None:
    monkeypatch.setenv("CRUCIBLE_EPHEMERAL_TIER", "AIR_GAPPED")
    with ephemeral.ephemeral_session() as sess:
        assert sess.forced_tier == "AIR_GAPPED"
        pol = sovereignty.current()
        assert pol.tier is sovereignty.Tier.AIR_GAPPED
        # air-gapped refuses even ZDR cloud — local only
        with pytest.raises(SovereigntyViolation):
            pol.assert_permitted("anthropic-zdr")
        pol.assert_permitted("ollama")


def test_permissive_override_falls_back_to_zdr(monkeypatch) -> None:
    # an operator can't accidentally WEAKEN ephemeral to PERMISSIVE
    monkeypatch.setenv("CRUCIBLE_EPHEMERAL_TIER", "PERMISSIVE")
    with ephemeral.ephemeral_session() as sess:
        assert sess.forced_tier == "TRUSTED_CLOUD"


def test_stricter_ambient_tier_is_not_relaxed_by_ephemeral(monkeypatch) -> None:
    # red-pen BLOCK-1: an operator already at a STRICTER tier than the ZDR default must not be
    # silently RELAXED to TRUSTED_CLOUD by entering ephemeral. Ephemeral only ever TIGHTENS egress.
    monkeypatch.setenv("CRUCIBLE_SOVEREIGNTY_TIER", "SOVEREIGN_CLOUD")   # ambient stricter than TRUSTED_CLOUD
    assert sovereignty.current().tier is sovereignty.Tier.SOVEREIGN_CLOUD
    with ephemeral.ephemeral_session() as sess:
        # forced = stricter(SOVEREIGN_CLOUD, TRUSTED_CLOUD) == SOVEREIGN_CLOUD — NOT relaxed.
        assert sess.forced_tier == "SOVEREIGN_CLOUD"
        assert sovereignty.current().tier is sovereignty.Tier.SOVEREIGN_CLOUD
        assert os.environ.get("CRUCIBLE_SOVEREIGNTY_TIER") == "SOVEREIGN_CLOUD"
    # restored to the ambient stricter tier afterward (env value the operator had set)
    assert sovereignty.current().tier is sovereignty.Tier.SOVEREIGN_CLOUD


def test_ambient_seal_latch_survives_the_session(monkeypatch) -> None:
    # red-pen BLOCK-1: set_policy() clears the X6 seal latch, so _force_tier must snapshot AND
    # restore _sealed_policy directly — an ambient seal that predated the session stays sealed.
    monkeypatch.setenv("CRUCIBLE_SOVEREIGNTY_TIER", "SOVEREIGN_CLOUD")
    monkeypatch.setenv("CRUCIBLE_SOVEREIGNTY_SEALED", "1")
    try:
        sovereignty.current()                                # latch the seal once
        assert sovereignty.is_sealed()
        sealed_tier = sovereignty.current().tier
        with ephemeral.ephemeral_session() as sess:
            assert sess.forced_tier == "SOVEREIGN_CLOUD"     # still not relaxed under a seal
        # the seal latch is restored exactly (not left cleared by the session's set_policy call)
        assert sovereignty.is_sealed()
        assert sovereignty.current().tier == sealed_tier
    finally:
        sovereignty.set_policy(None)                         # clear the latch so it can't leak to other tests


# ---- session bookkeeping ----------------------------------------------------


def test_is_active_and_no_nesting() -> None:
    assert not ephemeral.is_active()
    with ephemeral.ephemeral_session():
        assert ephemeral.is_active()
        with pytest.raises(EphemeralPurgeError):
            with ephemeral.ephemeral_session():
                pass
    assert not ephemeral.is_active()


def test_tier_restored_even_if_body_raises() -> None:
    prev_tier = sovereignty.current().tier
    with pytest.raises(RuntimeError):
        with ephemeral.ephemeral_session():
            raise RuntimeError("boom")
    assert sovereignty.current().tier == prev_tier
    assert paths.ephemeral_write_root() is None
    assert not ephemeral.is_active()


def test_console_run_base_is_tmpfs_and_registered_for_purge() -> None:
    base = ephemeral.console_run_base()
    assert base.is_dir()
    assert str(base) in ephemeral._PENDING_PURGE
    # stable within a process
    assert ephemeral.console_run_base() == base
