"""Regression: `ensure_loopback_charter` materializes the CRUCIBLE charter form of a loopback engage's
authorization so the T2 SQLi re-drive's HttpExecutor scope gate (which reads targets/<slug>/charter.md)
agrees with the engine's own signed --scope authority.

Root cause it guards: an autonomously-launched engage (the chat's per-session slug) had NO charter, so the
re-drive was refused as ``charter_missing`` → reachable=False → a genuinely-confirmed SQLi stayed a LEAD
instead of a FACT, even though the engine's own executor reached the same loopback host.
"""

from __future__ import annotations

import pytest

# This suite exercises `ensure_loopback_charter`, whose writer + reader both resolve
# `framework.v2.common.paths.charter_path` (and it patches `framework.v2.common.ethics`), so it needs the
# offense `framework` — absent in the sovereign CI leg. importorskip so it SKIPS there instead of failing;
# it RUNS in the offense leg, where it is registered in .github/workflows/ci.yml (guard:
# integration/tests/test_ci_framework_tests_run_in_offense_leg.py).
pytest.importorskip("framework")

from vigil_integration.live.wiring import ensure_loopback_charter, _host_is_loopback


def _patch_charter_path(monkeypatch, cp):
    """Point BOTH the writer (wiring) and the reader (ethics) at the same tmp charter path — both call the
    SAME module attribute ``framework.v2.common.paths.charter_path`` at call time."""
    from framework.v2.common import paths as _paths
    monkeypatch.setattr(_paths, "charter_path", lambda slug: cp)


def test_loopback_scope_writes_a_signed_in_scope_charter(tmp_path, monkeypatch):
    from framework.v2.common import ethics
    cp = tmp_path / "targets" / "sluggo" / "charter.md"
    _patch_charter_path(monkeypatch, cp)

    out = ensure_loopback_charter("sluggo", ["127.0.0.1"])
    assert out == str(cp)
    assert cp.is_file()

    # The CRUCIBLE scope gate reads it as SIGNED and 127.0.0.1 as IN-SCOPE — the two conditions the
    # re-drive's validate_action() requires (require_charter_signed + require_in_scope).
    signed, _reason = ethics.is_charter_signed("sluggo")
    assert signed is True
    assert "127.0.0.1" in ethics.parse_scope("sluggo")


def test_non_loopback_scope_writes_nothing(tmp_path, monkeypatch):
    # An external host must NEVER be auto-authorized — it still needs a real, human-signed charter.
    cp = tmp_path / "targets" / "ext" / "charter.md"
    _patch_charter_path(monkeypatch, cp)
    out = ensure_loopback_charter("ext", ["example.com"])
    assert out is None
    assert not cp.exists()


def test_mixed_scope_with_one_external_host_writes_nothing(tmp_path, monkeypatch):
    cp = tmp_path / "targets" / "mixed" / "charter.md"
    _patch_charter_path(monkeypatch, cp)
    out = ensure_loopback_charter("mixed", ["127.0.0.1", "example.com"])
    assert out is None
    assert not cp.exists()


def test_never_overwrites_an_existing_charter(tmp_path, monkeypatch):
    cp = tmp_path / "targets" / "human" / "charter.md"
    cp.parent.mkdir(parents=True)
    cp.write_text("# a real human-signed charter\nSigned: `A Human`\n", encoding="utf-8")
    _patch_charter_path(monkeypatch, cp)
    out = ensure_loopback_charter("human", ["127.0.0.1"])
    assert out is None
    assert "A Human" in cp.read_text(encoding="utf-8")   # untouched


def test_empty_scope_writes_nothing(tmp_path, monkeypatch):
    cp = tmp_path / "targets" / "empty" / "charter.md"
    _patch_charter_path(monkeypatch, cp)
    assert ensure_loopback_charter("empty", []) is None
    assert not cp.exists()


@pytest.mark.parametrize("host,expected", [
    ("127.0.0.1", True), ("127.0.0.5", True), ("::1", True), ("localhost", True),
    ("LOCALHOST", True), ("[::1]", True),
    ("example.com", False), ("10.0.0.1", False), ("0.0.0.0", False), ("", False),
])
def test_host_is_loopback(host, expected):
    assert _host_is_loopback(host) is expected
