"""Tests for common.capabilities — optional-dep probes + opt-in gate (WS-G).

The DEFAULT-path contract: every probe returns a bool without importing the
heavy module, and ``fast_numerics_enabled()`` is False unless BOTH numpy is
importable AND the opt-in flag is set — so an env that merely has numpy stays
on the deterministic path.
"""

from __future__ import annotations

import pytest

from framework.v2.common import capabilities as cap


def test_probes_return_bool() -> None:
    for probe in (cap.has_numpy, cap.has_z3, cap.has_semantic):
        assert isinstance(probe(), bool)


def test_fast_numerics_off_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CRUCIBLE_FAST_NUMERICS", raising=False)
    assert cap.fast_numerics_enabled() is False


def test_fast_numerics_requires_both_flag_and_numpy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Flag alone is not enough — it must AND with numpy importability.
    monkeypatch.setenv("CRUCIBLE_FAST_NUMERICS", "1")
    assert cap.fast_numerics_enabled() == cap.has_numpy()
    # Simulate numpy absent → gate closes even with the flag on.
    monkeypatch.setattr(cap, "has_numpy", lambda: False)
    assert cap.fast_numerics_enabled() is False


@pytest.mark.parametrize("val,expected", [("1", True), ("true", True), ("on", True),
                                          ("YES", True), ("0", False), ("", False),
                                          ("no", False), ("nope", False)])
def test_flag_parsing(monkeypatch: pytest.MonkeyPatch, val: str, expected: bool) -> None:
    monkeypatch.setenv("CRUCIBLE_FAST_NUMERICS", val)
    # gate == flag AND numpy; isolate the flag by ANDing out numpy dependence
    monkeypatch.setattr(cap, "has_numpy", lambda: True)
    assert cap.fast_numerics_enabled() is expected


def test_reset_cache_is_callable() -> None:
    cap.reset_cache()
    # still returns bools after a cache clear
    assert isinstance(cap.has_numpy(), bool)


def test_spec_exists_total_on_junk() -> None:
    # A nonexistent / malformed module name never raises — degrades to False.
    assert cap._spec_exists("definitely_not_a_real_module_xyz") is False
    assert cap._spec_exists("") is False
