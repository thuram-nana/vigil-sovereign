"""P3 — SIGIL adopts the shared vigil_core, and the offense-free guard widens to bar the Strix agent body.

Pins: sigil.reuse re-exports the SAME objects as vigil_core (no duplicate integrity code), and
assert_no_offense() fails closed if EITHER the CRUCIBLE engine (framework.*) OR the Strix agent body
(strix.*) is loaded into a SIGIL process.
"""
import sys

import pytest

import vigil_core
from sigil.reuse import assert_no_offense, sha256_hex, sign_head, verify_head


def test_reuse_reexports_the_shared_core():
    # SIGIL uses the shared core objects themselves — not a second copy.
    assert sha256_hex is vigil_core.sha256_hex
    assert sign_head is vigil_core.sign_head
    assert verify_head is vigil_core.verify_head


def test_assert_no_offense_passes_when_clean():
    assert_no_offense()  # neither framework.* nor strix.* is loaded


def test_assert_no_offense_bars_the_crucible_engine(monkeypatch):
    monkeypatch.setitem(sys.modules, "framework.v2.engage", object())
    with pytest.raises(RuntimeError, match="sovereignty"):
        assert_no_offense()


def test_assert_no_offense_bars_the_strix_agent_body(monkeypatch):
    monkeypatch.setitem(sys.modules, "strix.agents.factory", object())
    with pytest.raises(RuntimeError, match="sovereignty"):
        assert_no_offense()


def test_bare_offense_namespace_also_barred(monkeypatch):
    monkeypatch.setitem(sys.modules, "strix", object())
    with pytest.raises(RuntimeError, match="sovereignty"):
        assert_no_offense()
