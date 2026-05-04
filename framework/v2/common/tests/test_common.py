"""Smoke tests for common.{paths, docs, ethics}."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from framework.v2.common import docs, ethics, paths
from framework.v2.common.errors import (
    CharterMissing,
    CharterNotSigned,
    CrucibleRootNotFound,
    OutOfScope,
)


# --- paths --------------------------------------------------------------


def test_crucible_root_resolves() -> None:
    root = paths.crucible_root()
    assert (root / "CLAUDE.md").is_file()


def test_v2_root_under_crucible_root() -> None:
    assert paths.v2_root().parent.name == "framework"
    assert paths.v2_root().parent.parent == paths.crucible_root()


def test_charter_path_for_mrbeanpanel() -> None:
    cp = paths.charter_path("mrbeanpanel")
    assert cp.is_file()


def test_is_within() -> None:
    root = paths.crucible_root()
    assert paths.is_within(root / "framework" / "v2", root)
    assert not paths.is_within(Path("/etc"), root)


def test_root_with_bad_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CRUCIBLE_ROOT", "/nonexistent/path/that/is/not/real")
    paths._reset_cache()
    # walking up from this module's location still finds the real root
    assert paths.crucible_root().joinpath("CLAUDE.md").is_file()
    paths._reset_cache()


# --- docs ---------------------------------------------------------------


COGNITIVE_DOCS = (
    "reasoning-loops",
    "hypothesis-driven",
    "self-critique",
    "pivot-protocols",
    "decision-frameworks",
    "opsec-discipline",
    "threat-modeling",
    "kill-chain",
)


@pytest.mark.parametrize("stem", COGNITIVE_DOCS)
def test_cognitive_doc_loads(stem: str) -> None:
    doc = docs.cognitive(stem)
    assert len(doc.sections) > 0
    assert all(s.heading for s in doc.sections)
    assert all(s.anchor for s in doc.sections)


def test_section_lookup() -> None:
    doc = docs.cognitive("hypothesis-driven")
    sec = doc.section("1-the-hypothesis-form")
    assert sec.level == 2
    assert "given" in sec.body.lower()


def test_section_find_substring() -> None:
    doc = docs.cognitive("self-critique")
    sec = doc.find("quick", "critique")
    assert sec is not None
    assert "quick critique" in sec.heading.lower()


# --- ethics -------------------------------------------------------------


def test_charter_unsigned_is_unsigned() -> None:
    """The mrbeanpanel charter ships unsigned (placeholder name)."""
    signed, reason = ethics.is_charter_signed("mrbeanpanel")
    assert not signed
    assert "placeholder" in reason.lower()


def test_require_charter_signed_raises_for_unsigned() -> None:
    with pytest.raises(CharterNotSigned):
        ethics.require_charter_signed("mrbeanpanel")


def test_require_charter_signed_raises_for_missing() -> None:
    with pytest.raises(CharterMissing):
        ethics.require_charter_signed("does-not-exist")


def test_parse_scope_extracts_hosts() -> None:
    scope = ethics.parse_scope("mrbeanpanel")
    assert "mrbeanpanel.com" in scope
    assert "*.mrbeanpanel.com" in scope
    assert "api.mrbeanpanel.com" in scope


@pytest.mark.parametrize(
    "host,expected",
    [
        ("mrbeanpanel.com", True),
        ("api.mrbeanpanel.com", True),
        ("anything.mrbeanpanel.com", True),  # via wildcard
        ("evil.com", False),
        ("beansms.com", False),  # operator-owned but separate target
        ("MRBEANPANEL.COM", True),  # case-insensitive
    ],
)
def test_host_matches_scope(host: str, expected: bool) -> None:
    scope = ethics.parse_scope("mrbeanpanel")
    assert ethics.host_matches_scope(host, scope) == expected


def test_require_in_scope_passes_for_authorized() -> None:
    ethics.require_in_scope("mrbeanpanel", "https://api.mrbeanpanel.com/v2/users")


def test_require_in_scope_raises_for_unauthorized() -> None:
    with pytest.raises(OutOfScope):
        ethics.require_in_scope("mrbeanpanel", "https://evil.com/")


def test_authorization_ledger_round_trip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Append a line, expect is_authorized to return True. Restore afterward."""
    led = ethics.authorization_ledger()
    original = led.read_text(encoding="utf-8") if led.exists() else None
    try:
        ethics.init_authorization_ledger()
        with led.open("a", encoding="utf-8") as f:
            f.write(f"\n{ethics.now_iso()} | testbot | smoke-test.example\n")
        assert ethics.is_authorized_for_intake("https://smoke-test.example/")
        assert not ethics.is_authorized_for_intake("https://other.example/")
    finally:
        if original is not None:
            led.write_text(original, encoding="utf-8")
        else:
            led.unlink(missing_ok=True)
