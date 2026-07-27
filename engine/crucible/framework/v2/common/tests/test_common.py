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


def test_charter_path_for_template() -> None:
    cp = paths.charter_path("_template")
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
#
# These tests use a synthetic charter provisioned at tmp_path with a
# monkeypatched paths.charter_path so the suite never depends on any
# operator-specific engagement data. Drop any URL into the framework
# and the same gates apply against your own charter.


_SYNTHETIC_UNSIGNED_CHARTER = """\
# Engagement charter — `synthetic-target.example`

**Status:** Draft
**Date:** 2026-05-04

## 1. Operator attestation

I, **`<name>`**, attest:

- I am the legal owner of the systems listed in § 2.

Signed: `<name>`     Date: `__________`

## 2. In-scope systems

| Host / Surface | Notes | Auth required for testing |
|----------------|-------|---------------------------|
| `synthetic-target.example` | Primary web app | Yes |
| `*.synthetic-target.example` | All subdomains | Yes |
| `api.synthetic-target.example` | Public API | Yes |

## 3. Out of scope

- Anything not listed above.
"""


@pytest.fixture()
def synthetic_target(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    """Provision a synthetic UNSIGNED charter under tmp + redirect
    paths.charter_path for the slug returned. Tests requiring a real
    charter file use this in place of the operator's actual engagement.
    """
    slug = "synthetic-target"
    target_dir = tmp_path / "targets" / slug
    target_dir.mkdir(parents=True)
    (target_dir / "charter.md").write_text(_SYNTHETIC_UNSIGNED_CHARTER, encoding="utf-8")
    monkeypatch.setattr(
        paths, "charter_path",
        lambda s, _td=target_dir: _td / "charter.md" if s == slug else Path("/nonexistent"),
    )
    return slug


def test_charter_unsigned_is_unsigned(synthetic_target: str) -> None:
    """A draft charter with the literal `<name>` placeholder is unsigned."""
    signed, reason = ethics.is_charter_signed(synthetic_target)
    assert not signed
    assert "placeholder" in reason.lower()


def test_require_charter_signed_raises_for_unsigned(synthetic_target: str) -> None:
    with pytest.raises(CharterNotSigned):
        ethics.require_charter_signed(synthetic_target)


def test_require_charter_signed_raises_for_missing() -> None:
    with pytest.raises(CharterMissing):
        ethics.require_charter_signed("does-not-exist")


def _sig_verdict(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, signed_line_body: str) -> tuple:
    """Write a charter whose `Signed:` line is ``Signed:{signed_line_body}`` (the body carries the line
    terminator) followed by a real content line, redirect paths.charter_path, and return
    is_charter_signed's verdict. Probes the signature parser against separator / zero-width evasions."""
    slug = "sig-probe"
    d = tmp_path / "targets" / slug
    d.mkdir(parents=True, exist_ok=True)
    text = "# charter\n\n## 1. Attestation\nSigned:" + signed_line_body + "## 2. In-scope systems\n| `h` | x |\n"
    (d / "charter.md").write_text(text, encoding="utf-8")
    monkeypatch.setattr(paths, "charter_path",
                        lambda s, _p=d / "charter.md": _p if s == slug else Path("/nonexistent"))
    return ethics.is_charter_signed(slug)


# A BLANK `Signed:` line terminated by ANY line separator (not just \n) must NOT slurp the next content
# line as a bogus signature — the seedless-fusion auth-bypass CLASS the red-pen found. str.splitlines()
# splits on all of these; re's ^/$ under MULTILINE would split on \n ALONE (so U+2028/U+2029/U+0085/FS
# would let the value cross the visual break).
@pytest.mark.parametrize("sep", ["\n", "\r\n", "\r", chr(0x85), chr(0x2028), chr(0x2029), chr(0x1c)])
def test_blank_signed_line_any_separator_is_unsigned(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sep: str) -> None:
    signed, reason = _sig_verdict(tmp_path, monkeypatch, sep)
    assert not signed, f"blank Signed line + {sep!r} wrongly read as signed ({reason})"


# An invisible (zero-width / format-character-only) value is not a signature.
@pytest.mark.parametrize("zw", [chr(0x200B), chr(0xFEFF), chr(0x200B) + chr(0xFEFF)])
def test_zero_width_only_signature_is_unsigned(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, zw: str) -> None:
    signed, reason = _sig_verdict(tmp_path, monkeypatch, " " + zw + "\n")
    assert not signed, f"zero-width-only value {zw!r} wrongly read as signed ({reason})"


# Invisible-but-GRAPHICAL code points — Unicode category L/N/P/S yet ZERO visible ink, so a human sees a
# blank Signed: line — must also read as empty. This is the exhaustively-verified COMPLETE set of such
# code points (Default_Ignorable ∩ L/N/P/S, plus braille-blank U+2800): the third route in the
# charter-signature bypass class the re-verification found.
@pytest.mark.parametrize("cp", [0x2800, 0x115F, 0x1160, 0x3164, 0xFFA0])
def test_invisible_graphical_only_signature_is_unsigned(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cp: int) -> None:
    signed, reason = _sig_verdict(tmp_path, monkeypatch, " " + chr(cp) * 4 + "\n")
    assert not signed, f"invisible-graphical U+{cp:04X} x4 wrongly read as signed ({reason})"


@pytest.mark.parametrize("name", ["tester", "Jane Doe", "O'Brien, J. (lead)", "Jos" + chr(0xe9)])
def test_real_signature_is_signed(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    signed, reason = _sig_verdict(tmp_path, monkeypatch, " `" + name + "`   Date: `2026`\n")
    assert signed, f"legit signature {name!r} wrongly rejected ({reason})"


def test_parse_scope_extracts_hosts(synthetic_target: str) -> None:
    scope = ethics.parse_scope(synthetic_target)
    assert "synthetic-target.example" in scope
    assert "*.synthetic-target.example" in scope
    assert "api.synthetic-target.example" in scope


@pytest.mark.parametrize(
    "host,expected",
    [
        ("synthetic-target.example", True),
        ("api.synthetic-target.example", True),
        ("anything.synthetic-target.example", True),  # via wildcard
        ("evil.example", False),
        ("other-target.example", False),
        ("SYNTHETIC-TARGET.EXAMPLE", True),  # case-insensitive
    ],
)
def test_host_matches_scope(synthetic_target: str, host: str, expected: bool) -> None:
    scope = ethics.parse_scope(synthetic_target)
    assert ethics.host_matches_scope(host, scope) == expected


def test_require_in_scope_passes_for_authorized(synthetic_target: str) -> None:
    ethics.require_in_scope(
        synthetic_target, "https://api.synthetic-target.example/v2/users",
    )


def test_require_in_scope_raises_for_unauthorized(synthetic_target: str) -> None:
    with pytest.raises(OutOfScope):
        ethics.require_in_scope(synthetic_target, "https://evil.example/")


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
