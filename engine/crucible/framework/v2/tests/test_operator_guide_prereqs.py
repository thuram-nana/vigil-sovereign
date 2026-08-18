"""
W16-18 (#524) — the Operator's Guide must document two coverage prerequisites a
hands-on operator would otherwise miss, because missing either silently shrinks
what an engagement actually tests:

  1. Authenticated scanning EXISTS (scanner/session.py: AuthSession + LoginSequence)
     and the guide must say how to reach it — otherwise an operator tests only the
     anonymous front door and never sees the surface behind a login.

  2. The OOB relay is a PREREQUISITE for four of the eleven always-on seed checks
     (SSRF / XXE / RCE / deserialization). Without a relay these are INERT against a
     remote target — skipped, never guessed — so an unaware operator sees no findings
     of those classes and wrongly concludes the target is clean.

This is a doc-truth (grep-style) assertion: it fails if either prerequisite — or,
crucially, the inert-checks caveat — is removed from the user-facing chapter. The
guide's prose wraps and uses markdown emphasis, so the text is normalised (lower-
cased, backticks/asterisks stripped, whitespace collapsed) before substring checks
so a claim split across a line break still counts.
"""

from __future__ import annotations

import re
from pathlib import Path

_REPO = Path(__file__).resolve().parents[3]        # framework/v2/tests/ -> crucible root
_GUIDE = _REPO / "framework" / "v2" / "docs" / "OPERATOR-GUIDE.md"


def _norm(text: str) -> str:
    """Lower-case, strip markdown emphasis/code ticks, collapse whitespace — so a
    substring assertion is robust to line wrapping and `code`/**bold** markup."""
    text = text.replace("`", "").replace("*", "")
    return re.sub(r"\s+", " ", text).lower()


def test_the_operator_guide_exists() -> None:
    assert _GUIDE.is_file(), f"missing user-facing chapter: {_GUIDE}"


def test_authenticated_scanning_prerequisite_is_documented() -> None:
    doc = _norm(_GUIDE.read_text(encoding="utf-8"))
    # (a) the capability exists and is named by its real API, so the doc is grounded
    #     in shipped code, not aspiration.
    for needle in ("authenticated scanning", "behind a login", "authsession", "loginsequence"):
        assert needle in doc, f"OPERATOR-GUIDE no longer documents authenticated scanning: {needle!r} absent"
    # (b) how to enable it — the honest 'building block, not a login flag' framing plus
    #     the two-identity access-control pack that IS on the command line.
    for needle in ("building block", "access-control", "ac-victim-header"):
        assert needle in doc, f"OPERATOR-GUIDE no longer says how to enable authenticated scanning: {needle!r} absent"


def test_oob_relay_prerequisite_and_inert_checks_caveat_are_documented() -> None:
    doc = _norm(_GUIDE.read_text(encoding="utf-8"))
    # the relay itself is the prerequisite, and the four affected classes must be named.
    for needle in ("relay", "ssrf", "xxe", "rce", "deserialization"):
        assert needle in doc, f"OPERATOR-GUIDE no longer names the OOB relay / affected class: {needle!r} absent"
    # the load-bearing CAVEAT: without a relay these checks are inert against a remote target —
    # NOT skipped: the engine still exercises them (injects blind payloads) but the loopback
    # callback can't return, so nothing confirms and an operator wrongly concludes 'clean'.
    for needle in ("inert", "exercises", "remote target", "wrongly concludes", "clean"):
        assert needle in doc, f"OPERATOR-GUIDE no longer states the inert-checks caveat: {needle!r} absent"
    # the count claim ('four of eleven') is grounded in scanner.checks.DEFAULT_CHECKS.
    assert "eleven" in doc and "four" in doc, "OPERATOR-GUIDE no longer states four-of-eleven checks are OOB"


def test_negative_control() -> None:
    doc = _norm(_GUIDE.read_text(encoding="utf-8"))
    # Positive: an UNRELATED pre-existing anchor is present — proves the file is being
    # read and grep works (so a failure above is a real absence, not a broken path).
    assert "kill-switch" in doc, "sanity: the guide should still contain its kill-switch section"
    # Negative: a fabricated claim the fix explicitly refutes must be ABSENT — proves the
    # substring test can return False (it is not trivially always-true).
    assert "oob checks run against remote targets without a relay" not in doc
