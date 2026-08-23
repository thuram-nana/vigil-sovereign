"""`vigil --version` reports product version + build id + git sha, before any gate (W4-2, #442).

Runs in the required "integration two-env boundary (P5)" job (this file is under integration/tests
and not in that job's --ignore list). Importing ``vigil_integration.cli`` pulls no framework/sigil at
module load, and ``main(["--version"])`` returns BEFORE the dispatch/install-manifest gate — so the
version is answerable on a fresh or degraded install, which is the whole point.

FAILS WITHOUT THE FIX: on a tree whose ``main`` has no ``--version`` branch, argparse rejects the
unknown option (SystemExit / non-zero) instead of printing the version line, so these assertions fail.

NEGATIVE CONTROL: an unknown top-level flag must NOT be treated as ``--version`` — it must still be
rejected — proving the intercept is specific, not a catch-all that swallows every flag.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from vigil_integration.cli import main

REPO = Path(__file__).resolve().parents[2]
PRODUCT_VERSION = (REPO / "VERSION").read_text(encoding="utf-8").strip()


def test_version_flag_prints_all_three_facts_and_returns_zero(capsys):
    rc = main(["--version"])
    assert rc == 0
    out = capsys.readouterr().out.strip()
    assert out.startswith("vigil ")
    assert PRODUCT_VERSION in out
    assert "build " in out and "git " in out


def test_short_version_flag_is_equivalent(capsys):
    assert main(["-V"]) == 0
    out = capsys.readouterr().out.strip()
    assert out.startswith(f"vigil {PRODUCT_VERSION} ")


def test_negative_control_unknown_flag_is_not_swallowed_as_version():
    """A different unknown flag must be rejected by argparse (SystemExit), not printed as a version —
    the intercept is exactly ``--version``/``-V``, not "any flag"."""
    with pytest.raises(SystemExit):
        main(["--definitely-not-a-real-flag-zzz"])
