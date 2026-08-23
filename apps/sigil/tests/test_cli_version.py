"""`sigil --version` reports product version + build id + git sha, before any gate (W4-2, #442).

Runs in the required "SIGIL governor gates (P7 — offense gate + authn)" job, which runs the whole
``apps/sigil/tests/`` directory. ``--version`` short-circuits BEFORE logging setup and the
install-manifest / migration gates, so a fresh or legacy-store install can still report what it is.

FAILS WITHOUT THE FIX: without the ``--version`` branch, ``main(["--version"])`` reaches the
required-subparser argparse and exits non-zero instead of printing the version line.

NEGATIVE CONTROL: a bare invocation with no subcommand is still rejected (SystemExit) — the intercept
is specific to ``--version``/``-V``.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from sigil.cli import main

REPO = Path(__file__).resolve().parents[3]
PRODUCT_VERSION = (REPO / "VERSION").read_text(encoding="utf-8").strip()


def test_version_flag_prints_all_three_facts(capsys):
    main(["--version"])  # sigil's main returns None; the contract is the printed line
    out = capsys.readouterr().out.strip()
    assert out.startswith("sigil ")
    assert PRODUCT_VERSION in out
    assert "build " in out and "git " in out


def test_short_version_flag_is_equivalent(capsys):
    main(["-V"])
    assert capsys.readouterr().out.strip().startswith(f"sigil {PRODUCT_VERSION} ")


def test_negative_control_no_subcommand_is_still_rejected():
    with pytest.raises(SystemExit):
        main([])
