"""`python3 -m framework.v2 --version` reports product version + build id + git sha (W4-2, #442).

Runs in the required "CRUCIBLE core on vigil_core" job (``pytest framework/v2`` from engine/crucible,
which installs ``vigil_core`` editable). ``--version`` short-circuits at the very top of ``main`` —
before the umask latch, dispatch and argparse — so any install answers what it is.

FAILS WITHOUT THE FIX: without the ``--version`` branch, ``--version`` is an unknown option that lands
in ``parse_known_args`` rest with no subcommand, so ``main`` prints help and returns 2 instead of the
version line.

NEGATIVE CONTROL: an invalid subcommand is still rejected (SystemExit) — the intercept is specific to
``--version``/``-V`` and does not swallow arbitrary input.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from framework.v2.__main__ import main

REPO = Path(__file__).resolve().parents[5]
PRODUCT_VERSION = (REPO / "VERSION").read_text(encoding="utf-8").strip()


def test_version_flag_prints_all_three_facts_and_returns_zero(capsys):
    rc = main(["--version"])
    assert rc == 0
    out = capsys.readouterr().out.strip()
    assert out.startswith("framework.v2 ")
    assert PRODUCT_VERSION in out
    assert "build " in out and "git " in out


def test_short_version_flag_is_equivalent(capsys):
    assert main(["-V"]) == 0
    assert capsys.readouterr().out.strip().startswith(f"framework.v2 {PRODUCT_VERSION} ")


def test_negative_control_invalid_subcommand_is_rejected():
    with pytest.raises(SystemExit):
        main(["not-a-real-subcommand-zzz"])
