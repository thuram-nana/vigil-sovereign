"""`vigil-gateway --version` reports product version + build id + git sha (W4-2, #442).

Runs in the required "gateway egress gate (P6)" job (``PYTHONPATH=gateway python -m pytest
gateway/tests``). ``--version`` short-circuits before argparse's required subparser, so the gateway can
report what it is without a subcommand.

FAILS WITHOUT THE FIX: without the ``--version`` branch, the required-subparser argparse rejects
``["--version"]`` (SystemExit 2) instead of printing the version line.

NEGATIVE CONTROL: a bare invocation with no subcommand must still be rejected (SystemExit) — the
intercept does not turn every empty/odd invocation into a version print.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from vigil_gateway.cli import main

REPO = Path(__file__).resolve().parents[2]
PRODUCT_VERSION = (REPO / "VERSION").read_text(encoding="utf-8").strip()


def test_version_flag_prints_all_three_facts_and_returns_zero(capsys):
    rc = main(["--version"])
    assert rc == 0
    out = capsys.readouterr().out.strip()
    assert out.startswith("vigil-gateway ")
    assert PRODUCT_VERSION in out
    assert "build " in out and "git " in out


def test_short_version_flag_is_equivalent(capsys):
    assert main(["-V"]) == 0
    assert capsys.readouterr().out.strip().startswith(f"vigil-gateway {PRODUCT_VERSION} ")


def test_negative_control_no_subcommand_is_still_rejected():
    with pytest.raises(SystemExit):
        main([])
