"""CQ-1 — `vigil sandbox` honours `--`: everything after it is the COMMAND, never one of the sandbox's options.

The console's run-tests action builds `vigil sandbox --workspace W --base-dir B [--approve] -- <command>`; this
pins, against the REAL argparse parser, that a command text such as `--approve` or `--workspace=/` stays
positional and cannot set the approval leg or move the writable workspace."""
from __future__ import annotations

from vigil_integration import cli


def _parse(argv):
    return cli.build_parser().parse_args(argv)


def test_tokens_after_double_dash_are_the_command_not_options():
    a = _parse(["sandbox", "--workspace", "/w", "--base-dir", "/b", "--", "--approve"])
    assert a.command == ["--approve"] and a.approve is False and a.workspace == "/w"
    b = _parse(["sandbox", "--workspace", "/w", "--base-dir", "/b", "--", "--workspace=/"])
    assert b.command == ["--workspace=/"] and b.workspace == "/w"


def test_the_operator_leg_still_approves():
    a = _parse(["sandbox", "--workspace", "/w", "--base-dir", "/b", "--approve", "--", "pytest -q"])
    assert a.command == ["pytest -q"] and a.approve is True
