"""Tests for the entitlement provisioning CLI verbs (W17-6, #540).

Before this slice the entitlement CLI exposed only status/capabilities/verify;
moving a deployment from UNGOVERNED to governed required hand-writing Python
against `entitlement.provision`. These tests drive the new `provision`,
`new-authorizer`, `build-trust-root`, and `sign-entitlement` verbs end-to-end
and prove the result round-trips through `verify`.

The autouse `_isolated_entitlement_dir` fixture (conftest.py) points
CRUCIBLE_ENTITLEMENT_DIR at a per-test tmp dir and resets the cached policy, so
these tests never touch a real deployment's material.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from ...common import paths
from .. import cli, policy


def _subcommands(parser: argparse.ArgumentParser) -> set[str]:
    """The subcommand names the parser registers, derived from the parser
    itself (not hand-listed) so the doc drift-guard cannot go stale."""
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return set(action.choices.keys())
    raise AssertionError("entitlement CLI parser has no subparsers")


def _provisioning_verbs() -> set[str]:
    """Every registered verb that is NOT a read-only inspection verb — i.e.
    the provisioning surface, derived from the live parser."""
    return _subcommands(cli.build_parser()) - cli._READONLY_VERBS


# ---------------------------------------------------------------------------
# End-to-end round-trip through verify
# ---------------------------------------------------------------------------


def test_provision_one_shot_round_trips_through_verify(capsys: pytest.CaptureFixture[str]) -> None:
    # NEGATIVE CONTROL — before provisioning, the deployment is UNGOVERNED and
    # verify reports enforcement INACTIVE (so any ACTIVE below is caused by the
    # provisioning verb, not pre-existing state).
    assert cli.main(["verify"]) == 0
    assert "INACTIVE" in capsys.readouterr().out

    rc = cli.main(
        [
            "provision",
            "--institution-id", "inst-1",
            "--institution-name", "Authorized Red Team",
            "--tier", "offensive",
            "--valid-days", "30",
        ]
    )
    assert rc == 0

    # Material now exists on disk...
    assert paths.trust_root_path().is_file()
    assert paths.entitlement_path().is_file()

    # ...and round-trips: verify now reports enforcement ACTIVE and exits 0.
    policy.reset_policy()
    assert cli.main(["verify"]) == 0
    out = capsys.readouterr().out
    assert "ACTIVE" in out
    assert "offensive" in out


def test_granular_distributed_ceremony_round_trips(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    card = tmp_path / "panel-a.card.json"
    key = tmp_path / "panel-a.key"

    assert cli.main(
        [
            "new-authorizer",
            "--key-id", "panel-a",
            "--name", "Governance Panel Seat A",
            "--card-out", str(card),
            "--key-out", str(key),
        ]
    ) == 0
    assert card.is_file() and key.is_file()
    # The public card carries the pubkey, never the private key.
    card_obj = json.loads(card.read_text())
    assert card_obj["key_id"] == "panel-a"
    assert "public_key_b64" in card_obj
    assert "private" not in card.read_text().lower()

    assert cli.main(
        ["build-trust-root", "--card", str(card), "--threshold", "1"]
    ) == 0
    assert paths.trust_root_path().is_file()

    assert cli.main(
        [
            "sign-entitlement",
            "--institution-id", "inst-2",
            "--institution-name", "RT Beta",
            "--tier", "standard",
            "--valid-days", "7",
            "--signer", f"panel-a={key}",
        ]
    ) == 0
    assert paths.entitlement_path().is_file()

    policy.reset_policy()
    assert cli.main(["verify"]) == 0
    assert "ACTIVE" in capsys.readouterr().out


def test_capability_allowlist_is_least_privilege(capsys: pytest.CaptureFixture[str]) -> None:
    """A grant restricted with --capability confers ONLY the listed capability
    within its tier — proving the CLI plumbs granted_capabilities through."""
    rc = cli.main(
        [
            "provision",
            "--institution-id", "inst-3",
            "--institution-name", "Restricted",
            "--tier", "standard",
            "--capability", "aegis_respond",
            "--valid-days", "5",
        ]
    )
    assert rc == 0
    capsys.readouterr()

    policy.reset_policy()
    assert cli.main(["capabilities"]) == 0
    rows = {r["capability"]: r["available"] for r in json.loads(capsys.readouterr().out)}
    assert rows["aegis_respond"] is True          # granted
    assert rows["active_recon"] is False          # same tier, but not in the allowlist
    assert rows["exploit_execution"] is False     # above the tier


# ---------------------------------------------------------------------------
# Safety: governance material is never silently clobbered
# ---------------------------------------------------------------------------


def test_provision_refuses_to_overwrite_without_force(capsys: pytest.CaptureFixture[str]) -> None:
    base = [
        "provision",
        "--institution-id", "inst-4",
        "--institution-name", "Owner",
        "--tier", "standard",
        "--valid-days", "5",
    ]
    assert cli.main(base) == 0
    capsys.readouterr()
    # Second provision without --force must refuse (exit 2), not clobber.
    assert cli.main(base) == 2
    assert "refusing to overwrite" in capsys.readouterr().err
    # With --force it succeeds.
    assert cli.main(base + ["--force"]) == 0


def test_bad_signer_spec_is_rejected(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(
        [
            "sign-entitlement",
            "--institution-id", "x",
            "--institution-name", "x",
            "--tier", "standard",
            "--signer", "no-equals-sign",
        ]
    ) == 2
    assert "--signer must be key_id=PATH" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Doc-truth: the runbook exists and stays in lock-step with the CLI surface
# ---------------------------------------------------------------------------


def _runbook() -> Path:
    # Resolve the runbook in the SAME tree as the code under test — relative to
    # the cli module — not via paths.v2_root(), which follows CRUCIBLE_ROOT and
    # can point at an unrelated checkout. cli.__file__ is
    # .../framework/v2/entitlement/cli.py, so parents[1] is .../framework/v2.
    return Path(cli.__file__).resolve().parents[1] / "docs" / "ENTITLEMENT-PROVISIONING.md"


def test_runbook_exists() -> None:
    assert _runbook().is_file(), "entitlement provisioning runbook is missing"


def test_runbook_documents_every_provisioning_verb() -> None:
    """Derive the provisioning verbs from the live parser and assert each is
    documented in the runbook — a verb cannot ship without a runbook entry,
    and the runbook cannot claim a verb that does not exist."""
    text = _runbook().read_text(encoding="utf-8")
    verbs = _provisioning_verbs()
    assert verbs == {"provision", "new-authorizer", "build-trust-root", "sign-entitlement"}
    for verb in verbs:
        assert verb in text, f"runbook does not document provisioning verb {verb!r}"


def test_runbook_documents_the_aegis_enforcement_coupling() -> None:
    """The runbook must warn that provisioning turns AEGIS enforcement from
    'permitted-with-warning' into an entitlement-gated capability (the NOTE
    from the plan), so a third party is not surprised."""
    text = _runbook().read_text(encoding="utf-8")
    assert "AEGIS_RESPOND" in text
    assert "UNGOVERNED" in text
    # And the CLI help/module carries the same coupling note.
    assert "AEGIS_RESPOND" in cli._AEGIS_NOTE
