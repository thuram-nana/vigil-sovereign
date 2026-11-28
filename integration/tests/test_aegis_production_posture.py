"""AS-34 - OFFLINE posture test over the AEGIS PRODUCTION CloudFormation templates.

The production counterpart of integration/tests/test_aegis_infra_posture.py (AS-26 staging). It runs the
SAME analyzer (vigil_integration.aegis_infra_lint) over the production templates
(infra/aws/aegis-production/*.cfn.yaml), because the production platform ships the same resource shapes as
staging and MUST pass the same posture checks:

  * the REAL production templates are posture-clean (lint_paths over the production dir -> []); and
  * the owner/release-root generalization the analyzer grew for production is provably NOT a no-op - a
    deliberately-weakened in-memory production template fires exactly the expected violation.

The real-template half skips if PyYAML is unavailable (the constrained pytest-only job); the aegis-infra
advisory job and the required P5 integration job both install it and run the whole file. The production
roots are the REAL owner / release signing roots (staging uses test-owner / test-release); the analyzer
covers both classes with one rule, so this file pins the production class exactly as the staging file
pins the test class."""
from __future__ import annotations

from pathlib import Path

import pytest

from vigil_integration.aegis_infra_lint import check_mfa_roots, lint_paths

REPO = Path(__file__).resolve().parents[2]
TEMPLATE_DIR = REPO / "infra" / "aws" / "aegis-production"

_MFA4 = ["kms:PutKeyPolicy", "kms:ScheduleKeyDeletion", "kms:DisableKey", "kms:CreateGrant"]


def _templates() -> list[str]:
    return sorted(str(p) for p in TEMPLATE_DIR.glob("*.cfn.yaml"))


def _mfa_key(root: str, *, actions: "list[str] | str | None" = None, mfa_value: str = "false",
             op: str = "BoolIfExists") -> dict:
    return {"Type": "AWS::KMS::Key", "Properties": {
        "Tags": [{"Key": "vigil:root", "Value": root}],
        "KeyPolicy": {"Statement": [{"Effect": "Deny", "Action": _MFA4 if actions is None else actions,
                                     "Condition": {op: {"aws:MultiFactorAuthPresent": mfa_value}}}]}}}


# ==================================================================================================
# the real production templates are posture-clean
# ==================================================================================================
def test_real_production_templates_are_posture_clean() -> None:
    pytest.importorskip("yaml")
    paths = _templates()
    assert paths, "no AEGIS production templates found"
    violations = lint_paths(paths)
    assert not violations, "AS-34 posture violations:\n  - " + "\n  - ".join(str(v) for v in violations)


def test_there_are_four_production_templates() -> None:
    assert len(_templates()) == 4


# ==================================================================================================
# the production owner/release root class is checked exactly like the staging test class (not a no-op)
# ==================================================================================================
def test_production_owner_release_roots_gated_is_clean() -> None:
    good = {"Resources": {"O": _mfa_key("owner"), "R": _mfa_key("release")}}
    assert check_mfa_roots("t", good) == []


def test_production_owner_root_without_mfa_is_rejected() -> None:
    no_mfa = {"Resources": {"O": {"Type": "AWS::KMS::Key", "Properties": {
        "Tags": [{"Key": "vigil:root", "Value": "owner"}],
        "KeyPolicy": {"Statement": [{"Effect": "Allow", "Action": "kms:*"}]}}},
        "R": _mfa_key("release")}}
    assert any(x.rule == "mfa-root" for x in check_mfa_roots("t", no_mfa))


def test_production_owner_only_missing_release_is_rejected() -> None:
    """A template declaring an owner-class root MUST also declare a release-class root (spec 4.6)."""
    only_owner = {"Resources": {"O": _mfa_key("owner")}}
    assert any(x.rule == "mfa-root-missing" for x in check_mfa_roots("t", only_owner))


def test_production_inverted_gate_is_rejected() -> None:
    """A Deny on MultiFactorAuthPresent == 'true' is inverted (denies the MFA'd admin); it must fail."""
    inverted = {"Resources": {"O": _mfa_key("owner", mfa_value="true"),
                              "R": _mfa_key("release", mfa_value="true")}}
    assert any(x.rule == "mfa-root" for x in check_mfa_roots("t", inverted))
