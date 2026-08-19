"""W0-6 / #401 — `vigil up --services` egress gate FAILS CLOSED (no silent downgrade to ungated egress).

The gateway topology is the flagship egress gate: it exists to keep the Strix sandbox off Docker's default
bridge, which would otherwise carry a default route to the operator LAN / a third party / 169.254.169.254 —
the gateway/README FATAL-1. Before this fix, `_cmd_up` swallowed a gateway bring-up failure ("... preflight
skipped") and continued to `run_up`, silently bringing the UI up with the sandbox ungated — the worst
outcome. Now a gateway bring-up failure REFUSES the run (exit 2, `run_up` never reached) UNLESS the operator
EXPLICITLY passes ``--allow-ungated-egress``, which downgrades the refusal to a loud warning and continues.

Fail-before / pass-after: revert ONLY the `_cmd_up` egress-gate hunk and
``test_gateway_bringup_failure_refuses_ungated`` fails — the old code reached `run_up` after the swallow.

NEGATIVE CONTROLS (same module) prove the refusal is not a blanket abort / no-op:
  * a SUCCESSFUL gateway bring-up proceeds to `run_up` (the abort is triggered by the FAILURE, not by
    `--services` itself);
  * the explicit `--allow-ungated-egress` override proceeds despite the failure, and does so LOUDLY.

Hermetic: no docker daemon is touched — SandboxNetworking, RootServices and run_up are all stubbed.
"""
from __future__ import annotations

from pathlib import Path

import vigil_gateway.docker as gw_docker
import pytest

from vigil_integration import cli
from vigil_integration import services as smod
from vigil_integration import uiproxy as up_mod


class _FakeGatewayNet:
    """Stand-in for SandboxNetworking. `compose_up` raises iff the class-level `boom` flag is set
    (a simulated bring-up failure); otherwise it returns a healthy status dict."""

    boom = True

    def compose_up(self, *a, **kw):
        if _FakeGatewayNet.boom:
            raise RuntimeError("simulated: docker daemon unreachable")
        return {"image_built": False, "gateway": "running"}


class _FakeRootServices:
    """No-op root-services helper so the (best-effort) qdrant leg never shells out to docker."""

    def __init__(self, *a, **kw):
        pass

    def up(self, services):
        return {}


@pytest.fixture
def wired(monkeypatch):
    """Patch the gateway net, the root-services helper, and `run_up`; return a call recorder.

    `run_up` is the LAST thing `_cmd_up` does — reaching it means the UI came up. If the egress gate
    fails and the run continued ungated, this counter would be 1; fail-closed keeps it 0.
    """
    calls = {"run_up": 0}

    def _fake_run_up(*a, **kw):
        calls["run_up"] += 1
        return 0

    monkeypatch.setattr(gw_docker, "SandboxNetworking", _FakeGatewayNet)
    monkeypatch.setattr(smod, "RootServices", _FakeRootServices)
    monkeypatch.setattr(up_mod, "run_up", _fake_run_up)
    return calls


def _up_args(*extra: str):
    """Parse a realistic `vigil up --services ...` argv (defaults come from the real parser)."""
    return cli.build_parser().parse_args(["up", "--no-browser", "--services", *extra])


def test_gateway_bringup_failure_refuses_ungated(wired, capsys):
    _FakeGatewayNet.boom = True                       # the egress gate does not come up
    rc = cli._cmd_up(_up_args())
    assert rc == 2                                    # fail-closed: the run is REFUSED
    assert wired["run_up"] == 0                       # the UI is NEVER brought up ungated
    err = capsys.readouterr().err
    assert "REFUSED" in err                           # and the refusal is loud and specific
    assert "169.254.169.254" in err and "FATAL-1" in err


def test_negctl_gateway_up_proceeds(wired):
    # NEGATIVE CONTROL: a SUCCESSFUL gateway bring-up is NOT refused — proving the abort is triggered by the
    # egress-gate FAILURE, not by `--services` itself. (If the fix were a blanket refusal, this would fail.)
    _FakeGatewayNet.boom = False
    rc = cli._cmd_up(_up_args())
    assert rc == 0
    assert wired["run_up"] == 1                        # the UI comes up when the gate is healthy


def test_negctl_explicit_override_proceeds_with_warning(wired, capsys):
    # NEGATIVE CONTROL: `--allow-ungated-egress` downgrades the refusal to a loud warning and continues —
    # the escape hatch works AND is loud, so fail-closed is not a dead end and the downgrade is never silent.
    _FakeGatewayNet.boom = True
    rc = cli._cmd_up(_up_args("--allow-ungated-egress"))
    assert rc == 0
    assert wired["run_up"] == 1                        # explicit override → proceeds despite the failure
    err = capsys.readouterr().err
    assert "WARNING" in err and "UNGATED" in err and "FATAL-1" in err   # loud, not silent


def test_doctruth_override_flag_is_real_and_documented():
    # DOC-TRUTH: the flag the gateway/README tells operators to use must be a REAL registered option (derive
    # the mirrored claim from the code so the doc can't drift), and the README must describe the fail-closed
    # behaviour. `parse_args` succeeding proves the flag exists; a bogus flag would raise SystemExit.
    args = cli.build_parser().parse_args(["up", "--services", "--allow-ungated-egress"])
    assert args.allow_ungated_egress is True

    readme = (Path(__file__).resolve().parents[2] / "gateway" / "README.md").read_text(encoding="utf-8")
    assert "--allow-ungated-egress" in readme                 # the doc's flag name == the real flag
    assert "fails closed" in readme and "REFUSED" in readme    # the doc states the fail-closed behaviour
