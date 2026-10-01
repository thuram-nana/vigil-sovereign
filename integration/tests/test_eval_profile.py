"""
INV3 — the per-org investor-eval DEPLOYMENT CONFIG turns the product path on, from one honest source.

``vigil_integration.sovereign_deploy.eval_profile`` is the single source of truth a WS3 control plane reads to
make a per-org deployment "production-on": family re-drive FACT-mint ELIGIBLE (``VIGIL_FAMILY_REDRIVE`` +
``--brain hexstrike``) and the AEGIS Gateway in enforce mode, plus the AEGIS_RESPOND grant it must provision
out of band. The config is checked against the SAME predicate its consumer reads, so it can never falsely
report "on", and it is FATAL-2 import-clean (no engine import, no owner key).
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys

from vigil_integration.live.oracle_families import FAMILY_REDRIVE_FLAG, redrive_flag_enabled
from vigil_integration.sovereign_deploy import eval_profile as ep


def test_production_env_enables_fact_mint_via_the_same_flag_the_router_reads():
    env = ep.production_env()
    # the config SETS the flag the routing layer READS — one name, no drift.
    assert env[FAMILY_REDRIVE_FLAG] == "1"
    assert redrive_flag_enabled(env) is True
    assert ep.fact_mint_enabled(env) is True


def test_production_env_requests_aegis_enforce_and_governed_entitlement():
    env = ep.production_env()
    assert env[ep.AEGIS_MODE_ENV] == "enforce"
    assert ep.aegis_enforce_requested(env) is True
    # governed enforcement ACTIVE ⇒ AEGIS_RESPOND is a real fail-closed gate, not a permissive default.
    assert env[ep.ENTITLEMENT_ENFORCED_ENV] == "1"


def test_engage_flags_drive_the_propose_only_brain():
    assert ep.engage_fact_mint_flags() == ["--brain", "hexstrike"]
    assert ep.EVAL_BRAIN == "hexstrike"


def test_aegis_respond_is_a_required_capability():
    # the config NAMES the grant the deployment must provision (matches Capability.AEGIS_RESPOND.value).
    assert "aegis_respond" in ep.REQUIRED_CAPABILITIES


def test_readiness_is_green_on_production_env():
    r = ep.assess_readiness(ep.production_env())
    assert r.ready is True and r.missing == ()
    assert r.fact_mint_eligible and r.aegis_enforce_requested and r.governed_enforcement_active
    assert "aegis_respond" in r.required_capabilities


def test_readiness_negative_control_bare_env_is_not_ready():
    """The safe negative control: with NONE of the switches set (the default-off product path), the config
    honestly reports NOT ready and names every missing switch — it never rounds an un-configured deployment
    up to 'on'."""
    r = ep.assess_readiness({})
    assert r.ready is False
    assert r.fact_mint_eligible is False
    assert ep.fact_mint_enabled({}) is False
    blob = " ".join(r.missing)
    assert FAMILY_REDRIVE_FLAG in blob and ep.AEGIS_MODE_ENV in blob and ep.ENTITLEMENT_ENFORCED_ENV in blob


def test_falsy_flag_values_do_not_count_as_enabled():
    for val in ("", "0", "false", "no", "off"):
        assert ep.fact_mint_enabled({FAMILY_REDRIVE_FLAG: val}) is False
        assert ep.aegis_enforce_requested({ep.AEGIS_MODE_ENV: "observe"}) is False


def test_eval_profile_is_fatal2_import_clean():
    """FATAL-2: the deployment config loads in a SOVEREIGN-only interpreter (vigil_core + integration on the
    path, engine/crucible deliberately absent) and pulls NO ``framework`` / ``strix`` at module scope — so it
    holds no owner key and the offense engine never leaks into the deployment facade."""
    repo = pathlib.Path(__file__).resolve().parents[2]
    sov_path = os.pathsep.join([
        str(repo / "packages" / "core" / "vigil_core"),
        str(repo / "integration"),
    ])
    probe = (
        "import sys\n"
        "import vigil_integration.sovereign_deploy.eval_profile as ep\n"
        "assert ep.production_env()['VIGIL_FAMILY_REDRIVE'] == '1'\n"
        "assert 'framework' not in sys.modules, 'eval_profile pulled the offense engine'\n"
        "assert 'strix' not in sys.modules, 'eval_profile pulled strix'\n"
        "print('CLEAN')\n"
    )
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["PYTHONPATH"] = sov_path
    proc = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True,
                          env=env, cwd=str(repo), timeout=60)
    assert proc.returncode == 0, f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    assert "CLEAN" in proc.stdout
