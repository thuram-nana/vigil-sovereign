"""The two-environment boundary is STRUCTURAL, not disciplinary.

In a sovereign-only interpreter (vigil_core + apps/sigil + integration on the path, but NOT
engine/crucible and NOT vendor/strix), the offense namespaces are not importable at all, so
``assert_no_offense()`` holds by construction — and the inert seam still imports. The negative
control proves the guard is not vacuous: load an offense module and it fires.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys

import pytest

_REPO = pathlib.Path(__file__).resolve().parents[2]
_SOVEREIGN = _REPO / "apps" / "sigil"
_INTEGRATION = _REPO / "integration"
_CRUCIBLE = _REPO / "engine" / "crucible"


def _run(script: str, pythonpath: list[pathlib.Path]) -> subprocess.CompletedProcess:
    env = {
        k: v for k, v in os.environ.items()
        if k not in ("PYTHONPATH",)  # do not inherit a path that might leak the offense members
    }
    env["PYTHONPATH"] = os.pathsep.join(str(p) for p in pythonpath)
    return subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, env=env, timeout=60,
    )


def _sovereign_importable() -> bool:
    # vigil_core must be importable for sigil.reuse to load at all.
    proc = _run("import vigil_core, sigil.reuse; print('ok')", [_SOVEREIGN, _INTEGRATION])
    return proc.returncode == 0 and "ok" in proc.stdout


pytestmark = pytest.mark.skipif(
    not _sovereign_importable(),
    reason="vigil_core + apps/sigil not importable in this interpreter",
)


def test_sovereign_env_cannot_import_offense_and_guard_passes():
    script = r"""
import json
res = {}
for mod in ("framework", "framework.v2", "framework.v2.common.ethics", "strix", "strix.agents"):
    try:
        __import__(mod); res[mod] = "IMPORTED"
    except ImportError:
        res[mod] = "blocked"
from sigil.reuse import assert_no_offense
assert_no_offense()                       # must not raise in a sovereign-only interpreter
import vigil_integration.inert_finding     # the sovereign-safe seam still imports
print(json.dumps({"res": res, "guard": "passed"}))
"""
    proc = _run(script, [_SOVEREIGN, _INTEGRATION])
    assert proc.returncode == 0, f"stderr:\n{proc.stderr}"
    out = json.loads(proc.stdout.strip().splitlines()[-1])
    assert out["guard"] == "passed"
    for mod, status in out["res"].items():
        assert status == "blocked", f"{mod} was importable in the sovereign env: {status}"


def test_guard_is_not_vacuous_negative_control():
    # Put engine/crucible on the path, actually LOAD an offense module, and the guard must fire.
    if not _CRUCIBLE.is_dir():
        pytest.skip("engine/crucible not present")
    script = r"""
import framework.v2.common.ethics          # a real CRUCIBLE (offense-engine) module, now loaded
from sigil.reuse import assert_no_offense
try:
    assert_no_offense()
    print("GUARD_DID_NOT_FIRE")
except RuntimeError as e:
    print("GUARD_FIRED" if "sovereignty" in str(e) else f"WRONG_ERROR:{e}")
"""
    proc = _run(script, [_SOVEREIGN, _INTEGRATION, _CRUCIBLE])
    if proc.returncode != 0:
        pytest.skip(f"crucible deps unavailable in this interpreter: {proc.stderr.strip()[-200:]}")
    assert "GUARD_FIRED" in proc.stdout, proc.stdout + proc.stderr
