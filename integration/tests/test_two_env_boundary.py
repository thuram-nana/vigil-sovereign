"""The two-environment boundary is STRUCTURAL, proven two ways.

The earlier version of this test scrubbed only PYTHONPATH and ran under the ambient
interpreter — which is NOT a proof: in a correctly-built env-offense, ``engine/crucible`` and
``vendor/strix`` are editable-installed, so their ``.pth`` files import ``framework``/``strix``
at startup regardless of PYTHONPATH, and the "sovereign" assertion would flip red (red-pen
P5 BLOCK-1). The boundary is a property of *which packages are installed*, so it is proven here
at two levels:

1. ``test_no_sovereign_member_declares_offense_dependency`` — always runs, no external state:
   parse the sovereign members' pyproject and assert none declares a dependency on crucible /
   framework / strix. This is the dependency-graph guarantee.
2. ``test_real_sovereign_venv_cannot_reach_offense`` — builds an ACTUAL sovereign venv
   (``vigil_core`` + ``integration`` installed, crucible/strix deliberately NOT), whose
   site-packages therefore genuinely lacks the offense members, and probes it: ``framework``
   and ``strix`` are unimportable, ``assert_no_offense()`` passes, the inert seam imports.
   Skipped only if a venv/pip build is impossible (offline).

The negative control proves the guard is not vacuous: load an offense module and it fires.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tomllib

import pytest

_REPO = pathlib.Path(__file__).resolve().parents[2]
_SOVEREIGN = _REPO / "apps" / "sigil"
_INTEGRATION = _REPO / "integration"
_VIGIL_CORE = _REPO / "packages" / "core" / "vigil_core"
_CRUCIBLE = _REPO / "engine" / "crucible"

_FORBIDDEN = ("crucible", "framework", "strix")

_PROBE = r"""
import json
res = {}
for mod in ("framework", "framework.v2", "framework.v2.common.ethics", "strix", "strix.agents"):
    try:
        __import__(mod); res[mod] = "IMPORTED"
    except ImportError:
        res[mod] = "blocked"
from sigil.reuse import assert_no_offense
assert_no_offense()                       # must not raise in a genuinely sovereign env
import vigil_integration.inert_finding     # the sovereign-safe seam still imports
print(json.dumps({"res": res, "guard": "passed"}))
"""


def _dep_names(pyproject: pathlib.Path) -> list[str]:
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    project = data.get("project", {})
    deps = list(project.get("dependencies", []) or [])
    for extra in (project.get("optional-dependencies", {}) or {}).values():
        deps.extend(extra or [])
    return deps


def test_no_sovereign_member_declares_offense_dependency():
    # Always runs — no venv, no ambient interpreter state. The declared dependency graph of
    # every sovereign member must be free of crucible/framework/strix.
    members = {
        "vigil_core": _VIGIL_CORE / "pyproject.toml",
        "apps/sigil": _SOVEREIGN / "pyproject.toml",
        "integration": _INTEGRATION / "pyproject.toml",
    }
    for name, pp in members.items():
        assert pp.is_file(), f"{name} pyproject missing at {pp}"
        for dep in _dep_names(pp):
            low = dep.strip().lower()
            assert not any(low.startswith(f) or f"/{f}" in low for f in _FORBIDDEN), (
                f"sovereign member {name} declares an offense dependency: {dep!r}"
            )


def _build_sovereign_venv(tmp_path: pathlib.Path) -> pathlib.Path | None:
    venv = tmp_path / "sov-venv"
    if subprocess.run([sys.executable, "-m", "venv", str(venv)],
                      capture_output=True, text=True).returncode != 0:
        return None
    py = venv / "bin" / "python"
    if not py.exists():
        py = venv / "Scripts" / "python.exe"
    # Install ONLY the sovereign-safe members. crucible and strix are deliberately absent, so
    # this venv's site-packages cannot import framework/strix by any .pth or install path.
    res = subprocess.run(
        [str(py), "-m", "pip", "install", "-q", "-e", str(_VIGIL_CORE), "-e", str(_INTEGRATION)],
        capture_output=True, text=True, timeout=900,
    )
    return py if res.returncode == 0 else None


def test_real_sovereign_venv_cannot_reach_offense(tmp_path):
    py = _build_sovereign_venv(tmp_path)
    if py is None:
        pytest.skip("could not build a sovereign venv (offline / no pip)")
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    # apps/sigil on PYTHONPATH so sigil.reuse loads (it needs only vigil_core, which IS installed);
    # framework/strix are neither installed in this venv nor on the path.
    env["PYTHONPATH"] = str(_SOVEREIGN)
    proc = subprocess.run([str(py), "-c", _PROBE], capture_output=True, text=True, env=env, timeout=60)
    assert proc.returncode == 0, f"stderr:\n{proc.stderr}"
    out = json.loads(proc.stdout.strip().splitlines()[-1])
    assert out["guard"] == "passed"
    for mod, status in out["res"].items():
        assert status == "blocked", f"{mod} importable in a REAL sovereign venv: {status}"


def test_guard_is_not_vacuous_negative_control():
    # Put engine/crucible on the path, actually LOAD an offense module, and the guard must fire.
    if not _CRUCIBLE.is_dir():
        pytest.skip("engine/crucible not present")
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["PYTHONPATH"] = os.pathsep.join(str(p) for p in (_SOVEREIGN, _INTEGRATION, _CRUCIBLE))
    script = r"""
import framework.v2.common.ethics          # a real CRUCIBLE (offense-engine) module, now loaded
from sigil.reuse import assert_no_offense
try:
    assert_no_offense()
    print("GUARD_DID_NOT_FIRE")
except RuntimeError as e:
    print("GUARD_FIRED" if "sovereignty" in str(e) else f"WRONG_ERROR:{e}")
"""
    proc = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, env=env, timeout=60)
    if proc.returncode != 0:
        pytest.skip(f"crucible deps unavailable in this interpreter: {proc.stderr.strip()[-200:]}")
    assert "GUARD_FIRED" in proc.stdout, proc.stdout + proc.stderr
