"""
AS-28 — the AEGIS SaaS defense-image CLOSURE proof (the security core of the slice).

Two independent proofs that the gateway's runtime does NOT carry the offense engine:

  1. STATIC (``aegis.closure``): walk the module-level import graph from the serving entrypoints, soundly
     accounting for ancestor-package ``__init__`` execution AND PEP 562 lazy re-exports, assert nothing on
     the deny list is import-reachable and every first-party module resolved (fail-closed), and — a
     conservative overlay — assert no reachable AEGIS serving module carries a lazy/function-local offense
     import.
  2. RUNTIME ("also with ``anthropic`` blocked", the most robust): in a fresh subprocess install an import
     hook that makes ``anthropic`` and the other LLM/agent SDKs UNIMPORTABLE, import the entrypoints, then
     assert NO ``closure.is_denied`` module — a first-party offense module OR a third-party LLM/agent SDK —
     is present in ``sys.modules``. This directly catches an eager ``__init__`` offense pull or any
     dynamic/transitive path the static pass does not model.

Plus FLIP tests (the sound analyzer catches a planted lazy / PEP 562 offense import), negative controls
(the guards are not vacuous), and a RATCHET over the known, DISCLOSED residual.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys

import pytest

from framework.v2.aegis import closure as C

_ENGINE_ROOT = pathlib.Path(__file__).resolve().parents[4]  # .../engine/crucible
_MANIFEST = pathlib.Path(__file__).resolve().parents[1] / "saas-closure.json"


# --------------------------------------------------------------------------------------------------
# 1. STATIC closure is clean.
# --------------------------------------------------------------------------------------------------

def test_saas_gateway_closure_is_clean():
    report = C.check_saas_closure()
    assert report.denied == (), f"offense/denied modules reachable from the defense gateway: {report.denied}"
    assert report.unresolved == (), f"unresolvable first-party modules (fail-closed): {report.unresolved}"
    assert report.ok is True


def test_closure_excludes_every_llm_and_agent_sdk():
    # The sharpest, most robust contract: a DEFENSE data plane never loads an LLM/agent SDK or strix.
    report = C.check_saas_closure()
    tops = {m.split(".", 1)[0] for m in report.result.reachable}
    for pkg in C.DENIED_THIRD_PARTY:
        assert pkg not in tops, f"denied third-party package {pkg!r} is import-reachable from the gateway"


def test_closure_excludes_active_offense_verify_modules():
    # The concrete win of AS-28's lazy ``verify/__init__``: the OOB servers, live recon, credential
    # capture and token forgers are no longer dragged into the defense runtime.
    report = C.check_saas_closure()
    for m in report.result.reachable:
        reason = C.is_denied(m)
        assert reason is None, f"{m} reachable ({reason})"


# --------------------------------------------------------------------------------------------------
# 2. RUNTIME closure — the entrypoints import with anthropic + the agent SDKs BLOCKED.
# --------------------------------------------------------------------------------------------------

_BLOCKED = ("anthropic", "openai", "agents", "litellm", "langchain", "langgraph", "autogen", "strix")

_RUNTIME_PROBE = r"""
import sys, json

_BLOCKED = {blocked!r}

class _Blocker:
    def find_spec(self, name, path=None, target=None):
        top = name.split('.')[0]
        if top in _BLOCKED:
            raise ModuleNotFoundError(f"AS-28 closure test: {{name}} is blocked in the defense runtime")
        return None

sys.meta_path.insert(0, _Blocker())

# prove the blocker is live (the test would be vacuous otherwise)
try:
    import anthropic  # noqa: F401
    print(json.dumps({{"status": "blocker_dead"}})); sys.exit(0)
except ModuleNotFoundError:
    pass

# the SAME deny oracle the build-time gate uses, now applied to the live sys.modules. It is pure-stdlib
# (ast/pathlib/dataclasses) and offense-free, so importing it loads nothing on the deny list.
from framework.v2.aegis import closure as _C

# non-vacuity: the detector must actually fire on a known first-party offense module AND a blocked SDK,
# or the sys.modules assertion below would be meaningless.
if _C.is_denied("framework.v2.verify.oob") is None or _C.is_denied("anthropic") is None:
    print(json.dumps({{"status": "detector_dead"}})); sys.exit(0)

try:
    import framework.v2.aegis.cli      # the module `python3 -m framework.v2 aegis gateway` dispatches to
    import framework.v2.aegis.gateway  # the serving core
except ModuleNotFoundError as e:
    name = (e.name or "").split('.')[0]
    kind = "blocked_name_needed" if name in _BLOCKED else "other_import_error"
    print(json.dumps({{"status": kind, "module": e.name}})); sys.exit(0)

# THE assertion: no DENIED module — a first-party offense module OR a third-party LLM/agent SDK — is
# import-loaded into the serving process. Catches the lazy ``verify.oob`` AND any eager ``__init__``
# offense pull the static walk would miss.
offending = sorted(m for m in sys.modules if _C.is_denied(m) is not None)
# informational only: the DISCLOSED, ratcheted residual that IS loaded (agent-executor layer), NOT denied.
residual_loaded = sorted(m for m in sys.modules if m in _C.KNOWN_RESIDUAL)
print(json.dumps({{"status": "ok", "offending": offending, "residual_loaded": residual_loaded}}))
"""

# NEGATIVE CONTROL: deliberately import a deny-listed first-party offense module, then run the SAME
# sys.modules scan — it MUST flag it, proving the runtime assertion is not vacuous (runs in a subprocess,
# so the real test process never loads the offense module).
_RUNTIME_PROBE_NEG = r"""
import sys, json
from framework.v2.aegis import closure as _C
import framework.v2.verify.oob  # noqa: F401  (deny-listed offense module, loaded on purpose)
offending = sorted(m for m in sys.modules if _C.is_denied(m) is not None)
print(json.dumps({"offending": offending}))
"""


def _run_script(script: str) -> dict:
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["PYTHONPATH"] = str(_ENGINE_ROOT)
    proc = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True, text=True, env=env, cwd=str(_ENGINE_ROOT), timeout=120,
    )
    assert proc.returncode == 0, f"probe crashed:\nSTDOUT:{proc.stdout}\nSTDERR:{proc.stderr}"
    return json.loads(proc.stdout.strip().splitlines()[-1])


def _run_probe() -> dict:
    return _run_script(_RUNTIME_PROBE.format(blocked=list(_BLOCKED)))


def test_gateway_imports_with_anthropic_and_sdks_blocked():
    out = _run_probe()
    if out["status"] == "other_import_error":
        pytest.skip(f"unrelated dependency missing in this env: {out.get('module')!r}")
    assert out["status"] != "blocker_dead", "import blocker did not take effect"
    assert out["status"] != "detector_dead", "the is_denied detector is vacuous in the probe"
    assert out["status"] == "ok", (
        f"the defense gateway requires a blocked LLM/agent SDK at import: {out.get('module')!r}"
    )
    assert out["offending"] == [], (
        f"DENIED offense/SDK modules were import-loaded into the gateway process: {out['offending']}"
    )


def test_runtime_probe_detects_a_denied_module_negative_control():
    # Prove the runtime sys.modules scan is NOT vacuous: when a denied module IS loaded, it is flagged.
    out = _run_script(_RUNTIME_PROBE_NEG)
    assert "framework.v2.verify.oob" in out["offending"], (
        f"runtime is_denied scan failed to flag a deliberately-loaded denied module: {out['offending']}"
    )


# --------------------------------------------------------------------------------------------------
# 3. Negative controls — the guard is not vacuous, and it fails CLOSED.
# --------------------------------------------------------------------------------------------------

def test_closure_fires_on_an_offense_entrypoint():
    # Point the analyzer AT an active-offense module: it must refuse.
    report = C.check_saas_closure(["framework.v2.verify.oob"])
    assert report.ok is False
    assert any(m == "framework.v2.verify.oob" for m, _ in report.denied)


def test_closure_fails_closed_on_unresolvable_module():
    # An unknown first-party module (no file on disk) is a violation, never a silent pass.
    report = C.check_saas_closure(["framework.v2.aegis._nonexistent_entrypoint_"])
    assert report.ok is False
    assert "framework.v2.aegis._nonexistent_entrypoint_" in report.unresolved


def test_analyzer_skips_type_checking_blocks():
    # A module whose ONLY offense import is under ``if TYPE_CHECKING:`` must not be flagged (that import
    # never runs at import time). verify/__init__ is exactly such a module after the AS-28 change.
    result = C.import_closure(["framework.v2.verify"])
    off = sorted(m for m in result.reachable if C.is_denied(m))
    assert off == [], f"TYPE_CHECKING-only offense imports leaked into the closure: {off}"


# --------------------------------------------------------------------------------------------------
# 3b. SOUNDNESS FLIP TESTS — the sound analyzer catches a planted lazy / PEP 562 offense import.
#     (Fixtures under tests/closure_fixtures/ are PARSED by the analyzer, never imported — so they
#     never actually load offense; see that package's docstring.)
# --------------------------------------------------------------------------------------------------

_FIX = "framework.v2.aegis.tests.closure_fixtures"


def test_static_follows_pep562_lazy_reexport_to_denied_submodule():
    # ``from framework.v2.verify import OOBReceiver`` AT MODULE SCOPE is a real import-time edge: PEP 562
    # ``__getattr__`` imports verify.oob on first access. The sound walk must follow the shim and deny it.
    report = C.check_saas_closure([f"{_FIX}.pep562_lazy_offense"])
    assert report.ok is False
    assert any(m == "framework.v2.verify.oob" for m, _ in report.denied), (
        f"analyzer did not follow the PEP 562 lazy re-export to verify.oob: {report.denied}"
    )


def test_static_catches_lazy_offense_in_a_serving_module():
    # A function-local ``from ..verify.oob import OOBReceiver`` in an AEGIS serving module (the EXACT
    # pre-fix gateway pattern) is not an import-time edge — the conservative overlay, not the closure,
    # must catch it.
    report = C.check_saas_closure([f"{_FIX}.lazy_oob_serving"])
    assert report.ok is False
    assert any(t == "framework.v2.verify.oob" for _, t, _ in report.serving_lazy_denied), (
        f"serving-module lazy-offense overlay missed the smuggled import: {report.serving_lazy_denied}"
    )


def test_real_gateway_has_no_lazy_offense_import():
    # The fix: the gateway no longer imports verify.oob even lazily — it uses the offense-free
    # common.oob_receiver — so the serving-module lazy-offense overlay is clean on the real entrypoints.
    report = C.check_saas_closure()
    assert report.serving_lazy_denied == (), (
        f"an AEGIS serving module carries a lazy offense import: {report.serving_lazy_denied}"
    )


def test_pep562_shim_parser_reads_verify_and_fails_closed_on_opaque():
    import ast as _ast

    # the REAL verify shim parses to a concrete, non-opaque map that resolves OOBReceiver -> oob submodule.
    vinit = _ENGINE_ROOT / "framework" / "v2" / "verify" / "__init__.py"
    shim = C._parse_pep562_shim(_ast.parse(vinit.read_text(encoding="utf-8")))
    assert shim is not None and shim.opaque is False
    assert shim.lazy_symbols.get("OOBReceiver") == "oob"
    assert "oob" in shim.submodules

    # a ``__getattr__`` shim whose lazy map is NOT static string literals is OPAQUE -> fail closed.
    opaque = C._parse_pep562_shim(_ast.parse("def __getattr__(n):\n    return None\n_LAZY_SYMBOLS = dict(x=y)\n"))
    assert opaque is not None and opaque.opaque is True

    # a module with no ``__getattr__`` is not a shim at all.
    assert C._parse_pep562_shim(_ast.parse("X = 1\n")) is None


# --------------------------------------------------------------------------------------------------
# 4. RATCHET over the known, deferred residual (honest; must SHRINK, never GROW).
# --------------------------------------------------------------------------------------------------

def test_offense_executor_residual_does_not_grow():
    # The offense agent-EXECUTOR layer is still reachable via the eager intel->planner->agents package
    # __init__ chain (out of AS-28's VERIFY-token lane; deferred to the companion decoupling). Freeze it:
    # the reachable residual must stay WITHIN the recorded set, so no NEW offense coupling slips in.
    report = C.check_saas_closure()
    reachable_agents = {m for m in report.result.reachable if m == "framework.v2.agents" or m.startswith("framework.v2.agents.")}
    grew = sorted(reachable_agents - C.KNOWN_RESIDUAL)
    assert grew == [], f"NEW offense-agent coupling reached the defense runtime (ratchet broken): {grew}"


# --------------------------------------------------------------------------------------------------
# 5. Manifest consistency — the committed JSON cannot drift from the enforced Python constants.
# --------------------------------------------------------------------------------------------------

def test_closure_manifest_matches_module():
    data = json.loads(_MANIFEST.read_text(encoding="utf-8"))
    assert tuple(data["entrypoints"]) == C.SAAS_ENTRYPOINTS
    assert set(data["denied_third_party"]) == set(C.DENIED_THIRD_PARTY)
    assert set(data["denied_offense_prefixes"]) == set(C.DENIED_OFFENSE_PREFIXES)
    assert set(data["known_residual"]) == set(C.KNOWN_RESIDUAL)
