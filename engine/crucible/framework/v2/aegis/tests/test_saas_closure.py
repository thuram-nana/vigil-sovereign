"""
AS-28 — the AEGIS SaaS defense-image CLOSURE proof (the security core of the slice).

Two independent proofs that the gateway's runtime does NOT carry the offense engine:

  1. STATIC (``aegis.closure``): walk the module-level import graph from the serving entrypoints,
     soundly accounting for ancestor-package ``__init__`` execution, and assert nothing on the deny list
     is reachable and every first-party module resolved (fail-closed).
  2. RUNTIME ("also with ``anthropic`` blocked"): in a fresh subprocess install an import hook that makes
     ``anthropic`` and the other LLM/agent SDKs UNIMPORTABLE, then import the entrypoints and confirm they
     still load — catching any dynamic/transitive path the static pass does not model.

Plus negative controls (the guard is not vacuous) and a RATCHET over the known, deferred residual.
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

try:
    import framework.v2.aegis.cli      # the module `python3 -m framework.v2 aegis gateway` dispatches to
    import framework.v2.aegis.gateway  # the serving core
except ModuleNotFoundError as e:
    name = (e.name or "").split('.')[0]
    kind = "blocked_name_needed" if name in _BLOCKED else "other_import_error"
    print(json.dumps({{"status": kind, "module": e.name}})); sys.exit(0)

leaked = sorted(m for m in sys.modules if m.split('.')[0] in _BLOCKED)
print(json.dumps({{"status": "ok", "leaked": leaked}}))
"""


def _run_probe() -> dict:
    script = _RUNTIME_PROBE.format(blocked=list(_BLOCKED))
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["PYTHONPATH"] = str(_ENGINE_ROOT)
    proc = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True, text=True, env=env, cwd=str(_ENGINE_ROOT), timeout=120,
    )
    assert proc.returncode == 0, f"probe crashed:\nSTDOUT:{proc.stdout}\nSTDERR:{proc.stderr}"
    return json.loads(proc.stdout.strip().splitlines()[-1])


def test_gateway_imports_with_anthropic_and_sdks_blocked():
    out = _run_probe()
    if out["status"] == "other_import_error":
        pytest.skip(f"unrelated dependency missing in this env: {out.get('module')!r}")
    assert out["status"] != "blocker_dead", "import blocker did not take effect"
    assert out["status"] == "ok", (
        f"the defense gateway requires a blocked LLM/agent SDK at import: {out.get('module')!r}"
    )
    assert out["leaked"] == [], f"blocked packages leaked into the gateway process: {out['leaked']}"


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
