"""sx-s1 — ONE authoritative Strix runtime adapter, and the guard that keeps it the only one.

Before this slice the vendored Strix agent was started from several places with DIFFERENT amounts of
pre-flight; ``vigil strix`` in particular dispatched the raw console-script with NONE of it (no sandbox
network pin, no proof-run dir, no model/sovereignty gate) and never set ``VIGIL_BASE_DIR`` — so the child's
WARDEN gate re-rooted its approvals dir to the process CWD, found no provisioned authority, and hard-blocked
every ``exec_command``. This slice funnels the CLI paths through ``vigil_integration.strix_runtime`` and
pins, with a guard test, that the Strix executable is LOCATED in exactly one module.

NO FRAMEWORK IMPORTS. Everything here imports only ``vigil_integration`` + the standard library and injects
the sovereignty gate / the Docker networking, so it runs in the "integration two-env boundary (P5)" job in
BOTH legs and needs no entry in the ci.yml offense-leg run-list.
"""
from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path

import pytest

from vigil_integration import dispatch as D
from vigil_integration import strix_runtime as SR

_REPO = Path(__file__).resolve().parents[2]
_SCAN_ROOTS = (
    _REPO / "integration" / "vigil_integration",
    _REPO / "engine" / "crucible" / "framework" / "v2" / "console",
)


# --------------------------------------------------------------------------------------------------
# A fake SandboxNetworking (the strix_sandbox pre-flight seam) — no Docker.
# --------------------------------------------------------------------------------------------------
class _FakeNet:
    def __init__(self, state="running", present=True, network="vigil_sandbox"):
        self.sandbox_network = network
        self._state, self._present = state, present

    def container_state(self, name="vigil-gateway"):
        return self._state

    def network_exists(self, name=None):
        return self._present

    def strix_env(self):
        return {"STRIX_DOCKER_SANDBOX_NETWORK": self.sandbox_network}

    def sandbox_gateway_ip(self):
        return "172.31.240.2"


def _permit(_llm_env):
    """An injected sovereignty gate that PERMITS (no refusal, no pin/strip) — for the healthy path."""
    return "", {}, []


def _fn_code(path: Path, func_name: str) -> str:
    """A function's code with its docstring removed, parsed from the real file (never imported — so this
    reads console source in BOTH legs). A wiring probe must never match prose."""
    src = path.read_text(encoding="utf-8", errors="replace")
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == func_name:
            body = list(node.body)
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
                    and isinstance(body[0].value.value, str):
                body = body[1:]
            return "\n".join(ast.get_source_segment(src, s) or "" for s in body)
    raise AssertionError(f"{func_name} not found in {path}")


def _files_calling_which_strix() -> set[str]:
    """Every .py under the scan roots (excluding tests) that CALLS ``which("strix")`` — the PATH locator for
    the Strix executable. AST-based, so it matches real code only and is immune to the token appearing in a
    comment or docstring."""
    hits: set[str] = set()
    for root in _SCAN_ROOTS:
        for path in root.rglob("*.py"):
            if "/tests/" in path.as_posix() or path.name.startswith("test_"):
                continue
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call) or not node.args:
                    continue
                fn = node.func
                name = fn.attr if isinstance(fn, ast.Attribute) else (fn.id if isinstance(fn, ast.Name) else "")
                arg0 = node.args[0]
                if name == "which" and isinstance(arg0, ast.Constant) and arg0.value == "strix":
                    hits.add(path.name)
    return hits


# --------------------------------------------------------------------------------------------------
# THE GUARD: the Strix executable is located in exactly one module.
# --------------------------------------------------------------------------------------------------
def test_the_strix_binary_is_located_only_in_the_runtime_adapter():
    """No module other than the authoritative adapter may resolve the Strix executable via
    ``which("strix")`` — a new spawn path must go through ``strix_runtime`` (and thus its pre-flight)."""
    assert _files_calling_which_strix() == {"strix_runtime.py"}, (
        "the Strix executable is located outside the authoritative runtime adapter — every spawn path must "
        "resolve it via vigil_integration.strix_runtime.resolve_strix_bin()"
    )


def test_negative_control_the_runtime_adapter_really_locates_the_binary():
    """Proves the guard is not vacuous: the adapter is the file that DOES locate the binary, and its locator
    yields a real ``strix`` path."""
    assert "strix_runtime.py" in _files_calling_which_strix()
    assert SR.resolve_strix_bin().endswith("strix")


def test_resolve_strix_bin_survives_a_symlinked_venv_python(tmp_path, monkeypatch):
    """Regression: a venv's bin/python is usually a SYMLINK to the system interpreter. resolve_strix_bin must
    look in the venv bin dir (the symlink's own parent), not the RESOLVED target dir — else it misses the
    venv's `strix`, falls through to PATH, returns the bare name, and a spawn with a foreign cwd dies rc 127.
    """
    import os
    sysbin = tmp_path / "sysbin"; sysbin.mkdir()
    real_py = sysbin / "python3"; real_py.write_text("#!/bin/sh\n"); os.chmod(real_py, 0o755)
    venvbin = tmp_path / "venv" / "bin"; venvbin.mkdir(parents=True)
    (venvbin / "strix").write_text("#!/bin/sh\n"); os.chmod(venvbin / "strix", 0o755)
    venv_py = venvbin / "python3"; venv_py.symlink_to(real_py)   # the classic venv layout
    monkeypatch.setattr(SR.sys, "executable", str(venv_py))
    monkeypatch.setattr(SR.shutil, "which", lambda _n: None)     # PATH does NOT have strix (the child's case)
    got = SR.resolve_strix_bin()
    assert got == str(venvbin / "strix"), got   # the venv strix, NOT the bare name or the sysbin dir


def test_the_console_sources_its_strix_bin_from_the_adapter():
    """The console's codebase spawn builds its argv from the adapter's locator, not a raw ``which`` — so it
    cannot drift into a second, un-pre-flighted way to find the binary."""
    code = _fn_code(_SCAN_ROOTS[1] / "actions.py", "launch_assessment")
    assert "_strix_runtime_bin()" in code, "the console no longer sources its Strix bin from the adapter"
    assert 'which("strix")' not in code, "the console regressed to a raw Strix-binary locator"


# --------------------------------------------------------------------------------------------------
# vigil strix routes THROUGH the adapter, not the raw console-script.
# --------------------------------------------------------------------------------------------------
def test_the_strix_verb_is_declared_a_runtime_routed_verb():
    assert D._RUNTIME_MODULE.get("strix") == "vigil_integration.strix_runtime"
    # the fixed env table is untouched — strix still routes to the OFFENSE venv (the boundary property).
    assert D._ENV["strix"][0] == "offense"
    assert "strix" in D.PASSTHROUGH_VERBS


def test_dispatch_runs_the_runtime_module_in_the_offense_venv(monkeypatch, tmp_path):
    """``vigil strix …`` execs ``.venv-offense/bin/python -m vigil_integration.strix_runtime …`` — a
    separate offense-plane process that pre-flights before it ever reaches the raw agent."""
    py = tmp_path / ".venv-offense" / "bin" / "python"
    py.parent.mkdir(parents=True)
    py.write_text("#!/bin/sh\n")
    monkeypatch.setenv("VIGIL_ROOT", str(tmp_path))
    seen = {}

    class _Done:
        returncode = 7

    def _fake_run(cmd, *a, **k):
        seen["cmd"] = cmd
        seen["env"] = k.get("env")
        return _Done()

    monkeypatch.setenv("PYTHONPATH", "engine/crucible:integration")   # a cross-domain path from the parent
    monkeypatch.setenv("PYTHONHOME", "/some/home")
    monkeypatch.setenv("VIGIL_DESTRUCTION_OWNER_KEY", "owner-secret")
    monkeypatch.setattr(subprocess, "run", _fake_run)

    rc = D.dispatch("strix", ["--target", "/x", "--instruction", "look"])
    assert rc == 7
    assert seen["cmd"] == [str(py), "-m", "vigil_integration.strix_runtime",
                           "--target", "/x", "--instruction", "look"]
    env = seen["env"] or {}
    # the two-env + keyless-offense boundary still holds across this exec
    assert "PYTHONPATH" not in env and "PYTHONHOME" not in env
    assert "VIGIL_DESTRUCTION_OWNER_KEY" not in env, "an offense child must never inherit the owner key"


def test_dispatch_strix_fails_clean_when_the_offense_venv_is_missing(monkeypatch, tmp_path):
    monkeypatch.setenv("VIGIL_ROOT", str(tmp_path))              # no venv built under it
    assert D.dispatch("strix", ["--target", "/x"]) == 127


def test_dispatch_module_still_imports_no_subsystem():
    """Routing through the adapter must NOT import it (or framework/strix) into the pure-stdlib dispatcher —
    the boundary property test_dispatch_routing pins, re-checked here for this change."""
    code = ("import vigil_integration.dispatch, sys; "
            "bad = [m for m in ('framework','strix','sigil','vigil_integration.strix_runtime') "
            "if m in sys.modules]; print('LEAK:'+','.join(bad)) if bad else print('CLEAN')")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                         env={"PYTHONPATH": "integration", "PATH": "/usr/bin:/bin"}, cwd=str(_REPO))
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "CLEAN", out.stdout


# --------------------------------------------------------------------------------------------------
# resolve_base_dir — the concrete VIGIL_BASE_DIR fix.
# --------------------------------------------------------------------------------------------------
def test_resolve_base_dir_is_always_absolute(monkeypatch):
    monkeypatch.delenv("VIGIL_BASE_DIR", raising=False)
    default = SR.resolve_base_dir()
    assert os.path.isabs(default), "an unset base dir must resolve ABSOLUTE, not a CWD-relative .vigil-live"
    assert default.endswith(os.sep + ".vigil-live")
    assert os.path.isabs(SR.resolve_base_dir("some/rel/dir")), "a relative explicit base dir must absolutize"


def test_resolve_base_dir_respects_an_explicit_and_the_env(monkeypatch, tmp_path):
    monkeypatch.setenv("VIGIL_BASE_DIR", str(tmp_path / "env-base"))
    assert SR.resolve_base_dir() == str(tmp_path / "env-base")
    assert SR.resolve_base_dir(str(tmp_path / "explicit")) == str(tmp_path / "explicit"), (
        "an explicit base dir must win over the environment"
    )


def test_negative_control_base_dir_is_not_the_relative_default(monkeypatch):
    """The bug was a CWD-relative ``.vigil-live``; prove the resolver never returns that bare relative form."""
    monkeypatch.delenv("VIGIL_BASE_DIR", raising=False)
    assert SR.resolve_base_dir() != ".vigil-live"


# --------------------------------------------------------------------------------------------------
# strix_child_env — the single child-env assembler.
# --------------------------------------------------------------------------------------------------
def test_strix_child_env_carries_run_context_and_pins_win_last(tmp_path):
    env = SR.strix_child_env(
        base_dir=str(tmp_path / "base"), run_dir=str(tmp_path / "run"), slug="acme",
        sandbox_env={"STRIX_DOCKER_SANDBOX_NETWORK": "vigil_sandbox"},
        llm_env={"STRIX_LLM": "ollama/llama3"},
        alias_extra={"LLM_API_BASE": "http://localhost:11434"})
    assert env["VIGIL_PROOF_RUN_DIR"] == str(tmp_path / "run")
    assert env["VIGIL_ENGAGEMENT"] == "acme"
    assert env["VIGIL_BASE_DIR"] == str(tmp_path / "base") and os.path.isabs(env["VIGIL_BASE_DIR"])
    assert env["STRIX_DOCKER_SANDBOX_NETWORK"] == "vigil_sandbox"
    assert env["STRIX_LLM"] == "ollama/llama3" and env["LLM_API_BASE"] == "http://localhost:11434"


# --------------------------------------------------------------------------------------------------
# prepare / launch — the full pre-flight, fail-closed.
# --------------------------------------------------------------------------------------------------
def test_prepare_refuses_when_the_sandbox_cannot_be_pinned(tmp_path):
    d = SR.prepare(["--target", "/x"], base_dir=str(tmp_path), networking=_FakeNet(state="exited"),
                   sovereignty_gate=_permit)
    assert not d.ok and "not running" in d.refusal, "a down gateway must refuse the launch, not run ungated"
    assert d.env == {}


def test_prepare_refuses_on_a_sovereignty_violation_before_touching_the_sandbox(tmp_path):
    """The model-egress gate precedes the sandbox pre-flight — a forbidden backend refuses even with a
    perfectly healthy network (order: every refusal before any spawn)."""
    def _deny(_e):
        return "REFUSED: cloud model under a sovereign tier", {}, []
    d = SR.prepare(["--target", "/x"], base_dir=str(tmp_path), networking=_FakeNet(), sovereignty_gate=_deny)
    assert not d.ok and d.refusal.startswith("REFUSED: cloud")


def test_prepare_fails_closed_when_the_gate_raises(tmp_path):
    def _boom(_e):
        raise RuntimeError("policy engine exploded")
    d = SR.prepare(["--target", "/x"], base_dir=str(tmp_path), networking=_FakeNet(), sovereignty_gate=_boom)
    assert not d.ok and "refus" in d.refusal.lower()


def test_prepare_gated_success_assembles_the_child_env(tmp_path):
    d = SR.prepare(["--target", str(tmp_path / "proj")], base_dir=str(tmp_path), networking=_FakeNet(),
                   sovereignty_gate=_permit)
    assert d.ok and not d.refusal
    assert d.env["STRIX_DOCKER_SANDBOX_NETWORK"] == "vigil_sandbox"
    assert d.env["VIGIL_BASE_DIR"] == str(tmp_path) and os.path.isabs(d.env["VIGIL_BASE_DIR"])
    assert d.env["VIGIL_PROOF_RUN_DIR"].startswith(str(tmp_path))
    assert d.slug == "proj"


def test_launch_refuses_without_ever_spawning(tmp_path):
    spawned = []
    rc = SR.launch(["--target", "/x"], base_dir=str(tmp_path), networking=_FakeNet(state="exited"),
                   sovereignty_gate=_permit, runner=lambda cmd, env: spawned.append((cmd, env)) or 0)
    assert rc == 2 and spawned == [], "a refusal must return non-zero and spawn nothing"


def test_launch_spawns_with_the_gated_env_on_the_healthy_path(tmp_path):
    captured = {}

    def _runner(cmd, env):
        captured["cmd"], captured["env"] = cmd, env
        return 0

    rc = SR.launch(["--target", str(tmp_path / "proj")], base_dir=str(tmp_path), networking=_FakeNet(),
                   sovereignty_gate=_permit, runner=_runner)
    assert rc == 0
    assert captured["cmd"][0].endswith("strix")
    assert captured["cmd"][1:] == ["--target", str(tmp_path / "proj")]
    assert captured["env"]["VIGIL_BASE_DIR"] == str(tmp_path)
    assert captured["env"]["STRIX_DOCKER_SANDBOX_NETWORK"] == "vigil_sandbox"


def test_launch_strips_the_removed_api_base_aliases(tmp_path, monkeypatch):
    """The sovereignty positive-control's stripped ``api_base`` siblings must not survive into the child."""
    monkeypatch.setenv("OPENAI_BASE_URL", "http://evil.example:11434")

    def _pin(_e):
        return "", {"LLM_API_BASE": "http://localhost:11434"}, ["OPENAI_BASE_URL"]

    captured = {}
    SR.launch(["--target", "/x"], base_dir=str(tmp_path), networking=_FakeNet(), sovereignty_gate=_pin,
              runner=lambda cmd, env: captured.update(env=env) or 0)
    assert captured["env"].get("LLM_API_BASE") == "http://localhost:11434"
    assert "OPENAI_BASE_URL" not in captured["env"], "a stripped api_base alias leaked into the child"


# --------------------------------------------------------------------------------------------------
# derive_slug
# --------------------------------------------------------------------------------------------------
def test_derive_slug():
    assert SR.derive_slug(["--target", "/home/op/proj"]) == "proj"
    assert SR.derive_slug(["--mount", "/a/b/mono/"]) == "mono"
    assert SR.derive_slug(["--slug", "acme", "--target", "/x"]) == "acme"
    assert SR.derive_slug(["--slug=acme-1", "--target", "/x"]) == "acme-1"
    assert SR.derive_slug(["--help"]) == "strix-cli"
