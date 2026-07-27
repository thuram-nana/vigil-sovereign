"""Phase B1 — the unified ToolProfile + the tool-consciousness admission gate (tools/profile.py).

Proves: the join fuses the host roster + Strix CLI playbooks + typed argv builders on the binary name; the
gate ADMITS a globally-recognised tool with a CLI/background control surface and REFUSES one that is either
not recognised or has no way to be driven (no playbook + no builder), with an honest reason; the typed
builder list does not drift from the live executor's real _BUILDERS (source-text cross-check, no import).
"""
from __future__ import annotations

import ast
import pathlib

import pytest

from framework.v2.tools import profile as P


def _by_name(profiles):
    return {p["name"]: p for p in profiles}


def test_build_profiles_shape_and_summary_are_honest():
    out = P.build_profiles()
    assert set(out) == {"profiles", "summary"}
    profs = out["profiles"]
    assert profs and all({"name", "admitted", "control_surface", "global_recognition",
                          "admit_reason", "install_hint", "has_skill_doc", "has_typed_builder"} <= set(p)
                         for p in profs)
    s = out["summary"]
    assert s["total"] == len(profs)
    assert s["admitted"] + s["refused"] == s["total"]


def test_typed_builder_tools_admit_even_without_a_skill_doc():
    # nmap + hydra have a typed argv builder → a CLI control surface regardless of Strix being importable →
    # (they are also globally recognised via the host roster) → ADMITTED.
    got = _by_name(P.build_profiles()["profiles"])
    for name in ("nmap", "hydra"):
        p = got[name]
        assert p["has_typed_builder"] and p["control_surface"] == "cli"
        assert p["global_recognition"] and p["admitted"] and p["admit_reason"].startswith("admitted")


def test_roster_tool_with_no_usage_knowledge_is_refused():
    # a host-roster tool with NO skill playbook AND NO typed builder can't be driven → REFUSED honestly,
    # even though it's recognised + installable. (joern/nikto/tshark/wapiti/zaproxy/chromium are such.)
    got = _by_name(P.build_profiles()["profiles"])
    candidates = [n for n in ("joern", "nikto", "tshark", "wapiti", "zaproxy", "chromium") if n in got]
    assert candidates, "expected at least one roster tool without a playbook/builder"
    for name in candidates:
        p = got[name]
        assert not p["has_typed_builder"] and not p["has_skill_doc"]
        assert p["control_surface"] == "" and not p["admitted"]
        assert p["global_recognition"]                      # recognised (in the roster) …
        assert "no CLI-usage knowledge" in p["admit_reason"]  # … but refused for lack of a way to drive it


def test_admit_gate_unit():
    assert P._admit(False, "cli")[0] is False               # not recognised → refused
    assert "not a globally-recognised" in P._admit(False, "cli")[1]
    assert P._admit(True, "")[0] is False                   # recognised but no control surface → refused
    assert "no CLI-usage knowledge" in P._admit(True, "")[1]
    ok, why = P._admit(True, "cli")
    assert ok and why == "admitted (cli)"
    assert P._admit(True, "background")[0] is True          # background surface also admits


def test_skill_doc_only_tool_admits_when_strix_is_present():
    pytest.importorskip("strix")
    got = _by_name(P.build_profiles()["profiles"])
    # semgrep is in the host roster + has a Strix tooling playbook but is NOT a typed builder → the CLI
    # control surface comes from the playbook alone → admitted.
    if "semgrep" in got:
        p = got["semgrep"]
        assert p["has_skill_doc"] and not p["has_typed_builder"]
        assert p["control_surface"] == "cli" and p["admitted"]


def _repo_root() -> pathlib.Path:
    for anc in pathlib.Path(__file__).resolve().parents:
        if (anc / "engine" / "crucible").is_dir() and (anc / "integration").is_dir():
            return anc
    raise AssertionError("repo root not found")


def test_typed_builder_list_does_not_drift_from_the_live_executor():
    # profile._TYPED_BUILDER_TOOLS duplicates integration.live.executor._BUILDERS' keys to avoid a backwards
    # crucible→integration import; pin them equal by SOURCE TEXT (no cross-env import) so they can't drift.
    src = (_repo_root() / "integration/vigil_integration/live/executor.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    keys: set = set()
    for node in ast.walk(tree):
        target_names = []
        if isinstance(node, ast.Assign):
            target_names = [t.id for t in node.targets if isinstance(t, ast.Name)]
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            target_names = [node.target.id]
        if "_BUILDERS" in target_names and isinstance(getattr(node, "value", None), ast.Dict):
            keys = {k.value for k in node.value.keys if isinstance(k, ast.Constant)}
            break
    assert keys, "could not extract _BUILDERS keys from the executor source"
    assert set(P._TYPED_BUILDER_TOOLS) == keys, (
        f"typed-builder drift: profile={set(P._TYPED_BUILDER_TOOLS)} executor={keys}")
