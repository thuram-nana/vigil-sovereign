"""The W4 composite GitHub Action (.github/actions/vigil-codescan/action.yml) — structural guard.

Pins the shape CI depends on: it parses as valid YAML (no duplicate keys), is a COMPOSITE action, and its
last step invokes `python -m vigil_integration.cli ci-scan` wiring the documented inputs. A malformed
action.yml is how a shipped Action silently breaks for every consumer — this makes that a local failure.
"""

from __future__ import annotations

from pathlib import Path

import yaml

_ACTION = Path(__file__).resolve().parents[2] / ".github" / "actions" / "vigil-codescan" / "action.yml"


def test_action_yml_parses_and_is_composite() -> None:
    assert _ACTION.is_file(), _ACTION
    doc = yaml.safe_load(_ACTION.read_text(encoding="utf-8"))
    assert isinstance(doc, dict)
    assert doc.get("name") and doc.get("description")
    assert doc["runs"]["using"] == "composite"
    assert isinstance(doc["runs"]["steps"], list) and doc["runs"]["steps"]


def test_action_declares_the_documented_inputs_with_defaults() -> None:
    doc = yaml.safe_load(_ACTION.read_text(encoding="utf-8"))
    inputs = doc["inputs"]
    for name in ("queue-root", "base-dir", "fail-on", "max-files", "python-version"):
        assert name in inputs, name
        assert "default" in inputs[name]            # every input is optional (has a default)


def test_action_runs_the_ci_scan_cli_verb() -> None:
    doc = yaml.safe_load(_ACTION.read_text(encoding="utf-8"))
    runs = "\n".join(str(s.get("run", "")) for s in doc["runs"]["steps"])
    assert "vigil_integration.cli ci-scan" in runs
    # it threads the inputs through to the verb
    for flag in ("--queue-root", "--base-dir", "--fail-on", "--max-files"):
        assert flag in runs, flag
    # every composite run step declares a shell (a step without one is an invalid composite action)
    for step in doc["runs"]["steps"]:
        if "run" in step:
            assert step.get("shell"), step


def test_action_yml_has_no_duplicate_keys() -> None:
    # yaml.safe_load silently keeps the last of a duplicated key; a strict loader surfaces it (mirrors the
    # repo's yamllint key-duplicates=enable rule, which is the one structural rule it enforces on workflows).
    import yaml as _y

    class _StrictLoader(_y.SafeLoader):
        pass

    def _no_dupes(loader, node, deep=False):
        seen = set()
        for key_node, _ in node.value:
            key = loader.construct_object(key_node, deep=deep)
            assert key not in seen, f"duplicate key {key!r} in action.yml"
            seen.add(key)
        return _y.SafeLoader.construct_mapping(loader, node, deep=deep)

    _StrictLoader.add_constructor(_y.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _no_dupes)
    _y.load(_ACTION.read_text(encoding="utf-8"), Loader=_StrictLoader)
