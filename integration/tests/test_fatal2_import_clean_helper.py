"""Self-test of ``_fatal2.assert_import_clean`` — the fresh-interpreter FATAL-2 import check.

The helper is only worth having if it CATCHES a cross-plane import that an in-process ``sys.modules`` scan in
a framework-free process would miss: a module that imports the offense engine lazily or behind a guard. These
tests plant such modules in a temporary directory (put first on the child's path) and prove the helper flags
them, while a clean module passes. Framework-free in THIS process (the child is a separate interpreter), so
the file runs in the sovereign leg.
"""
from __future__ import annotations

import pytest
from _fatal2 import CHILD_PATH, REPO, assert_import_clean, import_report


def _plant(tmp_path, name: str, body: str):
    pkg = tmp_path / "fatal2_probe_pkg"
    pkg.mkdir(exist_ok=True)
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / f"{name}.py").write_text(body, encoding="utf-8")
    return f"import fatal2_probe_pkg.{name}"


def test_the_child_can_import_every_plane():
    # Otherwise a framework import could not be LOADED in the child and nothing would ever be flagged.
    assert {"integration", "engine/crucible", "apps/sigil", "gateway"} <= set(CHILD_PATH)
    report = import_report("import vigil_integration")
    assert report["framework_importable"] is True
    assert report["bad"] == []


def test_a_clean_module_passes(tmp_path):
    snippet = _plant(tmp_path, "clean", "import json\nVALUE = json.dumps({'ok': True})\n")
    assert_import_clean(snippet, extra_path=[tmp_path])


def test_a_lazy_import_time_framework_import_is_flagged(tmp_path):
    snippet = _plant(tmp_path, "lazy", "def _load():\n    import framework.v2.common  # noqa: F401\n\n_load()\n")
    with pytest.raises(AssertionError, match="framework"):
        assert_import_clean(snippet, extra_path=[tmp_path])


def test_a_guarded_framework_import_is_flagged(tmp_path):
    # the shape an in-process scan in a framework-free process can never see: the guard swallows the
    # ImportError there, but in a process that HAS the plane the module really co-loads it
    snippet = _plant(tmp_path, "guarded",
                     "try:\n    import framework.v2.common  # noqa: F401\nexcept ImportError:\n    pass\n")
    with pytest.raises(AssertionError, match="framework"):
        assert_import_clean(snippet, extra_path=[tmp_path])


def test_a_sovereign_import_is_flagged(tmp_path):
    snippet = _plant(tmp_path, "sov", "import importlib.util\n"
                     "assert importlib.util.find_spec('sigil') is not None\n"
                     "import sigil  # noqa: F401\n")
    with pytest.raises(AssertionError, match="sigil"):
        assert_import_clean(snippet, extra_path=[tmp_path])


def test_a_child_that_cannot_import_framework_is_a_failure_not_a_pass():
    # a clean verdict from a child that could not have loaded framework anyway proves nothing
    snippet = ("import sys\n"
               "sys.path[:] = [p for p in sys.path if not p.replace('\\\\', '/').endswith('engine/crucible')]\n")
    assert import_report(snippet)["framework_importable"] is False
    with pytest.raises(AssertionError, match="framework is not importable"):
        assert_import_clean(snippet)


def test_a_failing_snippet_is_a_failure_not_a_pass(tmp_path):
    with pytest.raises(AssertionError, match="child failed"):
        assert_import_clean("raise SystemExit(3)")


def test_the_child_runs_from_the_repository_root():
    assert (REPO / "integration" / "vigil_integration").is_dir()
