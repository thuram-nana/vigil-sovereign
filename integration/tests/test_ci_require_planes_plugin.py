"""The ``pytest_require_planes`` plugin does what the both-planes CI commands rely on it to do.

``.github/scripts/pytest_require_planes.py`` is the runtime half of the cross-plane guard (the static
half is ``test_ci_cross_plane_tests_run_with_both_planes.py``): in a process that names a plane in
``VIGIL_REQUIRE_PLANES``, a skip for that plane is a failure. These tests drive a REAL pytest
subprocess over throwaway test files, because the behaviour that matters is the exit status CI sees.

Framework-free (stdlib + pytest), so it runs in the SOVEREIGN leg.
"""
from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[2] / ".github" / "scripts"
# A name no environment provides, so "the plane cannot be imported" is true wherever this runs.
_PLANE = "vigil_plane_that_does_not_exist"


def _run(tmp_path: Path, body: str, *, require: str | None, plugin: bool = True, conftest: str | None = None):
    (tmp_path / "test_sample.py").write_text(textwrap.dedent(body), encoding="utf-8")
    if conftest is not None:
        (tmp_path / "conftest.py").write_text(textwrap.dedent(conftest), encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if k != "VIGIL_REQUIRE_PLANES"}
    env["PYTHONPATH"] = str(_SCRIPTS)
    if require is not None:
        env["VIGIL_REQUIRE_PLANES"] = require
    cmd = [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "-q", "-rs", str(tmp_path)]
    if plugin:
        cmd[3:3] = ["-p", "pytest_require_planes"]
    res = subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=tmp_path, timeout=120)
    return res.returncode, res.stdout + res.stderr


_IN_TEST = f"""
    import pytest
    def test_needs_plane():
        pytest.importorskip("{_PLANE}.sub.module")
    def test_plain():
        assert True
"""
_MODULE_LEVEL = f"""
    import pytest
    mod = pytest.importorskip("{_PLANE}.sub.module")
    def test_uses_it():
        assert mod
"""
_HAND_ROLLED = f"""
    import pytest
    def test_hand_rolled():
        try:
            import {_PLANE}.sub  # noqa: F401
        except ImportError as exc:
            pytest.skip(str(exc))
"""
_THIRD_PARTY = """
    import pytest
    def test_optional_dependency():
        pytest.importorskip("some_optional_third_party_package_xyz")
"""


def test_without_the_variable_the_plugin_is_inert(tmp_path):
    rc, out = _run(tmp_path, _IN_TEST, require=None)
    assert rc == 0, out
    assert "1 passed, 1 skipped" in out


def test_an_importorskip_of_a_required_plane_fails_inside_a_test(tmp_path):
    rc, out = _run(tmp_path, _IN_TEST, require=_PLANE)
    assert rc == 1, out
    assert "1 failed, 1 passed" in out
    assert "would SKIP, but this leg requires" in out and "No module named" in out


def test_a_module_level_importorskip_of_a_required_plane_fails_collection(tmp_path):
    rc, out = _run(tmp_path, _MODULE_LEVEL, require=_PLANE)
    assert rc not in (0, 5), out
    assert "would SKIP, but this leg requires" in out
    assert "skipped" not in out.splitlines()[-1]


def test_a_hand_rolled_skip_for_a_required_plane_fails_the_run(tmp_path):
    rc, out = _run(tmp_path, _HAND_ROLLED, require=_PLANE)
    assert rc == 1, out
    assert "skipped for a REQUIRED plane" in out and "test_sample.py::test_hand_rolled" in out


def test_a_skip_for_anything_else_is_still_a_skip(tmp_path):
    rc, out = _run(tmp_path, _THIRD_PARTY, require=_PLANE)
    assert rc == 0, out
    assert "1 skipped" in out
    # …and it is reported at the TEST's line, not at the plugin's wrapper.
    assert "test_sample.py:4" in out and "pytest_require_planes.py" not in out


def test_only_the_named_planes_are_required(tmp_path):
    rc, out = _run(tmp_path, _IN_TEST, require="some_other_plane, another")
    assert rc == 0, out
    assert "1 passed, 1 skipped" in out


def test_negative_control_without_the_plugin_the_same_file_goes_green(tmp_path):
    """The hole itself, kept visible: the variable alone changes nothing — it is the plugin that turns
    the skip into a failure, so a both-planes command that drops ``-p pytest_require_planes`` is back to
    a green run that executed nothing (the static guard fails the build on exactly that)."""
    rc, out = _run(tmp_path, _IN_TEST, require=_PLANE, plugin=False)
    assert rc == 0, out
    assert "1 passed, 1 skipped" in out


def test_a_custom_reason_still_reports_the_real_import_error(tmp_path):
    """pytest's Skipped carries only the reason text; the plugin re-imports to name what actually failed."""
    body = f"""
        import pytest
        def test_needs_plane():
            pytest.importorskip("{_PLANE}.renamed", reason="CRUCIBLE (offense) not importable here")
    """
    rc, out = _run(tmp_path, body, require=_PLANE)
    assert rc == 1, out
    assert "ModuleNotFoundError" in out and f"{_PLANE}" in out and "not importable here" in out


def test_an_xfail_mark_cannot_turn_the_failure_green(tmp_path):
    body = f"""
        import pytest
        @pytest.mark.xfail(strict=True, reason="slice S6")
        def test_expected_to_fail_for_another_reason():
            pytest.importorskip("{_PLANE}.x", reason="custom")
    """
    rc, out = _run(tmp_path, body, require=_PLANE)
    assert rc != 0, out
    assert "skipped for a REQUIRED plane" in out


def test_an_alias_taken_in_a_conftest_is_the_patched_function(tmp_path):
    conftest = """
        import pytest
        need = pytest.importorskip
    """
    body = f"""
        from conftest import need
        def test_uses_the_alias():
            need("{_PLANE}.x", reason="custom")
    """
    rc, out = _run(tmp_path, body, require=_PLANE, conftest=conftest)
    assert rc == 1, out
    assert "would SKIP, but this leg requires" in out


def test_a_skipif_whose_reason_names_a_required_plane_fails_the_run(tmp_path):
    body = f"""
        import pytest
        @pytest.mark.skipif(True, reason="floor L3/L4 denylist needs {_PLANE}")
        def test_gated():
            pass
    """
    rc, out = _run(tmp_path, body, require=_PLANE)
    assert rc == 1, out
    assert "skipped for a REQUIRED plane" in out and "test_gated" in out


def test_an_english_word_plane_matches_only_its_module_forms(tmp_path):
    """`framework` is also an English word: only `framework.<x>` or the quoted name counts as naming it."""
    body = """
        import pytest
        @pytest.mark.skipif(True, reason="needs the test framework's docker fixture")
        def test_english():
            pass
        @pytest.mark.skipif(True, reason="drives framework.v2.agent_body.interface (offense leg only)")
        def test_dotted():
            pass
    """
    rc, out = _run(tmp_path, body, require="framework")
    assert rc == 1, out
    assert "test_dotted" in out.split("skipped for a REQUIRED plane", 1)[1]
    assert "test_english" not in out.split("skipped for a REQUIRED plane", 1)[1]
