"""W1a — the dependency-aware REAL-test gate: buildsys detection + the offline command composer + the
sandbox read-only bind. Framework-free (stdlib + vigil_integration.{remediation,live} only) → runs in both
CI jobs. These prove the BEHAVIOR-PRESERVED axis is real (a runnable suite) yet fail-closed (a suite that
can't run is never claimed passed) and injection-free.
"""
from __future__ import annotations

from pathlib import Path

from vigil_integration.remediation.buildsys import (
    BuildPlan, detect_build_plan, compose_offline_test_command, _validated_specs,
)
from vigil_integration.live.sandbox_exec import build_bwrap_argv, _safe_ro_bind, _BWRAP_BASE_FLAGS


# ---------- buildsys: real-suite detection ----------
def _pyrepo(tmp_path, *, tests: bool) -> Path:
    r = tmp_path / "r"; (r / "svc").mkdir(parents=True)
    (r / "pyproject.toml").write_text("[project]\nname='x'\nversion='0'\n", encoding="utf-8")
    (r / "requirements.txt").write_text("requests\n", encoding="utf-8")
    (r / "svc" / "app.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    if tests:
        (r / "tests").mkdir()
        (r / "tests" / "test_app.py").write_text("from svc.app import f\ndef test_f():\n    assert f()==1\n", encoding="utf-8")
    return r


def test_detects_real_pytest_suite_and_install_specs(tmp_path):
    plan = detect_build_plan(str(_pyrepo(tmp_path, tests=True)))
    assert plan.language == "python"
    assert "compileall" in plan.build_cmd                    # the dep-free floor is still there
    assert plan.test_cmd == "python -m pytest -q"            # the REAL suite
    assert plan.needs_network is True
    assert "-r" in plan.install_specs and "requirements.txt" in plan.install_specs
    assert "pytest" in plan.install_specs                    # the runner is always installed
    assert "-e" in plan.install_specs and "." in plan.install_specs  # editable project install


def test_no_tests_means_no_real_suite_only_floor(tmp_path):
    plan = detect_build_plan(str(_pyrepo(tmp_path, tests=False)))
    assert plan.language == "python" and "compileall" in plan.build_cmd
    assert plan.test_cmd == "" and plan.install_specs == ()   # honest: no suite ⇒ no real-test claim


# ---------- the offline command composer ----------
def test_compose_offline_test_command_builds_venv_offline_install_pytest():
    plan = detect_build_plan_stub = BuildPlan(
        test_cmd="python -m pytest -q", install_specs=("-r", "requirements.txt", "-e", ".", "pytest"),
        language="python")
    cmd = compose_offline_test_command(plan, cache_dir_in_box="/vigil-depcache")
    assert "python3 -m venv .venv" in cmd
    assert "--no-index --find-links=\"/vigil-depcache\"" in cmd    # OFFLINE — never hits the network
    assert ".venv/bin/python -m pip install" in cmd and "-r requirements.txt -e . pytest" in cmd
    assert ".venv/bin/python -m pytest -q" in cmd                  # the suite runs from the venv


def test_composer_returns_empty_without_a_suite_or_bad_cache():
    assert compose_offline_test_command(BuildPlan(language="python"), cache_dir_in_box="/x") == ""
    good = BuildPlan(test_cmd="python -m pytest -q", install_specs=("pytest",), language="python")
    assert compose_offline_test_command(good, cache_dir_in_box="relative/not/abs") == ""   # cache must be absolute
    assert compose_offline_test_command(good, cache_dir_in_box="/ok")                       # sanity: abs works


def test_install_specs_injection_is_dropped():
    dirty = ("-r", "requirements.txt", "; rm -rf /", "$(evil)", "pkg&&curl", "-e", ".", "pytest", "good_pkg")
    kept = _validated_specs(dirty)
    assert "; rm -rf /" not in kept and "$(evil)" not in kept and "pkg&&curl" not in kept
    assert "-r" in kept and "requirements.txt" in kept and "-e" in kept and "." in kept
    assert "pytest" in kept and "good_pkg" in kept


# ---------- sandbox: read-only binds, zero-egress floor intact ----------
def test_ro_bind_appears_and_egress_floor_intact(tmp_path):
    cache = tmp_path / "wheelhouse"; cache.mkdir()
    argv = build_bwrap_argv("echo hi", tmp_path, bwrap="bwrap",
                            ro_binds=((str(cache), "/vigil-depcache"),))
    assert "--unshare-all" in argv                                  # the never-liftable zero-egress floor STAYS
    i = argv.index("--ro-bind")   # our extra bind is present, read-only, at the right target
    # find OUR bind specifically (there are several --ro-bind for /usr etc.)
    joined = " ".join(argv)
    assert f"--ro-bind {cache.resolve()} /vigil-depcache" in joined
    # it is inserted BEFORE the writable workspace bind
    assert joined.index("/vigil-depcache") < joined.index(f"--bind {tmp_path}")


def test_unsafe_ro_binds_are_rejected(tmp_path):
    missing = tmp_path / "nope"
    rel = "relative/dir"
    sym = tmp_path / "link"; (tmp_path / "real").mkdir(); sym.symlink_to(tmp_path / "real")
    argv = build_bwrap_argv("echo", tmp_path, bwrap="bwrap",
                            ro_binds=((str(missing), "/a"), (rel, "/b"), (str(sym), "/c"),
                                      (str(tmp_path / "real"), "notabsolute")))
    # every unsafe bind (missing / relative host / symlink host / non-absolute target) is DROPPED, so the
    # only `--ro-bind` left is the base /usr mount — no extra bind reached the argv.
    assert argv.count("--ro-bind") == 1                      # just the base `--ro-bind /usr /usr`
    for target in ("/a", "/b", "/c", "notabsolute"):
        assert target not in argv                            # no dropped target became a bind arg
    assert _safe_ro_bind(str(missing)) is None and _safe_ro_bind(rel) is None and _safe_ro_bind(str(sym)) is None
