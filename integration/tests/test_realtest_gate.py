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
from vigil_integration.live.sandbox_exec import build_bwrap_argv, _safe_ro_bind, _safe_box_target, _BWRAP_BASE_FLAGS


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


# ---------- buildsys: JS/TS real-suite detection (Wave D) ----------
def _jsrepo(tmp_path, *, lock="package-lock.json", scripts_test="jest", devdeps=None, name="jsr"):
    import json as _json
    r = tmp_path / name; (r / "src").mkdir(parents=True)
    (r / "src" / "app.js").write_text("module.exports = x => x;\n", encoding="utf-8")
    pkg = {"name": "x", "version": "0.0.0"}
    if scripts_test is not None:
        pkg["scripts"] = {"test": scripts_test}
    if devdeps:
        pkg["devDependencies"] = {d: "*" for d in devdeps}
    (r / "package.json").write_text(_json.dumps(pkg), encoding="utf-8")
    if lock:
        (r / lock).write_text("{}\n" if lock.endswith(".json") else "# lock\n", encoding="utf-8")
    return r


def test_js_detects_real_npm_suite_via_scripts_test(tmp_path):
    plan = detect_build_plan(str(_jsrepo(tmp_path, lock="package-lock.json", scripts_test="jest")))
    assert plan.language == "javascript" and plan.pkg_manager == "npm"
    assert plan.test_cmd == "npm test --silent" and plan.needs_network is True
    assert "node --check" in plan.build_cmd and plan.deps_files == ("package-lock.json",)


def test_js_detects_runner_from_devdeps_when_no_scripts_test(tmp_path):
    plan = detect_build_plan(str(_jsrepo(tmp_path, lock="package-lock.json", scripts_test=None, devdeps=["vitest"])))
    assert plan.test_cmd == "npx --offline vitest run" and plan.pkg_manager == "npm"


def test_js_yarn_and_pnpm_package_managers(tmp_path):
    yp = detect_build_plan(str(_jsrepo(tmp_path, lock="yarn.lock", scripts_test="jest", name="y")))
    assert yp.pkg_manager == "yarn" and yp.test_cmd == "yarn test"
    pp = detect_build_plan(str(_jsrepo(tmp_path, lock="pnpm-lock.yaml", scripts_test="jest", name="p")))
    assert pp.pkg_manager == "pnpm" and pp.test_cmd == "pnpm test"


def test_js_no_lockfile_or_placeholder_test_is_floor_only(tmp_path):
    # no lockfile -> no reproducible install -> floor only
    nl = detect_build_plan(str(_jsrepo(tmp_path, lock=None, scripts_test="jest", name="nl")))
    assert nl.language == "javascript" and nl.test_cmd == "" and "node --check" in nl.build_cmd
    # npm-init placeholder is not a real suite
    ph = detect_build_plan(str(_jsrepo(tmp_path, lock="package-lock.json",
                                       scripts_test='echo "Error: no test specified" && exit 1', name="ph")))
    assert ph.test_cmd == "" and ph.language == "javascript"


def test_js_compose_offline_npm_ci_then_runner():
    plan = BuildPlan(test_cmd="npm test --silent", language="javascript", pkg_manager="npm",
                     install_specs=("package-lock.json",))
    cmd = compose_offline_test_command(plan, cache_dir_in_box="/vigil-npmcache")
    assert 'npm_config_cache="/vigil-npmcache"' in cmd and "npm ci --offline" in cmd
    assert cmd.strip().endswith("npm test --silent") and cmd.startswith("set -e;")
    # yarn / pnpm variants use the frozen offline install with the mounted store
    yc = compose_offline_test_command(BuildPlan(test_cmd="yarn test", language="javascript", pkg_manager="yarn"),
                                      cache_dir_in_box="/c")
    assert "yarn install --offline --frozen-lockfile" in yc and '--cache-folder "/c"' in yc
    pc = compose_offline_test_command(BuildPlan(test_cmd="pnpm test", language="javascript", pkg_manager="pnpm"),
                                      cache_dir_in_box="/c")
    assert "pnpm install --offline --frozen-lockfile" in pc and '--store-dir "/c"' in pc


def test_js_detect_is_total_on_hostile_package_json(tmp_path):
    # red-pen BLOCK: a deeply-nested (valid) package.json under the size cap raised RecursionError before the
    # reader was made truly total. package.json is repo-controlled, so detect_build_plan must NEVER raise.
    import json as _json
    r = tmp_path / "hostile"; r.mkdir()
    (r / "package-lock.json").write_text("{}", encoding="utf-8")
    (r / "package.json").write_text("[" * 100000 + "]" * 100000, encoding="utf-8")   # ~200 KB, deeply nested
    plan = detect_build_plan(str(r))                                                  # must not raise
    assert plan.language == "javascript" and plan.test_cmd == ""                      # unparseable -> floor only
    # other hostile shapes: a list-typed package.json, binary bytes, a scripts/devDeps of the wrong type
    for body in ("[1,2,3]", "\x00\x01 not json", '{"scripts": [1,2], "devDependencies": "nope"}',
                 '{"scripts": {"test": 42}}'):
        (r / "package.json").write_text(body, encoding="utf-8", errors="replace")
        p2 = detect_build_plan(str(r))                                                # total, no raise
        assert p2.language == "javascript" and p2.test_cmd == ""


# ---------- buildsys: Go + JVM real-suite detection (Wave D) ----------
def _gorepo(tmp_path, *, vendored, name="gor"):
    r = tmp_path / name; r.mkdir()
    (r / "go.mod").write_text("module x\n\ngo 1.22\n", encoding="utf-8")
    (r / "main.go").write_text("package main\nfunc main() {}\n", encoding="utf-8")
    if vendored:
        (r / "vendor").mkdir()
        (r / "vendor" / "modules.txt").write_text("# vendored\n", encoding="utf-8")
    return r


def test_go_vendored_runs_offline_without_a_cache(tmp_path):
    plan = detect_build_plan(str(_gorepo(tmp_path, vendored=True)))
    assert plan.language == "go" and plan.pkg_manager == "go-vendor"
    assert plan.test_cmd == "go test ./..." and plan.needs_network is False
    cmd = compose_offline_test_command(plan, cache_dir_in_box="/vigil-gocache")
    assert "GOFLAGS=-mod=vendor" in cmd and "GOPROXY=off" in cmd and cmd.strip().endswith("go test ./...")


def test_go_module_needs_the_module_cache(tmp_path):
    plan = detect_build_plan(str(_gorepo(tmp_path, vendored=False, name="gom")))
    assert plan.pkg_manager == "go-mod" and plan.needs_network is True
    cmd = compose_offline_test_command(plan, cache_dir_in_box="/vigil-gocache")
    assert 'GOMODCACHE="/vigil-gocache"' in cmd and "GOPROXY=off" in cmd and "go test ./..." in cmd


def test_jvm_maven_and_gradle(tmp_path):
    mvn = tmp_path / "mvn"; mvn.mkdir(); (mvn / "pom.xml").write_text("<project/>\n", encoding="utf-8")
    mp = detect_build_plan(str(mvn))
    assert mp.language == "jvm" and mp.pkg_manager == "maven" and mp.test_cmd == "mvn -o -q test"
    mc = compose_offline_test_command(mp, cache_dir_in_box="/m2")
    assert 'mvn -o -q -Dmaven.repo.local="/m2" test' in mc

    for gf in ("build.gradle", "build.gradle.kts"):
        g = tmp_path / ("g" + gf); g.mkdir(); (g / gf).write_text("plugins {}\n", encoding="utf-8")
        gp = detect_build_plan(str(g))
        assert gp.language == "jvm" and gp.pkg_manager == "gradle" and gp.test_cmd == "gradle --offline test"
        gc = compose_offline_test_command(gp, cache_dir_in_box="/gh")
        assert 'gradle --offline --gradle-user-home "/gh" test' in gc


def test_go_jvm_compose_rejects_bad_inputs():
    for pm in ("go-mod", "go-vendor"):
        assert compose_offline_test_command(BuildPlan(test_cmd="go test ./...", language="go", pkg_manager=pm),
                                            cache_dir_in_box="rel") == ""       # cache must be absolute
    assert compose_offline_test_command(BuildPlan(test_cmd="x", language="go", pkg_manager="go-bogus"),
                                        cache_dir_in_box="/c") == ""            # unknown go mode
    assert compose_offline_test_command(BuildPlan(test_cmd="x", language="jvm", pkg_manager="sbt"),
                                        cache_dir_in_box="/c") == ""            # unknown jvm tool


def test_detect_is_total_on_a_walk_recursionerror(tmp_path, monkeypatch):
    # red-pen adjacent finding: os.walk is RECURSIVE on Python < 3.13, so a pathologically deep repo tree
    # raised RecursionError past detect_build_plan's OSError-only guard. Simulate it (env-independent) and
    # assert detection stays TOTAL — degrades to floor/empty, never raises.
    import vigil_integration.remediation.buildsys as B
    r = tmp_path / "deep"; (r / "svc").mkdir(parents=True)
    (r / "pyproject.toml").write_text("[project]\nname='x'\nversion='0'\n", encoding="utf-8")
    (r / "svc" / "app.py").write_text("def f():\n    return 1\n", encoding="utf-8")

    def _boom_walk(*a, **k):
        raise RecursionError("maximum recursion depth exceeded")
    monkeypatch.setattr(B.os, "walk", _boom_walk)

    plan = B.detect_build_plan(str(r))                 # must NOT raise
    # pyproject is found via _has() (no walk); _has_tests' walk self-degrades -> floor-only, honest SKIP
    assert plan.language == "python" and "compileall" in plan.build_cmd and plan.test_cmd == ""


def test_js_compose_rejects_non_allowlisted_test_cmd_and_bad_inputs():
    # a caller-built plan with an arbitrary (injection) test_cmd is REFUSED (only allowlisted runners compose)
    evil = BuildPlan(test_cmd="jest; rm -rf /", language="javascript", pkg_manager="npm")
    assert compose_offline_test_command(evil, cache_dir_in_box="/c") == ""
    # relative cache and unknown PM are refused
    assert compose_offline_test_command(BuildPlan(test_cmd="npm test --silent", language="javascript",
                                                  pkg_manager="npm"), cache_dir_in_box="rel") == ""
    assert compose_offline_test_command(BuildPlan(test_cmd="npm test --silent", language="javascript",
                                                  pkg_manager="deno"), cache_dir_in_box="/c") == ""


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


def test_ro_bind_refuses_host_socket_dirs_and_shadowing_box_targets(tmp_path):
    # HOST system roots + socket/kernel trees are refused (a read-only bind of /run would expose docker.sock
    # to connect() from inside the box — a pivot to host root that --unshare-net cannot stop).
    for d in ("/", "/run", "/run/foo", "/proc", "/sys", "/dev", "/etc", "/usr", "/var", "/home", "/lib"):
        assert _safe_ro_bind(d) is None, d
    cache = tmp_path / "wh"; cache.mkdir()
    assert _safe_ro_bind(str(cache)) is not None            # a real cache dir is fine
    # BOX mount points that shadow a base mount / dangerous dir are refused; a fresh top-level is ok.
    for bad in ("/usr", "/etc", "/tmp", "/run", "/", "/usr/lib", "relative", "/var/cache"):
        assert not _safe_box_target(bad), bad
    assert _safe_box_target("/vigil-depcache")
    # end-to-end: a /run->/run bind and a cache->/usr bind never reach the argv (only the base /usr survives)
    argv = build_bwrap_argv("echo", tmp_path, bwrap="bwrap",
                            ro_binds=(("/run", "/run"), (str(cache), "/usr")))
    assert argv.count("--ro-bind") == 1
    assert "/run" not in argv
