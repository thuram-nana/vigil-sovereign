"""remediation.buildsys — detect a repo's build/test commands for the deep-fix gate.

The deep-fix ladder runs a fix's patched clone through a BUILD/TEST gate (Axis A — it BLOCKS a fix that
breaks the code; it never certifies one). That runs inside the network-isolated bwrap sandbox
(`live.sandbox_exec.run_sandboxed`).

Two tiers of gate, in increasing strength:

  * The **dependency-FREE** floor (`build_cmd`): a compile/syntax check (`compileall`, `node --check`) that
    needs no third-party deps — always runnable, even with zero egress. This is what shipped originally.
  * The **real test suite** (`test_cmd` + `install_specs`): runs the repo's ACTUAL tests, but only once its
    third-party deps are resolved. The deps come EITHER from an offline cache/wheelhouse mounted read-only
    (`compose_offline_test_command`) OR, later, from a gated network install. When neither is available the
    caller falls back to the dependency-free floor and marks the test axis honestly SKIPPED — a real test
    suite that could not run is NEVER reported as passed.

This detector is PURE + TOTAL: it reads only the presence of well-known files (and parses package.json in a
fully-guarded reader), never imports `framework`, never runs anything, and is total on any attacker-influenced
repo — a hostile package.json or a pathological directory tree (RecursionError from `os.walk` on Python < 3.13)
degrades to a floor/empty plan rather than raising. Its emitted commands contain only FIXED literals + detected
filenames validated to be simple basenames (no repo-supplied free text) — so the composed `/bin/sh -c` string
is injection-free.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field

# a conservative basename allowlist so a detected filename can never inject shell metacharacters
_SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


@dataclass(frozen=True)
class BuildPlan:
    build_cmd: str = ""                       # dependency-FREE compile/syntax gate; "" = none detected
    test_cmd: str = ""                        # the REAL test invocation (e.g. "python -m pytest -q"); "" = none
    install_specs: tuple[str, ...] = ()       # pip/npm install ARGS (validated); the composer adds index/proxy flags
    deps_files: tuple[str, ...] = ()          # detected dependency manifests (basenames)
    needs_network: bool = False               # True ⇒ install_specs need deps from a cache or a gated network
    language: str = ""
    pkg_manager: str = ""                     # JS/TS package manager: npm | yarn | pnpm ("" for others)
    note: str = ""


def _has(repo: str, *names: str) -> bool:
    return any(os.path.exists(os.path.join(repo, n)) for n in names)


def _any_ext(repo: str, ext: str, *, max_walk: int = 4000) -> bool:
    """Is there at least one file with ``ext`` anywhere in the tree? Bounded walk; skips VCS/vendor dirs.
    TOTAL: a hostile/pathological tree (e.g. a RecursionError from the recursive ``os.walk`` on Python < 3.13,
    or an OSError mid-walk) degrades to "not found" (False), never a raise."""
    seen = 0
    try:
        for root, dirs, files in os.walk(repo):
            dirs[:] = [d for d in dirs if d not in (".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build")]
            for f in files:
                seen += 1
                if seen > max_walk:
                    return False
                if f.endswith(ext):
                    return True
    except (OSError, RecursionError, MemoryError):
        return False
    return False


def _has_tests(repo: str) -> bool:
    """A plausibly-runnable test setup: a pytest/tox config, a tests dir, or any test_*.py / *_test.py."""
    if _has(repo, "pytest.ini", "tox.ini") or _has(repo, "tests") or _has(repo, "test"):
        return True
    seen = 0
    try:
        for root, dirs, files in os.walk(repo):
            dirs[:] = [d for d in dirs if d not in (".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build")]
            for f in files:
                seen += 1
                if seen > 6000:
                    return False
                if (f.startswith("test_") and f.endswith(".py")) or f.endswith("_test.py"):
                    return True
    except (OSError, RecursionError, MemoryError):
        return False
    return False


def _py_install_specs(repo: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """(install_specs, deps_files) for a Python repo. Prefers requirement files, else an editable install of
    the project; always adds ``pytest`` so the runner is present. Every emitted token is a fixed literal or a
    basename that matches _SAFE_NAME (injection-free)."""
    specs: list[str] = []
    found: list[str] = []
    for name in ("requirements.txt", "requirements-dev.txt", "requirements-test.txt", "dev-requirements.txt"):
        if _has(repo, name) and _SAFE_NAME.match(name):
            specs += ["-r", name]
            found.append(name)
    if _has(repo, "pyproject.toml", "setup.py", "setup.cfg"):
        specs += ["-e", "."]
        found.append("pyproject.toml" if _has(repo, "pyproject.toml") else "setup.py")
    specs.append("pytest")   # ensure the test runner is installed even if the project doesn't pin it
    return tuple(specs), tuple(dict.fromkeys(found))


# JS/TS test runners we can invoke with a FIXED command (no repo free-text) — devDep/dep name -> npx invocation
_JS_RUNNERS = (("jest", "npx --offline jest"), ("vitest", "npx --offline vitest run"),
               ("mocha", "npx --offline mocha"), ("jasmine", "npx --offline jasmine"),
               ("ava", "npx --offline ava"))
# lockfile -> package manager + its offline frozen install (FIXED literals only)
_JS_LOCKS = (("package-lock.json", "npm"), ("npm-shrinkwrap.json", "npm"),
             ("yarn.lock", "yarn"), ("pnpm-lock.yaml", "pnpm"))
# the CLOSED set of JS test commands compose_offline_test_command will interpolate — defence in depth so a
# caller-built BuildPlan with an arbitrary test_cmd can never inject shell (mirrors the python tier's fixed cmd)
_JS_TEST_CMDS = frozenset(
    ["npm test --silent", "yarn test", "pnpm test"] + [inv for _n, inv in _JS_RUNNERS])


def _read_package_json(repo: str) -> dict:
    """Parse ``package.json`` (bounded read). TOTAL: package.json is repo-controlled (the codebase being
    remediated), so ANY failure — an OSError, a JSON ValueError, or a RecursionError/MemoryError from
    deeply-nested-but-valid JSON under the size cap — yields ``{}`` (floor-only detection), never a raise."""
    try:
        fp = os.path.join(repo, "package.json")
        if not os.path.isfile(fp) or os.path.getsize(fp) > 4_000_000:
            return {}
        with open(fp, encoding="utf-8", errors="replace") as fh:
            obj = json.loads(fh.read())
        return obj if isinstance(obj, dict) else {}
    except Exception:  # noqa: BLE001 — a hostile package.json must degrade to floor-only, never crash detection
        return {}


def _js_pkg_manager(repo: str) -> str:
    """The package manager from the lockfile present (npm > yarn > pnpm precedence by lockfile presence)."""
    for lock, pm in _JS_LOCKS:
        if _has(repo, lock):
            return pm
    return ""


def _js_test_cmd(repo: str, pm: str) -> str:
    """A FIXED test command for the repo, or "" if no runnable suite is detected. Prefers the project's own
    ``scripts.test`` (run via the detected PM) — faithful, and never interpolates the script's text — then
    falls back to a known runner found in (dev)dependencies. Injection-free: the returned string is composed
    only from fixed literals (the PM name and runner are from closed allowlists)."""
    pkg = _read_package_json(repo)
    scripts = pkg.get("scripts") if isinstance(pkg.get("scripts"), dict) else {}
    raw_test = scripts.get("test")
    test_script = raw_test if isinstance(raw_test, str) else ""   # a non-string scripts.test is malformed, not a suite
    # npm's init placeholder ("Error: no test specified") is not a real suite
    if test_script and "no test specified" not in test_script.lower():
        runner = {"npm": "npm test --silent", "yarn": "yarn test", "pnpm": "pnpm test"}.get(pm, "npm test --silent")
        return runner
    deps = {}
    for k in ("devDependencies", "dependencies", "peerDependencies"):
        d = pkg.get(k)
        if isinstance(d, dict):
            deps.update(d)
    for name, invocation in _JS_RUNNERS:
        if name in deps:
            return invocation
    return ""


def _js_offline_install(pm: str, cache_in_box: str) -> str:
    """The offline, frozen install for ``pm`` using the read-only cache/store mounted at ``cache_in_box``.
    FIXED literals only + the caller-controlled absolute cache path."""
    if pm == "npm":
        return f'npm_config_cache="{cache_in_box}" npm ci --offline --no-audit --no-fund'
    if pm == "yarn":
        return f'yarn install --offline --frozen-lockfile --cache-folder "{cache_in_box}"'
    if pm == "pnpm":
        return f'pnpm install --offline --frozen-lockfile --store-dir "{cache_in_box}"'
    return ""



def detect_build_plan(repo: str) -> BuildPlan:
    """Best-effort (build_cmd, test_cmd, install_specs) for ``repo``. The dependency-free ``build_cmd`` is the
    always-runnable floor; ``test_cmd``/``install_specs`` describe the REAL suite the caller runs only once
    deps are resolved (offline cache or gated network). TOTAL: ``repo`` is attacker-influenced (the codebase
    being remediated), so ANY failure — unreadable repo, hostile package.json, or a pathological directory
    tree that crashes ``os.walk`` (RecursionError on Python < 3.13) — degrades to a floor/empty plan, never a
    raise. The walk helpers self-degrade to "not found"; this outer guard is the belt for anything else."""
    try:
        return _detect_build_plan_inner(repo)
    except Exception:  # noqa: BLE001 — detection over an attacker-influenced repo must never crash the fix ladder
        return BuildPlan(note="build-system detection failed on a hostile repo; build/test axis skipped")


def _detect_build_plan_inner(repo: str) -> BuildPlan:
    try:
        if not repo or "://" in repo or not os.path.isdir(repo):
            return BuildPlan(note="no local repo to analyze")
    except OSError:
        return BuildPlan(note="repo not readable")

    # ---- Python ----
    if _has(repo, "pyproject.toml", "setup.py", "setup.cfg", "tox.ini", "pytest.ini") or _any_ext(repo, ".py"):
        build_cmd = "python3 -m compileall -q ."   # dependency-free floor
        if _has_tests(repo):
            specs, deps = _py_install_specs(repo)
            return BuildPlan(
                build_cmd=build_cmd, test_cmd="python -m pytest -q", install_specs=specs,
                deps_files=deps, needs_network=True, language="python",
                note="python: compileall floor + REAL pytest suite (needs deps from an offline cache or a gated install)")
        return BuildPlan(build_cmd=build_cmd, test_cmd="", language="python",
                         note="python: byte-compile gate (compileall); no test suite detected")

    # ---- JavaScript/TypeScript (Wave D: real jest/vitest/mocha suite + node --check floor) ----
    if _has(repo, "package.json") or _any_ext(repo, ".js") or _any_ext(repo, ".ts"):
        floor = "find . -path ./node_modules -prune -o -name '*.js' -print0 | xargs -0 -r -n1 node --check"
        pm = _js_pkg_manager(repo)
        test_cmd = _js_test_cmd(repo, pm) if pm else ""
        if test_cmd:
            lock = next((lk for lk, m in _JS_LOCKS if _has(repo, lk)), "")
            return BuildPlan(
                build_cmd=floor, test_cmd=test_cmd, install_specs=(lock,) if lock else (),
                deps_files=(lock,) if lock else (), needs_network=True, language="javascript", pkg_manager=pm,
                note=f"javascript: node --check floor + REAL {pm} suite ({test_cmd}) "
                     "(needs node_modules from an offline cache/store or a gated install)")
        return BuildPlan(
            build_cmd=floor, test_cmd="", language="javascript",
            note="javascript: node --check syntax gate; no runnable test suite detected "
                 "(no lockfile, or no scripts.test / jest|vitest|mocha)")

    # ---- Go (later wave) ----
    if _has(repo, "go.mod"):
        return BuildPlan(build_cmd="", test_cmd="", language="go",
                         note="go: build/test skipped (needs the module cache; a later wave)")

    return BuildPlan(note="no known build system detected — build/test axis skipped (apply-check only)")


def _validated_specs(install_specs: tuple[str, ...]) -> tuple[str, ...]:
    """Keep only install tokens that are safe to place in a shell command: pip flags (start with '-'), the
    editable dot, or a simple basename/package spec. Drops anything with shell metacharacters (defence in
    depth — detect_build_plan already only emits fixed literals + _SAFE_NAME basenames)."""
    ok: list[str] = []
    for tok in install_specs:
        t = str(tok)
        if t in ("-r", "-e", "."):
            ok.append(t)
        elif t.startswith("-") and _SAFE_NAME.match(t.lstrip("-")):
            ok.append(t)
        elif _SAFE_NAME.match(t):
            ok.append(t)
    return tuple(ok)


def compose_offline_test_command(plan: BuildPlan, *, cache_dir_in_box: str) -> str:
    """The `/bin/sh -c` string that, inside the sandbox with ``cache_dir_in_box`` mounted read-only, creates a
    venv, installs the repo's deps OFFLINE from the wheelhouse/cache (``--no-index --find-links``), and runs
    the REAL test suite from that venv. Returns "" when the plan has no real suite. Injection-free: only the
    validated specs + the (caller-controlled, absolute) cache path are interpolated."""
    if not plan.test_cmd:
        return ""
    if not (cache_dir_in_box or "").startswith("/"):
        return ""

    if plan.language == "javascript":
        # offline, frozen install from the mounted npm/yarn/pnpm cache, then the detected runner. The install
        # + runner are FIXED literals (PM + runner from closed allowlists); only the absolute cache path and
        # the (allowlisted) test_cmd are interpolated.
        install = _js_offline_install(plan.pkg_manager, cache_dir_in_box)
        if not install or plan.test_cmd not in _JS_TEST_CMDS:   # only an allowlisted runner is interpolated
            return ""
        return f"set -e; {install}; {plan.test_cmd}"

    if plan.language != "python" or not plan.install_specs:
        return ""
    specs = _validated_specs(plan.install_specs)
    if not specs:
        return ""
    specs_str = " ".join(specs)
    # venv (offline via bundled ensurepip) → offline pip install from the wheelhouse → real pytest from the venv
    return (
        "set -e; python3 -m venv .venv; "
        f'.venv/bin/python -m pip install --no-index --find-links="{cache_dir_in_box}" {specs_str}; '
        ".venv/bin/python -m pytest -q"
    )
