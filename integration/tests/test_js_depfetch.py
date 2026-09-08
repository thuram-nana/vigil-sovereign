"""Wave D — the GATED npm/yarn/pnpm fetch that fills the JS/TS deep-fix dep cache. KEY properties: the
network is only this host-side, egress-guarded install; the fix/test bwrap box is never given egress; the
fetch runs SCRIPT-DISABLED (--ignore-scripts, no supply-chain RCE) in a TEMP dir (the operator's repo is
never polluted). Framework-free (js_depfetch imports only egress_guard) → both CI legs."""
from __future__ import annotations

import os
import subprocess

from vigil_integration.remediation.js_depfetch import fetch_js_deps, FetchResult, _fetch_argv
from vigil_integration.live import egress_guard


def _jsrepo(tmp_path, *, lock="package-lock.json", name="r"):
    r = tmp_path / name; r.mkdir()
    (r / "package.json").write_text('{"name":"x","version":"0.0.0"}', encoding="utf-8")
    if lock:
        (r / lock).write_text("{}\n" if lock.endswith(".json") else "# lock\n", encoding="utf-8")
    return r


def test_fetch_argv_is_script_disabled_per_pm():
    for pm, needle in (("npm", "ci"), ("yarn", "install"), ("pnpm", "install")):
        argv = _fetch_argv(pm, "/cache")
        assert argv and "--ignore-scripts" in argv and needle in argv and "/cache" in argv
    assert _fetch_argv("bower", "/c") is None


def test_fetch_ok_runs_script_disabled_in_temp_not_repo(tmp_path, monkeypatch):
    monkeypatch.delenv("VIGIL_EGRESS_GUARD", raising=False)   # guard off ⇒ wrap_argv returns argv unchanged
    repo = _jsrepo(tmp_path); cache = tmp_path / "c"
    seen = {}

    def fake_run(argv, cwd, stdin, capture_output, text, timeout):
        seen["argv"] = argv; seen["cwd"] = cwd
        # the fetch dir must hold ONLY the copied manifest + lockfile (never node_modules in the repo)
        seen["staged"] = sorted(os.listdir(cwd))
        cache.mkdir(parents=True, exist_ok=True)
        (cache / "content").mkdir()
        (cache / "content" / "abc.tgz").write_bytes(b"x")
        return subprocess.CompletedProcess(argv, 0, "", "")

    fr = fetch_js_deps(str(repo), str(cache), pkg_manager="npm", runner=fake_run)
    assert fr.ok and fr.count == 1 and fr.cache_dir == str(cache)
    assert "--ignore-scripts" in seen["argv"] and "ci" in seen["argv"]
    assert seen["cwd"] != str(repo)                                   # ran in a TEMP dir, not the repo
    assert seen["staged"] == ["package-lock.json", "package.json"]    # only manifest + lockfile staged
    assert not (repo / "node_modules").exists()                       # operator's repo untouched


def test_fetch_requires_a_lockfile(tmp_path, monkeypatch):
    monkeypatch.delenv("VIGIL_EGRESS_GUARD", raising=False)
    repo = _jsrepo(tmp_path, lock=None)
    calls = []
    fr = fetch_js_deps(str(repo), str(tmp_path / "c"), pkg_manager="npm",
                       runner=lambda *a, **k: calls.append(a) or subprocess.CompletedProcess([], 0, "", ""))
    assert not fr.ok and "lockfile" in fr.note and not calls          # no reproducible fetch without a lock


def test_yarn_and_pnpm_lockfiles(tmp_path, monkeypatch):
    monkeypatch.delenv("VIGIL_EGRESS_GUARD", raising=False)
    def ok_run(cache):
        def _r(argv, **kw):
            os.makedirs(cache, exist_ok=True); open(os.path.join(cache, "a"), "w").close()
            return subprocess.CompletedProcess(argv, 0, "", "")
        return _r
    for pm, lock in (("yarn", "yarn.lock"), ("pnpm", "pnpm-lock.yaml")):
        repo = _jsrepo(tmp_path, lock=lock, name=pm); cache = tmp_path / ("c" + pm)
        fr = fetch_js_deps(str(repo), str(cache), pkg_manager=pm, runner=ok_run(str(cache)))
        assert fr.ok, (pm, fr.note)


def test_fetch_degrades_when_pm_fails(tmp_path, monkeypatch):
    monkeypatch.delenv("VIGIL_EGRESS_GUARD", raising=False)
    repo = _jsrepo(tmp_path)
    fr = fetch_js_deps(str(repo), str(tmp_path / "c"), pkg_manager="npm",
                       runner=lambda argv, **k: subprocess.CompletedProcess(argv, 1, "", "ETARGET no such version"))
    assert not fr.ok and "exit 1" in fr.note


def test_fetch_reports_guard_block(tmp_path, monkeypatch):
    monkeypatch.delenv("VIGIL_EGRESS_GUARD", raising=False)
    repo = _jsrepo(tmp_path)
    fr = fetch_js_deps(str(repo), str(tmp_path / "c"), pkg_manager="npm",
                       runner=lambda argv, **k: subprocess.CompletedProcess(argv, egress_guard.EGRESS_BLOCKED_EXIT, "", "blk"))
    assert not fr.ok and "BLOCKED" in fr.note


def test_fetch_fails_closed_when_guard_required_but_absent(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_EGRESS_GUARD", "require")
    monkeypatch.setenv("VIGIL_EGRESS_GUARD_BIN", str(tmp_path / "no-such-guard"))
    repo = _jsrepo(tmp_path); calls = []
    fr = fetch_js_deps(str(repo), str(tmp_path / "c"), pkg_manager="npm",
                       runner=lambda argv, **k: calls.append(argv) or subprocess.CompletedProcess(argv, 0, "", ""))
    assert not fr.ok and "unavailable" in fr.note.lower() and not calls   # never spawned the install


def test_fetch_unknown_pm_and_no_repo_are_honest(tmp_path):
    assert not fetch_js_deps(str(_jsrepo(tmp_path)), str(tmp_path / "c"), pkg_manager="bower").ok
    fr = fetch_js_deps("", "/tmp/x", pkg_manager="npm")
    assert isinstance(fr, FetchResult) and not fr.ok
