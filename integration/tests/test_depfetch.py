"""PCR / W1b — the GATED wheel-fetch that fills the deep-fix dep cache. The KEY property: the network is only
this host-side, egress-guarded `pip download`; the fix/test bwrap box is never given egress. Framework-free
(depfetch imports buildsys + egress_guard, both framework-free) → both CI legs."""
from __future__ import annotations

import subprocess
import types

from vigil_integration.remediation.depfetch import fetch_deps, _download_specs, FetchResult
from vigil_integration.live import egress_guard


def test_download_specs_drops_editable_keeps_project_and_reqs():
    assert _download_specs(("-r", "requirements.txt", "-e", ".", "pytest")) == ["-r", "requirements.txt", ".", "pytest"]


def _repo(tmp_path):
    r = tmp_path / "r"; r.mkdir()
    (r / "requirements.txt").write_text("requests\n", encoding="utf-8")
    return r


def test_fetch_ok_populates_cache(tmp_path, monkeypatch):
    monkeypatch.delenv("VIGIL_EGRESS_GUARD", raising=False)   # guard off ⇒ wrap_argv returns argv unchanged
    repo = _repo(tmp_path); cache = tmp_path / "c"
    seen = {}

    def fake_run(argv, cwd, stdin, capture_output, text, timeout):
        seen["argv"] = argv; seen["cwd"] = cwd
        (cache).mkdir(parents=True, exist_ok=True)
        (cache / "requests-1.0-py3-none-any.whl").write_bytes(b"x")
        return subprocess.CompletedProcess(argv, 0, "", "")

    fr = fetch_deps(str(repo), str(cache), install_specs=("-r", "requirements.txt", "-e", ".", "pytest"),
                    runner=fake_run)
    assert fr.ok and fr.count == 1 and fr.cache_dir == str(cache)
    assert seen["cwd"] == str(repo)                       # -r resolves in the repo
    assert "-e" not in seen["argv"] and "download" in seen["argv"] and "." in seen["argv"]


def test_fetch_degrades_when_pip_fails(tmp_path, monkeypatch):
    monkeypatch.delenv("VIGIL_EGRESS_GUARD", raising=False)
    repo = _repo(tmp_path)
    def fake_run(argv, **kw):
        return subprocess.CompletedProcess(argv, 1, "", "Could not find a version")
    fr = fetch_deps(str(repo), str(tmp_path / "c"), install_specs=("-r", "requirements.txt"), runner=fake_run)
    assert not fr.ok and "exit 1" in fr.note


def test_fetch_reports_guard_block(tmp_path, monkeypatch):
    monkeypatch.delenv("VIGIL_EGRESS_GUARD", raising=False)
    repo = _repo(tmp_path)
    def fake_run(argv, **kw):
        return subprocess.CompletedProcess(argv, egress_guard.EGRESS_BLOCKED_EXIT, "", "blocked")
    fr = fetch_deps(str(repo), str(tmp_path / "c"), install_specs=("pytest",), runner=fake_run)
    assert not fr.ok and "BLOCKED" in fr.note


def test_fetch_fails_closed_when_guard_required_but_absent(tmp_path, monkeypatch):
    # VIGIL_EGRESS_GUARD=require + no guard binary ⇒ wrap_argv raises ⇒ fetch REFUSES (never an unguarded download)
    monkeypatch.setenv("VIGIL_EGRESS_GUARD", "require")
    monkeypatch.setenv("VIGIL_EGRESS_GUARD_BIN", str(tmp_path / "no-such-guard"))
    repo = _repo(tmp_path)
    calls = []
    def fake_run(argv, **kw):
        calls.append(argv); return subprocess.CompletedProcess(argv, 0, "", "")
    fr = fetch_deps(str(repo), str(tmp_path / "c"), install_specs=("pytest",), runner=fake_run)
    assert not fr.ok and "unavailable" in fr.note.lower() and not calls   # never spawned the download


def test_fetch_no_repo_is_honest():
    fr = fetch_deps("", "/tmp/x", install_specs=("pytest",))
    assert isinstance(fr, FetchResult) and not fr.ok
