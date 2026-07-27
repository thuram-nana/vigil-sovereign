"""Phase B2 — on-demand tool install (tools/install.py). Fully mocked: no real package is ever installed.

Proves: only a B1-ADMITTED tool installs; an unknown/refused/already-installed tool is handled honestly;
without consent nothing runs (the ask-operator path returns the exact command); the DECLARED apt/pip
package is used as a SINGLE list-argv element (no shell → no command injection); the result reflects a live
re-probe (honest, not a claim).
"""
from __future__ import annotations

from framework.v2.tools import install as I


def _prof(**kw):
    base = {"name": "nmap", "admitted": True, "installed": False, "apt": "nmap", "pip": "",
            "install_hint": "sudo apt-get install -y nmap", "admit_reason": "admitted (cli)", "status": "missing"}
    base.update(kw)
    return base


def _fake_runner():
    calls = []
    def run(argv):
        calls.append(argv)
        return 0, "ok"
    return run, calls


def test_unknown_tool_is_refused(monkeypatch):
    monkeypatch.setattr(I, "_profile", lambda n: None)
    run, calls = _fake_runner()
    out = I.install_tool("totally-made-up", consent=True, runner=run)
    assert out["ok"] is False and "unknown tool" in out["error"] and not calls


def test_non_admitted_tool_is_never_installed(monkeypatch):
    monkeypatch.setattr(I, "_profile", lambda n: _prof(admitted=False, admit_reason="refused: not recognised"))
    run, calls = _fake_runner()
    out = I.install_tool("nmap", consent=True, runner=run)
    assert out["ok"] is False and "refused" in out["error"] and not calls   # gate honored, nothing ran


def test_already_installed_is_a_noop(monkeypatch):
    monkeypatch.setattr(I, "_profile", lambda n: _prof(installed=True, status="installed"))
    run, calls = _fake_runner()
    out = I.install_tool("nmap", consent=True, runner=run)
    assert out["ok"] is True and out.get("already_installed") and not calls


def test_without_consent_it_asks_and_runs_nothing(monkeypatch):
    monkeypatch.setattr(I, "_apt_usable", lambda: True)
    monkeypatch.setattr(I, "_profile", lambda n: _prof())
    run, calls = _fake_runner()
    out = I.install_tool("nmap", consent=False, runner=run)
    assert out["needs_consent"] is True and out["ok"] is False and not calls
    assert "apt-get" in out["command"] and "nmap" in out["command"]        # surfaces the exact command


def test_declared_package_is_a_single_argv_element_no_shell_injection(monkeypatch):
    # a (hypothetical) malicious declared package must stay ONE argv token — list form, never a shell string
    monkeypatch.setattr(I, "_apt_usable", lambda: True)
    argv, method = I._plan_argv(_prof(apt="evil; rm -rf / #", pip=""))
    assert method == "apt" and isinstance(argv, list)
    assert argv[-1] == "evil; rm -rf / #"          # the whole thing is one package token, not split/executed
    assert "apt-get" in argv and "install" in argv


def test_pip_tool_installs_via_declared_pip_and_reprobes(monkeypatch):
    # first probe: missing+admitted+pip; after the (mocked) install, re-probe reports installed.
    seq = iter([_prof(apt="", pip="semgrep"), _prof(apt="", pip="semgrep", installed=True, status="installed")])
    monkeypatch.setattr(I, "_profile", lambda n: next(seq))
    monkeypatch.setattr(I, "shutil_which_pipx", None, raising=False)
    run, calls = _fake_runner()
    out = I.install_tool("semgrep", consent=True, runner=run)
    assert calls and "semgrep" in calls[0]         # the DECLARED pip package was used
    assert out["ok"] is True and out["installed"] is True and out["status"] == "installed"


def test_honest_failure_when_reprobe_still_missing(monkeypatch):
    # the (mocked) installer "succeeds" (rc0) but the tool is still not on PATH → ok=False, honest error
    monkeypatch.setattr(I, "_profile", lambda n: _prof(apt="", pip="semgrep"))   # never flips to installed
    run, calls = _fake_runner()
    out = I.install_tool("semgrep", consent=True, runner=run)
    assert calls and out["ok"] is False and "did not make" in out["error"]


def test_apt_needing_root_without_sudo_is_refused_honestly(monkeypatch):
    monkeypatch.setattr(I, "_apt_usable", lambda: False)
    monkeypatch.setattr(I, "_profile", lambda n: _prof(apt="nmap", pip=""))     # apt-only, apt not usable
    run, calls = _fake_runner()
    out = I.install_tool("nmap", consent=True, runner=run)
    assert out["ok"] is False and "manually" in out["error"] and not calls
