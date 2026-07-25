"""S1 — the `vigil` super-CLI dispatcher routes each subsystem verb to its OWN environment's console-script
and NEVER co-loads the two trust domains.

Proves: sovereign verbs resolve into `.venv-sovereign`, offense verbs into `.venv-offense` (by a fixed
table, so no offense verb can reach the sovereign venv or vice-versa); the dispatcher module imports no
`framework`/`strix`/`sigil` (a fresh interpreter check); `dispatch` forwards argv + returns the child's
exit code, and fails clean when a venv is missing; and `cli.main` forwards passthrough verbs to `dispatch`
while native verbs bypass it.

Run: PYTHONPATH=integration python -m pytest integration/tests/test_dispatch_routing.py -q
"""
import subprocess
import sys

import pytest

from vigil_integration import dispatch as D


def test_verb_environment_table_is_correct():
    # sovereign verb → sovereign venv; every offense verb → offense venv. This is the whole boundary point.
    assert D._ENV["sigil"][0] == "sovereign"
    for verb in ("crucible", "aegis", "strix", "gateway"):
        assert D._ENV[verb][0] == "offense", f"{verb} must route to the offense venv"
    assert D.PASSTHROUGH_VERBS == {"sigil", "crucible", "aegis", "strix", "gateway"}


def test_resolve_routes_to_the_fixed_venv_path(monkeypatch, tmp_path):
    monkeypatch.setenv("VIGIL_ROOT", str(tmp_path))
    assert D.resolve("sigil") == tmp_path / ".venv-sovereign" / "bin" / "sigil"
    assert D.resolve("crucible") == tmp_path / ".venv-offense" / "bin" / "crucible"
    assert D.resolve("gateway") == tmp_path / ".venv-offense" / "bin" / "vigil-gateway"
    # NO offense verb ever resolves under the sovereign venv, and sigil never under the offense venv.
    assert ".venv-sovereign" not in str(D.resolve("crucible"))
    assert ".venv-offense" not in str(D.resolve("sigil"))


def test_dispatcher_module_imports_no_subsystem():
    """A fresh interpreter importing the dispatcher must pull NEITHER framework/strix NOR sigil — the module
    is pure-stdlib + exec-only, so `vigil sigil …` from the offense venv never co-loads the sovereign core."""
    code = ("import vigil_integration.dispatch, sys; "
            "bad = [m for m in ('framework','strix','sigil') if m in sys.modules]; "
            "print('LEAK:'+','.join(bad)) if bad else print('CLEAN')")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                         env={"PYTHONPATH": "integration", "PATH": "/usr/bin:/bin"})
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "CLEAN", out.stdout


def test_dispatch_missing_venv_fails_clean(monkeypatch, tmp_path):
    monkeypatch.setenv("VIGIL_ROOT", str(tmp_path))          # no venvs built under it
    assert D.dispatch("sigil", ["status"]) == 127


def test_dispatch_forwards_argv_and_returns_child_code(monkeypatch, tmp_path):
    script = tmp_path / ".venv-sovereign" / "bin" / "sigil"
    script.parent.mkdir(parents=True)
    script.write_text("#!/bin/sh\n")
    monkeypatch.setenv("VIGIL_ROOT", str(tmp_path))
    seen = {}

    class _Done:
        returncode = 42

    def _fake_run(cmd, *a, **k):
        seen["cmd"] = cmd
        seen["env"] = k.get("env")
        return _Done()

    monkeypatch.setenv("PYTHONPATH", "engine/crucible:integration")   # a cross-domain path from the parent
    monkeypatch.setenv("PYTHONHOME", "/some/home")
    monkeypatch.setattr(subprocess, "run", _fake_run)
    rc = D.dispatch("sigil", ["status", "--json"])
    assert rc == 42
    assert seen["cmd"] == [str(script), "status", "--json"], "forwards the exact script path + argv"
    # boundary: the cross-venv child must NOT inherit a PYTHONPATH/PYTHONHOME that could inject or misdirect
    # the other trust domain.
    assert "PYTHONPATH" not in (seen["env"] or {}) and "PYTHONHOME" not in (seen["env"] or {}), \
        "PYTHONPATH + PYTHONHOME are scrubbed for the cross-venv child"


def test_dispatch_corrupt_venv_fails_clean(monkeypatch, tmp_path):
    """A present console-script whose shebang interpreter is missing (a half-built venv) fails CLEAN +
    non-zero — never a raw traceback out of the dispatcher."""
    script = tmp_path / ".venv-sovereign" / "bin" / "sigil"
    script.parent.mkdir(parents=True)
    script.write_text("#!/nonexistent/python-xyz\necho hi\n")
    script.chmod(0o755)
    monkeypatch.setenv("VIGIL_ROOT", str(tmp_path))
    assert D.dispatch("sigil", ["status"]) == 127   # OSError caught → clean 127, no exception escapes


def test_main_forwards_passthrough_verbs_and_bypasses_for_native(monkeypatch):
    from vigil_integration import cli
    calls = []
    monkeypatch.setattr("vigil_integration.dispatch.dispatch", lambda verb, argv: calls.append((verb, argv)) or 7)
    assert cli.main(["sigil", "status", "--k"]) == 7
    assert calls == [("sigil", ["status", "--k"])]
    # a native verb must NOT go through dispatch (it uses the in-process argparse handlers).
    calls.clear()
    with pytest.raises(SystemExit):
        cli.main(["not-a-verb"])                              # argparse rejects → SystemExit (not dispatched)
    assert calls == [], "native/unknown verbs never reach the passthrough dispatcher"
