"""`vigil upgrade` (W5-5, #449) — the offense-side native verb forwards the crash-safe data migration to
the SOVEREIGN `sigil upgrade` in its OWN venv, and NEVER co-loads the sovereign core (FATAL-2).

The real orchestrator (backup -> verify -> migrate -> verify -> report, with rollback) lives in the
sovereign plane (apps/sigil/sigil/spine/upgrade.py, tested in apps/sigil/tests/test_spine_upgrade.py). The
`vigil` super-CLI holds the owner key in a separate process, so it must reach that logic ONLY by EXEC'ing
the sovereign console-script — exactly like `vigil backup`/`restore`. This test pins that forwarding.

FAILS WITHOUT THE FIX: `upgrade` is not a registered `vigil` verb on a pre-W5-5 tree, so argparse rejects
it (SystemExit) instead of forwarding.

Framework-free + sigil-free: imports only `vigil_integration.cli`, whose framework/sigil imports are all
function-local — so this runs in the sovereign leg of the P5 integration job with no boundary breach and
needs no offense-leg registration.

Run: PYTHONPATH=integration python -m pytest integration/tests/test_cli_upgrade_forwards.py -q
"""
import pytest

from vigil_integration import cli


def _capture_dispatch(monkeypatch):
    calls = []
    monkeypatch.setattr("vigil_integration.dispatch.dispatch",
                        lambda verb, argv: calls.append((verb, argv)) or 0)
    return calls


def test_upgrade_forwards_to_sovereign_sigil_upgrade(monkeypatch):
    calls = _capture_dispatch(monkeypatch)
    assert cli.main(["upgrade"]) == 0
    assert calls == [("sigil", ["upgrade"])], "vigil upgrade EXECs the sovereign `sigil upgrade`"


def test_upgrade_passes_check_and_no_backup_through(monkeypatch):
    calls = _capture_dispatch(monkeypatch)
    assert cli.main(["upgrade", "--check"]) == 0
    assert calls[-1] == ("sigil", ["upgrade", "--check"])
    assert cli.main(["upgrade", "--no-backup"]) == 0
    assert calls[-1] == ("sigil", ["upgrade", "--no-backup"])


def test_upgrade_returns_the_sovereign_exit_code(monkeypatch):
    # exit 3 (migration needed under --check) / 2 (refused-or-rolled-back) must propagate to the caller.
    monkeypatch.setattr("vigil_integration.dispatch.dispatch", lambda verb, argv: 3)
    assert cli.main(["upgrade", "--check"]) == 3
    monkeypatch.setattr("vigil_integration.dispatch.dispatch", lambda verb, argv: 2)
    assert cli.main(["upgrade"]) == 2


def test_upgrade_is_a_native_verb_not_a_passthrough(monkeypatch):
    # `upgrade` must be handled by the in-process argparse handler (which then EXECs sigil), NOT routed as a
    # subsystem passthrough verb — so it can shape/validate its own flags.
    from vigil_integration import dispatch as D
    assert "upgrade" not in D.PASSTHROUGH_VERBS


def test_cli_module_import_is_boundary_clean():
    """Importing `vigil_integration.cli` must not pull the sovereign core (`sigil`) or the offense engine
    (`framework`/`strix`) at module load — every such import in the verb handlers is function-local."""
    import subprocess
    import sys
    code = ("import vigil_integration.cli, sys; "
            "bad=[m for m in ('sigil','framework','strix') if m in sys.modules]; "
            "print('LEAK:'+','.join(bad)) if bad else print('CLEAN')")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                         env={"PYTHONPATH": "integration", "PATH": "/usr/bin:/bin"})
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "CLEAN", out.stdout


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
