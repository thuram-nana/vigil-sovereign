"""The network-isolated, workspace-confined exec sandbox (VIGIL write/exec tier).

The load-bearing property: an ARBITRARY command runs, but the two floors hold by KERNEL isolation —
NO egress (network namespace unshared) and NO write outside the bound workspace (host root read-only).
Fail-closed: no bwrap ⇒ refuse (never an un-sandboxed fallback). Framework-free (stdlib only) → both CI jobs.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from vigil_integration.live.sandbox_exec import (
    SandboxUnavailable,
    build_bwrap_argv,
    bwrap_path,
    run_sandboxed,
)


def _bwrap_works() -> bool:
    """bwrap is not just on PATH but can actually construct its namespaces here (unprivileged userns may be
    disabled in some sandboxes/CI) — otherwise the real-isolation tests skip rather than false-fail."""
    b = bwrap_path()
    if not b:
        return False
    try:
        p = subprocess.run([b, "--unshare-all", "--die-with-parent", "--ro-bind", "/", "/", "--", "/bin/true"],
                           stdin=subprocess.DEVNULL, capture_output=True, timeout=15)
        return p.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


_SANDBOX_OK = _bwrap_works()
_needs_bwrap = pytest.mark.skipif(not _SANDBOX_OK, reason="bwrap cannot construct namespaces in this environment")


# --- the two floors, proven by running REAL bwrap ---------------------------------------------------

@_needs_bwrap
def test_write_is_confined_to_the_workspace(tmp_path):
    ws = tmp_path / "ws"; ws.mkdir()
    out = run_sandboxed("echo hello-sandbox > out.txt && cat out.txt", workspace=ws, timeout=20)
    assert out.exit_code == 0 and "hello-sandbox" in out.stdout
    assert (ws / "out.txt").read_text().strip() == "hello-sandbox"     # the write landed in the workspace


@_needs_bwrap
def test_write_outside_the_workspace_is_refused(tmp_path):
    # Target a genuinely READ-ONLY host path (/etc is ro-bind). (A path under /tmp would hit the ephemeral
    # --tmpfs /tmp — writable but vanishing, never touching the host — which is a DIFFERENT property.)
    ws = tmp_path / "ws"; ws.mkdir()
    probe = "/etc/vigil-sandbox-escape-probe-DELETEME"
    out = run_sandboxed(f"echo x > {probe} 2>&1 || echo REFUSED", workspace=ws, timeout=20)
    assert not Path(probe).exists()                                     # the host's read-only /etc is untouched
    assert "REFUSED" in out.stdout or "read-only" in (out.stdout + out.stderr).lower()


@_needs_bwrap
def test_no_network_egress_from_inside(tmp_path):
    ws = tmp_path / "ws"; ws.mkdir()
    # connect to a raw IP (no DNS needed) — the unshared net namespace has no route, so it must fail. A
    # heredoc feeds the multi-line script to python via the INNER shell's stdin (real newlines, no escaping).
    prog = ("python3 - <<'PYEOF'\n"
            "import socket\n"
            "try:\n"
            "    socket.create_connection(('1.1.1.1', 80), 2); print('CONNECTED')\n"
            "except Exception as e:\n"
            "    print('NO-NETWORK', type(e).__name__)\n"
            "PYEOF\n")
    out = run_sandboxed(prog, workspace=ws, timeout=20)
    assert "CONNECTED" not in out.stdout                                # egress is impossible by construction
    assert "NO-NETWORK" in out.stdout


@_needs_bwrap
def test_arbitrary_shell_composition_works_inside(tmp_path):
    # the whole point of the tier: a full shell (pipes, redirects, subshells) works — safely, because isolated.
    ws = tmp_path / "ws"; ws.mkdir()
    out = run_sandboxed("for i in 1 2 3; do echo $i; done | tac | tr '\\n' ',' > r.txt; cat r.txt", workspace=ws)
    assert out.exit_code == 0 and out.stdout.strip() == "3,2,1,"


# --- fail-closed + argv shape (no bwrap needed) -----------------------------------------------------

def test_empty_command_refused(tmp_path):
    ws = tmp_path / "ws"; ws.mkdir()
    with pytest.raises(ValueError):
        run_sandboxed("   ", workspace=ws)


def test_unsafe_workspace_refused(tmp_path):
    with pytest.raises(ValueError):
        run_sandboxed("echo x", workspace=tmp_path / "does-not-exist")
    # a symlinked workspace is refused (an attacker must not be able to repoint the writable bind)
    real = tmp_path / "real"; real.mkdir()
    link = tmp_path / "link"; link.symlink_to(real)
    with pytest.raises(ValueError):
        run_sandboxed("echo x", workspace=link)


def test_fail_closed_without_bwrap(tmp_path, monkeypatch):
    ws = tmp_path / "ws"; ws.mkdir()
    monkeypatch.setattr("vigil_integration.live.sandbox_exec.bwrap_path", lambda: None)
    with pytest.raises(SandboxUnavailable):                             # NO un-sandboxed fallback
        run_sandboxed("echo x", workspace=ws)


def test_argv_shape_enforces_the_floors():
    ws = Path("/tmp/ws-xyz")
    argv = build_bwrap_argv("id; whoami", ws, bwrap="/usr/bin/bwrap")
    assert argv[0] == "/usr/bin/bwrap"
    assert "--unshare-all" in argv                                     # net (+ pid/ipc/…) unshared
    assert "--new-session" in argv                                     # blocks TIOCSTI stdin injection
    # host root mounted read-only; the ONLY writable bind is the workspace
    j = " ".join(argv)
    assert "--ro-bind / /" in j and f"--bind {ws} {ws}" in j and f"--chdir {ws}" in j
    # the command is the LAST element after `-- /bin/sh -c`, so it cannot inject into bwrap's own options
    assert argv[-3:] == ["/bin/sh", "-c", "id; whoami"] and "--" in argv


def test_injected_runner_receives_the_bwrap_argv(tmp_path):
    ws = tmp_path / "ws"; ws.mkdir()
    seen = {}

    def fake(argv, *, timeout, output_cap):
        seen["argv"] = argv
        from vigil_integration.live.sandbox_exec import SandboxOutcome
        return SandboxOutcome(exit_code=0, stdout="", stderr="")

    run_sandboxed("echo hi", workspace=ws, run=fake)
    assert seen["argv"][0].endswith("bwrap") and seen["argv"][-1] == "echo hi"
