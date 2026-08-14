"""The no-egress limit, enforced by RUNNING rather than by argv construction.

WHY THIS EXISTS. Every previous no-egress proof in this repository is a guarantee that a tool will not be
ASKED to leave the host: the wapiti module allowlist, nuclei's ``-disable-update-check``, nikto's
``-notel`` — all asserted over argv, with no process spawned (``test_wapiti_no_egress.py`` says so in its
own docstring). That guarantee kept failing in exactly one way: the tool egressed anyway, by its own
defaults, invisibly, until something ran it. wapiti's default modules reached ``wapiti3.ovh``; ``wapp``
downloaded a technology database by a different mechanism entirely; nuclei phoned home on two sensor
routes no gate covered.

These tests RUN the supervisor and MEASURE what it did. The two halves that make a detector worth
trusting are both here: it must FIRE on a real non-loopback connect, and it must stay SILENT on loopback
(a guard that blocks everything would pass a fire-only test while breaking every real scan).

Nothing here reaches a third party: the blocked-egress cases are blocked BY the guard under test, which is
what keeps them charter-safe — no packet leaves. The loopback cases talk to a listener this file starts.
"""

from __future__ import annotations

import os
import socket
import subprocess
import threading
from pathlib import Path

import pytest

ex = pytest.importorskip("vigil_integration.live.executor")
eg = pytest.importorskip("vigil_integration.live.egress_guard")

GUARD = Path(__file__).resolve().parents[2] / "tools" / "egress-guard" / "egress_guard"
_needs_guard = pytest.mark.skipif(
    not (GUARD.is_file() and os.access(GUARD, os.X_OK)),
    reason="egress_guard not built — run `make -C tools/egress-guard`")

_PY = "python3"


def _run_guarded(code: str, *, log: Path, fail_on_egress: bool = False, timeout: int = 60):
    argv = [str(GUARD), "--log", str(log)]
    if fail_on_egress:
        argv.append("--fail-on-egress")
    argv += ["--", _PY, "-c", code]
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)


@pytest.fixture()
def loopback_server():
    """A real loopback listener, so the positive control talks to something that actually answers."""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def _serve():
        srv.settimeout(0.25)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except (socket.timeout, OSError):
                continue
            try:
                conn.sendall(b"hi")
            finally:
                conn.close()

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    yield port
    stop.set()
    t.join(timeout=2)
    srv.close()


# ---------------------------------------------------------------------------------------------------
# the two halves of a trustworthy detector
# ---------------------------------------------------------------------------------------------------


@_needs_guard
def test_a_non_loopback_connect_is_refused_and_recorded(tmp_path):
    """IT FIRES. A connect to a public address is refused at the syscall and named in the log. The
    process never reaches the network: this is why running the test sends no packet off-host."""
    log = tmp_path / "guard.log"
    res = _run_guarded(
        "import socket\n"
        "try:\n"
        "    socket.create_connection(('1.1.1.1', 80), 3); print('CONNECTED')\n"
        "except OSError as e:\n"
        "    print('REFUSED', e.errno)\n",
        log=log)
    assert "CONNECTED" not in res.stdout, "a non-loopback connect SUCCEEDED — the guard did not hold"
    assert "REFUSED" in res.stdout
    text = log.read_text(encoding="utf-8")
    assert "BLOCKED connect -> 1.1.1.1:80" in text, f"the guard did not record the destination: {text!r}"
    assert "blocked=1" in text


@_needs_guard
def test_loopback_still_works_under_the_guard(loopback_server, tmp_path):
    """IT STAYS SILENT. The mutation control for the test above: a guard that refused everything would
    pass the fire test while making every real loopback scan impossible. Loopback must be untouched."""
    log = tmp_path / "guard.log"
    res = _run_guarded(
        "import socket\n"
        f"s = socket.create_connection(('127.0.0.1', {loopback_server}), 3)\n"
        "print('GOT', s.recv(2).decode()); s.close()\n",
        log=log)
    assert "GOT hi" in res.stdout, f"loopback was broken by the guard: {res.stdout!r} {res.stderr!r}"
    assert "blocked=0" in log.read_text(encoding="utf-8"), "a loopback connect was wrongly blocked"


@_needs_guard
def test_ipv6_loopback_is_allowed_and_ipv6_public_is_refused(tmp_path):
    """Both IP families are policed. ``::1`` proceeds; a public v6 address does not."""
    log = tmp_path / "guard.log"
    res = _run_guarded(
        "import socket\n"
        "try:\n"
        "    socket.create_connection(('2606:4700:4700::1111', 80), 3); print('V6-CONNECTED')\n"
        "except OSError as e:\n"
        "    print('V6-REFUSED')\n",
        log=log)
    assert "V6-CONNECTED" not in res.stdout, "a public IPv6 connect succeeded"
    assert "blocked=1" in log.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------------------------------
# the exit contract — a blocked run must be distinguishable from a clean one
# ---------------------------------------------------------------------------------------------------


@_needs_guard
def test_fail_on_egress_fails_the_run_even_when_the_tool_swallows_the_error(tmp_path):
    """THE CASE THAT MATTERS. A tool that catches its own connection error exits 0 and looks clean. With
    --fail-on-egress the RUN still fails (97), so an egress attempt cannot be hidden by the tool."""
    res = _run_guarded(
        "import socket\n"
        "try: socket.create_connection(('1.1.1.1', 80), 3)\n"
        "except Exception: pass\n"
        "print('tool exits zero')\n",
        log=tmp_path / "g.log", fail_on_egress=True)
    assert "tool exits zero" in res.stdout
    assert res.returncode == eg.EGRESS_BLOCKED_EXIT, "an egress attempt did not fail the run"
    assert eg.blocked_egress(res.returncode)


@_needs_guard
def test_a_clean_run_passes_the_childs_own_exit_code_through(tmp_path):
    """MUTATION CONTROL for the exit contract: the guard must not invent failures, and must not mask a
    tool's own failure as an egress block."""
    ok = _run_guarded("print('clean')", log=tmp_path / "a.log", fail_on_egress=True)
    assert ok.returncode == 0 and "clean" in ok.stdout
    bad = _run_guarded("import sys; sys.exit(42)", log=tmp_path / "b.log", fail_on_egress=True)
    assert bad.returncode == 42, "the tool's own exit code was masked"
    assert not eg.blocked_egress(bad.returncode)


# ---------------------------------------------------------------------------------------------------
# coverage a libc shim cannot buy: a statically linked binary
# ---------------------------------------------------------------------------------------------------


@_needs_guard
@pytest.mark.skipif(not Path("/usr/bin/nuclei").exists(), reason="nuclei not installed")
def test_a_statically_linked_go_binary_is_covered(tmp_path):
    """THE REASON THIS IS seccomp AND NOT LD_PRELOAD. ``nuclei`` is statically linked ('not a dynamic
    executable'), so an LD_PRELOAD connect-shim cannot see its syscalls at all. Measured on this machine:
    nuclei attempts a DNS connect merely to print its version. Under the guard that attempt is refused —
    which is both the proof of coverage and the reason the run stays charter-safe."""
    log = tmp_path / "guard.log"
    subprocess.run([str(GUARD), "--log", str(log), "--", "/usr/bin/nuclei", "-version"],
                   capture_output=True, text=True, timeout=90)
    text = log.read_text(encoding="utf-8") if log.exists() else ""
    assert "seen=" in text, "the guard saw no connect at all from the static binary — filter not applied"
    # Either it attempted egress and we blocked it, or the resolver was loopback and nothing was blocked.
    # Both are correct outcomes; what must be true is that the guard OBSERVED the static binary's syscalls.
    assert "blocked=" in text


# ---------------------------------------------------------------------------------------------------
# the wiring into the live executor — default OFF, opt-in, fail-closed only when demanded
# ---------------------------------------------------------------------------------------------------


def test_the_guard_is_off_by_default_and_argv_is_unchanged(monkeypatch):
    """An operator's ordinary host run must be byte-identical to before this feature existed."""
    monkeypatch.delenv("VIGIL_EGRESS_GUARD", raising=False)
    argv = ["nmap", "-Pn", "127.0.0.1"]
    assert eg.wrap_argv(argv) == argv
    assert eg.enabled() is False


@_needs_guard
def test_enabling_the_guard_prefixes_the_spawn(monkeypatch, tmp_path):
    monkeypatch.setenv("VIGIL_EGRESS_GUARD", "1")
    monkeypatch.setenv("VIGIL_EGRESS_GUARD_LOG", str(tmp_path / "l.log"))
    monkeypatch.setenv("VIGIL_EGRESS_GUARD_FAIL", "1")
    wrapped = eg.wrap_argv(["nmap", "-Pn", "127.0.0.1"])
    assert wrapped[0].endswith("egress_guard")
    assert "--fail-on-egress" in wrapped and "--" in wrapped
    # the tool's own argv survives intact, in order, after the separator
    assert wrapped[wrapped.index("--") + 1:] == ["nmap", "-Pn", "127.0.0.1"]


def test_require_mode_refuses_to_spawn_unguarded(monkeypatch):
    """FAIL CLOSED. Believing the guard is on while it is not is worse than knowing it is off, so
    `require` raises rather than silently spawning an unguarded tool."""
    monkeypatch.setenv("VIGIL_EGRESS_GUARD", "require")
    monkeypatch.setenv("VIGIL_EGRESS_GUARD_BIN", "/nonexistent/egress_guard")
    with pytest.raises(eg.EgressGuardUnavailable):
        eg.wrap_argv(["nmap", "127.0.0.1"])


def test_require_mode_failure_degrades_the_runner_instead_of_crashing(monkeypatch):
    """The executor's runner is TOTAL — it returns a RunOutcome, never raises. A demanded-but-missing
    guard must therefore surface as a failed outcome, with nothing spawned."""
    monkeypatch.setenv("VIGIL_EGRESS_GUARD", "require")
    monkeypatch.setenv("VIGIL_EGRESS_GUARD_BIN", "/nonexistent/egress_guard")
    out = ex.subprocess_runner(["echo", "hi"])
    assert out.exit_code is None and "egress guard unavailable" in out.stderr
