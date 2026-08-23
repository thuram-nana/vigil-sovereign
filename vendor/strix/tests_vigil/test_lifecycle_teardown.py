"""VIGIL S10 — signal-path lifecycle teardown.

Before S10 a signalled Strix run (SIGINT/SIGTERM/SIGHUP) tore down only its REPORT STATE and left the
detached sandbox CONTAINER running with nothing to reap it until the next launch. These assert the two
closures of that gap:

  * ``session_manager.kill_run_sync`` — a SYNCHRONOUS container teardown a signal handler can call
    (it cannot ``await`` the event loop it is interrupting): remove by SDK session label, else fall
    back to this process's own owner-pid label, then drop the cached session.
  * ``cli._signal_teardown`` — the handler now tears down BOTH the report state AND the container, and
    does so robustly (one leg failing still runs the other).

The container-removal PRIMITIVES are covered SDK-free in ``test_sandbox_hardening.py``; this file
exercises the session-cache orchestration + the handler, which import the Agents SDK, so it
``importorskip``s it and skips cleanly where the SDK is absent (the strix-vigil CI job installs it).
"""
from __future__ import annotations

import os

import pytest

pytest.importorskip("agents.sandbox.entries")  # session_manager / cli import the SDK at module load
# session_manager also pulls the full strix runtime dep chain (strix.config.settings -> pydantic-settings,
# runtime.backends -> docker). The SDK-only P8 CI job installs `agents`+litellm but NOT those, so import via
# importorskip: RUN where the full strix runtime is present, SKIP cleanly (never ERROR at collection) where a
# transitive dep is absent. The container-removal PRIMITIVES stay covered SDK-free in test_sandbox_hardening.py.
sh = pytest.importorskip("strix.runtime.sandbox_hardening")
session_manager = pytest.importorskip("strix.runtime.session_manager")


# --- duck-typed fake docker client (matches sandbox_hardening's use) -------------------------------

class _FakeContainer:
    def __init__(self, labels, cid):
        self.labels = labels
        self.id = cid
        self.short_id = cid[:12]
        self.removed = False

    def remove(self, force=False):
        assert force is True
        self.removed = True


class _FakeContainers:
    def __init__(self, containers):
        self._all = containers

    def list(self, all=False, filters=None):  # noqa: A002,ARG002 - docker-py signature
        want = (filters or {}).get("label", [])
        if isinstance(want, str):
            want = [want]
        out = []
        for c in self._all:
            matches = True
            for lbl in want:                    # every requested "k=v" must match
                k, _, v = lbl.partition("=")
                if c.labels.get(k) != v:
                    matches = False
                    break
            if matches:
                out.append(c)
        return out


class _FakeDockerClient:
    def __init__(self, containers):
        self.containers = _FakeContainers(containers)
        self.closed = False

    def close(self):
        self.closed = True


class _Inner:
    def __init__(self, session_id):
        self.state = type("S", (), {"session_id": session_id})()


class _FakeSession:
    def __init__(self, session_id):
        self._inner = _Inner(session_id)


class _FakeSdkClient:
    def __init__(self, docker_client):
        self.docker_client = docker_client


class _Sid:
    def __init__(self, hexs):
        self.hex = hexs


@pytest.fixture(autouse=True)
def _clean_cache():
    session_manager._SESSION_CACHE.clear()
    yield
    session_manager._SESSION_CACHE.clear()


# --- kill_run_sync ------------------------------------------------------------------------------

def test_kill_run_sync_removes_by_session_label_and_drops_the_cache():
    target = _FakeContainer({sh.LABEL_MANAGED: "1", sh.LABEL_SESSION: "abc123"}, "t")
    other = _FakeContainer({sh.LABEL_MANAGED: "1", sh.LABEL_SESSION: "zzz999"}, "o")
    dc = _FakeDockerClient([target, other])
    session_manager._SESSION_CACHE["scan-1"] = {
        "client": _FakeSdkClient(dc), "session": _FakeSession(_Sid("abc123")),
    }
    removed = session_manager.kill_run_sync("scan-1")
    assert removed == 1
    assert target.removed and not other.removed        # the run's own box, not a sibling's
    assert "scan-1" not in session_manager._SESSION_CACHE   # cache dropped -> no dead-handle reuse
    assert dc.closed                                    # docker client closed


def test_kill_run_sync_falls_back_to_owner_pid_when_session_id_is_unreadable(monkeypatch):
    # If the SDK session id cannot be read, the process still owns the box (its pid label). Since the
    # process is alive inside the handler, the plain reaper would SPARE it, so kill_run_sync removes by
    # its own owner-pid label instead. (Session id None -> label removal finds nothing -> fallback.)
    monkeypatch.setattr(sh, "owner_boot_id", lambda: "BOOT-NOW")
    mine = _FakeContainer({sh.LABEL_MANAGED: "1", sh.LABEL_OWNER_PID: str(os.getpid()),
                           sh.LABEL_OWNER_BOOT: "BOOT-NOW"}, "mine")
    dc = _FakeDockerClient([mine])
    session_manager._SESSION_CACHE["scan-2"] = {
        "client": _FakeSdkClient(dc), "session": _FakeSession(None),
    }
    removed = session_manager.kill_run_sync("scan-2")
    assert removed == 1 and mine.removed
    assert dc.closed


def test_kill_run_sync_no_cached_session_is_a_clean_zero():
    # NEGATIVE CONTROL: nothing cached (a run that never created a sandbox, or a double signal) -> 0,
    # no raise, no cache mutation.
    assert session_manager.kill_run_sync("never-started") == 0


def test_kill_run_sync_never_raises_on_a_broken_client():
    # NEGATIVE CONTROL: a broken docker client must not let a teardown exception escape a signal handler.
    class _BoomDocker:
        @property
        def containers(self):
            raise RuntimeError("daemon down")

        def close(self):
            pass
    session_manager._SESSION_CACHE["scan-3"] = {
        "client": _FakeSdkClient(_BoomDocker()), "session": _FakeSession(_Sid("x")),
    }
    assert session_manager.kill_run_sync("scan-3") == 0          # swallowed, not raised
    assert "scan-3" not in session_manager._SESSION_CACHE        # still dropped


# --- cli._signal_teardown -----------------------------------------------------------------------

class _FakeReportState:
    def __init__(self, raises=False):
        self.raises = raises
        self.cleanup_calls = []

    def cleanup(self, status=None):
        self.cleanup_calls.append(status)
        if self.raises:
            raise RuntimeError("report cleanup boom")


def test_signal_teardown_tears_down_both_report_state_and_container(monkeypatch):
    from strix.interface import cli

    killed = []
    monkeypatch.setattr(cli.session_manager, "kill_run_sync", lambda name: killed.append(name) or 1)
    rs = _FakeReportState()
    cli._signal_teardown("run-x", rs)
    assert rs.cleanup_calls == ["interrupted"]          # report state closed as interrupted (pre-existing)
    assert killed == ["run-x"]                           # AND the container is now torn down (the S10 gap)


def test_signal_teardown_still_kills_the_container_if_report_cleanup_raises(monkeypatch):
    # NEGATIVE CONTROL for the ordering/robustness: a signal handler must never let one leg's failure
    # mask the other. Report cleanup raising must NOT prevent the container teardown.
    from strix.interface import cli

    killed = []
    monkeypatch.setattr(cli.session_manager, "kill_run_sync", lambda name: killed.append(name) or 1)
    rs = _FakeReportState(raises=True)
    cli._signal_teardown("run-y", rs)                   # must not raise
    assert killed == ["run-y"]                           # container still reaped despite the report failure


def test_signal_teardown_does_not_raise_if_container_teardown_raises(monkeypatch):
    from strix.interface import cli

    def _boom(_name):
        raise RuntimeError("kill boom")
    monkeypatch.setattr(cli.session_manager, "kill_run_sync", _boom)
    rs = _FakeReportState()
    cli._signal_teardown("run-z", rs)                   # swallowed — a handler must never raise
    assert rs.cleanup_calls == ["interrupted"]
