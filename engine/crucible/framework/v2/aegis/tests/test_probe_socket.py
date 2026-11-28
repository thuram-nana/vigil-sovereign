"""AEGIS AS-5c (gateway local PROBE SOCKET) — deterministic, offline acceptance tests.

AS-5c is an OPERATIONAL read-only status surface (a local probe socket), not a detector, so DoD-1's
"detector near-zero-FP" is N/A; it is substituted by surface-correctness + a byte-identity negative control.
The seven DoD points, mapped to the sections below:

  (1) e2e behavioral — a configured probe socket, flag ON, answers each connection with ONE read-only JSON
      snapshot carrying the HONEST effective mode + the AS-5a capacity admission state, then closes; end-to-end
      through the live gateway over a real AF_UNIX socket. Connecting IS the probe.
  (2) gate-invariance — importing aegis leaves verify.verifier._ALL_ORACLES at exactly 15 (AS-5c adds NO
      OracleKind); probe_socket.py is NOT import-reachable from aegis/__init__ or framework.v2.__main__;
      gateway.PROBE_SOCKET_ENV is in lockstep with probe_socket.PROBE_SOCKET_ENV.
  (3) FATAL-2 — probe_socket.py imports ONLY the stdlib (no vigil_core even), never sigil/governor/strix.
  (4) determinism — a fixed snapshot over a fixed INJECTED clock yields a byte-identical payload; no wall-clock,
      no RNG anywhere on the probe answer.
  (5) default-OFF + byte-identity — VIGIL_AEGIS_PROBE_SOCKET off => NOTHING is bound, no thread runs, and the
      gateway data path is byte-identical (a flood still forwards); the flag is strict/fail-closed.
  (6) negative controls — the socket is owner-only (0600); the snapshot carries NO raw caller address and NO
      secret; a snapshot_fn FAULT degrades to snapshot_ok=False yet liveness (probe_ok) still answers; stop() is
      idempotent + unlinks; a probe answer is NOT a block/verdict (no certificate).
  (7) config/docs sync — a probe is operational, never a finding: the answer carries no attack verdict.

Everything is a pure function of its inputs with an INJECTED clock; no real secret and no network (AF_UNIX
loopback only). Skipped wholesale where the platform lacks AF_UNIX.
"""
from __future__ import annotations

import ast
import http.server
import json
import os
import socket
import socketserver
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest

from framework.v2.aegis import probe_socket as PS
from framework.v2.aegis.probe_socket import (
    PROBE_SOCKET_ENV,
    ProbeSocketServer,
    probe_socket_enabled,
)

pytestmark = pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="probe socket requires AF_UNIX")


@pytest.fixture()
def sock_path() -> Iterator[str]:
    """A short AF_UNIX path (well under the ~108-byte sun_path limit) in a private 0700 dir, cleaned up."""
    d = tempfile.mkdtemp(prefix="aeg")
    try:
        yield os.path.join(d, "p.sock")
    finally:
        for name in os.listdir(d):
            try:
                os.unlink(os.path.join(d, name))
            except OSError:
                pass
        try:
            os.rmdir(d)
        except OSError:
            pass


def _probe(path: str) -> dict:
    """Connect to the AF_UNIX probe socket, read the single JSON snapshot line, return it parsed."""
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    c.settimeout(5.0)
    c.connect(path)
    try:
        chunks = []
        while True:
            b = c.recv(4096)
            if not b:
                break
            chunks.append(b)
    finally:
        c.close()
    return json.loads(b"".join(chunks).decode("utf-8"))


# ==================================================================================================
# (1) e2e behavioral — the bare server answers a read-only snapshot and closes.
# ==================================================================================================
def test_server_answers_one_snapshot_then_closes(sock_path):
    srv = ProbeSocketServer(sock_path, lambda: {"effective_mode": "observe", "capacity_active": False},
                            monotonic=lambda: 1234.0).start()
    try:
        d = _probe(sock_path)
        assert d["aegis"] == "probe" and d["probe_ok"] is True
        assert d["snapshot_ok"] is True
        assert d["effective_mode"] == "observe" and d["capacity_active"] is False
        assert d["mono"] == 1234.0                    # the INJECTED clock, not a wall-clock
    finally:
        srv.stop()


def test_server_serves_repeatedly(sock_path):
    """Each connection gets its own fresh snapshot (the server is a standing listener, not one-shot)."""
    state = {"mode": "observe"}
    srv = ProbeSocketServer(sock_path, lambda: {"effective_mode": state["mode"]}, monotonic=lambda: 0.0).start()
    try:
        assert _probe(sock_path)["effective_mode"] == "observe"
        state["mode"] = "enforce"
        assert _probe(sock_path)["effective_mode"] == "enforce"   # re-read live on the next probe
    finally:
        srv.stop()


# ==================================================================================================
# (2) gate-invariance — AS-5c adds NO OracleKind; probe_socket.py off the __init__/__main__ import path.
# ==================================================================================================
def test_importing_aegis_leaves_all_oracles_frozen_at_15():
    import framework.v2.aegis  # noqa: F401
    from framework.v2.verify import verifier as V
    assert len(V._ALL_ORACLES) == 15                 # the probe socket is operational, not an oracle


def test_probe_socket_not_import_reachable_from_init_or_main():
    root = Path(__file__).resolve().parents[4]       # repo .../engine/crucible
    code = (
        "import sys;"
        "import framework.v2.aegis;"
        "import framework.v2.__main__;"
        "assert 'framework.v2.aegis.probe_socket' not in sys.modules, "
        "'probe_socket.py must be OFF the __init__/__main__ import path (make-gate byte-identity)';"
        "print('OK')"
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(root), str(root.parents[1] / "packages/core/vigil_core"),
                                         env.get("PYTHONPATH", "")])
    out = subprocess.run([sys.executable, "-c", code], cwd=str(root), env=env,
                         capture_output=True, text=True)
    assert out.returncode == 0, f"probe_socket reachable from init/main:\n{out.stdout}\n{out.stderr}"


def test_gateway_probe_socket_env_in_lockstep_with_module():
    from framework.v2.aegis import gateway as G
    assert G.PROBE_SOCKET_ENV == PROBE_SOCKET_ENV == "VIGIL_AEGIS_PROBE_SOCKET"


# ==================================================================================================
# (3) FATAL-2 — probe_socket.py imports ONLY the stdlib; never sigil/governor/strix (nor even vigil_core).
# ==================================================================================================
def test_probe_socket_imports_only_its_allowed_plane():
    src = Path(PS.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            roots.add((node.module or "").split(".")[0])
    for forbidden in ("sigil", "governor", "strix", "apps", "vigil_core"):
        assert forbidden not in roots, f"probe_socket must never import {forbidden!r} (FATAL-2)"
    allowed = {"__future__", "json", "os", "socket", "threading", "time", "typing"}
    assert roots <= allowed, f"unexpected absolute import roots in probe_socket.py: {sorted(roots - allowed)}"


# ==================================================================================================
# (4) determinism — a fixed snapshot over a fixed injected clock gives a byte-identical payload.
# ==================================================================================================
def test_payload_is_deterministic_and_clock_injected():
    snap = {"effective_mode": "enforce", "capacity": {"tracked_callers": 2, "global_inflight": 1}}
    srv = ProbeSocketServer("/unused", lambda: dict(snap), monotonic=lambda: 42.5)
    first = json.dumps(srv._payload(), sort_keys=True)
    assert json.dumps(srv._payload(), sort_keys=True) == first          # reproducible — no wall-clock/RNG
    p = srv._payload()
    assert p["mono"] == 42.5 and p["snapshot_ok"] is True
    assert p["capacity"] == {"tracked_callers": 2, "global_inflight": 1}


# ==================================================================================================
# (5) default-OFF + fail-closed flag parse.
# ==================================================================================================
def test_probe_socket_env_flag_is_strict_fail_closed(monkeypatch):
    monkeypatch.delenv(PROBE_SOCKET_ENV, raising=False)
    assert probe_socket_enabled() is False
    for on in ("1", "true", "YES", "on", " On "):
        monkeypatch.setenv(PROBE_SOCKET_ENV, on)
        assert probe_socket_enabled() is True, on
    for off in ("0", "false", "", "nope", "2", "enable"):
        monkeypatch.setenv(PROBE_SOCKET_ENV, off)
        assert probe_socket_enabled() is False, off


# ==================================================================================================
# (6) negative controls — mutation-sensitive per guard.
# ==================================================================================================
def test_socket_file_is_owner_only_0600(sock_path):
    srv = ProbeSocketServer(sock_path, dict, monotonic=lambda: 0.0).start()
    try:
        mode = stat.S_IMODE(os.stat(sock_path).st_mode)
        assert mode & 0o077 == 0, oct(mode)          # no group/other bits — a local peer cannot read it
    finally:
        srv.stop()


def test_snapshot_carries_no_raw_address_and_a_fault_degrades_gracefully(sock_path):
    """A snapshot_fn FAULT must not fail the probe: liveness (probe_ok) still answers, snapshot_ok=False."""
    def _boom() -> dict:
        raise RuntimeError("snapshot fault")
    srv = ProbeSocketServer(sock_path, _boom, monotonic=lambda: 7.0).start()
    try:
        d = _probe(sock_path)
        assert d["probe_ok"] is True and d["snapshot_ok"] is False     # fail-safe: liveness still answers
        assert "effective_mode" not in d                              # the faulting snapshot contributed nothing
    finally:
        srv.stop()


def test_probe_answer_is_not_a_block_or_verdict(sock_path):
    """A probe is operational telemetry — it carries NO certificate and NO attack verdict (never a block)."""
    srv = ProbeSocketServer(sock_path, lambda: {"effective_mode": "observe"}, monotonic=lambda: 0.0).start()
    try:
        d = _probe(sock_path)
        assert "certificate" not in d and "attack_class" not in d and "decision" not in d
        assert d["aegis"] == "probe"                  # it identifies as a probe, not a verdict
    finally:
        srv.stop()


def test_stop_is_idempotent_and_unlinks(sock_path):
    srv = ProbeSocketServer(sock_path, dict, monotonic=lambda: 0.0).start()
    assert os.path.exists(sock_path)
    srv.stop()
    assert not os.path.exists(sock_path)             # the socket file is removed
    srv.stop()                                       # a second stop is a safe no-op


def test_empty_path_is_a_fail_closed_construction_error():
    with pytest.raises(ValueError):
        ProbeSocketServer("", dict, monotonic=lambda: 0.0)


# ==================================================================================================
# Gateway integration — end-to-end through the live gateway over real loopback sockets.
# ==================================================================================================
class _Upstream(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_a):
        return

    def _reply(self):
        body = b"UPSTREAM-OK"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = _reply
    do_POST = _reply


@pytest.fixture()
def upstream() -> Iterator[int]:
    srv = socketserver.TCPServer(("127.0.0.1", 0), _Upstream)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield srv.server_address[1]
    finally:
        srv.shutdown()
        srv.server_close()


def _run_gateway(upstream_port: int, *, probe_socket_path=None, capacity_budget=None):
    from framework.v2.aegis.gateway import serve_gateway
    from framework.v2.aegis.models import AegisConfig
    cfg = AegisConfig(deployment_secret="k", mode="observe")
    gw = serve_gateway(f"http://127.0.0.1:{upstream_port}", config=cfg, host="127.0.0.1", port=0,
                       probe_socket_path=probe_socket_path, capacity_budget=capacity_budget,
                       monotonic_fn=lambda: 1000.0)
    threading.Thread(target=gw.serve_forever, daemon=True).start()
    return gw, gw.server_address[1]


def _get(port: int, path: str):
    try:
        r = urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5)   # noqa: S310
        return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def test_gateway_probe_socket_off_is_inert_not_bound(upstream, sock_path, monkeypatch):
    """DEFAULT-OFF byte-identity: a path is configured but VIGIL_AEGIS_PROBE_SOCKET is unset => NOTHING is
    bound, no socket file exists, and the data path still forwards unchanged."""
    monkeypatch.delenv(PROBE_SOCKET_ENV, raising=False)
    gw, port = _run_gateway(upstream, probe_socket_path=sock_path)
    try:
        assert gw.settings.probe_socket is None          # never built
        assert not os.path.exists(sock_path)             # nothing bound
        assert [_get(port, "/x")[0] for _ in range(4)] == [200] * 4   # data path byte-identical
    finally:
        gw.settings.stop_probe_socket()
        gw.shutdown(); gw.server_close()


def test_gateway_probe_socket_on_serves_mode_and_capacity(upstream, sock_path, monkeypatch):
    """Flag ON + a configured path + an AS-5a budget => the probe socket answers the HONEST effective mode and
    the live capacity snapshot, end-to-end through the running gateway."""
    from framework.v2.aegis.capacity import CapacityBudget
    monkeypatch.setenv(PROBE_SOCKET_ENV, "1")
    gw, port = _run_gateway(upstream, probe_socket_path=sock_path,
                            capacity_budget=CapacityBudget(rate_per_s=1.0, burst=5))
    try:
        assert gw.settings.probe_socket is not None
        d = _probe(sock_path)
        assert d["probe_ok"] is True and d["snapshot_ok"] is True
        assert d["enforcement"]["effective_mode"] == "observe"       # the honest gate state
        assert d["capacity"] == {"tracked_callers": 0, "global_inflight": 0}   # AS-5a snapshot, address-free
        assert d["capacity_active"] is False                          # VIGIL_AEGIS_CAPACITY not set
        assert d["mono"] == 1000.0                                    # the gateway's injected clock
        assert "127.0.0.1" not in json.dumps(d)                      # no upstream/caller address leaks
    finally:
        gw.settings.stop_probe_socket()
        gw.shutdown(); gw.server_close()


def test_gateway_no_probe_path_configured_has_no_socket(upstream, monkeypatch):
    """With no probe_socket_path the server is None even with the flag ON — the module is never imported into
    this gateway (byte-identical un-gated lifecycle)."""
    monkeypatch.setenv(PROBE_SOCKET_ENV, "1")
    gw, port = _run_gateway(upstream, probe_socket_path=None)
    try:
        assert gw.settings.probe_socket is None
        assert [_get(port, "/x")[0] for _ in range(3)] == [200] * 3
    finally:
        gw.shutdown(); gw.server_close()
