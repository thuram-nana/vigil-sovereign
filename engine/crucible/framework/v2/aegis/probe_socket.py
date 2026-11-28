"""aegis.probe_socket — AS-5c: the gateway's LOCAL operational PROBE SOCKET (read-only health + admission state).

The gateway already answers the UNAUTHENTICATED liveness/readiness probes (`/healthz`, `/readyz`) on its
data-plane HTTP port. Those are the right surface for a k8s/LB probe, but they are (a) on the network the
gateway also serves real traffic to, and (b) deliberately thin — a bare ``{"ok": …}`` — because anything they
expose is exposed to every client, attacker included. In particular the AS-5a capacity admission plane's live
load (how much the gateway is currently tracking / shedding) is OPERATIONAL state an orchestrator or operator
wants, but must NOT be published on the network data plane: it would hand an attacker a live read on how close
the gateway is to shedding.

This module is that missing surface: a dedicated LOCAL ``AF_UNIX`` probe socket, bound owner-only (0600),
OFF the data-plane HTTP port, that serves a single read-only, metadata-only JSON status snapshot to whoever
connects and then closes. It surfaces the OUTCOME of the AS-5a admission plane (the ``CapacityGovernor``
snapshot: tracked callers + global in-flight) alongside the honest effective mode — the "capacity & outcomes"
increment that sits between AS-5a (capacity) and AS-5d (outcomes + receipts) on the GW chain.

Doctrine (non-negotiable, enforced here and tested):
  * READ-ONLY, NEVER A BLOCK / NEVER A VERDICT. A probe answer is pure operational telemetry — it mints no
    certificate, no attack verdict, takes no response action. Exactly like capacity (an operational signal,
    never a finding) and the ``--status-out`` writer (telemetry only). Connecting IS the probe.
  * METADATA ONLY. The snapshot carries counts and the effective mode — never a raw caller address, never a
    secret, never upstream wiring. The AS-5a ``snapshot()`` is already address-free; this module adds nothing
    that is not.
  * LOCAL + CORRELATABLE, NOT HIDDEN. ``AF_UNIX`` + 0600 means a LOCAL operator/orchestrator process reads it,
    not the network — the opposite of a covert channel. AEGIS is operator-correlatable by doctrine; this is a
    surface FOR the operator, exposing nothing to an attacker.
  * DETERMINISM. No wall-clock and no RNG: the monotonic clock is INJECTED (the same clock the AS-2c/AS-5a
    planes use), so a probe's ``mono`` reading is reproducible under a fixed clock in tests and in audit.
  * FAIL-SAFE + TOTAL. Any error serving a probe is swallowed — a probe fault must NEVER touch the data path
    or crash the gateway. A bind failure leaves the feature DORMANT (the gateway proxies exactly as before).

DEFAULT-OFF: the socket is bound only when a gateway is given a ``probe_socket_path`` AND the strict,
fail-closed ``VIGIL_AEGIS_PROBE_SOCKET`` flag is set. OFF ⇒ nothing is bound, no thread runs, and the gateway
(data path AND lifecycle) is byte-identical to a gateway built without the feature.

FATAL-2: engine leg — imports ONLY the stdlib. No ``vigil_core`` (nothing here needs the shared contracts),
no ``sigil``/``governor``/``strix``, nothing on the scan/engage/benchmark gate path. It adds NO OracleKind and
registers NO vocabulary, so the make-gate byte-identity is structurally untouched.
"""

from __future__ import annotations

import json
import os
import socket
import threading
import time
from typing import Callable, Optional

__all__ = [
    "PROBE_SOCKET_ENV",
    "ProbeSocketServer",
    "probe_socket_enabled",
]

# The default-OFF switch for the local probe socket — strict, fail-closed, read when the gateway is built (so a
# deployment that does not opt in never binds anything). Only an explicit affirmative token turns it on; anything
# else (unset, typo, "0", "false") keeps the probe socket OFF — mirrors ``capacity.capacity_enabled`` exactly.
PROBE_SOCKET_ENV = "VIGIL_AEGIS_PROBE_SOCKET"

# A probe is a bare connect; we read and discard any bytes the client sends (so a well-meaning client that writes
# a request line does not get an RST), but never more than this — an operational probe sends nothing meaningful.
_MAX_PROBE_REQUEST_BYTES = 512

# Bound a slow/stalled probe client so it can never hold the single accept loop forever.
_PROBE_CLIENT_TIMEOUT_S = 2.0

# How long ``accept()`` blocks before the loop re-checks the stop flag — small, so ``stop()`` is prompt.
_ACCEPT_TIMEOUT_S = 0.5


def probe_socket_enabled() -> bool:
    """Is the local probe socket armed? Strict, fail-closed, DEFAULT OFF — only an explicit affirmative token
    arms it (mirrors ``capacity.capacity_enabled`` / ``gateway._saas_enforce_flag``). The socket is still bound
    only when a ``probe_socket_path`` was ALSO configured."""
    return (os.environ.get(PROBE_SOCKET_ENV) or "").strip().lower() in ("1", "true", "yes", "on")


class ProbeSocketServer:
    """A LOCAL ``AF_UNIX`` probe listener that answers each connection with ONE read-only JSON status snapshot
    and closes. Single-threaded accept loop on a daemon thread (operator probes are infrequent; a slow client is
    bounded by a recv/send timeout so it cannot stall the loop). Deterministic given an injected monotonic clock.
    Total: every error serving a probe is swallowed — a probe fault never reaches the gateway's data path.

    ``snapshot_fn`` is injected (the gateway supplies the live capacity/mode read; a test supplies a stub), so
    this module stays pure stdlib and decoupled from the gateway's internals."""

    def __init__(self, path: str, snapshot_fn: "Callable[[], dict[str, object]]", *,
                 monotonic: Callable[[], float] = time.monotonic,
                 accept_timeout: float = _ACCEPT_TIMEOUT_S) -> None:
        if not path:
            raise ValueError("ProbeSocketServer requires a non-empty socket path")
        self._path = str(path)
        self._snapshot_fn = snapshot_fn
        self._now = monotonic
        self._accept_timeout = float(accept_timeout)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._sock: "Optional[socket.socket]" = None
        self._thread: "Optional[threading.Thread]" = None

    @property
    def address(self) -> str:
        """The filesystem path the probe socket is (or will be) bound at."""
        return self._path

    # -- lifecycle --------------------------------------------------------------------------------------

    def start(self) -> "ProbeSocketServer":
        """Bind the ``AF_UNIX`` socket owner-only (0600) and start the accept loop on a daemon thread. Raises on
        a bind failure so the caller can leave the feature dormant (fail-open, exactly like the OOB receiver).
        Idempotent: a second ``start()`` on a live server is a no-op."""
        if not hasattr(socket, "AF_UNIX"):
            raise RuntimeError("probe socket requires AF_UNIX (unavailable on this platform)")
        with self._lock:
            if self._sock is not None:
                return self
            # A stale socket file from a crashed predecessor would make bind() fail with EADDRINUSE; remove it
            # first. Only ever unlink the exact configured path; a missing path is fine.
            try:
                os.unlink(self._path)
            except FileNotFoundError:
                pass
            except OSError:
                pass
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            # Create the socket file owner-only. bind() applies the process umask to 0o777, so tighten the umask
            # to 0o177 across the bind (⇒ 0o600), then restore it. chmod again defensively (belt and suspenders).
            old_umask = os.umask(0o177)
            try:
                sock.bind(self._path)
            finally:
                os.umask(old_umask)
            try:
                os.chmod(self._path, 0o600)
            except OSError:
                pass
            sock.listen(16)
            sock.settimeout(self._accept_timeout)
            self._sock = sock
            self._stop.clear()
            self._thread = threading.Thread(target=self._serve_loop, name="aegis-probe-socket", daemon=True)
            self._thread.start()
            return self

    def stop(self) -> None:
        """Stop the accept loop, close the listener, and unlink the socket file. Idempotent and total — the
        thread is a daemon regardless, so a missed stop never hangs the process."""
        with self._lock:
            self._stop.set()
            sock, self._sock = self._sock, None
            thread, self._thread = self._thread, None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2.0)
        try:
            os.unlink(self._path)
        except OSError:
            pass

    # -- serving ----------------------------------------------------------------------------------------

    def _serve_loop(self) -> None:
        """Accept one probe at a time until stopped. Every per-connection error is isolated; an accept timeout
        just re-checks the stop flag. A socket error after ``stop()`` closed the listener ends the loop."""
        while not self._stop.is_set():
            sock = self._sock
            if sock is None:
                break
            try:
                conn, _addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                # The listener was closed (stop) or faulted — end the loop if stopping, else keep serving.
                if self._stop.is_set():
                    break
                continue
            try:
                self._handle_conn(conn)
            except Exception:
                # A probe fault must NEVER escape the loop (and so never reach the gateway).
                pass

    def _handle_conn(self, conn: "socket.socket") -> None:
        """Serve ONE probe: drain any (bounded) request bytes, write the JSON snapshot + newline, close. Total:
        bounded by a recv/send timeout so a stalled client cannot pin the loop; every error is swallowed."""
        try:
            conn.settimeout(_PROBE_CLIENT_TIMEOUT_S)
            try:
                conn.recv(_MAX_PROBE_REQUEST_BYTES)   # drain + discard (a probe sends nothing meaningful)
            except OSError:
                pass
            payload = self._payload()
            try:
                conn.sendall(json.dumps(payload, ensure_ascii=False).encode("utf-8") + b"\n")
            except OSError:
                pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _payload(self) -> "dict[str, object]":
        """The read-only probe answer. Always carries ``probe_ok`` (the server answered ⇒ the gateway process is
        live) and a deterministic injected-clock ``mono`` reading, merged with the gateway-supplied operational
        snapshot (effective mode + AS-5a capacity state). A snapshot_fn fault degrades to ``snapshot_ok: False``
        rather than failing the probe — liveness still answers."""
        payload: "dict[str, object]" = {"aegis": "probe", "probe_ok": True, "mono": float(self._now())}
        try:
            snap = self._snapshot_fn()
            if isinstance(snap, dict):
                payload.update(snap)
                payload["snapshot_ok"] = True
            else:
                payload["snapshot_ok"] = False
        except Exception:
            payload["snapshot_ok"] = False
        return payload
