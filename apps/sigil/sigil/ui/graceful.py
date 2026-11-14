"""Graceful stop for the sovereign HTTP servers: the cockpit (`sigil serve`), the customer edge
(`sigil serve-customer`) and the public site (`sigil serve-public`).

On SIGTERM (what `systemctl stop|restart` sends) or SIGINT the server:
  1. sets ``server.stopping`` — every long-lived stream loop (the cockpit's SSE feeds) checks it and ends;
  2. stops its accept loop, then serves every connection already waiting in the listen queue. The kernel completes
     a TCP handshake before the server accepts it, so the client (nginx) may already have sent its request there;
     closing the listener with those connections queued would reset them, and nginx never re-sends a POST it has
     sent. On Linux the listener first drops new connection attempts (a socket filter on SYN; handshakes already
     under way still complete), so nothing can join the queue between the last accept and the close;
  3. closes its listening socket, so a new connection is refused (on Linux, the client's second SYN about a second
     later) — the reverse proxy sends it to the other edge port, or answers it;
  4. waits for every request accepted to finish, up to the server's own drain deadline
     (:meth:`GracefulMixin.drain_deadline`): :data:`DRAIN_DEADLINE_S` by default, longer where a request can
     legitimately take longer (the customer edge outwaits its slowest call to the cockpit, so a stop never cuts an
     action the cockpit is still completing). Each unit's ``TimeoutStopSec`` sits above its server's deadline (a
     test pins it), so a drain always ends before systemd would SIGKILL;
  5. closes the server (the cockpit writes its pending failed-login counts there) and returns.
A second signal during the drain ends the wait at once.

Request threads stay daemon threads, so a request still running at the deadline cannot hold the process past it.
stdlib only (FATAL-2).
"""
from __future__ import annotations

import signal
import socket
import struct
import sys
import threading
import time
from typing import Any, Callable, Optional

#: How long a stopping server waits for accepted requests to finish, unless the server sets its own
#: (:meth:`GracefulMixin.drain_deadline`). The cockpit and the public site use it (TimeoutStopSec=20); the customer edge
#: waits longer (custui.drain_deadline_s). A test pins each server's deadline below its units' TimeoutStopSec.
DRAIN_DEADLINE_S = 10.0

#: Once new connection attempts are dropped, how long a stop waits for the handshakes already under way to land in
#: the listen queue before it serves the queue and closes (a loopback handshake takes microseconds).
HANDSHAKE_GRACE_S = 0.2

_SO_ATTACH_FILTER = 26                     # Linux, <asm-generic/socket.h>
# A classic-BPF socket filter that drops a TCP segment with SYN set and ACK clear — a new connection attempt — and
# passes every other one. A TCP socket filter sees the segment from its TCP header; byte 13 holds the flags.
_DROP_NEW_CONNECTIONS = (
    (0x30, 0, 0, 13),                      # ldb [13]          A = TCP flags
    (0x54, 0, 0, 0x12),                    # and #0x12         keep SYN|ACK
    (0x15, 0, 1, 0x02),                    # jeq #0x02         SYN without ACK ?
    (0x06, 0, 0, 0),                       # ret #0            yes: drop it
    (0x06, 0, 0, 0xFFFFFFFF),              # ret #-1           no: pass the whole segment
)


class GracefulMixin:
    """Mix into a ``ThreadingHTTPServer`` (before it in the bases): counts the requests in flight and exposes
    ``stopping``, the event stream loops observe."""

    # socketserver's own close-time join waits for every request thread with no bound; the drain above is the
    # bounded wait, so the server's close never blocks past it.
    block_on_close = False

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.stopping = threading.Event()
        self._inflight = 0
        self._inflight_cv = threading.Condition()
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        # Counted on the ACCEPT thread, before the request thread starts, so a drain that begins right after an
        # accept always sees it.
        with self._inflight_cv:
            self._inflight += 1
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._request_done()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_done()

    def _request_done(self) -> None:
        with self._inflight_cv:
            self._inflight -= 1
            self._inflight_cv.notify_all()

    def drain_deadline(self) -> float:
        """How long this server, when it stops, waits for the requests it accepted. Read at stop time."""
        return DRAIN_DEADLINE_S

    def inflight(self) -> int:
        with self._inflight_cv:
            return self._inflight

    def wait_drained(self, deadline_s: float, *, abort: Optional[threading.Event] = None) -> bool:
        """Block until no request is in flight (True) or ``deadline_s`` passes / ``abort`` is set (False)."""
        end = time.monotonic() + max(0.0, deadline_s)
        with self._inflight_cv:
            while self._inflight > 0:
                left = end - time.monotonic()
                if left <= 0 or (abort is not None and abort.is_set()):
                    return False
                self._inflight_cv.wait(min(left, 0.1))
            return True


def _hold_new_connections(srv: Any) -> bool:
    """Linux: make the listening socket drop new connection attempts while the handshakes already under way still
    complete. The client's kernel sends its SYN again about a second later, by when the listener is closed and the
    attempt is refused before any byte of a request was sent — so nginx gives even a POST to the other port. The
    filter is cloned into a connection accepted after this, where it never matches (an established connection
    carries no SYN without ACK). Returns False where this is unavailable: the stop then closes right after
    serving the queue, and a connection whose handshake completes in between is reset."""
    sock = getattr(srv, "socket", None)
    if sock is None or not sys.platform.startswith("linux"):
        return False
    try:
        import ctypes  # stdlib; only needed to hand the kernel the filter program's address
        raw = b"".join(struct.pack("HBBI", *ins) for ins in _DROP_NEW_CONNECTIONS)
        prog = ctypes.create_string_buffer(raw, len(raw))
        fprog = struct.pack("HP", len(_DROP_NEW_CONNECTIONS), ctypes.addressof(prog))
        sock.setsockopt(socket.SOL_SOCKET, _SO_ATTACH_FILTER, fprog)
        return True
    except (OSError, ValueError, ImportError, AttributeError):
        return False


def _serve_waiting_connections(srv: Any) -> int:
    """Accept every connection waiting in the listen queue and hand each to the server as its accept loop would
    (counted in flight, served on its own thread). Returns how many were taken."""
    sock = getattr(srv, "socket", None)
    if sock is None:
        return 0
    try:
        sock.setblocking(False)
    except OSError:
        return 0
    taken = 0
    while True:
        try:
            request, client_address = srv.get_request()
        except BlockingIOError:
            break                           # the queue is empty
        except ConnectionAbortedError:
            continue                        # that client gave up while queued; the next one may still be there
        except OSError:
            break
        taken += 1
        try:
            request.setblocking(True)       # a BSD accept() hands out a non-blocking socket from a non-blocking one
        except OSError:
            pass
        if not srv.verify_request(request, client_address):
            srv.shutdown_request(request)
            continue
        try:
            srv.process_request(request, client_address)
        except Exception:  # noqa: BLE001 — as socketserver's own loop: report, close that connection, go on
            srv.handle_error(request, client_address)
            srv.shutdown_request(request)
    return taken


def _close_listener(srv: Any) -> None:
    """Close the listening socket so new connections are refused at once (the server's own `server_close` still
    runs after the drain; closing twice is harmless)."""
    sock = getattr(srv, "socket", None)
    if sock is None:
        return
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


def graceful_stop(srv: Any, *, drain_deadline_s: Optional[float] = None,
                  abort: Optional[threading.Event] = None, log: Callable[[str], None] = print,
                  serving: bool = True) -> bool:
    """Stop a ``GracefulMixin`` server: signal the streams, stop accepting, drain within the deadline (the
    server's own, :meth:`GracefulMixin.drain_deadline`, unless ``drain_deadline_s`` is given). Returns True when
    every accepted request finished in time. Call it from a thread other than the one inside ``serve_forever``
    (``shutdown`` waits for that loop to return); pass ``serving=False`` when that loop has already ended. A log
    line that cannot be written (a closed stdout) never interrupts the stop."""
    if drain_deadline_s is None:
        drain_deadline_s = float(srv.drain_deadline())

    def _say(msg: str) -> None:
        try:
            log(msg)
        except Exception:  # noqa: BLE001 — the stop must complete whatever happened to the log stream
            pass

    srv.stopping.set()
    if serving:
        srv.shutdown()                  # serve_forever returns; the listen queue may still hold connections
    if _hold_new_connections(srv):      # Linux: nothing new joins the queue from here on
        if abort is not None:
            abort.wait(HANDSHAKE_GRACE_S)
        else:
            time.sleep(HANDSHAKE_GRACE_S)
    _serve_waiting_connections(srv)     # every connection the kernel accepted is served, never reset
    _close_listener(srv)
    n = srv.inflight()
    if n:
        _say(f"  stopping: waiting up to {drain_deadline_s:g} s for {n} request(s) in flight")
    drained = srv.wait_drained(drain_deadline_s, abort=abort)
    if not drained:
        _say(f"  stopping: {srv.inflight()} request(s) still running at the deadline; closing")
    return drained


def serve_until_signal(srv: Any, *, drain_deadline_s: Optional[float] = None,
                       stop: Optional[threading.Event] = None, log: Callable[[str], None] = print) -> bool:
    """Serve ``srv`` until SIGTERM/SIGINT (or ``stop`` is set), then stop gracefully (:func:`graceful_stop`; the
    server's own drain deadline unless ``drain_deadline_s`` is given) and close it. Signal handlers are installed
    only on the main thread and are restored on return. Returns True when the drain finished within the
    deadline."""
    stop = stop if stop is not None else threading.Event()
    force = threading.Event()

    def _on_signal(signum, _frame):  # noqa: ANN001
        if stop.is_set():
            force.set()                 # a second signal ends the drain wait at once
        stop.set()

    previous: dict = {}
    if threading.current_thread() is threading.main_thread():
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                previous[sig] = signal.signal(sig, _on_signal)
            except (ValueError, OSError):
                pass
    failure: list = []

    def _serve() -> None:
        try:
            srv.serve_forever(poll_interval=0.25)
        except BaseException as exc:  # noqa: BLE001 — re-raised on the calling thread below
            failure.append(exc)

    worker = threading.Thread(target=_serve, name="sigil-http-serve", daemon=True)
    worker.start()
    drained = True
    try:
        while not stop.wait(0.5):
            if not worker.is_alive():   # serve_forever ended on its own (it failed): stop and report it
                break
    except KeyboardInterrupt:           # SIGINT before the handler was installed
        stop.set()
    finally:
        try:
            drained = graceful_stop(srv, drain_deadline_s=drain_deadline_s, abort=force, log=log,
                                    serving=worker.is_alive())
        finally:
            try:
                srv.server_close()
            finally:
                worker.join(timeout=5)
                for sig, h in previous.items():
                    try:
                        signal.signal(sig, h)
                    except (ValueError, OSError):
                        pass
                try:
                    sys.stdout.flush()
                except Exception:  # noqa: BLE001 — a closed stdout must not turn a clean stop into a failure
                    pass
    if failure:
        raise failure[0]                # a serve loop that failed fails the process (systemd restarts it)
    return drained
