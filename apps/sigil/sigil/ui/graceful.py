"""Graceful stop for the sovereign HTTP servers: the cockpit (`sigil serve`), the customer edge
(`sigil serve-customer`) and the public site (`sigil serve-public`).

On SIGTERM (what `systemctl stop|restart` sends) or SIGINT the server:
  1. sets ``server.stopping`` — every long-lived stream loop (the cockpit's SSE feeds) checks it and ends;
  2. stops accepting and closes its listening socket, so a new connection is refused at once (the reverse proxy
     in front answers it) instead of queueing behind a server that is going away;
  3. waits for every request already accepted to finish, up to :data:`DRAIN_DEADLINE_S` — shorter than the
     units' ``TimeoutStopSec=20``, so a drain always ends before systemd would SIGKILL;
  4. closes the server (the cockpit writes its pending failed-login counts there) and returns.
A second signal during the drain ends the wait at once.

Request threads stay daemon threads, so a request still running at the deadline cannot hold the process past it.
stdlib only (FATAL-2).
"""
from __future__ import annotations

import signal
import socket
import sys
import threading
import time
from typing import Any, Callable, Optional

#: How long a stopping server waits for accepted requests to finish. The sigil-cockpit, sigil-customer and
#: sigil-public units allow TimeoutStopSec=20 (a test pins DRAIN_DEADLINE_S below every one of them).
DRAIN_DEADLINE_S = 10.0


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

    def process_request(self, request, client_address):  # type: ignore[no-untyped-def]
        # Counted on the ACCEPT thread, before the request thread starts, so a drain that begins right after an
        # accept always sees it.
        with self._inflight_cv:
            self._inflight += 1
        try:
            super().process_request(request, client_address)  # type: ignore[misc]
        except BaseException:
            self._request_done()
            raise

    def process_request_thread(self, request, client_address):  # type: ignore[no-untyped-def]
        try:
            super().process_request_thread(request, client_address)  # type: ignore[misc]
        finally:
            self._request_done()

    def _request_done(self) -> None:
        with self._inflight_cv:
            self._inflight -= 1
            self._inflight_cv.notify_all()

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


def graceful_stop(srv: Any, *, drain_deadline_s: float = DRAIN_DEADLINE_S,
                  abort: Optional[threading.Event] = None, log: Callable[[str], None] = print) -> bool:
    """Stop a running ``GracefulMixin`` server: signal the streams, stop accepting, drain within the deadline.
    Returns True when every accepted request finished in time. Call it from a thread other than the one inside
    ``serve_forever`` (``shutdown`` waits for that loop to return)."""
    srv.stopping.set()
    srv.shutdown()                      # serve_forever returns; nothing new is accepted
    _close_listener(srv)
    n = srv.inflight()
    if n:
        log(f"  stopping: waiting up to {drain_deadline_s:g} s for {n} request(s) in flight")
    drained = srv.wait_drained(drain_deadline_s, abort=abort)
    if not drained:
        log(f"  stopping: {srv.inflight()} request(s) still running at the deadline; closing")
    return drained


def serve_until_signal(srv: Any, *, drain_deadline_s: float = DRAIN_DEADLINE_S,
                       stop: Optional[threading.Event] = None, log: Callable[[str], None] = print) -> bool:
    """Serve ``srv`` until SIGTERM/SIGINT (or ``stop`` is set), then stop gracefully (:func:`graceful_stop`) and
    close it. Signal handlers are installed only on the main thread and are restored on return. Returns True
    when the drain finished within the deadline."""
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
    worker = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.25},
                              name="sigil-http-serve", daemon=True)
    worker.start()
    drained = True
    try:
        while not stop.wait(0.5):
            if not worker.is_alive():   # serve_forever ended on its own: nothing left to drain
                break
    except KeyboardInterrupt:           # SIGINT before the handler was installed
        stop.set()
    finally:
        try:
            drained = graceful_stop(srv, drain_deadline_s=drain_deadline_s, abort=force, log=log)
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
                sys.stdout.flush()
    return drained
