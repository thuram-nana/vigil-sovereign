"""
scanner.cdp — a minimal Chrome DevTools Protocol driver over the WS client.

``scanner.browser`` shells out to headless Chromium's one-shot ``--dump-dom``: it
gets a post-load DOM *snapshot* and nothing else — no interaction, no event
dispatch, no way to observe whether an injected script actually *executed*. That
is enough for a static DOM-XSS *lead*, not a confirmation, and it cannot crawl a
single-page app whose routes and endpoints only exist after user interaction.

This module is the real driver. It launches Chromium with a remote-debugging
port, speaks CDP over the same RFC-6455 WS client the scanner already ships
(``scanner.websocket``), and exposes the primitives the browser-aware checks
need: navigate, evaluate JS, register a **binding** (a JS callback the page can
invoke, whose calls surface as CDP events), dispatch input, and read captured
network requests. The binding is the load-bearing bit: a DOM-XSS payload that
*executes* calls the binding with a unique canary, so the confirmation is real
JS execution observed in a real DOM — the strongest possible XSS proof, not a
reflected-substring guess.

Pure-stdlib + the scanner WS client; no third-party browser-automation dep. The
process, user-data dir, and WS connection are all torn down with the context
manager. If no browser is found, construction fails cleanly so callers skip the
dynamic path rather than guess.
"""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path
from types import TracebackType

from ..common.errors import CrucibleError
from .browser import find_browser
from .websocket import WSConnection, connect

# Flags that make Chromium headless, debuggable, and sandbox-tolerant. `port=0`
# lets the OS assign a port; Chromium writes the chosen one to DevToolsActivePort.
_LAUNCH_FLAGS = (
    "--headless=new",
    "--remote-debugging-port=0",
    "--no-sandbox",
    "--disable-gpu",
    "--disable-dev-shm-usage",
    "--disable-extensions",
    "--no-first-run",
    "--disable-background-networking",
)


class CdpError(CrucibleError):
    """A CDP driver failure — no browser, a launch/connect timeout, or a command
    error returned by the browser. Recoverable: the caller skips the dynamic path
    (a browser check never *guesses*, so a driver failure yields no finding)."""


class CdpSession:
    """A CDP command/event channel to one page target.

    ``send`` issues a command and returns its result, buffering any interleaved
    events for later polling (``events_of``/``drain_events``). Deterministic ids;
    a command that the browser reports as an error raises :class:`CdpError`."""

    def __init__(self, conn: WSConnection) -> None:
        self._conn = conn
        self._id = 0
        self._events: list[dict] = []

    def send(self, method: str, params: dict | None = None, *, timeout: float = 10.0) -> dict:
        self._id += 1
        mid = self._id
        self._conn.send_text(json.dumps({"id": mid, "method": method, "params": params or {}}))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            raw = self._conn.recv_text(timeout=max(0.05, deadline - time.monotonic()))
            if not raw:
                continue
            try:
                msg = json.loads(raw)
            except ValueError:
                continue
            if msg.get("id") == mid:
                if "error" in msg:
                    raise CdpError(f"{method} failed: {msg['error']}")
                return msg.get("result", {})
            if "method" in msg:
                self._events.append(msg)
        raise CdpError(f"CDP timeout waiting for {method}")

    def drain_events(self, *, timeout: float = 1.0) -> list[dict]:
        """Read and buffer any pending events for up to ``timeout`` seconds; return
        the full buffered event list. Used to collect binding calls / network
        requests that arrive asynchronously after a navigation settles."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            raw = self._conn.recv_text(timeout=max(0.05, deadline - time.monotonic()))
            if not raw:
                continue
            try:
                msg = json.loads(raw)
            except ValueError:
                continue
            if "method" in msg:
                self._events.append(msg)
        return list(self._events)

    def events_of(self, method: str) -> list[dict]:
        return [e for e in self._events if e.get("method") == method]

    def wait_event(self, method: str, *, timeout: float = 10.0) -> dict | None:
        """Return the first event of ``method`` (from the buffer or newly read),
        or None if none arrives within ``timeout``."""
        for e in self._events:
            if e.get("method") == method:
                return e
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            raw = self._conn.recv_text(timeout=max(0.05, deadline - time.monotonic()))
            if not raw:
                continue
            try:
                msg = json.loads(raw)
            except ValueError:
                continue
            if "method" in msg:
                self._events.append(msg)
                if msg["method"] == method:
                    return msg
        return None

    # -- high-level helpers -------------------------------------------------

    def enable_domains(self, *domains: str) -> None:
        for d in domains:
            self.send(f"{d}.enable")

    def navigate(self, url: str, *, timeout: float = 15.0, settle: float = 0.4) -> None:
        """Navigate and wait for load, then a brief settle for post-load JS. Clears
        the event buffer first so events belong to this navigation."""
        self._events.clear()
        self.send("Page.enable")
        self.send("Page.navigate", {"url": url}, timeout=timeout)
        self.wait_event("Page.loadEventFired", timeout=timeout)
        if settle > 0:
            self.drain_events(timeout=settle)

    def evaluate(self, expression: str, *, return_by_value: bool = True, timeout: float = 10.0):
        """Runtime.evaluate; returns the JS value (or None). ``await`` is allowed."""
        res = self.send("Runtime.evaluate", {
            "expression": expression, "returnByValue": return_by_value,
            "awaitPromise": True, "allowUnsafeEvalBlockedByCSP": True,
        }, timeout=timeout)
        return res.get("result", {}).get("value")

    def add_binding(self, name: str) -> None:
        """Register ``window[name](arg)`` — the page calling it surfaces as a
        ``Runtime.bindingCalled`` event carrying ``arg``. The execution oracle's
        unforgeable signal. Applies to the current AND future page contexts, so it
        survives a navigation."""
        self.send("Runtime.enable")
        self.send("Runtime.addBinding", {"name": name})

    def add_init_script(self, source: str) -> str:
        """Evaluate ``source`` in EVERY new document before its own scripts run
        (Page.addScriptToEvaluateOnNewDocument). Used to install a source->sink
        taint hook so a fast, pre-load DOM-XSS is still observed. Returns the
        script identifier."""
        self.send("Page.enable")
        res = self.send("Page.addScriptToEvaluateOnNewDocument", {"source": source})
        return res.get("identifier", "")

    def binding_calls(self, name: str) -> list[str]:
        """The payloads passed to ``window[name](...)`` observed so far."""
        return [e["params"].get("payload", "")
                for e in self.events_of("Runtime.bindingCalled")
                if e.get("params", {}).get("name") == name]

    def close(self) -> None:
        self._conn.close()


class CdpBrowser:
    """Launches headless Chromium with a remote-debugging port and hands out
    :class:`CdpSession`\\ s bound to its page target.

    Context-managed: the process, the temp user-data dir, and the WS connection
    are all cleaned up on exit. Raises :class:`CdpError` if no browser is found or
    the debugger never comes up — callers then skip the dynamic path."""

    def __init__(self, *, browser_path: str | None = None, launch_timeout: float = 20.0,
                 extra_flags: tuple[str, ...] = ()) -> None:
        self._path = browser_path or find_browser()
        if not self._path:
            raise CdpError("no Chromium/Chrome binary found for the CDP driver")
        self._launch_timeout = launch_timeout
        self._extra = extra_flags
        self._proc: subprocess.Popen | None = None
        self._udd: str | None = None
        self._port: int | None = None
        self._sessions: list[CdpSession] = []

    def start(self) -> "CdpBrowser":
        if self._proc is not None:
            return self
        self._udd = tempfile.mkdtemp(prefix="crucible-cdp-")
        argv = [self._path, *_LAUNCH_FLAGS, *self._extra, f"--user-data-dir={self._udd}", "about:blank"]
        self._proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        portfile = Path(self._udd) / "DevToolsActivePort"
        deadline = time.monotonic() + self._launch_timeout
        while time.monotonic() < deadline:
            if portfile.exists():
                try:
                    self._port = int(portfile.read_text().splitlines()[0])
                    break
                except (ValueError, IndexError):
                    pass
            if self._proc.poll() is not None:
                raise CdpError("browser exited before the debugger came up")
            time.sleep(0.1)
        if self._port is None:
            raise CdpError("browser debugger port did not appear within the timeout")
        return self

    def _page_ws_url(self) -> str:
        url = f"http://127.0.0.1:{self._port}/json"
        try:
            targets = json.loads(urllib.request.urlopen(url, timeout=5).read())  # noqa: S310 (loopback)
        except (OSError, ValueError) as e:
            raise CdpError(f"could not list CDP targets: {e}") from e
        for t in targets:
            if t.get("type") == "page" and t.get("webSocketDebuggerUrl"):
                return t["webSocketDebuggerUrl"]
        raise CdpError("no page target exposed by the browser")

    def session(self) -> CdpSession:
        """Open a CDP session on the browser's page target."""
        if self._proc is None:
            self.start()
        conn = connect(self._page_ws_url())
        if conn is None:
            raise CdpError("CDP websocket handshake failed")
        sess = CdpSession(conn)
        self._sessions.append(sess)
        return sess

    def stop(self) -> None:
        for s in self._sessions:
            try:
                s.close()
            except Exception:
                pass
        self._sessions.clear()
        if self._proc is not None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            self._proc = None
        if self._udd:
            shutil.rmtree(self._udd, ignore_errors=True)
            self._udd = None
        self._port = None

    def __enter__(self) -> "CdpBrowser":
        return self.start()

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None,
                 tb: TracebackType | None) -> None:
        self.stop()


def cdp_available() -> bool:
    """Whether a browser binary exists for the CDP driver (gates the dynamic path)."""
    return find_browser() is not None
