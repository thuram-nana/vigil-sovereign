"""
In-band (reflected-output) OS command injection confirmed by EXECUTION OUTPUT, not reflection.

MERIDIAN's cmdi sink (/diagnostics/ping?host=) concatenates the host into a shell string and reflects
the combined stdout/stderr, so ``host=127.0.0.1;id`` runs ``id`` and the response carries its real
``uid=<digits>(`` output. Every cmdi check in the engine was OOB/timing — nothing keyed on the in-band
execution signal — so a genuinely reflected-cmdi sink stayed a LEAD. CmdiReflectedCheck closes that gap
SOUNDLY: it confirms ONLY on the command OUTPUT ``uid=<digits>(`` (a property of ``id`` RUNNING, never of
input reflection — the payload contains no ``uid=``), attributed by a benign control.

The fixtures GENUINELY EXECUTE the injected command (subprocess, shell=True) so ``uid=`` is a real
property of execution, never canned text pattern-matched from the payload — the fake-fixture trap this
whole class exists to refuse. Four endpoints prove the sound boundary:
  * EXECUTES         -> confirms (a real FACT)
  * REFLECTS ``;id`` but runs nothing   -> does NOT confirm (reflection != execution)
  * HARDENED (rejects break-out / argv) -> does NOT confirm (the sound negative control)
  * STATICALLY prints uid (input-independent) -> does NOT confirm (control attribution refuses it)
"""

from __future__ import annotations

import contextlib
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator
from urllib.parse import parse_qs, urlsplit

from framework.v2.scanner.checks import CMDI_REFLECTED, CmdiReflectedCheck
from framework.v2.scanner.cli import loopback_send
from framework.v2.scanner.insertion import HttpRequest, InsertionKind, RequestTemplate
from framework.v2.verify.confirmation import confirm_finding
from framework.v2.verify.verifier import OracleVerifier

# A strict hostname/IP shape: letters, digits, dot, hyphen. Anything with a shell metachar fails it —
# this is the hardened twin's input gate (MERIDIAN's _valid_host), rejecting `127.0.0.1;id` before any
# shell runs.
import re as _re

_HOSTNAME_RE = _re.compile(r"^[A-Za-z0-9.\-]{1,253}$")


def _host(path: str) -> str:
    return parse_qs(urlsplit(path).query).get("host", [""])[0]


class _CmdiExec(BaseHTTPRequestHandler):
    """VULNERABLE: concatenates host into a shell string and reflects combined stdout/stderr. The
    injected command GENUINELY RUNS (shell=True), so `;id` produces real `uid=...` output. `echo` is the
    benign base (instant, always present) — the vuln is the shell concatenation + break-out, not ping."""

    def log_message(self, *a: object) -> None:
        return

    def _run(self, host: str) -> str:
        try:
            cp = subprocess.run("echo reached " + host, shell=True, capture_output=True,
                                text=True, timeout=5)
            return (cp.stdout or "") + (cp.stderr or "")
        except Exception as exc:  # noqa: BLE001
            return f"error: {exc}"

    def do_GET(self) -> None:  # noqa: N802
        out = self._run(_host(self.path))
        body = f"<pre class=\"console\">$ echo reached {_host(self.path)}\n{out}</pre>".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _ReflectOnly(_CmdiExec):
    """REFLECTS the raw host (incl. `;id`) back into the page but executes NOTHING — a search/echo
    endpoint. The old marker/`;echo` cmdi approach would wrongly fire here; the execution-output check
    must not (the payload carries no `uid=`)."""

    def do_GET(self) -> None:  # noqa: N802
        body = f"<p>You asked to ping: {_host(self.path)}</p>".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _Hardened(_CmdiExec):
    """HARDENED twin: a strict host validator refuses any break-out before a shell runs; a valid host is
    passed as an argv element (shell=False), so no metacharacter is ever interpreted. Never emits
    `uid=...`. This is the sound negative control — the hardened half MUST stay silent."""

    def do_GET(self) -> None:  # noqa: N802
        host = _host(self.path)
        if not _HOSTNAME_RE.match(host):
            body = f"Refused: {host} is not a valid hostname or IP address".encode()
        else:
            try:
                cp = subprocess.run(["echo", "reached", host], capture_output=True, text=True,
                                    timeout=5)  # argv, shell=False — no break-out possible
                body = ((cp.stdout or "") + (cp.stderr or "")).encode()
            except Exception as exc:  # noqa: BLE001
                body = f"error: {exc}".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _StaticUid(_CmdiExec):
    """Prints the server's own `id` output on EVERY request regardless of input (a status/diagnostics
    page with ZERO command injection). The marker is present under the payload AND under the benign
    control, so the control-attribution guard must REFUSE — presence is not attributable to the payload."""

    def do_GET(self) -> None:  # noqa: N802
        body = (f"<pre>server identity: uid=0(root) gid=0(root) groups=0(root)\n"
                f"you requested: {_host(self.path)}</pre>").encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@contextlib.contextmanager
def _server(handler) -> Iterator[str]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    srv.daemon_threads = True
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()
        th.join(timeout=5)


def _confirms(check: CmdiReflectedCheck, base: str) -> bool:
    """Drive the check through the REAL oracle pipeline (confirm_finding + OracleVerifier), exactly as
    the scanner engine does — returns True iff a command_injection FACT is confirmed."""
    tmpl = RequestTemplate(HttpRequest(method="GET", url=f"{base}/ping?host=x"))
    (pt,) = [p for p in tmpl.insertion_points(kinds=(InsertionKind.QUERY_VALUE,)) if p.name == "host"]
    ctx = check.probe(tmpl, pt, loopback_send)
    if ctx is None:
        return False
    return confirm_finding(
        finding={"bug_class": check.bug_class, "title": "t", "severity": "High",
                 "surface": "s", "summary": "x"},
        context=ctx, verifier=OracleVerifier()) is not None


def test_confirms_on_real_command_execution() -> None:
    # host=127.0.0.1;id GENUINELY runs `id` -> uid=<digits>( present; benign 127.0.0.1 -> no uid.
    with _server(_CmdiExec) as base:
        assert _confirms(CMDI_REFLECTED, base)


def test_does_not_confirm_on_reflection_only() -> None:
    # `;id` is reflected but never executed -> no uid output -> must NOT confirm.
    with _server(_ReflectOnly) as base:
        assert not _confirms(CMDI_REFLECTED, base)


def test_does_not_confirm_on_hardened_twin() -> None:
    # the hardened validator refuses the break-out (and uses argv for a valid host) -> no uid -> silent.
    with _server(_Hardened) as base:
        assert not _confirms(CMDI_REFLECTED, base)


def test_does_not_confirm_on_static_uid_page() -> None:
    # a page that prints uid regardless of input -> marker also in the benign control -> control
    # attribution refuses it (a LEAD, never a FACT).
    with _server(_StaticUid) as base:
        assert not _confirms(CMDI_REFLECTED, base)


def test_anchored_signature_rejects_echoed_lookalike() -> None:
    # the anchored regex must not match an echoed benign value like `fluid=1000(` / `squid=5(`.
    from framework.v2.scanner.checks import _CMDI_UID_RE
    assert _CMDI_UID_RE.search("uid=1000(kali)")
    assert _CMDI_UID_RE.search("groups output\nuid=0(root) gid=0(root)")
    assert not _CMDI_UID_RE.search("fluid=1000(x) squid=5(y) druid=1000(z)")
    assert not _CMDI_UID_RE.search("uid=abc(no-digits)")


def _point(param: str):
    """One QUERY_VALUE insertion point named ``param`` on a dummy loopback URL."""
    tmpl = RequestTemplate(HttpRequest(method="GET", url=f"http://127.0.0.1:1/p?{param}=x"))
    (pt,) = [p for p in tmpl.insertion_points(kinds=(InsertionKind.QUERY_VALUE,)) if p.name == param]
    return pt


def test_targeting_selects_cmdi_reflected_alongside_oob_on_command_sinks() -> None:
    # REGRESSION LOCK: the in-band cmdi check must NOT be shadowed behind the OOB cmdi check on the
    # targeted/autonomous path. select_checks dedups per (bug_class, channel), so a command-sink param
    # keeps BOTH the OOB (rce-oob) and the in-band (cmdi-reflected) command_injection checks.
    from framework.v2.scanner.checks import DEFAULT_CHECKS
    from framework.v2.scanner.targeting import select_checks
    for param in ("host", "cmd", "hostname", "ip", "command"):
        ids = [c.id for c in select_checks(_point(param), DEFAULT_CHECKS)]
        assert "cmdi-reflected" in ids, f"{param}: in-band cmdi shadowed out; selected={ids}"
        assert "rce-oob" in ids, f"{param}: OOB cmdi dropped; selected={ids}"


def test_targeting_does_not_select_cmdi_on_unrelated_param() -> None:
    # an id= param hints idor/boolean_sqli (+ the reflection classes), never command_injection.
    from framework.v2.scanner.checks import DEFAULT_CHECKS
    from framework.v2.scanner.targeting import select_checks
    ids = [c.id for c in select_checks(_point("id"), DEFAULT_CHECKS)]
    assert "cmdi-reflected" not in ids and "rce-oob" not in ids, f"cmdi should not target id=; got {ids}"
