"""
In-band (reflected-output) OS command injection is a LEAD, not a FACT — the computed-product signal a
benign CALCULATOR fakes.

CmdiReflectedCheck injects a shell break-out that makes a vulnerable sink COMPUTE an unguessable product
(``host=127.0.0.1;echo $((N1*N2))``) and confirms via side_effect over a benign ``127.0.0.1`` control. The
marker defeats pure reflection (the product VALUE is absent from the payload) and a documented-signature KB
(the product is per-build random, unlike ``id``'s ``uid=0(root)``) — but it does NOT defeat a benign
ARITHMETIC EVALUATOR: a calculator / instant-answer / ``$(( ))`` config-expander computes ``$((N1*N2))`` from
the input exactly as a shell does, with the product absent from the plain ``127.0.0.1`` control, so the
side_effect confirmation FIRES on it (``test_calculator_false_confirms_so_cmdi_reflected_is_lead_only`` — the
rate-1.0 red-pen FP). An in-band computed product therefore cannot distinguish shell execution from app math.

CONSEQUENCE: CmdiReflectedCheck is NOT in DEFAULT_CHECKS and command_injection.reflected_output is
fact_capable=false — the check is a LEAD driver (it flags the sink with a VIGIL-owned capture). The SOUND
command-injection FACTs are the dose-scaled TIMING channel (library w4b-time-cmdi-sleep →
time_based_command_injection; integration/tests/test_cmdi_timing_redrive.py) and the blind OOB curl callback
(library w4b-time-cmdi-oob-curl) — execution-provenance channels a calculator cannot reproduce. This file
pins the check's oracle behaviour (what it fires and does not fire on) and the calculator FP that makes it
lead-only.

The fixtures GENUINELY EXECUTE (subprocess, shell=True) so a positive is a real property of execution, and
the calculator fixture GENUINELY evaluates the arithmetic — neither is canned text.
"""

from __future__ import annotations

import contextlib
import re as _re
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator
from urllib.parse import parse_qs, urlsplit

from framework.v2.scanner.checks import CMDI_REFLECTED, CmdiReflectedCheck, _CMDI_N1, _CMDI_N2
from framework.v2.scanner.cli import loopback_send
from framework.v2.scanner.insertion import HttpRequest, InsertionKind, RequestTemplate
from framework.v2.verify.confirmation import confirm_finding
from framework.v2.verify.verifier import OracleVerifier

_PRODUCT = str(_CMDI_N1 * _CMDI_N2)                       # the value only a shell computes
_HOSTNAME_RE = _re.compile(r"^[A-Za-z0-9.\-]{1,253}$")    # the hardened twin's strict host gate


def _host(path: str) -> str:
    return parse_qs(urlsplit(path).query).get("host", [""])[0]


def _send200(handler: BaseHTTPRequestHandler, body: bytes) -> None:
    handler.send_response(200)
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class _CmdiExec(BaseHTTPRequestHandler):
    """VULNERABLE: concatenates host into a shell string and reflects stdout/stderr. The injected
    ``$((N1*N2))`` is GENUINELY COMPUTED by the shell (shell=True), so the product is real execution output.
    ``echo`` is the benign base (instant, always present) — the vuln is the shell concatenation."""

    def log_message(self, *a: object) -> None:
        return

    def _run(self, host: str) -> str:
        try:
            cp = subprocess.run("echo reached " + host, shell=True, capture_output=True, text=True, timeout=5)
            return (cp.stdout or "") + (cp.stderr or "")
        except Exception as exc:  # noqa: BLE001
            return f"error: {exc}"

    def do_GET(self) -> None:  # noqa: N802
        out = self._run(_host(self.path))
        _send200(self, f"<pre class=\"console\">$ echo reached {_host(self.path)}\n{out}</pre>".encode())


class _ReflectsRaw(_CmdiExec):
    """NOT vulnerable: echoes the raw host verbatim and executes NOTHING. The raw ``$((N1*N2))`` survives but
    the PRODUCT is never computed, so it must NOT fire (reflection != execution)."""

    def do_GET(self) -> None:  # noqa: N802
        _send200(self, f"<p>You asked to ping: {_host(self.path)}</p>".encode())


class _Hardened(_CmdiExec):
    """HARDENED twin: a strict validator refuses any break-out before a shell runs; a valid host goes through
    argv (shell=False), so no metacharacter is interpreted and the product is never computed."""

    def do_GET(self) -> None:  # noqa: N802
        host = _host(self.path)
        if not _HOSTNAME_RE.match(host):
            _send200(self, f"Refused: {host} is not a valid hostname or IP address".encode())
            return
        try:
            cp = subprocess.run(["echo", "reached", host], capture_output=True, text=True, timeout=5)
            _send200(self, ((cp.stdout or "") + (cp.stderr or "")).encode())
        except Exception as exc:  # noqa: BLE001
            _send200(self, f"error: {exc}".encode())


class _StaticProduct(_CmdiExec):
    """Prints the product on EVERY request regardless of input (a contrived status page). The marker is then
    present under the payload AND the benign control, so the control-attribution guard must REFUSE."""

    def do_GET(self) -> None:  # noqa: N802
        _send200(self, f"<pre>build id {_PRODUCT}; you requested {_host(self.path)}</pre>".encode())


class _CmdiKb(_CmdiExec):
    """THE path_traversal-analog (the decisive soundness test). A benign security-docs search that returns
    the command-injection ARTICLE — which contains the DOCUMENTED ``uid=0(root)`` PoC output — whenever the
    query looks like a cmdi payload, and a generic page otherwise. It reads NO shell and computes NOTHING.
    The OLD ``uid=``-signature signal would FALSE-FIRE here (uid=0(root) present under the ``;``-payload,
    absent from the benign control); the computed-PRODUCT signal does NOT, because the KB cannot produce the
    unguessable product."""

    def do_GET(self) -> None:  # noqa: N802
        host = _host(self.path)
        if any(t in host for t in (";", "|", "`", "$(", "id", "expr", "echo", "command")):
            body = (b"<article>Command injection (CWE-78): e.g. <code>;id</code> returns "
                    b"<code>uid=0(root) gid=0(root) groups=0(root)</code>. Never pass input to a shell.</article>")
        else:
            body = b"<p>host status: ok</p>"
        _send200(self, body)


class _Calculator(_CmdiExec):
    """BENIGN arithmetic evaluator — the DECISIVE false positive (the red-pen FP). It extracts a ``$((A*B))``
    expression from the input and emits the PRODUCT (an instant-answer box / config ``$(( ))`` expander),
    executing NO shell. It reproduces the EXACT marker CmdiReflectedCheck confirms on — the product present
    under the payload and absent from the plain ``127.0.0.1`` control — so side_effect FIRES exactly as it
    does on a real shell. This is why an in-band computed product is a LEAD, never a scan-route FACT."""

    _ARITH = _re.compile(r"\$\(\((\d+)\s*\*\s*(\d+)\)\)")

    def do_GET(self) -> None:  # noqa: N802
        host = _host(self.path)
        m = self._ARITH.search(host)
        if m:
            _send200(self, f"<p>= {int(m.group(1)) * int(m.group(2))}</p>".encode())
            return
        _send200(self, f"<p>you asked: {host}</p>".encode())


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
    """Drive the check through the REAL oracle pipeline (confirm_finding + OracleVerifier), exactly as the
    scanner engine does — True iff a command_injection FACT is confirmed."""
    tmpl = RequestTemplate(HttpRequest(method="GET", url=f"{base}/ping?host=x"))
    (pt,) = [p for p in tmpl.insertion_points(kinds=(InsertionKind.QUERY_VALUE,)) if p.name == "host"]
    ctx = check.probe(tmpl, pt, loopback_send)
    if ctx is None:
        return False
    return confirm_finding(
        finding={"bug_class": check.bug_class, "title": "t", "severity": "High",
                 "surface": "s", "summary": "x"},
        context=ctx, verifier=OracleVerifier()) is not None


def test_confirms_on_genuine_computed_product() -> None:
    # host=127.0.0.1;echo $((N1*N2)) GENUINELY computes the product; benign 127.0.0.1 does not. The check's
    # oracle fires here — but it fires identically on a benign calculator (below), which is why this channel
    # is a LEAD driver (not in DEFAULT_CHECKS, fact_capable=false), not a sound FACT minter.
    with _server(_CmdiExec) as base:
        assert _confirms(CMDI_REFLECTED, base)


def test_does_not_confirm_on_raw_reflection() -> None:
    # the raw $((N1*N2)) is echoed but never computed -> product absent -> must NOT confirm.
    with _server(_ReflectsRaw) as base:
        assert not _confirms(CMDI_REFLECTED, base)


def test_does_not_confirm_on_hardened_twin() -> None:
    # the hardened validator refuses the break-out (and uses argv) -> no product -> silent.
    with _server(_Hardened) as base:
        assert not _confirms(CMDI_REFLECTED, base)


def test_does_not_confirm_on_static_product_page() -> None:
    # a page that prints the product regardless of input -> marker also in the benign control -> control
    # attribution refuses it (a LEAD, never a FACT).
    with _server(_StaticProduct) as base:
        assert not _confirms(CMDI_REFLECTED, base)


def test_kb_documenting_cmdi_does_not_false_fact() -> None:
    # A benign cmdi-documentation search (the path_traversal KB analog) emits uid=0(root) correlated with the
    # payload but CANNOT produce the unguessable computed product -> must NOT confirm. The product signal is
    # KB-proof where the old uid=-signature signal was not. (It is NOT calculator-proof — see below.)
    with _server(_CmdiKb) as base:
        assert not _confirms(CMDI_REFLECTED, base)


def test_calculator_false_confirms_so_cmdi_reflected_is_lead_only() -> None:
    # THE DECISIVE SOUNDNESS BOUND (the rate-1.0 red-pen FP): a benign arithmetic evaluator COMPUTES
    # $((N1*N2)) from the input — product present under the payload, ABSENT from the plain 127.0.0.1 control —
    # so the in-band side_effect confirmation FIRES exactly as it does on a real shell. An in-band computed
    # product cannot distinguish shell execution from app math; that is WHY CmdiReflectedCheck is a LEAD
    # driver excluded from DEFAULT_CHECKS and command_injection.reflected_output is fact_capable=false. The
    # SOUND cmdi FACT is the dose-scaled timing channel (time_based_command_injection) + the OOB curl callback.
    with _server(_Calculator) as base:
        assert _confirms(CMDI_REFLECTED, base), (
            "a benign calculator must reproduce the in-band product FP — this is the soundness hole that "
            "makes the computed-product channel lead-only; if it stops firing, re-evaluate the DEFAULT_CHECKS "
            "exclusion and the fact_capable=false matrix branch")


def _point(param: str):
    """One QUERY_VALUE insertion point named ``param`` on a dummy loopback URL."""
    tmpl = RequestTemplate(HttpRequest(method="GET", url=f"http://127.0.0.1:1/p?{param}=x"))
    (pt,) = [p for p in tmpl.insertion_points(kinds=(InsertionKind.QUERY_VALUE,)) if p.name == param]
    return pt


def test_targeting_selects_oob_cmdi_on_command_sinks() -> None:
    # The sound in-band cmdi channel is NOT in DEFAULT_CHECKS (the computed product is calculator-fakeable, a
    # LEAD). On the targeted/autonomous path a command-sink param selects the OOB cmdi check (rce-oob, the
    # sound blind channel); the in-band CMDI_REFLECTED is deliberately absent from DEFAULT_CHECKS.
    from framework.v2.scanner.checks import CMDI_REFLECTED, DEFAULT_CHECKS
    from framework.v2.scanner.targeting import select_checks
    assert CMDI_REFLECTED not in DEFAULT_CHECKS, "in-band cmdi must not be a DEFAULT_CHECKS fact-minter (lead-only)"
    for param in ("host", "cmd", "hostname", "ip", "command"):
        ids = [c.id for c in select_checks(_point(param), DEFAULT_CHECKS)]
        assert "rce-oob" in ids, f"{param}: OOB cmdi dropped; selected={ids}"
        assert "cmdi-reflected" not in ids, f"{param}: in-band cmdi must be lead-only, not selected; got {ids}"


def test_targeting_does_not_select_cmdi_on_unrelated_param() -> None:
    # an id= param hints idor/boolean_sqli (+ the reflection classes), never command_injection.
    from framework.v2.scanner.checks import DEFAULT_CHECKS
    from framework.v2.scanner.targeting import select_checks
    ids = [c.id for c in select_checks(_point("id"), DEFAULT_CHECKS)]
    assert "cmdi-reflected" not in ids and "rce-oob" not in ids, f"cmdi should not target id=; got {ids}"
