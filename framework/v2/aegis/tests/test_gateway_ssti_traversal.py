"""
AEGIS Gateway — SSTI (server-side template injection) and path-traversal response-side block-paths.

Both prove EXPLOITATION from the app's OWN answer, so the gateway forwards, holds the response, runs
the response-side effect oracle over it, and withholds it only on a CONFIRMED verdict:

  * SSTI is BLOCKED only when the server EVALUATED the injected template expression (the response
    shows the computed result, the raw expression is GONE — ``evaluation_oracle``). A reflected /
    HTML-encoded template (the raw `{{7*7}}` survives) is NOT blocked — near-zero FP.
  * path traversal is BLOCKED only when a strict `/etc/passwd` root-line signature surfaces in the
    response AND the request value carried a `../`-style traversal payload. A benign request never
    enters the path; a benign page never carries a uid/gid-0 root line — near-zero FP.
  * every block carries a certificate that re-runs offline (``CertRef.reverify``).

The upstreams below are deliberately vulnerable stand-ins for the operator's own app so the
end-to-end proxy-and-confirm path is exercised over real sockets.
"""

from __future__ import annotations

import html as _html
import http.server
import re
import socketserver
import threading
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator

import pytest

from framework.v2.aegis.gateway import serve_gateway
from framework.v2.aegis.inspect import inspect_response
from framework.v2.aegis.models import AegisConfig, Verdict

# A canonical leaked /etc/passwd body.
_PASSWD = ("root:x:0:0:root:/root:/bin/bash\n"
           "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
           "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n")


class _VulnUpstream(http.server.BaseHTTPRequestHandler):
    """Deliberately vulnerable app: ?tpl=  is EVALUATED as a template (arithmetic computed), unless
    ?enc=1 (HTML-encoded) or ?reflect=1 (echoed verbatim, no evaluation). ?file= that walks the path
    toward /etc/passwd returns the passwd file; otherwise a benign page."""

    _ARITH = re.compile(r"(\d{1,6})\s*([*+])\s*(\d{1,6})")

    def log_message(self, *_a):
        return

    def _eval_tpl(self, tpl: str) -> str:
        # strip the template wrapper and compute the inner arithmetic — the SSTI sink.
        inner = tpl
        for l, r in (("{{", "}}"), ("${", "}"), ("#{", "}"), ("<%=", "%>"), ("*{", "}"), ("@(", ")")):
            if tpl.startswith(l) and tpl.endswith(r):
                inner = tpl[len(l):-len(r)]
                break
        m = self._ARITH.search(inner)
        if not m:
            return tpl
        a, op, b = int(m.group(1)), m.group(2), int(m.group(3))
        return str(a * b if op == "*" else a + b)

    def do_GET(self):
        qs = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query, keep_blank_values=True)
        tpl = (qs.get("tpl") or [""])[0]
        file_param = (qs.get("file") or [""])[0]
        if tpl:
            if "reflect" in qs:
                inner = tpl                                   # echoed verbatim (safe app)
            elif "enc" in qs:
                inner = _html.escape(tpl)                     # HTML-encoded (safe app)
            else:
                inner = self._eval_tpl(tpl)                   # EVALUATED (vulnerable)
            body = f"<html><body>result: {inner}</body></html>".encode()
        elif file_param and ("../" in file_param or "..\\" in file_param or "etc/passwd" in file_param):
            body = _PASSWD.encode()                           # served the file (vulnerable)
        else:
            body = b"<html><body>ok, 49 results</body></html>"  # benign page (note: contains '49')
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)


@pytest.fixture()
def vuln_upstream() -> Iterator[int]:
    srv = socketserver.TCPServer(("127.0.0.1", 0), _VulnUpstream)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield srv.server_address[1]
    finally:
        srv.shutdown()
        srv.server_close()


def _gateway(upstream_port: int, *, mode: str, sink: list | None = None):
    gw = serve_gateway(f"http://127.0.0.1:{upstream_port}",
                       config=AegisConfig(deployment_secret="k", mode=mode),
                       host="127.0.0.1", port=0,
                       on_verdict=(sink.append if sink is not None else None))
    threading.Thread(target=gw.serve_forever, daemon=True).start()
    return gw, gw.server_address[1]


def _hit(port: int, query: str):
    return urllib.request.urlopen(f"http://127.0.0.1:{port}/s?{query}", timeout=5)


_Q = urllib.parse.quote


# --------------------------------------------------------------------------- SSTI (1a)

def test_ssti_evaluated_expression_is_blocked_with_certificate(vuln_upstream):
    sink: list[Verdict] = []
    gw, port = _gateway(vuln_upstream, mode="enforce", sink=sink)
    try:
        with pytest.raises(urllib.error.HTTPError) as ei:
            _hit(port, "tpl=" + _Q("{{7*7}}"))
        assert ei.value.code == 403 and ei.value.headers.get("X-Aegis-Block") == "ssti"
        v = next(v for v in sink if v.decision == "confirmed" and v.attack_class == "ssti")
        assert v.certificate is not None and v.certificate.reverify() is True
    finally:
        gw.shutdown()


def test_ssti_dollar_wrapper_and_erb_are_blocked(vuln_upstream):
    gw, port = _gateway(vuln_upstream, mode="enforce")
    try:
        for payload in ("${1000*1000}", "<%= 31337+1 %>", "#{40*50}"):
            with pytest.raises(urllib.error.HTTPError) as ei:
                _hit(port, "tpl=" + _Q(payload))
            assert ei.value.code == 403 and ei.value.headers.get("X-Aegis-Block") == "ssti"
    finally:
        gw.shutdown()


def test_ssti_reflected_verbatim_is_NOT_blocked(vuln_upstream):
    """The app echoed `{{7*7}}` verbatim (no evaluation) — the raw expression survives, so the
    evaluation oracle correctly refuses. This is the near-zero-FP guarantee for SSTI."""
    gw, port = _gateway(vuln_upstream, mode="enforce")
    try:
        body = _hit(port, "tpl=" + _Q("{{7*7}}") + "&reflect=1").read().decode()
        assert "{{7*7}}" in body   # relayed unevaluated, not blocked
    finally:
        gw.shutdown()


def test_ssti_html_encoded_reflection_is_NOT_blocked(vuln_upstream):
    gw, port = _gateway(vuln_upstream, mode="enforce")
    try:
        body = _hit(port, "tpl=" + _Q("${7*7}") + "&enc=1").read().decode()
        assert "result:" in body   # encoded, relayed, not blocked
    finally:
        gw.shutdown()


def test_ssti_benign_template_variable_is_not_a_candidate(vuln_upstream):
    """`{{ user.name }}` / `${price}` are not PURE arithmetic, so they are not even SSTI candidates —
    even against the vulnerable app they are relayed (no coincidental evaluation to a magic number)."""
    gw, port = _gateway(vuln_upstream, mode="enforce")
    try:
        assert "result:" in _hit(port, "tpl=" + _Q("{{ user.name }}")).read().decode()
    finally:
        gw.shutdown()


# --------------------------------------------------------------------------- path traversal (1b)

def test_path_traversal_etc_passwd_is_blocked_with_certificate(vuln_upstream):
    sink: list[Verdict] = []
    gw, port = _gateway(vuln_upstream, mode="enforce", sink=sink)
    try:
        with pytest.raises(urllib.error.HTTPError) as ei:
            _hit(port, "file=" + _Q("../../../../etc/passwd"))
        assert ei.value.code == 403 and ei.value.headers.get("X-Aegis-Block") == "path_traversal"
        v = next(v for v in sink if v.decision == "confirmed" and v.attack_class == "path_traversal")
        assert v.certificate is not None and v.certificate.reverify() is True
    finally:
        gw.shutdown()


def test_benign_request_is_not_blocked_even_when_page_has_the_result_number(vuln_upstream):
    """The benign page contains '49' (the classic 7*7 result) but no template payload was sent and no
    passwd signature is present, so nothing fires — relayed untouched."""
    gw, port = _gateway(vuln_upstream, mode="enforce")
    try:
        assert "49 results" in _hit(port, "q=laptop").read().decode()
    finally:
        gw.shutdown()


# --------------------------------------------------------------------------- unit FP corpus

def _u(v: str) -> str:
    return "/s?" + urllib.parse.urlencode({"tpl": v})


def _uf(v: str) -> str:
    return "/s?" + urllib.parse.urlencode({"file": v})


def test_ssti_unit_fires_on_evaluation_only():
    # EVALUATED: result present, raw gone -> block.
    v = inspect_response(_u("{{7*7}}"), [], None, "<html>result: 49</html>", enforce=True)
    assert v is not None and v.attack_class == "ssti" and v.certificate.reverify()


def test_ssti_unit_zero_fp_corpus():
    # Each of these MUST NOT fire (near-zero FP).
    cases = [
        # reflected verbatim (raw survives)
        (_u("{{7*7}}"), "<html>result: {{7*7}}</html>"),
        # inner reflected without braces (still reflection, raw '7*7' present)
        (_u("{{7*7}}"), "<html>result: 7*7</html>"),
        # payload stripped, response has an UNRELATED number (not the computed 49)
        (_u("{{7*7}}"), "<html>result: 12 items</html>"),
        # benign input, benign page that merely contains '49'
        ("/s?q=laptop", "<html>ok, 49 results found</html>"),
        # a template variable (not arithmetic) — not a candidate
        (_u("{{ user.name }}"), "<html>result: alice</html>"),
        # single-digit result skipped as too coincidental
        (_u("{{1*1}}"), "<html>result: 1</html>"),
    ]
    for path, resp in cases:
        assert inspect_response(path, [], None, resp, enforce=True) is None, (path, resp)


def test_path_traversal_unit_fires_only_with_signature_and_traversal_request():
    # traversal request + passwd signature -> block.
    v = inspect_response(_uf("../../etc/passwd"), [], None, _PASSWD, enforce=True)
    assert v is not None and v.attack_class == "path_traversal" and v.certificate.reverify()


def test_path_traversal_unit_zero_fp_corpus():
    cases = [
        # passwd signature present but NO traversal payload in the request (a docs/paste page that
        # happens to show a passwd line) — not attributable, must not fire.
        ("/s?q=how+to+read+etc+passwd", _PASSWD),
        # traversal payload but a benign response (app resolved it safely / 404 text)
        (_uf("../../etc/passwd"), "<html>file not found</html>"),
        # a colon-separated line that is NOT a uid/gid-0 root passwd line
        (_uf("../../etc/passwd"), "<html>name:role:0:reader:active</html>"),
        # traversal payload, response mentions passwd but no root:x:0:0 line
        (_uf("../../etc/passwd"), "<html>Contents of /etc/passwd are protected</html>"),
    ]
    for path, resp in cases:
        assert inspect_response(path, [], None, resp, enforce=True) is None, (path, resp)


def test_observe_mode_forwards_but_emits_the_ssti_verdict(vuln_upstream):
    sink: list[Verdict] = []
    gw, port = _gateway(vuln_upstream, mode="observe", sink=sink)
    try:
        body = _hit(port, "tpl=" + _Q("{{13*13}}")).read().decode()
        assert "169" in body   # observe never blocks — the evaluated response is forwarded as-is
        assert any(v.decision == "confirmed" and v.attack_class == "ssti" for v in sink)
    finally:
        gw.shutdown()
