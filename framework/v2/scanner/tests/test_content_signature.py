"""
Path traversal / LFI confirmed by FILE CONTENT, not reflection.

The old path-traversal check planted a marker and looked for it reflected — which
proves input is echoed, not that a file was read. ContentSignatureCheck injects a
traversal and confirms only when a distinctive signature of the target file's
content (root:x:0:0:) actually appears. So a sink that RETURNS the file confirms,
while a sink that merely REFLECTS the path does not.
"""

from __future__ import annotations

import contextlib
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator
from urllib.parse import parse_qs, urlsplit

from framework.v2.scanner.checks import ContentSignatureCheck
from framework.v2.scanner.cli import loopback_send
from framework.v2.scanner.insertion import HttpRequest, InsertionKind, RequestTemplate
from framework.v2.scanner.library import compile_entry, load_library
from framework.v2.verify.confirmation import confirm_finding
from framework.v2.verify.verifier import OracleVerifier

_PASSWD = "root:x:0:0:root:/root:/bin/bash\n"


class _FileRead(BaseHTTPRequestHandler):
    """Real path traversal: a traversal reads /etc/passwd (returns file content,
    does NOT reflect the raw path)."""

    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        name = parse_qs(urlsplit(self.path).query).get("name", [""])[0]
        body = _PASSWD.encode() if "etc/passwd" in name else b"<p>ordinary document</p>"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _ReflectOnly(_FileRead):
    """Reflects the raw path back but reads no file — NOT a traversal (the old
    marker-reflection check would wrongly like this; the content check must not)."""

    def do_GET(self) -> None:  # noqa: N802
        name = parse_qs(urlsplit(self.path).query).get("name", [""])[0]
        body = f"<p>You requested: {name}</p>".encode()
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


def _confirms(check: ContentSignatureCheck, base: str) -> bool:
    tmpl = RequestTemplate(HttpRequest(method="GET", url=f"{base}/file?name=x"))
    (pt,) = [p for p in tmpl.insertion_points(kinds=(InsertionKind.QUERY_VALUE,)) if p.name == "name"]
    ctx = check.probe(tmpl, pt, loopback_send)
    if ctx is None:
        return False
    return confirm_finding(
        finding={"bug_class": check.bug_class, "title": "t", "severity": "High",
                 "surface": "s", "summary": "x"},
        context=ctx, verifier=OracleVerifier()) is not None


def test_confirms_on_real_file_read() -> None:
    check = ContentSignatureCheck(id="t", bug_class="path_traversal",
                                  payload="../../../../etc/passwd", signature="root:x:0:0:")
    with _server(_FileRead) as base:
        assert _confirms(check, base)


def test_does_not_confirm_on_reflection_only() -> None:
    # the payload IS reflected here, but no file is read -> must NOT confirm
    check = ContentSignatureCheck(id="t", bug_class="path_traversal",
                                  payload="../../../../etc/passwd", signature="root:x:0:0:")
    with _server(_ReflectOnly) as base:
        assert not _confirms(check, base)


def test_library_lfi_entries_compile_and_confirm() -> None:
    lfi = [e for e in load_library() if e.id.startswith("h1-lfi-")]
    assert len(lfi) >= 6
    assert all(e.oracle.kind == "content" for e in lfi)
    rep = next(e for e in lfi if e.id == "h1-lfi-etc-passwd")
    with _server(_FileRead) as base:
        assert _confirms(compile_entry(rep), base)
    with _server(_ReflectOnly) as base:
        assert not _confirms(compile_entry(rep), base)
