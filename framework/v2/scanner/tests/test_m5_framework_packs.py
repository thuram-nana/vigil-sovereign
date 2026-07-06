"""
M5a — framework/CMS exposure packs: a known-path signature confirmed by the
predicate oracle, run once per host as a request-level library check.

A PathProbeCheck fetches a fixed path (e.g. /.git/config, /actuator/env) and
confirms exposure ONLY when a distinctive signature appears — not on a 404 and
not on a signature-less 200 (precision). The campaign runs these as request-level
checks so a WordPress/Spring/Laravel exposure surfaces in a normal scan.
"""

from __future__ import annotations

import contextlib
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator

from framework.v2.scanner.campaign import WebScanCampaign
from framework.v2.scanner.checks import PathProbeCheck
from framework.v2.scanner.cli import loopback_send
from framework.v2.scanner.insertion import HttpRequest, RequestTemplate
from framework.v2.scanner.library import load_library, split_checks
from framework.v2.verify.confirmation import confirm_finding
from framework.v2.verify.verifier import OracleVerifier

_EXPOSED = {
    "/.git/config": "[core]\n\trepositoryformatversion = 0\n",
    "/actuator/env": '{"propertySources":[{"name":"systemEnvironment"}]}',
    "/decoy": "a perfectly ordinary page with no secrets",
}


class _App(BaseHTTPRequestHandler):
    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        from urllib.parse import urlsplit
        path = urlsplit(self.path).path
        if path == "/":
            body = b"<html>home</html>"
            status = 200
        elif path in _EXPOSED:
            body = _EXPOSED[path].encode()
            status = 200
        else:
            body = b"not found"
            status = 404
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@contextlib.contextmanager
def _server() -> Iterator[str]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _App)
    srv.daemon_threads = True
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()
        th.join(timeout=5)


def _confirms(check: PathProbeCheck, base: str) -> bool:
    tmpl = RequestTemplate(HttpRequest(method="GET", url=base + "/"))
    ctx = check.probe(tmpl, loopback_send)
    if ctx is None:
        return False
    return confirm_finding(
        finding={"bug_class": check.bug_class, "title": "t", "severity": "High",
                 "surface": "s", "summary": "x"},
        context=ctx, verifier=OracleVerifier()) is not None


def test_path_probe_confirms_only_on_the_real_signature() -> None:
    with _server() as base:
        # exposed path with its distinctive signature -> confirmed
        assert _confirms(PathProbeCheck(id="g", bug_class="exposure",
                                        probe_path="/.git/config", signature="repositoryformatversion"), base)
        assert _confirms(PathProbeCheck(id="a", bug_class="exposure",
                                        probe_path="/actuator/env", signature="propertySources"), base)
        # a 404 path -> not confirmed
        assert not _confirms(PathProbeCheck(id="x", bug_class="exposure",
                                            probe_path="/nope", signature="anything"), base)
        # a 200 page WITHOUT the signature -> not confirmed (precision)
        assert not _confirms(PathProbeCheck(id="d", bug_class="exposure",
                                            probe_path="/decoy", signature="repositoryformatversion"), base)


def test_shipped_framework_packs_compile_to_request_level_checks() -> None:
    fw = [e for e in load_library() if e.id.startswith("m5-fw-")]
    assert len(fw) >= 15
    point, request = split_checks(fw)
    assert not point and len(request) == len(fw)  # all request-level
    assert all(isinstance(c, PathProbeCheck) for c in request)


def test_campaign_runs_framework_pack_and_confirms_exposure() -> None:
    git_entry = [e for e in load_library() if e.id == "m5-fw-git-config"]
    with _server() as base:
        report = WebScanCampaign(
            loopback_send, max_pages=5, enable_oob=False,
            use_library=True, library_entries=git_entry,
        ).run(base + "/")
        exposures = [f for f in report.active_findings if f.bug_class == "exposure"]
        assert exposures, "framework-pack exposure not confirmed in the campaign"
        assert exposures[0].oracle_context is not None  # carries a re-verifiable cert
