"""
AEGIS G6 — the "add it in the form of an API or another way" surfaces:

  * inspect_http  — the sidecar detect API (any language POSTs a request description, gets a verdict
    it enforces itself),
  * AegisEnforceMiddleware — the in-process WSGI middleware (lowest latency; blocks a proven attack
    before the app sees it, buffering+restoring the body so the app reads it normally),
  * the `aegis gateway` CLI subcommand registration.

The through-line: a BLOCK rides only on a CONFIRMED verdict + a re-runnable certificate; observe is
read-only; malformed input fails closed; everything else passes through (fail-open).
"""

from __future__ import annotations

import io
import json

import pytest

from framework.v2.aegis.middleware import AegisEnforceMiddleware, inspect_http
from framework.v2.aegis.models import AegisConfig

_SQLI_PATH = "/s?q=" + "%27%20OR%20%271%27%3D%271"   # ' OR '1'='1


# --------------------------------------------------------------------------- inspect_http (API)

def test_api_proves_and_blocks_a_sqli_with_a_reverifiable_certificate():
    status, v = inspect_http(json.dumps({"method": "GET", "path": _SQLI_PATH, "headers": []}),
                             enforce=True)
    assert status == 200 and v["decision"] == "confirmed" and v["action"] == "block"
    assert v["attack_class"] == "sqli_attempt"
    from framework.v2.aegis.models import CertRef
    assert CertRef(**v["certificate"]).reverify() is True


def test_api_allows_benign_and_is_clear_not_safe():
    status, v = inspect_http(json.dumps({"method": "GET", "path": "/s?q=O%27Brien", "headers": []}),
                             enforce=True)
    assert status == 200 and v["decision"] == "clear" and v["action"] == "allow"


def test_api_observe_never_sets_block():
    status, v = inspect_http(json.dumps({"method": "GET", "path": _SQLI_PATH, "headers": []}),
                             enforce=False)
    # still confirmed (detection is honest) but the action is observe, not block.
    assert status == 200 and v["decision"] == "confirmed" and v["action"] == "observe"


def test_api_accepts_headers_as_dict_or_list():
    for headers in ({"Content-Type": "application/json"}, [["Content-Type", "application/json"]]):
        status, v = inspect_http(json.dumps({
            "method": "POST", "path": "/login",
            "headers": headers,
            "body": json.dumps({"user": "$(cat /etc/passwd)"})}), enforce=True)
        assert status == 200 and v["attack_class"] == "command_injection_attempt"


def test_api_malformed_input_fails_closed_400():
    status, v = inspect_http("{ not json", enforce=True)
    assert status == 400 and v["error"] == "bad_request"


# --------------------------------------------------------------------------- WSGI enforce middleware

def _app(environ, start_response):
    body = environ["wsgi.input"].read()           # proves the body survived buffering
    resp = f"APP-OK bodylen={len(body)}".encode()
    start_response("200 OK", [("Content-Type", "text/plain"), ("Content-Length", str(len(resp)))])
    return [resp]


def _call(mw, method, path, qs="", body=b""):
    environ = {"REQUEST_METHOD": method, "PATH_INFO": path, "QUERY_STRING": qs,
               "CONTENT_LENGTH": str(len(body)), "wsgi.input": io.BytesIO(body)}
    cap: dict = {}

    def sr(status, headers):
        cap["status"] = status
        cap["headers"] = dict(headers)
    out = b"".join(mw(environ, sr))
    return cap["status"], cap.get("headers", {}), out


def test_wsgi_enforce_blocks_a_proven_attack_before_the_app():
    mw = AegisEnforceMiddleware(_app, AegisConfig(deployment_secret="k", mode="enforce"))
    status, headers, out = _call(mw, "GET", "/s", "q=%27%20OR%20%271%27%3D%271")
    assert status.startswith("403") and headers.get("X-Aegis-Block") == "sqli_attempt"
    assert headers.get("X-Aegis-Certificate", "").startswith("aegis-cert:")
    assert b"APP-OK" not in out   # the app never saw the malicious request


def test_wsgi_enforce_passes_benign_and_restores_the_body():
    mw = AegisEnforceMiddleware(_app, AegisConfig(deployment_secret="k", mode="enforce"))
    status, _h, out = _call(mw, "GET", "/s", "q=laptop")
    assert status.startswith("200") and b"APP-OK" in out
    # a POST body is buffered for inspection and RESTORED so the app reads it.
    status, _h, out = _call(mw, "POST", "/upload", "", b"payload-bytes-here")
    assert status.startswith("200") and b"bodylen=18" in out


def test_wsgi_observe_mode_never_blocks():
    mw = AegisEnforceMiddleware(_app, AegisConfig(deployment_secret="k", mode="observe"))
    status, _h, out = _call(mw, "GET", "/s", "q=%27%20OR%20%271%27%3D%271")
    assert status.startswith("200") and b"APP-OK" in out


# --------------------------------------------------------------------------- CLI

def test_gateway_subcommand_is_registered():
    import argparse
    import contextlib

    from framework.v2.aegis import cli
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), pytest.raises(SystemExit):
        cli.main(["gateway", "--help"])
    help_text = buf.getvalue()
    assert "--upstream" in help_text and "--mode" in help_text
