"""W6-5 — the GATEWAY plane emits structured JSON through the shared redaction processor.

Before W6-5 the host gateway used a bare ``logging.basicConfig`` (plain text, no redaction). Its CLI now
installs the shared ``vigil_core.logging_setup`` handler (``_configure_logging``), so — per plane — its
logs are JSON, a bearer token / Authorization header / cookie is redacted, and non-secret context
survives. ``vigil_core`` is co-installed in the offense environment the gateway runs in.
"""
from __future__ import annotations

import io
import json
import logging

from vigil_gateway.cli import _configure_logging


def _run_and_capture(verbose=False):
    root = logging.getLogger()
    for h in list(root.handlers):
        if getattr(h, "name", None) == "vigil-gateway":
            root.removeHandler(h)
    _configure_logging(verbose)
    # redirect the shared handler's stream to a buffer to capture the line deterministically
    buf = io.StringIO()
    handler = next(h for h in root.handlers if getattr(h, "name", None) == "vigil-gateway")
    handler.setStream(buf)  # type: ignore[attr-defined]
    return logging.getLogger("vigil-gateway.test"), buf


def test_gateway_logs_are_json_and_redacted():
    log, buf = _run_and_capture(verbose=True)
    log.warning("proxy denied Authorization: Bearer GW-LEAK-TOKEN Cookie: sid=GW-LEAK-COOKIE",
                extra={"x-api-key": "GW-STRUCT-LEAK", "host": "example.test"})
    line = buf.getvalue().strip().splitlines()[-1]
    rec = json.loads(line)                        # well-formed JSON
    assert "GW-LEAK-TOKEN" not in line            # bearer masked
    assert "GW-LEAK-COOKIE" not in line           # cookie masked
    assert "GW-STRUCT-LEAK" not in line           # secret-keyed extra masked
    assert rec["host"] == "example.test"          # NEGATIVE control: non-secret survives


def test_gateway_installs_a_single_named_handler():
    _run_and_capture(verbose=False)
    root = logging.getLogger()
    named = [h for h in root.handlers if getattr(h, "name", None) == "vigil-gateway"]
    assert len(named) == 1                         # idempotent single handler, not a basicConfig stack
