"""W6-5 — the SOVEREIGN plane emits structured JSON through the shared redaction processor.

Before W6-5, SIGIL logged plain text to stderr with NO redaction mechanism (only a docstring
convention). This asserts the sovereign plane now, per plane, (a) emits well-formed JSON, (b) redacts a
bearer token, an Authorization header and a cookie whether they ride the message or a structured field,
(c) leaves non-secret context intact (the negative control that proves it is not a blanket no-op), and
(d) honours the single VIGIL_LOG_LEVEL.
"""
from __future__ import annotations

import io
import json

from sigil import obs


def _emit(level="DEBUG"):
    buf = io.StringIO()
    obs.configure_logging(level=level, stream=buf, force=True)
    return obs.get_logger("sigil.test.redaction"), buf


def test_sovereign_logs_are_well_formed_json():
    log, buf = _emit()
    log.info("cockpit ready")
    rec = json.loads(buf.getvalue().strip())
    assert rec["level"] == "INFO" and rec["logger"] == "sigil.test.redaction"
    assert rec["msg"] == "cockpit ready"


def test_sovereign_redacts_bearer_authorization_and_cookie():
    log, buf = _emit()
    log.warning("upstream call Authorization: Bearer SV-LEAK-TOKEN with Cookie: session=SV-LEAK-COOKIE",
                extra={"authorization": "Bearer STRUCT-LEAK", "route": "/api/whoami"})
    line = buf.getvalue().strip()
    rec = json.loads(line)
    assert "SV-LEAK-TOKEN" not in line       # bearer in message masked
    assert "SV-LEAK-COOKIE" not in line      # cookie in message masked
    assert "STRUCT-LEAK" not in line         # secret-keyed extra masked
    assert rec["route"] == "/api/whoami"     # NEGATIVE control: non-secret context survives


def test_single_level_var_governs_the_sovereign_plane(monkeypatch):
    monkeypatch.delenv("SIGIL_LOG_LEVEL", raising=False)
    monkeypatch.setenv("VIGIL_LOG_LEVEL", "ERROR")
    buf = io.StringIO()
    obs.configure_logging(stream=buf, force=True)   # resolve level from env
    log = obs.get_logger("sigil.test.level")
    log.info("below-threshold")
    log.error("at-threshold")
    out = buf.getvalue()
    assert "below-threshold" not in out and "at-threshold" in out
