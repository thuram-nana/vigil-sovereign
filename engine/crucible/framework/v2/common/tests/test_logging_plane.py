"""W6-5 — the OFFENSE plane, per plane, redacts through the SHARED helper and honours VIGIL_LOG_LEVEL.

The offense engine already emitted structured JSON with rotation; W6-5 points its redaction at the ONE
shared ``vigil_core.redact`` (via the re-export shim) and its level at the ONE ``VIGIL_LOG_LEVEL``. This
is the offense-plane leg of the cross-plane negative control: a bearer token, an Authorization header and
a cookie logged through the real structlog pipeline never reach disk, while non-secret context does.
"""
from __future__ import annotations

import json

from framework.v2.common import logging as v2log
from framework.v2.common import redact


def test_offense_pipeline_masks_bearer_authorization_cookie(tmp_path, monkeypatch) -> None:
    log_file = tmp_path / "eng" / ".crucible-v2.log"
    monkeypatch.setattr(v2log, "_engagement_log_path", lambda: log_file)
    v2log.configure()
    log = v2log.get_logger("test.w6.offense")
    log.info("http.request",
             authorization="Bearer OFF-LEAK-TOKEN",
             cookie="session=OFF-LEAK-COOKIE",
             url="http://127.0.0.1/pay", status=200)
    body = log_file.read_text(encoding="utf-8")
    rec = json.loads(body.strip().splitlines()[-1])   # well-formed JSON
    assert "OFF-LEAK-TOKEN" not in body               # bearer masked before disk
    assert "OFF-LEAK-COOKIE" not in body              # cookie masked before disk
    assert rec["authorization"] == redact.MASK
    assert rec["cookie"] == redact.MASK
    assert rec["url"] == "http://127.0.0.1/pay" and rec["status"] == 200   # NEGATIVE control


def test_offense_level_resolves_from_the_unified_var(tmp_path, monkeypatch) -> None:
    # The offense structlog wrapper's level now comes from the shared resolver, so the ONE VIGIL_LOG_LEVEL
    # governs the offense plane too. Verified through the real pipeline: at ERROR an info() is dropped by
    # the filtering bound logger before it can reach disk, while error() lands.
    log_file = tmp_path / "eng" / ".crucible-v2.log"
    monkeypatch.setattr(v2log, "_engagement_log_path", lambda: log_file)
    monkeypatch.delenv("SIGIL_LOG_LEVEL", raising=False)
    monkeypatch.setenv("VIGIL_LOG_LEVEL", "ERROR")
    v2log.configure()
    log = v2log.get_logger("test.w6.level")
    log.info("below.threshold", n=1)
    log.error("at.threshold", n=2)
    body = log_file.read_text(encoding="utf-8") if log_file.exists() else ""
    assert "below.threshold" not in body       # INFO filtered out by the unified level
    assert "at.threshold" in body              # ERROR emitted
