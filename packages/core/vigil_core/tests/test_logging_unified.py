"""W6-5 — the ONE shared logging setup: structured JSON, shared redaction, rotation, one level var.

This is the proving test the claims registry (W0-3 #398) cites for W6-5. It exercises the shared
``vigil_core.logging_setup`` + ``vigil_core.redact`` that all three planes now reuse:

  * structured JSON that is well-formed;
  * the shared redaction processor masks a bearer token, an Authorization header and a cookie —
    POSITIVE control — while a NON-secret field survives (the NEGATIVE control that proves the redactor
    is not a blanket no-op that would gut the audit trail);
  * ONE ``VIGIL_LOG_LEVEL`` takes effect, and the deprecated ``SIGIL_LOG_LEVEL`` is still honoured with a
    deprecation warning;
  * rotation with retention triggers and is size-bounded (the fix for the unbounded UI logs).

A tree WITHOUT this change has no ``vigil_core.logging_setup`` module, so this file fails at import —
the required "fails without the fix" property, observed by construction rather than assumed.
"""
from __future__ import annotations

import glob
import io
import json
import logging
import os
import stat
import warnings

import pytest

from vigil_core import logging_setup as L
from vigil_core import redact

_POSIX = os.name == "posix"


# ---------------------------------------------------------------- redaction (shared helper)
def test_scrub_masks_credentials_and_preserves_telemetry() -> None:
    # POSITIVE: every credential-keyed field masks (recursing into lists + dicts).
    out = redact.scrub_log_event({
        "authorization": "Bearer abc.def",
        "cookie": "sid=deadbeef",
        "api_key": "k",
        "nested": [{"set-cookie": "sid=x; HttpOnly"}],
        # NEGATIVE control: telemetry that merely contains a secret word is NOT masked.
        "tokens_in": 1234, "cache_key": "abc", "status": 200,
    })
    assert out["authorization"] == redact.MASK
    assert out["cookie"] == redact.MASK
    assert out["api_key"] == redact.MASK
    assert out["nested"][0]["set-cookie"] == redact.MASK
    assert out["tokens_in"] == 1234 and out["cache_key"] == "abc" and out["status"] == 200


def test_free_text_message_masking() -> None:
    # A secret riding the free-text message (not a structured field) is masked in every shape.
    msg = redact.redact_log_message(
        "auth Authorization: Bearer AKIA.SECRET.TOKEN then Cookie: session=zzz and password=hunter2"
    )
    assert "AKIA.SECRET.TOKEN" not in msg
    assert "zzz" not in msg
    assert "hunter2" not in msg
    # a bare bearer anywhere
    assert "topsecret" not in redact.redact_log_message("using Bearer topsecret now")
    # NEGATIVE control: an ordinary non-secret assignment is untouched.
    assert "count=3" in redact.redact_log_message("processed count=3 rows path=/tmp/x")


# ---------------------------------------------------------------- JSON formatter + redaction
def _capture(name: str, level: str = "DEBUG"):
    buf = io.StringIO()
    lg = logging.getLogger(name)
    for h in list(lg.handlers):
        lg.removeHandler(h)
    lg.propagate = False
    L.configure_logging(level=level, stream=buf, root=lg, force=True)
    return lg, buf


def test_output_is_well_formed_json_with_fields() -> None:
    lg, buf = _capture("t.json")
    lg.info("service ready")
    rec = json.loads(buf.getvalue().strip())
    assert rec["level"] == "INFO"
    assert rec["logger"] == "t.json"
    assert rec["msg"] == "service ready"
    assert "ts" in rec


def test_json_line_redacts_secret_message_and_extra() -> None:
    lg, buf = _capture("t.redact")
    lg.warning("sent Authorization: Bearer LEAKED-TOKEN-9f",
               extra={"cookie": "sid=LEAKED-COOKIE", "user": "alice", "count": 7})
    line = buf.getvalue().strip()
    rec = json.loads(line)                         # well-formed even with secrets present
    assert "LEAKED-TOKEN-9f" not in line           # POSITIVE: bearer in the message masked
    assert "LEAKED-COOKIE" not in line             # POSITIVE: cookie in an extra masked
    assert rec["cookie"] == redact.MASK
    assert rec["user"] == "alice" and rec["count"] == 7   # NEGATIVE control: non-secret survives


# ---------------------------------------------------------------- the one level variable
def test_vigil_log_level_takes_effect(monkeypatch) -> None:
    monkeypatch.delenv("SIGIL_LOG_LEVEL", raising=False)
    monkeypatch.setenv("VIGIL_LOG_LEVEL", "ERROR")
    lg, buf = _capture("t.level", level=None)      # resolve from env
    assert lg.level == logging.ERROR
    lg.info("suppressed")                          # below ERROR — dropped
    lg.error("emitted")
    out = buf.getvalue()
    assert "suppressed" not in out and "emitted" in out


def test_legacy_var_honoured_with_deprecation_warning(monkeypatch) -> None:
    monkeypatch.delenv("VIGIL_LOG_LEVEL", raising=False)
    monkeypatch.setenv("SIGIL_LOG_LEVEL", "WARNING")
    L.reset_deprecation_warning()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        name = L.resolve_level_name()
    assert name == "WARNING"
    assert any(issubclass(w.category, DeprecationWarning) for w in caught)


def test_vigil_var_wins_over_legacy(monkeypatch) -> None:
    monkeypatch.setenv("SIGIL_LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("VIGIL_LOG_LEVEL", "ERROR")
    assert L.resolve_level_name() == "ERROR"


# ---------------------------------------------------------------- rotation + retention (the bound)
def test_rotating_line_writer_bounds_and_retains(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("VIGIL_LOG_MAX_BYTES", "256")
    monkeypatch.setenv("VIGIL_LOG_BACKUP_COUNT", "3")
    path = tmp_path / "ui" / "logs" / "backend.log"
    w = L.RotatingLineWriter(path)
    for i in range(200):
        w.write(f"line-{i:04d}-{'x' * 30}\n")
    w.close()
    files = sorted(glob.glob(str(path) + "*"))
    assert len(files) >= 2, "rotation never triggered"          # it rotated
    assert len(files) <= 1 + 3, "retention window not enforced"  # live + <=backup_count backups
    for f in files:
        assert os.path.getsize(f) <= 4096                        # each file is bounded
    if _POSIX:
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
        assert stat.S_IMODE(os.stat(path.parent).st_mode) == 0o700


@pytest.mark.skipif(not _POSIX, reason="POSIX permission bits")
def test_file_handler_rotates_and_is_owner_only(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("VIGIL_LOG_MAX_BYTES", "512")
    monkeypatch.setenv("VIGIL_LOG_BACKUP_COUNT", "2")
    logfile = tmp_path / "svc" / "app.log"
    lg = logging.getLogger("t.filerot")
    for h in list(lg.handlers):
        lg.removeHandler(h)
    lg.propagate = False
    L.configure_logging(level="INFO", logfile=logfile, root=lg, force=True)
    for i in range(200):
        lg.info("event %d payload %s", i, "y" * 40)
    files = sorted(glob.glob(str(logfile) + "*"))
    assert len(files) >= 2                                        # rotated
    assert stat.S_IMODE(os.stat(logfile).st_mode) == 0o600        # 0600, no world-readable window
