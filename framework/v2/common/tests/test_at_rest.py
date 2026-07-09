"""
Speed X2 — data-at-rest protection: owner-only permissions + deterministic secret
redaction, with NO encryption dependency and NO change to file CONTENT (only mode).

These tests pin the security contract:
  * secure_write creates 0600 files with no world-readable window (the file is
    0600 from the instant it exists), secure_dir 0700 directories;
  * tighten_umask only ever ADDS restrictions, never loosens a stricter ambient mask;
  * the .http evidence redactor masks credential header VALUES but keeps the header
    NAME and never touches non-credential headers (so proof stays legible);
  * the log scrubber masks secret-keyed fields (recursively) before they hit disk.

POSIX-only assertions (mode bits) are skipped where the platform cannot represent them.
"""

from __future__ import annotations

import os
import stat

import pytest

from framework.v2.common import paths, redact

_POSIX = os.name == "posix"


# --------------------------------------------------------------------------- perms


@pytest.mark.skipif(not _POSIX, reason="POSIX permission bits")
def test_secure_write_creates_owner_only_file(tmp_path) -> None:
    p = tmp_path / "nested" / "secret.json"
    paths.secure_write(p, '{"k": 1}')
    assert p.read_text(encoding="utf-8") == '{"k": 1}'          # content unchanged
    assert stat.S_IMODE(p.stat().st_mode) == 0o600              # rw-------
    assert stat.S_IMODE(p.parent.stat().st_mode) == 0o700       # parent rwx------


@pytest.mark.skipif(not _POSIX, reason="POSIX permission bits")
def test_secure_write_has_no_world_readable_window(tmp_path) -> None:
    # Under a genuinely wide-open ambient umask (a naive create would be 0o666),
    # secure_write's file is 0600 the instant it exists (created via os.open with
    # the mode, not created-then-chmod'd).
    prev = os.umask(0o000)
    try:
        p = tmp_path / "cred.json"
        paths.secure_write(p, "x")
        assert stat.S_IMODE(p.stat().st_mode) == 0o600
        # contrast: a naive write under this umask IS world-accessible — proving the
        # ambient umask really is open and the mode came from secure_write, not luck.
        q = tmp_path / "naive.json"
        q.write_text("x", encoding="utf-8")
        assert stat.S_IMODE(q.stat().st_mode) & 0o077
    finally:
        os.umask(prev)


@pytest.mark.skipif(not _POSIX, reason="POSIX permission bits")
def test_secure_write_bytes_and_overwrite_retightens(tmp_path) -> None:
    p = tmp_path / "b.bin"
    p.write_bytes(b"old")
    os.chmod(p, 0o644)                                    # pre-existing world-readable
    paths.secure_write(p, b"\x00\x01\x02")
    assert p.read_bytes() == b"\x00\x01\x02"
    assert stat.S_IMODE(p.stat().st_mode) == 0o600        # re-tightened on overwrite


@pytest.mark.skipif(not _POSIX, reason="POSIX permission bits")
def test_secure_dir_is_owner_only_when_created(tmp_path) -> None:
    d = paths.secure_dir(tmp_path / "state")
    assert d.is_dir()
    assert stat.S_IMODE(d.stat().st_mode) == 0o700


@pytest.mark.skipif(not _POSIX, reason="POSIX permission bits")
def test_secure_dir_never_repermissions_a_preexisting_dir(tmp_path) -> None:
    # Blast-radius guard (X2 review): secure_dir must NOT chmod a directory it did
    # not create — a sensitive store's parent can be a SHARED path (the framework
    # source root for the ambient log, an operator's evidence output dir), and
    # tightening it to 0700 would lock other users out of a whole tree.
    shared = tmp_path / "shared"
    shared.mkdir()
    os.chmod(shared, 0o755)
    paths.secure_dir(shared)                     # already exists → must be left alone
    assert stat.S_IMODE(shared.stat().st_mode) == 0o755


@pytest.mark.skipif(not _POSIX, reason="POSIX permission bits")
def test_tighten_umask_only_adds_restrictions() -> None:
    saved = os.umask(0o022)          # start permissive
    try:
        eff = paths.tighten_umask()
        assert eff == (0o022 | 0o077)        # union, owner-only for group/other
        # a stricter ambient mask is never loosened
        os.umask(0o077)
        assert paths.tighten_umask() == 0o077
    finally:
        os.umask(saved)


# --------------------------------------------------------------------------- redaction


def test_redact_header_masks_credentials_keeps_names() -> None:
    assert redact.redact_header("Authorization", "Bearer abc.def") == redact.MASK
    assert redact.redact_header("cookie", "sid=deadbeef") == redact.MASK
    assert redact.redact_header("Set-Cookie", "sid=deadbeef; HttpOnly") == redact.MASK
    assert redact.redact_header("X-Relay-Key", "s3cr3t") == redact.MASK
    # non-credential headers pass through untouched — proof must stay legible.
    assert redact.redact_header("Content-Type", "application/json") == "application/json"
    assert redact.redact_header("X-Reflected-Payload", "<script>") == "<script>"


def test_scrub_log_event_masks_secret_keys_recursively() -> None:
    event = {
        "event": "http.request", "url": "http://127.0.0.1/x",
        "authorization": "Bearer xyz", "access_token": "t0k",
        "api_key": "k", "status": 200,
        "nested": {"session_cookie": "c", "keep": "v"},
    }
    out = redact.scrub_log_event(event)
    assert out["authorization"] == redact.MASK
    assert out["access_token"] == redact.MASK
    assert out["api_key"] == redact.MASK
    assert out["nested"]["session_cookie"] == redact.MASK
    # non-secret fields survive verbatim
    assert out["url"] == "http://127.0.0.1/x"
    assert out["status"] == 200
    assert out["nested"]["keep"] == "v"


def test_scrub_is_deterministic_and_total() -> None:
    e = {"token": "a", "x": 1, "y": [1, 2, 3]}
    assert redact.scrub_log_event(e) == redact.scrub_log_event(dict(e))
    assert redact.scrub_log_event(e)["y"] == [1, 2, 3]     # unrecognised value untouched


def test_token_telemetry_is_not_over_masked() -> None:
    # Regression (X2 review): a bare 'token' substring match would eat the numeric
    # telemetry every LLM backend logs (tokens_in/tokens_out/token_max/token_count)
    # and the planner budget's token_max — flipping numbers to a string and gutting
    # the audit trail / Ops Console token view. Matching must be segment/suffix-based.
    for k in ("tokens_in", "tokens_out", "token_max", "token_count", "max_tokens",
              "total_tokens", "cache_key", "sort_key", "keyword", "key_count", "monkey"):
        assert not redact.is_secret_key(k), f"telemetry/identifier over-masked: {k}"
    out = redact.scrub_log_event({"tokens_in": 1234, "tokens_out": 567, "token_max": 200000})
    assert out == {"tokens_in": 1234, "tokens_out": 567, "token_max": 200000}   # numbers intact


def test_secret_suffixes_and_segments_still_mask() -> None:
    # …while any real credential field — exact, secret-suffixed, or with a strong
    # secret segment — is still masked.
    for k in ("token", "access_token", "auth_token", "refresh_token", "session_token",
              "api_key", "private_key", "session_key", "client_secret", "db_password",
              "authorization", "session_cookie", "x-api-key", "x-relay-key", "x_auth_token"):
        assert redact.is_secret_key(k), f"real secret field left unmasked: {k}"


# --------------------------------------------------------------- logging end-to-end


def test_engagement_log_scrubs_secrets_and_is_owner_only(tmp_path, monkeypatch) -> None:
    import json as _json

    from framework.v2.common import logging as v2log

    log_file = tmp_path / "eng" / ".crucible-v2.log"
    monkeypatch.setattr(v2log, "_engagement_log_path", lambda: log_file)
    v2log.configure()
    log = v2log.get_logger("test.x2")
    log.info("http.request", url="http://127.0.0.1/pay",
             authorization="Bearer SECRET-TOKEN", status=200)

    body = log_file.read_text(encoding="utf-8")
    line = _json.loads(body.strip().splitlines()[-1])
    assert line["authorization"] == redact.MASK       # secret masked before disk
    assert "SECRET-TOKEN" not in body                 # the raw token never landed
    assert line["url"] == "http://127.0.0.1/pay"      # non-secret preserved
    if _POSIX:
        assert stat.S_IMODE(log_file.stat().st_mode) == 0o600   # file 0600 (no create window)


@pytest.mark.skipif(not _POSIX, reason="POSIX permission bits")
def test_ambient_log_does_not_lock_down_its_shared_parent(tmp_path, monkeypatch) -> None:
    # Regression (X2 review, blast radius): the ambient log's parent is the shared
    # framework source root; writing a line must NOT chmod that parent to 0700.
    from framework.v2.common import logging as v2log

    shared_parent = tmp_path / "src-root"
    shared_parent.mkdir()
    os.chmod(shared_parent, 0o755)
    log_file = shared_parent / ".crucible-v2.log"
    monkeypatch.setattr(v2log, "_engagement_log_path", lambda: log_file)
    v2log.configure()
    v2log.get_logger("test.x2").info("ambient.event", n=1)

    assert stat.S_IMODE(shared_parent.stat().st_mode) == 0o755    # parent untouched
    assert stat.S_IMODE(log_file.stat().st_mode) == 0o600         # but the log itself is 0600


@pytest.mark.skipif(not _POSIX, reason="POSIX permission bits")
def test_rotated_backup_is_tightened_on_upgrade(tmp_path, monkeypatch) -> None:
    # Regression (X2 2nd-pass review): a pre-X2 log at 0644 that is over the cap gets
    # rotated to .1 via os.replace (which preserves the loose mode) — the backup must be
    # tightened to 0600, not left world-readable.
    from framework.v2.common import logging as v2log

    log_file = tmp_path / "eng" / ".crucible-v2.log"
    log_file.parent.mkdir(parents=True)
    log_file.write_text("x" * 10, encoding="utf-8")   # simulate a pre-X2 log...
    os.chmod(log_file, 0o644)                          # ...created world-readable
    monkeypatch.setattr(v2log, "_engagement_log_path", lambda: log_file)
    monkeypatch.setattr(v2log, "_LOG_MAX_BYTES", 1)    # force rotation on next write
    monkeypatch.setattr(v2log, "_SECURED_LOGS", set())
    v2log.configure()
    v2log.get_logger("test.x2").info("rotate.me", n=1)

    backup = log_file.with_suffix(log_file.suffix + ".1")
    assert backup.is_file()
    assert stat.S_IMODE(backup.stat().st_mode) == 0o600    # backup tightened, not left 0644
    assert stat.S_IMODE(log_file.stat().st_mode) == 0o600  # fresh log 0600
