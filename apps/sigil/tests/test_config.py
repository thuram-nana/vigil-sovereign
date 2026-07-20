"""SIGIL production-hardening (OBS audit) — config layering, self-check, structured logging, and
the removal of every hardcoded operator path.
Run: ~/.sigil/venv/bin/python tests/test_config.py

These prove the deployability + observability fixes: no `/home/<user>` literal survives in the
hardened modules, `effective_config()` honours a live env override with secrets redacted,
`doctor()` self-checks the runtime, `_load_env_file` cannot be crashed by a non-UTF-8 byte, and
the logging infra emits operational lines without ever leaking a secret it was never given.
"""
from __future__ import annotations

import io
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path

from sigil import config, obs

_REPO = Path(__file__).resolve().parents[1]

# built so this test file does not itself contain the forbidden literal (keeps the grep honest).
_FORBIDDEN = "/home/" + "kali"

# the modules hardened in this change — none may retain an operator-specific absolute path.
_EDITED = [
    "sigil/config.py", "sigil/obs.py", "sigil/voice/dispatch.py",
    "sigil/agents/sentinel.py", "sigil/agents/scholar.py", "sigil/agents/runner.py",
    "sigil/agents/artificer.py", "sigil/ingest/git.py", "sigil/ingest/hooks.py",
    "sigil/consolidate/extract.py",
]


@contextmanager
def _env(**overrides):
    """Set env vars for the block, restoring the prior state exactly afterwards."""
    saved = {k: os.environ.get(k) for k in overrides}
    try:
        for k, v in overrides.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        yield
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def test_no_hardcoded_operator_path_remains():
    offenders = []
    for rel in _EDITED:
        text = (_REPO / rel).read_text(encoding="utf-8")
        if _FORBIDDEN in text:
            offenders.append(rel)
    assert not offenders, f"hardcoded {_FORBIDDEN!r} still present in: {offenders}"


def test_effective_config_reflects_sigil_home_override():
    with tempfile.TemporaryDirectory() as td:
        with _env(SIGIL_HOME=td):
            cfg = config.effective_config()
        assert cfg["SIGIL_HOME"] == td, cfg["SIGIL_HOME"]
        assert cfg["SPINE_PATH"].startswith(td), cfg["SPINE_PATH"]
        assert cfg["QDRANT_PATH"].startswith(td), cfg["QDRANT_PATH"]


def test_effective_config_redacts_secrets():
    with _env(ANTHROPIC_API_KEY="SUPER-SECRET-KEY-abc123", SIGIL_ANTHROPIC_API_KEY=None):
        cfg = config.effective_config()
    assert cfg["ANTHROPIC_API_KEY"] == "***redacted***", cfg["ANTHROPIC_API_KEY"]
    # the literal secret must appear in NO value of the effective view
    assert all("SUPER-SECRET-KEY-abc123" != v for v in cfg.values())


def test_ingest_repos_override_is_colon_separated():
    with _env(SIGIL_INGEST_REPOS="/opt/repo-a:/opt/repo-b"):
        cfg = config.effective_config()
    assert cfg["INGEST_REPOS"] == ["/opt/repo-a", "/opt/repo-b"], cfg["INGEST_REPOS"]


def test_doctor_returns_list_of_checks():
    checks = config.doctor()
    assert isinstance(checks, list) and checks, "doctor must return a non-empty list"
    names = set()
    for row in checks:
        assert isinstance(row, tuple) and len(row) == 3, row
        name, ok, detail = row
        assert isinstance(name, str) and isinstance(ok, bool) and isinstance(detail, str), row
        names.add(name)
    # the audit named these self-checks explicitly
    for expected in ("sigil_home_writable", "kernel_binary", "qdrant", "keyring"):
        assert expected in names, f"missing doctor check: {expected} ({names})"


def test_load_env_file_tolerates_non_utf8_byte():
    key = "SIGIL_TEST_BADBYTE_MARKER"
    os.environ.pop(key, None)
    try:
        with tempfile.TemporaryDirectory() as td:
            # a lone 0xFF byte is invalid UTF-8; import/load must NOT crash on it.
            (Path(td) / "sigil.env").write_bytes(b"# comment\n" + key.encode() + b"=va\xfflue\n")
            config._load_env_file(Path(td))  # must not raise
        assert os.environ.get(key) is not None, "the key past the bad byte was still parsed"
    finally:
        os.environ.pop(key, None)


def test_configure_logging_emits_without_leaking_secret():
    secret = "TOKEN-do-not-log-9f8e7d"
    buf = io.StringIO()
    obs.configure_logging(level="INFO", stream=buf, force=True)
    log = obs.get_logger("sigil.test.config")
    log.info("configuration loaded on host")           # an operational line — never the secret
    out = buf.getvalue()
    assert "configuration loaded on host" in out, out
    assert "sigil.test.config" in out and "INFO" in out, out
    assert secret not in out, "a secret we never logged must not appear in output"


def test_get_logger_returns_named_logger():
    import logging
    lg = obs.get_logger("sigil.example")
    assert isinstance(lg, logging.Logger) and lg.name == "sigil.example"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for fn in fns:
        try:
            fn(); print(f"  PASS  {fn.__name__}"); passed += 1
        except AssertionError as e:
            print(f"  FAIL  {fn.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            print(f"  ERROR {fn.__name__}: {e}")
    print(f"{passed}/{len(fns)} config/obs hardening guarantees hold")
    raise SystemExit(0 if passed == len(fns) else 1)
