"""
vigil_core.logging_setup — the ONE structured-logging setup shared by every VIGIL plane (W6-5).

Before this, three logging stacks disagreed: the offense engine had structlog JSON + redaction +
rotation, the sovereign SIGIL plane logged plain text to stderr with no redaction, and the host
gateway used a bare ``logging.basicConfig``. Only ``SIGIL_LOG_LEVEL`` existed, governing one of the
three. This module unifies them on ONE pattern — structured JSON lines, a SHARED redaction processor
(``vigil_core.redact``), size-based rotation with retention, and ONE ``VIGIL_LOG_LEVEL`` — reusable by
every plane because ``vigil_core`` is a member of both isolated environments and depends on NO
``framework.*`` / ``strix.*`` / ``sigil.*`` (FATAL-2 stays intact).

Deliberately STDLIB-ONLY: the host gateway declares zero third-party runtime dependencies and structlog
is not in the sovereign environment, so this builds on ``logging`` + ``json`` alone. The offense engine
keeps its own structlog pipeline (already JSON + redaction + rotation) but now (a) resolves its level
from the same ``VIGIL_LOG_LEVEL`` and (b) redacts through the same shared ``vigil_core.redact`` helper,
so the single variable and the single redactor genuinely govern all planes.
"""

from __future__ import annotations

import datetime as _dt
import json
import logging
import os
import warnings
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Optional, TextIO

from . import redact

# The one level variable (W6-5). ``SIGIL_LOG_LEVEL`` is the deprecated predecessor: still honoured, with
# a one-time deprecation warning, so an existing deployment keeps working while operators migrate.
LEVEL_ENV = "VIGIL_LOG_LEVEL"
LEGACY_LEVEL_ENV = "SIGIL_LOG_LEVEL"
DEFAULT_LEVEL = "INFO"

# Rotation bounds — the SAME env names and defaults the offense engine's rotator reads, so a deployment
# widens retention once for every plane. Disk is bounded to ~``(backup_count + 1) * max_bytes`` per file.
_MAX_BYTES_ENV = "VIGIL_LOG_MAX_BYTES"
_BACKUP_COUNT_ENV = "VIGIL_LOG_BACKUP_COUNT"
_DEFAULT_MAX_BYTES = 64 * 1024 * 1024
_DEFAULT_BACKUP_COUNT = 16

_HANDLER_NAME = "vigil"
_SECURE_FILE_MODE = 0o600
_SECURE_DIR_MODE = 0o700

# Set once the deprecated variable has been warned about, so a hot logging path warns exactly once.
_LEGACY_WARNED = False

# The attributes every ``logging.LogRecord`` carries; anything ELSE in ``record.__dict__`` is an
# operator-supplied ``extra=`` structured field and is emitted (after redaction) as a JSON key.
_STD_RECORD_ATTRS = frozenset({
    "name", "msg", "args", "levelname", "levelno", "pathname", "filename", "module", "exc_info",
    "exc_text", "stack_info", "lineno", "funcName", "created", "msecs", "relativeCreated", "thread",
    "threadName", "processName", "process", "taskName", "asctime", "message",
})


def _int_env(name: str, default: int) -> int:
    try:
        return max(1, int(os.environ.get(name, str(default))))
    except (TypeError, ValueError):
        return default


def rotation_limits() -> tuple[int, int]:
    """Return ``(max_bytes, backup_count)`` from the environment, with fail-closed generous defaults.
    Read at call time so a deployment can widen retention and a test can monkeypatch the env."""
    return _int_env(_MAX_BYTES_ENV, _DEFAULT_MAX_BYTES), _int_env(_BACKUP_COUNT_ENV, _DEFAULT_BACKUP_COUNT)


def reset_deprecation_warning() -> None:
    """Test seam: re-arm the one-time legacy-variable deprecation warning."""
    global _LEGACY_WARNED
    _LEGACY_WARNED = False


def _warn_legacy_once() -> None:
    global _LEGACY_WARNED
    if _LEGACY_WARNED:
        return
    _LEGACY_WARNED = True
    warnings.warn(
        f"{LEGACY_LEVEL_ENV} is deprecated; set {LEVEL_ENV} instead — it governs every VIGIL plane. "
        f"{LEGACY_LEVEL_ENV} is still honoured for now.",
        DeprecationWarning,
        stacklevel=3,
    )


def resolve_level_name(level: Optional[object] = None) -> str:
    """Resolve the effective level NAME. Order: explicit ``level`` arg (an int level or a name) →
    ``VIGIL_LOG_LEVEL`` → ``SIGIL_LOG_LEVEL`` (deprecated, warns once) → INFO. An unknown name falls back
    to INFO rather than raising."""
    if level is not None:
        if isinstance(level, int):
            return logging.getLevelName(level)
        name = str(level).strip().upper()
        return name if name in logging._nameToLevel else DEFAULT_LEVEL  # noqa: SLF001 (stable stdlib map)
    raw = os.environ.get(LEVEL_ENV)
    if raw is None:
        legacy = os.environ.get(LEGACY_LEVEL_ENV)
        if legacy is not None:
            _warn_legacy_once()
            raw = legacy
    if raw is None:
        return DEFAULT_LEVEL
    name = str(raw).strip().upper()
    return name if name in logging._nameToLevel else DEFAULT_LEVEL  # noqa: SLF001


def resolve_level(level: Optional[object] = None) -> int:
    """Resolve the effective level as an int, via :func:`resolve_level_name`."""
    return logging.getLevelName(resolve_level_name(level))


class RedactingJsonFormatter(logging.Formatter):
    """Render a ``LogRecord`` as ONE JSON line, with the SHARED redactor applied to both the free-text
    message and every structured ``extra=`` field. Deterministic key order (``sort_keys``) so the output
    is stable and diff-able. The redaction is defense-in-depth: a secret in the message text is masked by
    ``redact_log_message`` and a secret-keyed extra by ``scrub_log_event``, so no plane can leak a
    credential through a log line even if a call site is careless."""

    def format(self, record: logging.LogRecord) -> str:
        event: dict[str, Any] = {
            "ts": _dt.datetime.fromtimestamp(record.created, tz=_dt.timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": redact.redact_log_message(record.getMessage()),
        }
        # Operator-supplied structured fields (logger.info("x", extra={...})): everything on the record
        # that is not a standard LogRecord attribute. Scrubbed by key-name before emission.
        extras = {k: v for k, v in record.__dict__.items() if k not in _STD_RECORD_ATTRS}
        if extras:
            for k, v in redact.scrub_log_event(extras).items():
                event.setdefault(k, v)
        if record.exc_info:
            event["exc"] = redact.redact_log_message(self.formatException(record.exc_info))
        if record.stack_info:
            event["stack"] = redact.redact_log_message(self.formatStack(record.stack_info))
        return json.dumps(event, default=str, separators=(",", ":"), sort_keys=True)


class _SecureRotatingFileHandler(RotatingFileHandler):
    """A ``RotatingFileHandler`` that creates its file 0600 with no world-readable window (log lines can
    carry an operator token before redaction catches a novel shape), under a 0700 parent."""

    def _open(self):  # type: ignore[override]
        path = Path(self.baseFilename)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            os.chmod(path.parent, _SECURE_DIR_MODE)
        except OSError:
            pass
        fd = os.open(self.baseFilename, os.O_WRONLY | os.O_CREAT | os.O_APPEND, _SECURE_FILE_MODE)
        return os.fdopen(fd, self.mode, encoding=self.encoding or "utf-8")


def configure_logging(
    level: Optional[object] = None,
    *,
    stream: Optional[TextIO] = None,
    logfile: Optional[os.PathLike[str] | str] = None,
    handler_name: str = _HANDLER_NAME,
    root: Optional[logging.Logger] = None,
    force: bool = False,
) -> logging.Logger:
    """Install the ONE structured-JSON + redaction handler and return the configured logger.

    Idempotent: a second call only re-sets the level unless ``force=True`` (which rebuilds the handler —
    used by tests to capture into a ``StringIO``). Writes to ``logfile`` (rotating, 0600) when given,
    otherwise to ``stream`` (default stderr). The level is resolved via :func:`resolve_level`, so ONE
    ``VIGIL_LOG_LEVEL`` governs whichever plane calls this."""
    logger = root if root is not None else logging.getLogger()
    lvl = resolve_level(level)
    existing = [h for h in logger.handlers if getattr(h, "name", None) == handler_name]
    if existing and not force:
        logger.setLevel(lvl)
        for h in existing:
            h.setLevel(lvl)
        return logger
    for h in existing:
        logger.removeHandler(h)

    handler: logging.Handler
    if logfile is not None:
        max_bytes, backup_count = rotation_limits()
        handler = _SecureRotatingFileHandler(
            os.fspath(logfile), maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8", delay=True
        )
    else:
        handler = logging.StreamHandler(stream)
    handler.set_name(handler_name)
    handler.setFormatter(RedactingJsonFormatter())
    handler.setLevel(lvl)
    logger.addHandler(handler)
    logger.setLevel(lvl)
    return logger


def get_logger(name: str) -> logging.Logger:
    """Return a named stdlib logger; it inherits whatever handler ``configure_logging`` installed."""
    return logging.getLogger(name)


class RotatingLineWriter:
    """A file-like sink that appends text and rotates with RETENTION when it crosses the size cap — the
    bound for the ``.vigil-live/ui/logs/*.log`` child-capture files, which were previously unbounded
    (W6-5). Retains history: the live file becomes ``.1``, existing backups shift up, and only the backup
    PAST the retention window is pruned (an explicit policy, not silent truncation). The file is 0600 under
    a 0700 dir. Not a general logging handler — it is the write end a subprocess-output pump thread uses."""

    def __init__(self, path: os.PathLike[str] | str, *, max_bytes: int = 0, backup_count: int = 0) -> None:
        self._path = Path(path)
        dmax, dbackup = rotation_limits()
        self._max_bytes = max_bytes if max_bytes > 0 else dmax
        self._backup_count = max(1, backup_count if backup_count > 0 else dbackup)
        self._fh: Optional[Any] = None
        self._path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self._path.parent, _SECURE_DIR_MODE)
        except OSError:
            pass

    def _ensure_open(self) -> None:
        if self._fh is None:
            fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, _SECURE_FILE_MODE)
            self._fh = os.fdopen(fd, "a", encoding="utf-8", errors="replace")

    def _rotate(self) -> None:
        """Roll the over-cap file into a numbered backup ring, retaining history."""
        if self._fh is not None:
            try:
                self._fh.close()
            finally:
                self._fh = None
        keep = self._backup_count
        oldest = self._path.with_suffix(self._path.suffix + f".{keep}")
        try:
            if oldest.exists():
                oldest.unlink()
        except OSError:
            pass
        for k in range(keep - 1, 0, -1):
            src = self._path.with_suffix(self._path.suffix + f".{k}")
            dst = self._path.with_suffix(self._path.suffix + f".{k + 1}")
            try:
                if src.exists():
                    os.replace(src, dst)
            except OSError:
                pass
        try:
            os.replace(self._path, self._path.with_suffix(self._path.suffix + ".1"))
        except OSError:
            pass

    def write(self, text: str) -> int:
        if not text:
            return 0
        try:
            if self._path.exists() and self._path.stat().st_size >= self._max_bytes:
                self._rotate()
        except OSError:
            pass
        self._ensure_open()
        assert self._fh is not None
        n = self._fh.write(text)
        self._fh.flush()
        return n

    def flush(self) -> None:
        if self._fh is not None:
            try:
                self._fh.flush()
            except OSError:
                pass

    def close(self) -> None:
        if self._fh is not None:
            try:
                self._fh.close()
            finally:
                self._fh = None


__all__ = [
    "LEVEL_ENV",
    "LEGACY_LEVEL_ENV",
    "DEFAULT_LEVEL",
    "rotation_limits",
    "resolve_level",
    "resolve_level_name",
    "reset_deprecation_warning",
    "RedactingJsonFormatter",
    "configure_logging",
    "get_logger",
    "RotatingLineWriter",
]
