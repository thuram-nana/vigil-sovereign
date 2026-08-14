"""Per-tool TOKEN BUDGETS — an operator-editable daily token allowance per tool/API, with
**WARN + THROTTLE** enforcement (never a hard block).

Why this lives in ``vigil_core``: it is the one substrate BOTH isolated planes import (the offense
engine, the sovereign cockpit) plus the console — so every token-spending path charges and reads the
SAME ledger, across the two-process boundary, over a plain file. No plane imports another.

Operator doctrine (their explicit choices):

  * **Token-based, PER TOOL, editable from the UI.** Nothing is hard-coded at a call site: a call site
    only names its ``tool`` and the token count it spent. The per-tool *limits* and *modes* live in a
    JSON config the UI writes (``set_tool``); a tool with no operator override falls back to a default
    from :data:`DEFAULT_TOOLS`. So the operator can always change any tool's budget and it takes effect
    immediately — nothing recompiled, nothing hard-coded.

  * **WARN + THROTTLE, NEVER HARD-BLOCK.** Going over budget SLOWS a caller by a bounded delay and
    raises a warning; it NEVER refuses a call. ``reserve()`` returns guidance (a delay + a warn flag),
    not a veto. The operator stays in control — raise the limit in the UI at any time.

Load-bearing safety property: **metering must never break a call.** Every public function is total —
a missing/locked/corrupt store, a bad clock, an unknown tool: the worst case is "no throttle, no
warning, proceed" (fail-OPEN for the *metering*, so functionality is never lost — "everything still
perfect"). Enforcement is advisory back-pressure, deliberately not a gate.
"""
from __future__ import annotations

import json
import os
import threading
import time
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

# --------------------------------------------------------------------------------------------------
# The tool registry — DEFAULTS ONLY. The operator's UI overrides these into the store; a call site
# never carries a number. `kind` is "llm" (tokens) or "requests" (a request-count budget for a non-LLM
# API), which is purely a display hint — the ledger counts integer units either way.
# --------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class ToolDef:
    label: str
    default_limit: int
    kind: str = "llm"                       # "llm" (tokens) | "requests"
    default_output_max: int = 32_000        # per-CALL output-token ceiling (a single call can never
    #                                         request more than this many output tokens); llm-only.


DEFAULT_TOOLS: dict[str, ToolDef] = {
    # LLM token spenders (the paid ones the operator cares about)
    "engine":       ToolDef("Autonomous engine (engage / think)", 2_000_000, "llm"),
    "chat":         ToolDef("Console chat", 1_000_000, "llm"),
    "terminal":     ToolDef("Terminal AI router", 200_000, "llm", default_output_max=4_000),
    "codefix":      ToolDef("Auto-fix coder", 500_000, "llm"),
    "threat_model": ToolDef("Threat modeling", 400_000, "llm"),
    "fireteam":     ToolDef("Fireteam agents", 1_000_000, "llm"),
    "sigil":        ToolDef("SIGIL perception / consolidation", 300_000, "llm"),
    "strix":        ToolDef("Strix scans", 2_000_000, "llm"),
    # non-LLM external APIs (request-count budgets)
    "vulnfeed":     ToolDef("Vuln feed (NVD / OSV / CISA-KEV)", 5_000, "requests"),
    "recon":        ToolDef("Passive recon (crt.sh / DoH / RDAP)", 2_000, "requests"),
}

_MODES = ("off", "warn", "throttle")
_DEFAULT_MODE = "throttle"
_DEFAULT_WARN_FRAC = 0.8

# Throttle shape: a BOUNDED ramp once over the limit. Never blocks — the largest delay it can ever
# return is _MAX_THROTTLE_S. Env-tunable so an operator (or a test) can flatten it.
_THROTTLE_BASE_S = float(os.environ.get("VIGIL_TOKEN_BUDGET_THROTTLE_BASE_S") or 0.75)
_MAX_THROTTLE_S = float(os.environ.get("VIGIL_TOKEN_BUDGET_MAX_THROTTLE_S") or 8.0)

_LOCK = threading.Lock()          # in-process serialization; cross-process is the file lock below


# --------------------------------------------------------------------------------------------------
# Where the ledger lives. One file under the shared live dir so both planes + the console see it.
# --------------------------------------------------------------------------------------------------
def _store_path() -> Path:
    override = os.environ.get("VIGIL_TOKEN_BUDGET_FILE")
    if override:
        return Path(override)
    base = os.environ.get("VIGIL_LIVE_DIR") or os.environ.get("CRUCIBLE_LIVE_DIR") or ".vigil-live"
    return Path(base) / "token-budgets.json"


def _today(now: Optional[float]) -> str:
    ts = now if now is not None else time.time()
    return datetime.fromtimestamp(float(ts), tz=timezone.utc).strftime("%Y-%m-%d")


def _blank() -> dict:
    return {"version": 1, "tools": {}, "usage": {"day": "", "used": {}}}


def _read_unlocked(path: Path) -> dict:
    try:
        d = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(d, dict):
            return _blank()
        d.setdefault("tools", {})
        d.setdefault("usage", {"day": "", "used": {}})
        d["usage"].setdefault("day", "")
        d["usage"].setdefault("used", {})
        return d
    except (OSError, ValueError):
        return _blank()


def _write_unlocked(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + f".tmp.{os.getpid()}")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)          # atomic within a filesystem


@contextmanager
def _locked(path: Path) -> Iterator[None]:
    """Cross-process advisory lock around a read-modify-write. Best-effort: if flock is unavailable
    (non-POSIX) or the lock file cannot be opened, we proceed with the in-process lock only — a lost
    update on a metering counter is acceptable; breaking the caller is not."""
    lockf = None
    fd = None
    try:
        import fcntl
        path.parent.mkdir(parents=True, exist_ok=True)
        lockf = path.with_suffix(path.suffix + ".lock")
        fd = os.open(str(lockf), os.O_CREAT | os.O_RDWR, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
    except Exception:              # noqa: BLE001 — locking is best-effort; never fail the caller
        fd = None
    try:
        yield
    finally:
        if fd is not None:
            try:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_UN)
            except Exception:      # noqa: BLE001
                pass
            try:
                os.close(fd)
            except OSError:
                pass


def _rollover(data: dict, day: str) -> dict:
    """Reset the daily usage counters when the UTC day changes. The per-tool LIMITS/modes persist;
    only the used-counts reset."""
    if data["usage"].get("day") != day:
        data["usage"] = {"day": day, "used": {}}
    return data


# --------------------------------------------------------------------------------------------------
# Per-tool resolution: operator override (store) over registry default. NEVER a call-site constant.
# --------------------------------------------------------------------------------------------------
def _tool_cfg(data: dict, tool: str) -> dict:
    d = DEFAULT_TOOLS.get(tool)
    cfg = dict(data.get("tools", {}).get(tool, {}) or {})
    limit = cfg.get("limit")
    if limit is None:
        limit = d.default_limit if d else 1_000_000
    mode = cfg.get("mode")
    if mode not in _MODES:
        mode = _DEFAULT_MODE
    warn_frac = cfg.get("warn_frac")
    try:
        warn_frac = float(warn_frac)
    except (TypeError, ValueError):
        warn_frac = _DEFAULT_WARN_FRAC
    output_max = cfg.get("output_max")
    if output_max is None:
        output_max = d.default_output_max if d else 32_000
    return {
        "label": cfg.get("label") or (d.label if d else tool),
        "kind": cfg.get("kind") or (d.kind if d else "llm"),
        "limit": max(0, int(limit)),
        "mode": mode,
        "warn_frac": min(1.0, max(0.0, warn_frac)),
        "output_max": max(1, int(output_max)),
    }


def _throttle_delay(frac: float, mode: str) -> float:
    if mode != "throttle" or frac < 1.0:
        return 0.0
    over = frac - 1.0
    return round(min(_MAX_THROTTLE_S, _THROTTLE_BASE_S * (1.0 + over)), 3)


@dataclass(frozen=True)
class Status:
    tool: str
    label: str
    kind: str
    limit: int
    used: int
    mode: str
    warn_frac: float
    output_max: int
    day: str

    @property
    def frac(self) -> float:
        return (self.used / self.limit) if self.limit > 0 else 0.0

    @property
    def level(self) -> str:
        if self.limit <= 0:
            return "ok"
        if self.frac >= 1.0:
            return "over"
        if self.frac >= self.warn_frac:
            return "warn"
        return "ok"

    @property
    def throttle_delay_s(self) -> float:
        return _throttle_delay(self.frac, self.mode)

    @property
    def warn(self) -> bool:
        return self.level in ("warn", "over") and self.mode in ("warn", "throttle")

    def as_dict(self) -> dict:
        return {
            "tool": self.tool, "label": self.label, "kind": self.kind,
            "limit": self.limit, "used": self.used, "frac": round(self.frac, 4),
            "level": self.level, "mode": self.mode, "warn_frac": self.warn_frac,
            "output_max": self.output_max, "throttle_delay_s": self.throttle_delay_s,
            "warn": self.warn, "day": self.day,
        }


def _status_from(data: dict, tool: str, day: str) -> Status:
    cfg = _tool_cfg(data, tool)
    used = int(data["usage"]["used"].get(tool, 0) or 0)
    return Status(tool=tool, label=cfg["label"], kind=cfg["kind"], limit=cfg["limit"],
                  used=used, mode=cfg["mode"], warn_frac=cfg["warn_frac"],
                  output_max=cfg["output_max"], day=day)


# --------------------------------------------------------------------------------------------------
# Public API — every function is TOTAL (never raises for the caller).
# --------------------------------------------------------------------------------------------------
def status(tool: str, *, now: Optional[float] = None) -> Status:
    """The tool's current state. Read-only; safe to call anywhere. Fail-open: an unreadable store
    reports zero usage against the default limit."""
    day = _today(now)
    try:
        with _LOCK:
            path = _store_path()
            data = _rollover(_read_unlocked(path), day)
        return _status_from(data, tool, day)
    except Exception:              # noqa: BLE001 — metering must never break a caller
        d = DEFAULT_TOOLS.get(tool)
        return Status(tool, d.label if d else tool, d.kind if d else "llm",
                      d.default_limit if d else 1_000_000, 0, _DEFAULT_MODE, _DEFAULT_WARN_FRAC,
                      d.default_output_max if d else 32_000, day)


def reserve(tool: str, *, now: Optional[float] = None) -> Status:
    """Guidance to consult BEFORE spending: read the tool's status and act on ``.throttle_delay_s`` /
    ``.warn``. This never refuses — warn + throttle only."""
    return status(tool, now=now)


def record(tool: str, tokens: int, *, now: Optional[float] = None) -> Status:
    """Charge ``tokens`` (input+output for an LLM call, or 1 per request for a request-budget tool) to
    ``tool`` for today, and return the post-charge status. Fail-open: a store error is swallowed and a
    best-effort status is returned so the caller proceeds."""
    n = max(0, int(tokens or 0))
    day = _today(now)
    try:
        with _LOCK:
            path = _store_path()
            with _locked(path):
                data = _rollover(_read_unlocked(path), day)
                data["usage"]["day"] = day
                data["usage"]["used"][tool] = int(data["usage"]["used"].get(tool, 0) or 0) + n
                _write_unlocked(path, data)
        return _status_from(data, tool, day)
    except Exception:              # noqa: BLE001
        return status(tool, now=now)


def _usage_field(usage: object, *names: str) -> int:
    for n in names:
        v = usage.get(n) if isinstance(usage, dict) else getattr(usage, n, None)
        if v is not None:
            try:
                return int(v)
            except (TypeError, ValueError):
                pass
    return 0


def record_usage(tool: str, usage: object, *, now: Optional[float] = None) -> Status:
    """Charge from a provider ``usage`` object/dict that carries ``input_tokens``/``output_tokens``
    (Anthropic shape) or ``prompt_tokens``/``completion_tokens`` (OpenAI shape). A ``None`` usage or a
    missing field charges 0. Never raises — a direct-SDK call site can call this straight from its
    response without guarding."""
    try:
        i = _usage_field(usage, "input_tokens", "prompt_tokens")
        o = _usage_field(usage, "output_tokens", "completion_tokens")
        return record(tool, i + o, now=now)
    except Exception:              # noqa: BLE001
        return status(tool, now=now)


def throttle(tool: str, *, now: Optional[float] = None) -> Status:
    """Convenience for a spending path: consult the budget, SLEEP the bounded throttle delay if over,
    and return the status (so the caller can log ``.warn``). Never blocks — the sleep is capped at
    ``_MAX_THROTTLE_S``."""
    st = reserve(tool, now=now)
    delay = st.throttle_delay_s
    if delay > 0:
        time.sleep(delay)
    return st


def clamp_output(tool: str, requested_max_tokens: int, *, now: Optional[float] = None) -> int:
    """Clamp a per-call output-token request to the tool's configured ceiling — the safety net so a
    single call can never ask for an absurd output. Returns the smaller of the request and the
    ceiling (and at least 1). Fail-open: on any error, return the request unchanged."""
    try:
        req = int(requested_max_tokens)
        ceiling = status(tool, now=now).output_max
        return max(1, min(req, ceiling))
    except Exception:              # noqa: BLE001
        return requested_max_tokens


def set_tool(tool: str, *, limit: Optional[int] = None, mode: Optional[str] = None,
             warn_frac: Optional[float] = None, output_max: Optional[int] = None,
             label: Optional[str] = None, now: Optional[float] = None) -> Status:
    """The UI's writer: override a tool's budget/mode. Only the provided fields change; the rest keep
    their current (operator-or-default) value. Raises ``ValueError`` on a bad mode so the endpoint can
    400 — but never corrupts the store."""
    if mode is not None and mode not in _MODES:
        raise ValueError(f"mode must be one of {_MODES}, got {mode!r}")
    day = _today(now)
    with _LOCK:
        path = _store_path()
        with _locked(path):
            data = _rollover(_read_unlocked(path), day)
            cur = dict(data.setdefault("tools", {}).get(tool, {}) or {})
            if limit is not None:
                cur["limit"] = max(0, int(limit))
            if mode is not None:
                cur["mode"] = mode
            if warn_frac is not None:
                cur["warn_frac"] = min(1.0, max(0.0, float(warn_frac)))
            if output_max is not None:
                cur["output_max"] = max(1, int(output_max))
            if label is not None:
                cur["label"] = str(label)[:80]
            data["tools"][tool] = cur
            _write_unlocked(path, data)
    return _status_from(data, tool, day)


def list_status(*, now: Optional[float] = None) -> list[Status]:
    """Every tool's status — the union of the registry and any operator-added tool — for the UI.
    Sorted by kind then label so the screen is stable."""
    day = _today(now)
    try:
        with _LOCK:
            path = _store_path()
            data = _rollover(_read_unlocked(path), day)
    except Exception:              # noqa: BLE001
        data = _blank()
    names = set(DEFAULT_TOOLS) | set(data.get("tools", {})) | set(data["usage"]["used"])
    out = [_status_from(data, t, day) for t in names]
    out.sort(key=lambda s: (0 if s.kind == "llm" else 1, s.label.lower()))
    return out


# --------------------------------------------------------------------------------------------------
# Tool tagging — a ContextVar so a CENTRAL LLM hook (e.g. the kernel's complete_with_failover) can
# know which tool is spending without every caller threading an argument through. A subsystem wraps
# its work in ``with using_tool("chat"): ...``; the hook reads ``current_tool()``.
# --------------------------------------------------------------------------------------------------
_CURRENT_TOOL: ContextVar[str] = ContextVar("vigil_current_tool", default="engine")


@contextmanager
def using_tool(tool: str) -> Iterator[None]:
    token = _CURRENT_TOOL.set(str(tool or "engine"))
    try:
        yield
    finally:
        _CURRENT_TOOL.reset(token)


def current_tool(default: str = "engine") -> str:
    try:
        return _CURRENT_TOOL.get() or default
    except Exception:              # noqa: BLE001
        return default
