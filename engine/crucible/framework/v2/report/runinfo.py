"""
report.runinfo — the plain facts about ONE engagement run, read from what the run actually wrote.

The case file has to answer a non-specialist's first questions — *what was examined, when did it
start, when did it finish, how long did it take, what settings were used, and what do those
settings mean I did NOT get* — and it has to answer them from recorded data or not at all.

This module reads the small set of files a run leaves behind (``meta.json``, ``reverifiable.json``,
``progress.jsonl``, the stored ``report.json``) and returns a :class:`RunInfo` of exactly what was
recorded. Every field that has no source is ``None``, and the renderers print "not recorded" for
it. Nothing here estimates, back-calculates or fills in a plausible value.

Times are rendered in UTC and labelled as such. UTC is used deliberately: the recipient of a
dossier is often in a different country from the machine that produced it, and a bare local time
is ambiguous evidence.

Pure apart from reading files under the run directory; deterministic given the same run.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# Month names, so a date reads as a date to a reader who is not a programmer.
_MONTHS = ("January", "February", "March", "April", "May", "June",
           "July", "August", "September", "October", "November", "December")

# Scan options whose PRESENCE materially narrows what was tested. Each maps to a plain-English
# statement of the limit it imposed. This is the backbone of the scope-honesty section: the
# document states the limits from the command that actually ran, not from a generic template.
_OPTION_MEANING: dict[str, str] = {
    "--no-oob": (
        "Out-of-band checks were switched OFF. Some serious weaknesses only reveal themselves "
        "when the tested system makes a connection back out to a listener under the tester's "
        "control. Those checks were not performed, so weaknesses of that kind would not have "
        "been found."
    ),
    "--targeted": (
        "The run was targeted rather than exhaustive: checks were focused on the specific "
        "address supplied, rather than sweeping every possibility."
    ),
    "--safe": "Only checks classified as safe for a live system were run.",
    "--dry-run": "This was a rehearsal: no live testing traffic was sent.",
    "--passive": "Only passive observation was performed; no test input was sent to the system.",
    "--no-crawl": "The site was not explored automatically; only the address supplied was examined.",
}

# Options that carry a value, with a template for the plain-English limit they impose.
_OPTION_VALUE_MEANING: dict[str, str] = {
    "--max-pages": (
        "At most {value} page(s) of the site were explored. Anything beyond that limit was not "
        "examined."
    ),
    "--max-requests": "At most {value} test request(s) were sent in total.",
    "--timeout": "Each request was given at most {value} second(s) to respond.",
    "--rate": "Requests were sent at no more than {value} per second, to avoid disturbing the system.",
}


def human_time(value: Any) -> Optional[str]:
    """A recorded time as a sentence a non-specialist can read, in UTC and labelled — e.g.
    ``"29 July 2026 at 15:20:10 UTC"``. Accepts a UNIX timestamp (int/float) or an ISO-8601
    string. Returns ``None`` when the value is missing or unreadable, so the caller prints
    "not recorded" rather than inventing a time."""
    dt = _to_datetime(value)
    if dt is None:
        return None
    return f"{dt.day} {_MONTHS[dt.month - 1]} {dt.year} at {dt:%H:%M:%S} UTC"


def _to_datetime(value: Any) -> Optional[datetime]:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    s = str(value).strip()
    if not s:
        return None
    # a numeric string is a UNIX timestamp
    try:
        return datetime.fromtimestamp(float(s), tz=timezone.utc)
    except (TypeError, ValueError, OverflowError, OSError):
        pass
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def human_duration(seconds: Any) -> Optional[str]:
    """A measured duration in words: ``"0.23 seconds"``, ``"4 minutes 12 seconds"``. ``None``
    when nothing was recorded."""
    try:
        s = float(seconds)
    except (TypeError, ValueError):
        return None
    if s < 0:
        return None
    if s < 1:
        return f"{s:.2f} seconds"
    if s < 60:
        return f"{s:.1f} seconds"
    minutes, rest = divmod(int(round(s)), 60)
    if minutes < 60:
        return f"{minutes} minute{'s' if minutes != 1 else ''} {rest} second{'s' if rest != 1 else ''}"
    hours, minutes = divmod(minutes, 60)
    return f"{hours} hour{'s' if hours != 1 else ''} {minutes} minute{'s' if minutes != 1 else ''}"


@dataclass
class ScopeLimit:
    """One recorded limit on what was tested, with the option that imposed it."""

    option: str
    meaning: str


@dataclass
class RunInfo:
    """What the run recorded about itself. Every optional field is ``None`` when the run did
    not record it — the documents then say "not recorded" rather than guessing."""

    run_id: str = ""
    target: Optional[str] = None
    status: Optional[str] = None
    started: Optional[str] = None            # human, UTC
    finished: Optional[str] = None           # human, UTC
    duration: Optional[str] = None           # human
    command: list[str] = field(default_factory=list)
    limits: list[ScopeLimit] = field(default_factory=list)
    pages_examined: Optional[int] = None
    requests_examined: Optional[int] = None
    test_requests_sent: Optional[int] = None
    endpoints_discovered: Optional[int] = None
    finding_times: dict[str, str] = field(default_factory=dict)   # bug class -> human time
    notes: list[str] = field(default_factory=list)

    @property
    def started_text(self) -> str:
        return self.started or "not recorded"

    @property
    def finished_text(self) -> str:
        return self.finished or "not recorded"

    @property
    def duration_text(self) -> str:
        return self.duration or "not recorded"


def _read_json(path: Path) -> Any:
    try:
        if path.is_symlink() or not path.is_file():
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _parse_limits(cmd: list[str]) -> list[ScopeLimit]:
    """Turn the recorded command line into the plain-English limits it imposed. Only options
    this module has a written meaning for are reported — an unrecognised option is left out
    rather than described with a guess."""
    limits: list[ScopeLimit] = []
    seen: set[str] = set()
    for i, tok in enumerate(cmd):
        opt = str(tok)
        if opt in _OPTION_MEANING and opt not in seen:
            seen.add(opt)
            limits.append(ScopeLimit(option=opt, meaning=_OPTION_MEANING[opt]))
            continue
        base, _, inline = opt.partition("=")
        if base in _OPTION_VALUE_MEANING and base not in seen:
            value = inline or (cmd[i + 1] if i + 1 < len(cmd) else "")
            if value and not str(value).startswith("-"):
                seen.add(base)
                limits.append(ScopeLimit(
                    option=f"{base} {value}",
                    meaning=_OPTION_VALUE_MEANING[base].format(value=value)))
    return limits


_TS_KEYS = ("ts", "time", "timestamp", "at")


def _progress_finding_times(run_dir: Path) -> dict[str, str]:
    """Per-finding confirmation times, IF the progress log recorded any. The scan progress log
    is a JSON-lines stream; a ``scan.finding`` line carries a timestamp only when the producer
    wrote one. When it did not, this returns ``{}`` and the documents say the time was not
    recorded for individual findings."""
    p = run_dir / "progress.jsonl"
    if p.is_symlink() or not p.is_file():
        return {}
    out: dict[str, str] = {}
    try:
        text = p.read_text(encoding="utf-8")
    except OSError:
        return {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if not isinstance(obj, dict) or obj.get("event") != "scan.finding":
            continue
        for key in _TS_KEYS:
            if key in obj:
                human = human_time(obj[key])
                if human:
                    out[str(obj.get("bug_class") or "")] = human
                break
    return out


def read_run_info(run_dir: Path | str, export_doc: Any = None) -> RunInfo:
    """Read everything the run recorded about itself. ``export_doc`` is the already-parsed
    stored ``report.json`` when the caller has it (its ``summary`` carries the coverage
    counts). Never raises: an absent or malformed file simply leaves fields unrecorded."""
    run = Path(run_dir)
    info = RunInfo(run_id=run.name)

    meta = _read_json(run / "meta.json")
    if isinstance(meta, dict):
        info.target = str(meta.get("target") or "").strip() or None
        info.status = str(meta.get("status") or "").strip() or None
        info.started = human_time(meta.get("started"))
        info.finished = human_time(meta.get("finished"))
        cmd = meta.get("cmd")
        if isinstance(cmd, list):
            info.command = [str(c) for c in cmd]
            info.limits = _parse_limits(info.command)

    # The measured duration lives with the re-verifiable material the scanner wrote.
    rv = _read_json(run / "reverifiable.json")
    if isinstance(rv, dict):
        info.duration = human_duration(rv.get("elapsed_s"))
        for attr, key in (("pages_examined", "pages_crawled"),
                          ("requests_examined", "requests_audited"),
                          ("test_requests_sent", "audit_requests_sent")):
            v = rv.get(key)
            if isinstance(v, int):
                setattr(info, attr, v)
        if info.target is None:
            info.target = str(rv.get("target") or "").strip() or None

    if isinstance(export_doc, dict):
        if info.target is None:
            info.target = str(export_doc.get("target") or "").strip() or None
        summary = export_doc.get("summary")
        if isinstance(summary, dict):
            for attr, key in (("pages_examined", "pages_crawled"),
                              ("requests_examined", "requests_audited"),
                              ("endpoints_discovered", "discovered_endpoints")):
                v = summary.get(key)
                if isinstance(v, int) and getattr(info, attr) is None:
                    setattr(info, attr, v)

    info.finding_times = _progress_finding_times(run)

    if info.started is None and info.finished is not None:
        info.notes.append(
            "The run recorded when it finished but not when it started, so no start time is "
            "stated. The measured duration is reported separately where it was recorded."
        )
    if not info.finding_times:
        info.notes.append(
            "The engine did not record a separate time for each individual finding. All "
            "findings were produced within the single engagement window stated above."
        )
    return info


# --------------------------------------------------------------------------------------------------
# a redaction pass for anything read out of a command line into a hand-to-anyone document
# --------------------------------------------------------------------------------------------------

_URL_USERINFO_RE = re.compile(r"([a-zA-Z][a-zA-Z0-9+.\-]*://)[^/\s:@]+(?::[^/\s@]*)?@")


def safe_command_token(token: str) -> str:
    """Strip credentials embedded in a URL argument before a command line is printed into a
    document that will be handed to a third party. Display-only."""
    return _URL_USERINFO_RE.sub(lambda m: m.group(1) + "[redacted]@", str(token or ""))
