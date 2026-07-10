"""
defender.logsource — OFFLINE log/alert ingestion into normalized event records.

The blue-team half of the purple-team loop needs to reason over the operator's OWN
telemetry: the syslog, the CEF alert stream, the Windows event log. This module turns
those operator-supplied, offline files into a single normalized ``LogEvent`` shape that
the Sigma runtime (``defender.sigma``) and the detection-efficacy signal
(``defender.efficacy``) evaluate against. It never reaches the network and never touches
a target — it reads a file the operator hands it, exactly like the SBOM / pcap / cloud
file-ingest paths.

Three formats, each a small, explicit, TOTAL parser:

  * SYSLOG   — RFC 3164 (``<PRI>Mon dd HH:MM:SS host tag[pid]: msg``) and RFC 5424
               (``<PRI>1 ISO-TS host app pid msgid sd msg``). Structured ``key=value`` and
               ``key="quoted value"`` pairs inside the message become matchable fields.
  * CEF      — ArcSight Common Event Format
               (``CEF:v|vendor|product|version|sigid|name|sev|ext``). The header maps to
               ``cef_*`` fields; the extension's ``key=value`` pairs become fields.
  * EVTX-JSON— a Windows event-log export as JSON (``evtx_dump``/``Get-WinEvent | ConvertTo-Json``),
               accepted as a JSON array, a single object, or newline-delimited JSON. Both the
               flat shape (``{"EventID": 4688, "CommandLine": ...}``) and the nested
               ``Event.System`` / ``Event.EventData`` (incl. the ``Data:[{@Name,#text}]`` array)
               shape are flattened into fields.

Doctrine, by construction:
  * DEFENSIVE ONLY. This improves the owner's detection coverage. It parses logs; it never
    emits an evasion payload and never suppresses a signal.
  * OFFLINE / PASSIVE. It reads a local file the operator supplied. No egress, no target.
  * UNTRUSTED INPUT. A log/alert file is treated as hostile bytes: bounded total size, bounded
    line length, bounded event count, no ``eval``, no regex catastrophe (linear scans only),
    ``json.loads`` only. Every parser is TOTAL — a malformed line/record is skipped, never raised.
  * DETERMINISM. ``parse_* -> [LogEvent]`` is a PURE function of its input text: no wallclock,
    no rng, stable ordering (input order preserved). Re-parsing the same bytes yields the same
    events.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

# --- untrusted-input bounds (all deliberately generous but finite) ----------
_MAX_BYTES = 64 * 1024 * 1024      # 64 MiB: refuse to slurp an unbounded file
_MAX_EVENTS = 200_000              # cap the number of normalized events
_MAX_LINE = 64 * 1024              # a single line/record longer than this is truncated
_MAX_FIELDS = 256                  # cap distinct fields per event (a hostile line can't explode memory)
_MAX_VALUE = 8 * 1024             # cap one field value's length

Fields = dict[str, "str | int"]


@dataclass(frozen=True)
class LogEvent:
    """One normalized log/alert record. ``fields`` are the matchable attributes a Sigma
    detection evaluates (str or int); ``channel`` is the coarse source family
    ('syslog'/'cef'/'windows'); ``source_format`` is the concrete parser that produced it;
    ``raw`` is the (bounded) original line, kept for keyword/free-text Sigma searches."""

    channel: str
    fields: Fields = field(default_factory=dict)
    source_format: str = ""
    raw: str = ""

    def get(self, name: str) -> "str | int | None":
        return self.fields.get(name)

    def as_dict(self) -> dict:
        return {"channel": self.channel, "source_format": self.source_format,
                "fields": dict(self.fields), "raw": self.raw}


# ---------------------------------------------------------------------------
# shared helpers
# ---------------------------------------------------------------------------


def _clip(text: str, limit: int = _MAX_VALUE) -> str:
    return text if len(text) <= limit else text[:limit]


def _coerce(value: str) -> "str | int":
    """A bare integer literal becomes an int (so numeric Sigma comparisons and int
    equality work); everything else stays a (clipped) string. Deterministic and total."""
    v = value.strip()
    if v and (v.isdigit() or (v[0] == "-" and v[1:].isdigit())):
        try:
            return int(v)
        except ValueError:
            return _clip(v)
    return _clip(v)


# key=value  and  key="quoted value"  (single OR double quotes). Linear, no backtracking blowup.
_KV_RE = re.compile(r'([A-Za-z0-9_.\-]{1,128})=("(?:[^"\\]|\\.){0,8192}"|\'(?:[^\'\\]|\\.){0,8192}\'|[^\s]{0,8192})')


def _parse_kv_pairs(text: str, into: Fields) -> None:
    """Extract ``key=value`` / ``key="value"`` pairs from free text into ``into`` (bounded).
    First-writer-wins per key so a structured field is not clobbered by a later stray match."""
    for m in _KV_RE.finditer(text):
        if len(into) >= _MAX_FIELDS:
            break
        key = m.group(1)
        if key in into:
            continue
        raw = m.group(2)
        if len(raw) >= 2 and raw[0] in "\"'" and raw[-1] == raw[0]:
            raw = raw[1:-1]
        into[key] = _coerce(raw)


def _iter_lines(text: str):
    """Yield non-empty, length-bounded lines. Total: never raises."""
    for line in text.splitlines():
        s = line.strip()
        if s:
            yield _clip(s, _MAX_LINE)


# ---------------------------------------------------------------------------
# syslog
# ---------------------------------------------------------------------------

_PRI_RE = re.compile(r"^<(\d{1,3})>")
# RFC3164:  Mon dd HH:MM:SS host tag[pid]: message    (dd may be space-padded)
_SYSLOG3164_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>[^\s]+)\s+"
    r"(?P<tag>[^\s:\[]{1,64})(?:\[(?P<pid>\d{1,10})\])?:\s?(?P<msg>.*)$"
)
# RFC5424:  1 TIMESTAMP HOST APP PROCID MSGID STRUCTURED-DATA MSG
_SYSLOG5424_RE = re.compile(
    r"^1\s+(?P<ts>[^\s]+)\s+(?P<host>[^\s]+)\s+(?P<app>[^\s]+)\s+"
    r"(?P<pid>[^\s]+)\s+(?P<msgid>[^\s]+)\s+(?P<rest>.*)$"
)


def _split_pri(line: str) -> tuple["int | None", str]:
    m = _PRI_RE.match(line)
    if not m:
        return None, line
    try:
        pri = int(m.group(1))
    except ValueError:
        return None, line
    return pri, line[m.end():]


def parse_syslog(text: str) -> list[LogEvent]:
    """Parse RFC 3164 and RFC 5424 syslog lines into ``LogEvent``s (channel 'syslog').

    A ``<PRI>`` prefix (if present) yields ``facility``/``severity``. The RFC 5424 branch is
    tried first (it is unambiguous: version digit ``1`` after the PRI); otherwise RFC 3164.
    A line matching neither still becomes an event carrying the whole line as ``message`` — the
    parser is TOTAL, so an operator's oddly-shaped logger never sinks the ingest. Structured
    ``key=value`` pairs in the message become matchable fields. Deterministic; input order kept."""
    out: list[LogEvent] = []
    for line in _iter_lines(text):
        if len(out) >= _MAX_EVENTS:
            break
        pri, body = _split_pri(line)
        fields: Fields = {}
        if pri is not None:
            fields["facility"] = pri // 8
            fields["severity"] = pri % 8
        m5 = _SYSLOG5424_RE.match(body)
        if m5:
            fields["timestamp"] = m5.group("ts")
            fields["host"] = m5.group("host")
            fields["app"] = m5.group("app")
            if m5.group("pid") not in ("-", ""):
                fields["procid"] = _coerce(m5.group("pid"))
            if m5.group("msgid") not in ("-", ""):
                fields["msgid"] = m5.group("msgid")
            # STRUCTURED-DATA ('-' or [id k="v" ...]) then MSG — keep the MSG and mine k=v from both.
            rest = m5.group("rest")
            fields["message"] = _clip(rest)
            _parse_kv_pairs(rest, fields)
        else:
            m3 = _SYSLOG3164_RE.match(body)
            if m3:
                fields["timestamp"] = m3.group("ts")
                fields["host"] = m3.group("host")
                fields["app"] = m3.group("tag")
                if m3.group("pid"):
                    fields["procid"] = _coerce(m3.group("pid"))
                msg = m3.group("msg")
                fields["message"] = _clip(msg)
                _parse_kv_pairs(msg, fields)
            else:
                fields["message"] = _clip(body)
                _parse_kv_pairs(body, fields)
        out.append(LogEvent(channel="syslog", source_format="syslog", fields=fields, raw=line))
    return out


# ---------------------------------------------------------------------------
# CEF
# ---------------------------------------------------------------------------

_CEF_HEADER = ("cef_version", "device_vendor", "device_product",
               "device_version", "cef_signature_id", "cef_name", "cef_severity")
# CEF extension keys: token=... ; a value runs up to the next ' token=' or end of line.
_CEF_EXT_RE = re.compile(r"([A-Za-z][A-Za-z0-9_.\-]{0,127})=(.*?)(?=\s[A-Za-z][A-Za-z0-9_.\-]{0,127}=|$)")


def _cef_unescape(text: str) -> str:
    # CEF escapes '\|', '\\' in the header and '\=', '\\' in the extension. A minimal, total unescape.
    return (text.replace("\\|", "|").replace("\\=", "=").replace("\\n", "\n").replace("\\\\", "\\"))


def _split_cef_header(text: str) -> "list[str] | None":
    """Split the 7 header segments on UNESCAPED '|'. Returns [seg0..seg6, extension] or None
    if there are not enough segments. Total."""
    segs: list[str] = []
    buf: list[str] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "\\" and i + 1 < n:
            buf.append(text[i:i + 2])
            i += 2
            continue
        if c == "|":
            segs.append("".join(buf))
            buf = []
            i += 1
            if len(segs) == 7:                 # everything after the 7th '|' is the extension
                segs.append(text[i:])
                return segs
            continue
        buf.append(c)
        i += 1
    segs.append("".join(buf))
    return segs if len(segs) >= 7 else None


def parse_cef(text: str) -> list[LogEvent]:
    """Parse CEF alert lines into ``LogEvent``s (channel 'cef'). The 7 pipe-delimited header
    fields become ``cef_version/device_vendor/device_product/device_version/cef_signature_id/
    cef_name/cef_severity``; the extension's ``key=value`` pairs become matchable fields (an
    unescaped '=' inside a value is handled). A line without a ``CEF:`` prefix or with too few
    header segments is skipped (total). Deterministic; input order kept."""
    out: list[LogEvent] = []
    for line in _iter_lines(text):
        if len(out) >= _MAX_EVENTS:
            break
        idx = line.find("CEF:")
        if idx < 0:
            continue
        payload = line[idx + 4:]
        segs = _split_cef_header(payload)
        if segs is None:
            continue
        fields: Fields = {}
        for name, seg in zip(_CEF_HEADER, segs[:7]):
            val = _cef_unescape(seg.strip())
            if val:
                fields[name] = _coerce(val) if name in ("cef_version", "cef_severity") else _clip(val)
        extension = segs[7] if len(segs) > 7 else ""
        for m in _CEF_EXT_RE.finditer(extension):
            if len(fields) >= _MAX_FIELDS:
                break
            key = m.group(1)
            if key in fields:
                continue
            fields[key] = _coerce(_cef_unescape(m.group(2).strip()))
        out.append(LogEvent(channel="cef", source_format="cef", fields=fields, raw=line))
    return out


# ---------------------------------------------------------------------------
# Windows EVTX-JSON
# ---------------------------------------------------------------------------


def _flatten_evtx_record(rec: object) -> "Fields | None":
    """Flatten one Windows event record (dict) into fields. Handles the flat export and the
    nested ``Event.System`` / ``Event.EventData`` shape (incl. the ``Data:[{@Name,#text}]``
    array). Returns None for a non-dict. Bounded and total."""
    if not isinstance(rec, dict):
        return None
    fields: Fields = {}

    def _put(key: object, val: object) -> None:
        if len(fields) >= _MAX_FIELDS:
            return
        if not isinstance(key, str) or not key:
            return
        k = key.lstrip("@#").strip()
        if not k or k in fields:
            return
        if isinstance(val, bool):
            fields[k] = str(val)
        elif isinstance(val, int):
            fields[k] = val
        elif isinstance(val, (str, float)):
            fields[k] = _coerce(str(val))
        # dict/list values are containers, not leaf fields — skipped (handled by callers below)

    def _absorb_map(d: object) -> None:
        if not isinstance(d, dict):
            return
        for k, v in d.items():
            if k == "Data":
                _absorb_data(v)
            elif isinstance(v, dict):
                # a leaf like {"#text": "...", "@Name": "..."} or a small nested map
                if "#text" in v and "@Name" in v:
                    _put(v.get("@Name"), v.get("#text"))
                else:
                    _put(k, v.get("#text", None))
            else:
                _put(k, v)

    def _absorb_data(data: object) -> None:
        # EventData.Data is commonly a list of {"@Name": ..., "#text": ...}, or a dict, or a scalar.
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and "@Name" in item:
                    _put(item.get("@Name"), item.get("#text"))
                elif isinstance(item, dict):
                    _absorb_map(item)
        elif isinstance(data, dict):
            _absorb_map(data)

    inner = rec.get("Event") if isinstance(rec.get("Event"), dict) else rec
    if isinstance(inner, dict):
        _absorb_map(inner.get("System")) if isinstance(inner.get("System"), dict) else None
        ed = inner.get("EventData")
        if isinstance(ed, dict):
            _absorb_map(ed)
        elif isinstance(ed, list):
            _absorb_data(ed)
        # also absorb any top-level scalar keys (the flat export shape)
        for k, v in inner.items():
            if k in ("System", "EventData", "Event"):
                continue
            if isinstance(v, (dict, list)):
                _absorb_map(v)
            else:
                _put(k, v)
    return fields or None


def parse_evtx_json(text: str) -> list[LogEvent]:
    """Parse a Windows event-log JSON export into ``LogEvent``s (channel 'windows'). Accepts a
    JSON array of records, a single record object, an object wrapping a list under 'Events'/
    'records', or newline-delimited JSON (one record per line). Each record is flattened
    (System + EventData, incl. the ``Data:[{@Name,#text}]`` array). ``json.loads`` only, bounded,
    total: an undecodable blob or record is skipped, never raised. Deterministic; input order kept."""
    records: list[object] = []
    stripped = text.strip()
    parsed_whole = False
    if stripped[:1] in ("[", "{"):
        try:
            doc = json.loads(stripped)
            parsed_whole = True
            if isinstance(doc, list):
                records = list(doc)
            elif isinstance(doc, dict):
                for key in ("Events", "events", "records", "Records"):
                    if isinstance(doc.get(key), list):
                        records = list(doc[key])
                        break
                else:
                    records = [doc]
        except (json.JSONDecodeError, ValueError, RecursionError):
            parsed_whole = False
    if not parsed_whole:
        # newline-delimited JSON (one object per line)
        for line in _iter_lines(text):
            try:
                records.append(json.loads(line))
            except (json.JSONDecodeError, ValueError, RecursionError):
                continue

    out: list[LogEvent] = []
    for rec in records:
        if len(out) >= _MAX_EVENTS:
            break
        fields = _flatten_evtx_record(rec)
        if fields is None:
            continue
        out.append(LogEvent(channel="windows", source_format="evtx_json", fields=fields,
                            raw=_clip(json.dumps(rec, default=str, sort_keys=True))))
    return out


# ---------------------------------------------------------------------------
# format detection + unified entry points
# ---------------------------------------------------------------------------

_PARSERS = {"syslog": parse_syslog, "cef": parse_cef, "evtx_json": parse_evtx_json}


def detect_format(text: str) -> str:
    """Best-effort format sniff. JSON-ish (starts with '{'/'[') -> 'evtx_json'; a 'CEF:' marker
    on the first non-empty line -> 'cef'; otherwise 'syslog'. Total and deterministic."""
    s = text.lstrip()
    if s[:1] in ("[", "{"):
        return "evtx_json"
    for line in _iter_lines(text):
        if "CEF:" in line:
            return "cef"
        break
    return "syslog"


def parse_log(text: str, fmt: str = "auto") -> list[LogEvent]:
    """Parse ``text`` in ``fmt`` ('syslog'|'cef'|'evtx_json'|'auto'). Unknown fmt -> [] (total).
    Pure: same bytes in, same events out."""
    if not isinstance(text, str) or not text.strip():
        return []
    chosen = detect_format(text) if fmt == "auto" else fmt
    parser = _PARSERS.get(chosen)
    return parser(text) if parser is not None else []


@dataclass
class LogLoad:
    """The outcome of a file load: the parsed events plus an honest ``note`` when the file was
    absent/oversized/unreadable (a clean skip, never a crash)."""

    events: list[LogEvent] = field(default_factory=list)
    format: str = ""
    ok: bool = True
    note: str = ""


def load_log_file(path: str, fmt: str = "auto", *, max_bytes: int = _MAX_BYTES) -> LogLoad:
    """Read an operator-supplied log file (bounded) and parse it. GRACEFUL ABSENCE: a missing,
    empty, oversized, or unreadable file yields ``LogLoad(ok=False, events=[], note=...)`` —
    never an exception — so a caller that opts into log ingestion but points at a bad path
    degrades to 'no events', not a broken engagement. UNTRUSTED: reads at most ``max_bytes``
    and errors are contained. Deterministic given file contents."""
    if not path or not isinstance(path, str):
        return LogLoad(ok=False, note="no log path supplied")
    p = Path(path).expanduser()
    try:
        if not p.is_file():
            return LogLoad(ok=False, note=f"log file not found: {p}")
        size = p.stat().st_size
        if size > max_bytes:
            return LogLoad(ok=False, note=f"log file too large ({size} > {max_bytes} bytes) — refused")
        text = p.read_text(encoding="utf-8", errors="replace")[: max_bytes]
    except OSError as e:
        return LogLoad(ok=False, note=f"cannot read log file {p}: {e}")
    chosen = detect_format(text) if fmt == "auto" else fmt
    events = parse_log(text, chosen)
    return LogLoad(events=events, format=chosen, ok=True,
                   note=f"parsed {len(events)} event(s) as {chosen}")


# ---------------------------------------------------------------------------
# gated sensor (T1, kill-switch only) — for the W1.4 tool seam
# ---------------------------------------------------------------------------


class LogSourceSensor:
    """Read an operator-supplied log/alert FILE and return normalized ``LogEvent``s.

    A gated ``agents.tools.Tool`` (so it runs through ``invoke_tool``'s fail-closed chain). It
    is PASSIVE / OFFLINE — it reads a local file, sends no traffic, reaches no host — so it is
    Tier-1, no entitlement, no egress, and (naming neither ``target`` nor ``host`` in its args)
    it is gated ONLY by the engagement kill-switch. A tripped switch refuses the read; a missing
    file degrades cleanly to a failed result. args: ``{"log": "/path/to/file", "format":
    "auto"|"syslog"|"cef"|"evtx_json"}``.

    It deliberately mints NOTHING into the world-model (``normalize`` returns ``[]``): the log
    events feed the DEFENSIVE reasoning (Sigma runtime + detection efficacy), not the attack
    graph. Its parsed events ride on the ``ToolResult.output['events']`` for that consumer."""

    name = "log_source"
    tier = "T1"
    capability = None
    destructive = False
    egress_hosts: tuple = ()

    def run(self, args: dict, ctx) -> "object":
        from ..agents.tools import ToolResult
        path = args.get("log") if isinstance(args, dict) else None
        if not path or not isinstance(path, str):
            return ToolResult(ok=False, note="log_source requires args['log'] (a path to a log file)")
        fmt = args.get("format", "auto") if isinstance(args, dict) else "auto"
        if not isinstance(fmt, str):
            fmt = "auto"
        load = load_log_file(path, fmt)
        if not load.ok:
            return ToolResult(ok=False, note=load.note)
        return ToolResult(
            ok=True, summary=load.note,
            output={"format": load.format, "count": len(load.events),
                    "events": [e.as_dict() for e in load.events]})

    def normalize(self, result, ctx, *, seq: int):
        # Defensive log events do not project onto the attack world-model (prove-don't-guess:
        # they are telemetry the operator already holds, not new attack facts). Mint nothing.
        return []
