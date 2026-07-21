"""
detection.logs — the deterministic telemetry parsers for the AEGIS Detection Mirror edge/auth planes.

The Sentinels read telemetry the systems you protect actually produced; they wield no tool. This module
turns three retained log sources into typed, ordered records the oracles reason over:

  * ``parse_access_log`` — an Apache/nginx Combined-Log-Format (CLF) access log (the RAMPART edge plane).
  * ``parse_auth_log``   — the loopback app's ``auth.log`` (``<ts>  src=.. user=.. result=..``).
  * ``parse_conn_log``   — a connection/flow log (``<ts>  src=.. dst=.. dport=.. proto=..``) — the
    conntrack/NetFlow evidence ``port_scan`` runs over (the edge app emits HTTP logs, not per-port
    connection records, so this plane is fed by ingested flow telemetry — stated honestly).

Invariants this module upholds (the red-pen attacks exactly these):

  * **NO CLOCK / NO RNG.** The record ordering axis is derived FROM THE RECORDS: the 0-based line index
    (``seq``) and the timestamp PARSED OUT OF THE LOG TEXT (``ts``, epoch seconds via a pure days-from-
    civil computation — never ``time``/``datetime.now``/``random``/``uuid``). Parsing a timestamp string
    a log already contains is reading data, not a wallclock.
  * **TOTAL on malformed input.** Log lines are attacker-influenceable. Every parser degrades a
    malformed/garbage line to a record with as much as parsed (``ts=None``, empty fields) and NEVER
    raises. A line that cannot be parsed simply matches no signature (no signal). ``seq`` stays the line
    index so evidence references remain stable.
  * **Percent-decoding for structure.** Attack payloads reach the edge percent-encoded; the injection
    oracles need the DECODED form. Each access record carries both the raw request target and its decoded
    form so an oracle can match the true structure (``' OR '1'='1``) without being defeated by ``%27``.

Import-clean: stdlib only (``re`` + ``urllib.parse.unquote``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import unquote

# ---------------------------------------------------------------------------------------------------
# pure timestamp parsing (NO wallclock) — the log's OWN timestamp string → a comparable epoch int
# ---------------------------------------------------------------------------------------------------

_MONTHS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}


def _days_from_civil(y: int, m: int, d: int) -> int:
    """Howard Hinnant's pure days-from-civil: calendar date → days since 1970-01-01. Integer-only, no
    ``datetime`` (so no wallclock/tz surprise); deterministic for a given (y, m, d)."""
    y -= 1 if m <= 2 else 0
    era = (y if y >= 0 else y - 399) // 400
    yoe = y - era * 400
    doy = (153 * (m + (-3 if m > 2 else 9)) + 2) // 5 + d - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


# CLF-style ``21/Jul/2026:15:26:30`` (a trailing space / a ``+0000`` tz suffix are both tolerated).
_CLF_TS_RE = re.compile(
    r"^\s*(\d{1,2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})", re.ASCII)


def parse_clf_time(ts_raw: object) -> Optional[int]:
    """Parse a CLF/auth timestamp string to epoch SECONDS (UTC, tz-naive — the loopback logs carry no
    zone), purely from the string's own digits. Returns ``None`` on any malformed value — never raises,
    never consults a clock."""
    if not isinstance(ts_raw, str):
        return None
    m = _CLF_TS_RE.match(ts_raw)
    if m is None:
        return None
    try:
        day = int(m.group(1))
        mon = _MONTHS.get(m.group(2).lower())
        if mon is None:
            return None
        year, hh, mm, ss = int(m.group(3)), int(m.group(4)), int(m.group(5)), int(m.group(6))
        if not (1 <= day <= 31 and 0 <= hh <= 23 and 0 <= mm <= 59 and 0 <= ss <= 60):
            return None
        return _days_from_civil(year, mon, day) * 86400 + hh * 3600 + mm * 60 + ss
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------------------------------
# record models
# ---------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class AccessRecord:
    """One CLF access-log line. ``target`` is the raw request target (path+query, still percent-encoded);
    ``decoded_target`` is its ``unquote``d form for structural matching. ``ts`` is epoch seconds parsed
    from the line (``None`` if absent/malformed); ``seq`` is the 0-based line index."""

    seq: int
    raw: str
    src: str = ""
    ts: Optional[int] = None
    ts_raw: str = ""
    method: str = ""
    target: str = ""
    route: str = ""
    query: str = ""
    decoded_target: str = ""
    decoded_query: str = ""
    protocol: str = ""
    status: int = 0
    size: int = 0
    referer: str = ""
    user_agent: str = ""

    @property
    def key(self) -> int:
        """The ordering axis: the parsed timestamp when present, else the line index (both from the
        record itself — never a clock)."""
        return self.ts if self.ts is not None else self.seq


@dataclass(frozen=True)
class AuthRecord:
    """One ``auth.log`` line: ``<ts>  src=<ip> user=<user> result=<success|failure>``."""

    seq: int
    raw: str
    src: str = ""
    user: str = ""
    result: str = ""
    ts: Optional[int] = None
    ts_raw: str = ""

    @property
    def is_failure(self) -> bool:
        return self.result == "failure"

    @property
    def key(self) -> int:
        return self.ts if self.ts is not None else self.seq


@dataclass(frozen=True)
class ConnRecord:
    """One connection/flow line: ``<ts>  src=<ip> dst=<ip> dport=<port> proto=<tcp|udp>``. The
    conntrack/NetFlow evidence ``port_scan`` runs over."""

    seq: int
    raw: str
    src: str = ""
    dst: str = ""
    dport: int = 0
    proto: str = ""
    ts: Optional[int] = None
    ts_raw: str = ""

    @property
    def key(self) -> int:
        return self.ts if self.ts is not None else self.seq


# ---------------------------------------------------------------------------------------------------
# parsers — TOTAL, never raise, one record per line (seq = line index)
# ---------------------------------------------------------------------------------------------------

# %h %l %u [%t] "%r" %>s %b "%{Referer}i" "%{User-agent}i" — the trailing quoted pair is optional so a
# stripped-down CLF line still parses its request/status.
_CLF_RE = re.compile(
    r'^(?P<h>\S+)\s+(?P<l>\S+)\s+(?P<u>\S+)\s+\[(?P<t>[^\]]*)\]\s+'
    r'"(?P<req>[^"]*)"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)")?')


def _decode(s: str) -> str:
    """Percent-decode total: ``unquote`` never raises on bad escapes (it leaves them literal)."""
    try:
        return unquote(s)
    except Exception:  # noqa: BLE001 — a malformed escape must never crash the parser
        return s


def _split_request(req: str) -> tuple[str, str, str]:
    """Split a CLF request line ``METHOD TARGET PROTO`` tolerantly. A missing protocol keeps the rest as
    the target; a blank request yields empty fields. Never raises."""
    req = req.strip()
    if not req:
        return "", "", ""
    parts = req.split(" ")
    if len(parts) == 1:
        return parts[0], "", ""
    method = parts[0]
    last = parts[-1]
    if last.upper().startswith("HTTP/") and len(parts) >= 3:
        return method, " ".join(parts[1:-1]), last
    return method, " ".join(parts[1:]), ""


def parse_access_line(line: str, seq: int) -> AccessRecord:
    """Parse ONE CLF line to an :class:`AccessRecord`. Total: an unparseable line yields a record with
    ``raw``/``seq`` set and empty structural fields (it will match no signature)."""
    raw = line.rstrip("\n")
    m = _CLF_RE.match(raw)
    if m is None:
        return AccessRecord(seq=seq, raw=raw)
    method, target, proto = _split_request(m.group("req"))
    route, _, query = target.partition("?")
    try:
        status = int(m.group("status"))
    except (TypeError, ValueError):
        status = 0
    size_s = m.group("size") or "0"
    try:
        size = int(size_s) if size_s not in ("-", "") else 0
    except (TypeError, ValueError):
        size = 0
    ts_raw = (m.group("t") or "").strip()
    return AccessRecord(
        seq=seq, raw=raw,
        src=m.group("h") or "",
        ts=parse_clf_time(ts_raw), ts_raw=ts_raw,
        method=method, target=target, route=route, query=query,
        decoded_target=_decode(target), decoded_query=_decode(query),
        protocol=proto, status=status, size=size,
        referer=(m.group("ref") or ""), user_agent=(m.group("ua") or ""),
    )


def parse_access_log(text: object) -> list[AccessRecord]:
    """Parse a CLF access log (``text`` = the file contents). Total on any input — a non-str yields
    ``[]``; blank lines are skipped but ``seq`` tracks the surviving records in order."""
    if not isinstance(text, str):
        return []
    out: list[AccessRecord] = []
    seq = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        out.append(parse_access_line(line, seq))
        seq += 1
    return out


_KV_TOKEN_RE = re.compile(r"^(\w+)=(\S+)$")


def _kv(line: str) -> dict:
    """Parse ``key=value`` tokens from a whitespace-delimited line. Tokenizing FIRST (``str.split``)
    keeps this LINEAR — a single ``re.findall(r'(\\w+)=(\\S+)', ...)`` over a long line WITHOUT an ``=``
    backtracks O(n^2) (a ReDoS on attacker-influenced logs); an anchored per-token match cannot."""
    out: dict = {}
    for tok in line.split():
        m = _KV_TOKEN_RE.match(tok)
        if m:
            out[m.group(1)] = m.group(2)
    return out


def parse_auth_line(line: str, seq: int) -> AuthRecord:
    """Parse ONE ``auth.log`` line. Total: unknown/missing keys degrade to empty strings."""
    raw = line.rstrip("\n")
    ts_m = _CLF_TS_RE.match(raw)
    ts_raw = raw[ts_m.start():ts_m.end()].strip() if ts_m else ""
    kv = _kv(raw)
    result = (kv.get("result") or "").lower()
    return AuthRecord(
        seq=seq, raw=raw,
        src=kv.get("src", ""), user=kv.get("user", ""),
        result=result if result in ("success", "failure") else "",
        ts=parse_clf_time(ts_raw), ts_raw=ts_raw,
    )


def parse_auth_log(text: object) -> list[AuthRecord]:
    if not isinstance(text, str):
        return []
    out: list[AuthRecord] = []
    seq = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        out.append(parse_auth_line(line, seq))
        seq += 1
    return out


def parse_conn_line(line: str, seq: int) -> ConnRecord:
    """Parse ONE connection/flow line. Total: a non-integer ``dport`` degrades to 0 (matches nothing)."""
    raw = line.rstrip("\n")
    ts_m = _CLF_TS_RE.match(raw)
    ts_raw = raw[ts_m.start():ts_m.end()].strip() if ts_m else ""
    kv = _kv(raw)
    try:
        dport = int(kv.get("dport", "0"))
    except (TypeError, ValueError):
        dport = 0
    if not (0 <= dport <= 65535):
        dport = 0
    return ConnRecord(
        seq=seq, raw=raw,
        src=kv.get("src", ""), dst=kv.get("dst", ""),
        dport=dport, proto=(kv.get("proto") or "").lower(),
        ts=parse_clf_time(ts_raw), ts_raw=ts_raw,
    )


def parse_conn_log(text: object) -> list[ConnRecord]:
    if not isinstance(text, str):
        return []
    out: list[ConnRecord] = []
    seq = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        out.append(parse_conn_line(line, seq))
        seq += 1
    return out
