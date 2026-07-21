"""
fsjob.traffic — read-only captured-traffic proxy tools over a STATIC corpus (VIGIL-FUSION F9).

A port of redamon's passive ``traffic_tools`` (proxy_search/get/grep/sitemap/params) as pure,
read-only sensors over a provided corpus of captured HTTP transactions. Deliberately NON-live: there is
no proxy, no replay, no fuzz, no network — the DANGEROUS active tools (proxy_replay/proxy_fuzz) that
emit live traffic are NOT implemented in this slice; when added they will be actions that must clear the
WARDEN tier + conjunctive gate + egress gate (SCOUT §361), never a read tool.

Sovereign posture:

  * **Sensors, not authorities.** Everything these tools return is attacker-influenced data captured
    from a possibly-hostile target → an LLM LEAD only, never a fact. :meth:`TrafficCorpus.to_llm_digest`
    frames it through the F1 untrusted-content boundary (``prompt_safety.wrap_untrusted``) so it enters
    a reasoning call as inert DATA.
  * **Secret-free.** Header/body previews are scrubbed through the ONE F3 redaction path
    (``tools.redact_tool_args``) so a captured ``Authorization``/``Cookie`` is never surfaced or logged.
  * **Total + DoS-safe.** The constructor coerces the corpus and SKIPS malformed entries; every method
    is total. ``grep`` is a LITERAL (fixed-string) match — ReDoS-free by construction — over bounded
    text; all outputs are row/size bounded.

Import-clean: pydantic + stdlib + the F1/F3 helpers only.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import parse_qsl, urlsplit

from pydantic import BaseModel, Field

from ..safety import wrap_untrusted, wrap_untrusted_inline
from ..tools import redact_tool_args

_MAX_ROWS = 200
_MAX_BODY_CHARS = 12000
_MAX_SNIPPET = 240
_MAX_CORPUS = 100_000            # a corpus larger than this is truncated (DoS bound)

# Anchored, bounded char classes → linear matching, no catastrophic backtracking.
_UUID_RE = re.compile(r"\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z")
_JWT_RE = re.compile(r"\A[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\Z")
_B64_RE = re.compile(r"\A[A-Za-z0-9+/]{16,}={0,2}\Z")


def _scrub_str(value: object) -> str:
    """Scrub inline secrets from a free string via the ONE F3 redaction path."""
    if not isinstance(value, str):
        value = "" if value is None else str(value)
    return redact_tool_args({"v": value}).get("v", "")


def _scrub_headers(headers: object) -> Dict[str, str]:
    """Redact a header map (masks Authorization/Cookie/… wholesale, scrubs inline secrets elsewhere)."""
    if not isinstance(headers, dict):
        return {}
    scrubbed = redact_tool_args({str(k): ("" if v is None else str(v)) for k, v in headers.items()})
    return {k: (v if isinstance(v, str) else str(v)) for k, v in scrubbed.items()}


def _classify_value(value: str) -> List[str]:
    classes: List[str] = []
    if _UUID_RE.match(value):
        classes.append("uuid")
    if _JWT_RE.match(value):
        classes.append("jwt")
    if not classes and _B64_RE.match(value):
        classes.append("base64")
    return classes


class CapturedTxn(BaseModel):
    """One captured HTTP transaction in the static corpus (read-only). Extra/malformed source fields are
    ignored; a source row that cannot be coerced is skipped by the loader (total)."""

    id: str
    method: str = "GET"
    url: str = ""
    status: int = 0
    req_headers: Dict[str, str] = Field(default_factory=dict)
    req_body: str = ""
    resp_headers: Dict[str, str] = Field(default_factory=dict)
    resp_body: str = ""

    @property
    def host(self) -> str:
        return urlsplit(self.url).netloc

    @property
    def path(self) -> str:
        return urlsplit(self.url).path or "/"


def _load(transactions: Iterable[Any]) -> List[CapturedTxn]:
    out: List[CapturedTxn] = []
    if not isinstance(transactions, Iterable) or isinstance(transactions, (str, bytes)):
        return out
    for i, row in enumerate(transactions):
        if i >= _MAX_CORPUS:
            break
        try:
            if isinstance(row, CapturedTxn):
                out.append(row)
            elif isinstance(row, dict):
                out.append(CapturedTxn.model_validate(row))
        except Exception:  # noqa: BLE001 — a malformed corpus row is skipped, never fatal
            continue
    return out


class TrafficCorpus:
    """Read-only search/get/grep/sitemap/params over a provided static corpus of captured transactions.
    No live proxy — the corpus is injected; nothing here emits traffic or mutates state."""

    def __init__(self, transactions: Iterable[Any]) -> None:
        self._txns: tuple = tuple(_load(transactions))
        self._by_id = {t.id: t for t in self._txns}

    def __len__(self) -> int:
        return len(self._txns)

    def _row(self, t: CapturedTxn, *, bodies: bool = False) -> Dict[str, Any]:
        row: Dict[str, Any] = {"id": t.id, "method": t.method, "url": _scrub_str(t.url),
                               "status": t.status, "host": t.host, "path": t.path}
        if bodies:
            row["req_headers"] = _scrub_headers(t.req_headers)
            row["resp_headers"] = _scrub_headers(t.resp_headers)
            row["req_body"] = _scrub_str(t.req_body[:_MAX_BODY_CHARS])
            row["resp_body"] = _scrub_str(t.resp_body[:_MAX_BODY_CHARS])
        return row

    def search(self, *, method: Optional[str] = None, host: Optional[str] = None,
               status: Optional[int] = None, contains: Optional[str] = None,
               limit: int = _MAX_ROWS) -> List[Dict[str, Any]]:
        """Filter transactions by method/host/status and a LITERAL url substring. Bounded, redacted."""
        try:
            cap = max(0, min(int(limit), _MAX_ROWS))
        except (TypeError, ValueError):
            cap = _MAX_ROWS
        needle = contains if isinstance(contains, str) else None
        want_method = method.upper() if isinstance(method, str) else None
        out: List[Dict[str, Any]] = []
        for t in self._txns:
            if want_method is not None and t.method.upper() != want_method:
                continue
            if isinstance(host, str) and host and host not in t.host:
                continue
            if isinstance(status, int) and t.status != status:
                continue
            if needle is not None and needle not in t.url:
                continue
            out.append(self._row(t))
            if len(out) >= cap:
                break
        return out

    def get(self, txn_id: object) -> Optional[Dict[str, Any]]:
        """Full (redacted, body-bounded) transaction by id, or ``None``. Never raises."""
        if not isinstance(txn_id, str):
            return None
        t = self._by_id.get(txn_id)
        return self._row(t, bodies=True) if t is not None else None

    def grep(self, needle: object, *, limit: int = _MAX_ROWS) -> List[Dict[str, Any]]:
        """LITERAL (fixed-string) match over url + request/response bodies (bounded). ReDoS-free by
        construction. Returns matching ids with a short redacted snippet around the first hit."""
        if not isinstance(needle, str) or needle == "":
            return []
        try:
            cap = max(0, min(int(limit), _MAX_ROWS))
        except (TypeError, ValueError):
            cap = _MAX_ROWS
        out: List[Dict[str, Any]] = []
        for t in self._txns:
            hay_fields = (("url", t.url), ("req_body", t.req_body[:_MAX_BODY_CHARS]),
                          ("resp_body", t.resp_body[:_MAX_BODY_CHARS]))
            for field_name, hay in hay_fields:
                idx = hay.find(needle)
                if idx < 0:
                    continue
                start = max(0, idx - _MAX_SNIPPET // 2)
                snippet = hay[start:start + _MAX_SNIPPET]
                out.append({"id": t.id, "field": field_name, "url": _scrub_str(t.url),
                            "snippet": _scrub_str(snippet)})
                break
            if len(out) >= cap:
                break
        return out

    def sitemap(self) -> List[Dict[str, Any]]:
        """Endpoints grouped by host → sorted paths, with the methods and status codes seen (deterministic)."""
        by_host: Dict[str, Dict[str, Any]] = {}
        for t in self._txns:
            h = by_host.setdefault(t.host, {"paths": set(), "methods": set(), "statuses": set()})
            h["paths"].add(t.path)
            h["methods"].add(t.method.upper())
            h["statuses"].add(t.status)
        return [{"host": host, "paths": sorted(v["paths"]),
                 "methods": sorted(v["methods"]), "statuses": sorted(v["statuses"])}
                for host, v in sorted(by_host.items())]

    def params(self) -> List[Dict[str, Any]]:
        """Query/form parameters observed across the corpus, with value classes (uuid/jwt/base64) and a
        redacted example — a recon aid. Deterministic ordering; values redacted before exposure."""
        seen: Dict[str, Dict[str, Any]] = {}

        def _note(name: str, value: str) -> None:
            rec = seen.setdefault(name, {"name": name, "classes": set(), "example": "", "count": 0})
            rec["count"] += 1
            for cls in _classify_value(value):
                rec["classes"].add(cls)
            if not rec["example"]:
                # Scrub the value UNDER ITS OWN PARAM NAME so the key-based mask fires — matching the
                # search/get/grep path, which scrub the identical value inline as ``name=value``. A bare
                # value under a neutral key slips ``_is_secret_key`` and ``_redact_str`` never masks a
                # lone value, so a captured ``token=``/``password=``/``apikey=`` credential would surface
                # here. ONE secret vocabulary, ONE scrubber path (F3).
                rec["example"] = str(redact_tool_args({name: value[:80]}).get(name, ""))

        for t in self._txns:
            for k, v in parse_qsl(urlsplit(t.url).query, keep_blank_values=True):
                _note(k, v)
            # best-effort: a urlencoded request body's params
            if "=" in t.req_body and "\n" not in t.req_body[:_MAX_BODY_CHARS]:
                for k, v in parse_qsl(t.req_body[:_MAX_BODY_CHARS], keep_blank_values=True):
                    _note(k, v)
        return [{"name": r["name"], "classes": sorted(r["classes"]),
                 "example": r["example"], "count": r["count"]}
                for r in sorted(seen.values(), key=lambda r: r["name"])]

    def to_llm_digest(self, rows: object, *, label: str = "CAPTURED_TRAFFIC") -> str:
        """Frame corpus rows for a reasoning call as INERT, untrusted DATA (F1 boundary) — a LEAD, never
        a fact. Bodies/snippets are wrapped in the one-time nonce boundary so injected marker text inside
        captured content cannot break out of the frame. Total like its siblings: a non-list ``rows`` (or
        a non-dict entry) degrades to no-signal, never raises (a crash is a denial-of-cognition)."""
        lines: List[str] = []
        if isinstance(rows, (list, tuple)):
            for row in rows[:_MAX_ROWS]:
                if not isinstance(row, dict):
                    continue
                method = str(row.get("method", ""))
                url = str(row.get("url", ""))
                base = f"{method} {url} -> {row.get('status', '')}".strip()
                snippet = row.get("snippet") or row.get("resp_body") or ""
                if snippet:
                    base += " " + wrap_untrusted_inline(str(snippet)[:_MAX_SNIPPET], "TXN")
                lines.append(base)
        body = "\n".join(lines) if lines else "(no matching captured transactions)"
        return wrap_untrusted(body, label)
