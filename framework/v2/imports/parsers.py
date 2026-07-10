"""
imports.parsers — parse a third-party tool export into ``ImportedFinding``s.

The heavy lifting is REUSED, not re-implemented: the Nuclei / ZAP / Burp / sqlmap
parsers already live (tested against captured real output) in ``eval.adapters`` —
this module wraps each and maps its ``NormalizedFinding`` onto ``ImportedFinding``,
deriving the host. It adds ONE new parser, ``parse_generic``, for a tool-neutral
findings JSON (the escape hatch for any tool CRUCIBLE has no dedicated adapter for).

Every parser is a pure ``str -> list[ImportedFinding]``: it raises
``ImportAdapterError`` on MALFORMED input (non-JSON where JSON is promised, the wrong
top-level shape) and returns ``[]`` on an empty-but-well-formed export. No I/O, no
network, no eval/shell — the input is untrusted text and is treated as data only.
"""

from __future__ import annotations

import json
from urllib.parse import urlsplit

from ..eval.adapters import (
    AdapterError,
    parse_burp,
    parse_nuclei,
    parse_sqlmap,
    parse_zap,
)
from ..eval.validation import NormalizedFinding
from .models import ImportAdapterError, ImportedFinding

# The maximum number of findings a single import will mint. A defensive bound so a
# hostile / runaway export cannot balloon the world-model in one call. Excess findings
# are dropped with a warning (surfaced by the importer), never silently.
MAX_FINDINGS = 5000


def _host_of(location: str) -> str:
    """Best-effort host from a location string — a URL's netloc, else the leading
    ``host[:port]`` token of a bare ``host/path``. CONSERVATIVE: a bare single token
    that does not look like a host (no dot, not an IP, not ``localhost``) is NOT treated
    as one — e.g. sqlmap's location is a parameter name (``id``), which must never
    become a bogus ``domain:id`` asset. Total; never raises."""
    import ipaddress

    s = (location or "").strip()
    if not s:
        return ""
    try:
        if "://" in s:
            return (urlsplit(s).hostname or "").strip()
        token = s.split("/", 1)[0].split(":", 1)[0].strip()
        if not token:
            return ""
        if "." in token or token.lower() == "localhost":
            return token
        try:
            ipaddress.ip_address(token)
            return token
        except ValueError:
            return ""  # a bare non-dotted token is a param/label, not a host
    except Exception:
        return ""


def _from_normalized(findings: list[NormalizedFinding]) -> list[ImportedFinding]:
    """Map the eval harness's tool-agnostic shape onto ours, deriving the host."""
    out: list[ImportedFinding] = []
    for f in findings:
        out.append(ImportedFinding(
            tool=f.tool,
            bug_class=f.bug_class,
            location=f.location,
            host=_host_of(f.location),
            severity=f.severity,
            tool_confirmed=f.confirmed,
            evidence=f.evidence,
        ))
    return out


def _wrap(parser, output: str) -> list[ImportedFinding]:
    """Run a reused eval parser and translate its ``AdapterError`` into ours, so a
    caller sees one exception family regardless of which adapter parsed."""
    try:
        normalized = parser(output)
    except AdapterError as e:
        raise ImportAdapterError(str(e)) from e
    return _from_normalized(normalized)


def parse_nuclei_export(output: str) -> list[ImportedFinding]:
    """Nuclei ``-jsonl`` output (one JSON object per line)."""
    return _wrap(parse_nuclei, output)


def parse_zap_export(output: str) -> list[ImportedFinding]:
    """OWASP ZAP traditional JSON report (``{"site": [{"alerts": [...]}]}``)."""
    return _wrap(parse_zap, output)


def parse_burp_export(output: str) -> list[ImportedFinding]:
    """Burp REST scan-issues JSON (array / ``{"issues": [...]}`` / ``issue_events``)."""
    return _wrap(parse_burp, output)


def parse_sqlmap_export(output: str) -> list[ImportedFinding]:
    """sqlmap stdout injection-summary log."""
    return _wrap(parse_sqlmap, output)


def parse_generic(output: str) -> list[ImportedFinding]:
    """A tool-neutral findings JSON — the escape hatch for any tool without a
    dedicated adapter. Accepts a bare array of finding objects OR
    ``{"findings": [...]}`` / ``{"results": [...]}``. Each finding object reads
    (first present key wins):

        bug_class : ``bug_class`` | ``type`` | ``name`` | ``vuln`` | ``category``
        location  : ``location`` | ``url`` | ``target`` | ``endpoint`` | ``uri``
        host      : ``host`` (else derived from location)
        severity  : ``severity``
        confirmed : ``confirmed`` (bool — the tool's own confidence)
        evidence  : ``evidence`` | ``detail`` | ``description``
        tool      : ``tool`` | ``scanner`` (else ``"generic"``)

    Non-JSON, or a non-object/array top level, is malformed -> ImportAdapterError.
    Individual entries that are not objects are skipped defensively (they do not
    abort the whole import)."""
    try:
        data = json.loads(output)
    except (json.JSONDecodeError, TypeError) as e:
        raise ImportAdapterError(f"generic findings export is not valid JSON: {e}") from e

    if isinstance(data, dict):
        items = data.get("findings")
        if items is None:
            items = data.get("results")
        if items is None:
            # a single finding object is tolerated
            items = [data]
    elif isinstance(data, list):
        items = data
    else:
        raise ImportAdapterError("generic findings export must be a JSON array or object")

    if not isinstance(items, list):
        raise ImportAdapterError("generic findings 'findings'/'results' must be an array")

    def _first(d: dict, *keys: str, default: str = "") -> str:
        for k in keys:
            v = d.get(k)
            if v not in (None, ""):
                return str(v)
        return default

    out: list[ImportedFinding] = []
    for entry in items:
        if not isinstance(entry, dict):
            continue  # skip a malformed entry, don't abort the batch
        location = _first(entry, "location", "url", "target", "endpoint", "uri")
        host = _first(entry, "host") or _host_of(location)
        out.append(ImportedFinding(
            tool=_first(entry, "tool", "scanner", default="generic"),
            bug_class=_first(entry, "bug_class", "type", "name", "vuln", "category", default="unknown"),
            location=location,
            host=host,
            severity=_first(entry, "severity"),
            tool_confirmed=bool(entry.get("confirmed", False)),
            evidence=_first(entry, "evidence", "detail", "description"),
        ))
    return out


# format name -> (parser, default source-tool label). ``detect_format`` and the CLI
# read this table; it is the whole contract of supported inputs.
_PARSERS = {
    "nuclei": (parse_nuclei_export, "nuclei"),
    "zap": (parse_zap_export, "zap"),
    "burp": (parse_burp_export, "burp"),
    "sqlmap": (parse_sqlmap_export, "sqlmap"),
    "generic": (parse_generic, "generic"),
}


def available_formats() -> list[str]:
    """The supported import formats, sorted (the CLI/API surface)."""
    return sorted(_PARSERS)


def parse_export(fmt: str, output: str) -> tuple[list[ImportedFinding], str]:
    """Parse ``output`` with the parser for ``fmt``. Returns ``(findings,
    default_source_tool)``. Enforces ``MAX_FINDINGS`` (excess dropped by the caller).
    An unknown format is an ImportAdapterError (fail-loud, never a silent no-op)."""
    key = (fmt or "").strip().lower()
    if key not in _PARSERS:
        raise ImportAdapterError(
            f"unknown import format {fmt!r}; supported: {', '.join(available_formats())}")
    parser, default_tool = _PARSERS[key]
    findings = parser(output)
    return findings, default_tool


def detect_format(output: str) -> str | None:
    """Best-effort format sniff for a raw export, for the operator convenience path.
    Deterministic and side-effect-free; returns None when it cannot tell (the caller
    then requires an explicit ``format``). Never raises."""
    s = (output or "").strip()
    if not s:
        return None
    # sqlmap is a text log, not JSON.
    if "sqlmap identified the following injection point" in s.lower() or "Parameter:" in s:
        return "sqlmap"
    # JSON shapes. Try the FIRST line as an object (nuclei is JSONL — one object per
    # line — so this catches both single- and multi-line nuclei exports).
    try:
        first_obj = json.loads(s.splitlines()[0])
    except Exception:
        first_obj = None
    if isinstance(first_obj, dict) and ("template-id" in first_obj or "matched-at" in first_obj):
        return "nuclei"
    try:
        data = json.loads(s)
    except Exception:
        return None
    if isinstance(data, dict):
        if "site" in data:
            return "zap"
        if "issues" in data or "issue_events" in data:
            return "burp"
        if "findings" in data or "results" in data:
            return "generic"
    if isinstance(data, list):
        return "generic"
    return None
