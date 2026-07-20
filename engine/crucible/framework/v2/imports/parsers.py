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
import re
from urllib.parse import urlsplit

from ..eval.adapters import (
    AdapterError,
    parse_burp,
    parse_nuclei,
    parse_sqlmap,
    parse_zap,
)
from ..eval.adapters_ext import parse_nikto, parse_wapiti
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


def parse_nikto_export(output: str) -> list[ImportedFinding]:
    """Nikto ``-Format json`` report (host(s) → vulnerabilities list of ``{msg, url, ...}``)."""
    return _wrap(parse_nikto, output)


def parse_wapiti_export(output: str) -> list[ImportedFinding]:
    """Wapiti JSON report (``{"vulnerabilities": {"<category>": [{path, parameter, level}]}}``)."""
    return _wrap(parse_wapiti, output)


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


# SARIF result.level -> our severity bucket. `error`/`warning`/`note`/`none` is the SARIF vocabulary.
_SARIF_LEVEL_SEV = {"error": "High", "warning": "Medium", "note": "Low", "none": "Info"}
# SARIF result.kind values that are NOT a finding (a passing / inapplicable check) — skipped.
_SARIF_NON_FINDING_KINDS = {"pass", "notapplicable", "informational"}
# CWE number (un-padded) -> CRUCIBLE bug_class, so a SARIF finding tagged with a CWE routes to the oracle
# that can re-verify it (a URL-located DAST finding), instead of an opaque tool-specific rule id. A SAST
# class with no runtime oracle (hardcoded_secret / weak_crypto) still imports as an honest lead.
_CWE_TO_BUG_CLASS = {
    "79": "xss", "80": "xss", "83": "xss",
    "89": "sqli", "564": "sqli",
    "77": "command_injection", "78": "command_injection",
    "94": "rce", "95": "rce",
    "22": "path_traversal", "23": "path_traversal", "36": "path_traversal", "98": "lfi",
    "611": "xxe", "827": "xxe",
    "918": "ssrf",
    "502": "deserialization",
    "90": "ldap_injection", "643": "xpath_injection",
    "917": "ssti", "1336": "ssti",
    "601": "open_redirect", "352": "csrf",
    "798": "hardcoded_secret", "259": "hardcoded_secret",
    "327": "weak_crypto", "326": "weak_crypto",
}
_CWE_RE = re.compile(r"cwe[-_ ]?0*(\d+)", re.I)


def _sarif_tool_name(run: dict) -> str:
    tool = run.get("tool")
    drv = tool.get("driver") if isinstance(tool, dict) else None
    return str(drv.get("name") or "") if isinstance(drv, dict) else ""


def _sarif_rules(run: dict) -> tuple[dict, list]:
    """(ruleId -> rule dict across all tool components, driver-rules-by-index) — for CWE/tag lookup."""
    by_id: dict = {}
    by_index: list = []
    tool = run.get("tool") if isinstance(run.get("tool"), dict) else {}
    driver = tool.get("driver") if isinstance(tool.get("driver"), dict) else {}
    if isinstance(driver.get("rules"), list):
        by_index = [r for r in driver["rules"] if isinstance(r, dict)]
    for comp in [driver, *(tool.get("extensions") or [])]:
        if isinstance(comp, dict):
            for r in (comp.get("rules") or []):
                if isinstance(r, dict) and r.get("id"):
                    by_id.setdefault(str(r["id"]), r)
    return by_id, by_index


def _sarif_cwe(rule: dict | None) -> str:
    """The first CWE number (un-padded) from a rule's ``properties.cwe`` / ``properties.tags``, or ''."""
    if not isinstance(rule, dict):
        return ""
    props = rule.get("properties") if isinstance(rule.get("properties"), dict) else {}
    cands: list[str] = []
    if props.get("cwe"):
        cands.append(str(props["cwe"]))
    tags = props.get("tags")
    if isinstance(tags, list):
        cands.extend(str(t) for t in tags)
    for cand in cands:
        m = _CWE_RE.search(cand)
        if m:
            return str(int(m.group(1)))   # normalise cwe-079 / cwe-79 -> "79"
    return ""


def _sarif_location(res: dict) -> tuple[str, str]:
    """(location, host) from a result's first physicalLocation. A ``http(s)://`` uri is a URL (host
    derivable → re-verifiable); a file uri is a code location (host '')."""
    locs = res.get("locations")
    if not isinstance(locs, list) or not locs or not isinstance(locs[0], dict):
        return ("", "")
    pl = locs[0].get("physicalLocation")
    if not isinstance(pl, dict):
        return ("", "")
    art = pl.get("artifactLocation")
    uri = str(art.get("uri") or "") if isinstance(art, dict) else ""
    region = pl.get("region")
    line = f":{region['startLine']}" if isinstance(region, dict) and region.get("startLine") else ""
    loc = f"{uri}{line}" if uri else ""
    host = _host_of(uri) if uri.startswith(("http://", "https://")) else ""
    return (loc, host)


def parse_sarif(output: str) -> list[ImportedFinding]:
    """A SARIF 2.1.0 static/dynamic-analysis export (``{"runs": [{"tool": ..., "results": [...]}]}``) —
    the industry-standard interchange format. Each result becomes a LEAD: its bug_class is mapped from the
    rule's CWE tag when possible (so a URL-located DAST finding routes to the oracle that re-verifies it),
    else the raw ruleId; severity from ``level``; the location/host from the first physicalLocation (a
    ``http(s)`` uri is host-derivable, a file uri is a code location). A ``kind`` of pass/notApplicable is
    skipped. Malformed / non-SARIF JSON -> ImportAdapterError; a run with no results contributes nothing."""
    try:
        data = json.loads(output)
    except (json.JSONDecodeError, TypeError) as e:
        raise ImportAdapterError(f"SARIF export is not valid JSON: {e}") from e
    if not isinstance(data, dict) or not isinstance(data.get("runs"), list):
        raise ImportAdapterError("SARIF export must be a JSON object with a 'runs' array")

    out: list[ImportedFinding] = []
    for run in data["runs"]:
        if not isinstance(run, dict):
            continue
        tool_name = _sarif_tool_name(run) or "sarif"
        by_id, by_index = _sarif_rules(run)
        for res in (run.get("results") or []):
            if not isinstance(res, dict):
                continue
            if str(res.get("kind", "fail")).strip().lower() in _SARIF_NON_FINDING_KINDS:
                continue
            rid = str(res.get("ruleId") or "")
            rule = by_id.get(rid)
            if rule is None:
                idx = res.get("ruleIndex")
                if isinstance(idx, int) and 0 <= idx < len(by_index):
                    rule = by_index[idx]
                    rid = rid or str(rule.get("id") or "")
            cwe = _sarif_cwe(rule)
            bug_class = _CWE_TO_BUG_CLASS.get(cwe) or rid or "unknown"
            severity = _SARIF_LEVEL_SEV.get(str(res.get("level") or "").strip().lower(), "Medium")
            location, host = _sarif_location(res)
            msg = res.get("message")
            evidence = str(msg.get("text") or "")[:500] if isinstance(msg, dict) else ""
            out.append(ImportedFinding(
                tool=tool_name, bug_class=bug_class, location=location, host=host,
                severity=severity, tool_confirmed=False, evidence=evidence))
    return out


# format name -> (parser, default source-tool label). ``detect_format`` and the CLI
# read this table; it is the whole contract of supported inputs.
_PARSERS = {
    "nuclei": (parse_nuclei_export, "nuclei"),
    "zap": (parse_zap_export, "zap"),
    "burp": (parse_burp_export, "burp"),
    "sqlmap": (parse_sqlmap_export, "sqlmap"),
    "nikto": (parse_nikto_export, "nikto"),
    "wapiti": (parse_wapiti_export, "wapiti"),
    "sarif": (parse_sarif, "sarif"),
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
        # SARIF is the distinctive {version?, runs:[...]} shape — sniff it BEFORE the generic
        # findings/results fallback (a SARIF run also has a `results` key nested under it).
        if isinstance(data.get("runs"), list) and ("$schema" in data or "version" in data
                                                    or any(isinstance(r, dict) and "tool" in r
                                                           for r in data["runs"][:1])):
            return "sarif"
        if "site" in data:
            return "zap"
        if "issues" in data or "issue_events" in data:
            return "burp"
        # Wapiti's `vulnerabilities` is a DICT (category -> list); Nikto's is a LIST of {msg,...}.
        if isinstance(data.get("vulnerabilities"), dict):
            return "wapiti"
        vulns = data.get("vulnerabilities")
        if isinstance(vulns, list) and any(isinstance(v, dict) and "msg" in v for v in vulns[:3]):
            return "nikto"
        if "findings" in data or "results" in data:
            return "generic"
    if isinstance(data, list):
        return "generic"
    return None
