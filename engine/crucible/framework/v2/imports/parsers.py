"""
imports.parsers — parse a third-party tool export into ``ImportedFinding``s.

The heavy lifting is REUSED where it exists: the Nuclei / ZAP / Burp / sqlmap / nikto /
wapiti parsers already live (tested against captured real output) in ``eval.adapters``
and ``eval.adapters_ext`` — this module wraps each and maps its ``NormalizedFinding``
onto ``ImportedFinding``, deriving the host. The rest are implemented natively here:
``parse_generic`` (a tool-neutral findings JSON — the escape hatch for any tool CRUCIBLE
has no dedicated adapter for), ``parse_sarif``, and the three LIVE-EXECUTOR readers
``parse_ffuf_export`` / ``parse_httpx_export`` / ``parse_hydra_export``.

Every parser is a pure ``str -> list[ImportedFinding]``: it raises
``ImportAdapterError`` on MALFORMED input (non-JSON where JSON is promised, the wrong
top-level shape) and returns ``[]`` on an empty-but-well-formed export. No I/O, no
network, no eval/shell — the input is untrusted text and is treated as data only.
TOTALITY: malformed, truncated, empty and adversarial input yields either ``[]`` or a
clean ``ImportAdapterError`` — never an unhandled exception.

GRADING is not a plumbing detail and is stated per parser. Two of the readers here
report OBSERVATIONS, not weaknesses (see ``OBSERVATION_BUG_CLASSES``), and NOTHING any
parser emits is ever a CRUCIBLE fact — every import mints a GROUNDING_INTEL lead
(``lead: True, unverified: True``). Only a fired deterministic oracle produces a fact.
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


# --- nikto: the report is an ARRAY of per-host blocks -----------------------------------------
# Nikto's JSON reporter builds ``$JSONRPT_ALL = []`` and pushes one block per host, then encodes
# THAT array (``json_host_start`` / ``json_close`` in nikto 2.6.0's ``nikto_report_json.plugin``).
# So the top level is ALWAYS a JSON array — even for a single host, even when the scan found
# nothing, even when the target refused the connection. Verified against three live nikto 2.6.0
# runs on this host. Each block carries the keys below plus ``vulnerabilities``, which the plugin
# initialises to ``[]``: an EMPTY list is a clean scan, not an unrecognisable report.
_NIKTO_HOST_KEYS = ("server_banner", "start_time", "end_time")


def _is_nikto_host_report(obj: object) -> bool:
    """True when ``obj`` is one of nikto's per-host report blocks.

    Two independent tells, so a clean scan is still recognisable: nikto's ``{msg: ...}``
    vulnerability shape, or — when there are no vulnerabilities to look at — the host header
    keys its report plugin always writes. Both require ``vulnerabilities`` to be a LIST, which
    is what separates nikto from wapiti (whose ``vulnerabilities`` is a DICT of category → list)
    and from a generic findings array (whose entries carry no ``vulnerabilities`` at all)."""
    if not isinstance(obj, dict) or not isinstance(obj.get("vulnerabilities"), list):
        return False
    if any(isinstance(v, dict) and "msg" in v for v in obj["vulnerabilities"][:3]):
        return True
    return any(k in obj for k in _NIKTO_HOST_KEYS) or ("ip" in obj and "port" in obj)


def _nikto_authorities(output: str, count: int) -> list[tuple[str, str]] | None:
    """Recover ``(host, host[:port])`` for each of nikto's findings, in emission order.

    The eval adapter's ``NormalizedFinding`` has no host field and nikto's per-item ``url`` is a
    bare PATH (``/robots.txt`` — confirmed against live 2.6.0 output), so without this every
    finding imports with no host: no asset observation, no HOSTS edge, and — worse on a
    MULTI-host report, which is the shape nikto's array exists for — every host's ``/`` collapses
    onto one path-keyed endpoint node. The host is right there in the report block.

    Re-walks the raw JSON in the order ``eval.adapters_ext.parse_nikto`` emits (hosts in order,
    each block's vulnerabilities in order, a ``None`` vulnerabilities value skipped exactly as it
    skips one). Returns None unless the walk lines up 1:1 with ``count`` findings — attributing a
    finding to the WRONG host is worse than leaving it unattributed, so a mismatch attributes
    nothing. Total; never raises."""
    try:
        data = json.loads(output)
    except Exception:
        return None
    if isinstance(data, dict):
        blocks = [data]
    elif isinstance(data, list):
        blocks = [h for h in data if isinstance(h, dict)]   # mirrors ``_nikto_hosts``
    else:
        return None

    def _text(value: object) -> str:
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            return ""
        return str(value).strip()

    out: list[tuple[str, str]] = []
    for block in blocks:
        vulns = block.get("vulnerabilities", [])
        if vulns is None:
            continue                       # parse_nikto skips this block; so must the walk
        if not isinstance(vulns, list):
            return None                    # parse_nikto raises on this; attribute nothing
        host = _text(block.get("host")) or _text(block.get("ip"))
        port = _text(block.get("port"))
        authority = f"{host}:{port}" if host and port.isdigit() else host
        out.extend([(host, authority)] * len(vulns))
    return out if len(out) == count else None


def parse_nikto_export(output: str) -> list[ImportedFinding]:
    """Nikto ``-Format json`` report — an ARRAY of per-host blocks, each with a
    ``vulnerabilities`` list of ``{msg, url, ...}`` (a single bare block is also tolerated).

    The scanned host is lifted off the block and onto each finding, and a bare-path location is
    qualified with it (``/robots.txt`` → ``127.0.0.1:18711/robots.txt``) so findings from
    different hosts stay distinct surfaces. Nikto's report carries no scheme, so none is
    invented — the qualified location is exactly the block's ``host``/``port`` plus the path
    nikto reported. A location that is already an absolute URL is left alone."""
    findings = _wrap(parse_nikto, output)
    authorities = _nikto_authorities(output, len(findings))
    if authorities is None:
        return findings
    out: list[ImportedFinding] = []
    for finding, (host, authority) in zip(findings, authorities):
        if not host:
            out.append(finding)
            continue
        location = finding.location
        if location and "://" not in location and not location.startswith(f"{authority}/"):
            location = f"{authority}{location}" if location.startswith("/") else f"{authority}/{location}"
        out.append(finding.model_copy(update={"host": finding.host or host, "location": location}))
    return out


def _wapiti_target(output: str) -> tuple[str, str] | None:
    """``(host, scheme://authority)`` for the host wapiti scanned, from the report's own
    ``infos.target``, or None when the report does not name one.

    Wapiti locates every finding by a bare PATH (``/search``) and names the host ONCE, in the
    report header. ``infos`` is a structured object — ``{"target": "http://127.0.0.1:19006/",
    "date": …, "version": "Wapiti 3.2.10", …}`` — verified against a live 3.2.10 report, not a
    fixture. Total; never raises."""
    try:
        data = json.loads(output)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    infos = data.get("infos")
    target = infos.get("target") if isinstance(infos, dict) else None
    if not isinstance(target, str) or "://" not in target:
        return None
    try:
        u = urlsplit(target)
    except ValueError:
        return None
    if not u.hostname or not u.scheme or not u.netloc:
        return None
    return u.hostname, f"{u.scheme}://{u.netloc}"


def parse_wapiti_export(output: str) -> list[ImportedFinding]:
    """Wapiti JSON report (``{"vulnerabilities": {"<category>": [{path, parameter, level}]}}``).

    The scanned host is lifted off the report header and onto each finding, and a bare-path
    location is qualified with it (``/search?q`` → ``http://127.0.0.1:19006/search?q``) — the same
    correction ``parse_nikto_export`` makes, for the same reason and with the same consequence when
    it is missing: no asset observation, no HOSTS edge, and an endpoint node keyed on the PATH
    ALONE, so every host wapiti ever scans collapses its ``/search`` onto one shared node. Measured
    on a live report: without this, one XSS lead minted 1 unanchored observation; with it, 3
    anchored ones. Unlike nikto's, wapiti's header carries a scheme, so the qualified location is a
    real absolute URL and no scheme is invented. A report that names no target, or a location that
    is already absolute, is left exactly as it was.

    Only a ROOTED path is qualified. ``eval.adapters_ext.parse_wapiti`` falls back to the bare
    PARAMETER NAME when a finding carries no ``path``, and turning ``id`` into
    ``http://host/id`` would invent a surface the tool never reported — so such a finding keeps its
    location and gains only the host, which is a fact the report does state."""
    findings = _wrap(parse_wapiti, output)
    target = _wapiti_target(output)
    if target is None:
        return findings
    host, root = target
    out: list[ImportedFinding] = []
    for finding in findings:
        location = finding.location
        if location.startswith("/"):
            location = f"{root}{location}"
        out.append(finding.model_copy(update={"host": finding.host or host, "location": location}))
    return out


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
    # RecursionError (not a ValueError) is what adversarially nested JSON raises; catching it here
    # is what makes "a hostile export never crashes the importer" true rather than aspirational.
    except (json.JSONDecodeError, TypeError, RecursionError) as e:
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
    except (json.JSONDecodeError, TypeError, RecursionError) as e:   # see parse_generic on RecursionError
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


# ==================================================================================================
# ffuf / httpx / hydra — the three live-executor tools that had NO READER.
#
# The engine's typed argv builders could already run these three, but their bytes went nowhere: this
# registry held no key for them, so a run produced output nothing in the engine could read. A driver
# that cannot parse its own tool's output IS the defect; these three parsers close it, each written
# to the format the real binary actually emits. Shapes below were captured from live runs on this
# host against a local target — ffuf 2.1.0-dev, ProjectDiscovery httpx (Kali installs it as
# ``httpx-toolkit``), hydra 9.7 — not taken from documentation.
#
# GRADING is the load-bearing part, not the plumbing:
#
#   * ffuf DISCOVERS CONTENT. A path that answered is an OBSERVATION about the surface's shape.
#     ``/admin`` returning 200 is not a weakness and is never graded as one.
#   * httpx FINGERPRINTS. A status code, page title, server banner or detected technology is an
#     OBSERVATION.
#   * hydra reporting a VALID LOGIN authenticated to the service. That is a genuine weakness and is
#     graded as one (``weak_credentials`` — the class the wapiti adapter already uses).
#
# And none of it is EVER a CRUCIBLE fact: like every other import these mint GROUNDING_INTEL leads.
# ==================================================================================================

# The bug classes that name an OBSERVATION rather than a weakness. Written down in ONE place, rather
# than left implicit across two parsers, so the grading rule above is checkable rather than folklore.
OBSERVATION_BUG_CLASSES = frozenset({"content_discovery", "http_fingerprint"})

# ``json.loads`` raises RecursionError — NOT a ValueError — on adversarially nested input
# (``"["*100000``). Catching it alongside ValueError is what keeps "malformed input never crashes"
# true for a hostile export, not merely a corrupt one.
_JSON_ERRORS = (ValueError, RecursionError)


def _text_field(value: object) -> str:
    """A trimmed string for a JSON scalar; '' for anything structural or boolean. Total."""
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        return ""
    return str(value).strip()


def _json_lines(output: str, tool: str) -> list[dict]:
    """Every non-blank line of a JSON-Lines export, as objects.

    A non-JSON line, or a line that is not an object, is MALFORMED -> ImportAdapterError. That is
    the ``parse_nuclei`` convention and it is deliberate: a reader that quietly skipped the lines it
    could not understand would report a clean result for a run it never actually read.

    THE ONE EXCEPTION IS A TORN TAIL, and it is not a relaxation of that rule — it is the rule
    applied to a condition the rule did not consider. These two readers consume a stream, not a
    file: httpx writes its JSONL to STDOUT, and ``live.executor`` kills an over-running tool with
    SIGKILL (``subprocess.run`` timeout), which no tool can catch and flush behind. The capture then
    ends MID-RECORD. Under the strict rule that cost the WHOLE report — every endpoint httpx had
    already probed and printed was thrown away because the last one was half-written — which is the
    same "a tool ran, succeeded, and was heard as silence" failure the strict rule exists to
    prevent, arriving from the other side.

    The tail is recognised by THREE conditions together, and the third is what keeps this from
    becoming the silent-skip the strict rule forbids:

      * it is the LAST line, and
      * the output does NOT end in a line terminator, so the writer demonstrably never finished it,
      * and at least one COMPLETE record was already read — so there is a report to keep.

    Without the third, an export that is nothing BUT one unparseable blob (a truncated single-object
    report file, which is what a cut-off ffuf ``-of json`` looks like) would return an empty list and
    read exactly like a clean scan. There is nothing to salvage in that case and nothing to be quiet
    about, so it stays the hard error it always was. One record is lost; every complete record before
    it is kept; an unparseable line ANYWHERE ELSE, or a torn-looking last line in an output that DID
    end cleanly, still raises. Truncation cannot forge a complete record: a JSON object cut short is
    unparseable unless it happens to be cut exactly at its closing brace, at which point it is not
    cut short at all."""
    text = output or ""
    lines = text.splitlines()
    # No terminator on the final line ⇒ the writer was cut off mid-line (see above).
    torn_tail = bool(lines) and not text.endswith(("\n", "\r"))
    last = len(lines) - 1
    records: list[dict] = []
    for idx, raw in enumerate(lines):
        line = raw.strip()
        if not line:
            continue
        salvageable = idx == last and torn_tail and bool(records)
        try:
            record = json.loads(line)
        except _JSON_ERRORS as e:
            if salvageable:
                break                       # the torn tail: one record lost, the report kept
            raise ImportAdapterError(f"{tool} emitted a non-JSON line: {line[:120]!r}: {e}") from e
        if not isinstance(record, dict):
            if salvageable:
                break
            raise ImportAdapterError(f"{tool} line is not a JSON object: {line[:120]!r}")
        records.append(record)
    return records


# --- ffuf: content discovery ----------------------------------------------------------------------

_FFUF_BUG_CLASS = "content_discovery"


def _is_ffuf_result(obj: object) -> bool:
    """True when ``obj`` is one of ffuf's result records — the strict shape, used by the SNIFFER.

    ffuf keys a result by the URL it requested and the status it got back, with the fuzzed words in
    an ``input`` MAP. That map being a map (httpx's ``input`` is a string) is what stops the two
    JSON-emitting probes from being confused for one another."""
    return (isinstance(obj, dict)
            and isinstance(obj.get("url"), str)
            and isinstance(obj.get("input"), dict)
            and isinstance(obj.get("status"), int) and not isinstance(obj.get("status"), bool))


def _is_ffuf_report(obj: object) -> bool:
    """True when ``obj`` is ffuf's ``-of json`` report object.

    Two tells, so a CLEAN scan stays recognisable: ffuf's own envelope keys (``commandline`` /
    ``config``, which no other supported format writes) around a ``results`` LIST, and — when there
    are results to look at — that they carry ffuf's result shape. An empty ``results`` is a scan
    that discovered nothing, which is a RESULT, not an unreadable report.

    Deliberately NARROW: ``results`` alone is also the generic escape hatch's own key, so claiming
    every ``{"results": [...]}`` for ffuf would steal it. Nothing less than the envelope will do."""
    if not isinstance(obj, dict) or not isinstance(obj.get("results"), list):
        return False
    if not ("commandline" in obj or "config" in obj):
        return False
    return not obj["results"] or any(_is_ffuf_result(r) for r in obj["results"][:3])


def _ffuf_evidence(item: dict) -> str:
    """A stable one-line summary of what the path answered. DETERMINISTIC on purpose: ffuf's
    ``duration`` (and the report's ``time``) change every run, and an evidence string that changed
    per run would make a re-import of the same scan differ from itself."""
    bits = [f"status {_text_field(item.get('status'))}"]
    for key, label in (("length", "bytes"), ("words", "words"), ("lines", "lines")):
        val = _text_field(item.get(key))
        if val:
            bits.append(f"{val} {label}")
    ctype = _text_field(item.get("content-type"))
    if ctype:
        bits.append(f"type {ctype}")
    redirect = _text_field(item.get("redirectlocation"))
    if redirect:
        bits.append(f"-> {redirect}")
    return "discovered: " + ", ".join(bits)


def _ffuf_findings(results: list) -> list[ImportedFinding]:
    """Grade ffuf's result records. ONE place, so the report form and the JSON-Lines form cannot
    drift into grading the same discovery differently."""
    out: list[ImportedFinding] = []
    for item in results:
        if not isinstance(item, dict):
            continue                         # skip a malformed entry, don't abort the batch
        url = _text_field(item.get("url"))
        if not url:
            continue                         # nothing to anchor the observation on
        out.append(ImportedFinding(
            tool="ffuf",
            bug_class=_FFUF_BUG_CLASS,
            location=url,
            host=_host_of(url) or _host_of(_text_field(item.get("host"))),
            severity="info",
            tool_confirmed=False,
            evidence=_ffuf_evidence(item)[:500],
        ))
    return out


def parse_ffuf_export(output: str) -> list[ImportedFinding]:
    """ffuf's JSON report — ``-of json -o <path>``, the format the live executor writes.

    Captured shape (ffuf 2.1.0-dev)::

        {"commandline": "ffuf -u http://h/FUZZ -w wl -of json -o out.json",
         "time": "2026-08-13T18:39:48-04:00",
         "results": [{"input": {"FFUFHASH": "f80301", "FUZZ": "admin"}, "position": 1,
                      "status": 200, "length": 10, "words": 2, "lines": 1,
                      "content-type": "text/html", "redirectlocation": "", "scraper": {},
                      "duration": 271684, "resultfile": "",
                      "url": "http://h/admin", "host": "h:port"}],
         "config": {...}}

    A scan that matched nothing writes the SAME object with ``"results": []``.

    ffuf's stdout JSON-Lines form (``-json``, one result object per line) is accepted too — it is
    the same tool's real output and reading it costs nothing. One trap it hides: under ``-json`` and
    ``-of ejson`` ffuf BASE64-ENCODES the ``input`` values (``"FUZZ": "YWRtaW4="``) while ``-of
    json`` leaves them plain. The location is therefore always taken from ``url``, which is plain in
    every form — never reconstructed from the fuzzed word.

    A JSON-LINES STREAM OF EXACTLY ONE LINE IS STILL A JSON-LINES STREAM. That case is called out
    because it used to be the one that failed: a single result line is ALSO a valid whole JSON
    document, so it took the report branch, found no ``results`` key, and was refused as a malformed
    report — a scan that found exactly one path (the ordinary outcome of a small wordlist) read as
    an unreadable export. It is recognised by ffuf's own result SHAPE (``_is_ffuf_result``), the same
    strict test the sniffer uses, so a genuinely malformed report is still refused.

    GRADING: every result is ``content_discovery`` at severity ``info``, ``tool_confirmed`` False. A
    discovered path is an OBSERVATION about the surface — it is NEVER a vulnerability. ffuf found
    that ``/admin`` answers; whether ``/admin`` should answer is a question for an oracle."""
    text = (output or "").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
        whole_json = True
    except _JSON_ERRORS:
        whole_json = False

    if not whole_json:
        # Not one JSON document. Either the -json stdout stream (many lines, each an object) or a
        # report file that was cut off. `_json_lines` tells them apart: it salvages a torn TAIL after
        # complete records, and refuses an export that is nothing but an unparseable blob.
        results: list = list(_json_lines(output, "ffuf"))   # the -json stdout form
    elif isinstance(data, dict):
        if "results" not in data:
            if _is_ffuf_result(data):
                return _ffuf_findings([data])   # a one-line -json stream, not a malformed report
            raise ImportAdapterError("ffuf report is missing its 'results' array")
        found = data["results"]
        if found is None:
            found = []                       # a run that recorded no results is empty, not broken
        if not isinstance(found, list):
            raise ImportAdapterError("ffuf report 'results' must be an array")
        results = found
    elif isinstance(data, list):
        results = data                       # a bare results array (tolerated, not what ffuf emits)
    else:
        raise ImportAdapterError("ffuf report must be a JSON object with a 'results' array")

    return _ffuf_findings(results)


# --- httpx: HTTP probing / fingerprint --------------------------------------------------------------

_HTTPX_BUG_CLASS = "http_fingerprint"


def _is_httpx_record(obj: object) -> bool:
    """True when ``obj`` is one of ProjectDiscovery httpx's JSONL records.

    Requires the pairing no other supported format writes: a STRING ``input`` (the target exactly as
    it was given) alongside the probed ``url``, plus one of the outcome keys httpx always emits. The
    string-ness of ``input`` is what separates an httpx line from an ffuf result line, whose
    ``input`` is the fuzzed-word map."""
    if not isinstance(obj, dict):
        return False
    if not isinstance(obj.get("input"), str) or not isinstance(obj.get("url"), str):
        return False
    return ("status_code" in obj) or ("failed" in obj) or ("scheme" in obj and "host" in obj)


def _httpx_evidence(record: dict) -> str:
    """A stable fingerprint summary. DETERMINISTIC: httpx's ``timestamp`` and ``time`` (the response
    duration) are excluded for the same reason ffuf's ``duration`` is."""
    bits: list[str] = []
    status = _text_field(record.get("status_code"))
    if status:
        bits.append(f"status {status}")
    for key, label in (("title", "title"), ("webserver", "server"), ("content_type", "type")):
        val = _text_field(record.get(key))
        if val:
            bits.append(f"{label} {val}")
    tech = record.get("tech")
    if isinstance(tech, list):
        names = [_text_field(t) for t in tech]
        joined = ", ".join(n for n in names if n)
        if joined:
            bits.append(f"tech {joined}")
    return "probe: " + ", ".join(bits) if bits else "probe: responded"


def parse_httpx_export(output: str) -> list[ImportedFinding]:
    """ProjectDiscovery httpx JSON Lines — ``-json``, one object per probed URL on stdout, which is
    what the live executor's builder asks for.

    Captured shape (``httpx-toolkit -u <url> -silent -no-color -disable-update-check -json``; on
    Kali the REAL ProjectDiscovery binary installs under the name ``httpx-toolkit``, because the
    plain ``httpx`` name belongs to an unrelated Python HTTP client)::

        {"timestamp":"2026-08-13T18:40:03.030328987-04:00","port":"18821",
         "url":"http://h:18821/","input":"http://h:18821/","title":"Cap Target","scheme":"http",
         "webserver":"CapTarget/1.0","content_type":"text/html","method":"GET","host":"h",
         "host_ip":"127.0.0.1","path":"/","time":"580.949µs","a":["127.0.0.1"],"tech":["Basic"],
         "words":2,"lines":1,"status_code":200,"content_length":56,"failed":false,
         "knowledgebase":{"pHash":0}}

    A probe that never connected is emitted (under ``-probe``) as
    ``{"url":…,"error":"… connection refused","status_code":0,"failed":true}``. That is the ABSENCE
    of a live endpoint, so it mints nothing — recording it would put a host that refused the
    connection into the world-model as an asset.

    GRADING: every record is ``http_fingerprint`` at severity ``info``, ``tool_confirmed`` False. A
    status code, title, server banner or detected technology is an OBSERVATION about what is
    running — httpx makes no vulnerability claim and none is invented for it."""
    out: list[ImportedFinding] = []
    for record in _json_lines(output, "httpx"):
        if record.get("failed") is True:
            continue                        # a probe that did not connect is not an endpoint
        url = _text_field(record.get("url")) or _text_field(record.get("input"))
        if not url:
            continue
        out.append(ImportedFinding(
            tool="httpx",
            bug_class=_HTTPX_BUG_CLASS,
            location=url,
            host=_host_of(url) or _text_field(record.get("host")),
            severity="info",
            tool_confirmed=False,
            evidence=_httpx_evidence(record)[:500],
        ))
    return out


# --- hydra: online credential attack ----------------------------------------------------------------
#
# hydra's success lines, taken from the format strings in the SHIPPED BINARY (hydra 9.7 —
# ``strings /usr/bin/hydra``), not from its man page:
#
#     [%d][%s] host: %s   password: %s                        (services with no username)
#     [%d][%s] host: %s   login: %s                           (services with no password)
#     [%d][%s] host: %s   login: %s   password: %s
#     [%d][%s] host: %s   misc: %s   login: %s   password: %s  (http-get / http-post-form / …)
#     [%d][http-proxy-urlenum] host: %s   url: %s              (URL enumeration, not a credential)
#
# The field separator is exactly THREE spaces, and the VALUES contain spaces and colons: an
# ``http-post-form`` spec is ``<path>:<params>:<failure string>`` and the failure string is normally
# a sentence, so a real captured line reads
#
#     [18822][http-post-form] host: h   misc: /login:user=^USER^&pass=^PASS^:Login failed   login: admin   password: secret123
#
# The line is therefore split on the field MARKERS, never on whitespace — a naive ``split()``
# truncates every form spec hydra has ever printed, at the first space inside the failure string.
_HYDRA_HIT = re.compile(r"^\[(\d+)\]\[([^\]]+)\]\s+host:\s*(.*)$")
_HYDRA_FIELD = re.compile(r"[ ]{3}(misc|login|password|url):[ ]*")
# The same shape as a whole-blob search, for the sniffer (one scan, no line list to materialise).
_HYDRA_HIT_ANY = re.compile(r"^\[\d+\]\[[^\]]+\]\s+host:\s", re.M)
# Tells that a text blob is hydra output even when it reported nothing — the banner it always prints
# and the summary line it always ends on. Without these a CLEAN run (the negative control, the run
# that MUST stay silent) would be an unrecognisable format rather than an honest zero.
_HYDRA_BANNER = re.compile(r"^Hydra v[\d.]+|thc-hydra|^\d+ of \d+ target", re.M)

# hydra's closing tally, e.g. `1 of 1 target successfully completed, 2 valid passwords found`
# (`%d of %d target%s%scompleted, %lu valid password` + the plural, in the 9.7 binary). Read as a
# CROSS-CHECK on the hit lines above — see the tripwire at the end of `parse_hydra_export`.
# The digit run is BOUNDED. `int()` raises ValueError past 4300 digits (CPython's int/str
# conversion limit), so an unbounded `\d+` would let a hostile blob crash a parser whose whole
# contract is to be total on untrusted bytes. Nine digits is more credentials than exist.
_HYDRA_TALLY = re.compile(r"(\d{1,9})\s+valid\s+passwords?\s+found")
_HYDRA_BUG_CLASS = "weak_credentials"
# hydra's password is a REAL credential for a real account. It is masked in the evidence string —
# which is persisted into the intel store and rendered into reports — exactly as the live executor
# masks the ``-p`` position in the signed argv record. The finding is not weakened by this: it still
# names the service, the host and the login that were proven to work, and the raw tool output the
# executor recorded still holds the value for the operator who needs it.
_HYDRA_MASK = "•••• (masked)"


def _is_hydra_report(obj: object) -> bool:
    """True when ``obj`` is hydra's OPTIONAL JSON report (``-o <file> -b json|jsonv1``).

    Recognised ONLY by hydra's own ``generator.software`` stamp, and that precision matters more
    here than anywhere else in this module: hydra's report keys its hits ``results`` — which is ALSO
    ffuf's key and ALSO one of the tool-neutral escape hatch's two keys. Three formats, one key. So
    each of the three rules demands its own tool's envelope and none may settle for ``results``
    alone; widen any one of them and it takes the other two's reports with it."""
    if not isinstance(obj, dict) or not isinstance(obj.get("results"), list):
        return False
    gen = obj.get("generator")
    return isinstance(gen, dict) and _text_field(gen.get("software")).lower() == "hydra"


def _hydra_json_findings(data: dict) -> list[ImportedFinding]:
    """The findings of hydra's JSON report. Same grading as the stdout text — it is the same tool
    reporting the same event — but the report carries no ``misc``, so the location is the bare
    ``host:port`` and no path is invented for it.

    Captured from hydra 9.7 (``-o out.json -b json``; ``-b jsonv1`` is byte-identical in shape)::

        { "generator": {"software": "Hydra", "version": "v9.7", …},
        "results": [ {"port": 18821, "service": "http-get", "host": "h", "login": "admin",
                      "password": "secret123"} ],
        "success": true, "errormessages": [  ], "quantityfound": 1   }"""
    out: list[ImportedFinding] = []
    for rec in data["results"]:
        if not isinstance(rec, dict):
            continue
        fields = {k: _text_field(rec.get(k)) for k in ("login", "password") if k in rec}
        if not fields:
            continue
        host = _text_field(rec.get("host"))
        port = _text_field(rec.get("port"))
        service = _text_field(rec.get("service")) or "unknown"
        bits = [f"service {service}"]
        if fields.get("login"):
            bits.append(f"login {fields['login']}")
        if "password" in fields:
            bits.append(f"password {_HYDRA_MASK if fields['password'] else '<empty>'}")
        out.append(ImportedFinding(
            tool="hydra",
            bug_class=_HYDRA_BUG_CLASS,
            location=f"{host}:{port}" if host and port.isdigit() else host,
            host=_host_of(host),
            severity="high",
            tool_confirmed=True,
            evidence="valid login: " + ", ".join(bits),
        ))
    # The report's OWN count, cross-checked exactly as the stdout tally is (see the tripwire below).
    claimed = data.get("quantityfound")
    if isinstance(claimed, int) and not isinstance(claimed, bool) and claimed > len(out):
        raise ImportAdapterError(
            f"hydra's report tallied {claimed} valid credential(s) but only {len(out)} could be "
            "read from it — the reader cannot parse a result its own tool proved")
    return out


def _hydra_fields(rest: str) -> tuple[str, dict[str, str]]:
    """Split the text after ``host:`` into ``(host, {field: value})`` on hydra's field markers.

    ``re.split`` with one capture group yields ``[host, key, value, key, value, …]``, so a value
    keeps every space and colon it contained. First occurrence of a key wins. Total."""
    parts = _HYDRA_FIELD.split(rest)
    fields: dict[str, str] = {}
    for i in range(1, len(parts) - 1, 2):
        fields.setdefault(str(parts[i]), str(parts[i + 1]).strip())
    return parts[0].strip(), fields


def _hydra_location(authority: str, fields: dict[str, str]) -> str:
    """The surface the hit sits on: ``host[:port]`` qualified with a path when hydra printed one.

    hydra's ``misc`` is the module argument — a PATH for the http modules (``/private``,
    ``/login:user=^USER^&pass=^PASS^:Login failed``), something else entirely for others (an SMB
    domain, an oracle SID). Only a value that starts with ``/`` is treated as a path, and only its
    path segment (up to hydra's first ``:`` delimiter) is used. No scheme is invented — hydra's
    output carries none, exactly as nikto's does not."""
    url = fields.get("url", "")
    if "://" in url:
        return url
    path = ""
    misc = fields.get("misc", "")
    if misc.startswith("/"):
        path = misc.split(":", 1)[0]
    elif url.startswith("/"):
        path = url
    if not authority:
        return path
    return f"{authority}{path}" if path else authority


def parse_hydra_export(output: str) -> list[ImportedFinding]:
    """hydra's native stdout text — the format contract for this tool, because hydra has no
    machine-readable stdout mode (``-o`` writes the same lines to a file; ``-b json`` applies to
    that file only, and the executor reads stdout).

    Captured lines (hydra 9.7, live against a local target)::

        [18821][http-get] host: h   misc: /private   login: admin   password: secret123
        [18822][http-post-form] host: h   misc: /login:user=^USER^&pass=^PASS^:Login failed   login: admin   password: secret123

    A run that cracked nothing prints its banner, its ``[DATA]`` lines and
    ``1 of 1 target completed, 0 valid password found`` — and NO hit line. That parses to zero
    findings: the clean control stays silent, which is the whole point of the row.

    GRADING: a hit line carrying a login and/or a password means hydra AUTHENTICATED. That is a
    genuine weakness — ``weak_credentials``, severity ``high``, ``tool_confirmed`` True (hydra
    self-confirms by exploitation, the same standing sqlmap has). It is still a LEAD to CRUCIBLE
    until an oracle re-verifies it; ``tool_confirmed`` records the tool's own confidence and has
    never been a fact. The ``http-proxy-urlenum`` variant carries a ``url`` and no credential — that
    is content discovery, graded ``content_discovery`` like ffuf's, never as a credential. A line
    with neither is not graded at all: hydra proved nothing there, so nothing is claimed.

    hydra's OPTIONAL JSON report (``-o <file> -b json``) is read too, under this same key. It is not
    the path a live run takes — the executor reads stdout, and ``-o`` does NOT silence the stdout hit
    line anyway (verified: 9.7 prints both, despite ``-h`` saying "instead of stdout") — but an
    operator importing a saved ``-b json`` file is a real path, and hydra keys its hits ``results``,
    so without this it lands in the tool-neutral parser as class-less, location-less entries. That is
    the nikto misroute again, and it is closed here rather than left to be rediscovered."""
    report = None
    text = (output or "").lstrip()
    if text.startswith("{"):
        try:
            candidate = json.loads(text)
        except _JSON_ERRORS:
            candidate = None
        if _is_hydra_report(candidate):
            report = candidate
    if report is not None:
        return _hydra_json_findings(report)

    out: list[ImportedFinding] = []
    for raw in (output or "").splitlines():
        match = _HYDRA_HIT.match(raw.strip())
        if not match:
            continue
        port, service, rest = match.group(1), match.group(2).strip(), match.group(3)
        host, fields = _hydra_fields(rest)
        authority = f"{host}:{port}" if host else ""
        login = fields.get("login", "")
        password = fields.get("password", "")
        url = fields.get("url", "")

        # KEY PRESENCE, not truthiness: hydra prints `password: ` with an EMPTY value for an account
        # that authenticates with a blank password (`-e n`). That is the strongest credential finding
        # the tool can report, and a `if password:` test would have thrown it away.
        if "login" in fields or "password" in fields:
            bits = [f"service {service}"]
            if login:
                bits.append(f"login {login}")
            if "password" in fields:
                bits.append(f"password {_HYDRA_MASK if password else '<empty>'}")
            misc = fields.get("misc", "")
            if misc:
                bits.append(f"spec {misc[:200]}")
            out.append(ImportedFinding(
                tool="hydra",
                bug_class=_HYDRA_BUG_CLASS,
                location=_hydra_location(authority, fields),
                host=_host_of(host),
                severity="high",
                tool_confirmed=True,   # hydra logged in — its own confidence, still a lead to us
                evidence="valid login: " + ", ".join(bits),
            ))
        elif "url" in fields:
            out.append(ImportedFinding(
                tool="hydra",
                bug_class=_FFUF_BUG_CLASS,
                location=_hydra_location(authority, fields),
                host=_host_of(host),
                severity="info",
                tool_confirmed=False,
                evidence=f"discovered: {service} {url[:200]}",
            ))
        # else: a hit line with no credential and no url proves nothing — nothing is minted.

    # THE TALLY TRIPWIRE. hydra ends every completed run with its own count of what it cracked, and
    # it increments that count in the same place it prints the hit line — so the two agree, and a
    # shortfall means the reader could not read a credential the TOOL ITSELF says it proved. That is
    # the defect this whole reader exists to prevent (a tool that runs, succeeds, and is heard as
    # silence), so it is LOUD rather than a short list: hydra's smb module, for one, prints its
    # successes as `[445][smb] Host: … Account: … Valid password` — a capital-H shape the hit regex
    # above does not match — and without this check an smb crack would import as a clean run.
    # Mirrors `eval.adapters.parse_sqlmap`, which raises when sqlmap says it identified injection
    # points and no parameter block could be parsed. A run that cracked nothing tallies 0 and is
    # unaffected: the negative control stays silent, and stays silent for the right reason.
    creds = sum(1 for f in out if f.bug_class == _HYDRA_BUG_CLASS)
    claimed = sum(int(m.group(1)) for m in _HYDRA_TALLY.finditer(output or ""))
    if claimed > creds:
        raise ImportAdapterError(
            f"hydra tallied {claimed} valid credential(s) but only {creds} could be read from its "
            "output — the reader cannot parse a result its own tool proved")
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
    "ffuf": (parse_ffuf_export, "ffuf"),
    "httpx": (parse_httpx_export, "httpx"),
    "hydra": (parse_hydra_export, "hydra"),
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
    # hydra is a text log too. Two tells, so a run that cracked NOTHING is still recognised as a
    # hydra run that found nothing rather than as an unknown format: its own `[port][service] host:`
    # hit line, or the banner/summary it prints whether or not it found anything.
    if _HYDRA_HIT_ANY.search(s) or _HYDRA_BANNER.search(s):
        return "hydra"
    # JSON shapes. Try the FIRST line as an object (nuclei is JSONL — one object per
    # line — so this catches both single- and multi-line nuclei exports).
    try:
        first_obj = json.loads(s.splitlines()[0])
    except Exception:
        first_obj = None
    if isinstance(first_obj, dict) and ("template-id" in first_obj or "matched-at" in first_obj):
        return "nuclei"
    # httpx is JSONL as well, and its records are self-describing: a STRING `input` next to the
    # probed `url`. Checked here, on the first LINE, because a single-record httpx export is also
    # parseable as one whole JSON object and would otherwise fall through to the object branch.
    if _is_httpx_record(first_obj):
        return "httpx"
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
        if _is_nikto_host_report(data):
            return "nikto"               # a single bare host block (tolerated, not what nikto emits)
        # ffuf and hydra's JSON report BEFORE the generic fallback. THREE formats key their findings
        # `results` — ffuf's report, hydra's `-b json` report, and the tool-neutral escape hatch —
        # so whichever is checked first takes the other two's reports with it. Both rules above are
        # narrower than `results` alone (each demands its own tool's envelope: ffuf's
        # `commandline`/`config`, hydra's `generator.software`), so both go first and the generic
        # branch keeps everything that is neither. Widening ANY of the three steals from the others.
        if _is_ffuf_report(data):
            return "ffuf"
        if _is_hydra_report(data):
            return "hydra"
        if "findings" in data or "results" in data:
            return "generic"
    if isinstance(data, list):
        # A top-level ARRAY is what nikto ACTUALLY emits — one block per host, always, because its
        # report plugin encodes an arrayref. Sniffed BEFORE the generic fallback, which previously
        # swallowed every real nikto report: the generic parser finds no `vulnerabilities` key it
        # understands, so a scan's whole finding list collapsed into one `unknown`-class entry with
        # no location. Verified against live nikto 2.6.0 output.
        if data and all(_is_nikto_host_report(h) for h in data[:3]):
            return "nikto"
        return "generic"
    return None
