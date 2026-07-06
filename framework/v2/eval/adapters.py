"""
eval.adapters — pluggable incumbent adapters for the comparative harness.

Each adapter wraps an industry scanner (Nuclei, ZAP, sqlmap, Burp) behind the
`harness.Adapter` protocol: ``available()`` reports whether the tool can run on
this host, and ``run(target)`` executes it and maps its native output into
`harness.NormalizedFinding` so the harness scores it against the same ground
truth as CRUCIBLE.

Availability is cheap and side-effect-free:

  * NucleiAdapter / ZapAdapter / SqlmapAdapter — the binary is on ``PATH``
    (``shutil.which``).
  * BurpAdapter — a REST endpoint is configured (``CRUCIBLE_BURP_URL``), since
    Burp is a service reached over HTTP, not a CLI on ``PATH``.

If ``available()`` is False the harness skips the tool; nothing is run. When a
tool *is* run, the adapter shells out (or, for Burp, calls the REST API), and the
parser turns the tool's output into findings — raising :class:`AdapterError`
only on **malformed** output (a non-JSON line where JSON is promised, a report
missing its top-level shape), never on an empty-but-well-formed result.

The parsers are the tested unit here: each is a pure ``str -> list`` function
exercised against a captured sample of that tool's real output, so parsing is
proven without the tools installed. The ``run()`` wrappers that invoke the tools
are thin and deliberately untested live.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess  # noqa: S404 (invoking operator-owned local scanners by design)
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

from ..common.errors import EvalError
from .validation import CorpusTarget, NormalizedFinding


class AdapterError(EvalError):
    """An incumbent adapter could not parse its tool's output. A recoverable
    measurement error (the tool ran but emitted something the parser cannot map),
    never an authorization decision."""


# ===========================================================================
# Nuclei — JSONL output (`-jsonl`): one JSON object per finding.
# ===========================================================================


def parse_nuclei(output: str) -> list[NormalizedFinding]:
    """Parse Nuclei ``-jsonl`` output. Each non-blank line is one JSON object;
    ``template-id`` (else ``info.name``) is the bug class and ``matched-at``
    (else ``host``) is the location. A non-JSON line is malformed -> AdapterError."""
    findings: list[NormalizedFinding] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as e:
            raise AdapterError(f"nuclei emitted a non-JSON line: {line!r}: {e}") from e
        if not isinstance(record, dict):
            raise AdapterError(f"nuclei line is not a JSON object: {line!r}")
        info = record.get("info") if isinstance(record.get("info"), dict) else {}
        bug_class = record.get("template-id") or info.get("name") or "unknown"
        location = record.get("matched-at") or record.get("host") or ""
        findings.append(NormalizedFinding(
            tool="nuclei",
            bug_class=str(bug_class),
            location=str(location),
            severity=str(info.get("severity", "")),
            confirmed=False,  # nuclei matches a template; it does not oracle-prove
            evidence=str(info.get("name", "")),
        ))
    return findings


class NucleiAdapter:
    """Nuclei via ``nuclei -u <url> -jsonl -silent``."""

    name: str = "nuclei"

    def __init__(self, *, binary: str = "nuclei", extra_args: tuple[str, ...] = (), timeout: float = 600.0) -> None:
        self._binary = binary
        self._extra_args = tuple(extra_args)
        self._timeout = timeout

    def available(self) -> bool:
        return shutil.which(self._binary) is not None

    def run(self, target: CorpusTarget) -> list[NormalizedFinding]:
        cmd = [self._binary, "-u", target.base_url, "-jsonl", "-silent", *self._extra_args]
        proc = subprocess.run(  # noqa: S603 (fixed argv, operator-owned tool)
            cmd, capture_output=True, text=True, timeout=self._timeout, check=False,
        )
        return parse_nuclei(proc.stdout)


# ===========================================================================
# OWASP ZAP — traditional JSON report: {"site": [{"alerts": [...]}]}.
# ===========================================================================


def parse_zap(output: str) -> list[NormalizedFinding]:
    """Parse a ZAP JSON report. Each alert under each site yields one finding per
    instance; ``alert`` is the bug class, ``riskdesc`` the severity, and the
    instance ``uri`` (with its query) the location. Missing ``site`` -> malformed."""
    try:
        data = json.loads(output)
    except json.JSONDecodeError as e:
        raise AdapterError(f"zap report is not valid JSON: {e}") from e
    if not isinstance(data, dict) or "site" not in data:
        raise AdapterError("zap report is missing its top-level 'site' array")

    sites = data["site"]
    if isinstance(sites, dict):
        sites = [sites]
    if not isinstance(sites, list):
        raise AdapterError("zap report 'site' must be an object or array")

    findings: list[NormalizedFinding] = []
    for site in sites:
        alerts = site.get("alerts", []) if isinstance(site, dict) else []
        for alert in alerts or []:
            if not isinstance(alert, dict):
                raise AdapterError(f"zap alert is not an object: {alert!r}")
            bug_class = alert.get("alert") or alert.get("name") or "unknown"
            riskdesc = str(alert.get("riskdesc", ""))
            severity = riskdesc.split(" ", 1)[0].lower() if riskdesc else ""
            instances = alert.get("instances") or [{}]
            for inst in instances:
                inst = inst if isinstance(inst, dict) else {}
                uri = str(inst.get("uri", "") or site.get("@name", ""))
                param = str(inst.get("param", ""))
                # keep the fuzzed parameter in the location so a param-only match
                # still lands when the URI carries no query string
                location = uri if (not param or "?" in uri) else f"{uri}?{param}"
                findings.append(NormalizedFinding(
                    tool="zap",
                    bug_class=str(bug_class),
                    location=location,
                    severity=severity,
                    confirmed=False,
                    evidence=str(inst.get("evidence", "")),
                ))
    return findings


class ZapAdapter:
    """ZAP via its CLI (``zap.sh``/``zap-cli``/``zaproxy``), emitting a JSON report."""

    name: str = "zap"

    def __init__(self, *, binaries: tuple[str, ...] = ("zap.sh", "zap-cli", "zaproxy"), timeout: float = 600.0) -> None:
        self._binaries = tuple(binaries)
        self._timeout = timeout

    def _resolve(self) -> str | None:
        for binary in self._binaries:
            if shutil.which(binary):
                return binary
        return None

    def available(self) -> bool:
        return self._resolve() is not None

    def run(self, target: CorpusTarget) -> list[NormalizedFinding]:
        binary = self._resolve()
        if binary is None:  # defensive: run() called past available()
            raise AdapterError("no ZAP binary on PATH")
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "zap-report.json"
            cmd = [binary, "-cmd", "-quickurl", target.base_url, "-quickout", str(report)]
            subprocess.run(  # noqa: S603 (fixed argv, operator-owned tool)
                cmd, capture_output=True, text=True, timeout=self._timeout, check=False,
            )
            try:
                output = report.read_text(encoding="utf-8")
            except OSError as e:
                raise AdapterError(f"zap produced no JSON report at {report}: {e}") from e
        return parse_zap(output)


# ===========================================================================
# sqlmap — parsed from its stdout log (the injection-point summary block).
# ===========================================================================

_SQLMAP_PARAM = re.compile(r"^Parameter:\s*(?P<name>.+?)\s*\((?P<place>[^)]+)\)\s*$")
_SQLMAP_TYPE = re.compile(r"^Type:\s*(?P<type>.+?)\s*$")
_SQLMAP_IDENTIFIED = "identified the following injection point"


def parse_sqlmap(output: str) -> list[NormalizedFinding]:
    """Parse sqlmap's stdout injection summary. Each ``Parameter: <name> (<place>)``
    block with its ``Type:`` lines becomes one confirmed ``sql_injection`` finding
    located on ``<name>``. If sqlmap says it *identified* injection points but no
    parameter block can be parsed, the output is malformed -> AdapterError."""
    findings: list[NormalizedFinding] = []
    current: str | None = None
    place = ""
    types: list[str] = []

    def flush() -> None:
        if current is not None:
            findings.append(NormalizedFinding(
                tool="sqlmap",
                bug_class="sql_injection",
                location=current,
                severity="high",
                confirmed=True,  # sqlmap confirms an injection by exploiting it
                evidence=f"{place}: {', '.join(types)}".strip(": "),
            ))

    for raw in output.splitlines():
        line = raw.strip()
        pm = _SQLMAP_PARAM.match(line)
        if pm:
            flush()
            current = pm.group("name")
            place = pm.group("place")
            types = []
            continue
        tm = _SQLMAP_TYPE.match(line)
        if tm and current is not None:
            types.append(tm.group("type"))
    flush()

    if not findings and _SQLMAP_IDENTIFIED in output:
        raise AdapterError("sqlmap reported injection points but no parameter block could be parsed")
    return findings


class SqlmapAdapter:
    """sqlmap via ``sqlmap -u <url> --batch``, parsing its stdout log."""

    name: str = "sqlmap"

    def __init__(self, *, binary: str = "sqlmap", extra_args: tuple[str, ...] = ("--batch",), timeout: float = 600.0) -> None:
        self._binary = binary
        self._extra_args = tuple(extra_args)
        self._timeout = timeout

    def available(self) -> bool:
        return shutil.which(self._binary) is not None

    def run(self, target: CorpusTarget) -> list[NormalizedFinding]:
        cmd = [self._binary, "-u", target.base_url, *self._extra_args]
        proc = subprocess.run(  # noqa: S603 (fixed argv, operator-owned tool)
            cmd, capture_output=True, text=True, timeout=self._timeout, check=False,
        )
        return parse_sqlmap(proc.stdout)


# ===========================================================================
# Burp — the REST API scan-issues JSON (Enterprise/Pro/burp-rest-api shapes).
# ===========================================================================


def _burp_issue_list(data: object) -> list[dict]:
    """Normalize the several Burp issue payload shapes to a flat list of issue
    dicts: a bare array, ``{"issues": [...]}``, ``{"issue_events": [{"issue": ...}]}``,
    or a single issue object."""
    if isinstance(data, list):
        return [it for it in data]
    if isinstance(data, dict):
        if isinstance(data.get("issues"), list):
            return list(data["issues"])
        if isinstance(data.get("issue_events"), list):
            return [ev.get("issue", {}) for ev in data["issue_events"] if isinstance(ev, dict)]
        return [data]
    raise AdapterError("burp issues payload must be a JSON object or array")


def parse_burp(output: str) -> list[NormalizedFinding]:
    """Parse Burp REST scan-issues JSON. ``name`` is the bug class, ``severity``
    the severity, and the location comes from ``url`` (else ``origin`` + ``path``).
    A ``confidence`` of ``certain`` marks the finding confirmed. Non-JSON or a
    non-object issue is malformed -> AdapterError."""
    try:
        data = json.loads(output)
    except json.JSONDecodeError as e:
        raise AdapterError(f"burp issues payload is not valid JSON: {e}") from e

    findings: list[NormalizedFinding] = []
    for issue in _burp_issue_list(data):
        if not isinstance(issue, dict):
            raise AdapterError(f"burp issue is not an object: {issue!r}")
        bug_class = issue.get("name") or issue.get("issue_type") or issue.get("type") or "unknown"
        severity = str(issue.get("severity", "")).lower()
        confidence = str(issue.get("confidence", "")).lower()
        url = issue.get("url")
        if not url:
            url = f"{issue.get('origin', '')}{issue.get('path', '')}"
        findings.append(NormalizedFinding(
            tool="burp",
            bug_class=str(bug_class),
            location=str(url),
            severity=severity,
            confirmed=confidence == "certain",
            evidence=str(issue.get("issueDetail") or issue.get("detail") or confidence),
        ))
    return findings


class BurpAdapter:
    """Burp via its REST API. Availability is a configured base URL
    (``CRUCIBLE_BURP_URL`` or an explicit ``api_url``) — Burp is a service, not a
    binary on ``PATH``. ``run()`` GETs the issues endpoint and parses the JSON."""

    name: str = "burp"

    def __init__(self, *, api_url: str | None = None, issues_path: str = "/issues", timeout: float = 60.0) -> None:
        # None -> read the env; an explicit "" disables the adapter deterministically.
        self._api_url = api_url if api_url is not None else os.environ.get("CRUCIBLE_BURP_URL", "")
        self._issues_path = issues_path
        self._timeout = timeout

    def available(self) -> bool:
        return bool(self._api_url)

    def run(self, target: CorpusTarget) -> list[NormalizedFinding]:
        url = self._api_url.rstrip("/") + self._issues_path
        try:
            with urllib.request.urlopen(url, timeout=self._timeout) as resp:  # noqa: S310 (operator-configured REST endpoint)
                body = resp.read().decode("utf-8", "replace")
        except (urllib.error.URLError, OSError) as e:
            raise AdapterError(f"burp REST API unreachable at {url}: {e}") from e
        return parse_burp(body)
