"""
eval.adapters_ext — Wapiti and Nikto incumbent adapters for the comparative harness.

`eval.adapters` ships the Nuclei/ZAP/sqlmap/Burp adapters; this module adds the two
scanners actually present on the benchmark host — **Wapiti** (an active DAST that
crawls and fuzzes) and **Nikto** (a server/misconfiguration scanner). Both conform
to the same ``validation.Adapter`` protocol: ``available()`` is a cheap
``shutil.which`` probe, and ``run(target)`` shells out, then a pure ``parse_*``
function maps the tool's native JSON into ``validation.NormalizedFinding`` so the
harness scores it against the same ground truth as CRUCIBLE.

As in ``eval.adapters``, the PARSERS are the tested unit: each is a pure
``str -> list`` mapping exercised against a captured sample of the real tool's
output, so parsing is proven without the tools installed. They raise
:class:`AdapterError` only on **malformed** output (non-JSON, or a top-level shape
that is not the tool's), never on an empty-but-well-formed result. The ``run()``
wrappers that invoke the tools are thin and skip cleanly when the tool is absent.

Output formats (captured from the tools on this host):

  * **Wapiti** ``wapiti -u <url> -f json -o <file>`` — a report object whose
    ``vulnerabilities`` is a ``{category: [ {method, path, parameter, info, level,
    module}, ... ]}`` map. Location is ``path`` (+ ``?parameter``); the category
    key is the bug class.
  * **Nikto** ``nikto -h <url> -Format json -output <file>`` — a LIST of host
    objects, each ``{host, ip, port, server_banner, vulnerabilities: [ {id, method,
    msg, url, references}, ... ]}``. The bug class is inferred from ``msg`` keywords;
    the location is the path in ``msg`` (else ``url``).
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess  # noqa: S404 (invoking operator-owned local scanners by design)
import tempfile
from pathlib import Path

from ..common.errors import EvalError
from .validation import CorpusTarget, NormalizedFinding


class AdapterError(EvalError):
    """A Wapiti/Nikto adapter could not parse its tool's output. A recoverable
    measurement error (the tool ran but emitted something the parser cannot map),
    never an authorization decision."""


def _slug(text: str) -> str:
    """A normalized bug-class slug from a free-text category: lowercase, non-alnum
    runs collapsed to a single underscore, trimmed."""
    return re.sub(r"[^a-z0-9]+", "_", text.strip().lower()).strip("_") or "unknown"


# ===========================================================================
# Wapiti — report object with a {category: [findings]} vulnerabilities map.
# ===========================================================================

# Wapiti category (lowercased) -> normalized bug_class. Unlisted categories fall
# back to a slug of the category name, so coverage never silently drops a class.
_WAPITI_CLASS: dict[str, str] = {
    "cross site scripting": "xss",
    "stored cross site scripting": "xss",
    "sql injection": "sql_injection",
    "blind sql injection": "sql_injection",
    "path traversal": "path_traversal",
    "linux/unix file disclosure": "path_traversal",
    "open redirect": "open_redirect",
    "server side request forgery": "ssrf",
    "command execution": "command_injection",
    "cross site request forgery": "csrf",
    "crlf injection": "crlf_injection",
    "xml external entity": "xxe",
    "content security policy configuration": "security_misconfiguration",
    "http secure headers": "security_misconfiguration",
    "htaccess bypass": "security_misconfiguration",
    "httponly flag cookie": "cookie_security",
    "secure flag cookie": "cookie_security",
    "backup file": "exposure",
    "potentially dangerous file": "exposure",
    "weak credentials": "weak_credentials",
}

# Wapiti "level" (1..3) -> severity label.
_WAPITI_LEVEL = {1: "low", 2: "medium", 3: "high", 4: "critical"}


def parse_wapiti(output: str) -> list[NormalizedFinding]:
    """Parse a Wapiti JSON report. Each item under each ``vulnerabilities``
    category becomes one finding located on ``path`` (+ ``?parameter`` when a
    parameter is named); the category key maps to the bug class. A payload that is
    not a JSON object, or that lacks a ``vulnerabilities`` object, is malformed ->
    AdapterError."""
    try:
        data = json.loads(output)
    except json.JSONDecodeError as e:
        raise AdapterError(f"wapiti report is not valid JSON: {e}") from e
    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), dict):
        raise AdapterError("wapiti report is missing its 'vulnerabilities' object")

    findings: list[NormalizedFinding] = []
    for category, items in data["vulnerabilities"].items():
        if not isinstance(items, list):
            raise AdapterError(f"wapiti category {category!r} is not a list of findings")
        bug_class = _WAPITI_CLASS.get(str(category).strip().lower(), _slug(str(category)))
        for item in items:
            if not isinstance(item, dict):
                raise AdapterError(f"wapiti finding under {category!r} is not an object: {item!r}")
            path = str(item.get("path", "") or item.get("url", ""))
            param = str(item.get("parameter", "") or "")
            location = f"{path}?{param}" if (path and param) else (path or param)
            level = item.get("level")
            severity = _WAPITI_LEVEL.get(level if isinstance(level, int) else -1, "")
            findings.append(NormalizedFinding(
                tool="wapiti",
                bug_class=bug_class,
                location=location,
                severity=severity,
                confirmed=False,  # wapiti's detections are heuristic, not oracle-proven
                evidence=str(item.get("info", "")),
            ))
    return findings


class WapitiAdapter:
    """Wapiti via ``wapiti -u <url> -f json -o <file>``, parsing the JSON report."""

    name: str = "wapiti"

    def __init__(
        self,
        *,
        binary: str = "wapiti",
        extra_args: tuple[str, ...] = ("--flush-session",),
        timeout: float = 900.0,
    ) -> None:
        self._binary = binary
        self._extra_args = tuple(extra_args)
        self._timeout = timeout

    def available(self) -> bool:
        return shutil.which(self._binary) is not None

    def run(self, target: CorpusTarget) -> list[NormalizedFinding]:
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "wapiti.json"
            cmd = [self._binary, "-u", target.base_url, "-f", "json",
                   "-o", str(report), *self._extra_args]
            subprocess.run(  # noqa: S603 (fixed argv, operator-owned tool)
                cmd, capture_output=True, text=True, timeout=self._timeout, check=False,
            )
            try:
                output = report.read_text(encoding="utf-8")
            except OSError as e:
                raise AdapterError(f"wapiti produced no JSON report at {report}: {e}") from e
        return parse_wapiti(output)


# ===========================================================================
# Nikto — a list of host objects, each with a vulnerabilities array of messages.
# ===========================================================================

# (substring in the lowered "msg url" text, normalized bug_class). First match
# wins, so more specific signals are listed before the generic header/misc ones.
_NIKTO_RULES: tuple[tuple[str, str], ...] = (
    (".git", "exposure"),
    (".env", "exposure"),
    ("actuator", "exposure"),
    (".svn", "exposure"),
    ("phpinfo", "exposure"),
    ("backup", "exposure"),
    ("swagger", "exposure"),
    ("cross site scripting", "xss"),
    (" xss", "xss"),
    ("sql injection", "sql_injection"),
    ("access-control-allow-origin", "cors"),
    ("cross-origin", "cors"),
    ("open redirect", "open_redirect"),
    ("redirect", "open_redirect"),
    ("directory indexing", "directory_listing"),
    ("index of", "directory_listing"),
    ("traversal", "path_traversal"),
    ("remote file", "rfi"),
    ("outdated", "outdated_software"),
    ("appears to be outdated", "outdated_software"),
    ("security header", "security_misconfiguration"),
    ("header is not set", "security_misconfiguration"),
    ("header is deprecated", "security_misconfiguration"),
)

_NIKTO_PATH = re.compile(r"^(/\S*?):")


def _nikto_class(text: str) -> str:
    low = text.lower()
    for needle, bug_class in _NIKTO_RULES:
        if needle in low:
            return bug_class
    return "security_misconfiguration"


def _nikto_location(msg: str, url: str) -> str:
    """Prefer a leading ``/path:`` in the message (Nikto's real subject), else the
    structural ``url`` field."""
    m = _NIKTO_PATH.match(msg.strip())
    if m:
        return m.group(1)
    return url or "/"


def _nikto_hosts(data: object) -> list[dict]:
    """Normalize Nikto's payload to a flat list of host objects: a bare array of
    hosts, or a single host object."""
    if isinstance(data, list):
        return [h for h in data if isinstance(h, dict)]
    if isinstance(data, dict):
        return [data]
    raise AdapterError("nikto payload must be a JSON array or object")


def parse_nikto(output: str) -> list[NormalizedFinding]:
    """Parse a Nikto JSON report. Each vulnerability message under each host
    becomes one finding: the bug class is inferred from the message keywords and
    the location from a ``/path:`` in the message (else the ``url``). Non-JSON, or a
    vulnerabilities value that is not a list, is malformed -> AdapterError."""
    try:
        data = json.loads(output)
    except json.JSONDecodeError as e:
        raise AdapterError(f"nikto report is not valid JSON: {e}") from e

    findings: list[NormalizedFinding] = []
    for host in _nikto_hosts(data):
        vulns = host.get("vulnerabilities", [])
        if vulns is None:
            continue
        if not isinstance(vulns, list):
            raise AdapterError("nikto 'vulnerabilities' must be a list")
        for item in vulns:
            if not isinstance(item, dict):
                raise AdapterError(f"nikto vulnerability is not an object: {item!r}")
            msg = str(item.get("msg", ""))
            url = str(item.get("url", ""))
            findings.append(NormalizedFinding(
                tool="nikto",
                bug_class=_nikto_class(f"{msg} {url}"),
                location=_nikto_location(msg, url),
                severity="",
                confirmed=False,  # nikto's checks are signature/heuristic, not proven
                evidence=msg[:200],
            ))
    return findings


class NiktoAdapter:
    """Nikto via ``nikto -h <url> -Format json -output <file>``, parsing the JSON.

    Nikto appends the format extension to ``-output`` inconsistently across
    versions, so ``run`` reads whichever of the requested path / ``<path>.json``
    the tool actually wrote."""

    name: str = "nikto"

    def __init__(
        self,
        *,
        binary: str = "nikto",
        extra_args: tuple[str, ...] = (),
        timeout: float = 900.0,
    ) -> None:
        self._binary = binary
        self._extra_args = tuple(extra_args)
        self._timeout = timeout

    def available(self) -> bool:
        return shutil.which(self._binary) is not None

    def run(self, target: CorpusTarget) -> list[NormalizedFinding]:
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "nikto.json"
            cmd = [self._binary, "-h", target.base_url, "-Format", "json",
                   "-output", str(report), *self._extra_args]
            subprocess.run(  # noqa: S603 (fixed argv, operator-owned tool)
                cmd, capture_output=True, text=True, timeout=self._timeout, check=False,
            )
            for candidate in (report, Path(str(report) + ".json")):
                try:
                    output = candidate.read_text(encoding="utf-8")
                    break
                except OSError:
                    continue
            else:
                raise AdapterError(f"nikto produced no JSON report at {report}(.json)")
        return parse_nikto(output)
