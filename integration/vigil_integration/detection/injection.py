"""
detection.injection — the RAMPART in-path structural injection oracles (INJECTION-SENTINEL).

Each oracle recognises a hostile injection CONSTRUCT in a request — not a mere keyword. The benign-twin
discipline is a safety property here: these run in-path (edge, can block), so a false positive is an
outage. Every detector requires genuine attack STRUCTURE so a legitimate look-alike stays silent:

  * ``sqli_structure`` — a NUMERIC-LITERAL or SELF-EQUAL tautology (``1=1`` / ``'1'='1`` / ``x=x``),
    UNION-SELECT, a time-or-error function, or a quote-break-comment — NOT a legitimate filter DSL that
    compares a field to a value (``type=novel and year=2024``), the lone word ``select`` in prose, or an
    apostrophe in a name (``O'Reilly``).
  * ``xss_structure`` — a real ``<script>`` / a curated event-handler ``on…=`` / a ``javascript:`` call,
    NOT escaped HTML (``&lt;script&gt;``) or the bare word "javascript"/"onload" in prose.
  * ``path_traversal`` — a ``../`` (or encoded) escape or a known sensitive absolute path, NOT a dotted
    filename (``report..2024.pdf``).
  * ``crlf_injection`` — an encoded/raw CR/LF/NUL in the request, NOT the hex text "0a" in a value.
  * ``cmd_injection`` — a shell substitution ``$(…)``/backticks, or a separator followed by a real binary
    that carries genuine command structure (the binary at end-of-value like ``|whoami`` or with its
    typical argument like ``;cat /etc/passwd``), NOT a lone ``&`` URL separator, nor a semicolon/matrix-
    delimited list whose token merely equals a binary name (``;id=123`` / ``;id;email`` / ``;chmod=755``).

The structural detectors are module-level pure functions so ``detection.recon.waf_probe`` can reuse them
(the "throw every class at the WAF" composite). All oracles scan the PERCENT-DECODED request target so
``%27`` cannot hide a payload. Pure/deterministic/total; a FACT is minted only via the base
oracle's signed-and-re-verified certificate path.

Import-clean: stdlib ``re`` + the detection base.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from .base import DetectionOracle, Grade, OracleHit

# ---------------------------------------------------------------------------------------------------
# structural detectors (pure) — return the fired signature family, or None
# ---------------------------------------------------------------------------------------------------


# Structural attack payloads that matter are short; a request target longer than this is itself
# anomalous. Capping the scanned prefix bounds every detector to linear-ish time (defense-in-depth
# against ReDoS on attacker-influenced telemetry) — an over-long param degrades to no-signal (total).
_MAX_SCAN = 16384


def _first_match(text: str, patterns: list) -> Optional[str]:
    """Return the label of the first ``(label, regex)`` that matches ``text``, else ``None``. Total; the
    scanned input is capped to a bounded prefix so no pattern can be driven into catastrophic
    backtracking by a pathologically long value."""
    if not isinstance(text, str) or not text:
        return None
    if len(text) > _MAX_SCAN:
        text = text[:_MAX_SCAN]
    for label, rx in patterns:
        try:
            if rx.search(text):
                return label
        except Exception:  # noqa: BLE001
            continue
    return None


# -- SQLi ------------------------------------------------------------------------------------------
_SQLI_PATTERNS = [
    # A boolean tautology with NUMERIC-LITERAL operands: OR 1=1 / and 2 <> 3 / OR '1'='1. A legitimate
    # filter DSL compares a FIELD to a value (``year=2024``), never two bare literals, so a
    # number-vs-number comparison behind or/and is hostile while ``and year=2024`` stays silent.
    ("sql-tautology", re.compile(
        r"\b(?:or|and)\s+['\"`]?\d+['\"`]?\s*(?:=|<>|!=|<=|>=|<|>)\s*['\"`]?\d+['\"`]?", re.I)),
    # A boolean tautology with MATCHING operands: OR x=x / OR 'a'='a' / and name=name — a self-equal
    # comparison (backreference to the same token). ``and year=2024`` has distinct operands → no match.
    ("sql-tautology", re.compile(
        r"\b(?:or|and)\s+['\"`]?(\w+)['\"`]?\s*(?:=|<>|!=|<=|>=|<|>|\blike\b)\s*['\"`]?\1\b", re.I)),
    ("sql-union", re.compile(r"\bunion\b(?:\s+all)?\s+\bselect\b", re.I)),
    # a string-literal break immediately into an SQL operator/keyword: x' OR … / x' UNION … / x';
    # (disjoint, non-nested quantifiers only — no ambiguous \s*(?:)|\s)* that could backtrack O(n^2))
    ("sql-quote-break", re.compile(r"['\"`]\s*(?:or|and|union|;)\b\s*['\"`\d(]", re.I)),
    ("sql-comment", re.compile(r"['\"`]\s*(?:--|#|/\*)", re.I)),
    ("sql-timefn", re.compile(
        r"\b(?:sleep|benchmark|pg_sleep|waitfor\s+delay|dbms_pipe\.receive_message|extractvalue|updatexml|load_file)\s*\(",
        re.I)),
]


def detect_sqli(text: object) -> Optional[str]:
    return _first_match(str(text or ""), _SQLI_PATTERNS)


# -- XSS -------------------------------------------------------------------------------------------
# A curated event-handler name list so ``onboarding=`` / prose "onload" never fire — only a real
# handler NAME immediately followed by ``=`` matches.
_EVENT_HANDLERS = (
    "onerror|onload|onclick|ondblclick|onmouseover|onmouseout|onmousemove|onmousedown|onmouseup|"
    "onfocus|onblur|onchange|onsubmit|onreset|onkeydown|onkeyup|onkeypress|ontoggle|onanimationstart|"
    "onanimationend|ontransitionend|onpointerover|onpointerenter|oncontextmenu|onwheel|onscroll|"
    "oninput|ondrag|ondrop|oncopy|onpaste|oncut|onplay|onpause|oncanplay|onloadstart|onhashchange|"
    "onpopstate|onmessage|onresize|onbeforeunload|onreadystatechange|onstart|onbegin")
_XSS_PATTERNS = [
    ("xss-script-tag", re.compile(r"<\s*/?\s*script\b", re.I)),
    ("xss-event-handler", re.compile(r"\b(?:" + _EVENT_HANDLERS + r")\s*=", re.I)),
    ("xss-js-uri", re.compile(
        r"javascript\s*:\s*(?:[a-z_$][\w$.]*\s*\(|void|alert|eval|prompt|confirm|document|window|location)", re.I)),
    ("xss-vector-tag", re.compile(r"<\s*(?:svg|iframe|img|object|embed|body|base|form|math|details|marquee)[\s/>]", re.I)),
]


def detect_xss(text: object) -> Optional[str]:
    return _first_match(str(text or ""), _XSS_PATTERNS)


# -- path traversal --------------------------------------------------------------------------------
_TRAVERSAL_PATTERNS = [
    ("traversal-dotdot", re.compile(r"\.\.[\\/]", re.I)),
    ("traversal-encoded", re.compile(r"%2e%2e|%252e|\.\.%2f|%2e%2e%2f|%c0%ae|%c0%af|\.\.%5c", re.I)),
    ("traversal-sensitive", re.compile(
        r"/etc/(?:passwd|shadow|hosts)\b|/proc/self/(?:environ|cmdline)|boot\.ini|win\.ini|/windows/win\.ini", re.I)),
]


def detect_traversal(text: object) -> Optional[str]:
    return _first_match(str(text or ""), _TRAVERSAL_PATTERNS)


# -- CRLF / NUL smuggling --------------------------------------------------------------------------
_CRLF_PATTERNS = [
    ("crlf-encoded", re.compile(r"%0d%0a|%0a%0d|%0d|%0a", re.I)),
    ("crlf-nul", re.compile(r"%00|\x00")),
    ("crlf-raw", re.compile(r"[\r\n]")),
]


def detect_crlf(text: object) -> Optional[str]:
    return _first_match(str(text or ""), _CRLF_PATTERNS)


# -- command injection -----------------------------------------------------------------------------
_SEP = r"(?:;|\||\|\||&&|%0a|\n)"
_CMD_PATTERNS = [
    # $(cmd) / `cmd` — a shell command substitution with non-empty content
    ("cmd-subshell", re.compile(r"\$\([^)]+\)|`[^`]+`")),
    # a separator then a binary that carries GENUINE COMMAND STRUCTURE — the binary MUST be followed by
    # whitespace and at least one argument char (``\s+\S``). A BARE binary token (``;id``, ``|whoami``,
    # ``;chmod=755``) is textually indistinguishable from a field/column/matrix-param value whose token
    # happens to equal a binary name (``fields=name;email;id``, ``columns=a|b|id``, ``;id=123``), so — per
    # the benign-twin discipline (precision over recall: an in-path false positive is an outage) — a bare
    # token DOES NOT fire; a bare no-arg injection is a documented, accepted miss (see module docstring).
    # Genuine no-structure injection is still caught by cmd-subshell ($()/backticks) and cmd-known-arg.
    ("cmd-binary", re.compile(
        _SEP + r"\s*(?:whoami|uname|ifconfig|ipconfig|nslookup|netcat|ncat|powershell|pwsh|certutil|"
        r"systeminfo|crontab|chmod|id|/bin/sh|/bin/bash)\s+\S", re.I)),
    # a separator then a common binary WITH its typical injection argument (avoids benign ";cat")
    ("cmd-known-arg", re.compile(
        _SEP + r"\s*(?:cat\s+/|ls\s+-?[al/]|wget\s+https?://|curl\s+https?://|ping\s+-[a-z]|nc\s+-|nc\s+\d)", re.I)),
]


def detect_cmd(text: object) -> Optional[str]:
    return _first_match(str(text or ""), _CMD_PATTERNS)


# The reusable class→detector map (recon.waf_probe consumes it for the composite WAF-probe lead).
ATTACK_DETECTORS = {
    "sqli": detect_sqli,
    "xss": detect_xss,
    "traversal": detect_traversal,
    "crlf": detect_crlf,
    "cmd": detect_cmd,
}


# ---------------------------------------------------------------------------------------------------
# the in-path injection oracles — per-request, FACT-grade
# ---------------------------------------------------------------------------------------------------


class _PerRequestInjectionOracle(DetectionOracle):
    """Base for the structural oracles: scan each access record's decoded (and, for traversal/crlf, raw)
    target; fire FACT on the FIRST record that matches, embedding that one line as the proof."""

    evidence_kind = "access_log"
    default_grade = Grade.FACT

    def _classify(self, rec: Any) -> Optional[str]:  # pragma: no cover - abstract
        raise NotImplementedError

    def evaluate(self, records: Any) -> Optional[OracleHit]:
        if not isinstance(records, (list, tuple)):
            return None
        for rec in records:
            kind = self._classify(rec)
            if kind:
                src = getattr(rec, "src", "") or ""
                target = getattr(rec, "decoded_target", "") or getattr(rec, "target", "")
                return OracleHit(
                    signature_kind=kind,
                    summary=f"{self.name} signature {kind!r} in request {target!r} from {src or 'edge'}",
                    evidence_records=(rec,), source=src,
                )
        return None


class SqliStructureOracle(_PerRequestInjectionOracle):
    name = "sqli_structure"
    bug_class = "sqli"
    severity = "high"

    def _classify(self, rec: Any) -> Optional[str]:
        return detect_sqli(getattr(rec, "decoded_target", ""))


class XssStructureOracle(_PerRequestInjectionOracle):
    name = "xss_structure"
    bug_class = "xss"
    severity = "medium"

    def _classify(self, rec: Any) -> Optional[str]:
        return detect_xss(getattr(rec, "decoded_target", ""))


class PathTraversalOracle(_PerRequestInjectionOracle):
    name = "path_traversal"
    bug_class = "path_traversal"
    severity = "high"

    def _classify(self, rec: Any) -> Optional[str]:
        # traversal hides in both the raw (encoded) and decoded target.
        return (detect_traversal(getattr(rec, "target", ""))
                or detect_traversal(getattr(rec, "decoded_target", "")))


class CrlfInjectionOracle(_PerRequestInjectionOracle):
    name = "crlf_injection"
    bug_class = "crlf_injection"
    severity = "medium"

    def _classify(self, rec: Any) -> Optional[str]:
        # CR/LF is percent-encoded in the raw target; the decoded target carries the literal control char.
        return (detect_crlf(getattr(rec, "target", ""))
                or detect_crlf(getattr(rec, "decoded_target", "")))


class CmdInjectionOracle(_PerRequestInjectionOracle):
    name = "cmd_injection"
    bug_class = "cmd_injection"
    severity = "high"

    def _classify(self, rec: Any) -> Optional[str]:
        return (detect_cmd(getattr(rec, "decoded_target", ""))
                or detect_cmd(getattr(rec, "target", "")))
