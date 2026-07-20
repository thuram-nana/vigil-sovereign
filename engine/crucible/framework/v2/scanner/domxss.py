"""
scanner.domxss — static DOM-XSS source→sink analysis.

DOM-based XSS lives entirely client-side: attacker-controlled *sources*
(``location.hash``, ``document.referrer``, ``window.name``, postMessage data)
flowing into dangerous *sinks* (``innerHTML``, ``document.write``, ``eval``,
``setTimeout`` with a string) without sanitisation. It is invisible to a
server-response scanner — the server never sees the payload.

Dynamic confirmation of DOM-XSS needs a real DOM (a headless browser) to observe
the sink fire; that is a deliberate infrastructure dependency this stdlib module
does not take. What it CAN do — and what Burp's static DOM analysis also does — is
find the source→sink *flow* by lightweight taint over the page's JavaScript, and
surface it as a **candidate** (not an oracle-confirmed finding). The honesty is
explicit: a `DomXssCandidate` carries a confidence tier (`Firm` for a source used
directly in a sink, `Tentative` for a source reaching a sink via a variable) and
is never dressed up as a proven exploit.

Pure and deterministic; no network, no browser.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Attacker-controllable DOM sources.
_SOURCES = [
    r"location\.hash", r"location\.search", r"location\.href", r"location\.pathname",
    r"document\.URL", r"document\.documentURI", r"document\.baseURI",
    r"document\.referrer", r"window\.name", r"document\.cookie",
    r"location\s*\.\s*(?:hash|search|href)", r"\.data\b",  # event.data (postMessage)
]
_SOURCE_RX = re.compile("|".join(f"(?:{s})" for s in _SOURCES))

# Dangerous sinks: (name, regex capturing the sink's argument/RHS).
_SINKS: list[tuple[str, re.Pattern[str]]] = [
    ("innerHTML", re.compile(r"\.innerHTML\s*=\s*([^;\n]+)")),
    ("outerHTML", re.compile(r"\.outerHTML\s*=\s*([^;\n]+)")),
    ("insertAdjacentHTML", re.compile(r"\.insertAdjacentHTML\s*\([^,]+,\s*([^)\n]+)\)")),
    ("document.write", re.compile(r"document\.write(?:ln)?\s*\(([^)\n]+)\)")),
    ("eval", re.compile(r"\beval\s*\(([^)\n]+)\)")),
    ("Function", re.compile(r"\bnew\s+Function\s*\(([^)\n]+)\)")),
    ("setTimeout", re.compile(r"\bsetTimeout\s*\(\s*([\"'][^)\n]+)\)")),
    ("setInterval", re.compile(r"\bsetInterval\s*\(\s*([\"'][^)\n]+)\)")),
    ("jQuery.html", re.compile(r"\.html\s*\(([^)\n]+)\)")),
    ("location.assign", re.compile(r"location\s*\.\s*(?:href|assign)\s*[=(]\s*([^);\n]+)")),
    ("script.src", re.compile(r"\.src\s*=\s*([^;\n]+)")),
]

# assignment of a source to a variable: `var x = ... location.hash ...`
_ASSIGN_RX = re.compile(r"(?:var|let|const)?\s*([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+)")


@dataclass(frozen=True)
class DomXssCandidate:
    """A static source→sink flow — a CANDIDATE, not an oracle-confirmed finding.
    Dynamic confirmation requires a headless browser (out of scope here)."""

    source: str
    sink: str
    confidence: str  # Firm (direct) | Tentative (via variable)
    evidence: str

    bug_class: str = "dom_xss"


def analyze_js(js: str) -> list[DomXssCandidate]:
    """Find DOM-XSS source→sink flows in one JavaScript string."""
    tainted = _tainted_vars(js)
    out: list[DomXssCandidate] = []
    seen: set[tuple[str, str, str]] = set()
    for sink_name, rx in _SINKS:
        for m in rx.finditer(js):
            arg = m.group(1)
            src = _SOURCE_RX.search(arg)
            if src:
                key = (src.group(0), sink_name, "direct")
                if key not in seen:
                    seen.add(key)
                    out.append(DomXssCandidate(src.group(0), sink_name, "Firm", _clip(m.group(0))))
                continue
            var = _tainted_in(arg, tainted)
            if var is not None:
                key = (tainted[var], sink_name, var)
                if key not in seen:
                    seen.add(key)
                    out.append(DomXssCandidate(tainted[var], sink_name, "Tentative", _clip(m.group(0))))
    return out


def analyze_html(html: str) -> list[DomXssCandidate]:
    """Extract inline scripts + ``javascript:`` URLs from HTML and analyze them."""
    out: list[DomXssCandidate] = []
    for m in re.finditer(r"<script\b[^>]*>(.*?)</script>", html, re.DOTALL | re.IGNORECASE):
        out.extend(analyze_js(m.group(1)))
    for m in re.finditer(r"javascript:([^\"'>]+)", html, re.IGNORECASE):
        out.extend(analyze_js(m.group(1)))
    return out


def _tainted_vars(js: str) -> dict[str, str]:
    """Variables assigned (directly) from a DOM source -> the source they carry."""
    tainted: dict[str, str] = {}
    for m in _ASSIGN_RX.finditer(js):
        name, rhs = m.group(1), m.group(2)
        src = _SOURCE_RX.search(rhs)
        if src and name not in ("innerHTML", "outerHTML", "src"):
            tainted[name] = src.group(0)
    return tainted


def _tainted_in(expr: str, tainted: dict[str, str]) -> str | None:
    for var in tainted:
        if re.search(rf"\b{re.escape(var)}\b", expr):
            return var
    return None


def _clip(s: str, n: int = 120) -> str:
    s = " ".join(s.split())
    return s if len(s) <= n else s[:n] + "…"
