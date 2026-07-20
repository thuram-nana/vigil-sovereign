"""
analysis.analyzers.builtin — the offline pattern analyzer.

A real, dependency-free SAST pass: a curated ruleset of dangerous-code
patterns matched line-by-line across source files. It is deterministic
and always available, so DAA produces findings even on a host with no
external analyzer installed.

The ruleset is intentionally high-signal and conservative. Like all
pattern SAST it can false-positive (a regex cannot prove a sink is
reachable); findings are leads for the reasoning kernel to confirm, not
verdicts. Operators extend the ruleset; they do not depend on it being
exhaustive — that is what the external adapters add.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from ..models import AnalysisFinding, AnalysisTarget

_NAME = "pattern"


@dataclass(frozen=True)
class _Rule:
    rule_id: str
    severity: str
    pattern: re.Pattern[str]
    message: str
    cwe: str
    extensions: frozenset[str]  # empty = all


def _r(
    rule_id: str,
    severity: str,
    regex: str,
    message: str,
    cwe: str,
    exts: tuple[str, ...] = (),
) -> _Rule:
    return _Rule(
        rule_id=rule_id,
        severity=severity,
        pattern=re.compile(regex),
        message=message,
        cwe=cwe,
        extensions=frozenset(exts),
    )


# Curated dangerous-pattern ruleset.
_RULES: tuple[_Rule, ...] = (
    _r("DAA-EVAL", "high", r"\beval\s*\(", "Use of eval() — code injection risk", "CWE-95",
       (".py", ".js", ".ts", ".rb", ".php")),
    _r("DAA-EXEC", "high", r"\bexec\s*\(", "Use of exec() — code injection risk", "CWE-95",
       (".py", ".php")),
    _r("DAA-SHELL-TRUE", "high", r"shell\s*=\s*True",
       "subprocess with shell=True — OS command injection risk", "CWE-78", (".py",)),
    _r("DAA-PICKLE", "medium", r"\bpickle\.loads?\s*\(",
       "Deserializing with pickle — arbitrary code execution on untrusted data", "CWE-502",
       (".py",)),
    # Dataflow-ish: a DB cursor .execute()/.executemany() whose argument is
    # built by string concatenation or an f-string is the classic SQLi taint
    # shape a constant query never has. High-signal, still a lead not a proof.
    _r("DAA-SQL-CONCAT", "high",
       r"\.execute(?:many)?\s*\(\s*(?:f['\"]|['\"].*['\"]\s*[%+]|['\"].*\{)",
       "SQL query built by string concatenation/format into execute() — SQL injection risk",
       "CWE-89", (".py",)),
    # Flask's render_template_string renders its argument as a Jinja template;
    # passing anything but a constant is server-side template injection.
    _r("DAA-SSTI", "high", r"\brender_template_string\s*\(",
       "render_template_string() on non-constant input — server-side template injection",
       "CWE-1336", (".py",)),
    _r("DAA-YAML-LOAD", "medium", r"yaml\.load\s*\((?![^)]*Loader)",
       "yaml.load without a safe Loader — arbitrary object construction", "CWE-502", (".py",)),
    _r("DAA-WEAK-HASH", "low", r"\b(?:hashlib\.)?(?:md5|sha1)\s*\(",
       "Weak hash (MD5/SHA1) used — unsuitable for security", "CWE-327"),
    _r("DAA-SECRET", "high",
       r"(?i)\b(password|passwd|secret|api[_-]?key|token|private[_-]?key)\b\s*[:=]\s*['\"][^'\"]{6,}['\"]",
       "Possible hardcoded secret", "CWE-798"),
    _r("DAA-TLS-VERIFY-OFF", "medium", r"verify\s*=\s*False",
       "TLS verification disabled", "CWE-295", (".py",)),
    _r("DAA-REQUESTS-INSECURE", "medium", r"\bcurl\b.*\s-k\b|--insecure\b",
       "Insecure transport flag (-k/--insecure)", "CWE-295", (".sh",)),
    _r("DAA-DEBUG-TRUE", "low", r"(?i)\bdebug\s*=\s*True",
       "Debug mode enabled — may leak internals in production", "CWE-489", (".py",)),
    _r("DAA-MD-INNERHTML", "medium", r"\.innerHTML\s*=",
       "Direct innerHTML assignment — DOM XSS risk", "CWE-79", (".js", ".ts", ".tsx", ".jsx")),
)


class PatternAnalyzer:
    """Offline pattern-based static analyzer. Always available."""

    name = _NAME

    def __init__(self, rules: tuple[_Rule, ...] = _RULES) -> None:
        self._rules = rules

    def is_available(self) -> tuple[bool, str]:
        return True, "built-in (no external dependency)"

    def analyze(self, target: AnalysisTarget) -> list[AnalysisFinding]:
        root = Path(target.root).expanduser()
        findings: list[AnalysisFinding] = []
        for path in target.iter_files():
            findings.extend(self._scan_file(path, root, target.max_file_bytes))
        findings.sort(key=lambda f: (f.path, f.line, f.rule_id))
        return findings

    def _scan_file(self, path: Path, root: Path, max_bytes: int) -> list[AnalysisFinding]:
        try:
            if path.stat().st_size > max_bytes:
                return []
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        try:
            rel = str(path.relative_to(root)) if root.is_dir() else path.name
        except ValueError:
            rel = str(path)

        ext = path.suffix
        out: list[AnalysisFinding] = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            for rule in self._rules:
                if rule.extensions and ext not in rule.extensions:
                    continue
                if rule.pattern.search(line):
                    out.append(
                        AnalysisFinding(
                            analyzer=_NAME,
                            rule_id=rule.rule_id,
                            severity=rule.severity,
                            path=rel,
                            line=lineno,
                            message=rule.message,
                            snippet=line.strip()[:200],
                            cwe=rule.cwe,
                        )
                    )
        return out
