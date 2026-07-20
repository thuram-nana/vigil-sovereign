"""
eval.owasp_benchmark — a NEUTRAL ground-truth loader for the OWASP Benchmark.

The credibility problem with a bespoke benchmark is that the ground-truth manifest
is co-designed with the tool being measured. The OWASP Benchmark
(https://owasp.org/www-project-benchmark/) removes that objection: it is a large,
independently-published Java test suite (~2,700 test cases) that ships its OWN
labelled ground truth — ``expectedresults-1.2.csv`` — one row per test case with a
category, a real-vulnerability boolean, and a CWE. Nobody scoring against it wrote
the labels, so the numbers are not contestable on fairness grounds.

This module turns that published CSV into the harness's :class:`ExpectedFinding`
vocabulary and supplies the two translation pieces the comparative scorer needs:

  * ``OWASP_CATEGORY_TO_FAMILY`` — OWASP's category names → a neutral bug-class
    *family* token. A family, not a specific CRUCIBLE subclass, because OWASP's
    ``sqli`` is one label where CRUCIBLE distinguishes boolean/error/time-based.
  * ``owasp_class_key`` — a class-key (for :func:`eval.validation.score`) that
    collapses BOTH CRUCIBLE's fine-grained classes AND the family labels to the
    same family token, so a ``boolean_sqli`` detection matches an ``sqli`` label.
    Applied to both sides symmetrically, it can never inflate a match.

**Honesty about reachability.** OWASP Benchmark mixes categories a black-box HTTP
scanner CAN confirm over the wire (injection, traversal, XSS) with categories that
are code-level properties invisible to DAST (weak hash, weak randomness, insecure
cookie flags, trust-boundary, broken crypto). A DAST scored on the whole suite
would post an unfairly low recall on categories it structurally cannot reach.
``DAST_REACHABLE`` names the honest subset, and ``load_owasp_expectedresults`` with
``dast_only=True`` (the default) restricts ground truth to it. Scoring the
SAST-only categories is left to a SAST tool; this is standard practice for DAST
benchmarking and is disclosed, not hidden.

No third-party deps — the CSV is parsed with the stdlib. Running the app itself is
heavy (a Java/Tomcat build); this loader is usable the moment the CSV is present,
so the ground truth can be prepared and reviewed independently of a live run.
"""

from __future__ import annotations

import csv
from pathlib import Path

from ..common.errors import EvalError
from .models import _normalize_class
from .validation import ExpectedFinding


class OwaspBenchmarkError(EvalError):
    """A malformed or unreadable OWASP Benchmark expected-results file."""


# OWASP Benchmark 1.2 category tokens → a neutral bug-class family. The family is
# deliberately coarse (the granularity OWASP itself labels at); `owasp_class_key`
# maps CRUCIBLE's finer classes down to the same tokens.
OWASP_CATEGORY_TO_FAMILY: dict[str, str] = {
    "cmdi": "command_injection",
    "sqli": "sqli",
    "xss": "xss",
    "pathtraver": "path_traversal",
    "ldapi": "ldap_injection",
    "xpathi": "xpath_injection",
    # SAST-only categories (kept for completeness; excluded by dast_only):
    "crypto": "weak_crypto",
    "hash": "weak_hash",
    "securecookie": "insecure_cookie",
    "trustbound": "trust_boundary",
    "weakrand": "weak_random",
}

# The categories a black-box HTTP scanner can actually confirm over the wire.
DAST_REACHABLE: frozenset[str] = frozenset(
    {"cmdi", "sqli", "xss", "pathtraver", "ldapi", "xpathi"}
)

# CRUCIBLE's fine-grained bug classes → the same neutral families, so a subclass
# detection is credited against OWASP's coarse label. Any class not listed passes
# through unchanged (already family-level or out of OWASP's scope).
_CRUCIBLE_CLASS_TO_FAMILY: dict[str, str] = {
    "boolean_sqli": "sqli",
    "error_based_sqli": "sqli",
    "time_based_sqli": "sqli",
    "sqli": "sqli",
    "lfi": "path_traversal",
    "path_traversal": "path_traversal",
    "rce": "command_injection",
    "command_injection": "command_injection",
    "blind_xxe": "xxe",
}


def owasp_class_key(raw: str) -> str:
    """A family-collapsing class-key for :func:`eval.validation.score`.

    Lower/strip/normalise, then fold known CRUCIBLE subclasses and OWASP family
    labels to a common family token. Symmetric across produced and expected, so it
    only ever *merges* labels that denote the same vulnerability family — it cannot
    manufacture a match between genuinely different classes."""
    base = raw.strip().lower()
    family = _CRUCIBLE_CLASS_TO_FAMILY.get(base, base)
    return _normalize_class(family)


def load_owasp_expectedresults(
    csv_path: str | Path,
    *,
    dast_only: bool = True,
    base_path: str = "/benchmark",
) -> list[ExpectedFinding]:
    """Parse an OWASP Benchmark ``expectedresults-*.csv`` into ground-truth
    :class:`ExpectedFinding`s — one per row that is a REAL vulnerability.

    Row shape (v1.2): ``# test name, category, real vulnerability, cwe``. The
    header line begins with ``#`` and is skipped. A row counts as ground truth iff
    its real-vulnerability column is truthy; the false rows are the clean cases a
    tool must NOT flag (they surface as false positives by the scorer's off-manifest
    rule, so they need no explicit entry). Location is the test endpoint path,
    ``<base_path>/<test name>`` — CRUCIBLE's endpoint-aware finding location lines
    up with it path-first.

    With ``dast_only`` (default) only :data:`DAST_REACHABLE` categories are kept —
    the honest black-box-scoreable subset. Set it False to load the full suite
    (e.g. to score a SAST tool)."""
    p = Path(csv_path).expanduser()
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as e:
        raise OwaspBenchmarkError(f"cannot read OWASP expected-results {p}: {e}") from e

    out: list[ExpectedFinding] = []
    reader = csv.reader(text.splitlines())
    for row in reader:
        if not row:
            continue
        name = row[0].strip().lstrip("#").strip()
        # skip the header row and any comment/blank lines
        if not name or name.lower().startswith("test name") or len(row) < 3:
            continue
        category = row[1].strip().lower()
        is_real = row[2].strip().lower() in ("true", "1", "yes")
        if not is_real:
            continue
        if dast_only and category not in DAST_REACHABLE:
            continue
        family = OWASP_CATEGORY_TO_FAMILY.get(category)
        if family is None:
            # an unknown category is surfaced, not silently dropped
            raise OwaspBenchmarkError(
                f"unknown OWASP category {category!r} on {name}; extend "
                "OWASP_CATEGORY_TO_FAMILY before scoring this suite."
            )
        location = f"{base_path.rstrip('/')}/{name}"
        out.append(ExpectedFinding(bug_class=family, location=location))
    return out
