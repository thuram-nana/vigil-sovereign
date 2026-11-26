"""AS-4a — the D13 over-claim lint for SIGIL's customer-facing *product* copy.

WHY THIS EXISTS. VIGIL *observes* and *detects with oracle confirmation*; it does NOT guarantee
prevention or completeness. Marketing over-claims ("universal detection", "zero false negatives",
"complete MITRE coverage", a status badge that reads "Protected", ...) are forbidden (doctrine D13).
Prior claim-discipline passes removed them from the customer app; this module is the deterministic
regression guard that KEEPS them out — a single enumerated checker a sigil test drives.

RELATIONSHIP TO THE EXISTING CHECKERS (no double-code). Two sibling guards already live in the suite
and are deliberately NOT merged into this one, because each owns a different surface with a different
word-list:
  * ``tests/test_public_terms_page.py::overclaims`` — the *legal* pages (Terms / Privacy HTML): a
    legal word-list ("guarantee", "bank-grade", "protected"/"secure" with legal allowances).
  * ``tests/test_customer_onboarding.py::_FORBIDDEN`` — the Guide copy must not leak model names,
    prices or the word "margin" (an internals guard, not an over-claim guard).
Neither enumerates the D13 *product-claim* list below, and neither scans the customer app JS. This
module is the D13 product-copy guard; it mirrors the legal checker's shape (explicit phrases + a
word rule + per-rule allowances) so the two read as a family, not a fork.

DESIGN.
  * The forbidden terms are ENUMERATED and EXPLICIT (``RULES`` below) — one named rule per D13 term,
    each a small tuple of literal phrases, never a broad regex that would also catch legitimate copy.
  * Each match is a whole token: ``(?<![\\w-])phrase(?![\\w-])`` so "protected-host" (a plan's slot
    feature) and "data-protection" (the law) are NOT mistaken for the "Protected" status badge.
  * Per-rule ALLOWANCES neutralise a provable, mechanism-qualified claim (e.g. "zero false positives
    by construction" — the oracle gate makes it true) before the bare phrase is searched.
  * PURE + DETERMINISTIC: no wall-clock, no RNG, no network — the result is a function of the bytes.
  * FAIL-CLOSED: ``scan_files`` raises if a surface it is supposed to read is missing or unreadable;
    a file it cannot scan is a lint FAILURE, never a silent pass.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

_UI = Path(__file__).resolve().parent                      # apps/sigil/sigil/ui
_CUSTOMER_APP = _UI / "customer_app"

#: The customer-facing product-copy surfaces this lint owns. ENUMERATED (not a glob) so that a file
#: which disappears is a hard failure in ``scan_files`` rather than a silently smaller scan. These are
#: the SIGIL-side copy surfaces the AS-4a plan named (DEPLOYMENT.md is an engine-side operator doc,
#: outside the two-env boundary, so it is not in this sigil-side set).
COPY_SURFACES: tuple[Path, ...] = (
    _CUSTOMER_APP / "app.js",
    _CUSTOMER_APP / "guide.js",
    _CUSTOMER_APP / "index.html",
    _UI / "provision.py",
)


class OverclaimLintError(RuntimeError):
    """A surface the lint is required to scan could not be read — fail-closed, not a clean pass."""


@dataclass(frozen=True)
class Rule:
    """One enumerated D13 forbidden claim: its id, what it forbids, the literal phrases that spell it,
    and the explicit phrases that *neutralise* a hit (a provable, qualified use that is allowed)."""

    name: str
    description: str
    phrases: tuple[str, ...]
    allowances: tuple[str, ...] = field(default_factory=tuple)


#: The D13 term list, enumerated. Editing this is the ONLY way the forbidden set changes.
RULES: tuple[Rule, ...] = (
    Rule(
        "universal_detection_prevention",
        'claims VIGIL detects or prevents everything ("universal detection/prevention")',
        ("universal detection", "universal prevention", "universally detect", "universally prevent"),
    ),
    Rule(
        "zero_false_positives_negatives",
        "claims zero false positives or negatives (FP/FN) as a blanket product promise",
        (
            "zero false positive",
            "zero false positives",
            "zero false negative",
            "zero false negatives",
            "zero false positives/negatives",
            "zero false positives or negatives",
        ),
        # The oracle gate makes the mechanism-qualified precision claim provable, so it is NOT a D13
        # over-claim. Masked out before the bare phrase is searched (see the architecture pages).
        allowances=(
            "zero false positives by construction",
            "zero false positive by construction",
        ),
    ),
    Rule(
        "near_zero_false_positives",
        'claims "near-zero false positives"',
        (
            "near-zero false positive",
            "near-zero false positives",
            "near zero false positive",
            "near zero false positives",
        ),
    ),
    Rule(
        "complete_mitre_coverage",
        "claims complete / full MITRE (ATT&CK) coverage",
        (
            "complete mitre coverage",
            "complete mitre att&ck coverage",
            "complete att&ck coverage",
            "full mitre coverage",
            "full mitre att&ck coverage",
            "100% mitre",
        ),
    ),
    Rule(
        "permanent_protection",
        'claims "permanent protection"',
        ("permanent protection", "permanently protected"),
    ),
    Rule(
        "fully_protected",
        'claims a host/asset is "fully protected"',
        ("fully protected",),
    ),
    Rule(
        "all_threats_blocked",
        'claims every threat/attack is blocked ("all threats blocked")',
        ("all threats blocked", "blocks all threats", "block all threats", "all attacks blocked", "blocks all attacks"),
    ),
    Rule(
        "protected_status",
        'uses the bare word "protected" as a STATE/status (e.g. a badge reading "Protected")',
        ("protected",),
        # "protected-host" (a plan slot) and "data-protection" (the law) are excluded by the token
        # boundary, not here; this rule fires only on a standalone status word.
    ),
)


@dataclass(frozen=True)
class Finding:
    """One over-claim found: which rule, the exact phrase matched, the surface, and a small excerpt."""

    rule: str
    phrase: str
    surface: str
    excerpt: str


_EXCERPT_PAD = 24


def _blank(match: re.Match[str]) -> str:
    """Replace an allowance span with same-length spaces, so later match offsets stay aligned."""
    return " " * (match.end() - match.start())


def _token(phrase: str) -> re.Pattern[str]:
    """A whole-token, case-insensitive matcher for ``phrase``: not preceded or followed by a word
    character or a hyphen, so "protected-host" / "near-zero ..." do not bleed across rules."""
    return re.compile(r"(?<![\w-])" + re.escape(phrase) + r"(?![\w-])", re.IGNORECASE)


def scan_text(text: str, surface: str = "<string>") -> list[Finding]:
    """Every D13 over-claim in ``text``. Deterministic: per rule, mask that rule's allowances, then
    match each enumerated phrase as a whole token. Findings are returned in a stable order (rule
    order, then position)."""
    findings: list[Finding] = []
    for rule in RULES:
        masked = text
        for allowance in rule.allowances:
            masked = re.compile(re.escape(allowance), re.IGNORECASE).sub(_blank, masked)
        for phrase in rule.phrases:
            for m in _token(phrase).finditer(masked):
                start = max(0, m.start() - _EXCERPT_PAD)
                end = min(len(text), m.end() + _EXCERPT_PAD)
                excerpt = re.sub(r"\s+", " ", text[start:end]).strip()
                findings.append(Finding(rule.name, phrase, surface, excerpt))
    return findings


def scan_files(paths: tuple[Path, ...] = COPY_SURFACES) -> list[Finding]:
    """Scan every enumerated copy surface. FAIL-CLOSED: a missing or unreadable file raises
    ``OverclaimLintError`` — a surface the lint cannot read is a failure, never a clean pass."""
    findings: list[Finding] = []
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise OverclaimLintError(f"cannot read copy surface {path}: {exc}") from exc
        findings.extend(scan_text(text, surface=path.name))
    return findings


def format_findings(findings: list[Finding]) -> str:
    """A stable, human-readable report of ``findings`` for a failing assertion message."""
    return "\n".join(f"  [{f.rule}] {f.surface}: {f.phrase!r} — …{f.excerpt}…" for f in findings)
