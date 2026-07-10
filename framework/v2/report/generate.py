"""
report.generate — the three deterministic Markdown renderers.

Each renderer is a PURE function of the graded findings + a small ``ReportMeta``.
There is no wallclock and no RNG on this path: with ``ReportMeta.generated_at``
left ``None`` (the default), the same findings render byte-identically every time.
An operator who wants a timestamp passes one explicitly; it is the only source of
non-determinism and it is opt-in.

Prove-don't-guess is carried through every document:

  * EXECUTIVE   leads with plain-language impact. "What we found" lists ONLY proven
                facts as confirmed; leads live in their own clearly-labelled section
                and are never stated as things an attacker *can* do.
  * TECHNICAL   per-finding PoC/summary + remediation, with a verification block that
                either shows the deterministic-oracle proof (oracle kind, calibrated
                — never 1.0 — confidence, and the re-runnable certificate digest) or
                labels the finding a LEAD.
  * REMEDIATION impact × effort ordering over proven findings (see ``priority``),
                with leads listed separately and never inserted into the fix order.

The renderers mirror ``framework/templates/report-*.md`` and reuse the same grading
authority as ``agents/reporter_agent.py`` (``report.grounding``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from .grounding import GRADE_DEMOTED, GradedFinding, grade_findings
from .priority import SEVERITY_RANK, effort_size, prioritize, priority_score

_SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")

# Class-level remediation guidance, matched by substring (first hit wins). This is
# generic, well-known guidance — not a fabricated finding-specific claim — so it is
# honest to render deterministically. Default guidance covers the unmatched case.
_REMEDIATION_RULES: tuple[tuple[tuple[str, ...], str], ...] = (
    (("boolean_sqli", "sqli", "sql_injection"),
     "Use parameterised queries / prepared statements for every database call; never "
     "interpolate user input into SQL. Add a positive-input allowlist where feasible."),
    (("rce", "command_injection", "os_command"),
     "Remove the shell/eval sink; if an external command is unavoidable, use an argument "
     "vector (no shell) with a strict allowlist of commands and arguments."),
    (("ssti", "template_injection", "evaluation"),
     "Never render user input as a template; use a logic-less/sandboxed template engine "
     "and pass user data strictly as escaped context values."),
    (("reflected_xss", "stored_xss", "xss", "reflection_context", "dom_execution"),
     "Context-aware output-encode all user-influenced data at render time and enable the "
     "template engine's auto-escaping; add a restrictive Content-Security-Policy."),
    (("idor", "bola", "insecure_direct", "broken_object"),
     "Enforce per-object authorization on every request (check the caller may access "
     "the referenced object); never rely on unguessable identifiers."),
    (("bfla", "broken_function", "authorization", "authz"),
     "Centralise function-level authorization in one policy layer that every controller "
     "passes through; deny by default."),
    (("auth_bypass", "authentication_bypass"),
     "Fix the authentication decision so it fails closed; verify the session/token on every "
     "protected route and re-check on privilege changes."),
    (("ssrf",),
     "Validate and allowlist outbound destinations; block link-local/metadata ranges and "
     "resolve-then-connect to prevent DNS-rebinding."),
    (("path_traversal", "lfi", "rfi"),
     "Canonicalise and confine file paths to an allowlisted base directory; reject any path "
     "that escapes it after normalisation."),
    (("xxe",),
     "Disable external-entity and DTD processing in the XML parser."),
    (("signature", "missing_signature"),
     "Verify the provider signature (HMAC/asymmetric) on every inbound webhook/callback "
     "before acting on it; reject unsigned or mismatched requests."),
    (("rate_limit", "rate-limit"),
     "Apply per-account and per-IP rate limiting / lockout on the affected endpoint."),
    (("mass_assignment", "mass-assignment"),
     "Bind only an explicit allowlist of fields from the request to the model."),
    (("open_redirect", "open-redirect"),
     "Allowlist redirect targets to same-origin paths; never redirect to a raw user-supplied URL."),
    (("cors",),
     "Reflect only allowlisted origins; never combine a wildcard/reflected origin with credentials."),
    (("weak_tls", "tls_weakness", "weak_cipher"),
     "Disable the weak protocol/cipher and require modern TLS (1.2+) with strong suites."),
    (("header", "hsts", "csp", "cookie", "clickjack", "cache_control"),
     "Set the missing security header / cookie attribute per current hardening guidance."),
    (("deserial",),
     "Do not deserialise untrusted input into live objects; use a data-only format with a schema."),
    (("supply_chain", "supply-chain", "dependency", "framework_version", "outdated"),
     "Upgrade the affected dependency/framework and pin versions; add SBOM + advisory monitoring."),
)

_DEFAULT_REMEDIATION = (
    "Remediate at the root cause for this bug class and add a regression test that "
    "re-runs this finding's proof; re-verify with `python3 -m framework.v2 verify`."
)


def _remediation_for(bug_class: str) -> str:
    b = (bug_class or "").strip().lower()
    if b:
        for keys, text in _REMEDIATION_RULES:
            if any(k in b for k in keys):
                return text
    return _DEFAULT_REMEDIATION


@dataclass
class ReportMeta:
    """Engagement metadata for the report headers. Everything is optional so a report
    renders from findings alone. ``generated_at`` is the ONLY non-deterministic input;
    left ``None`` (default) no timestamp is emitted and the render is reproducible."""

    target: str = "engagement"
    window_start: str | None = None
    window_end: str | None = None
    status: str = "Draft"
    generated_at: str | None = None
    extra_surfaces: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# shared helpers
# ---------------------------------------------------------------------------


def _by_severity(graded: Iterable[GradedFinding]) -> list[GradedFinding]:
    """Deterministic display order: severity rank, then finding slug."""
    return sorted(
        graded,
        key=lambda g: (SEVERITY_RANK.get(g.finding.severity, 5), g.finding.finding_slug),
    )


def _severity_counts(graded: Iterable[GradedFinding]) -> dict[str, int]:
    counts = {s: 0 for s in _SEVERITIES}
    for g in graded:
        counts[g.finding.severity] = counts.get(g.finding.severity, 0) + 1
    return counts


def _plain_impact(g: GradedFinding) -> str:
    """The plain-language impact line for a finding: its impact statement if present,
    else its summary."""
    f = g.finding
    text = (f.impact or "").strip() or (f.summary or "").strip()
    return text or "_(impact unspecified)_"


def _grounding_line(facts: list[GradedFinding], leads: list[GradedFinding]) -> str:
    demoted = sum(1 for g in leads if g.grade == GRADE_DEMOTED)
    seg = f"**{len(facts)}** oracle-confirmed fact(s)"
    if leads:
        seg += f" · **{len(leads)}** unconfirmed lead(s)"
        if demoted:
            seg += f" (of which **{demoted}** recorded a proof that failed re-verification)"
    return seg + "."


def _split(graded: list[GradedFinding]) -> tuple[list[GradedFinding], list[GradedFinding]]:
    facts = [g for g in graded if g.is_fact]
    leads = [g for g in graded if g.is_lead]
    return facts, leads


def _meta_header(meta: ReportMeta) -> list[str]:
    lines = [f"**Target:** `{meta.target}`"]
    if meta.window_start or meta.window_end:
        lines.append(
            f"**Engagement window:** {meta.window_start or '?'} — {meta.window_end or '?'}"
        )
    lines.append(f"**Status:** {meta.status}")
    if meta.generated_at:
        lines.append(f"**Generated:** {meta.generated_at}")
    return lines


# ---------------------------------------------------------------------------
# 1. EXECUTIVE — plain-language, business framing, facts-first
# ---------------------------------------------------------------------------


def render_executive(graded: list[GradedFinding], meta: ReportMeta) -> str:
    facts, leads = _split(graded)
    counts = _severity_counts(facts)
    L: list[str] = [f"# Security Assessment — Executive Summary — `{meta.target}`", ""]
    L += _meta_header(meta)
    L += [
        "",
        "> Plain-language summary for business owners, partners, and non-technical",
        "> reviewers. Every item under **What we found** is a PROVEN fact — an attacker",
        "> action a deterministic oracle confirmed. Unproven leads are listed separately.",
        "",
        _grounding_line(facts, leads),
        "",
        "## At a glance",
        "",
        "Confirmed findings by severity:",
        "",
        "| Severity | Confirmed |",
        "|----------|----------:|",
    ]
    for s in _SEVERITIES:
        L.append(f"| {s} | {counts[s]} |")
    L += ["", "## What we found", ""]
    if facts:
        L.append("Confirmed issues, worst first — each is a proven attacker capability:")
        L.append("")
        for g in _by_severity(facts):
            f = g.finding
            L.append(
                f"- **{f.title}.** {_plain_impact(g)} "
                f"_(Confirmed `{f.severity}` — oracle `{g.oracle_kind or 'deterministic'}`.)_"
            )
    else:
        L.append("_No findings were confirmed by a deterministic oracle in this engagement._")
    L += ["", "## Leads to verify (not confirmed)", ""]
    if leads:
        L.append(
            "The following were flagged by reasoning but are **not** confirmed facts. "
            "They are leads to verify, not statements of what an attacker can do:"
        )
        L.append("")
        for g in _by_severity(leads):
            f = g.finding
            tag = "recorded a proof that failed re-verification" if g.grade == GRADE_DEMOTED \
                else "no deterministic proof"
            L.append(f"- _{f.title}_ — candidate `{f.severity}` ({tag}). Verify before relying on it.")
    else:
        L.append("_None._")
    L += [
        "",
        "## Basis for these statements",
        "",
        "Every confirmed finding above was proven by re-executing its retained evidence "
        "through a deterministic oracle at report-generation time — not asserted from a "
        "stored flag. Each carries a re-runnable certificate (see the technical report), so "
        "any reviewer can reproduce the proof offline with "
        "`python3 -m framework.v2 verify`. Leads carry no such proof and are labelled as such.",
        "",
    ]
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------------------
# 2. TECHNICAL — per-finding PoC + remediation, proof shown or lead labelled
# ---------------------------------------------------------------------------


def render_technical(graded: list[GradedFinding], meta: ReportMeta) -> str:
    facts, leads = _split(graded)
    ordered = _by_severity(graded)
    counts_fact = _severity_counts(facts)
    counts_lead = _severity_counts(leads)
    L: list[str] = [f"# Technical Report — `{meta.target}`", ""]
    L += _meta_header(meta)
    L += [
        "**Audience:** engineering team.",
        "",
        _grounding_line(facts, leads),
        "",
        "Grounding is per-finding and explicit:",
        "- A **FACT** was confirmed by a deterministic oracle whose retained proof re-fired "
        "at report time; it carries a re-runnable certificate reference.",
        "- A **LEAD** has no re-firing deterministic proof (LLM-advisory, or a recorded "
        "oracle proof that failed re-verification). It is NOT a confirmed fact.",
        "",
        "## Findings overview",
        "",
        "| Slug | Title | Severity | Grounding | Fix effort |",
        "|------|-------|----------|-----------|-----------|",
    ]
    for g in ordered:
        f = g.finding
        grounding = "FACT" if g.is_fact else ("LEAD (demoted)" if g.grade == GRADE_DEMOTED else "LEAD")
        L.append(
            f"| `{f.finding_slug}` | {f.title} | {f.severity} | {grounding} | "
            f"{effort_size(f.bug_class)} |"
        )
    L += ["", "### Severity distribution (confirmed facts)", "", "```"]
    for s in _SEVERITIES:
        L.append(f"{s:<9}: {counts_fact[s]}")
    L += ["```", "", "### Severity distribution (leads)", "", "```"]
    for s in _SEVERITIES:
        L.append(f"{s:<9}: {counts_lead[s]}")
    L += ["```", "", "## Findings detail", ""]

    for g in ordered:
        f = g.finding
        L += [
            f"### {f.finding_slug} — {f.title}",
            "",
            f"**Severity:** {f.severity}  ",
            f"**Bug class:** `{f.bug_class}`  ",
            f"**Surface:** `{f.surface}`  ",
            f"**Derived from hypothesis:** `{f.derived_from_hypothesis or '(none)'}`  ",
        ]
        if g.event_id is not None:
            L.append(f"**Blackboard event id:** {g.event_id}  ")
        L += ["", "#### Summary", "", f.summary or "_(no summary)_", "",
              "#### Impact", "", f.impact or "_(impact unspecified)_", ""]

        # ---- verification block: proof shown, or lead labelled ----
        if g.is_fact:
            conf = f"{g.confidence:.3f}" if g.confidence is not None else "n/a"
            L += [
                "#### Verification (deterministic oracle) — PROVEN FACT",
                "",
                f"**Confirmed by oracle:** `{g.oracle_kind or 'unknown'}`  ",
                f"**Calibrated confidence:** {conf}  ",
            ]
            if g.certificate_digest:
                L += [
                    f"**Certificate reference:** `sha256:{g.certificate_digest}`  ",
                    "",
                    "This finding's retained evidence re-fired its oracle at report time. "
                    "Reproduce the proof offline with `python3 -m framework.v2 verify`.",
                ]
            else:
                L.append("")
            if f.oracle_rationale:
                L += ["", f.oracle_rationale]
            L.append("")
        elif g.grade == GRADE_DEMOTED:
            L += [
                "#### Verification (unverified at report time) — LEAD",
                "",
                "_Recorded as oracle-confirmed, but its retained proof did NOT re-verify "
                f"when this report was generated ({g.reason}). Shown as a lead, NOT a "
                "confirmed fact — investigate why the evidence no longer reproduces._",
                "",
            ]
        else:
            L += [
                "#### Verification — LEAD (unconfirmed)",
                "",
                f"_{g.reason}. A lead to verify, NOT a confirmed fact._",
                "",
            ]

        # ---- remediation ----
        L += ["#### Recommended remediation (class-level guidance)", "",
              _remediation_for(f.bug_class), ""]
        if f.cvss_vector:
            L.append(f"**CVSS 3.1 vector:** `{f.cvss_vector}`  ")
        if f.cvss_base is not None:
            L.append(f"**CVSS base score:** {f.cvss_base}  ")
        L += ["", "---", ""]

    L += [
        "## Notes",
        "",
        "This report is generated deterministically from the confirmed-findings set and "
        "each finding's re-executed proof. Facts are proven; leads are labelled. Remediation "
        "text is class-level guidance, not finding-specific instruction.",
        "",
    ]
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------------------
# 3. REMEDIATION — impact × effort ordering over proven findings
# ---------------------------------------------------------------------------


def render_remediation(graded: list[GradedFinding], meta: ReportMeta) -> str:
    facts, leads = _split(graded)
    rows = prioritize(graded)  # proven facts only, ordered by impact × effort
    L: list[str] = [f"# Remediation Roadmap — `{meta.target}`", ""]
    L += _meta_header(meta)
    L += [
        "**Audience:** tech lead, engineering manager.",
        "",
        "## How to read this",
        "",
        "Proven findings are ordered by a deterministic **priority score = impact ÷ effort**, "
        "so high-impact / low-effort fixes (quick wins) come first.",
        "- **Impact** is the business weight of the (context-adjusted) severity: "
        "Critical=5, High=4, Medium=3, Low=2, Info=1.",
        "- **Effort** is a class-level fix estimate: S=1 (hours), M=2 (days), L=3 (weeks), "
        "XL=4 (quarter+).",
        "",
        _grounding_line(facts, leads),
        "",
        "## Prioritised order (proven findings)",
        "",
    ]
    if rows:
        L += [
            "| Rank | Slug | Title | Severity | Effort | Priority (impact÷effort) | Tier |",
            "|-----:|------|-------|----------|--------|-------------------------:|------|",
        ]
        for r in rows:
            f = r.graded.finding
            L.append(
                f"| {r.rank} | `{f.finding_slug}` | {f.title} | {f.severity} | "
                f"{r.effort} | {r.score:.4f} | {r.tier} |"
            )
        L += ["", "### Per-finding fix", ""]
        for r in rows:
            f = r.graded.finding
            L += [
                f"{r.rank}. **`{f.finding_slug}` — {f.title}** "
                f"({f.severity}, effort {r.effort}, priority {r.score:.4f})  ",
                f"   {_remediation_for(f.bug_class)}",
            ]
        # quick wins = the top-tier (severe + small effort) subset, already in order
        quick = [r for r in rows if r.tier == 0]
        L += ["", "## Quick wins (high impact, low effort)", ""]
        if quick:
            for r in quick:
                f = r.graded.finding
                L.append(f"- **`{f.finding_slug}` — {f.title}** ({f.severity}, effort {r.effort}).")
        else:
            L.append("_No severe finding has a small-effort fix; see the prioritised order above._")
    else:
        L.append("_No confirmed findings to prioritise._")

    L += ["", "## Unconfirmed leads — verify before prioritising", ""]
    if leads:
        L.append(
            "These are NOT in the prioritised order above because they are unproven. "
            "Verify each before scheduling remediation effort:"
        )
        L.append("")
        for g in _by_severity(leads):
            f = g.finding
            tag = "recorded a proof that failed re-verification" if g.grade == GRADE_DEMOTED \
                else "no deterministic proof"
            L.append(f"- _`{f.finding_slug}` — {f.title}_ (candidate {f.severity}; {tag}).")
    else:
        L.append("_None._")

    # deterministic tier summary
    L += ["", "## Summary", "", "| Tier | Proven findings |", "|------|----------------:|"]
    for t in (0, 1, 2, 3):
        L.append(f"| {t} | {sum(1 for r in rows if r.tier == t)} |")
    L += [f"| **Total** | **{len(rows)}** |", ""]
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------------------
# bundle
# ---------------------------------------------------------------------------


def generate_reports(
    findings: Iterable,
    meta: ReportMeta | None = None,
) -> dict[str, str]:
    """Grade the findings ONCE (so all three documents agree) and render the bundle.

    ``findings`` may be findings or ``(finding, event_id)`` pairs (blackboard rows or
    JSON dicts). Returns ``{"executive", "technical", "remediation-roadmap"}`` → Markdown.
    Deterministic given ``meta`` (with ``generated_at`` unset)."""
    meta = meta or ReportMeta()
    graded = grade_findings(findings)
    return {
        "executive": render_executive(graded, meta),
        "technical": render_technical(graded, meta),
        "remediation-roadmap": render_remediation(graded, meta),
    }
