"""live.ci_annotate — the FACT/LEAD-typed PR annotation layer for the W4 CI Action.

Turns a ``run_codescan`` result's findings into GitHub Actions workflow-command annotations
(``::error`` / ``::warning file=…,line=…::…``) and a job-summary markdown, TYPED by the HONEST oracle
verdict: a finding is a FACT only when the single-region ``STATIC_RULE`` oracle actually CONFIRMED it
(``static_oracle_confirmed is True``) — never merely because a DAA regex matched. A DAA match the oracle
did not confirm (a LEAD-only class, a non-Python file, or an oracle refusal) is surfaced as a LEAD (a
``::warning``), never claimed oracle-verified.

This keys off ``static_oracle_confirmed`` — NOT the DAA-tier ``verified_by_oracle`` / ``grounding`` fields,
which codescan deliberately sets for every DAA match — so CI annotations report honestly WITHOUT any change
to codescan's labeling. Pure stdlib; attacker-influenceable strings (title/path/class come from the scanned
PR's own code) are bounded + escaped per the GitHub workflow-command spec before splicing. FATAL-2:
framework-free, offense-side, NO network — the caller (the ``ci-scan`` CLI) prints these lines / writes the
summary file.
"""

from __future__ import annotations

from typing import Any

_MAX = 400  # bound every attacker-influenceable field before it is spliced into an annotation / markdown


def _bound(value: Any, limit: int = _MAX) -> str:
    """A length-bounded, control-char-free string (finding fields may come from the scanned PR's own code)."""
    s = str(value if value is not None else "")
    for ch in ("\x00", "\n", "\r"):
        if ch in s:
            s = s.replace(ch, " ")
    return s[:limit]


def is_fact(finding: "dict[str, Any]") -> bool:
    """A finding is a FACT iff the deterministic single-region oracle CONFIRMED it (``static_oracle_confirmed
    is True``) — never because a DAA regex merely matched. Honest typing that needs no change to codescan."""
    return finding.get("static_oracle_confirmed") is True


def _loc(finding: "dict[str, Any]") -> "tuple[str, int]":
    """``(path, line)`` from a finding's ``location``/``surface`` (``"path:line"``); line defaults to 1."""
    loc = _bound(finding.get("location") or finding.get("surface") or "", 400)
    path, sep, line = loc.rpartition(":")
    if not sep:
        return (loc or "", 1)
    try:
        return (path, max(1, int(line)))
    except (TypeError, ValueError):
        return (loc, 1)


def _esc_data(s: str) -> str:
    """Escape a GitHub workflow-command MESSAGE (the part after ``::``) per the documented spec."""
    return s.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _esc_prop(s: str) -> str:
    """Escape a workflow-command PROPERTY value (file/line/title) — data escaping plus ``,`` and ``:``."""
    return _esc_data(s).replace(",", "%2C").replace(":", "%3A")


def annotation_lines(findings: "list[dict[str, Any]] | None") -> "list[str]":
    """One GitHub Actions workflow command per finding — ``::error`` for an oracle-confirmed FACT,
    ``::warning`` for a LEAD. ``file``/``line``/``title`` are escaped properties; the message is escaped
    data. Deterministic (input order preserved)."""
    out: list[str] = []
    for f in findings or []:
        path, line = _loc(f)
        title = _bound(f.get("title") or f.get("bug_class") or "finding", 200)
        bug = _bound(f.get("bug_class") or "", 80)
        sev = _bound(f.get("severity") or "", 32)
        label = "FACT" if is_fact(f) else "LEAD"
        cmd = "error" if is_fact(f) else "warning"
        msg = f"[VIGIL {label}] {bug} ({sev}): {title}" if bug else f"[VIGIL {label}] {title}"
        out.append(
            f"::{cmd} file={_esc_prop(path)},line={line},"
            f"title={_esc_prop('VIGIL ' + label)}::{_esc_data(msg)}")
    return out


def _md(value: Any) -> str:
    """Bound + neutralize markdown table / code-span metacharacters in attacker-influenceable text."""
    return _bound(value, 300).replace("|", "\\|").replace("`", "'")


def counts(findings: "list[dict[str, Any]] | None") -> "dict[str, Any]":
    """``{facts, leads, total, by_severity:{<sev-lower>: n}}`` — the summary the CLI uses for a fail
    threshold and the job summary. Severity is lower-cased so a ``--fail-on`` compare is case-insensitive."""
    fs = list(findings or [])
    by_sev: dict[str, int] = {}
    for f in fs:
        sev = _bound(f.get("severity") or "", 32).strip().lower() or "unknown"
        by_sev[sev] = by_sev.get(sev, 0) + 1
    facts = sum(1 for f in fs if is_fact(f))
    return {"facts": facts, "leads": len(fs) - facts, "total": len(fs), "by_severity": by_sev}


def summary_markdown(findings: "list[dict[str, Any]] | None", *, repo: str = "", commit: str = "") -> str:
    """A GitHub job-summary markdown: a header line, the FACT/LEAD counts, then a typed table per tier."""
    fs = list(findings or [])
    facts = [f for f in fs if is_fact(f)]
    leads = [f for f in fs if not is_fact(f)]
    lines = ["## VIGIL code security scan", ""]
    hdr = []
    if repo:
        hdr.append(f"**repo** `{_md(repo)}`")
    if commit:
        hdr.append(f"**commit** `{_md(commit)}`")
    if hdr:
        lines += ["  ·  ".join(hdr), ""]
    lines += [f"**{len(facts)} oracle-confirmed FACT(s)**, **{len(leads)} LEAD(s)**.", ""]
    for label, group in (("Oracle-confirmed FACTs", facts), ("Leads (unconfirmed — review)", leads)):
        if not group:
            continue
        lines += [f"### {label}", "", "| severity | class | location | finding |", "|---|---|---|---|"]
        for f in group:
            path, line = _loc(f)
            lines.append(
                f"| {_md(f.get('severity'))} | {_md(f.get('bug_class'))} | "
                f"`{_md(path)}:{line}` | {_md(f.get('title'))} |")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


__all__ = ["is_fact", "annotation_lines", "summary_markdown", "counts"]
