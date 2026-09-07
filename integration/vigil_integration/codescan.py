"""codescan — the deterministic local-codebase scan that grounds a gated fix.

A codebase (source) target has no live HTTP oracle, so its findings are grounded in a DIFFERENT deterministic
oracle: a Deep-Analysis-Arsenal (DAA) static rule that MATCHED real bytes in the operator's own source. That
match is a fact over data the target (the codebase) produced, and it is RE-RUNNABLE — the same rule re-run
over the same file either fires again (still vulnerable) or does not (fixed). This module makes that end-to-end:

  1. ``run_codescan`` runs DAA over ``root`` and writes each confirmed finding into the engagement's OWN signed
     offense spine at ``<base_dir>/<slug>.spine`` — the SAME provenance store ``vigil patch --from-spine`` reads
     — as a ``status="fact"`` record whose ``evidence_ref`` is a content digest of the DAA match (analyzer,
     rule_id, path, line, snippet, cwe). So the existing gated auto-patch machine can drive a code finding with
     no new trust path. It also returns the findings (CWE-tagged) for the console's Findings screen.

  2. ``verify_finding_cleared`` is the FIX-VERIFICATION oracle for a code finding: re-run DAA over ``root`` and
     report whether the finding's rule still fires at its file. Deterministic, offline, non-destructive.

HONESTY: a DAA static-analysis match is a STATIC fact (``source="daa:<rule_id>"``), not a live-exploit oracle
fact — the finding records exactly that. It never claims runtime exploitability; it claims the vulnerable
pattern is present in the source, provably and re-runnably.

Two-env note: this runs in the OFFENSE venv (which imports both ``framework.v2.analysis`` — DAA — and the
``vigil_integration`` spine layer). It is reached only via the ``vigil codescan`` CLI verb, never imported by
the sovereign/console leg (FATAL-2).
"""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Any


def _b64(s: str) -> str:
    """URL-safe, padding-free base64 — argv-safe (``[-_A-Za-z0-9]`` only), and reversible."""
    return base64.urlsafe_b64encode(s.encode("utf-8")).decode("ascii").rstrip("=")


def _unb64(s: str) -> str:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii")).decode("utf-8")


def make_ref(rule_id: str, rel_path: str, line: int) -> str:
    """A stable, argv-safe, RECOVERABLE finding ref: ``<rule_id>~<b64 path>~L<line>``. The path is encoded so
    the fix-verification oracle can re-scan exactly the file the rule fired on. Falls back to a non-recoverable
    ``<rule_id>~H<hash>`` when the encoded ref would exceed the argv/lookup bound (then verify degrades to
    'does this rule still fire anywhere', which is conservative — never a false 'fixed')."""
    ref = f"{rule_id}~{_b64(rel_path)}~L{int(line)}"
    if len(ref) <= 190 and _ref_is_argv_safe(ref):
        return ref
    from hashlib import sha256
    return f"{rule_id}~H{sha256(f'{rel_path}:{line}'.encode()).hexdigest()[:16]}"


def parse_ref(ref: str) -> tuple[str, str | None, int | None]:
    """Recover ``(rule_id, rel_path|None, line|None)`` from a ref made by :func:`make_ref`. A hashed-fallback
    ref (``~H...``) or a malformed ref yields ``(rule_id, None, None)`` so verify falls back to rule-anywhere."""
    parts = str(ref or "").split("~")
    if len(parts) != 3 or not parts[0]:
        return (parts[0] if parts else "", None, None)
    rule_id, enc, ln = parts
    if enc.startswith("H"):
        return (rule_id, None, None)
    try:
        path = _unb64(enc)
        line = int(ln[1:]) if ln.startswith("L") else None
        return (rule_id, path, line)
    except Exception:  # noqa: BLE001 — a bad ref degrades to rule-anywhere, never a crash
        return (rule_id, None, None)


def _ref_is_argv_safe(ref: str) -> bool:
    return bool(ref) and len(ref) <= 200 and not ref.startswith("-") and ".." not in ref \
        and not any(c in ref for c in "/\\ \t\r\n")


def _cap(sev: str) -> str:
    s = str(sev or "").strip().lower()
    return {"critical": "Critical", "high": "High", "medium": "Medium",
            "low": "Low", "info": "Info"}.get(s, "Medium")


def _daa_findings(root: str, max_files: int = 5000) -> list[Any]:
    """Run DAA over ``root`` and return its AnalysisFindings (deterministic; no LLM, no network)."""
    from framework.v2.analysis.models import DEFAULT_EXTENSIONS, AnalysisTarget
    from framework.v2.analysis.orchestrator import run_analysis
    report = run_analysis(AnalysisTarget(root=str(root), extensions=DEFAULT_EXTENSIONS, max_files=max_files))
    return list(report.findings)


def _bug_class(rule_id: str, cwe: str) -> str:
    try:
        from framework.v2.analysis.seed import _RULE_BUG_CLASS
        if rule_id in _RULE_BUG_CLASS:
            return _RULE_BUG_CLASS[rule_id]
    except Exception:  # noqa: BLE001
        pass
    return cwe or "Static Analysis Finding"


def run_codescan(*, root: str, slug: str, base_dir: str, max_files: int = 5000) -> dict[str, Any]:
    """Scan ``root`` with DAA and write each finding into the signed ``<base_dir>/<slug>.spine`` as a
    re-runnable static fact. Returns ``{root, slug, spine, findings:[...], counts}`` — findings carry the
    argv-safe ``ref`` (== the spine record ref), ``bug_class``, ``cwe``, severity, file/line and message.

    Fail-closed: an unreadable root or a spine-write failure raises (the caller surfaces it). NEVER fabricates
    a finding — only DAA matches over the real source are written, each as ``status="fact"`` (a legitimate,
    re-runnable static fact) with a content-digest ``evidence_ref``."""
    from vigil_core import digest_payload
    from vigil_core.vault import Vault

    from .agent.state import AgentState, Finding
    from .live.spine_identity import DEFAULT_SPINE_KEY_FILE, load_or_create_spine_keypair
    from .live.spine_vigilcore import VigilCoreSpine

    src = Path(root).expanduser()
    if not src.exists():
        raise FileNotFoundError(f"codescan root does not exist: {root}")

    daa = _daa_findings(str(src), max_files=max_files)
    state = AgentState(engagement_slug=slug, target=str(src),
                       objective="local codebase static review (DAA deterministic oracle)")
    findings_out: list[dict[str, Any]] = []
    seen_refs: set[str] = set()
    for af in daa:
        ref = make_ref(af.rule_id, af.path, af.line)
        if ref in seen_refs:                       # a rule twice on the same path/line → one fact
            continue
        seen_refs.add(ref)
        evidence = {"analyzer": af.analyzer, "rule_id": af.rule_id, "path": af.path,
                    "line": af.line, "snippet": af.snippet, "cwe": af.cwe}
        evidence_ref = "sha256:" + digest_payload(evidence)
        bug_class = _bug_class(af.rule_id, af.cwe)
        f = Finding(ref=ref, bug_class=bug_class, title=af.message, severity=_cap(af.severity),
                    source=f"daa:{af.rule_id}", target=f"{af.path}:{af.line}")
        state.record_fact(f, evidence_ref=evidence_ref)   # status→fact, requires the signed evidence_ref
        findings_out.append({
            "ref": ref, "check_id": ref, "bug_class": bug_class,
            "cwe": [af.cwe] if af.cwe else [],
            "title": af.message, "severity": _cap(af.severity),
            "location": f"{af.path}:{af.line}", "surface": f"{af.path}:{af.line}",
            "grounding": "fact", "verified_by_oracle": True,
            "confirmed_by": f"daa:{af.rule_id}", "oracle_kind": f"daa:{af.rule_id}",
            "evidence": af.snippet, "analyzer": af.analyzer, "re_verifiable": True,
            "kind": "finding", "references": [], "remediation": "",
        })

    base = Path(base_dir)
    base.mkdir(parents=True, exist_ok=True)
    vault = Vault(base / "vault")
    kp = load_or_create_spine_keypair(path=str(base / DEFAULT_SPINE_KEY_FILE), vault=vault)
    spine_path = base / f"{slug}.spine"
    spine = VigilCoreSpine(kp, str(spine_path))
    spine.write_state(state, seq=1, engagement=None)   # one signed snapshot; finding_from_spine reads global-latest

    counts: dict[str, int] = {}
    for fo in findings_out:
        k = str(fo["severity"]).lower()
        counts[k] = counts.get(k, 0) + 1
    # every DAA finding is a re-runnable static FACT, so facts == total, leads == 0 (the Findings screen's
    # summary tile reads this shape).
    return {"root": str(src), "slug": slug, "spine": str(spine_path), "engine": "codescan-daa",
            "findings": findings_out, "counts": counts, "total": len(findings_out),
            "summary": {"findings": len(findings_out), "facts": len(findings_out), "leads": 0}}


def verify_finding_cleared(*, root: str, ref: str, max_files: int = 5000) -> dict[str, Any]:
    """The fix-verification oracle for a code finding: re-run DAA over ``root`` and report whether the finding
    still fires. ``cleared`` is True iff the finding's rule no longer matches at its file (when the ref carries a
    recoverable path) or anywhere (a hashed-fallback ref). Deterministic, offline, non-destructive.

    Returns ``{ref, rule_id, path, cleared, still_fires_at:[...] }``. A root that cannot be scanned yields
    ``cleared=False`` with a reason — never a false 'fixed'."""
    rule_id, path, _line = parse_ref(ref)
    if not rule_id:
        return {"ref": ref, "cleared": False, "reason": "unparseable finding ref"}
    try:
        daa = _daa_findings(str(root), max_files=max_files)
    except Exception as exc:  # noqa: BLE001 — cannot re-scan ⇒ cannot claim cleared (fail-closed to NOT-fixed)
        return {"ref": ref, "rule_id": rule_id, "path": path, "cleared": False,
                "reason": f"re-scan failed: {type(exc).__name__}: {exc}"}
    hits = [f for f in daa if f.rule_id == rule_id and (path is None or f.path == path)]
    return {"ref": ref, "rule_id": rule_id, "path": path,
            "cleared": len(hits) == 0,
            "still_fires_at": [f"{f.path}:{f.line}" for f in hits]}
