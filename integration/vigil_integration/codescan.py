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


def _rule_is_clean(rule_id: str) -> bool:
    """A rule_id safe to embed VERBATIM in a ref (readable) — no ``~`` delimiter and argv-safe on its own.
    Built-in DAA-* ids are clean; a hostile external id (semgrep/gitleaks check_id with a ``~``, space, or
    leading dash) is NOT, and is b64-encoded instead so make_ref/parse_ref stay exact inverses AND argv-safe."""
    return bool(rule_id) and "~" not in rule_id and not rule_id.startswith("-") \
        and not any(c in rule_id for c in "/\\ \t\r\n") and ".." not in rule_id


def make_ref(rule_id: str, rel_path: str, line: int) -> str:
    """A stable, argv-safe, RECOVERABLE finding ref. Clean (built-in) rule ids stay readable:
    ``<rule_id>~<b64 path>~L<line>``. A dirty external rule id (contains ``~``/space/leading-dash) is encoded
    whole: ``Z~<b64 rule_id>~<b64 path>~L<line>`` — still fully recoverable and argv-safe. Falls back to a
    non-recoverable hash form only when the encoded ref would exceed the lookup bound (verify then degrades to
    'does this rule still fire anywhere', which is conservative — never a false 'fixed')."""
    if _rule_is_clean(rule_id):
        ref = f"{rule_id}~{_b64(rel_path)}~L{int(line)}"
    else:
        ref = f"Z~{_b64(rule_id)}~{_b64(rel_path)}~L{int(line)}"
    if len(ref) <= 190 and _ref_is_argv_safe(ref):
        return ref
    from hashlib import sha256
    return f"Z~{_b64(rule_id)}~H{sha256(f'{rel_path}:{line}'.encode()).hexdigest()[:16]}"


def parse_ref(ref: str) -> tuple[str, str | None, int | None]:
    """Recover ``(rule_id, rel_path|None, line|None)`` from a ref made by :func:`make_ref` — the exact inverse
    over every id make_ref accepts. A hashed-fallback ref (``~H...``) yields ``(rule_id, None, None)`` so verify
    falls back to rule-anywhere; a malformed ref yields ``("" , None, None)`` (verify then refuses)."""
    r = str(ref or "")
    if "~" not in r:
        return (r, None, None)
    # b64-encoded-rule form: Z~<b64 rule_id>~(<b64 path>~L<line> | H<hash>)
    if r.startswith("Z~"):
        rest = r[2:]
        enc_rule, _, tail = rest.partition("~")
        try:
            rid = _unb64(enc_rule)
        except Exception:  # noqa: BLE001
            return ("", None, None)
        if tail.startswith("H") or "~" not in tail:
            return (rid, None, None)   # hashed fallback → rule-anywhere
        enc_path, _, ln = tail.partition("~")
        try:
            return (rid, _unb64(enc_path), int(ln[1:]) if ln.startswith("L") else None)
        except Exception:  # noqa: BLE001
            return (rid, None, None)
    # verbatim clean-rule form: <rule_id>~<b64 path>~L<line>  (rsplit so a rule_id containing "~" — which
    # _rule_is_clean forbids, but be robust — is never truncated).
    head, _, last = r.rpartition("~")
    if last.startswith("H"):
        return (head, None, None)      # <rule_id>~H<hash> → rule-anywhere
    rule_id, _, enc = head.rpartition("~")
    if not rule_id:
        return (head, None, None)
    try:
        return (rule_id, _unb64(enc), int(last[1:]) if last.startswith("L") else None)
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
    # MONOTONIC seq: a re-scan (or a scan that reuses a slug) appends a NEW snapshot that SUPERSEDES the prior
    # by recency — finding_from_spine reads global-latest by (seq, hash), so without this every scan wrote
    # seq=1 and the winner was decided by hash order, letting a stale/foreign scan shadow this one. head_seq
    # is verifier-gated and total (0 on a fresh/empty spine).
    try:
        _seq = int(spine.head_seq()) + 1
    except Exception:  # noqa: BLE001 — a fresh/unreadable spine starts the clock at 1
        _seq = 1
    spine.write_state(state, seq=_seq, engagement=None)

    counts: dict[str, int] = {}
    for fo in findings_out:
        k = str(fo["severity"]).lower()
        counts[k] = counts.get(k, 0) + 1
    # every DAA finding is a re-runnable static FACT, so facts == total, leads == 0 (the Findings screen's
    # summary tile reads this shape).
    return {"root": str(src), "slug": slug, "spine": str(spine_path), "engine": "codescan-daa",
            "findings": findings_out, "counts": counts, "total": len(findings_out),
            "summary": {"findings": len(findings_out), "facts": len(findings_out), "leads": 0}}


class CodeFixVerdict:
    """A fix-verification verdict for a CODE finding, shaped for ``autopatch.verify_patch``'s reader
    (``.fired`` True = the vulnerable pattern STILL matches; False = it no longer fires). It carries NO signed
    ``cert`` — the DAA re-run is deterministic + re-runnable, so a silent verdict earns the honest
    ``verified-no-pr`` status, never the signed ``remediated`` (which stays reserved for the live-oracle +
    m-of-n PR path)."""

    __slots__ = ("fired", "detail")

    def __init__(self, fired: bool, detail: dict[str, Any]) -> None:
        self.fired = bool(fired)
        self.detail = detail


def build_code_fix_oracle(finding_ref: str, *, max_files: int = 5000) -> Any:
    """Build the deep-fix verify oracle for a code finding: ``oracle(request, patched_build)`` re-runs the DAA
    rule over the PATCHED clone (``patched_build`` = the clone workdir / its ``build_ref``) and reports whether
    the finding still fires. Deterministic, offline, non-destructive — the code-finding analogue of the HTTP
    re-drive oracle, and the sole thing that turns a built patch into ``verified-no-pr``."""
    ref = str(finding_ref or "")

    def _oracle(_request: Any, patched_build: Any) -> CodeFixVerdict:
        root = str(getattr(patched_build, "build_ref", "") or patched_build or "")
        res = verify_finding_cleared(root=root, ref=ref, max_files=max_files)
        return CodeFixVerdict(fired=not bool(res.get("cleared")), detail=res)

    return _oracle


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
    # SOUNDNESS: `cleared` requires the rule to fire NOWHERE in the tree for this rule_id — NOT merely at the
    # originally-recorded path. Narrowing to the exact path would report `cleared` when the vulnerable code was
    # simply MOVED/renamed (the rule still fires at a new path) — a false 'fixed', the worst outcome. Checking
    # rule-anywhere is strictly conservative: it never claims fixed while the pattern remains, and when the rule
    # has several instances it stays not-cleared until they are ALL gone. `moved` flags exactly the
    # recorded-path-gone-but-fires-elsewhere case so the operator is not misled.
    hits = [f for f in daa if f.rule_id == rule_id]
    at_recorded_path = path is not None and any(f.path == path for f in hits)
    return {"ref": ref, "rule_id": rule_id, "path": path,
            "cleared": len(hits) == 0,
            "moved": bool(hits) and path is not None and not at_recorded_path,
            "still_fires_at": [f"{f.path}:{f.line}" for f in hits]}
