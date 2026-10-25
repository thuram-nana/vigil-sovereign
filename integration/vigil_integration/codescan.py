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


# INV2 — the CLOSED-vocabulary STATIC_RULE rule_id a DAA finding maps to, for the FACT-capable tiers ONLY.
# A DAA regex match only says WHERE to look; the pure STATIC_RULE oracle (analysis.static_facts) re-parses the
# RETAINED source region and RE-DERIVES the code property itself — it NEVER trusts the DAA rule_id or CWE. Only
# mappings the single-region offline oracle can SOUNDLY confirm are listed: weak hash/cipher
# (``broken-crypto-invocation``). TLS verify-off maps to ``insecure-flag-literal`` but the oracle fires only
# when import provenance is present in the retained region (fail-closed to a LEAD otherwise). LEAD-only DAA
# classes — and ``debug=True`` (DAA-DEBUG-TRUE), which no static-FACT tier covers — are deliberately ABSENT:
# they can never mint a static FACT here, matching the LEAD-only guards in verify/oracles.py.
_STATIC_RULE_FOR_DAA: dict[str, str] = {
    "DAA-WEAK-HASH": "broken-crypto-invocation",
    "DAA-TLS-VERIFY-OFF": "insecure-flag-literal",
}


def _static_rule_for(af: Any) -> str:
    """The CLOSED-vocabulary STATIC_RULE rule_id for a DAA finding on a PYTHON source file, or ``""`` when the
    finding is not FACT-capable through the single-region offline oracle (a non-Python file, or a DAA class with
    no sound static-FACT tier). ``""`` ⇒ the finding stays a DAA fact exactly as before and is NEVER promoted to
    an oracle-re-verifiable static FACT."""
    path = str(getattr(af, "path", "") or "")
    if not path.endswith(".py"):
        return ""      # the STATIC_RULE oracle re-parses Python only; any other language REFUSES (a LEAD)
    return _STATIC_RULE_FOR_DAA.get(str(getattr(af, "rule_id", "") or ""), "")


def _retain_source_region(root: str, af: Any) -> str:
    """The RETAINED source region the STATIC_RULE oracle re-parses OFFLINE to re-derive the code property: the
    module's top-level import statements (the crypto/HTTP provenance the oracle RESOLVES) plus the top-level
    statement enclosing the finding line — both at column 0, so the concatenation re-parses as a module. Falls
    back to the whole file (unparseable module), then the one-line snippet (unreadable file); the oracle then
    re-parses whatever is retained and REFUSES → a LEAD, never a crash. The retained bytes travel verbatim into
    the finding, so a confirmed static FACT re-verifies OFFLINE and a tamper that removes the property no longer
    re-fires."""
    import ast as _ast
    snippet = str(getattr(af, "snippet", "") or "")
    try:
        text = (Path(root) / str(af.path)).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return snippet
    try:
        tree = _ast.parse(text)
    except SyntaxError:
        return text                         # whole file; the oracle re-parses it (or REFUSES → a LEAD)
    try:
        line = int(af.line)
    except (TypeError, ValueError):
        line = 0
    imports: list[str] = []
    enclosing = ""
    for node in tree.body:                  # TOP-LEVEL statements only ⇒ each source segment starts at column 0
        if isinstance(node, (_ast.Import, _ast.ImportFrom)):
            seg = _ast.get_source_segment(text, node)
            if seg:
                imports.append(seg)
            continue
        end = getattr(node, "end_lineno", None) or getattr(node, "lineno", 0)
        if not enclosing and getattr(node, "lineno", 0) <= line <= end:
            enclosing = _ast.get_source_segment(text, node) or ""
    region = "\n".join([*imports, enclosing]) if enclosing else "\n".join(imports)
    return region or text


def run_codescan(*, root: str, slug: str, base_dir: str, max_files: int = 5000,
                 include_paths: "set[str] | None" = None) -> dict[str, Any]:
    """Scan ``root`` with DAA and write each finding into the signed ``<base_dir>/<slug>.spine`` as a
    re-runnable static fact. Returns ``{root, slug, spine, findings:[...], counts}`` — findings carry the
    argv-safe ``ref`` (== the spine record ref), ``bug_class``, ``cwe``, severity, file/line and message.

    ``include_paths`` (repo-root-relative POSIX paths, matching ``finding.path``) DIFF-SCOPES the scan: when
    given, only findings in those files are kept — the PR-bot passes a PR's changed-files set so the review
    is scoped to the diff. The analyzers still run over the whole tree (external tools scan wholesale), but
    the recorded facts are filtered to the changed files, yielding ONE spine snapshot scoped to the PR. None
    (the default) keeps every finding (a full scan), so existing callers are byte-identical.

    Fail-closed: an unreadable root or a spine-write failure raises (the caller surfaces it). NEVER fabricates
    a finding — only DAA matches over the real source are written, each as ``status="fact"`` (a legitimate,
    re-runnable static fact) with a content-digest ``evidence_ref``."""
    from vigil_core import digest_payload
    from vigil_core.vault import Vault

    from framework.v2.analysis.static_facts import confirm_code_region, static_fact_finding

    from .agent.state import AgentState, Finding
    from .live.spine_identity import DEFAULT_SPINE_KEY_FILE, load_or_create_spine_keypair
    from .live.spine_vigilcore import VigilCoreSpine

    src = Path(root).expanduser()
    if not src.exists():
        raise FileNotFoundError(f"codescan root does not exist: {root}")

    daa = _daa_findings(str(src), max_files=max_files)
    if include_paths is not None:   # diff-scope: keep only findings in the PR's changed files
        # FAIL-CLOSED on a namespace mismatch. A non-empty scope that resolves to NO real file under the
        # scan root means the checkout-root and the changed-files (repo-root-relative) namespaces disagree
        # (a tarball checkout's "<owner>-<repo>-<sha>/" prefix, a monorepo subdir, …). Filtering to an empty
        # "clean" result there is a silent false-negative — refuse it LOUDLY instead of reporting clean.
        if include_paths and not any((src / p).is_file() for p in include_paths):
            raise FileNotFoundError(
                f"diff-scope include_paths does not resolve under the scan root {src}: the checkout-root / "
                f"repo-root path namespaces disagree — refusing a silent clean (sample {sorted(include_paths)[:3]})")
        daa = [af for af in daa if getattr(af, "path", None) in include_paths]
    state = AgentState(engagement_slug=slug, target=str(src),
                       objective="local codebase static review (DAA deterministic oracle)")
    findings_out: list[dict[str, Any]] = []
    # INV2 — the oracle-re-verifiable STATIC FACTs. Each carries its RETAINED source region in ``oracle_context``,
    # so ``python3 -m framework.v2 verify <scan.json>`` re-runs the pure STATIC_RULE oracle over the retained
    # bytes (the `active_findings` convention read_reverifiable/reverify_document consume). A DAA match the sound
    # oracle REFUSES (e.g. a hash marked ``usedforsecurity=False``) is NOT added here — it stays a DAA lead.
    static_facts_out: list[dict[str, Any]] = []
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
        fo = {
            "ref": ref, "check_id": ref, "bug_class": bug_class,
            "cwe": [af.cwe] if af.cwe else [],
            "title": af.message, "severity": _cap(af.severity),
            "location": f"{af.path}:{af.line}", "surface": f"{af.path}:{af.line}",
            "grounding": "fact", "verified_by_oracle": True,
            "confirmed_by": f"daa:{af.rule_id}", "oracle_kind": f"daa:{af.rule_id}",
            "evidence": af.snippet, "analyzer": af.analyzer, "re_verifiable": True,
            "kind": "finding", "references": [], "remediation": "",
        }
        findings_out.append(fo)

        # INV2 — SAST bridge: promote a FACT-capable DAA match to an oracle-re-verifiable STATIC FACT. The pure
        # STATIC_RULE oracle re-parses the RETAINED region and re-derives the property itself; it fires (a FACT)
        # or refuses (a LEAD). The DAA rule_id/CWE are NEVER trusted for the verdict — only `path`/`line` point
        # at WHERE to retain. This adds NO oracle/kind (STATIC_RULE is already registered) and does not alter the
        # existing DAA finding above, so the spine/patch path and `make gate` are unchanged.
        static_rule_id = _static_rule_for(af)
        if not static_rule_id:
            continue
        region = _retain_source_region(str(src), af)
        sfact = confirm_code_region(af.path, af.line, region, static_rule_id)
        fo["static_rule_id"] = static_rule_id
        fo["static_oracle_confirmed"] = bool(sfact.confirmed)
        if not sfact.confirmed:
            continue                               # the sound oracle REFUSED the DAA match → a LEAD, never a FACT
        sff = static_fact_finding(sfact, check_id=f"static:{static_rule_id}:{af.path}:{af.line}")
        sff.update({
            "finding_slug": sff["check_id"],
            "kind": "active",                      # read by reverify_document / read_reverifiable
            "grounding": "fact", "re_verifiable": True, "verified_by_oracle": True,
            "oracle_kind": sfact.confirmed_by, "confirmed_by": sfact.confirmed_by,
            "confidence": sfact.confidence,
            "title": af.message, "severity": _cap(af.severity),
            "location": f"{af.path}:{af.line}", "surface": f"{af.path}:{af.line}",
            "cwe": [af.cwe] if af.cwe else [],
            "daa_rule_id": af.rule_id, "daa_ref": ref,
            "evidence": sfact.evidence, "references": [], "remediation": "",
        })
        static_facts_out.append(sff)
        fo["static_fact_ref"] = sff["check_id"]

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
    # summary tile reads this shape). INV2 adds `static_facts` — the subset ALSO confirmed by the pure
    # STATIC_RULE oracle and re-verifiable offline via `python3 -m framework.v2 verify`; `active_findings`
    # exposes them under the standard re-verifiable convention so the scan JSON is directly re-verifiable.
    return {"root": str(src), "slug": slug, "spine": str(spine_path), "engine": "codescan-daa",
            "findings": findings_out, "counts": counts, "total": len(findings_out),
            "static_facts": static_facts_out, "active_findings": static_facts_out,
            "summary": {"findings": len(findings_out), "facts": len(findings_out), "leads": 0,
                        "static_facts": len(static_facts_out)}}


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
    # EVASION GUARD (red-pen/crypto-notary MEDIUM): if the finding's recorded file is GONE from the tree, a
    # rule-fires-nowhere result does NOT prove the pattern was removed — the file may have been renamed to an
    # UNSCANNED extension (e.g. .py -> .txt), moving the vulnerable code out of DAA's view. DAA only scans a
    # fixed extension set, so we cannot see it. Report NOT cleared (path_removed) so a rename can never read as
    # fixed; a legitimate delete lands here too and is honestly surfaced for manual confirmation.
    path_removed = False
    if path is not None and not hits:
        try:
            import os as _os
            path_removed = not _os.path.isfile(_os.path.join(str(root), path))
        except OSError:
            path_removed = True
    cleared = (len(hits) == 0) and not path_removed
    reason = ("" if cleared else
              ("the finding's file is gone from the tree (moved/renamed/deleted) — a re-scan cannot confirm the "
               "pattern was removed vs. hidden in an unscanned file; verify manually" if path_removed else
               "the finding's rule still fires"))
    return {"ref": ref, "rule_id": rule_id, "path": path,
            "cleared": cleared,
            "moved": bool(hits) and path is not None and not at_recorded_path,
            "path_removed": path_removed,
            "reason": reason,
            "still_fires_at": [f"{f.path}:{f.line}" for f in hits]}
