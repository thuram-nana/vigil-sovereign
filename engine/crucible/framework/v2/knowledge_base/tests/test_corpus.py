"""
Tests for the per-ORG knowledge-base corpus (enterprise KNOWLEDGE-BASE wave, slice 1).

Proves the load-bearing invariants:

  * (tenant_id, slug) SCOPING. Two fake tenant roots (one CRUCIBLE_ROOT per org — the genuine
    isolation boundary); a process scoped to org A sees ONLY A's slugs' findings and never B's, and
    every record is keyed (A, slug). An explicit cross-org request fails CLOSED.
  * EMPTY / MISSING corpus. No engagements (or no targets/ dir at all) → an empty corpus, never a crash.
  * AGGREGATION correctness over seeded <slug>.report.json (oracle-confirmed active + passive leads),
    authored finding files, and report docs — counts, provenance, severity histogram, filters.

Scoping is driven by monkeypatching ``paths.targets_root`` (so target_dir / phase_report_path /
charter_path all follow) + ``CRUCIBLE_TENANT``, mirroring the D2 sharding tests' convention.

Run (from /home/kali/vigil-wt-kb):
  PYTHONPATH="packages/core/vigil_core:gateway:engine/crucible:integration:." \
    python -m pytest engine/crucible/framework/v2/knowledge_base/tests/test_corpus.py -q
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import pytest

from framework.v2.common import paths
from framework.v2.common.errors import CrucibleRootNotFound
from framework.v2.knowledge_base import KnowledgeBaseScopeError
from framework.v2.knowledge_base import aggregate as kb


# ---------------------------------------------------------------------------
# seeding helpers
# ---------------------------------------------------------------------------


def _scope_to(monkeypatch, targets_dir: Path, tenant: Optional[str]) -> None:
    """Point the framework's targets_root() at ``targets_dir`` and set (or clear) the active tenant."""
    targets_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(paths, "targets_root", lambda: targets_dir)
    if tenant is None:
        monkeypatch.delenv("CRUCIBLE_TENANT", raising=False)
    else:
        monkeypatch.setenv("CRUCIBLE_TENANT", tenant)


def _mk_engagement(targets_dir: Path, slug: str, *, charter: bool = True) -> Path:
    d = targets_dir / slug
    (d / "findings").mkdir(parents=True, exist_ok=True)
    (d / "reports").mkdir(parents=True, exist_ok=True)
    if charter:
        (d / "charter.md").write_text("# charter\n", encoding="utf-8")
    return d


def _write_report_json(targets_dir: Path, slug: str, *, active=(), passive=(),
                       target: str = "https://example.test") -> None:
    (targets_dir / slug).mkdir(parents=True, exist_ok=True)
    payload = {"target": target, "active_findings": list(active), "passive_findings": list(passive)}
    (targets_dir / slug / f"{slug}.report.json").write_text(json.dumps(payload), encoding="utf-8")


def _active(check_id: str, bug_class: str, *, title: str = "", severity: str = "",
            confirmed_by: str = "differential_response", endpoint: str = "/x",
            confidence: float = 0.9) -> dict:
    """An AuditFinding-shaped dict (oracle-confirmed active finding)."""
    return {"check_id": check_id, "bug_class": bug_class, "insertion_point": "query:q",
            "param": "q", "endpoint": endpoint, "confidence": confidence,
            "confirmed_by": confirmed_by, "rationale": "r", "title": title, "severity": severity}


def _passive(check_id: str, title: str, severity: str = "Low") -> dict:
    return {"check_id": check_id, "title": title, "severity": severity,
            "confidence": "Firm", "url": "https://example.test/", "evidence": "e"}


def _write_finding_file(engagement_dir: Path, name: str, *, title: str, severity: str,
                        status: str = "Open", bug_class: Optional[str] = None) -> None:
    body = [f"# Finding 001 — `{name}`", "", "## Metadata", "",
            f"- **Title:** {title}",
            f"- **Severity:** `{severity}`",
            f"- **Status:** `{status}`"]
    if bug_class:
        body.append(f"- **Bug class:** `{bug_class}`")
    (engagement_dir / "findings" / name).write_text("\n".join(body) + "\n", encoding="utf-8")


def _write_report_doc(engagement_dir: Path, name: str, heading: str) -> None:
    (engagement_dir / "reports" / name).write_text(f"# {heading}\n\nbody\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# (tenant_id, slug) scoping + cross-tenant isolation
# ---------------------------------------------------------------------------


def test_cross_tenant_isolation_two_separate_roots(tmp_path, monkeypatch) -> None:
    """One CRUCIBLE_ROOT per org (the genuine isolation boundary): org A's process sees ONLY A's slug
    and findings; org B's only B's. Neither can read the other's secret-titled finding."""
    root_a = tmp_path / "orgA" / "targets"
    root_b = tmp_path / "orgB" / "targets"
    _mk_engagement(root_a, "alpha")
    _write_report_json(root_a, "alpha",
                       active=[_active("sqli-1", "sqli", title="alpha-secret-finding", severity="High")])
    _mk_engagement(root_b, "beta")
    _write_report_json(root_b, "beta",
                       active=[_active("xss-1", "xss", title="beta-secret-finding", severity="Medium")])

    _scope_to(monkeypatch, root_a, "orgA")
    ca = kb.corpus()
    assert ca.slugs() == ["alpha"]
    titles_a = {f.title for f in ca.findings}
    assert "alpha-secret-finding" in titles_a
    assert "beta-secret-finding" not in titles_a                 # cannot read org B
    assert all(f.slug == "alpha" and f.tenant_id == "orgA" for f in ca.findings)
    assert all(e.key == ("orgA", "alpha") for e in ca.engagements)

    _scope_to(monkeypatch, root_b, "orgB")
    cb = kb.corpus()
    assert cb.slugs() == ["beta"]
    titles_b = {f.title for f in cb.findings}
    assert "beta-secret-finding" in titles_b
    assert "alpha-secret-finding" not in titles_b                # cannot read org A
    assert all(f.tenant_id == "orgB" for f in cb.findings)


def test_everything_keyed_by_tenant_and_slug(tmp_path, monkeypatch) -> None:
    t = tmp_path / "orgA" / "targets"
    e = _mk_engagement(t, "shop")
    _write_report_json(t, "shop", active=[_active("c1", "idor", title="t", severity="High")],
                       passive=[_passive("p1", "missing header")])
    _write_finding_file(e, "001-logic.md", title="Logic flaw", severity="Critical")
    _write_report_doc(e, "technical.md", "Technical report")
    _scope_to(monkeypatch, t, "orgA")

    c = kb.corpus()
    assert c.tenant_id == "orgA" and c.scope == "orgA"
    assert all(x.key == ("orgA", "shop") for x in c.engagements)
    assert all(f.key == ("orgA", "shop") for f in c.findings)
    assert all(r.key == ("orgA", "shop") for r in c.reports)


def test_cross_tenant_request_refused_at_api(tmp_path, monkeypatch) -> None:
    """Naming another org explicitly fails CLOSED on every entrypoint; the active org (or None) is fine."""
    t = tmp_path / "orgA" / "targets"
    _mk_engagement(t, "alpha")
    _scope_to(monkeypatch, t, "orgA")

    assert kb.corpus("orgA").tenant_id == "orgA"
    assert kb.corpus(None).tenant_id == "orgA"
    assert kb.corpus().tenant_id == "orgA"

    for call in (lambda: kb.corpus("orgB"),
                 lambda: kb.list_engagements("orgB"),
                 lambda: kb.query("orgB"),
                 lambda: kb.show("alpha", "orgB")):
        with pytest.raises(KnowledgeBaseScopeError):
            call()


def test_global_scope_when_unsharded(tmp_path, monkeypatch) -> None:
    """Unsharded (CRUCIBLE_TENANT unset) == the default/global scope: tenant_id is None, label (global);
    a global process cannot be asked to serve a specific org."""
    t = tmp_path / "solo" / "targets"
    _mk_engagement(t, "only")
    _scope_to(monkeypatch, t, None)

    assert kb.active_org() is None
    c = kb.corpus()
    assert c.tenant_id is None and c.scope == "(global)"
    assert all(e.key == (None, "only") for e in c.engagements)
    with pytest.raises(KnowledgeBaseScopeError):
        kb.corpus("orgA")


def test_unsafe_tenant_fails_closed(monkeypatch) -> None:
    """A hostile / mis-set CRUCIBLE_TENANT propagates the fail-closed validation error (never silently
    falls back to a shared scope)."""
    monkeypatch.setenv("CRUCIBLE_TENANT", "../evil")
    with pytest.raises(CrucibleRootNotFound):
        kb.active_org()
    with pytest.raises(CrucibleRootNotFound):
        kb.corpus()


# ---------------------------------------------------------------------------
# empty / missing corpus (never a crash)
# ---------------------------------------------------------------------------


def test_empty_corpus_no_engagements(tmp_path, monkeypatch) -> None:
    empty = tmp_path / "empty" / "targets"
    _scope_to(monkeypatch, empty, "orgA")                        # dir exists, but holds no slugs
    c = kb.corpus()
    assert c.is_empty()
    assert c.slugs() == []
    assert kb.list_engagements() == []
    assert kb.query() == []
    assert c.by_severity() == {}
    assert kb.show("nope")["engagement"] is None


def test_missing_targets_dir_never_crashes(tmp_path, monkeypatch) -> None:
    missing = tmp_path / "ghost" / "targets"                     # never created
    monkeypatch.setattr(paths, "targets_root", lambda: missing)
    monkeypatch.setenv("CRUCIBLE_TENANT", "orgA")
    c = kb.corpus()
    assert c.is_empty()
    assert kb.list_engagements() == []


def test_scaffolding_and_hidden_dirs_excluded(tmp_path, monkeypatch) -> None:
    t = tmp_path / "orgA" / "targets"
    _mk_engagement(t, "real")
    _mk_engagement(t, "_template")
    _mk_engagement(t, "_practice")
    (t / ".git").mkdir(parents=True, exist_ok=True)
    _scope_to(monkeypatch, t, "orgA")
    assert kb.corpus().slugs() == ["real"]


# ---------------------------------------------------------------------------
# aggregation correctness
# ---------------------------------------------------------------------------


def test_aggregation_over_seeded_reports_and_findings(tmp_path, monkeypatch) -> None:
    t = tmp_path / "orgA" / "targets"
    e = _mk_engagement(t, "shop")
    _write_report_json(
        t, "shop",
        active=[_active("sqli-1", "sqli", title="SQLi in q", severity="High"),
                _active("idor-1", "idor", title="IDOR on /acct", severity="Critical")],
        passive=[_passive("hdr-1", "Missing CSP", severity="Low")],
        target="https://shop.example")
    _write_finding_file(e, "001-logic.md", title="Coupon stacking", severity="High",
                        bug_class="business-logic")
    _write_finding_file(e, "002-auth.md", title="Weak 2FA", severity="Medium")
    _write_report_doc(e, "technical.md", "Technical report — shop")
    _write_report_doc(e, "executive.md", "Executive summary")
    _scope_to(monkeypatch, t, "orgA")

    c = kb.corpus()

    # engagement summary
    assert len(c.engagements) == 1
    eng = c.engagements[0]
    assert eng.slug == "shop" and eng.target == "https://shop.example"
    assert eng.has_charter and eng.has_scan_report
    assert eng.finding_count == 4          # 2 oracle-confirmed active + 2 authored finding files
    assert eng.lead_count == 1             # 1 passive lead
    assert eng.report_count == 2

    # provenance split
    by_src: dict[str, int] = {}
    for f in c.findings:
        by_src[f.source] = by_src.get(f.source, 0) + 1
    assert by_src == {"scan:active": 2, "finding-file": 2, "scan:passive": 1}
    assert len(c.confirmed_findings()) == 4
    assert len(c.leads()) == 1
    for f in c.findings:
        if f.source == "scan:active":
            assert f.oracle_confirmed and f.oracle_kind == "differential_response"
        else:
            assert not f.oracle_confirmed

    # severity histogram over confirmed findings
    assert c.by_severity() == {"High": 2, "Critical": 1, "Medium": 1}

    # reports indexed (not re-rendered)
    assert {r.name for r in c.reports} == {"technical", "executive"}
    tech = next(r for r in c.reports if r.name == "technical")
    assert tech.title == "Technical report — shop" and tech.size_bytes > 0

    # queries (every filter ANDs)
    assert {f.title for f in kb.query(severity="High")} == {"SQLi in q", "Coupon stacking"}
    assert [f.title for f in kb.query(source="scan:passive")] == ["Missing CSP"]
    assert len(kb.query(confirmed_only=True)) == 4
    assert len(kb.query(slug="shop")) == 5
    assert kb.query(slug="does-not-exist") == []
    assert {f.title for f in kb.query(bug_class="business-logic")} == {"Coupon stacking"}

    # show() for one engagement
    shown = kb.show("shop")
    assert shown["engagement"]["slug"] == "shop"
    assert len(shown["findings"]) == 5 and len(shown["reports"]) == 2

    # to_dict is JSON-serializable and summarizes
    blob = json.dumps(c.to_dict())
    assert "shop" in blob
    assert c.to_dict()["summary"]["confirmed_finding_count"] == 4


def test_active_finding_without_severity_buckets_as_confirmed(tmp_path, monkeypatch) -> None:
    """An oracle-confirmed active finding with no textbook severity bucket is counted as 'Confirmed'
    (mirrors ScanReport.by_severity) — still confirmed + oracle-grounded."""
    t = tmp_path / "orgA" / "targets"
    _mk_engagement(t, "api")
    _write_report_json(t, "api", active=[_active("c1", "ssrf", title="SSRF", severity="")])
    _scope_to(monkeypatch, t, "orgA")
    c = kb.corpus()
    assert c.by_severity() == {"Confirmed": 1}
    (f,) = c.findings
    assert f.confirmed and f.oracle_confirmed and f.severity == ""


def test_finding_file_metadata_parsing_contextual_severity(tmp_path, monkeypatch) -> None:
    """The real OBSIDIAN finding format: a plain-text Title that itself contains inline code, and a
    backtick-quoted Severity followed by contextual prose."""
    t = tmp_path / "orgA" / "targets"
    e = _mk_engagement(t, "mail")
    (e / "findings" / "001-no-dmarc.md").write_text(
        "# Finding 001 — `no-dmarc-sender-spoofable`\n\n"
        "## Metadata\n\n"
        "- **ID:** `001`\n"
        "- **Title:** Domain publishes no DMARC, so mail from `@x.com` can be spoofed\n"
        "- **Severity:** `Medium` *(contextual — base posture is Low)*\n"
        "- **Status:** `Open`\n",
        encoding="utf-8")
    _scope_to(monkeypatch, t, "orgA")
    (f,) = kb.corpus().findings
    assert f.source == "finding-file"
    assert f.title == "Domain publishes no DMARC, so mail from `@x.com` can be spoofed"
    assert f.severity == "Medium"
    assert f.status == "Open"
    assert f.confirmed and not f.oracle_confirmed


def test_malformed_report_json_degrades_gracefully(tmp_path, monkeypatch) -> None:
    """A corrupt <slug>.report.json is skipped (0 scan findings) but the engagement is still enumerated
    and its authored finding files are still indexed — never a crash."""
    t = tmp_path / "orgA" / "targets"
    e = _mk_engagement(t, "shop")
    (t / "shop" / "shop.report.json").write_text("{ not valid json ", encoding="utf-8")
    _write_finding_file(e, "001-x.md", title="Still indexed", severity="High")
    _scope_to(monkeypatch, t, "orgA")
    c = kb.corpus()
    assert c.slugs() == ["shop"]
    assert c.engagements[0].has_scan_report is True
    assert [f.title for f in c.findings] == ["Still indexed"]
    assert c.engagements[0].finding_count == 1


def test_active_org_reflects_env(monkeypatch) -> None:
    monkeypatch.setenv("CRUCIBLE_TENANT", "orgZ")
    assert kb.active_org() == "orgZ"
    monkeypatch.delenv("CRUCIBLE_TENANT", raising=False)
    assert kb.active_org() is None


# ---------------------------------------------------------------------------
# containment (red-pen HIGH + MED): a symlink/traversal must never escape the active tenant's root
# ---------------------------------------------------------------------------


def test_symlinked_slug_cannot_escape_the_tenant_root(tmp_path, monkeypatch) -> None:
    """red-pen HIGH: a symlink planted under the active tenant's targets/ pointing at ANOTHER org's root must
    NOT be read on ANY path (report.json included) — org A never pulls org B's findings into its corpus."""
    a = tmp_path / "orgA" / "targets"
    b = tmp_path / "orgB" / "targets"
    a.mkdir(parents=True)
    b.mkdir(parents=True)
    _write_report_json(b, "beta", active=[_active("B-SECRET-sqli", "sqli", title="orgB secret", severity="High")])
    (a / "beta").symlink_to(b / "beta", target_is_directory=True)   # the escape
    _scope_to(monkeypatch, a, "orgA")
    c = kb.corpus()
    assert "B-SECRET-sqli" not in {f.ref for f in c.findings}        # org B's finding never crosses
    assert all(f.tenant_id == "orgA" for f in c.findings)
    assert "beta" not in {e.slug for e in c.engagements}             # the escaping slug is not even enumerated


def test_safe_target_dir_and_enumeration_refuse_a_symlink_escape(tmp_path, monkeypatch) -> None:
    """red-pen MED (zero-coverage guard): _safe_target_dir / _engagement_slugs refuse a slug whose dir resolves
    outside the active root, and admit a genuine in-root slug."""
    a = tmp_path / "orgA" / "targets"
    b = tmp_path / "orgB" / "targets"
    a.mkdir(parents=True)
    (b / "evil").mkdir(parents=True)
    (a / "evil").symlink_to(b / "evil", target_is_directory=True)
    (a / "real").mkdir()
    _scope_to(monkeypatch, a, "orgA")
    assert kb._safe_target_dir("evil") is None                      # escapes → refused
    assert kb._safe_target_dir("real") is not None                  # genuinely inside → allowed
    slugs = kb._engagement_slugs()
    assert "evil" not in slugs and "real" in slugs


def test_schema_drift_non_iterable_findings_degrade_not_crash(tmp_path, monkeypatch) -> None:
    """red-pen LOW: a valid-JSON report.json whose active/passive_findings is a truthy NON-iterable scalar must
    NOT crash the whole-org corpus — it degrades to no findings for that slug."""
    a = tmp_path / "orgA" / "targets"
    a.mkdir(parents=True)
    (a / "shop").mkdir()
    (a / "shop" / "shop.report.json").write_text(
        json.dumps({"target": "t", "active_findings": 5, "passive_findings": True}), encoding="utf-8")
    _write_report_json(a, "ok", active=[_active("OK-1", "xss", severity="Medium")])
    _scope_to(monkeypatch, a, "orgA")
    c = kb.corpus()                                                 # must not raise
    assert "OK-1" in {f.ref for f in c.findings}                    # the well-formed engagement still aggregates
    assert {e.slug for e in c.engagements} >= {"shop", "ok"}        # drifted slug present, contributes nothing fatal


def test_leaf_symlink_inside_a_contained_slug_cannot_escape(tmp_path, monkeypatch) -> None:
    """re-red-pen HIGH (leaf-symlink leak the dir-level fix missed): a GENUINELY in-root slug dir whose
    <slug>.report.json, findings/ (whole dir), reports/ (whole dir), charter.md, or an individual *.md is a
    symlink into ANOTHER org's root must leak NOTHING — every concrete leaf read is containment-checked."""
    a = tmp_path / "orgA" / "targets"
    b = tmp_path / "orgB" / "targets"
    a.mkdir(parents=True)
    # org B's crown jewels:
    be = _mk_engagement(b, "beta")
    _write_report_json(b, "beta",
                       active=[_active("B-SECRET-rce", "rce", title="orgB CROWN JEWEL", severity="Critical",
                                       confirmed_by="oob_callback")],
                       target="https://secret.orgB")
    _write_finding_file(be, "001-secret.md", title="orgB secret finding doc", severity="Critical")
    _write_report_doc(be, "technical.md", "orgB secret report")

    # SHAPE (c): a real slug dir whose report.json is a symlink to org B's report
    (a / "foo").mkdir()
    (a / "foo" / "foo.report.json").symlink_to(b / "beta" / "beta.report.json")
    # SHAPE (b): a real slug dir whose findings/ is a symlink to org B's findings/
    (a / "bar").mkdir()
    (a / "bar" / "findings").symlink_to(b / "beta" / "findings", target_is_directory=True)
    (a / "bar" / "reports").mkdir()
    # SHAPE (b'): a real slug dir whose reports/ is a symlink to org B's reports/
    (a / "baz").mkdir()
    (a / "baz" / "findings").mkdir()
    (a / "baz" / "reports").symlink_to(b / "beta" / "reports", target_is_directory=True)
    # PER-FILE: a real findings/ dir holding one symlinked finding doc into org B
    qd = a / "qux"
    (qd / "findings").mkdir(parents=True)
    (qd / "reports").mkdir()
    (qd / "findings" / "001-x.md").symlink_to(b / "beta" / "findings" / "001-secret.md")
    # CHARTER: a real slug dir whose charter.md is a symlink into org B
    (a / "cha").mkdir()
    (a / "cha" / "charter.md").symlink_to(b / "beta" / "charter.md")

    _scope_to(monkeypatch, a, "orgA")
    c = kb.corpus()

    refs = {f.ref for f in c.findings}
    titles = {f.title for f in c.findings}
    targets = {e.target for e in c.engagements}
    assert "B-SECRET-rce" not in refs                               # report.json leaf symlink refused
    assert "orgB CROWN JEWEL" not in titles
    assert "orgB secret finding doc" not in titles                  # findings/ dir + per-file symlink refused
    assert "https://secret.orgB" not in targets                     # report target never crosses
    assert all(f.tenant_id == "orgA" for f in c.findings)
    assert not any(r.title == "orgB secret report" for r in c.reports)  # reports/ dir symlink refused
    # the symlinked leaves do not even register as "present"
    cha = next(e for e in c.engagements if e.slug == "cha")
    assert cha.has_charter is False
    foo = next(e for e in c.engagements if e.slug == "foo")
    assert foo.has_scan_report is False


def test_scaffold_readme_and_nonlive_status_not_counted_as_confirmed(tmp_path, monkeypatch) -> None:
    """re-red-pen MED (claim-discipline miscount): findings/README.md (shipped by targets/_template into
    every engagement) is NOT a finding, and a WITHDRAWN / DRAFT doc is not a live confirmed finding."""
    a = tmp_path / "orgA" / "targets"
    # a fresh, zero-work engagement that only carries the scaffold README
    fresh = _mk_engagement(a, "fresh")
    (fresh / "findings" / "README.md").write_text("# How to write findings\n", encoding="utf-8")
    # an engagement with a real Open finding + a WITHDRAWN + a DRAFT + a PLAIN (non-backtick) multi-word
    # nonconfirming status with trailing prose (must still be classified non-confirmed).
    work = _mk_engagement(a, "work")
    _write_finding_file(work, "001-real.md", title="Real bug", severity="High", status="Open")
    _write_finding_file(work, "002-gone.md", title="Retracted", severity="High", status="WITHDRAWN")
    _write_finding_file(work, "003-wip.md", title="Not ready", severity="Critical", status="DRAFT")
    (work / "findings" / "004-fp.md").write_text(                   # plain Status, multi-word + PUNCTUATED prose
        "# Finding 004 — `maybe`\n\n## Metadata\n\n"
        "- **Title:** Looks like a bug\n"
        "- **Severity:** High\n"
        "- **Status:** False Positive — duplicate of 001, benign\n",
        encoding="utf-8")
    (work / "findings" / "005-dup.md").write_text(                  # plain Status, UNPUNCTUATED trailing prose
        "# Finding 005 — `maybe2`\n\n## Metadata\n\n"
        "- **Title:** Also not real\n"
        "- **Severity:** Medium\n"
        "- **Status:** Duplicate of 003\n",
        encoding="utf-8")
    _scope_to(monkeypatch, a, "orgA")
    c = kb.corpus()

    fresh_eng = next(e for e in c.engagements if e.slug == "fresh")
    assert fresh_eng.finding_count == 0                             # README is not a confirmed finding
    assert fresh_eng.lead_count == 0                                # and not a lead either
    assert not any(f.ref.lower() == "readme" for f in c.findings)   # and not indexed as one at all

    work_eng = next(e for e in c.engagements if e.slug == "work")
    assert work_eng.finding_count == 1                             # only the Open one counts
    assert work_eng.lead_count == 0                                # retracted/draft/FP docs are NOT leads
    confirmed_titles = {f.title for f in c.findings if f.slug == "work" and f.confirmed}
    assert confirmed_titles == {"Real bug"}
    # the withdrawn/draft/false-positive/duplicate docs are still indexed (history) but marked not-confirmed
    # (incl. BOTH punctuated 'False Positive — …' and UNPUNCTUATED 'Duplicate of 003' trailing prose)
    unconfirmed = {f.title for f in c.findings if f.slug == "work" and not f.confirmed}
    assert unconfirmed == {"Retracted", "Not ready", "Looks like a bug", "Also not real"}
    assert c.leads() == []                                          # no passive scan findings here at all


def test_oracle_confirmed_requires_a_named_oracle(tmp_path, monkeypatch) -> None:
    """re-red-pen MED (provenance overclaim): an active finding that NAMES no confirming oracle
    (confirmed_by empty) must NOT be stamped oracle_confirmed=True (that would assert a confirmation while
    naming no oracle). A named confirmer still carries oracle_confirmed=True + the oracle_kind."""
    a = tmp_path / "orgA" / "targets"
    _mk_engagement(a, "api")
    _write_report_json(a, "api", active=[
        _active("named-1", "sqli", title="named", severity="High", confirmed_by="oob_callback"),
        _active("unnamed-1", "sqli", title="unnamed", severity="High", confirmed_by=""),
    ])
    _scope_to(monkeypatch, a, "orgA")
    by_ref = {f.ref: f for f in kb.corpus().findings}
    assert by_ref["named-1"].oracle_confirmed is True and by_ref["named-1"].oracle_kind == "oob_callback"
    assert by_ref["unnamed-1"].oracle_confirmed is False and by_ref["unnamed-1"].oracle_kind == ""
    assert by_ref["unnamed-1"].confirmed is True                    # still an active finding, just not oracle-grounded here
