"""
K3 — deep-learn FIND/DETECT/PREVENT (`knowledge_engine.deeplearn` + `retrieve`).

Doctrine under test:
  * DETECT maps ONLY onto EXISTING deterministic oracle kinds (the canonical BUG_CLASS_ORACLES); an
    unmappable class drafts a GATED proposal — it NEVER invents an oracle kind and NEVER a soft oracle;
  * everything is ADVISORY — skills carry no tier/authority, the skill_ref classifies as a LEAD (never
    grounded), and nothing here mints a fact, fires an oracle, or mutates a store;
  * deterministic given (lead, now); a runaway skill dir is bounded at retrieval (MAX_SKILLS);
  * path-safety — an unsafe vuln id can't write outside the skills dir.
"""

from __future__ import annotations

import argparse
import io
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from framework.v2.knowledge_engine.deeplearn import deep_learn
from framework.v2.knowledge_engine.retrieve import MAX_SKILLS, retrieve_skillset
from framework.v2.verify.models import OracleKind
from framework.v2.worldmodel.models import classify_provenance

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
_ALL_KINDS = {k.value for k in OracleKind}
_NVD_FEED = {"vulnerabilities": [{"cve": {
    "id": "CVE-2024-5555", "descriptions": [{"lang": "en", "value": "demo"}],
    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.1}, "baseSeverity": "CRITICAL"}]},
    "configurations": []}}]}


def test_detect_maps_known_class_onto_existing_oracle_kinds(tmp_path):
    props: list = []
    r = deep_learn({"id": "CVE-2024-0001", "severity": "CRITICAL", "exploit_known": True,
                    "cwes": ["CWE-89"]}, skills_dir=tmp_path, now=NOW, proposals_out=props)
    assert r.detect.mapped is True and r.detect.oracle_kinds and not props
    # EVERY mapped kind is a REAL OracleKind — K3 can never emit a mapping onto an invented kind.
    assert set(r.detect.oracle_kinds) <= _ALL_KINDS
    assert "boolean_inference" in r.detect.oracle_kinds


def test_detect_unknown_class_drafts_a_gated_proposal_never_invents(tmp_path):
    props: list = []
    r = deep_learn({"id": "CVE-2024-0002", "cwes": ["CWE-352"]},   # CSRF — not in the oracle vocabulary
                   skills_dir=tmp_path, now=NOW, proposals_out=props)
    assert r.detect.mapped is False and r.detect.oracle_kinds == []
    assert r.detect.proposal_id and len(props) == 1
    p = props[0]
    assert p.status.value == "draft" and p.change.patch == ""       # DRAFT, described-only (authorize≠apply)
    assert p.change.target_artifact.startswith("oracle:")           # proposes a REAL oracle, invents nothing


def test_detect_never_maps_onto_a_nonexistent_kind_for_any_supported_cwe(tmp_path):
    # sweep every curated CWE mapping: whatever it resolves to must be REAL oracle kinds or a gated proposal.
    from framework.v2.knowledge_engine.deeplearn import _CWE_TO_BUGCLASS
    for cwe in _CWE_TO_BUGCLASS:
        r = deep_learn({"id": f"CVE-X-{cwe.replace('CWE-', '')}", "cwes": [cwe]},
                       skills_dir=tmp_path, now=NOW)
        assert set(r.detect.oracle_kinds) <= _ALL_KINDS, (cwe, r.detect.oracle_kinds)


def test_detect_never_invents_a_kind_for_any_known_bug_class_hint(tmp_path):
    # the STRONGEST coverage of the hint path: EVERY canonical known bug_class fed as an attacker-controlled
    # `bug_class` hint must resolve to REAL oracle kinds (never an invented one); a mapped result is
    # non-empty, an unmapped one drafts a gated proposal (never a fabricated kind).
    from framework.v2.verify.verifier import known_bug_classes
    for bc in sorted(known_bug_classes()):
        r = deep_learn({"id": "CVE-SWEEP-1", "bug_class": bc}, skills_dir=tmp_path, now=NOW)
        assert set(r.detect.oracle_kinds) <= _ALL_KINDS, (bc, r.detect.oracle_kinds)
        assert (r.detect.oracle_kinds if r.detect.mapped else r.detect.proposal_id)


def test_skills_written_and_advisory(tmp_path):
    r = deep_learn({"id": "CVE-2024-0003", "cwes": ["CWE-918"]}, skills_dir=tmp_path, now=NOW)
    for p in (r.find_skill, r.detect_skill, r.prevent_skill):
        assert Path(p).is_file()
    body = Path(r.detect_skill).read_text(encoding="utf-8")
    assert "category: detect" in body and "tier:" not in body      # advisory frontmatter, no authority key
    assert classify_provenance(r.skill_ref) == "ungrounded"        # strictly a LEAD, never grounded


def test_deep_learn_is_deterministic(tmp_path):
    lead = {"id": "CVE-2024-0004", "cwes": ["CWE-78"], "severity": "HIGH"}
    r1 = deep_learn(lead, skills_dir=tmp_path / "a", now=NOW)
    r2 = deep_learn(lead, skills_dir=tmp_path / "b", now=NOW)
    assert r1.detect.oracle_kinds == r2.detect.oracle_kinds
    assert (Path(r1.detect_skill).read_text(encoding="utf-8")
            == Path(r2.detect_skill).read_text(encoding="utf-8"))


def test_unsafe_vuln_id_is_rejected(tmp_path):
    for bad in ("../../etc/passwd", "a/b", "", "x" * 200):
        with pytest.raises(ValueError):
            deep_learn({"id": bad}, skills_dir=tmp_path, now=NOW)


# ---- retrieve: advisory skillset, bounded ----------------------------------

def test_retrieve_caps_and_filters(tmp_path):
    for i in range(7):
        deep_learn({"id": f"CVE-2024-{i:04d}", "cwes": ["CWE-89"]}, skills_dir=tmp_path, now=NOW)
    r = retrieve_skillset("find", skills_dir=tmp_path)
    assert len(r["skills"]) == MAX_SKILLS                            # bounded (7 written, ≤5 returned)
    assert [s["id"] for s in r["skills"]] == sorted(s["id"] for s in r["skills"])   # id-sorted, deterministic
    assert all(s["category"] == "find" for s in r["skills"])        # query filter works
    assert "FACT" in r["doctrine"]
    assert retrieve_skillset("no-such-skill-xyz", skills_dir=tmp_path)["skills"] == []


# ---- CLI end-to-end: real slug → leads → deep-learn ------------------------

def test_cli_learn_reads_leads_and_writes_skills(tmp_path, monkeypatch):
    from framework.v2.common import paths
    from framework.v2.intel import cli as intel_cli
    from framework.v2.knowledge_engine import cli as kcli
    monkeypatch.setattr(paths, "memory_db", lambda: tmp_path / "mls.sqlite")
    monkeypatch.setattr("sys.stdout", io.StringIO())          # swallow the CLIs' JSON prints

    feed = tmp_path / "nvd.json"
    feed.write_text(json.dumps(_NVD_FEED), encoding="utf-8")
    intel_cli.main(["ingest-intel", "--file", str(feed), "--format", "nvd", "--slug", "kd"])

    sk = tmp_path / "skills"
    rc = kcli._learn(argparse.Namespace(slug="kd", vuln="", all=True, skills_dir=str(sk)))
    assert rc == 0
    files = list(sk.rglob("*.md"))
    assert files and any(f.parent.name == "detect" for f in files)   # a detect skill was written


def test_cli_learn_refused_when_killswitch_tripped(tmp_path, monkeypatch):
    from framework.v2.common import paths
    from framework.v2.knowledge_engine import cli as kcli
    monkeypatch.setattr(paths, "killswitch_path", lambda slug: tmp_path / f"{slug}.halt")
    (tmp_path / "kd.halt").write_text("{}", encoding="utf-8")    # file presence = TRIPPED
    rc = kcli._learn(argparse.Namespace(slug="kd", vuln="", all=True, skills_dir=str(tmp_path / "s")))
    assert rc == 3                                               # refused before reading/learning anything
    assert not (tmp_path / "s").exists()
