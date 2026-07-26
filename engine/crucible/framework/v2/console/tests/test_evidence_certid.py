"""
P3 Evidence Browser — the console `evidence()` provider now carries a REAL cert id (a
content hash of the retained oracle_context) so the UI can address a certificate, and it
must yield exactly one honest re-verify state per certificate: sound / tampered / claim-
mismatch (and a distinct no-certificate case). These pin the data contract the Evidence
screen renders — all computed OFFLINE (a pure oracle re-run, no target traffic).
"""

from __future__ import annotations

import json

from framework.v2.console import actions, api
from framework.v2.evidence.canonical import digest_payload
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.confirmation import confirm_finding


def _finding_with_context() -> tuple[dict, FindingContext]:
    ctx = FindingContext.from_http_responses(
        {"status": 200, "body": "No results."},
        {"status": 200, "body": "id=1 alice user\nid=2 bob admin"},
        bug_class="boolean_sqli",
        discriminator={"dimensions": ["status", "length", "lexical"]},
    )
    c = confirm_finding(finding={"bug_class": "boolean_sqli"}, context=ctx)
    finding = {
        "check_id": "boolean-sqli", "bug_class": "boolean_sqli",
        "insertion_point": "query", "param": "q",
        "confirmed_by": c.confirmed_by.value, "confidence": c.confidence,
        "oracle_context": ctx.model_dump(mode="json"),
    }
    return finding, ctx


def _stage(tmp_path, monkeypatch, report: dict, rid: str = "run-1") -> str:
    run = tmp_path / rid
    run.mkdir(parents=True)
    (run / "reverifiable.json").write_text(json.dumps(report), encoding="utf-8")
    monkeypatch.setattr(actions, "run_dir", lambda r: tmp_path / r)
    return rid


def test_cert_id_is_the_content_hash_of_the_retained_context(tmp_path, monkeypatch) -> None:
    f, _ctx = _finding_with_context()
    rid = _stage(tmp_path, monkeypatch, {"target": "https://app/", "active_findings": [f]})
    d = api.evidence(rid)
    cert = d["findings"][0]
    assert cert["sound"] and cert["has_certificate"]
    # the cert id is a REAL, deterministic content address — "sha256:" + canonical-JSON digest,
    # the same digest the signed EvidenceCertificate binds as oracle_context_digest.
    assert cert["cert_id"] == "sha256:" + digest_payload(f["oracle_context"])


def test_no_certificate_yields_empty_cert_id(tmp_path, monkeypatch) -> None:
    # a finding without a retained oracle_context is a lead, not a certified fact — no id is minted.
    rid = _stage(tmp_path, monkeypatch,
                 {"target": "https://app/",
                  "active_findings": [{"check_id": "x", "bug_class": "boolean_sqli"}]})
    cert = api.evidence(rid)["findings"][0]
    assert cert["has_certificate"] is False and cert["cert_id"] == ""


def test_tampered_context_changes_the_cert_id_and_does_not_reproduce(tmp_path, monkeypatch) -> None:
    f, _ = _finding_with_context()
    good_id = "sha256:" + digest_payload(f["oracle_context"])
    # collapse the differential the oracle needs (make the mutated branch identical to baseline):
    # the retained evidence no longer proves anything → the pure oracle cannot re-confirm.
    f["oracle_context"]["mutated"] = dict(f["oracle_context"]["baseline"])
    rid = _stage(tmp_path, monkeypatch, {"target": "https://app/", "active_findings": [f]})
    cert = api.evidence(rid)["findings"][0]
    # a content address must diverge when the content changes, and the oracle must NOT re-confirm.
    assert cert["cert_id"] and cert["cert_id"] != good_id
    assert cert["has_certificate"] and cert["reproduced"] is False and cert["sound"] is False


def test_claim_mismatch_is_a_distinct_state(tmp_path, monkeypatch) -> None:
    # the evidence re-confirms, but the finding CLAIMS a different oracle kind than actually fires:
    # reproduced True, matches_claim False, sound False → the UI's "⚠ Claim mismatch" state.
    f, _ = _finding_with_context()
    f["confirmed_by"] = "definitely_not_the_real_oracle"
    rid = _stage(tmp_path, monkeypatch, {"target": "https://app/", "active_findings": [f]})
    cert = api.evidence(rid)["findings"][0]
    assert cert["reproduced"] is True and cert["matches_claim"] is False and cert["sound"] is False


def test_evidence_is_resilient_and_sends_no_traffic_marker(tmp_path, monkeypatch) -> None:
    # missing run → resilient (never raises); the doctrine string is the offline/no-trust promise.
    d = api.evidence("nope")
    assert d["findings"] == [] and (d.get("pending") or "error" in d)
    f, _ = _finding_with_context()
    rid = _stage(tmp_path, monkeypatch, {"target": "https://app/", "active_findings": [f]})
    assert "offline" in api.evidence(rid)["doctrine"].lower()
