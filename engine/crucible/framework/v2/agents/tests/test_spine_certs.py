"""
agents.spine_certs — a LIVE engage's oracle-confirmed FACTs, exported off the .blackboard
spine as the SAME offline-re-verifiable certificate bundle the scanner/proof paths produce.

The contract these tests pin:

  * a spine FACT (a `finding` event with verified_by_oracle=True + a retained oracle_context)
    is exported into `active_findings` and RE-VERIFIES offline through `framework.v2 verify`,
    exactly like a scanner reverifiable.json;
  * a one-byte TAMPER of the retained evidence is REJECTED by the re-verifier;
  * the NON-LAUNDERING gate holds: a LEAD is never exported as a re-verifiable fact — not a
    passive lead (no cert), and CRUCIALLY not a demoted active whose oracle_context WOULD
    re-fire but which the engagement recorded as verified_by_oracle=False.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from framework.v2.agents import spine_certs
from framework.v2.agents.blackboard import open_blackboard
from framework.v2.verify import reverify
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.confirmation import confirm_finding

_CANARY = "vgLK7tQ2mXb9Zp4WdR"
_BUG_CLASS = "request_smuggling"


def _desync_ctx(*, genuine: bool = True) -> FindingContext:
    """A re-verifiable CL.TE desync certificate. ``genuine=False`` drops the canary from the
    conflict leg so the oracle does NOT re-fire (the tampered twin)."""
    return FindingContext.from_smuggling_desync(
        canary=_CANARY, technique="CL.TE",
        conflict_second={"channel": True, "status": 400,
                         "body": (f"HTTP/1.1 400 Bad Request: unrecognised method GET /{_CANARY}"
                                  if genuine else "HTTP/1.1 200 OK ordinary second response")},
        control_second={"channel": True, "status": 200,
                        "body": "HTTP/1.1 200 OK ordinary second response"},
        bug_class=_BUG_CLASS,
    )


def _fact_payload(slug: str, *, genuine: bool = True) -> dict:
    """A FindingPayload-shaped spine FACT: an oracle fired and its certificate is retained."""
    ctx = _desync_ctx(genuine=genuine)
    confirmed = confirm_finding(finding={"bug_class": _BUG_CLASS}, context=ctx)
    assert confirmed is not None
    return {
        "finding_slug": slug,
        "title": "CL.TE request smuggling desync",
        "severity": "High",
        "bug_class": _BUG_CLASS,
        "surface": "header:transfer-encoding",
        "summary": "unique canary echoed on the conflict leg, absent from the control",
        "critique_status": "confirmed",
        "oracle_context": ctx.model_dump(mode="json"),
        "verified_by_oracle": True,
        "confidence": confirmed.confidence,
        "oracle_kind": confirmed.confirmed_by.value,
        "oracle_rationale": "canary differential",
    }


def _demoted_lead_payload(slug: str) -> dict:
    """A demoted active finding: it RETAINS a genuine, re-firing oracle_context, but the
    engagement graded it verified_by_oracle=False (its live grounding was not `fact`). It must
    stay a LEAD in the export — this is the sharpest laundering vector."""
    p = _fact_payload(slug, genuine=True)
    p["verified_by_oracle"] = False
    p["critique_status"] = "llm_advisory"
    return p


def _passive_lead_payload(slug: str) -> dict:
    """A passive hygiene lead: no oracle, no certificate."""
    return {
        "finding_slug": slug,
        "title": "missing security header",
        "severity": "Low",
        "bug_class": "passive:missing-header",
        "surface": "(response)",
        "summary": "X-Content-Type-Options not set",
        "critique_status": "llm_advisory",
        "oracle_context": None,
        "verified_by_oracle": False,
        "confidence": None,
        "oracle_kind": None,
        "oracle_rationale": "",
    }


@pytest.fixture()
def bb(tmp_path: Path):
    b = open_blackboard(db_path=tmp_path / "bb.sqlite")
    yield b
    b.close()


def _seed(bb, slug: str = "live-engage") -> None:
    """One FACT + one demoted-lead-with-cert + one passive lead on the spine."""
    bb.post(engagement=slug, kind="finding", agent_name="spine", payload=_fact_payload("001-desync"))
    bb.post(engagement=slug, kind="finding", agent_name="spine", payload=_demoted_lead_payload("002-demoted"))
    bb.post(engagement=slug, kind="finding", agent_name="spine", payload=_passive_lead_payload("003-passive"))


def test_only_the_fact_is_exported_as_reverifiable(bb) -> None:
    _seed(bb)
    doc = spine_certs.export_reverifiable_from_spine(bb, "live-engage")
    # exactly the ONE real fact reaches active_findings...
    assert [f["finding_slug"] for f in doc["active_findings"]] == ["001-desync"]
    # ...and the two leads (incl. the demoted-with-cert one, whose oracle WOULD re-fire) are
    # NOT there — they are disclosed under `leads`, never as re-verifiable facts.
    lead_slugs = {l["finding_slug"] for l in doc["leads"]}
    assert lead_slugs == {"002-demoted", "003-passive"}
    for f in doc["active_findings"]:
        assert isinstance(f["oracle_context"], dict) and f["oracle_context"]


def test_exported_fact_reverifies_offline(bb, tmp_path: Path) -> None:
    _seed(bb)
    out = spine_certs.write_reverifiable_from_spine(bb, "live-engage", tmp_path / "spine.json")
    # the offline re-verifier (what `python3 -m framework.v2 verify <file>` dispatches to)
    rc = reverify.main([str(out)])
    assert rc == 0
    # and directly: the retained cert re-fires and matches its claim
    doc = json.loads(out.read_text(encoding="utf-8"))
    results = reverify.reverify_document(doc)
    assert results and all(r.ok for r in results)
    assert results[0].confirmed_by == "differential_response"


def test_tampered_export_is_rejected(bb, tmp_path: Path) -> None:
    _seed(bb)
    out = spine_certs.write_reverifiable_from_spine(bb, "live-engage", tmp_path / "spine.json")
    doc = json.loads(out.read_text(encoding="utf-8"))
    # flip the retained evidence to the canary-free twin while keeping the claim: the unique-
    # canary differential no longer fires — the certificate must NOT reproduce.
    doc["active_findings"][0]["oracle_context"] = _desync_ctx(genuine=False).model_dump(mode="json")
    tampered = tmp_path / "tampered.json"
    tampered.write_text(json.dumps(doc), encoding="utf-8")
    assert reverify.main([str(tampered)]) == 2
    results = reverify.reverify_document(doc)
    assert not results[0].ok and not results[0].reproduced


def test_demoted_finding_would_reverify_but_is_never_exported(bb) -> None:
    """The load-bearing anti-laundering assertion: the demoted lead RETAINS a genuine, re-firing
    certificate; if the gate keyed on cert-presence it would leak in and re-verify. It does not,
    because the export keys on the engagement's RECORDED verdict (verified_by_oracle)."""
    bb.post(engagement="only-demoted", kind="finding", agent_name="spine",
            payload=_demoted_lead_payload("001-demoted"))
    doc = spine_certs.export_reverifiable_from_spine(bb, "only-demoted")
    assert doc["active_findings"] == []          # nothing laundered into a fact
    # prove the excluded lead's OWN certificate really would have re-verified — so exclusion is
    # a verdict decision, not an accident of a broken cert.
    lead_cert = _demoted_lead_payload("001-demoted")["oracle_context"]
    r = reverify.reverify_context(lead_cert, bug_class=_BUG_CLASS)
    assert r.ok and r.reproduced


def test_export_is_deterministic(bb) -> None:
    _seed(bb)
    a = spine_certs.export_reverifiable_from_spine(bb, "live-engage")
    b = spine_certs.export_reverifiable_from_spine(bb, "live-engage")
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
