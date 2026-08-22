"""B5 — the console `proof_list` provider (surfaces the persisted Proof Studio records for a run).

`proof_list` reads plain JSON records written host-side by the keyless offense mint
(`vigil_integration.proof.run`) under `<run_dir>/proofs/` — it imports NO integration package (no
framework→integration dependency) and sends no traffic. Honesty under test: facts sort before leads before
denied, and the disposition counts are exact; a denied record never claims to have crossed the spine.
"""

from __future__ import annotations

import json

from framework.v2.console import actions, api


def _write(rd, rec):
    d = rd / "proofs"
    d.mkdir(parents=True, exist_ok=True)
    (d / (rec["proof_id"] + ".json")).write_text(json.dumps(rec), encoding="utf-8")


def test_proof_list_is_safe_on_a_missing_run():
    d = api.proof_list("no-such-run-xyz")
    assert d["run_id"] == "no-such-run-xyz" and d["proofs"] == [] and d.get("pending") is True
    assert "FACT" in d["doctrine"] or "fact" in d["doctrine"].lower()


def test_proof_list_orders_facts_first_and_counts_are_exact(tmp_path, monkeypatch):
    monkeypatch.setattr(actions, "console_dir", lambda: tmp_path / ".console")
    run = "20260101-000000-001"
    rd = actions.run_dir(run)
    rd.mkdir(parents=True, exist_ok=True)
    _write(rd, {"proof_id": "aaa", "finding_ref": "l1", "bug_class": "xss", "status": "lead",
                "confirmed_by": "", "confidence": 0.0, "spooled": False, "exchanges": [], "reason": "not reproduced"})
    _write(rd, {"proof_id": "bbb", "finding_ref": "f1", "bug_class": "sqli", "status": "fact",
                "confirmed_by": "sqli_breakout", "confidence": 0.99, "spooled": True,
                "exchanges": [{"channel": "request_payload", "role": "q"}], "reason": "reproduced"})
    _write(rd, {"proof_id": "ccc", "finding_ref": "d1", "bug_class": "rce", "status": "denied",
                "gate_category": "destructive", "confirmed_by": "", "confidence": 0.0, "spooled": False,
                "exchanges": [], "reason": "content gate refused"})

    d = api.proof_list(run)
    assert d["total"] == 3 and d["facts"] == 1 and d["leads"] == 1 and d["denied"] == 1
    assert d["pending"] is False
    assert d["proofs"][0]["status"] == "fact"                    # facts sort first
    assert d["proofs"][0]["confirmed_by"] == "sqli_breakout"
    # the denied record honestly never claims to have crossed the spine
    denied = [p for p in d["proofs"] if p["status"] == "denied"][0]
    assert denied["spooled"] is False and denied["gate_category"] == "destructive"


def test_proof_list_surfaces_a_degraded_subsystem_distinctly_from_a_clean_run(tmp_path, monkeypatch):
    """inv 12 (S9): a degradation manifest makes a CLEAN reading impossible — an empty proof list reads as a
    typed subsystem failure, never "nothing found". Computed with stdlib only in the console (no integration
    import), so the state is surfaced even when the integration package is itself unavailable."""
    monkeypatch.setattr(actions, "console_dir", lambda: tmp_path / ".console")

    # a genuinely clean run: no proof records, no degradation manifest — the ONLY honest "clean" state.
    clean_run = "20260101-000000-010"
    crd = actions.run_dir(clean_run)
    crd.mkdir(parents=True, exist_ok=True)
    clean = api.proof_list(clean_run)
    assert clean["pending"] is True and clean["verification_degraded"] is False
    assert clean["disposition"] == "nothing_found" and clean["clean"] is True

    # a degraded run: the proof sink never installed. Still zero proof records, but NOT clean.
    degraded_run = "20260101-000000-011"
    drd = actions.run_dir(degraded_run)
    (drd / "proofs").mkdir(parents=True, exist_ok=True)
    (drd / "proofs" / "_degraded.json").write_text(
        json.dumps({"degradations": [{"kind": "proof_subsystem_unavailable", "where": "bootstrap",
                                      "detail": "RuntimeError", "count": 1}]}),
        encoding="utf-8")
    d = api.proof_list(degraded_run)
    assert d["total"] == 0 and d["proofs"] == [], "the degradation manifest was mis-read as a proof record"
    assert d["verification_degraded"] is True and d["clean"] is False, (
        "CLEAN must be impossible while the proof subsystem is degraded"
    )
    assert d["disposition"] == "proof_subsystem_unavailable"
    assert {c["kind"] for c in d["degraded_causes"]} == {"proof_subsystem_unavailable"}
    assert d["disposition"] != clean["disposition"], (
        "a down proof subsystem renders identically to a clean target — the inv-12 conflation is back"
    )
