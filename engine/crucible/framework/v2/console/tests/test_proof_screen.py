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
