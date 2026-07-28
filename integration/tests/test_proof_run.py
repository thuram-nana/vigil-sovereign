"""Proof Studio wiring (B5) — the run-integration seam ``proof.run`` + its coupling to ``proof.sink``.

Doctrine under test — the persistence + read path a real Strix run drives:
  * a REPRODUCING captured exchange, handed to ``build_report_mint``'s callback, mints a FACT and PERSISTS a
    proof record whose ``status == "fact"`` with the captured channels + the oracle that fired;
  * a non-reproducing capture persists an honest LEAD (no ``confirmed_by`` fact, never spooled);
  * the record id is a content address (deterministic — re-minting overwrites, never duplicates);
  * a report with no attached executor capture mints nothing (the model's text alone never makes a proof);
  * end-to-end through the real ``ProofSink``: an ALLOWED report with a capture persists a record; a report
    whose poc_script_code is DENIED by the content gate persists NOTHING (the sink never calls the mint).

Needs framework (context_from_exchanges + the oracle) → run with PYTHONPATH=integration:engine/crucible:gateway.
"""

from __future__ import annotations

from vigil_core import generate_keypair
from vigil_integration.proof.run import build_report_mint, read_proofs
from vigil_integration.proof.sink import CAPTURE_KEY, ProofSink

SIGNER = generate_keypair()
SIGNERS = [("root0", SIGNER.private_key_b64)]


def _capture(value: str = "' OR '1'='1"):
    """One request-payload exchange (the SQLi-breakout oracle judges the decoded value) + its raw blob."""
    return {
        "exchanges": [{"channel": "request_payload", "role": "q", "request_bytes_ref": "req",
                       "bug_class": "sqli_attempt"}],
        "blobs": {"req": value.encode("utf-8")},
    }


def _report(check_id: str, poc: str = "print('benign reproduction')", value: str = "' OR '1'='1") -> dict:
    return {"id": check_id, "bug_class": "sqli_attempt", "poc_script_code": poc, CAPTURE_KEY: _capture(value)}


def test_reproducing_capture_persists_a_fact_record(tmp_path):
    mint = build_report_mint(run_dir=tmp_path, signers=SIGNERS, engagement_slug="acme")
    res = mint(_report("sqli-001"))
    assert res is not None and res.is_fact

    recs = read_proofs(tmp_path)
    assert len(recs) == 1
    rec = recs[0]
    assert rec["status"] == "fact"
    assert rec["bug_class"] == "sqli_attempt"
    assert rec["finding_ref"] == "sqli-001"
    assert rec["confirmed_by"]                                  # a real oracle name, not empty
    assert [e["channel"] for e in rec["exchanges"]] == ["request_payload"]


def test_non_reproducing_capture_persists_a_lead(tmp_path):
    mint = build_report_mint(run_dir=tmp_path, signers=SIGNERS, engagement_slug="acme")
    res = mint(_report("x", value="O'Brien"))                   # a benign value the oracle won't fire on
    assert res is not None and res.status == "lead"

    recs = read_proofs(tmp_path)
    assert len(recs) == 1 and recs[0]["status"] == "lead" and recs[0]["spooled"] is False


def test_record_id_is_a_content_address_so_reminting_does_not_duplicate(tmp_path):
    mint = build_report_mint(run_dir=tmp_path, signers=SIGNERS, engagement_slug="acme")
    mint(_report("sqli-001"))
    mint(_report("sqli-001"))                                   # same finding identity → same file
    assert len(read_proofs(tmp_path)) == 1


def test_a_report_without_a_capture_mints_nothing(tmp_path):
    mint = build_report_mint(run_dir=tmp_path, signers=SIGNERS, engagement_slug="acme")
    assert mint({"id": "x", "bug_class": "sqli_attempt", "poc_script_code": "print('x')"}) is None
    assert read_proofs(tmp_path) == []                          # the model's free text alone is never a proof


def test_sink_allows_and_mints_then_persists(tmp_path):
    mint = build_report_mint(run_dir=tmp_path, signers=SIGNERS, engagement_slug="acme")
    sink = ProofSink(quarantine_dir=str(tmp_path / "q"), mint=mint)
    out = sink(_report("sqli-001"))
    assert out.gate == "allow" and out.minted
    assert len(read_proofs(tmp_path)) == 1


def test_sink_denies_dangerous_poc_and_persists_no_proof(tmp_path):
    mint = build_report_mint(run_dir=tmp_path, signers=SIGNERS, engagement_slug="acme")
    sink = ProofSink(quarantine_dir=str(tmp_path / "q"), mint=mint)
    out = sink(_report("evil", poc="rm -rf / --no-preserve-root"))   # destructive → content-gate DENY
    assert out.gate == "deny"
    assert read_proofs(tmp_path) == []                          # a denied PoC never becomes a persisted proof
