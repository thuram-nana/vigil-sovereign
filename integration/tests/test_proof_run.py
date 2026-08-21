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


# ---- INV 6/8 gate: an error-signature FACT must bind the exploit REQUEST -----------------------------

def _errsig_capture(*, with_request: bool):
    """An error-signature capture whose RESPONSE carries a datastore error the oracle fires on. With
    ``with_request`` it also binds the exploit REQUEST bytes (inv 8); without, it is response-only."""
    ex = {"channel": "error_signature", "role": "mutated", "response_bytes_ref": "resp",
          "status": 500, "bug_class": "error_based_sqli"}
    blobs = {"resp": b"HTTP/1.1 500\r\n\r\nORA-00933: SQL command not properly ended"}
    if with_request:
        ex["request_bytes_ref"] = "req"
        blobs["req"] = b"GET /items?id=1%27 HTTP/1.1\r\nHost: t\r\n\r\n"
    return {"exchanges": [ex], "blobs": blobs}


def test_error_signature_without_a_bound_request_stays_a_lead(tmp_path):
    """INV 6/8: a datastore-error RESPONSE with no bound request must NOT mint a FACT — the certificate
    would record a response with no record of what was sent, which VIGIL cannot attribute. The mint declines
    (returns None → the finding stays a LEAD) BEFORE minting."""
    mint = build_report_mint(run_dir=tmp_path, signers=SIGNERS, engagement_slug="acme")
    res = mint({"id": "e1", "bug_class": "error_based_sqli", CAPTURE_KEY: _errsig_capture(with_request=False)})
    assert res is None, "an error-signature capture with no bound request minted instead of staying a LEAD"


def test_error_signature_with_a_bound_request_can_mint(tmp_path):
    """The gate lets a request-bound error-signature capture through — the certificate then binds request +
    response (inv 8). Reverting the request binding turns this into the LEAD above."""
    mint = build_report_mint(run_dir=tmp_path, signers=SIGNERS, engagement_slug="acme")
    res = mint({"id": "e2", "bug_class": "error_based_sqli", CAPTURE_KEY: _errsig_capture(with_request=True)})
    assert res is not None, "the gate blocked a request-bound error-signature capture from minting"
    assert getattr(res, "is_fact", False), "a request-bound datastore-error capture did not mint a FACT"


def test_error_signature_role_bypass_is_closed(tmp_path):
    """RED-PEN regression: the oracle adjudicates ``_by_role(exs,'mutated') or exs[0]`` — so a role="" (or
    any non-'mutated') error-signature exchange with NO bound request is still adjudicated. The gate must
    select the SAME observed exchange the oracle does, not a literal role=='mutated' filter, and decline."""
    mint = build_report_mint(run_dir=tmp_path, signers=SIGNERS, engagement_slug="acme")
    for role in ("", "q", "observed"):
        cap = {"exchanges": [{"channel": "error_signature", "role": role, "response_bytes_ref": "resp",
                              "status": 500, "bug_class": "error_based_sqli"}],
               "blobs": {"resp": b"HTTP/1.1 500\r\n\r\nORA-00933: SQL command not properly ended"}}
        res = mint({"id": f"e-role-{role or 'empty'}", "bug_class": "error_based_sqli", CAPTURE_KEY: cap})
        assert res is None, f"role={role!r} error-signature capture with no request minted instead of a LEAD"


def test_error_signature_dangling_or_whitespace_request_ref_is_closed(tmp_path):
    """RED-PEN regression: the gate must require the request to RESOLVE to non-empty bytes, not merely be a
    non-empty ref STRING — a dangling ref (no blob) or a whitespace-only ref materializes nothing."""
    mint = build_report_mint(run_dir=tmp_path, signers=SIGNERS, engagement_slug="acme")
    resp = b"HTTP/1.1 500\r\n\r\nORA-00933: SQL command not properly ended"
    cases = [
        ("dangling", {"resp": resp}, "req"),                 # request_bytes_ref='req' but no 'req' blob
        ("ws-bytes", {"resp": resp, "req": b"   "}, "req"),   # resolves to whitespace-only bytes
        ("ws-ref", {"resp": resp}, "   "),                    # the ref itself is whitespace → no blob
    ]
    for name, blobs, ref in cases:
        cap = {"exchanges": [{"channel": "error_signature", "role": "mutated", "response_bytes_ref": "resp",
                              "request_bytes_ref": ref, "status": 500, "bug_class": "error_based_sqli"}],
               "blobs": blobs}
        res = mint({"id": f"e-{name}", "bug_class": "error_based_sqli", CAPTURE_KEY: cap})
        assert res is None, f"{name}: an unresolvable/whitespace request ref minted instead of a LEAD"
