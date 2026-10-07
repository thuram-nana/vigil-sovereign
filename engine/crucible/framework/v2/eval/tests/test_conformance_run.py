"""Lane C / C2 — the signed conformance run is green, offline-verifiable, and byte-stable.

These tests gate the whole C2 deliverable:
  * every frozen bundle re-verifies SOUND with the two STANDALONE verifiers and its verdict re-derives;
  * the FULL tamper battery is REFUSED (a single slip fails the run);
  * the C1 differential parity holds (standalone kernel == real oracle);
  * both standalone verifiers are zero-VIGIL (AST over the import graph);
  * the committed signed scorecard verifies OFFLINE three independent ways, including the zero-VIGIL
    verify_vf.verify_threshold over the same canonical bytes; and
  * minting the corpus + building the scorecard is DETERMINISTIC — byte-identical to what is committed
    (so a re-run in CI, or by a third party, reproduces the exact artifacts).
"""
from __future__ import annotations

import json
from pathlib import Path

from framework.v2.eval import conformance_run as C


def test_conformance_run_is_green():
    res = C.conformance_run()
    corpus, parity, zv = res["corpus"], res["parity"], res["zero_vigil"]
    assert corpus["all_families_sound"], [f for f in corpus["families"] if not f["sound"]]
    assert corpus["families_total"] >= 10  # a sound bundle per fact-capable general family
    assert corpus["all_tampers_refused"], corpus
    assert corpus["tamper_total"] == corpus["families_total"] * 6
    assert parity["parity_holds"], parity
    assert parity["oracle_case_agree"] == parity["oracle_case_total"] > 0
    assert parity["dispatch_agree"] == parity["dispatch_total"] > 0
    assert zv["zero_vigil"], zv
    assert res["scorecard"]["green"] is True


def test_every_family_sound_and_tampers_refused():
    corpus = C.run_frozen_corpus()
    for fam in corpus["families"]:
        assert fam["pcf_sound"], fam["family"]            # verify_pcf: authentic + bound + pin
        assert fam["reproduced"] and fam["re_derived_fired"], fam["family"]  # verify_vf re-derivation
        assert not fam["unported_keys"], (fam["family"], fam["unported_keys"])
        assert fam["tampers_all_refused"], fam
        kinds = {c["tamper"] for c in fam["tampers"]}
        assert {"flip-claim-class", "strip-signatures", "tamper-oracle-context-value",
                "flip-signature-byte", "wrong-trust-root-pin", "benign-retained-value"} <= kinds


def test_committed_scorecard_verifies_offline():
    offline = C.verify_scorecard_offline()
    assert offline["framework_verify_scorecard"] is True
    assert offline["pin_matches"] is True
    assert offline["standalone_verify_vf_threshold"] is True   # zero-VIGIL party can verify
    assert offline["offline_ok"] is True


def test_both_standalone_verifiers_are_zero_vigil():
    zv = C.run_zero_vigil()
    assert zv["verify_vf_offenders"] == [], zv
    assert zv["verify_pcf_offenders"] == [], zv


def test_corpus_mint_is_deterministic_byte_identical(tmp_path):
    """Re-mint into a scratch dir and compare every file byte-for-byte to the committed corpus."""
    out = tmp_path / "corpus"
    C.mint_corpus(out)
    committed = C._CORPUS_DIR
    for p in sorted(committed.glob("*.pcf.json")):
        assert (out / p.name).read_bytes() == p.read_bytes(), f"corpus drift: {p.name}"
    # the trust root is re-minted beside the committed one (same path), so re-read it as the control
    assert json.loads((committed / "trust-root.json").read_text())["threshold"] == 1


def test_scorecard_content_and_signature_are_deterministic(tmp_path):
    """The scorecard CONTENT + the fixture signature re-derive byte-identically to what is committed."""
    res = C.conformance_run()
    sc_path = tmp_path / "conformance-scorecard.json"
    C.sign_scorecard_file(res["scorecard"], scorecard_path=sc_path)
    committed = C._SCORECARD
    assert sc_path.read_bytes() == committed.read_bytes(), "scorecard content drift"
    # fixture key is deterministic → the signature envelope is byte-identical too
    assert (sc_path.with_suffix(".sig.json").read_bytes()
            == committed.with_suffix(".sig.json").read_bytes()), "scorecard signature drift"
    assert (sc_path.with_suffix(".fingerprint.txt").read_bytes()
            == committed.with_suffix(".fingerprint.txt").read_bytes())


def test_committed_scorecard_matches_a_fresh_run():
    """The committed scorecard JSON equals a freshly-built scorecard over the committed corpus (so a
    stale or hand-edited scorecard is caught)."""
    fresh = C.build_scorecard(C.run_frozen_corpus(), C.run_parity(), C.run_zero_vigil())
    committed = json.loads(C._SCORECARD.read_text(encoding="utf-8"))
    assert fresh == committed, "committed scorecard is stale vs a fresh run"


def test_operator_key_path_signs_and_verifies(tmp_path):
    """FATAL-2: an operator key passed IN signs the SAME content and verifies offline (the published-
    attestation path), independent of the fixture key."""
    from vigil_core.crypto import generate_keypair

    kp = generate_keypair()
    res = C.conformance_run()
    sc_path = tmp_path / "op-scorecard.json"
    C.sign_scorecard_file(res["scorecard"], signing_key_b64=kp.private_key_b64,
                          key_id="operator", scorecard_path=sc_path)
    offline = C.verify_scorecard_offline(sc_path)
    assert offline["offline_ok"] is True
    # same CONTENT as the committed scorecard (only the trust root / signature differ)
    assert sc_path.read_bytes() == C._SCORECARD.read_bytes()
