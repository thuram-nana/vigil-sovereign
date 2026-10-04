"""M3 — STATIC_RULE class-relabel soundness (anti-relabel binding).

A producer-controlled free ``bug_class`` must NOT be able to mint a signed FACT (PCF + standards "proven")
for a class the STATIC_RULE oracle is HARD-CODED to never prove. The oracle re-derives the proven property
SOLELY from the retained ``rule_id``; the canonical class is therefore DERIVED from the rule_id, and a
caller-supplied label that DISAGREES is a relabel that must be refused.

The exact audit repro: ``from_code_region(path, line, broken_crypto_src, 'broken-crypto-invocation',
bug_class='static_taint')`` used to export via ``to_pcf`` and verify ``verified=True`` with
``claim.class == static_taint`` — a broken-crypto re-fire laundered into a proof of the LEAD-only
``static_taint`` class. These controls pin the three independent refusals:

  * construction (``FindingContext.from_code_region``) REFUSES a mismatched bug_class;
  * the re-execution boundary (``reverify_context``) re-derives the class from ``rule_id`` and DEMOTES a
    relabel — so ``to_pcf`` refuses to export, ``verify_pcf`` rejects at the oracle step, and
    ``report.standards.map_finding`` never grades it proven;
  * PCF step-5 (``oracle_confirms_class``) knows STATIC_RULE is a confirmer ONLY for the FACT-capable
    static classes, never the LEAD-only ones.

The consistent path (broken-crypto rule + broken-crypto class) is the positive control: it still mints,
exports, verifies and grades proven exactly as before.
"""

from __future__ import annotations

import pytest

from framework.v2.entitlement.crypto import generate_keypair
from framework.v2.entitlement.models import AuthorizerKey, TrustRoot
from framework.v2.evidence.certify import build_certificate, sign_certificate, verify_certificate
from framework.v2.evidence.pcf import _SIG_DOMAIN, _project_view, PcfExportError, to_pcf, verify_pcf
from framework.v2.report.standards import map_finding
from framework.v2.verify.adapter import _STATIC_RULE_BUG_CLASS, FindingContext
from framework.v2.verify.oracles import _LEAD_ONLY_RULE_IDS
from framework.v2.verify.reverify import reverify_context
from framework.v2.verify.verifier import (
    _STATIC_RULE_LEAD_ONLY_CLASSES, OracleVerifier, oracle_confirms_class)

# A region the STATIC_RULE oracle genuinely FIRES on (a real md5 invocation) — the proof is a broken-crypto
# code property. The relabel carries this proof under the LEAD-only `static_taint` label.
_BROKEN_CRYPTO_SRC = "import hashlib\ndef sign(x):\n    return hashlib.md5(x).hexdigest()\n"
_TAINT_SRC = 'import os\ndef run():\n    os.system(request.args["c"])\n'


def _relabel_oc() -> dict:
    """A relabelled context built DIRECTLY (bypassing from_code_region's construction-time guard) to
    simulate a producer that assembles the context itself, or a pre-fix certificate: a broken-crypto region
    the oracle fires on, carrying the FLIPPED, LEAD-only `static_taint` label."""
    return FindingContext(
        bug_class="static_taint",
        static_rule={"rule_id": "broken-crypto-invocation", "source": _BROKEN_CRYPTO_SRC,
                     "language": "python", "path": "app/mod.py", "line": 3},
    ).to_verifier_context()


def _consistent_oc() -> dict:
    """A CONSISTENT static context via the supported API — class derived from the rule_id."""
    return FindingContext.from_code_region(
        "app/mod.py", 3, _BROKEN_CRYPTO_SRC, "broken-crypto-invocation").to_verifier_context()


def _finding(oc: dict, bug_class: str, *, slug: str) -> dict:
    return {"check_id": slug, "bug_class": bug_class, "confirmed_by": "static_rule",
            "confidence": 0.9, "oracle_context": oc, "insertion_point": "app/mod.py:3"}


def _map_input(oc: dict, bug_class: str, slug: str) -> dict:
    return {"finding_slug": slug, "title": "static finding", "severity": "Medium",
            "bug_class": bug_class, "surface": "app/mod.py:3", "summary": "retained source region",
            "verified_by_oracle": True, "oracle_kind": "static_rule", "confidence": 0.9,
            "critique_status": "confirmed", "oracle_context": oc}


def _trust_root(threshold: int = 2, n: int = 3):
    keys = [generate_keypair() for _ in range(n)]
    tr = TrustRoot(schema_version=1, threshold=threshold, authorizers=[
        AuthorizerKey(key_id=f"gov-{i}", name=f"A{i}", public_key_b64=k.public_key_b64)
        for i, k in enumerate(keys)])
    signers = [(f"gov-{i}", k.private_key_b64) for i, k in enumerate(keys)]
    return tr, signers


def _project_pcf(signed, oc: dict) -> dict:
    """Project a signed certificate into the PCF wire view WITHOUT to_pcf's reproducibility guard — the
    only way to obtain a relabel PCF to feed verify_pcf (to_pcf itself refuses it). Mirrors to_pcf's body."""
    cert = signed.certificate
    view = _project_view(cert, oc)
    view["signature"] = {"scheme": "ed25519", "domain": _SIG_DOMAIN,
                         "signatures": [{"key_id": s.key_id, "sig": s.signature_b64} for s in signed.signatures]}
    view["_crucible"] = {"certificate": cert.model_dump(mode="json")}
    return view


def _signed_relabel_cert(oc: dict, signers):
    """A signed RELABEL certificate obtained PAST the S2 build-time class-bind (which now REFUSES a relabel at
    birth — see ``test_build_certificate_refuses_a_relabel_at_the_mint``). Mirrors a pre-S2 / hand-assembled
    certificate: build it CONSISTENT (its rule_id's own class), then relabel the ``bug_class`` on the model and
    re-sign. This keeps the DOWNSTREAM to_pcf / verify_pcf relabel refusals under test — the point of this
    module — now that the relabel can no longer be minted through build_certificate directly."""
    base = build_certificate(_finding(oc, "static_broken_crypto", slug="relabel"))
    relabelled = base.model_copy(update={"bug_class": "static_taint"})
    return sign_certificate(relabelled, signers[:2])


# ---------------------------------------------------------------------------
# (1) CONSTRUCTION — from_code_region refuses a mismatched bug_class.
# ---------------------------------------------------------------------------

def test_from_code_region_refuses_a_bug_class_that_disagrees_with_rule_id():
    # the exact audit repro: a broken-crypto region relabelled `static_taint` (a LEAD-only class).
    with pytest.raises(ValueError):
        FindingContext.from_code_region("app/mod.py", 3, _BROKEN_CRYPTO_SRC,
                                        "broken-crypto-invocation", bug_class="static_taint")
    # the reverse direction (a LEAD-only rule relabelled to a FACT-capable class) is refused too.
    with pytest.raises(ValueError):
        FindingContext.from_code_region("app/mod.py", 3, _TAINT_SRC,
                                        "direct-taint", bug_class="static_broken_crypto")
    # a FACT<->FACT relabel (broken-crypto proof labelled insecure-flag) is refused.
    with pytest.raises(ValueError):
        FindingContext.from_code_region("app/mod.py", 3, _BROKEN_CRYPTO_SRC,
                                        "broken-crypto-invocation", bug_class="static_insecure_flag")
    # an out-of-vocabulary rule_id has no canonical class to alias -> any explicit bug_class is refused.
    with pytest.raises(ValueError):
        FindingContext.from_code_region("app/mod.py", 3, "x = 1\n", "totally-made-up", bug_class="static_taint")


def test_from_code_region_accepts_only_an_alias_of_the_same_canonical_class():
    # the no-override legit path derives the canonical class (unchanged behaviour).
    ctx = FindingContext.from_code_region("app/mod.py", 3, _BROKEN_CRYPTO_SRC, "broken-crypto-invocation")
    assert ctx.bug_class == "static_broken_crypto"
    # an ALIAS spelling that normalises to the SAME canonical class is accepted, and normalised to canonical.
    aliased = FindingContext.from_code_region("app/mod.py", 3, _BROKEN_CRYPTO_SRC,
                                              "broken-crypto-invocation", bug_class="static_weak_crypto")
    assert aliased.bug_class == "static_broken_crypto"


# ---------------------------------------------------------------------------
# (2) RE-EXECUTION BOUNDARY — reverify_context re-derives the class from rule_id.
# ---------------------------------------------------------------------------

def test_reverify_demotes_a_relabel_and_reconfirms_a_consistent_static_fact():
    relabel = _relabel_oc()
    rr = reverify_context(relabel, bug_class="static_taint")
    assert not rr.ok and not rr.reproduced, "a relabelled static context must NOT re-confirm"
    assert "does not match" in rr.note
    # a relabel claimed under its TRUE (rule_id-derived) class also cannot ride the broken-crypto fire into a
    # LEAD-only FACT: the oracle is fail-closed for direct-taint, so even the honest class does not reproduce.
    taint_relabel = FindingContext(
        bug_class="static_taint",
        static_rule={"rule_id": "direct-taint", "source": _TAINT_SRC,
                     "language": "python", "path": "a.py", "line": 1}).to_verifier_context()
    assert not reverify_context(taint_relabel, bug_class="static_taint").ok
    # the consistent static fact re-fires and binds its own (rule_id-derived) class.
    ok = reverify_context(_consistent_oc(), bug_class="static_broken_crypto")
    assert ok.ok and ok.reproduced and ok.confirmed_by == "static_rule"


# ---------------------------------------------------------------------------
# (3) PCF EXPORT + VERIFY — to_pcf refuses a relabel; verify_pcf rejects at the oracle step.
# ---------------------------------------------------------------------------

def test_build_certificate_refuses_a_relabel_at_the_mint():
    # S2 (Lane S): the EARLIEST refusal — build_certificate re-checks oracle_confirms_class and will not even
    # BUILD a cert whose confirmed_by (static_rule) does not prove the claimed LEAD-only class (static_taint).
    with pytest.raises(ValueError, match="not a valid confirmer"):
        build_certificate(_finding(_relabel_oc(), "static_taint", slug="relabel"))


def test_to_pcf_refuses_to_export_a_relabel_and_exports_a_consistent_fact():
    _tr, signers = _trust_root()
    relabel = _relabel_oc()
    signed = _signed_relabel_cert(relabel, signers)   # past the S2 build guard, to test to_pcf's own refusal
    with pytest.raises(PcfExportError):
        to_pcf(signed, oracle_context=relabel)
    # positive control: a consistent static fact exports, byte-faithful to the signed cert.
    consistent = _consistent_oc()
    signed_ok = sign_certificate(
        build_certificate(_finding(consistent, "static_broken_crypto", slug="ok")), signers[:2])
    pcf = to_pcf(signed_ok, oracle_context=consistent)
    assert pcf["claim"]["class"] == "static_broken_crypto"


def test_verify_pcf_rejects_a_relabel_at_the_oracle_step_and_verifies_a_consistent_fact():
    tr, signers = _trust_root()
    relabel = _relabel_oc()
    signed = _signed_relabel_cert(relabel, signers)   # past the S2 build guard (see dedicated test above)
    pcf = _project_pcf(signed, relabel)   # a hand-built / pre-fix PCF, past to_pcf's own guard
    r = verify_pcf(pcf, tr)
    assert not r.verified and r.step == "oracle", f"relabel PCF verified or wrong step: {r.step}: {r.reason}"
    # positive control: a consistent static fact verifies end to end.
    consistent = _consistent_oc()
    signed_ok = sign_certificate(
        build_certificate(_finding(consistent, "static_broken_crypto", slug="ok")), signers[:2])
    good = to_pcf(signed_ok, oracle_context=consistent)
    assert verify_pcf(good, tr).verified


# ---------------------------------------------------------------------------
# (4) STANDARDS GRADING — map_finding never grades a relabel proven.
# ---------------------------------------------------------------------------

def test_map_finding_does_not_grade_a_relabel_proven_but_grades_a_consistent_fact():
    relabel = map_finding(_map_input(_relabel_oc(), "static_taint", "relabel"))
    assert relabel["graded"] != "fact" and relabel["is_fact"] is False
    assert relabel["status"] != "proven" and relabel["coverage_asserted"] is False
    assert relabel["controls"] is None
    # positive control: the consistent broken-crypto fact grades proven with the crypto CWEs.
    ok = map_finding(_map_input(_consistent_oc(), "static_broken_crypto", "ok"))
    assert ok["graded"] == "fact" and ok["status"] == "proven" and ok["coverage_asserted"] is True
    assert "CWE-327" in ok["controls"]["cwe"]


# ---------------------------------------------------------------------------
# (5) CLAIM-GROUNDED (PCF step 5) — oracle_confirms_class, + drift guard.
# ---------------------------------------------------------------------------

def test_oracle_confirms_class_static_rule_confirms_only_fact_capable_classes():
    assert oracle_confirms_class("static_rule", "static_broken_crypto") is True
    assert oracle_confirms_class("static_rule", "static_insecure_flag") is True
    # LEAD-only static classes: STATIC_RULE is NOT a confirmer (it provably never mints them).
    assert oracle_confirms_class("static_rule", "static_taint") is False
    assert oracle_confirms_class("static_rule", "static_insecure_randomness") is False
    # a non-STATIC_RULE oracle never confirms a static class.
    assert oracle_confirms_class("differential_response", "static_broken_crypto") is False


def test_static_lead_only_class_set_cannot_drift_from_the_oracle():
    """The class-level LEAD-only set is exactly the image of the oracle's LEAD-only rule_ids under the closed
    rule_id -> class map, so the two sources of truth can never diverge."""
    assert _STATIC_RULE_LEAD_ONLY_CLASSES == {
        _STATIC_RULE_BUG_CLASS[rid] for rid in _LEAD_ONLY_RULE_IDS}


# ---------------------------------------------------------------------------
# (6) MINT CHOKE (the 4th binding point) — verifier.confirm + the integration public mint.
#
# The prior three controls bound CONSTRUCTION, RE-EXEC, GRADE and EXPORT, but NOT the mint: a producer who
# assembles the oracle_context DIRECTLY (claimed == ctx bug_class == `static_taint`, inner rule_id =
# broken-crypto-invocation) and calls the PUBLIC mint (confirm_and_certify / certify_admitted,
# provenance="live_redrive") used to sign status="fact" for the LEAD-only `static_taint` class. These controls
# drive that exact public mint and pin the refusal.
# ---------------------------------------------------------------------------


def test_confirm_demotes_a_static_rule_relabel_at_the_mint_choke():
    """verifier.confirm (the single choke every mint path re-adjudicates through) DERIVES the authoritative
    class from the FIRED signal's own observed['rule_id'] and DEMOTES a relabel out of the confirming set — so
    a directly-assembled relabel context is NOT confirmed, while the consistent context still confirms."""
    relabel = OracleVerifier().confirm(_relabel_oc())
    assert relabel.confirmed is False, "a directly-assembled static_rule relabel must NOT confirm at the mint choke"
    assert "anti-relabel" in relabel.rationale.lower() or "does not" in relabel.rationale.lower()
    # the STATIC_RULE oracle DID fire (the broken-crypto region is real) — the demotion is the class binding,
    # not a non-firing oracle: the fired signal is retained for audit.
    assert any(s.kind.value == "static_rule" and s.fired for s in relabel.signals)
    # the consistent context (class derived from the rule_id) still confirms under its OWN class.
    consistent = OracleVerifier().confirm(_consistent_oc())
    assert consistent.confirmed is True and consistent.bug_class == "static_broken_crypto"


def _mint():
    """The PUBLIC integration mint path (the no-hallucinated-findings choke). Imported lazily via importorskip
    so the engine-only (CRUCIBLE-core) CI job SKIPS these rather than failing; the offense leg has
    `integration` on the path and RUNS them."""
    oa = pytest.importorskip("vigil_integration.oracle_adapter")
    vd = pytest.importorskip("vigil_integration.live.verdict")
    return oa, vd


def test_public_mint_refuses_a_directly_assembled_static_rule_relabel():
    """NEGATIVE CONTROL (drives the PUBLIC mint directly — the gap the prior suite missed). A directly-
    assembled static_rule ctx with claimed == ctx bug_class == `static_taint` + inner rule_id
    broken-crypto-invocation must mint NO signed fact via confirm_and_certify OR certify_admitted, and the
    returned object must NOT reach web_redrive's `if r.is_fact:` true branch."""
    oa, vd = _mint()
    _tr, signers = _trust_root()
    finding = _finding(_relabel_oc(), "static_taint", slug="relabel-mint")

    # confirm_and_certify — the real mint choke. provenance="live_redrive" is a reproduced channel, so the
    # ONLY thing that can stop the signed fact is the class binding (not the provenance gate).
    r = oa.confirm_and_certify(finding, engagement_slug="m3", signers=signers, provenance="live_redrive")
    assert r.is_fact is False, "a static_rule relabel must NOT mint a signed fact at the public mint choke"
    assert r.status != "fact" and r.signed is None
    # web_redrive.py does `if r.is_fact: res.fact = r` — a False here means the relabel can never surface as a
    # fact on that render path (nor on engine.py's `is_fact and status == 'fact'` projection gate).
    assert r.is_fact is False

    # certify_admitted (the wrapper that production uses) refuses too: a FACT AdmittedVerdict + the same
    # relabel finding still yields a LEAD, because certify_admitted delegates to confirm_and_certify.
    admitted = vd.admit("error_signature.datastore_error", fired=True, conclusive=True,
                        observed={"channel_established": True})
    r2 = oa.certify_admitted(finding, admitted, engagement_slug="m3", signers=signers,
                             provenance="live_redrive")
    assert r2.is_fact is False and r2.status != "fact" and r2.signed is None


def test_public_mint_still_signs_a_consistent_static_broken_crypto():
    """POSITIVE CONTROL — a consistent static_broken_crypto (rule_id broken-crypto-invocation + class
    static_broken_crypto) STILL mints + signs + verifies, unchanged behaviour. The fired oracle re-fires for
    the CLAIM's own class, so the class binding is a no-op on the legit path."""
    oa, _vd = _mint()
    tr, signers = _trust_root()
    oc = _consistent_oc()
    finding = _finding(oc, "static_broken_crypto", slug="consistent-mint")
    r = oa.confirm_and_certify(finding, engagement_slug="m3", signers=signers[:2], provenance="live_redrive")
    assert r.is_fact is True and r.status == "fact"
    assert r.bug_class == "static_broken_crypto" and r.confirmed_by == "static_rule"
    assert r.signed is not None and r.signed.certificate.bug_class == "static_broken_crypto"
    assert len(r.signed.signatures) == 2
    # the signed certificate independently verifies (the mint is sound end to end, not merely labelled a fact).
    ok = verify_certificate(r.signed, oracle_context=oc, trust_root=tr)
    assert ok.ok, f"the consistent static fact must verify: {ok.reason}"
