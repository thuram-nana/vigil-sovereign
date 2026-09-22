"""
Content-Security-Policy — the TWO distinct sound claims (Wave 2.4), verified deterministically
without a browser and without network:

  (a) ACHIEVED CSP BYPASS (``csp_bypass`` -> DOM_EXECUTION, guarded by ``csp_purports_to_block``):
      an injected canary that EXECUTED in a real DOM DESPITE a retained enforced CSP whose
      script-src purported to block it. Here the execution signal (binding calls) is supplied
      directly so the GUARD logic + oracle wiring + retained-context re-fire / tamper-reject are
      proven without a browser (the live end-to-end path is in ``test_csp_bypass_browser.py``).
  (b) PERMISSIVE-POLICY POSTURE-FACT (``csp_posture`` -> CSP_POSTURE): a pure parse over the
      RETAINED enforced CSP header, no browser. ``capture_csp_posture`` takes the retained headers
      directly, so the FACT / non-fire is proven fully offline.

The crux this file pins:
  * a NO-CSP / PERMISSIVE / REPORT-ONLY execution is plain DOM-XSS and must NEVER mint a bypass;
  * a STRICT policy that BLOCKS execution (no binding call) must never mint;
  * a permissive header FACTs the posture claim, a well-formed / nonce-neutralized / report-only /
    script-src-less header must NOT;
  * both retained contexts re-fire offline and reject tamper (a mutated canary, or a header edited
    to a permissive/well-formed value, no longer confirms).
"""

from __future__ import annotations

from email.message import Message

from framework.v2.scanner.csp_bypass import (
    CspBypassResult,
    _BINDING,
    capture_csp_posture,
    csp_bypass_finding,
    csp_posture_finding,
)
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.models import OracleKind
from framework.v2.verify.oracles import (
    csp_posture_oracle,
    csp_purports_to_block,
    dom_execution_csp_bypass_oracle,
)
from framework.v2.report.standards import known_mapped_classes
from framework.v2.verify.verifier import (
    BUG_CLASS_ORACLES,
    OracleVerifier,
    normalize_bug_class,
)

_CANARY = "cspb00deadbeefca"
_RESTRICTIVE = f"script-src 'self' 'nonce-staticNonceABC'"          # no unsafe-inline, no wildcard
_STRICT = "script-src 'self'"
_PERMISSIVE = "script-src 'unsafe-inline'; object-src 'none'"
_WELLFORMED = "script-src 'nonce-staticNonceABC'; object-src 'none'"
_NEUTRALIZED = "script-src 'nonce-staticNonceABC' 'unsafe-inline'"


def _headers(csp: str | None, *, report_only: bool = False) -> Message:
    m = Message()
    if csp is not None:
        m["Content-Security-Policy-Report-Only" if report_only else "Content-Security-Policy"] = csp
    return m


# ---------------------------------------------------------------------------
# 1. Oracle wiring + registry hygiene
# ---------------------------------------------------------------------------


def test_csp_classes_route_to_the_right_oracles() -> None:
    assert BUG_CLASS_ORACLES["csp_posture"] == (OracleKind.CSP_POSTURE,)
    assert BUG_CLASS_ORACLES["csp_bypass"][0] is OracleKind.DOM_EXECUTION
    assert OracleKind.CSP_POSTURE not in BUG_CLASS_ORACLES["csp_bypass"]  # achieved bypass adds no kind


def test_csp_aliases_fold_onto_the_right_canonical_key() -> None:
    for spelling in ("content_security_policy", "csp_weakness", "csp_misconfiguration",
                     "csp_unsafe_inline", "permissive_csp"):
        assert normalize_bug_class(spelling) == "csp_posture"
    for spelling in ("csp_bypass_xss", "content_security_policy_bypass"):
        assert normalize_bug_class(spelling) == "csp_bypass"


def test_both_csp_classes_are_standards_mapped() -> None:
    # known_mapped_classes() == frozenset(BUG_CLASS_ORACLES) is enforced globally; assert our rows.
    assert "csp_posture" in known_mapped_classes()
    assert "csp_bypass" in known_mapped_classes()


# ---------------------------------------------------------------------------
# 2. Permissive-policy POSTURE oracle (pure parse)
# ---------------------------------------------------------------------------


def _posture(csp: str, *, report_only: bool = False):
    return csp_posture_oracle(
        {"rule": "permissive_script_src", "url": "http://t/", "header": csp, "report_only": report_only})


def test_posture_fires_on_a_real_permissive_weakness() -> None:
    assert _posture(_PERMISSIVE).fired                       # unsafe-inline, no nonce/hash
    assert _posture("script-src *").fired                    # wildcard
    assert _posture("script-src http:").fired                # scheme source
    assert _posture("script-src 'self' data:").fired         # data: scheme
    assert _posture("script-src 'self' 'unsafe-eval'").fired # unsafe-eval
    assert _posture("default-src 'unsafe-inline'").fired      # falls back to default-src


def test_posture_is_silent_on_a_hardened_or_uninformative_policy() -> None:
    assert not _posture(_WELLFORMED).fired                    # nonce-based, no permissive token
    assert not _posture(_NEUTRALIZED).fired                   # unsafe-inline NEUTRALIZED by a nonce
    assert not _posture(_STRICT).fired                        # script-src 'self' only
    assert not _posture(_PERMISSIVE, report_only=True).fired  # report-only enforces nothing
    assert not _posture("frame-ancestors 'none'").fired       # no effective script-src to judge
    assert not _posture("").fired                             # no header -> REFUSE, not fire


def test_capture_csp_posture_facts_a_permissive_header_and_reverifies() -> None:
    res = capture_csp_posture("http://t/", response_headers=_headers(_PERMISSIVE))
    assert res.is_weak and res.weaknesses
    outcome = OracleVerifier().confirm(res.context.to_verifier_context())
    assert outcome.confirmed
    assert any(s.kind is OracleKind.CSP_POSTURE and s.fired for s in outcome.signals)
    rebuilt = FindingContext.model_validate(res.context.model_dump())
    assert OracleVerifier().confirm(rebuilt.to_verifier_context()).confirmed


def test_capture_csp_posture_is_silent_on_the_benign_twins() -> None:
    for csp in (_WELLFORMED, _NEUTRALIZED, _STRICT):
        res = capture_csp_posture("http://t/", response_headers=_headers(csp))
        assert not res.is_weak
        assert not OracleVerifier().confirm(res.context.to_verifier_context()).confirmed
    # report-only permissive header: parsed, but never mints
    res = capture_csp_posture("http://t/", response_headers=_headers(_PERMISSIVE, report_only=True))
    assert res.report_only and not res.is_weak
    assert not OracleVerifier().confirm(res.context.to_verifier_context()).confirmed


def test_posture_context_rejects_a_header_tampered_to_well_formed() -> None:
    res = capture_csp_posture("http://t/", response_headers=_headers(_PERMISSIVE))
    ctx = res.context.model_dump()
    ctx["csp_control"]["header"] = _WELLFORMED           # attacker edits the retained header
    tampered = FindingContext.model_validate(ctx)
    assert not OracleVerifier().confirm(tampered.to_verifier_context()).confirmed


# ---------------------------------------------------------------------------
# 3. The achieved-bypass GUARD (csp_purports_to_block) + guarded oracle
# ---------------------------------------------------------------------------


def test_guard_only_true_for_a_restrictive_enforced_policy() -> None:
    assert csp_purports_to_block({"header": _RESTRICTIVE, "report_only": False})
    assert csp_purports_to_block({"header": _STRICT, "report_only": False})
    # permissive / absent / report-only never purport to block
    assert not csp_purports_to_block({"header": _PERMISSIVE, "report_only": False})
    assert not csp_purports_to_block({"header": "script-src *", "report_only": False})
    assert not csp_purports_to_block({"header": _RESTRICTIVE, "report_only": True})
    assert not csp_purports_to_block({"header": "", "report_only": False})
    assert not csp_purports_to_block({"header": "frame-ancestors 'none'", "report_only": False})


def test_guarded_oracle_fires_only_on_execution_despite_a_blocking_policy() -> None:
    # executed under a RESTRICTIVE policy -> genuine bypass
    sig = dom_execution_csp_bypass_oracle(
        [f"{_BINDING}:{_CANARY}"], _CANARY, {"header": _RESTRICTIVE, "report_only": False})
    assert sig.fired and sig.kind is OracleKind.DOM_EXECUTION and sig.observed.get("csp_bypassed") is True
    # executed under NO CSP -> plain DOM-XSS, NOT a bypass
    assert not dom_execution_csp_bypass_oracle(
        [f"{_BINDING}:{_CANARY}"], _CANARY, {"header": "", "report_only": False}).fired
    # executed under a PERMISSIVE CSP -> plain DOM-XSS, NOT a bypass
    assert not dom_execution_csp_bypass_oracle(
        [f"{_BINDING}:{_CANARY}"], _CANARY, {"header": _PERMISSIVE, "report_only": False}).fired
    # executed under a REPORT-ONLY CSP -> not enforced, NOT a bypass
    assert not dom_execution_csp_bypass_oracle(
        [f"{_BINDING}:{_CANARY}"], _CANARY, {"header": _RESTRICTIVE, "report_only": True}).fired
    # NO execution (strict policy blocked it) -> never fires
    assert not dom_execution_csp_bypass_oracle(
        [], _CANARY, {"header": _RESTRICTIVE, "report_only": False}).fired


# ---------------------------------------------------------------------------
# 4. Retained achieved-bypass context: re-fires + tamper-rejects
# ---------------------------------------------------------------------------


def _bypass_result(*, executed: bool, csp: str, report_only: bool = False) -> CspBypassResult:
    calls = [f"{_BINDING}:{_CANARY}"] if executed else []
    ctx = FindingContext.from_csp_bypass(calls, _CANARY, csp, report_only=report_only, bug_class="csp_bypass")
    return CspBypassResult(
        payload="<script nonce=x>…</script>", canary=_CANARY, injection="query:q",
        csp_header=csp, report_only=report_only, executed=executed, context=ctx)


def test_planted_bypass_context_confirms_and_round_trips() -> None:
    r = _bypass_result(executed=True, csp=_RESTRICTIVE)
    assert r.bypassed and r.csp_purported_to_block
    outcome = OracleVerifier().confirm(r.context.to_verifier_context())
    assert outcome.confirmed
    assert any(s.kind is OracleKind.DOM_EXECUTION and s.fired for s in outcome.signals)
    rebuilt = FindingContext.model_validate(r.context.model_dump())
    assert OracleVerifier().confirm(rebuilt.to_verifier_context()).confirmed


def test_execution_on_a_no_csp_page_is_not_a_bypass() -> None:
    r = _bypass_result(executed=True, csp="")
    assert r.executed and not r.bypassed          # executed, but no policy purported to block
    assert not OracleVerifier().confirm(r.context.to_verifier_context()).confirmed


def test_execution_under_a_permissive_csp_is_not_a_bypass() -> None:
    r = _bypass_result(executed=True, csp=_PERMISSIVE)
    assert r.executed and not r.bypassed
    assert not OracleVerifier().confirm(r.context.to_verifier_context()).confirmed


def test_strict_policy_that_blocks_never_mints() -> None:
    r = _bypass_result(executed=False, csp=_STRICT)
    assert not r.executed and not r.bypassed
    assert not OracleVerifier().confirm(r.context.to_verifier_context()).confirmed


def test_tampered_canary_no_longer_confirms_a_bypass() -> None:
    r = _bypass_result(executed=True, csp=_RESTRICTIVE)
    ctx = r.context.model_dump()
    ctx["dom_canary"] = "cspb99000000dead"        # a canary the binding call never carried
    assert not OracleVerifier().confirm(FindingContext.model_validate(ctx).to_verifier_context()).confirmed


def test_tampered_csp_header_to_permissive_no_longer_confirms_a_bypass() -> None:
    # the strongest tamper: keep the real execution, but edit the retained CSP to a PERMISSIVE
    # value so the guard would no longer treat it as a bypass — must not confirm offline.
    r = _bypass_result(executed=True, csp=_RESTRICTIVE)
    ctx = r.context.model_dump()
    ctx["csp_block_control"]["header"] = _PERMISSIVE
    assert not OracleVerifier().confirm(FindingContext.model_validate(ctx).to_verifier_context()).confirmed


# ---------------------------------------------------------------------------
# 5. Findings carry the retained oracle context
# ---------------------------------------------------------------------------


def test_findings_carry_a_reverifiable_oracle_context() -> None:
    posture = csp_posture_finding(capture_csp_posture("http://t/", response_headers=_headers(_PERMISSIVE)))
    assert posture["bug_class"] == "csp_posture"
    assert OracleVerifier().confirm(posture["oracle_context"]).confirmed

    bypass = csp_bypass_finding(_bypass_result(executed=True, csp=_RESTRICTIVE))
    assert bypass["bug_class"] == "csp_bypass"
    assert OracleVerifier().confirm(bypass["oracle_context"]).confirmed
