"""W16-STD-5 — the three always-applicable constitution *client-side* posture-weakness oracles.

Constitution §V ("Client-side (XSS, CSRF, clickjacking, postMessage) — Always for browser apps") names
four always-applicable client-side classes. XSS already has an oracle; this file pins the other three,
each of which proves a MISSING/WEAK DEFENSE (a posture weakness) — NEVER an achieved-state exploit
(docs/DELIBERATE-REFUSALS.md refusal 8). Every test carries its NEGATIVE CONTROL in the same run: a
non-vulnerable page/handler/endpoint that HAS the defense is NOT confirmed; a genuinely-vulnerable one
that LACKS it IS. Plus the structural guard that every always-applicable constitution class maps to a
real oracle row (acceptance e) — which is RED without the three new BUG_CLASS_ORACLES rows.

Fail-without-fix: on the unfixed tree the three classes are out-of-vocabulary (`is_known_bug_class`
False) and no oracle exists, so `confirm_*_posture(<vulnerable>)` returns confirmed=False and the
structural test fails.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from framework.v2.verify import client_side_posture as cs
from framework.v2.verify.models import OracleKind
from framework.v2.verify.verifier import (
    BUG_CLASS_ORACLES,
    canonical_bug_class,
    canonical_oracle_for,
    is_known_bug_class,
)

_REPO = Path(__file__).resolve().parents[6]


# ---------------------------------------------------------------------------
# Clickjacking — missing framing defense (a pure header check). Positive + negative in one run.
# ---------------------------------------------------------------------------

def test_clickjacking_fires_only_when_no_framing_defense_is_present() -> None:
    # VULNERABLE: a real HTML response with NO X-Frame-Options and NO CSP frame-ancestors.
    vuln = cs.confirm_clickjacking_posture(
        cs.ingest_response_headers("https://app.example/dash",
                                   {"Content-Type": "text/html", "Server": "nginx"}))
    assert vuln.confirmed, vuln.rationale
    sig = next(s for s in vuln.signals if s.kind is OracleKind.CLICKJACKING_POSTURE)
    assert sig.fired and "NO framing defense" in sig.evidence

    # NEGATIVE CONTROLS: either defense present (on a framable HTML doc) → NOT confirmed.
    assert not cs.confirm_clickjacking_posture(
        cs.ingest_response_headers("https://x", {"Content-Type": "text/html", "X-Frame-Options": "DENY"})).confirmed
    assert not cs.confirm_clickjacking_posture(
        cs.ingest_response_headers("https://x", {"Content-Type": "text/html", "X-Frame-Options": "SAMEORIGIN"})).confirmed
    assert not cs.confirm_clickjacking_posture(
        cs.ingest_response_headers("https://x", {"Content-Type": "text/html; charset=utf-8",
                                                 "Content-Security-Policy": "frame-ancestors 'none'"})).confirmed
    # a permissive-but-declared frame-ancestors is a deliberate policy → stays a lead (no FACT).
    assert not cs.confirm_clickjacking_posture(
        cs.ingest_response_headers("https://x", {"Content-Type": "text/html",
                                                 "Content-Security-Policy": "default-src *; frame-ancestors https:"})).confirmed


def test_clickjacking_refuses_when_the_response_is_not_a_framable_document() -> None:
    # a JSON/API response with NO framing headers cannot be meaningfully clickjacked → REFUSE (no FP).
    assert not cs.confirm_clickjacking_posture(
        cs.ingest_response_headers("https://api/x", {"Content-Type": "application/json"})).confirmed
    # a framable XHTML document with no framing defense DOES fire (positive control for the ctype gate).
    assert cs.confirm_clickjacking_posture(
        cs.ingest_response_headers("https://x", {"Content-Type": "application/xhtml+xml"})).confirmed


def test_clickjacking_refuses_when_headers_were_not_observed() -> None:
    # No retained header set at all — absence must be OBSERVED, not assumed. REFUSE (not confirmed).
    assert not cs.confirm_clickjacking_posture({"rule": "framing_unprotected"}).confirmed
    assert not cs.confirm_clickjacking_posture({}).confirmed


# ---------------------------------------------------------------------------
# CSRF — anti-CSRF token not enforced (a control-differential). Positive + negative in one run.
# ---------------------------------------------------------------------------

def test_csrf_fires_only_when_token_removal_does_not_change_acceptance() -> None:
    # VULNERABLE: a state-changing request accepted 2xx with a valid token AND accepted 2xx with the
    # token removed/forged — the synchronizer token is not enforced.
    vuln = cs.confirm_csrf_posture(
        cs.ingest_csrf_differential("POST", "/api/profile",
                                    token_present_status=200, token_absent_status=200))
    assert vuln.confirmed, vuln.rationale
    sig = next(s for s in vuln.signals if s.kind is OracleKind.CSRF_POSTURE)
    assert sig.fired and "NOT enforced" in sig.evidence

    # NEGATIVE CONTROLS.
    # protected: stripping the token changed acceptance (403) → token IS enforced.
    assert not cs.confirm_csrf_posture(
        cs.ingest_csrf_differential("POST", "/api/profile", token_present_status=200, token_absent_status=403)).confirmed
    # safe method: enforcement not applicable → REFUSE.
    assert not cs.confirm_csrf_posture(
        cs.ingest_csrf_differential("GET", "/api/profile", token_present_status=200, token_absent_status=200)).confirmed
    # no working baseline: the valid-token control itself did not succeed → REFUSE.
    assert not cs.confirm_csrf_posture(
        cs.ingest_csrf_differential("POST", "/api/profile", token_present_status=500, token_absent_status=200)).confirmed


# ---------------------------------------------------------------------------
# postMessage — wildcard target-origin / missing origin check (static). Positive + negative in one run.
# ---------------------------------------------------------------------------

def test_postmessage_wildcard_send_fires_but_specific_origin_does_not() -> None:
    vuln = cs.confirm_postmessage_posture(
        cs.ingest_postmessage_handler("(function(){ top.postMessage(secretState, '*'); })()"))
    assert vuln.confirmed, vuln.rationale
    # NEGATIVE CONTROL: a send to a SPECIFIC origin is not a weakness.
    assert not cs.confirm_postmessage_posture(
        cs.ingest_postmessage_handler("top.postMessage(secretState, 'https://trusted.example')")).confirmed


def test_postmessage_missing_origin_check_fires_but_a_present_one_does_not() -> None:
    vuln = cs.confirm_postmessage_posture(
        cs.ingest_postmessage_handler(
            "window.addEventListener('message', function(e){ render(e.data.html); })",
            rule="no_origin_check"))
    assert vuln.confirmed, vuln.rationale
    sig = next(s for s in vuln.signals if s.kind is OracleKind.POSTMESSAGE_POSTURE)
    assert sig.fired and "ANY origin" in sig.evidence

    # NEGATIVE CONTROLS.
    # an origin check IS present → protected.
    assert not cs.confirm_postmessage_posture(
        cs.ingest_postmessage_handler(
            "window.addEventListener('message', function(e){ if(e.origin!=='https://t') return; render(e.data.html); })",
            rule="no_origin_check")).confirmed
    # the handler does not consume event.data → no untrusted payload acted on → no fire.
    assert not cs.confirm_postmessage_posture(
        cs.ingest_postmessage_handler(
            "window.addEventListener('message', function(e){ ping(); })", rule="no_origin_check")).confirmed


# ---------------------------------------------------------------------------
# (a) each class has a BUG_CLASS_ORACLES row and can ADJUDICATE an imported finding.
# ---------------------------------------------------------------------------

def test_each_client_side_class_has_a_bug_class_oracle_row() -> None:
    assert BUG_CLASS_ORACLES["clickjacking"] == (OracleKind.CLICKJACKING_POSTURE,)
    assert BUG_CLASS_ORACLES["csrf"] == (OracleKind.CSRF_POSTURE,)
    assert BUG_CLASS_ORACLES["postmessage"] == (OracleKind.POSTMESSAGE_POSTURE,)


def test_confirm_seam_adjudicates_an_imported_finding() -> None:
    # An "imported finding" = a raw observation an operator/scanner hands in; the seam adjudicates it.
    assert cs.confirm_clickjacking_posture(
        {"rule": "framing_unprotected", "url": "https://imported",
         "headers": {"content-type": "text/html"}}).confirmed
    assert cs.confirm_csrf_posture(
        {"rule": "token_not_enforced", "method": "DELETE", "endpoint": "/account",
         "token_present_status": 204, "token_absent_status": 204}).confirmed
    assert cs.confirm_postmessage_posture(
        {"rule": "wildcard_target", "target_origin": "*"}).confirmed


# ---------------------------------------------------------------------------
# (e) STRUCTURAL — every always-applicable constitution class has an oracle row, grounded in the
#     ACTUAL constitution doc (§V coverage doctrine). RED without the three new rows.
# ---------------------------------------------------------------------------

# The always-applicable constitution classes (constitution §V "Coverage doctrine", the rows marked
# "Always" / "Always for browser apps" / "Always — highest-yield"), expressed in the oracle vocabulary.
# The client-side row is the one W16-STD-5 completes.
_ALWAYS_APPLICABLE_CONSTITUTION_CLASSES = {
    "authentication": "auth_bypass",          # VI. Authentication & identity — Always
    "authorization": "authorization",         # VII. Authorization (RBAC/ABAC/BOLA/BFLA) — Always
    "injection_sqli": "sqli",                 # VIII. Injection (SQL/NoSQL/LDAP/OS/SSTI/XXE) — Always
    "injection_xxe": "xxe",
    "client_side_xss": "xss",                 # IX. Client-side (XSS, CSRF, clickjacking, postMessage)
    "client_side_csrf": "csrf",
    "client_side_clickjacking": "clickjacking",
    "client_side_postmessage": "postmessage",
    "business_logic": "business_logic",       # X. Business logic — Always (highest-yield)
    "cryptography": "weak_tls",               # XI. Cryptography & secrets — Always
}


def test_every_always_applicable_constitution_class_has_an_oracle_row() -> None:
    missing = [name for name, cls in _ALWAYS_APPLICABLE_CONSTITUTION_CLASSES.items()
               if not is_known_bug_class(cls) or canonical_oracle_for(cls) is None]
    assert missing == [], (
        "an always-applicable constitution class (constitution §V) has NO oracle row — the deterministic "
        f"substrate cannot adjudicate it: {missing}")
    # and each canonicalises to a real class the map actually contains.
    for cls in _ALWAYS_APPLICABLE_CONSTITUTION_CLASSES.values():
        assert canonical_bug_class(cls) in BUG_CLASS_ORACLES


def test_structural_guard_is_tied_to_the_real_constitution_client_side_row() -> None:
    """Tie the guard to the ACTUAL constitution doc so the four client-side classes cannot drift away
    from what the constitution declares always-applicable."""
    doc = _REPO / "docs" / "knowledge" / "constitution-obsidian.md"
    if not doc.is_file():
        pytest.skip("constitution doc not present in this tree")
    text = doc.read_text(encoding="utf-8")
    # the §V client-side coverage row names exactly these four always-applicable classes.
    assert "Client-side (XSS, CSRF, clickjacking, postMessage)" in text
    for cls in ("xss", "csrf", "clickjacking", "postmessage"):
        assert is_known_bug_class(cls), f"constitution client-side class {cls!r} has no oracle row"
