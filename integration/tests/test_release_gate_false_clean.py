"""Release gate #7 / #10 — the FALSE-CLEAN battery, as an honest scoreboard.

WHAT THIS FILE IS. The product's thesis is a *sound negative*: when VIGIL says CLEAN it must mean "examined
and found nothing", never "did not look" or "could not tell". The release gate requires an independent red
team to attack BOTH claim directions (plan #10) and that *"every missing channel yields INCONCLUSIVE"*
(#7). This file is the false-CLEAN direction: it tries to manufacture a CLEAN verdict out of evidence that
is missing, truncated, undecodable, unsupported, or simply never examined — and asserts each attempt
degrades to INCONCLUSIVE (or refuses), never to an optimistic CLEAN.

The single admission point is ``live.verdict.admit`` (the registry in ``evidence-branches.json`` is
load-bearing); the family summary is ``live.verdict.compose``; the proof-subsystem degradation state is
``proof.degradation``. This board drives those real seams directly.

HOW IT STAYS HONEST (model: ``test_production_invariants.py``). Each attack row asserts the TRUE bar; a bar
the system does not meet is marked ``@pytest.mark.xfail(strict=True, reason="<slice>")`` so an unexpected
pass fails the build and the board self-updates. Every row carries a negative control — most importantly a
control proving CLEAN IS reachable when it is genuinely earned, so "never CLEAN" is a real distinction and
not a renderer that simply never emits CLEAN.

NO FRAMEWORK IMPORTS — pure ``vigil_integration`` + stdlib, so it runs in BOTH legs of the required P5 job
and needs no ci.yml offense-leg entry.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from vigil_integration.live.verdict import (
    UnregisteredBranch,
    Verdict,
    admit,
    compose,
)

_REPO = Path(__file__).resolve().parents[2]
_LADDER = _REPO / "docs" / "capability-matrix" / "evidence-branches.json"


def _branches() -> list[dict]:
    return json.loads(_LADDER.read_text(encoding="utf-8"))["branches"]


def _a_clean_capable_branch() -> dict:
    for b in _branches():
        if b.get("clean_capable"):
            return b
    raise AssertionError("no clean-capable branch in the ladder — the negative control cannot be built")


def _a_body_derived_branch() -> dict:
    """A branch whose declared preconditions include readable body semantics — the surface truncation /
    undecodability degrade first."""
    for b in _branches():
        if "body_semantically_available" in (b.get("preconditions") or []):
            return b
    raise AssertionError("no body-derived branch in the ladder")


# =========================================================================================================
# MISSING evidence — a precondition the branch declares was never satisfied.
# =========================================================================================================
def test_a_missing_precondition_is_inconclusive_never_clean():
    """A branch whose declared precondition did not hold for THIS observation cannot support a negative
    conclusion — neither firing nor non-firing is meaningful over evidence that was never established."""
    clean = _a_clean_capable_branch()
    # withhold the branch's own precondition(s): none present in `observed`
    out = admit(clean["id"], fired=False, conclusive=True, observed={})
    assert out.verdict is Verdict.INCONCLUSIVE, (
        f"{clean['id']} produced {out.verdict} with an unmet precondition — a missing precondition must never "
        "yield CLEAN"
    )


def test_negative_control_the_same_branch_CAN_reach_clean_when_earned():
    """Non-vacuity: with its precondition satisfied and a conclusive non-firing, the SAME clean-capable
    branch DOES reach CLEAN. So the row above proves 'missing evidence ≠ clean', not 'CLEAN is unreachable'."""
    clean = _a_clean_capable_branch()
    observed = {p: True for p in (clean.get("preconditions") or [])} or {"channel_established": True}
    out = admit(clean["id"], fired=False, conclusive=True, observed=observed)
    assert out.verdict is Verdict.CLEAN, (
        f"{clean['id']} could not reach CLEAN even when its preconditions held and the oracle conclusively "
        f"did not fire ({out.reason}) — the false-clean controls would be vacuous"
    )


# =========================================================================================================
# TRUNCATED / UNDECODABLE evidence — the channel was established but the body was not semantically readable.
# =========================================================================================================
def test_a_truncated_or_undecodable_body_is_inconclusive_never_clean():
    """The transport succeeded (``channel_established``) but the body was truncated or could not be decoded
    (``body_semantically_available`` is False/absent). A body-derived branch must not read CLEAN off a body
    it could not actually read."""
    body = _a_body_derived_branch()
    observed = {"channel_established": True}  # body_semantically_available deliberately absent
    out = admit(body["id"], fired=False, conclusive=True, observed=observed)
    assert out.verdict is Verdict.INCONCLUSIVE, (
        f"{body['id']} read {out.verdict} off a body it could not decode — truncated/undecodable evidence "
        "must degrade to INCONCLUSIVE"
    )


def test_body_derived_branches_are_declared_not_clean_capable():
    """Structural backstop: every body-derived branch is declared ``clean_capable: false`` in the ladder, so
    even a mis-supplied ``observed`` cannot let one assert absence off body content."""
    offenders = [b["id"] for b in _branches()
                 if "body_semantically_available" in (b.get("preconditions") or []) and b.get("clean_capable")]
    assert not offenders, f"body-derived branches must not be CLEAN-capable: {offenders}"


# =========================================================================================================
# UNSUPPORTED evidence — a branch with no capability declaration, or one declared unable to assert absence.
# =========================================================================================================
def test_an_unregistered_branch_refuses_it_does_not_default_to_clean():
    """A verdict requested for a branch with no declaration must FAIL LOUDLY, never silently default to
    'allowed'/CLEAN — that is how a new evidence path would acquire absence authority nobody reviewed."""
    with pytest.raises(UnregisteredBranch):
        admit("totally.unregistered.branch", fired=False, conclusive=True,
              observed={"channel_established": True})


def test_a_branch_not_declared_clean_capable_is_inconclusive_on_a_conclusive_non_fire():
    """A registered branch whose declaration says it may NOT assert absence must return INCONCLUSIVE even on a
    conclusive non-firing with every precondition satisfied — its evidence surface cannot carry a negative."""
    ncc = next((b for b in _branches() if not b.get("clean_capable")), None)
    assert ncc is not None, "expected at least one non-clean-capable branch in the ladder"
    observed = {p: True for p in (ncc.get("preconditions") or [])}
    out = admit(ncc["id"], fired=False, conclusive=True, observed=observed)
    assert out.verdict is Verdict.INCONCLUSIVE, (
        f"{ncc['id']} is declared not clean-capable but returned {out.verdict} — it asserted an absence it "
        "may not"
    )


# =========================================================================================================
# INCONCLUSIVE oracle — a non-firing that is not conclusive is not a clean bill of health.
# =========================================================================================================
def test_a_non_conclusive_non_firing_is_inconclusive_never_clean():
    clean = _a_clean_capable_branch()
    observed = {p: True for p in (clean.get("preconditions") or [])} or {"channel_established": True}
    out = admit(clean["id"], fired=False, conclusive=False, observed=observed)
    assert out.verdict is Verdict.INCONCLUSIVE, (
        f"{clean['id']} read CLEAN off a NON-conclusive oracle result — only a conclusive non-firing may be "
        "clean"
    )


# =========================================================================================================
# NEVER EXAMINED — an empty family must not compose to CLEAN.
# =========================================================================================================
def test_an_empty_family_composes_to_inconclusive_not_clean():
    """Nothing examined is not the same as nothing found. A family with no branch verdicts (the surface was
    never probed) must compose to INCONCLUSIVE — defaulting the empty case to CLEAN is exactly how an
    un-probed family gets reported as safe."""
    assert compose([]) is Verdict.INCONCLUSIVE, (
        "an empty family composed to something other than INCONCLUSIVE — an un-probed surface could read clean"
    )


def test_one_inconclusive_branch_poisons_a_family_clean():
    """CLEAN is reachable ONLY when EVERY relevant branch was itself CLEAN. A single INCONCLUSIVE branch —
    e.g. one whose body could not be decoded — must pull the family off CLEAN, so a family is called clean
    only if nothing was left unexamined."""
    assert compose([Verdict.CLEAN, Verdict.INCONCLUSIVE]) is Verdict.INCONCLUSIVE
    assert compose([Verdict.CLEAN, Verdict.LEAD]) is Verdict.LEAD
    assert compose([Verdict.CLEAN, Verdict.FACT]) is Verdict.FACT


def test_negative_control_an_all_clean_family_composes_to_clean():
    """Non-vacuity for the family rows: when every branch is genuinely CLEAN, the family IS CLEAN."""
    assert compose([Verdict.CLEAN, Verdict.CLEAN, Verdict.CLEAN]) is Verdict.CLEAN


# =========================================================================================================
# A DEGRADED proof subsystem is never a clean target (the six-swallow conflation, S9).
# =========================================================================================================
def test_a_degraded_proof_subsystem_is_never_read_as_clean(tmp_path):
    """"target clean", "sink never installed", "capture failed" and "mint crashed" must not be one UI state.
    While the proof subsystem is degraded, a CLEAN reading is impossible — the zero-records run reads as a
    distinct, typed 'verification degraded' state, not as nothing-found."""
    from vigil_integration.proof import degradation as deg

    assert deg.record_degradation(tmp_path, deg.PROOF_SUBSYSTEM_UNAVAILABLE, where="probe")
    degraded = deg.summarize(n_records=0, facts=0, leads=0, denied=0,
                             degradations=deg.read_degradations(tmp_path))
    assert degraded["verification_degraded"] and not degraded["clean"], (
        "a zero-records run with a degraded proof subsystem read as clean — the inv-12 / false-clean "
        "conflation is back"
    )


def test_negative_control_a_healthy_zero_finding_run_IS_clean(tmp_path):
    """Non-vacuity: a genuinely healthy run with no findings and no degradation IS the honest clean state —
    so the degraded row proves 'degraded ≠ clean', not 'clean is never reported'."""
    from vigil_integration.proof import degradation as deg

    clean = deg.summarize(n_records=0, facts=0, leads=0, denied=0, degradations=deg.read_degradations(tmp_path))
    assert clean["clean"] and not clean["verification_degraded"], (
        "a healthy zero-finding run did not read as clean — the honest negative can never be reported"
    )
    assert clean["disposition"] != deg.summarize(
        n_records=0, facts=0, leads=0, denied=0,
        degradations=[{"kind": deg.PROOF_SUBSYSTEM_UNAVAILABLE, "where": "x", "count": 1}],
    )["disposition"], "clean and degraded collapse to one disposition"


# =========================================================================================================
# The scoreboard itself.
# =========================================================================================================
def test_the_negatives_capable_branch_count_is_pinned_and_named():
    """W16-STD-1 criterion (d): the number of evidence branches that CAN assert a bounded negative (a CLEAN)
    is asserted in a test, so the ladder cannot silently gain or lose absence-authority.

    The issue framed this as '6 of 26': at issue time the ladder held 26 branches, 6 of them clean-capable
    (20 could not assert a negative). The ladder has since grown — the total is NOT 26 any more, and pinning a
    total would be brittle churn — so the load-bearing number is the count of CLEAN-CAPABLE branches, pinned
    to the exact 6 named below. The insertion-coverage slice did NOT add a clean-capable branch (a
    body-derived CLEAN still needs the render_dom / streaming-decoder work).

    HONEST SCOPE (do not overclaim across the three redirect header branches): only
    ``open_redirect.location_header`` gained the cookie / urlencoded-body / JSON-body insertion surfaces —
    before it, a redirect reachable only from those surfaces was unexamined, so its CLEAN was a latent
    false-CLEAN, and test_web_redrive.py proves the fix (a JSON-body-only redirect is FOUND; a clean target
    names all five surfaces). ``host_header.location_header`` is a REQUEST-LEVEL Host-header surface, probed
    once on the bare template — it does NOT depend on parameter insertion, so it gained nothing here. The
    OIDC check is not driven by the web re-drive at all, so a non-query ``redirect_uri`` stays a NAMED
    residual. This test guards that honest scope against the registry drifting back to the overclaim.

    WAVE 3 (HexStrike TLS breadth) ADDED NO CLEAN-CAPABLE BRANCH. The pin stays at 6.

    It briefly did. ``tls_weakness.deprecated_protocol_offer`` shipped as the 7th, on this argument: the
    negative is something the PEER SAID, not a signal that was merely absent — VIGIL narrows its own
    ClientHello to a single deprecated version and the endpoint answers on an ESTABLISHED TCP channel with
    ``alert(70) protocol_version``, which RFC 8446 4.1.1 requires of a server that will not speak the
    offered version.

    THAT ARGUMENT WAS WRONG, and the error is worth keeping written down because it is subtle and it is the
    kind this board exists to catch. "The peer said it" is true of ONE CONNECTION. The conclusion rests on a
    PAIR: the refusal, and a separate handshake VIGIL COMPLETED at another version to show the thing
    answering is a TLS service at all. Those are two different TCP connections, and NOTHING IN THE RETAINED
    EVIDENCE BINDS THEM TO THE SAME PEER. An ordinary L4 fan-out breaks it — a Kubernetes Service with more
    than one pod, an haproxy/nginx TCP pool, an L4 VIP, a DNS A-record pool mid-rollout: one connection is
    answered by a backend whose minimum is TLS1.1 (a genuine alert(70)) and the next by a backend that
    speaks TLS1.0, so VIGIL holds a real refusal beside a real completed session and clears a version the
    endpoint DOES accept. It is not detectable as self-contradiction, because ``minimum_version=TLSv1.1`` is
    a legal configuration. A red-pen reproduced it end to end through the real runner, the real gate and a
    real two-backend round-robin listener; that listener is now a permanent negative control in
    ``test_tls_breadth.py``. The limit is irreducible with what TLS gives the refused leg: the completed leg
    retains ``spki_sha256``, but a refusing peer sends the alert IN PLACE OF the ServerHello and presents no
    certificate to bind against, and re-probing k times would only make the claim probabilistic, which the
    oracle doctrine forbids. So the branch is ``clean_capable: false`` and a refusal is INCONCLUSIVE; the
    registry row's ``blocking_work`` names what a sound CLEAN would need.

    Note what is NOT the reason: the guards were all sound and all held. The closed singleton reason set
    (``tls_breadth.VERSION_REJECTION_REASONS``), the ``channel_established`` precondition and the
    peer-TLS-session witness are all still enforced and still tested — they are asserted below, because the
    branch keeps them and they are the right guards if a sound CLEAN ever becomes reachable. What failed was
    the INFERENCE from a sound per-connection observation to a claim about an endpoint.

    WAVE 3's other two branches never had absence-authority — ``tls_weakness.weak_cipher_offer`` cannot,
    because the local OpenSSL build limits which legacy suites can be offered at all (a refusal may mean
    untested), and ``tls_weakness.certificate_validity`` (WIRED + FACT-capable as of M1.3) still cannot: a
    validity defect is an existential FACT, but a non-defect over the retained LEAF is not a bounded negative
    over the presented chain, so the branch mints yet may NOT assert absence (``clean_capable: false``)."""
    branches = {b["id"]: b for b in _branches()}
    clean = sorted(bid for bid, b in branches.items() if b.get("clean_capable"))
    expected = sorted([
        "open_redirect.location_header",
        "cors.reflected_origin_with_credentials",
        "host_header.location_header",
        "oidc_redirect_uri.location_header",
        "service_reachability.tcp_handshake",
        "tls_weakness.tls_handshake",
    ])
    assert clean == expected, (
        f"the set of CLEAN-capable branches changed to {clean}; if this is intended, update the pin AND the "
        f"reasoning — a clean-capable branch is one that may assert absence, the most safety-sensitive claim")
    assert len(clean) == 6, f"expected exactly 6 negatives-capable branches, found {len(clean)}"

    # POSITIVE assertions about the DEMOTION, so it cannot be silently undone. Not "it is absent from the
    # list above" — that would also pass if the row disappeared entirely.
    dep = branches["tls_weakness.deprecated_protocol_offer"]
    assert dep["clean_capable"] is False, (
        "tls_weakness.deprecated_protocol_offer regained absence-authority. It may not have it: the "
        "corroborating handshake and the refusal are on two different TCP connections and nothing binds "
        "them to the same peer. Re-read this test's docstring before touching the registry row.")
    assert dep["fact_capable"] is True, "the demotion must not have cost the branch its FACT capability"
    assert dep["target_clean_capable"] is True and (dep.get("blocking_work") or "").strip(), (
        "a demoted capability keeps its TARGET and must name the engineering that would close the gap "
        "(claim discipline: meet up, never soften the claim)")
    for must_say in ("connection", "peer"):
        assert must_say in dep["blocking_work"].lower(), (
            f"blocking_work must name the cross-{must_say} binding that a sound CLEAN would need")
    assert "MISSING: cross_connection_peer_identity_binding" in dep["control_requirements"], (
        "the missing control that caps this branch must be named in control_requirements")

    # The guards that were NOT the problem are KEPT, and stay asserted: the closed peer-alert reason set
    # and the channel_established precondition. They keep a bare non-TLS alert(70) emitter out of the
    # conclusive path and are the right guards if a sound CLEAN ever becomes reachable.
    assert "channel_established" in dep.get("preconditions", []), (
        "the deprecated-protocol branch dropped its established-channel precondition")
    from vigil_integration.live import tls_breadth as _tb
    assert _tb.VERSION_REJECTION_REASONS == frozenset({"TLSV1_ALERT_PROTOCOL_VERSION"}), (
        "the TLS refusal vocabulary widened — every added reason is a new way for a non-version failure "
        "to be recorded as a version refusal")

    for not_clean_capable in ("tls_weakness.weak_cipher_offer", "tls_weakness.certificate_validity"):
        assert branches[not_clean_capable]["clean_capable"] is False, (
            f"{not_clean_capable} gained absence-authority it has no bounded negative for")
    # certificate_validity is now WIRED (M1.3) and FACT-capable, but it did NOT gain CLEAN-authority — that is
    # the safety-relevant property this release gate pins: the branch mints an existential defect FACT yet a
    # non-defect over the retained LEAF is not a bounded negative over the presented chain, so it still may not
    # assert absence. The clean-capable SET pinned above already excludes it; here we pin the capability row.
    cv = branches["tls_weakness.certificate_validity"]
    assert cv.get("wired") is True and cv["fact_capable"] is True, (
        "certificate_validity is wired + fact_capable as of M1.3 — if that regressed, fix the slice not the pin")
    assert cv["target_clean_capable"] is True and (cv.get("blocking_work") or "").strip(), (
        "the FACT-only state must keep its CLEAN target and name the full-chain work that would close the gap "
        "(claim discipline: meet up, never soften the claim)")
    assert "MISSING: full_chain_retention" in cv["control_requirements"], (
        "the control that caps CLEAN (no retained presented chain) must stay named")
    # the three redirect HEADER branches must all remain negatives-capable ...
    for header_branch in ("open_redirect.location_header", "host_header.location_header",
                          "oidc_redirect_uri.location_header"):
        assert header_branch in clean, f"{header_branch} must remain a negatives-capable branch"
    # ... but ONLY open_redirect.location_header gained the synthesised insertion surfaces. Pin that honest
    # scope from the registry's OWN blocking_work so a re-introduced overclaim (host_header/oidc "gained
    # cookie/body coverage") turns this red rather than green-passing as it did before the red-pen.
    orl = branches["open_redirect.location_header"]["blocking_work"]
    assert "_redirect_templates" in orl and "five insertion surfaces" in orl, (
        "open_redirect.location_header must record that it gained the synthesised insertion surfaces")
    hh = branches["host_header.location_header"]["blocking_work"]
    assert "REQUEST-LEVEL" in hh and "does not depend on query/body parameter insertion" in hh, (
        "host_header.location_header must stay declared a request-level surface, not a param-insertion one")
    oidc = branches["oidc_redirect_uri.location_header"]["blocking_work"]
    assert "RESIDUAL" in oidc and "cookie or request body" in oidc, (
        "oidc_redirect_uri non-query redirect_uri must stay a named residual, not a gained surface")


def test_no_row_is_a_non_strict_xfail():
    """A non-strict xfail would swallow an XPASS and the board would stop self-updating."""
    module = __import__(__name__, fromlist=["*"])
    for name, obj in vars(module).items():
        if not (name.startswith("test_") and callable(obj)):
            continue
        for mark in getattr(obj, "pytestmark", []):
            if mark.name == "xfail":
                assert mark.kwargs.get("strict"), f"{name} uses a non-strict xfail and would hide a regression"
