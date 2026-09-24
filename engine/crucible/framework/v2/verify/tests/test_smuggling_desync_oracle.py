"""verify.oracles.smuggling_desync_oracle (Wave 4.2) — the pure HTTP request-smuggling desync oracle + its
verifier wiring.

This retires audit A12 (#269): the request_smuggling signal no longer rests on TIMING (a probe that hung
longer than a control — a hypothesis a normal origin awaiting an incomplete declared body reproduces
identically). It proves an ACHIEVED desync (CWE-444) by a DIFFERENTIAL over VIGIL's OWN second requests on
two connections it owns: a UNIQUE per-probe canary embedded in the smuggled prefix of a framing-conflict
first request is ECHOED in VIGIL's OWN second-request response on that connection AND ABSENT from an
identical WELL-FORMED control connection's second response. NO victim is poisoned (both requests are VIGIL's
own on its own sockets). It fails closed on: a weak/absent canary; a missing / no-channel leg; a bare
mangled-method status with no canary echo (a plain 405 must not mint); or a canary that ALSO echoes in the
control (an endpoint reflecting it regardless — not attributable to a desync). It REUSES the frozen
``OracleKind.DIFFERENTIAL_RESPONSE`` (so ``oracle_version(DIFFERENTIAL_RESPONSE)`` is UNTOUCHED and
``_ALL_ORACLES`` stays EXACTLY 15), reachable via a fresh ``smuggling_desync`` ctx key no benchmark/scan/
engage finding carries — ``make gate`` byte-identical.
"""

from __future__ import annotations

from framework.v2.verify.models import OracleKind
from framework.v2.verify.oracles import smuggling_desync_oracle
from framework.v2.verify.verifier import _ALL_ORACLES, OracleVerifier

_CANARY = "vgsmug" + "a1b2c3d4e5f6a7b8c9d0"   # unique, high-entropy, >= 12 alnum chars


def _rec(*, canary=_CANARY, technique="CL.TE",
         conflict_body="", conflict_status=200, conflict_channel=True,
         control_body="follow ok", control_status=200, control_channel=True):
    return {
        "canary": canary, "technique": technique,
        "conflict": {"channel": conflict_channel, "status": conflict_status, "reason": "",
                     "body": conflict_body},
        "control": {"channel": control_channel, "status": control_status, "reason": "", "body": control_body},
    }


def test_fires_when_canary_echoed_in_conflict_and_absent_in_control() -> None:
    sig = smuggling_desync_oracle(_rec(conflict_body=f"HTTP/1.1 200 OK\r\n\r\nreflect c={_CANARY}"))
    assert sig.fired and sig.conclusive
    assert sig.kind is OracleKind.DIFFERENTIAL_RESPONSE
    assert sig.confidence >= 0.9


def test_te_cl_technique_also_fires() -> None:
    sig = smuggling_desync_oracle(_rec(technique="TE.CL", conflict_body=f"...{_CANARY}..."))
    assert sig.fired


def test_mangled_method_status_alone_does_not_mint() -> None:
    # A plain 405/400 for a mangled method, with NO unique canary echoed, is NOT proof of smuggling (red-pen).
    sig = smuggling_desync_oracle(_rec(conflict_body="Method Not Allowed", conflict_status=405))
    assert not sig.fired
    # both legs answered and no canary leaked -> a channel-confirmed negative (conclusive), admission
    # downgrades it to INCONCLUSIVE (the branch is not clean_capable).
    assert sig.conclusive


def test_canary_echoed_in_control_too_is_refused() -> None:
    # An endpoint that reflects the canary into EVERY response (even the well-formed control) — the echo is
    # not attributable to a framing desync. REFUSE (a LEAD), never a channel-confirmed negative.
    sig = smuggling_desync_oracle(_rec(conflict_body=f"x {_CANARY} x", control_body=f"y {_CANARY} y"))
    assert not sig.fired and not sig.conclusive


def test_weak_or_short_canary_is_a_lead() -> None:
    for bad in ("aaaa", "short", "aaaaaaaaaaaaaaaa", "vg!!short"):
        sig = smuggling_desync_oracle(_rec(canary=bad, conflict_body=f"echo {bad}"))
        assert not sig.fired and not sig.conclusive, bad


def test_missing_leg_is_inconclusive() -> None:
    sig = smuggling_desync_oracle({"canary": _CANARY, "technique": "CL.TE",
                                   "conflict": {"channel": True, "status": 200, "body": _CANARY}})
    assert not sig.fired and not sig.conclusive


def test_no_channel_on_a_leg_is_inconclusive_never_a_desync() -> None:
    sig = smuggling_desync_oracle(_rec(conflict_body=_CANARY, conflict_channel=False))
    assert not sig.fired and not sig.conclusive
    sig2 = smuggling_desync_oracle(_rec(conflict_body=_CANARY, control_channel=False))
    assert not sig2.fired and not sig2.conclusive


def test_benign_well_behaved_server_no_desync_is_a_conclusive_negative() -> None:
    # A benign / anti-smuggling front-end: the canary leaks NOWHERE. Both legs answered normally -> a
    # channel-confirmed negative (no fire), which admission maps to INCONCLUSIVE (not clean_capable).
    sig = smuggling_desync_oracle(_rec(conflict_body="ordinary follow-up", control_body="ordinary follow-up"))
    assert not sig.fired and sig.conclusive


def test_empty_or_malformed_observed_does_not_fire() -> None:
    for bad in (None, {}, "nope", 42, {"canary": _CANARY}):
        sig = smuggling_desync_oracle(bad)
        assert not sig.fired


def test_is_deterministic() -> None:
    rec = _rec(conflict_body=f"leak {_CANARY}")
    a = smuggling_desync_oracle(rec)
    b = smuggling_desync_oracle(rec)
    assert (a.fired, a.confidence, a.conclusive) == (b.fired, b.confidence, b.conclusive)


def test_verifier_routes_via_the_fresh_key_on_request_smuggling() -> None:
    v = OracleVerifier()
    ctx = {"bug_class": "request_smuggling",
           "smuggling_desync": _rec(conflict_body=f"HTTP/1.1 200 OK\r\n\r\n{_CANARY}")}
    out = v.confirm(ctx)
    assert out.confirmed
    assert any(s.kind is OracleKind.DIFFERENTIAL_RESPONSE and s.fired for s in out.signals)
    # a benign (no-echo) record does NOT confirm
    assert not v.confirm({"bug_class": "request_smuggling",
                          "smuggling_desync": _rec(conflict_body="ordinary")}).confirmed


def test_reuses_frozen_differential_response_kind_gate_byte_identical() -> None:
    # No NEW OracleKind: reuse DIFFERENTIAL_RESPONSE (already in the frozen fallback, which stays EXACTLY 15).
    assert len(_ALL_ORACLES) == 15
    assert OracleKind.DIFFERENTIAL_RESPONSE in _ALL_ORACLES
    # the ordinary baseline/mutated differential still works on the SAME kind/arm (not shadowed by the new key)
    v = OracleVerifier()
    out = v.confirm({"bug_class": "boolean_sqli",
                     "baseline": {"status": 200, "body": "no rows"},
                     "mutated": {"status": 200, "body": "row1 row2 row3 row4 row5 admin secret dump"}})
    assert any(s.kind is OracleKind.DIFFERENTIAL_RESPONSE for s in out.signals)
