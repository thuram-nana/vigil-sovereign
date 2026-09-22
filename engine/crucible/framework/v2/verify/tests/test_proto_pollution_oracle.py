"""
verify.oracles.prototype_pollution_oracle (Wave 2.2) — the pure client-side prototype-
pollution oracle + its verifier wiring.

Proves the oracle fires ONLY on the ACHIEVED polluted state (Object.prototype[uniqKey] ===
uniqVal AND a benign-key control undefined), refuses on presence-without-pollution / value
mismatch / ambient pollution / short markers, is deterministic, and that the new
``OracleKind.PROTOTYPE_POLLUTION`` is reachable ONLY via its explicit BUG_CLASS_ORACLES row
and is NOT in the frozen ``_ALL_ORACLES`` fallback (so ``make gate`` stays byte-identical).
"""

from __future__ import annotations

from framework.v2.verify.models import OracleKind
from framework.v2.verify.oracles import prototype_pollution_oracle
from framework.v2.verify.verifier import _ALL_ORACLES, OracleVerifier

_KEY = "cpp_abcdef012345"
_VAL = "ppv_abcdef012345"
_BENIGN = "benign_112233445566"


def _obs(**over):
    base = {"polluted_key": _KEY, "expected_val": _VAL, "polluted_val": _VAL,
            "benign_key": _BENIGN, "benign_key_undefined": True}
    base.update(over)
    return base


def test_fires_on_achieved_pollution_with_benign_control_undefined() -> None:
    sig = prototype_pollution_oracle(_obs())
    assert sig.fired and sig.kind is OracleKind.PROTOTYPE_POLLUTION
    assert sig.confidence >= 0.9
    # evidence reads as the ACHIEVED STATE, not "a script ran"
    assert "Object.prototype" in sig.evidence and _KEY in sig.evidence
    assert "executed" not in sig.evidence.lower() and "script ran" not in sig.evidence.lower()


def test_presence_without_pollution_does_not_fire() -> None:
    assert not prototype_pollution_oracle(_obs(polluted_val=None)).fired


def test_value_mismatch_does_not_fire() -> None:
    assert not prototype_pollution_oracle(_obs(polluted_val="ppv_somethingelse")).fired


def test_ambient_benign_key_polluted_does_not_fire() -> None:
    # the benign control is NOT undefined ⇒ cannot attribute ⇒ refuse
    assert not prototype_pollution_oracle(_obs(benign_key_undefined=False)).fired
    assert not prototype_pollution_oracle(_obs(benign_key_undefined=None)).fired


def test_short_or_missing_markers_do_not_fire() -> None:
    assert not prototype_pollution_oracle(_obs(polluted_key="short", expected_val="short")).fired
    assert not prototype_pollution_oracle(_obs(expected_val="ab", polluted_val="ab")).fired
    assert not prototype_pollution_oracle({}).fired
    assert not prototype_pollution_oracle(None).fired


def test_pre_existing_named_prototype_keys_do_not_fire() -> None:
    """SELF-CONTAINED SOUNDNESS (red-pen MEDIUM): the oracle's STANDALONE re-fire — its certificate —
    must NOT be satisfiable by a pre-existing NAMED Object.prototype property. A crafted context whose
    polluted_key is a real prototype member (toString/hasOwnProperty/constructor/__proto__) with a
    matching value and an undefined benign control must be REFUSED, because the key is not VIGIL's
    ``cpp_<hex>`` per-probe canary shape. Only the high-entropy marker VIGIL drove in can fire."""
    for name in ("toString", "hasOwnProperty", "constructor", "__proto__", "isPrototypeOf",
                 "valueOf", "propertyIsEnumerable"):
        obs = _obs(polluted_key=name, expected_val=name, polluted_val=name)
        assert not prototype_pollution_oracle(obs).fired, f"named prototype key {name!r} must not fire"
    # a non-canary but long/arbitrary key is likewise refused (shape, not mere length)
    assert not prototype_pollution_oracle(
        _obs(polluted_key="totallyarbitrarykey123", expected_val="somevalue123",
             polluted_val="somevalue123")).fired
    # the genuine VIGIL canary shape still fires (the guard is a shape filter, not a kill-switch)
    assert prototype_pollution_oracle(_obs()).fired


def test_is_deterministic() -> None:
    a = prototype_pollution_oracle(_obs())
    b = prototype_pollution_oracle(_obs())
    assert (a.fired, a.confidence, a.evidence) == (b.fired, b.confidence, b.evidence)


def test_verifier_routes_only_via_the_explicit_row() -> None:
    v = OracleVerifier()
    assert v.oracles_for("prototype_pollution") == (OracleKind.PROTOTYPE_POLLUTION,)
    # fires through the verifier over the proto_pollution ctx key
    out = v.confirm({"bug_class": "prototype_pollution", "proto_pollution": _obs()})
    assert out.confirmed
    # an unknown class does NOT pick up the new kind (it is not in the frozen fallback)
    assert OracleKind.PROTOTYPE_POLLUTION not in v.oracles_for("some_unknown_class")


def test_new_kind_excluded_from_frozen_fallback_gate_byte_identical() -> None:
    """The new OracleKind must NOT be in the frozen unknown-class fallback, and the enum must carry it —
    so the kind fires ONLY through its explicit row and `make gate` stays byte-identical."""
    assert OracleKind.PROTOTYPE_POLLUTION in set(OracleKind)
    assert OracleKind.PROTOTYPE_POLLUTION not in _ALL_ORACLES
    assert len(_ALL_ORACLES) == 15
