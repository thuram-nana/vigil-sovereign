"""
Client-side prototype pollution confirmation (Wave 2.2) — result-handling + oracle
wiring without a browser, plus the red-pen non-fire fixtures.

The live browser path is skip-gated on a real Chromium (see
``test_proto_pollution_browser.py``); this file drives ``scanner.proto_pollution`` with
a STUB browser that models several render behaviours, so the drive→readback→oracle
logic and the deterministic ``prototype_pollution`` oracle are verified deterministically.
It proves:

  * a FACT on a planted prototype-pollution page (Object.prototype achievedly polluted
    to the unique per-probe value, benign-key control undefined);
  * SILENCE on the benign twin (reflects the key but does NOT pollute), a
    presence-not-pollution fixture (payload echoed, prototype clean), an ambient-key
    fixture (benign key not undefined), and a value-mismatch fixture — the oracle fires
    only on the ACHIEVED polluted state, never on mere appearance;
  * the retained ``oracle_context`` re-fires and round-trips (a re-verifiable
    certificate), and a tampered value no longer confirms.
"""

from __future__ import annotations

import json
import re

from framework.v2.scanner.proto_pollution import (
    ProtoPollutionResult,
    _BINDING,
    confirm_proto_pollution,
    proto_pollution_finding,
)
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.models import OracleKind
from framework.v2.verify.verifier import BUG_CLASS_ORACLES, OracleVerifier, normalize_bug_class

_KEY_RE = re.compile(r"cpp_[0-9a-f]{12}")


# ---------------------------------------------------------------------------
# Stub browser. The session models the readback binding: on ``evaluate`` of the
# readback snippet it extracts the probe's key + benign key and reports a JSON blob
# via the binding per the configured render ``mode``:
#   * 'pollute'  = Object.prototype[key] === value, benign key undefined (FACT)
#   * 'reflect'  = the page reflected the key but did NOT pollute (polluted_val null)
#   * 'ambient'  = the prototype was polluted BUT the benign key is also polluted
#                  (benign_key_undefined False) — cannot attribute
#   * 'mismatch' = polluted to a DIFFERENT value than the one driven in
# ---------------------------------------------------------------------------


class _StubSession:
    def __init__(self, mode: str) -> None:
        self._mode = mode
        self._calls: list[str] = []
        self.bound: list[str] = []

    def add_binding(self, name: str) -> None:
        self.bound.append(name)

    def navigate(self, url: str, *, settle: float = 0.4, timeout: float = 15.0) -> None:
        self._url = url

    def evaluate(self, expression: str, **_kw):
        # The readback snippet embeds the key + benign key as JSON literals; pull them out.
        keys = re.findall(r'"(cpp_[0-9a-f]{12}|benign_[0-9a-f]{12})"', expression)
        if len(keys) < 2:
            return None
        key, benign = keys[0], keys[1]
        # The value driven in for this key rode in the navigated URL (ppv_<same tag>).
        tag = key[len("cpp_"):]
        val = f"ppv_{tag}"
        blob = {"pollute": {"polluted_key": key, "polluted_val": val, "benign_key": benign,
                            "benign_key_undefined": True},
                "reflect": {"polluted_key": key, "polluted_val": None, "benign_key": benign,
                            "benign_key_undefined": True},
                "ambient": {"polluted_key": key, "polluted_val": val, "benign_key": benign,
                            "benign_key_undefined": False},
                "mismatch": {"polluted_key": key, "polluted_val": "other_val_xyz", "benign_key": benign,
                             "benign_key_undefined": True}}[self._mode]
        self._calls.append(json.dumps(blob))
        return None

    def binding_calls(self, name: str) -> list[str]:
        return list(self._calls) if name == _BINDING else []


class _StubBrowser:
    def __init__(self, mode: str) -> None:
        self._mode = mode

    def start(self) -> "_StubBrowser":
        return self

    def session(self) -> _StubSession:
        return _StubSession(self._mode)

    def stop(self) -> None:
        return None


def _run(mode: str):
    return confirm_proto_pollution(
        "http://127.0.0.1:9/proto",
        browser=_StubBrowser(mode),
        settle=0.0,
    )


# ---------------------------------------------------------------------------
# 1. Oracle wiring: prototype_pollution maps to PROTOTYPE_POLLUTION
# ---------------------------------------------------------------------------


def test_prototype_pollution_routes_to_its_own_oracle_kind() -> None:
    assert normalize_bug_class("prototype_pollution") == "prototype_pollution"
    assert normalize_bug_class("client_side_prototype_pollution") == "prototype_pollution"
    assert normalize_bug_class("proto_pollution") == "prototype_pollution"
    assert BUG_CLASS_ORACLES["prototype_pollution"][0] is OracleKind.PROTOTYPE_POLLUTION
    assert OracleVerifier().oracles_for("prototype_pollution")[0] is OracleKind.PROTOTYPE_POLLUTION


# ---------------------------------------------------------------------------
# 2. FACT on a planted pollution; SILENT on benign / presence / ambient / mismatch
# ---------------------------------------------------------------------------


def test_planted_pollution_achieves_state_and_the_context_confirms() -> None:
    results = _run("pollute")
    assert results and all(isinstance(r, ProtoPollutionResult) for r in results)
    assert all(r.polluted for r in results)              # every source/syntax achieved pollution
    r = results[0]
    assert r.bug_class == "prototype_pollution" and _KEY_RE.fullmatch(r.key)
    # every gadget syntax + source appeared (query/fragment/json_query)
    assert {x.source for x in results} == {"query", "fragment", "json_query"}
    outcome = OracleVerifier().confirm(r.context.to_verifier_context())
    assert outcome.confirmed
    assert any(s.kind is OracleKind.PROTOTYPE_POLLUTION and s.fired for s in outcome.signals)
    rebuilt = FindingContext.model_validate(r.context.model_dump())
    assert OracleVerifier().confirm(rebuilt.to_verifier_context()).confirmed


def test_benign_twin_reflects_without_polluting_never_fires() -> None:
    results = _run("reflect")
    assert results and not any(r.polluted for r in results)
    assert not OracleVerifier().confirm(results[0].context.to_verifier_context()).confirmed


def test_presence_not_pollution_never_fires() -> None:
    # Identical to the benign twin's shape: the payload key is echoed but Object.prototype
    # is clean (polluted_val is null), so the achieved-state oracle must not fire.
    results = _run("reflect")
    assert not any(r.polluted for r in results)


def test_ambient_key_fixture_refuses_to_attribute() -> None:
    # The prototype IS polluted but the benign-key control is ALSO polluted (undefined=False):
    # the oracle cannot attribute the state to THIS probe, so it refuses.
    results = _run("ambient")
    assert results and not any(r.polluted for r in results)
    assert not OracleVerifier().confirm(results[0].context.to_verifier_context()).confirmed


def test_value_mismatch_never_fires() -> None:
    results = _run("mismatch")
    assert results and not any(r.polluted for r in results)
    assert not OracleVerifier().confirm(results[0].context.to_verifier_context()).confirmed


# ---------------------------------------------------------------------------
# 3. Tamper rejection + finding shape
# ---------------------------------------------------------------------------


def test_a_tampered_value_no_longer_confirms() -> None:
    r = _run("pollute")[0]
    ctx = r.context.model_dump()
    ctx["proto_pollution"]["polluted_val"] = "ppv_000000000000"   # a different value than driven in
    tampered = FindingContext.model_validate(ctx)
    assert not OracleVerifier().confirm(tampered.to_verifier_context()).confirmed


def test_proto_pollution_finding_carries_the_retained_oracle_context() -> None:
    r = _run("pollute")[0]
    finding = proto_pollution_finding(r)
    assert finding["bug_class"] == "prototype_pollution"
    octx = finding["oracle_context"]
    assert octx.get("proto_pollution")
    assert OracleVerifier().confirm(octx).confirmed
