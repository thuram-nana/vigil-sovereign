"""W13-2 (#495) — build_offense_bridge composes the REAL existing offense gates (not stubs).

This is the OFFENSE-leg companion to test_sovereign_bridge.py. It imports ``framework`` (behind an
``importorskip``), so it runs ONLY in the offense leg of the required "integration two-env boundary (P5)"
CI job — it is listed there explicitly (the ``test_ci_framework_tests_run_in_offense_leg`` guard enforces
that). It proves the facade genuinely DELEGATES to the already-existing gates, so "composed from the existing
gates" is true of the code and not a hollow abstraction:

  * the sovereignty leg is the REAL kernel sovereignty gate (via ``live.think_claude.llm_egress_refusal``):
    an AIR_GAPPED tier refuses a cloud backend THROUGH the facade, and the DENY is attributed to it;
  * the entitlement leg is the REAL ``framework.v2.entitlement.require_capability``: with enforcement forced
    on and no trust root, a non-baseline capability is refused THROUGH the facade;
  * the authority leg is the REAL ``conjunctive_gate.build_offense_gate`` (kill-switch ∧ scope ∧ WARDEN) —
    exercised with the framework CRUCIBLE authority stubbed exactly as test_conjunctive_gate.py does, so an
    out-of-envelope authority denies THROUGH the facade and an in-envelope one lets it proceed.

NEGATIVE CONTROLS live alongside each: the permissive/enforced-off counterpart ALLOWs, so every DENY is
shown to come from the gate actually refusing, never from the facade being a no-op.
"""

from __future__ import annotations

import sys
import types

import pytest

pytest.importorskip("framework.v2.entitlement")
pytest.importorskip("framework.v2.kernel.sovereignty")

from vigil_core.gate import GateVerdict  # noqa: E402
from vigil_integration.sovereign_bridge import (  # noqa: E402
    AuthorizeRequest,
    DeploymentProfile,
    Effect,
    EnforcementMode,
    build_offense_bridge,
)


def _allow_verdict(*_a, **_k) -> GateVerdict:
    return GateVerdict(True, "allow", "in envelope (stub authority)", True, None)


@pytest.fixture
def _clean_sovereignty():
    from framework.v2.kernel import sovereignty as sov

    prior = sov.current()
    try:
        yield sov
    finally:
        sov.set_policy(None)
        # restore whatever was explicitly active before (None means env-derived; the default)
        if prior is not None and getattr(sov, "_active_policy", None) is None:
            pass  # env-derived default is the correct resting state


@pytest.fixture
def _clean_entitlement(monkeypatch):
    from framework.v2 import entitlement as ent

    ent.reset_policy()
    try:
        yield ent
    finally:
        monkeypatch.undo()
        ent.reset_policy()


# --------------------------------------------------------------------------------------------------------
# sovereignty leg — the REAL kernel sovereignty gate refuses a cloud backend through the facade
# --------------------------------------------------------------------------------------------------------
def test_air_gapped_tier_denies_cloud_backend_through_the_facade(_clean_sovereignty):
    sov = _clean_sovereignty
    sov.set_policy(sov.SovereigntyPolicy(tier=sov.Tier.AIR_GAPPED))

    bridge = build_offense_bridge(
        slug="acme", trust_root=object(), classify=lambda n: "A0",
        include_entitlement=False, base_gate=_allow_verdict,
    )
    req = AuthorizeRequest(tool_name="llm.chat", target_url="", backend="anthropic")
    d = bridge.authorize(req)
    assert d.effect is Effect.DENY, "AIR_GAPPED must refuse a cloud backend through the facade"
    assert d.denied_by == "sovereignty"
    assert d.reason_code == "SOVEREIGNTY_REFUSED"


def test_permissive_tier_allows_the_same_backend_through_the_facade(_clean_sovereignty):
    # NEGATIVE CONTROL: the gate is not a blanket no-op — flip the tier and the SAME request is allowed.
    sov = _clean_sovereignty
    sov.set_policy(sov.SovereigntyPolicy(tier=sov.Tier.PERMISSIVE))

    bridge = build_offense_bridge(
        slug="acme", trust_root=object(), classify=lambda n: "A0",
        include_entitlement=False, base_gate=_allow_verdict,
    )
    d = bridge.authorize(AuthorizeRequest(tool_name="llm.chat", target_url="", backend="anthropic"))
    assert d.effect is Effect.ALLOW, "PERMISSIVE must allow the backend the sovereignty gate permits"


# --------------------------------------------------------------------------------------------------------
# entitlement leg — the REAL require_capability refuses a non-baseline capability through the facade
# --------------------------------------------------------------------------------------------------------
def test_enforced_entitlement_denies_ungranted_capability_through_the_facade(
    _clean_sovereignty, _clean_entitlement, monkeypatch,
):
    from framework.v2.entitlement import Capability

    sov = _clean_sovereignty
    sov.set_policy(sov.SovereigntyPolicy(tier=sov.Tier.PERMISSIVE))  # let sovereignty pass; isolate entitlement
    monkeypatch.setenv("CRUCIBLE_ENTITLEMENT_ENFORCED", "1")  # active, but no trust root provisioned
    _clean_entitlement.reset_policy()

    bridge = build_offense_bridge(
        slug="acme", trust_root=object(), classify=lambda n: "A0", base_gate=_allow_verdict,
    )
    d = bridge.authorize(AuthorizeRequest(
        tool_name="exploit.run", target_url="", backend="ollama",
        capability=Capability.EXPLOIT_EXECUTION,
    ))
    assert d.effect is Effect.DENY, "an enforced entitlement with no grant must refuse a non-baseline cap"
    assert d.denied_by == "entitlement"
    assert d.reason_code == "ENTITLEMENT_DENIED"
    assert str(Capability.EXPLOIT_EXECUTION.value) == d.capability


def test_ungoverned_entitlement_allows_capability_through_the_facade(
    _clean_sovereignty, _clean_entitlement, monkeypatch,
):
    # NEGATIVE CONTROL: with enforcement OFF (dev default), the SAME capability request passes — proving the
    # DENY above came from the enforced gate, not from the facade refusing capabilities wholesale.
    from framework.v2.entitlement import Capability

    sov = _clean_sovereignty
    sov.set_policy(sov.SovereigntyPolicy(tier=sov.Tier.PERMISSIVE))
    monkeypatch.delenv("CRUCIBLE_ENTITLEMENT_ENFORCED", raising=False)
    _clean_entitlement.reset_policy()

    bridge = build_offense_bridge(
        slug="acme", trust_root=object(), classify=lambda n: "A0", base_gate=_allow_verdict,
    )
    d = bridge.authorize(AuthorizeRequest(
        tool_name="exploit.run", target_url="", backend="ollama",
        capability=Capability.EXPLOIT_EXECUTION,
    ))
    assert d.effect is Effect.ALLOW, "ungoverned entitlement must permit the capability (facade not a no-op)"


def test_entitlement_leg_with_no_capability_declared_fails_closed(_clean_sovereignty, _clean_entitlement):
    sov = _clean_sovereignty
    sov.set_policy(sov.SovereigntyPolicy(tier=sov.Tier.PERMISSIVE))

    bridge = build_offense_bridge(
        slug="acme", trust_root=object(), classify=lambda n: "A0", base_gate=_allow_verdict,
    )
    d = bridge.authorize(AuthorizeRequest(tool_name="exploit.run", target_url="", backend="ollama"))
    assert d.effect is Effect.DENY and d.denied_by == "entitlement"
    assert d.reason_code == "ENTITLEMENT_MISSING"


# --------------------------------------------------------------------------------------------------------
# authority leg — the REAL conjunctive gate-of-record decides through the facade (framework authority stubbed
# exactly as test_conjunctive_gate.py does, so no signed-authority provisioning is needed)
# --------------------------------------------------------------------------------------------------------
def _stub_framework_authority(monkeypatch, *, allowed: bool):
    for name in ("framework", "framework.v2", "framework.v2.authority"):
        monkeypatch.setitem(sys.modules, name, sys.modules.get(name) or types.ModuleType(name))
    gate_mod = types.ModuleType("framework.v2.authority.gate")
    gate_mod.load_authority_for_gate = lambda slug, trust_root: object()
    gate_mod.authorize_action = lambda authority, req, **kw: types.SimpleNamespace(
        allowed=allowed, reason=("in envelope" if allowed else "out of scope"),
    )
    models_mod = types.ModuleType("framework.v2.authority.models")
    models_mod.ActionRequest = lambda **kw: types.SimpleNamespace(**kw)
    monkeypatch.setitem(sys.modules, "framework.v2.authority.gate", gate_mod)
    monkeypatch.setitem(sys.modules, "framework.v2.authority.models", models_mod)


def test_real_conjunctive_authority_denies_out_of_envelope_through_the_facade(monkeypatch, _clean_sovereignty):
    from vigil_core import TrustRoot, generate_keypair

    kp = generate_keypair()
    from vigil_core import AuthorizerKey

    tr = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=kp.public_key_b64)])
    _stub_framework_authority(monkeypatch, allowed=False)
    _clean_sovereignty.set_policy(_clean_sovereignty.SovereigntyPolicy(tier=_clean_sovereignty.Tier.PERMISSIVE))

    # No base_gate injected → build_offense_bridge builds the REAL conjunctive gate over the stubbed authority.
    bridge = build_offense_bridge(
        slug="acme", trust_root=tr, classify=lambda n: "A0", floor="A0", ceiling="A3",
        include_sovereignty=False, include_entitlement=False,
    )
    d = bridge.authorize(AuthorizeRequest(tool_name="http.get", target_url="https://acme.test"))
    assert d.effect is Effect.DENY, "an out-of-envelope authority must deny through the facade"
    assert d.denied_by == "authority"
    assert d.reason_code == "OUT_OF_ENVELOPE"


def test_real_conjunctive_authority_allows_in_envelope_auto_tool_through_the_facade(
    monkeypatch, _clean_sovereignty,
):
    # NEGATIVE CONTROL for the authority leg: in-envelope + an A0 read tool under an A0 floor auto-allows.
    from vigil_core import AuthorizerKey, TrustRoot, generate_keypair

    kp = generate_keypair()
    tr = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=kp.public_key_b64)])
    _stub_framework_authority(monkeypatch, allowed=True)
    _clean_sovereignty.set_policy(_clean_sovereignty.SovereigntyPolicy(tier=_clean_sovereignty.Tier.PERMISSIVE))

    bridge = build_offense_bridge(
        slug="acme", trust_root=tr, classify=lambda n: "A0", floor="A0", ceiling="A3",
        include_sovereignty=False, include_entitlement=False,
    )
    d = bridge.authorize(AuthorizeRequest(tool_name="http.get", target_url="https://acme.test"))
    assert d.effect is Effect.ALLOW and d.denied_by is None


def test_offense_bridge_is_production_enforce_by_default(_clean_sovereignty):
    _clean_sovereignty.set_policy(_clean_sovereignty.SovereigntyPolicy(tier=_clean_sovereignty.Tier.PERMISSIVE))
    bridge = build_offense_bridge(
        slug="acme", trust_root=object(), classify=lambda n: "A0",
        include_sovereignty=False, include_entitlement=False, base_gate=_allow_verdict,
    )
    assert bridge.mode is EnforcementMode.ENFORCE
    assert bridge.profile is DeploymentProfile.PRODUCTION
