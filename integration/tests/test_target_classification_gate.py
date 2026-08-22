"""W13-4 (#497) — the target-classification leg composed INTO the sovereign_bridge facade.

This is the facade-wiring companion to ``packages/core/vigil_core/tests/test_target_classification.py``
(which pins the pure classifier). It runs in the SOVEREIGN leg of the required "integration two-env boundary
(P5)" CI job: it imports ``framework`` NOWHERE — the classification leg is a stdlib-only leaf, and the
authority/sovereignty/entitlement legs are turned off or injected, so the whole facade is exercised without
the offense engine. What it pins:

  * classification is ON by default and runs FIRST in the offense chain (UNKNOWN is refused before any other
    leg) — proving the guardrail is bound into the EXISTING gate decision, not a separate one;
  * an UNKNOWN target is refused THROUGH the facade, attributed to the classification leg;
  * a registered in-scope asset is ALLOWED through the facade, and — the STRUCTURAL proof — the SAME
    downstream authority gate is still traversed (registration automates, it does not bypass);
  * NEGATIVE CONTROL: a target explicitly classified OUT_OF_SCOPE is refused even with a permissive scope;
  * FAILS WITHOUT THE FIX: build_offense_bridge grows the ``include_classification`` / ``asset_store`` /
    ``scope_check`` seam here — on a tree without W13-4 these kwargs raise ``TypeError`` and every test fails.

FATAL-2: importing the facade + the classifier loads neither ``framework`` nor ``strix`` nor ``sigil``.
"""

from __future__ import annotations

import sys

from vigil_core.gate import GateVerdict
from vigil_core.target_classification import RegisteredAssetStore, TargetClass
from vigil_integration.sovereign_bridge import (
    AuthorizeRequest,
    Effect,
    build_offense_bridge,
)


def _allow_authority(*_a, **_k) -> GateVerdict:
    return GateVerdict(True, "allow", "in envelope (stub authority)", True, None)


def _spy_authority():
    """An authority stub that RECORDS being called, so a test can prove the downstream gate is traversed even
    when classification allowed (the registered-asset store automates, it does not bypass)."""
    calls: list[tuple] = []

    def gate(tool_name, target_url, destructive=False, **_k) -> GateVerdict:
        calls.append((tool_name, target_url, destructive))
        return GateVerdict(True, "allow", "in envelope (spy authority)", True, None)

    return gate, calls


# ---------------------------------------------------------------------------------------------------------
# classification is ON by default and runs first
# ---------------------------------------------------------------------------------------------------------
def test_classification_is_on_by_default_and_is_the_first_leg():
    bridge = build_offense_bridge(
        slug="acme", trust_root=object(), classify=lambda n: "A0",
        include_sovereignty=False, include_entitlement=False,
        scope_check=lambda h: True, base_gate=_allow_authority,
    )
    assert bridge.gate_names[0] == "classification"
    assert "authority" in bridge.gate_names


# ---------------------------------------------------------------------------------------------------------
# UNKNOWN is refused through the facade, attributed to the classification leg
# ---------------------------------------------------------------------------------------------------------
def test_unknown_target_is_refused_through_the_facade():
    spy, calls = _spy_authority()
    bridge = build_offense_bridge(
        slug="acme", trust_root=object(), classify=lambda n: "A0",
        include_sovereignty=False, include_entitlement=False,
        asset_store=RegisteredAssetStore(),      # nothing registered
        scope_check=lambda h: False,             # nothing in scope → UNKNOWN
        base_gate=spy,
    )
    d = bridge.authorize(AuthorizeRequest(tool_name="http.get", target_url="https://stranger.test"))
    assert d.effect is Effect.DENY
    assert d.denied_by == "classification"
    assert d.reason_code == "TARGET_UNKNOWN"
    # short-circuit: the downstream authority gate was NEVER reached for an unknown target.
    assert calls == []


def test_empty_target_is_refused_as_unknown_through_the_facade():
    bridge = build_offense_bridge(
        slug="acme", trust_root=object(), classify=lambda n: "A0",
        include_sovereignty=False, include_entitlement=False,
        scope_check=lambda h: True, base_gate=_allow_authority,
    )
    d = bridge.authorize(AuthorizeRequest(tool_name="http.get", target_url=""))
    assert d.effect is Effect.DENY and d.denied_by == "classification"
    assert d.reason_code == "TARGET_UNKNOWN"


# ---------------------------------------------------------------------------------------------------------
# a registered in-scope asset is allowed — and the same downstream gate is still traversed
# ---------------------------------------------------------------------------------------------------------
def test_registered_asset_is_allowed_and_the_authority_gate_is_still_traversed():
    store = RegisteredAssetStore()
    store.register("lab.acme.test", TargetClass.OWN_INFRA, note="registered lab box")
    spy, calls = _spy_authority()
    bridge = build_offense_bridge(
        slug="acme", trust_root=object(), classify=lambda n: "A0",
        include_sovereignty=False, include_entitlement=False,
        asset_store=store,
        scope_check=lambda h: False,   # NOT relying on scope — the registration is what classifies it
        base_gate=spy,
    )
    d = bridge.authorize(AuthorizeRequest(tool_name="http.get", target_url="https://lab.acme.test/x"))
    assert d.effect is Effect.ALLOW, "a registered own-infra asset must be allowed through the facade"
    # STRUCTURAL: registration AUTOMATED classification but did NOT bypass the authority gate — it ran.
    assert calls == [("http.get", "https://lab.acme.test/x", False)]


def test_in_scope_target_without_registration_is_allowed_via_the_charter_scope():
    # NEGATIVE CONTROL for the classification leg being a real gate: flip scope_check and the SAME
    # unregistered target flips from refused (UNKNOWN) to allowed (own-infra via the charter scope).
    spy, calls = _spy_authority()
    bridge = build_offense_bridge(
        slug="acme", trust_root=object(), classify=lambda n: "A0",
        include_sovereignty=False, include_entitlement=False,
        scope_check=lambda h: h == "app.acme.test", base_gate=spy,
    )
    allowed = bridge.authorize(AuthorizeRequest(tool_name="http.get", target_url="https://app.acme.test"))
    assert allowed.effect is Effect.ALLOW and calls == [("http.get", "https://app.acme.test", False)]

    refused = bridge.authorize(AuthorizeRequest(tool_name="http.get", target_url="https://elsewhere.test"))
    assert refused.effect is Effect.DENY and refused.denied_by == "classification"


# ---------------------------------------------------------------------------------------------------------
# NEGATIVE CONTROL — a classified OUT_OF_SCOPE target is refused even with a permissive scope
# ---------------------------------------------------------------------------------------------------------
def test_registered_out_of_scope_target_is_refused_through_the_facade():
    store = RegisteredAssetStore()
    store.register("forbidden.test", TargetClass.OUT_OF_SCOPE, note="explicitly forbidden")
    spy, calls = _spy_authority()
    bridge = build_offense_bridge(
        slug="acme", trust_root=object(), classify=lambda n: "A0",
        include_sovereignty=False, include_entitlement=False,
        asset_store=store,
        scope_check=lambda h: True,   # permissive scope — the registration must still win and DENY
        base_gate=spy,
    )
    d = bridge.authorize(AuthorizeRequest(tool_name="http.get", target_url="https://forbidden.test"))
    assert d.effect is Effect.DENY
    assert d.denied_by == "classification"
    assert d.reason_code == "TARGET_OUT_OF_SCOPE"
    assert calls == []   # denied before the downstream gate


def test_classification_can_be_disabled_only_by_explicit_composition_not_a_runtime_flag():
    # Turning the leg off is CHAIN COMPOSITION at build time, never a per-request bypass: with it off the
    # chain does not contain it, and the request object has no field that could switch it back on.
    bridge = build_offense_bridge(
        slug="acme", trust_root=object(), classify=lambda n: "A0",
        include_classification=False, include_sovereignty=False, include_entitlement=False,
        base_gate=_allow_authority,
    )
    assert "classification" not in bridge.gate_names


def test_classifier_and_facade_import_is_two_env_clean():
    # FATAL-2, proven in an ISOLATED subprocess (so it holds even under the offense venv, where framework IS
    # installed but must not be pulled in by importing the classifier or the facade).
    import os
    import subprocess
    from pathlib import Path

    repo = Path(__file__).resolve().parents[2]
    probe = (
        "import sys; "
        "import vigil_core.target_classification as tc; "
        "import vigil_integration.sovereign_bridge as m; "
        "assert 'framework' not in sys.modules, 'framework leaked'; "
        "assert 'strix' not in sys.modules, 'strix leaked'; "
        "assert 'sigil' not in sys.modules, 'sigil leaked'; "
        "assert hasattr(tc, 'classify_target') and hasattr(m, 'build_offense_bridge'); print('CLEAN')"
    )
    env = {
        # include the repo's vigil_core so the probe uses the TREE-UNDER-TEST (CI pip-installs it from the
        # branch; a local editable venv may point at a different checkout) — the FATAL-2 assertion is what matters.
        "PYTHONPATH": f"{repo / 'integration'}:{repo / 'gateway'}:{repo / 'packages' / 'core' / 'vigil_core'}",
        "PATH": os.environ.get("PATH", ""),
    }
    out = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True, env=env, timeout=60)
    assert out.returncode == 0 and "CLEAN" in out.stdout, f"FATAL-2 probe failed: {out.stdout}\n{out.stderr}"
