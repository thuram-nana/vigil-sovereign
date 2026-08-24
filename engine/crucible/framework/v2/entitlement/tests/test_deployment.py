"""
W13-3 (#496) — the deployment class + lifecycle EXTEND the entitlement layer
with NO duplicated policy.

Fail-without-fix: imports ``..deployment`` at module scope (absent on a tree
without W13-3 → collection error).

Negative controls:
  * a non-ACTIVE deployment is refused by the lifecycle gate;
  * a tampered profile fails signature verification; and
  * a structural assertion that this module defines NO capability→tier policy
    (the capability decision stays in policy.py), so the extension cannot have
    silently duplicated the entitlement's policy.
"""

from __future__ import annotations

import ast
import inspect
from datetime import datetime, timezone

import pytest

from ...common.errors import DeploymentNotOperable
from .. import deployment as deployment_module
from .. import provision
from ..deployment import (
    DeploymentClass,
    DeploymentLifecycle,
    DeploymentProfileDocument,
    is_operable,
    require_operable_deployment,
    sign_deployment_profile,
    verify_deployment_profile,
)
from ..models import AuthorizerKey, TrustRoot

_NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)


def _profile(lifecycle: DeploymentLifecycle) -> DeploymentProfileDocument:
    return DeploymentProfileDocument(
        profile_id="dep-1",
        entitlement_id="ent-42",
        customer="ACME Corp",
        deployment_class=DeploymentClass.PRODUCTION,
        lifecycle=lifecycle,
        issued_at=_NOW,
    )


def _authorizer_set(n: int, threshold: int) -> tuple[TrustRoot, dict[str, str]]:
    authorizers: list[AuthorizerKey] = []
    privs: dict[str, str] = {}
    for i in range(n):
        ak, priv = provision.new_authorizer(f"a{i}", f"Authoriser {i}")
        authorizers.append(ak)
        privs[f"a{i}"] = priv
    return provision.build_trust_root(authorizers, threshold), privs


# ---------------------------------------------------------------------------
# Deployment class REUSES the one deployment taxonomy of record
# ---------------------------------------------------------------------------


def test_deployment_class_is_the_shared_taxonomy() -> None:
    from vigil_core.target_classification import DeploymentMode

    # Re-exported, not re-minted: same enum object, so it cannot drift.
    assert DeploymentClass is DeploymentMode
    assert {c.value for c in DeploymentClass} >= {
        "local_offline",
        "local_lab",
        "staging",
        "production",
        "reviewer",
    }


# ---------------------------------------------------------------------------
# Lifecycle gate — only ACTIVE is operable
# ---------------------------------------------------------------------------


def test_active_deployment_is_operable() -> None:
    doc = _profile(DeploymentLifecycle.ACTIVE)
    assert is_operable(doc) is True
    require_operable_deployment(doc)  # does not raise


@pytest.mark.parametrize(
    "lifecycle",
    [
        DeploymentLifecycle.DRAFT,
        DeploymentLifecycle.SUSPENDED,
        DeploymentLifecycle.EXPIRED,
        DeploymentLifecycle.REVOKED,
    ],
)
def test_negative_control_non_active_deployment_is_refused(
    lifecycle: DeploymentLifecycle,
) -> None:
    doc = _profile(lifecycle)
    assert is_operable(doc) is False
    with pytest.raises(DeploymentNotOperable):
        require_operable_deployment(doc)


# ---------------------------------------------------------------------------
# Signed + tamper-evident
# ---------------------------------------------------------------------------


def test_sign_and_verify_roundtrip() -> None:
    tr, privs = _authorizer_set(3, 2)
    signed = sign_deployment_profile(
        _profile(DeploymentLifecycle.ACTIVE), {"a0": privs["a0"], "a1": privs["a1"]}
    )
    ok, _ = verify_deployment_profile(signed, tr)
    assert ok is True


def test_negative_control_tampered_lifecycle_is_detected() -> None:
    # Flip a SUSPENDED profile to ACTIVE after signing — verification must fail.
    tr, privs = _authorizer_set(1, 1)
    signed = sign_deployment_profile(_profile(DeploymentLifecycle.SUSPENDED), {"a0": privs["a0"]})
    tampered = signed.model_copy(
        update={
            "document": signed.document.model_copy(
                update={"lifecycle": DeploymentLifecycle.ACTIVE}
            )
        }
    )
    ok, _ = verify_deployment_profile(tampered, tr)
    assert ok is False


def test_below_threshold_fails() -> None:
    tr, privs = _authorizer_set(3, 2)
    signed = sign_deployment_profile(_profile(DeploymentLifecycle.ACTIVE), {"a0": privs["a0"]})
    ok, _ = verify_deployment_profile(signed, tr)
    assert ok is False


# ---------------------------------------------------------------------------
# NO DUPLICATED POLICY — the extension defines no capability→tier map; the
# capability decision stays in policy.py.
# ---------------------------------------------------------------------------


def test_no_duplicated_capability_policy() -> None:
    src = inspect.getsource(deployment_module)
    # The deployment extension must not re-implement the capability ladder.
    for forbidden in ("REQUIRED_TIER", "CapabilityTier", "effective_capabilities", "tier_permits"):
        assert forbidden not in src, (
            f"deployment.py references {forbidden!r} — the capability decision "
            f"must stay in entitlement.policy, not be duplicated in the deployment leg"
        )


def test_deployment_module_defines_no_capability_fields() -> None:
    # The signed profile carries class/customer/lifecycle/entitlement_id — NOT a
    # capability list or tier (those live in the referenced SignedEntitlement).
    fields = set(DeploymentProfileDocument.model_fields)
    assert "entitlement_id" in fields  # it REFERENCES the capability grant
    assert "capability_tier" not in fields
    assert "granted_capabilities" not in fields


def test_the_lifecycle_gate_and_capability_gate_are_distinct_symbols() -> None:
    # Prove composition, not duplication: the lifecycle gate lives here; the
    # capability gate is imported from policy and is a DIFFERENT function.
    from .. import require_capability

    assert require_operable_deployment is not require_capability
    # The deployment module does not shadow/redefine require_capability.
    tree = ast.parse(inspect.getsource(deployment_module))
    defined = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    assert "require_capability" not in defined
