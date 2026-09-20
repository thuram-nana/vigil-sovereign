"""
test_authority_root_decouple — the Phase 0.1 authority/entitlement storage decouple.

Phase 0.1 (#803) made a remote engage require an owner-signed, threshold-verified authority, and
``wiring.provision_authority`` PERSISTS that authority's trust root so the engage path and the console
remote-engage gate can load + verify it. The DEFECT this locks the fix for: the trust root was written to
``.entitlement/trust-root.json`` — the SAME file ``entitlement.policy._enforcement_active()`` keys CAPABILITY
enforcement on — so provisioning an authority collaterally flipped entitlement enforcement ON. With no
entitlement GRANT minted, every gated capability (``deep_static_analysis`` / ``active_recon`` /
``exploit_execution``) then DENIED, silently breaking ``vigil codescan`` / deep-fix / recon on the first
``vigil engage`` of a fresh deploy.

The fix DECOUPLES the storage: the authority trust root lives in a dedicated store
(``framework.v2.authority.store.write_authority_root`` / ``load_authority_root`` ->
``<v2_root>/.authority-root/trust-root.json``, override ``VIGIL_AUTHORITY_ROOT_DIR``) that
``entitlement.policy`` does NOT watch. This test proves BOTH halves hold:

  1. REGRESSION GONE  — provisioning an authority does NOT activate entitlement enforcement; a gated
     capability stays ALLOWED (ungoverned) with no entitlement trust root on disk.
  2. AUTHORITY GATE HOLDS — the remote-engage gate + the engage-path resolver still FIND + VERIFY a
     provisioned authority via the new store, and still REFUSE fail-closed when none is provisioned.

Offense leg (imports ``framework`` behind an importorskip) — runs only where CRUCIBLE is importable.
The autouse fixtures in integration/conftest.py isolate BOTH ``CRUCIBLE_ENTITLEMENT_DIR`` and
``VIGIL_AUTHORITY_ROOT_DIR`` to throwaway per-test dirs, so "fresh deploy" is the true starting state.
"""

from __future__ import annotations

import pytest

pytest.importorskip("framework.v2.authority.charter", reason="CRUCIBLE (offense) not importable here")
pytest.importorskip("framework.v2.entitlement", reason="entitlement package not importable here")

from vigil_integration.live.wiring import provision_authority  # noqa: E402


# --------------------------------------------------------------------------------------------------------
# 1. THE REGRESSION — provisioning an authority must not activate entitlement capability enforcement
# --------------------------------------------------------------------------------------------------------
def test_provisioning_an_authority_does_not_activate_entitlement_enforcement(tmp_path):
    from framework.v2 import entitlement as ent
    from framework.v2.authority.store import load_authority_root
    from framework.v2.common import paths
    from framework.v2.entitlement import Capability

    # FRESH DEPLOY baseline: no entitlement trust root, no authority root -> ungoverned -> gated cap ALLOWED.
    ent.reset_policy()
    assert not paths.trust_root_path().is_file(), "precondition: entitlement store must start empty"
    assert load_authority_root() is None, "precondition: authority-root store must start empty"
    assert ent.current_policy().enforced is False
    assert ent.is_capability_available(Capability.DEEP_STATIC_ANALYSIS) is True

    # Provision a signed authority the way build_engine does on the first engage (homed governance key).
    prov = provision_authority(slug="regress-decouple", scope=["127.0.0.1"], base_dir=str(tmp_path))
    assert prov.trust_root is not None

    # The authority root WAS persisted — to the DEDICATED authority-root store, NOT the entitlement store.
    assert load_authority_root() is not None, "authority trust root must persist to the new store"
    assert paths.authority_root_path().is_file(), "authority root must be written to .authority-root/"
    assert not paths.trust_root_path().is_file(), (
        "REGRESSION: provisioning an authority must NOT write the entitlement trust root "
        "(that is the file entitlement.policy keys enforcement on)")

    # THE INVARIANT: entitlement enforcement stays INACTIVE, so the gated capability is still ALLOWED.
    ent.reset_policy()   # force a re-read of disk (the enforcement decision is cached)
    assert ent.current_policy().enforced is False, (
        "provisioning an authority must not flip entitlement enforcement ON")
    decision = ent.require_capability(Capability.DEEP_STATIC_ANALYSIS)   # must NOT raise
    assert decision.allowed is True
    assert decision.enforced is False
    # active_recon is the other capability the defect broke — same result.
    assert ent.is_capability_available(Capability.ACTIVE_RECON) is True


def test_negative_control_a_real_entitlement_trust_root_still_activates_enforcement(tmp_path, monkeypatch):
    """Negative control: the decouple did NOT neuter the enforcement switch. Writing a trust root through the
    REAL entitlement provisioning flow (the operator's explicit ``.entitlement/`` path) still flips enforcement
    ON — and with no grant minted, the gated capability is then DENIED. This proves test #1's ALLOW came from
    the storage being decoupled, not from enforcement being globally disabled."""
    from framework.v2 import entitlement as ent
    from framework.v2.entitlement import Capability
    from framework.v2.entitlement.provision import build_trust_root, new_authorizer, write_trust_root

    ak, _priv = new_authorizer("owner-0", "Owner")
    write_trust_root(build_trust_root([ak], threshold=1))   # the LEGITIMATE entitlement flow (entitlement/cli)
    ent.reset_policy()
    assert ent.current_policy().enforced is True, "an entitlement trust root MUST activate enforcement"
    with pytest.raises(Exception):   # no grant minted -> EntitlementMissing -> DENY
        ent.require_capability(Capability.DEEP_STATIC_ANALYSIS)


# --------------------------------------------------------------------------------------------------------
# 2. THE AUTHORITY GATE STILL HOLDS — find + verify via the new store; refuse fail-closed when unprovisioned
# --------------------------------------------------------------------------------------------------------
def test_authority_gate_finds_a_provisioned_authority_via_the_new_store(tmp_path, monkeypatch):
    from framework.v2 import engage
    from framework.v2.common import paths
    from framework.v2.console import actions

    # Isolate the authority-DOCUMENT dir too (its default `.authority/` is not env-overridable), so the doc
    # provision writes and the doc the gate reads land in one throwaway place — no in-tree pollution / leak.
    authority_docs = tmp_path / "authority-docs"
    monkeypatch.setattr(paths, "authority_dir", lambda: authority_docs)

    slug = "acme-remote"

    # UNPROVISIONED: no authority document and no authority root -> both read sites refuse, fail-closed.
    assert actions._has_verified_authority(slug) is False, "no authority provisioned -> remote engage refused"
    assert engage._engage_authority_trust_root(slug) is None, "no authority doc -> greenfield (kill-switch only)"

    # Provision an owner-signed authority for the slug (writes the signed doc + the authority root).
    prov = provision_authority(slug=slug, scope=["10.0.0.5"], base_dir=str(tmp_path))
    assert prov.authority_path  # the signed authority document was written

    # The gate now FINDS + VERIFIES the authority via the DEDICATED authority-root store (not the entitlement one).
    assert actions._has_verified_authority(slug) is True, (
        "a provisioned owner-signed authority must be found + verified via the new authority-root store")
    # The engage path pins the SAME governance trust root (non-None) for the provisioned slug.
    assert engage._engage_authority_trust_root(slug) is not None, (
        "engage must discover the authority trust root from the new store to load the authority VERIFIED")

    # A DIFFERENT slug (no authority document) is still refused, even though a root now exists on disk —
    # verification requires the per-slug signed document, so the gate is not a blanket allow.
    assert actions._has_verified_authority("some-other-slug") is False


def test_write_and_read_target_the_same_authority_root_store(tmp_path):
    """Proof the WRITE and both READS agree on one location: what provision_authority persists is exactly what
    load_authority_root (used by BOTH read sites) reads back — a byte-faithful round-trip through the new store."""
    from framework.v2.authority.store import load_authority_root

    prov = provision_authority(slug="roundtrip", scope=["127.0.0.1"], base_dir=str(tmp_path))
    loaded = load_authority_root()
    assert loaded is not None
    # same TrustRoot material — only the storage LOCATION changed vs. the old entitlement-store write.
    assert loaded.model_dump(mode="json") == prov.trust_root.model_dump(mode="json")
