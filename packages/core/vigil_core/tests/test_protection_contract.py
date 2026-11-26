"""AEGIS AS-2b — the protection contract (§4.5) + the append-only provider registry.

Load-bearing invariants a false-green would break (a half-built contract reading as "enforcing"; a
provider slice silently rewriting an earlier provider; a non-deterministic registry breaking a
cross-plane digest; the baseline provider claiming an outcome class AS-1a cannot reach):

  * a MINIMAL contract reads fail-closed EVERYWHERE — ``headline`` and every dimension ``unsupported``,
    every term / prerequisite / lease at its non-enforcing value, the failure policy fail-CLOSED;
  * the contract and the provider registry ROUND-TRIP byte-identically (determinism);
  * the registry is APPEND-ONLY — ``register`` preserves the existing prefix, refuses a duplicate id,
    and never mutates the original (immutability);
  * the baseline SIGIL provider reaches outcome classes 1, 3 and 5 ONLY (contract V7);
  * ``extra='forbid'`` + a wrong ``schema`` string + a bad digest are rejected (negative controls);
  * the contract reuses the AS-2a ``OriginTuple`` (IP-literal origins refused) — no drift on "origin";
  * the module is FATAL-2 clean — no ``framework`` / ``sigil`` import.
"""
from __future__ import annotations

import ast
import importlib
import inspect
import json

import pytest


def _imported_roots(module_name: str) -> set[str]:
    """The top-level package roots a module IMPORTS (from real import statements, not its prose)."""
    mod = importlib.import_module(module_name)
    tree = ast.parse(inspect.getsource(mod))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    return roots

from vigil_core.aegis_schemas import AdapterCapability, AssetRef, EffectVerification, OutcomeClass
from vigil_core.authority_v2 import MonitoringCapability, OriginTuple
from vigil_core.monitoring_authority import MonitoringMode
from vigil_core.protection_contract import (
    BASELINE_SIGIL_PROVIDER,
    PROTECTION_CONTRACT_SCHEMA,
    PROVIDER_REGISTRY_SCHEMA,
    AuthorizedActions,
    BindingState,
    CertState,
    DuplicateProviderError,
    EdgeBlock,
    FailureBasis,
    Headline,
    LicensingMode,
    LockState,
    OriginBlock,
    ProtectionContract,
    ProviderDescriptor,
    ProviderRegistry,
    ReleaseState,
    RevocationState,
    SignerRole,
    baseline_provider_registry,
)


def _minimal_contract(**over: object) -> ProtectionContract:
    base: dict[str, object] = dict(
        asset=AssetRef(ref="a1", instance_id="i1"),
        origin=OriginBlock(tuple=OriginTuple(host="api.example.com")),
    )
    base.update(over)
    return ProtectionContract(**base)  # type: ignore[arg-type]


# --- fail-closed defaults ------------------------------------------------------------------------
def test_minimal_contract_reads_fail_closed() -> None:
    c = _minimal_contract()
    assert c.headline is Headline.UNSUPPORTED
    for level in (c.dimensions.asset_placement, c.dimensions.edge, c.dimensions.origin_lock,
                  c.dimensions.telemetry, c.dimensions.detection_enforcement,
                  c.dimensions.authority_release):
        assert level is Headline.UNSUPPORTED
    assert c.licensing_mode is LicensingMode.UNKNOWN
    # authority / enforcement all at the non-enforcing floor:
    assert c.authorized_actions.mode is MonitoringMode.OBSERVE
    assert c.authorized_actions.capabilities == []
    assert c.authorized_actions.lease.valid is False
    assert c.authorized_actions.revocation.state is RevocationState.NONE
    assert c.authorized_actions.signer_role is SignerRole.NONE
    assert c.enforcement_terms.effective is False
    assert c.enforcement_terms.flag is False
    assert c.enforcement_terms.enforce_release.state is ReleaseState.NONE
    # failure policy fail-CLOSED, prerequisites UNMET:
    assert c.failure_policy.gateway_down is FailureBasis.FAIL_CLOSED
    assert c.failure_policy.overload is FailureBasis.FAIL_CLOSED
    assert c.customer_prerequisites.origin_bound is False
    assert c.customer_prerequisites.crypto_lock is False
    # origin binding / lock / cert at their floors:
    assert c.origin.binding.state is BindingState.UNVERIFIED
    assert c.origin.lock.state is LockState.NONE
    assert c.edge.viewer_tls.cert_state is CertState.UNKNOWN
    assert c.edge.chain == "shared_actor"


def test_trust_assumptions_default_true_surfacing_limitations() -> None:
    t = _minimal_contract().trust_assumptions
    assert t.sigil_unit_sees_plaintext is True
    assert t.ip_allowlist_lock_does_not_isolate_tenants is True
    assert t.gateway_reported_not_independent is True


# --- round-trip + determinism --------------------------------------------------------------------
def test_contract_round_trip_byte_identical() -> None:
    c = _minimal_contract(
        headline=Headline.OBSERVING,
        available_telemetry=["request_meta", "llm_io"],
        not_observed=["websocket", "chunked", "websocket"],
        enforcement_capabilities=[
            AdapterCapability(kind="inline_block", outcome_class=OutcomeClass.PREVENTED_BEFORE_EXECUTION,
                              effect_verification=EffectVerification.RECEIPT)],
        authorized_actions=AuthorizedActions(capabilities=[MonitoringCapability.OBSERVE,
                                                           MonitoringCapability.BLOCK]),
        versions={"contract": "v1", "event": "v2"},
    )
    cb = c.canonical_bytes()
    c2 = ProtectionContract.parse(json.loads(cb))
    assert c2 == c
    assert c2.canonical_bytes() == cb
    assert c.digest() == c2.digest()
    assert c.not_observed == ["chunked", "websocket"]  # sorted + de-duplicated
    assert f'"schema":"{PROTECTION_CONTRACT_SCHEMA}"'.encode() in cb


def test_contract_list_order_independence() -> None:
    a = _minimal_contract(available_telemetry=["b", "a"])
    b = _minimal_contract(available_telemetry=["a", "b"])
    assert a.canonical_bytes() == b.canonical_bytes()


# --- the append-only provider registry -----------------------------------------------------------
def test_baseline_provider_reaches_only_classes_1_3_5() -> None:
    reached = set(BASELINE_SIGIL_PROVIDER.outcome_classes)
    assert reached == {OutcomeClass.PREVENTED_BEFORE_EXECUTION,
                       OutcomeClass.RESPONSE_WITHHELD_AFTER_EXECUTION,
                       OutcomeClass.DETECTED_WITHOUT_ENFORCEMENT}
    assert OutcomeClass.INTERRUPTED_AFTER_PARTIAL_EXECUTION not in reached  # class 2
    assert OutcomeClass.CONTAINED_AFTER_COMPROMISE not in reached           # class 4


def test_registry_register_is_append_only_and_immutable() -> None:
    reg = baseline_provider_registry()
    assert reg.provider_ids == ("sigil_gateway",)
    extra = ProviderDescriptor(provider_id="guardduty", title="GuardDuty",
                               capabilities=[AdapterCapability(
                                   kind="guardduty_finding",
                                   outcome_class=OutcomeClass.DETECTED_WITHOUT_ENFORCEMENT,
                                   effect_verification=EffectVerification.REPORTED)])
    reg2 = reg.register(extra)
    # prefix preserved, provider appended at the end, original UNCHANGED:
    assert reg2.providers[: len(reg.providers)] == reg.providers
    assert reg2.provider_ids == ("sigil_gateway", "guardduty")
    assert reg.provider_ids == ("sigil_gateway",)
    assert reg2.get("guardduty") is extra


def test_registry_providers_tuple_refuses_in_place_mutation() -> None:
    # frozen=True blocks REASSIGNMENT of `providers`, but a list would still accept .append(...) /
    # providers[i] = ... on a HELD instance, bypassing register()'s append-only + dedup guard and the
    # _no_dupes validator. Storing providers as an immutable tuple refuses both in-place mutations.
    reg = baseline_provider_registry()
    extra = ProviderDescriptor(provider_id="guardduty",
                               capabilities=[AdapterCapability(
                                   kind="guardduty_finding",
                                   outcome_class=OutcomeClass.DETECTED_WITHOUT_ENFORCEMENT,
                                   effect_verification=EffectVerification.REPORTED)])
    assert isinstance(reg.providers, tuple)
    with pytest.raises(AttributeError):
        reg.providers.append(extra)  # type: ignore[attr-defined]
    with pytest.raises(TypeError):
        reg.providers[0] = extra  # type: ignore[index]
    # the held registry is unchanged — the only growth path is register(), which returns a new registry:
    assert reg.provider_ids == ("sigil_gateway",)
    assert reg.register(extra).provider_ids == ("sigil_gateway", "guardduty")


def test_registry_inner_descriptor_and_capability_are_frozen_and_singleton_unpoisonable() -> None:
    # red-pen wufm8d7z1: the OUTER tuple was immutable but a HELD descriptor and its capabilities list were not, so an
    # in-place edit could over-claim an outcome class, bypass clean_token on title via assignment, and — through the
    # shared BASELINE_SIGIL_PROVIDER singleton — poison every other caller process-wide. Lock all of it.
    import pydantic

    from vigil_core.protection_contract import BASELINE_SIGIL_PROVIDER

    reg_a = baseline_provider_registry()
    reg_b = baseline_provider_registry()
    assert reg_a.providers[0] is reg_b.providers[0] is BASELINE_SIGIL_PROVIDER   # still a shared singleton...
    assert isinstance(reg_a.providers[0].capabilities, tuple)                    # ...now deeply immutable, so safe
    with pytest.raises(pydantic.ValidationError):
        reg_a.providers[0].provider_id = "x"                                    # frozen descriptor
    with pytest.raises(pydantic.ValidationError):
        reg_a.providers[0].title = "SIGIL spoof"                                # assignment cannot bypass clean_token
    with pytest.raises(AttributeError):
        reg_a.providers[0].capabilities.append(                                 # tuple, not list
            AdapterCapability(kind="contain", outcome_class=OutcomeClass.CONTAINED_AFTER_COMPROMISE,
                              effect_verification=EffectVerification.NONE))
    with pytest.raises(pydantic.ValidationError):
        reg_a.providers[0].capabilities[0].outcome_class = OutcomeClass.CONTAINED_AFTER_COMPROMISE  # frozen capability
    # a brand-new baseline is uncontaminated — nothing leaked through the singleton:
    fresh = baseline_provider_registry().providers[0]
    assert OutcomeClass.CONTAINED_AFTER_COMPROMISE not in fresh.outcome_classes
    assert fresh.title == "SIGIL in-request-path gateway"


def test_registry_refuses_duplicate_provider_id() -> None:
    reg = baseline_provider_registry()
    dup = ProviderDescriptor(provider_id="sigil_gateway",
                             capabilities=[AdapterCapability(
                                 kind="x", outcome_class=OutcomeClass.DETECTED_WITHOUT_ENFORCEMENT)])
    with pytest.raises(DuplicateProviderError):
        reg.register(dup)
    # a registry CONSTRUCTED with duplicate ids is also refused:
    with pytest.raises(ValueError):
        ProviderRegistry(providers=[BASELINE_SIGIL_PROVIDER, BASELINE_SIGIL_PROVIDER])


def test_registry_round_trip_byte_identical() -> None:
    reg = baseline_provider_registry().register(
        ProviderDescriptor(provider_id="cloudtrail",
                           capabilities=[AdapterCapability(
                               kind="cloudtrail", outcome_class=OutcomeClass.DETECTED_WITHOUT_ENFORCEMENT)]))
    cb = reg.canonical_bytes()
    assert ProviderRegistry.parse(json.loads(cb)).canonical_bytes() == cb
    assert f'"schema":"{PROVIDER_REGISTRY_SCHEMA}"'.encode() in cb


def test_provider_requires_at_least_one_capability() -> None:
    with pytest.raises(Exception):
        ProviderDescriptor(provider_id="empty", capabilities=[])


# --- negative controls ---------------------------------------------------------------------------
def test_unknown_key_rejected() -> None:
    with pytest.raises(Exception):
        _minimal_contract(bogus="x")


def test_wrong_schema_rejected() -> None:
    bad = json.loads(_minimal_contract().canonical_bytes())
    bad["schema"] = "vigil.aegis.protection-contract.v2"
    with pytest.raises(ValueError):
        ProtectionContract.parse(bad)


def test_ip_literal_origin_refused_via_reused_origin_tuple() -> None:
    with pytest.raises(ValueError):
        OriginBlock(tuple=OriginTuple(host="169.254.169.254"))


def test_bad_grant_digest_rejected() -> None:
    with pytest.raises(ValueError):
        AuthorizedActions(grant_sha256="deadbeef")


def test_versions_rejects_control_chars() -> None:
    with pytest.raises(ValueError):
        _minimal_contract(versions={"event": "v2\n"})


# --- FATAL-2 cleanliness -------------------------------------------------------------------------
def test_module_is_fatal2_clean() -> None:
    assert _imported_roots("vigil_core.protection_contract").isdisjoint({"framework", "sigil"})
