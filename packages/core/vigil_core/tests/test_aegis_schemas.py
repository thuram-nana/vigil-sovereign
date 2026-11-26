"""AEGIS AS-2b — the base data contracts (``aegis_schemas``).

Load-bearing invariants a false-green would break (a consumer over-claiming protection from a
half-built record; a non-deterministic wire form breaking a cross-plane digest; a malformed event
smuggling a control char into a rendered card; the baseline claiming an outcome class 1a cannot
reach):

  * every contract ROUND-TRIPS: build -> canonical_bytes -> json.loads -> parse -> equal, and the
    re-serialised bytes are BYTE-IDENTICAL (determinism is independent of input field / list order);
  * every state enum DEFAULTS to its SAFEST member (``unknown`` health, ``none`` effect-verification,
    empty reachable set) — absence never reads as "healthy" / "verified" / "reachable";
  * ``extra='forbid'`` makes an unknown key a parse rejection (malformed -> reject, negative control);
  * a wrong ``schema`` string is refused (a v1 payload can never masquerade as a v2 event);
  * ``Criticality.authority`` is pinned to ``none`` — tenant criticality carries no authority;
  * a host that is an IP literal is refused (no bare-IP origin, SSRF floor);
  * the baseline response manifest reaches outcome classes 1, 3 and 5 ONLY (contract V7);
  * forward-compatibility: a payload omitting a later-added optional field still parses (defaults);
  * the module is FATAL-2 clean — it imports no ``framework`` / ``sigil`` symbol.
"""
from __future__ import annotations

import ast
import inspect
import importlib
import json

import pytest


def _imported_roots(module_name: str) -> set[str]:
    """The set of top-level package roots this module IMPORTS (from its real import statements, not a
    substring of its prose). FATAL-2 forbids ``framework`` (the offensive engine) and ``sigil`` (the
    sovereign app) from a ``vigil_core`` module."""
    mod = importlib.import_module(module_name)
    tree = ast.parse(inspect.getsource(mod))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    return roots

from vigil_core.aegis_schemas import (
    ALL_OUTCOME_CLASSES,
    BASELINE_REACHABLE_OUTCOMES,
    EVENT_V2_SCHEMA,
    HEALTH_V1_SCHEMA,
    RESPONSE_MANIFEST_SCHEMA,
    AdapterCapability,
    AegisEventV2,
    AssetRef,
    Criticality,
    EffectVerification,
    EngineHealth,
    EngineHealthState,
    OutcomeClass,
    PlacementState,
    ResponseDeadlines,
    ResponseManifest,
    baseline_response_manifest,
    clean_token,
)


def _event(**over: object) -> AegisEventV2:
    base: dict[str, object] = dict(
        org_id="acme", host="api.example.com", instance_id="i1", epoch=2, seq=5,
        decision="confirmed", attack_class="sqli", action="block", confidence=0.9,
        provenance_tier="grounded", certificate_sha256="a" * 64,
        outcome_class=OutcomeClass.PREVENTED_BEFORE_EXECUTION, rule_refs=["r1", "r2"], event_id="ev1",
    )
    base.update(over)
    return AegisEventV2(**base)  # type: ignore[arg-type]


# --- round-trip + determinism --------------------------------------------------------------------
def test_event_round_trip_byte_identical() -> None:
    e = _event()
    cb = e.canonical_bytes()
    e2 = AegisEventV2.parse(json.loads(cb))
    assert e2 == e
    assert e2.canonical_bytes() == cb
    assert e.digest() == e2.digest()
    assert f'"schema":"{EVENT_V2_SCHEMA}"'.encode() in cb


def test_event_determinism_is_order_independent() -> None:
    a = _event(rule_refs=["r2", "r1", "r1"])
    b = _event(rule_refs=["r1", "r2"])
    assert a.rule_refs == ["r1", "r2"]  # sorted + de-duplicated
    assert a.canonical_bytes() == b.canonical_bytes()


def test_event_accepts_schema_alias_and_name() -> None:
    e = _event()
    by_alias = json.loads(e.canonical_bytes())
    assert by_alias["schema"] == EVENT_V2_SCHEMA
    assert AegisEventV2.parse(by_alias) == e
    by_name = {**by_alias}
    by_name["schema_id"] = by_name.pop("schema")
    assert AegisEventV2.parse(by_name) == e  # populate_by_name


def test_health_and_manifest_round_trip() -> None:
    h = EngineHealth(engine="unit", instance_id="u1", seq=3, last_heartbeat_seq=2,
                     state=EngineHealthState.CRASH_LOOP, reasons=["restarts>3", "restarts>3"])
    assert h.reasons == ["restarts>3"]  # de-duplicated
    assert EngineHealth.parse(json.loads(h.canonical_bytes())) == h
    m = baseline_response_manifest()
    assert ResponseManifest.parse(json.loads(m.canonical_bytes())) == m


def test_asset_ref_round_trip() -> None:
    a = AssetRef(ref="asset-1", connection_path="alb->unit", instance_id="i1", cell="cell-a",
                 placement_state=PlacementState.PLACED, isolation_tier="t2")
    assert AssetRef.parse(json.loads(a.canonical_bytes())) == a


# --- fail-closed defaults ------------------------------------------------------------------------
def test_health_defaults_to_unknown_not_healthy() -> None:
    h = EngineHealth(engine="unit", instance_id="u1", seq=1)
    assert h.state is EngineHealthState.UNKNOWN  # absence is NOT "healthy"


def test_adapter_effect_verification_defaults_to_none() -> None:
    c = AdapterCapability(kind="inline_block", outcome_class=OutcomeClass.PREVENTED_BEFORE_EXECUTION)
    assert c.effect_verification is EffectVerification.NONE  # unverified until declared


def test_manifest_reachable_defaults_empty() -> None:
    assert ResponseManifest().reachable == []  # claim nothing until a provider declares it


def test_asset_placement_defaults_declared() -> None:
    a = AssetRef(ref="a", instance_id="i")
    assert a.placement_state is PlacementState.DECLARED


def test_deadlines_defaults_are_the_proposed_slos() -> None:
    d = ResponseDeadlines()
    assert (d.visibility_p95_seconds, d.staleness_heartbeats, d.revocation_seconds,
            d.renewal_lead_days, d.convergence_sweeps) == (120, 3, 300, 14, 2)


# --- honesty / contract-shape properties ---------------------------------------------------------
def test_criticality_authority_is_pinned_none() -> None:
    assert Criticality(tenant_declared="tier-0").authority == "none"
    with pytest.raises(Exception):
        Criticality(tenant_declared="tier-0", authority="owner")  # type: ignore[arg-type]


def test_baseline_manifest_reaches_only_classes_1_3_5() -> None:
    m = baseline_response_manifest()
    assert set(m.reachable) == set(BASELINE_REACHABLE_OUTCOMES)
    assert OutcomeClass.INTERRUPTED_AFTER_PARTIAL_EXECUTION not in m.reachable  # class 2
    assert OutcomeClass.CONTAINED_AFTER_COMPROMISE not in m.reachable          # class 4
    assert len(ALL_OUTCOME_CLASSES) == 5


# --- forward-compatibility -----------------------------------------------------------------------
def test_event_forward_compat_omitting_optional_fields_parses() -> None:
    # a minimal (older-style) payload that omits every optional field still parses via defaults.
    minimal = {"schema": EVENT_V2_SCHEMA, "org_id": "acme", "host": "api.example.com",
               "instance_id": "i1", "epoch": 0, "seq": 0, "decision": "clear", "event_id": "ev0"}
    e = AegisEventV2.parse(minimal)
    assert e.outcome_class is None and e.rule_refs == [] and e.attack_class == ""


# --- negative controls (malformed -> reject) -----------------------------------------------------
def test_unknown_key_rejected() -> None:
    with pytest.raises(Exception):
        _event(unexpected="x")


def test_wrong_schema_rejected() -> None:
    bad = json.loads(_event().canonical_bytes())
    bad["schema"] = "vigil.aegis.event.v1"
    with pytest.raises(ValueError):
        AegisEventV2.parse(bad)


def test_ip_literal_host_rejected() -> None:
    for host in ("10.0.0.1", "127.1", "0x7f.1", "2130706433"):
        with pytest.raises(ValueError):
            _event(host=host)


def test_bad_literals_and_ranges_rejected() -> None:
    with pytest.raises(Exception):
        _event(decision="nope")
    with pytest.raises(Exception):
        _event(confidence=1.5)
    with pytest.raises(Exception):
        _event(seq=-1)


def test_bad_cert_digest_rejected() -> None:
    with pytest.raises(ValueError):
        _event(certificate_sha256="deadbeef")  # not 64 hex


def test_control_char_and_traversal_rejected() -> None:
    with pytest.raises(ValueError):
        EngineHealth(engine="unit\nspoof", instance_id="u1", seq=1)
    with pytest.raises(ValueError):
        _event(org_id="../escape")  # path traversal in a component field
    with pytest.raises(ValueError):
        clean_token("a\x00b", label="x")


def test_clean_token_rejects_unicode_linebreaks_and_bidi() -> None:
    # The C0/DEL check alone ACCEPTS these — a line-oriented renderer/log would show one token as two
    # lines (U+2028/9, U+0085 NEL), or bidi-reorder it (U+202E, Trojan-Source). canonical.py serialises
    # with ensure_ascii=False, so each would land as raw bytes in canonical_bytes. All must be refused,
    # both directly and through a representative token-bearing schema field (event.attack_class,
    # health.engine), each of which runs clean_token.
    # Code points (built via chr so this source file holds no raw control bytes): U+2028 LINE
    # SEPARATOR, U+2029 PARAGRAPH SEPARATOR, U+0085 NEL (a C1 control), U+202E RTL OVERRIDE.
    for ch in (chr(0x2028), chr(0x2029), chr(0x0085), chr(0x202E)):
        with pytest.raises(ValueError):
            clean_token(f"a{ch}b", label="x")
        with pytest.raises(ValueError):
            _event(attack_class=f"sq{ch}li")
        with pytest.raises(ValueError):
            EngineHealth(engine=f"un{ch}it", instance_id="u1", seq=1)


def test_clean_token_still_allows_ordinary_space() -> None:
    # The broadened Unicode-category check must NOT regress a legitimate multi-word label: an ordinary
    # space (U+0020, category Zs) is neither a control/format char (Cc/Cf) nor a Zl/Zp separator.
    assert clean_token("multi word label", label="x") == "multi word label"
    assert _event(attack_class="sql injection").attack_class == "sql injection"


def test_bad_outcome_class_rejected() -> None:
    with pytest.raises(Exception):
        ResponseManifest(reachable=["not_a_class"])  # type: ignore[list-item]


# --- FATAL-2 cleanliness -------------------------------------------------------------------------
def test_module_is_fatal2_clean() -> None:
    assert _imported_roots("vigil_core.aegis_schemas").isdisjoint({"framework", "sigil"})


def test_schema_constants_follow_convention() -> None:
    assert EVENT_V2_SCHEMA == "vigil.aegis.event.v2"
    assert HEALTH_V1_SCHEMA == "vigil.aegis.health.v1"
    assert RESPONSE_MANIFEST_SCHEMA == "vigil.aegis.response-manifest.v1"
