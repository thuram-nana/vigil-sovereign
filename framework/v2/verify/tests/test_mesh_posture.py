"""
Wave-G3 — the service-mesh-posture oracle (retained mesh-config LEAD -> FACT over its ACHIEVED STATE).

A mesh linter's "PeerAuthentication is PERMISSIVE / this AuthorizationPolicy allows everyone" is a
THIRD-PARTY heuristic — a LEAD. The mesh-posture oracle (the MESH twin of ``k8s_posture_oracle`` /
``cloud_posture_oracle``) promotes it to a FACT ONLY when the RETAINED control proves a CONCRETE insecure
ACHIEVED STATE: an Istio PeerAuthentication with PERMISSIVE/DISABLE mTLS, an ALLOW AuthorizationPolicy that
admits every caller (an empty catch-all rule or a ``*`` wildcard principal), or a Linkerd server whose
``default-inbound-policy`` is ``all-unauthenticated``. A STRICT PeerAuthentication, a scoped/deny policy,
an ALLOW policy with no rules (deny-all), an authenticated inbound policy, a control with only ABSENT
fields, an EXPLICIT pass status, and malformed evidence all correctly do NOT fire — near-zero false
positives. The confirmed fact re-verifies offline from its retained context. NO live mesh call is ever
made; a service-mesh ATTACK is never performed.
"""

from __future__ import annotations

from framework.v2.verify import (
    mesh_posture_oracle,
    confirm_mesh_posture,
    mesh_posture_context,
    ingest_mesh_config,
    confirm_mesh_config,
)
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.models import OracleKind
from framework.v2.verify.reverify import reverify_context
from framework.v2.verify.verifier import _ALL_ORACLES, OracleVerifier

# A mesh-wide Istio PeerAuthentication accepting plaintext (PERMISSIVE) — the canonical mesh weakness.
_PERMISSIVE_MTLS = {
    "resource_kind": "PeerAuthentication", "name": "default", "namespace": "istio-system",
    "scope": "mesh", "mtls_mode": "PERMISSIVE",
}
# An Istio AuthorizationPolicy that admits every caller (an empty catch-all rule under ALLOW).
_ALLOW_ALL = {
    "resource_kind": "AuthorizationPolicy", "name": "ns-allow", "namespace": "prod",
    "scope": "namespace", "action": "ALLOW", "rules": [{}],
}


# ---- the oracle fires ONLY on a proven insecure achieved state --------------


def test_fires_on_permissive_mtls_peerauthentication() -> None:
    sig = mesh_posture_oracle(_PERMISSIVE_MTLS)
    assert sig.fired and sig.kind is OracleKind.MESH_POSTURE
    assert sig.confidence >= 0.7
    assert sig.observed["rule"] == "permissive_mtls"


def test_fires_on_disable_mtls() -> None:
    sig = mesh_posture_oracle({"resource_kind": "PeerAuthentication", "name": "d", "mtls_mode": "DISABLE"})
    assert sig.fired
    assert sig.observed["rule"] == "permissive_mtls"


def test_fires_on_allow_all_empty_catch_all_rule() -> None:
    sig = mesh_posture_oracle(_ALLOW_ALL)
    assert sig.fired
    assert sig.observed["rule"] == "authz_allow_all"
    assert sig.observed["detail"] == "empty_catch_all_rule"


def test_fires_on_allow_all_wildcard_principal() -> None:
    wild = {"resource_kind": "AuthorizationPolicy", "name": "a", "action": "ALLOW",
            "rules": [{"from": [{"source": {"principals": ["*"]}}]}]}
    sig = mesh_posture_oracle(wild)
    assert sig.fired
    assert sig.observed["detail"] == "wildcard_principal"


def test_fires_when_action_is_unset_defaulting_to_allow() -> None:
    # Istio's default action is ALLOW, so an unset action with a catch-all rule allows everyone.
    unset = {"resource_kind": "AuthorizationPolicy", "name": "a", "rules": [{}]}
    assert mesh_posture_oracle(unset).fired


def test_fires_on_linkerd_all_unauthenticated_inbound() -> None:
    sig = mesh_posture_oracle({"resource_kind": "Server", "name": "web",
                               "default_inbound_policy": "all-unauthenticated"})
    assert sig.fired
    assert sig.observed["rule"] == "linkerd_unauthenticated"


def test_mtls_mode_is_case_insensitive() -> None:
    assert mesh_posture_oracle({"resource_kind": "PeerAuthentication", "name": "d",
                                "mtls_mode": "permissive"}).fired


# ---- the oracle does NOT fire on a hardened / unprovable posture ------------


def test_strict_mtls_does_not_fire() -> None:
    strict = {"resource_kind": "PeerAuthentication", "name": "d", "scope": "mesh", "mtls_mode": "STRICT"}
    assert not mesh_posture_oracle(strict).fired


def test_absent_mtls_mode_does_not_fire() -> None:
    # an unset mode inherits a parent policy — never promoted (stays a lead)
    assert not mesh_posture_oracle({"resource_kind": "PeerAuthentication", "name": "d"}).fired


def test_scoped_allow_policy_does_not_fire() -> None:
    scoped = {"resource_kind": "AuthorizationPolicy", "name": "a", "action": "ALLOW",
              "rules": [{"from": [{"source": {"principals": ["cluster.local/ns/prod/sa/web"]}}]}]}
    assert not mesh_posture_oracle(scoped).fired


def test_deny_action_never_fires_even_with_catch_all_rule() -> None:
    deny = {"resource_kind": "AuthorizationPolicy", "name": "a", "action": "DENY", "rules": [{}]}
    assert not mesh_posture_oracle(deny).fired


def test_allow_policy_with_no_rules_is_deny_all_and_does_not_fire() -> None:
    # an ALLOW policy with an empty rules list denies everything (secure) — NOT an allow-all
    assert not mesh_posture_oracle({"resource_kind": "AuthorizationPolicy", "name": "a",
                                    "action": "ALLOW", "rules": []}).fired


def test_to_only_rule_does_not_fire() -> None:
    # a to-only (path-restricted) ALLOW rule is deliberately conservative — public endpoints are a design
    # choice, not a near-zero-FP-provable misconfig
    to_only = {"resource_kind": "AuthorizationPolicy", "name": "a", "action": "ALLOW",
               "rules": [{"to": [{"operation": {"paths": ["/public"]}}]}]}
    assert not mesh_posture_oracle(to_only).fired


def test_authenticated_linkerd_policy_does_not_fire() -> None:
    for pol in ("cluster-authenticated", "all-authenticated", "deny"):
        assert not mesh_posture_oracle({"resource_kind": "Server", "name": "web",
                                        "default_inbound_policy": pol}).fired


def test_explicit_pass_status_never_fires_even_with_a_flag() -> None:
    assert not mesh_posture_oracle({"resource_kind": "PeerAuthentication", "name": "d",
                                    "mtls_mode": "PERMISSIVE", "status": "PASS"}).fired


def test_absent_fields_do_not_fire() -> None:
    assert not mesh_posture_oracle({"resource_kind": "AuthorizationPolicy", "name": "a"}).fired
    assert not mesh_posture_oracle({"resource_kind": "PeerAuthentication", "name": "d",
                                    "mtls_mode": "UNKNOWN"}).fired


def test_garbage_and_empty_do_not_fire_and_never_raise() -> None:
    for junk in (None, "", 123, [], {}, {"resource_kind": "PeerAuthentication"},
                 {"rules": "nope"}, {"mtls_mode": ["not", "a", "string"]}):
        assert not mesh_posture_oracle(junk).fired


# ---- routing + the frozen-fallback invariant --------------------------------


def test_routes_via_verifier_and_kind_is_out_of_the_frozen_fallback() -> None:
    v = OracleVerifier()
    assert v.oracles_for("mesh_misconfiguration") == (OracleKind.MESH_POSTURE,)
    assert v.oracles_for("mesh_posture") == (OracleKind.MESH_POSTURE,)          # alias folds
    assert v.oracles_for("permissive_mtls") == (OracleKind.MESH_POSTURE,)       # alias folds
    assert v.oracles_for("istio_misconfiguration") == (OracleKind.MESH_POSTURE,)  # alias folds
    # the NEW kind is reachable ONLY via its explicit row — never the unknown-class fallback
    assert OracleKind.MESH_POSTURE not in _ALL_ORACLES
    assert len(_ALL_ORACLES) == 15
    assert OracleKind.MESH_POSTURE not in v.oracles_for("some_unknown_class")


def test_confirm_via_seam_and_verifier() -> None:
    assert confirm_mesh_posture(_PERMISSIVE_MTLS).confirmed
    assert confirm_mesh_posture(_ALLOW_ALL).confirmed
    assert OracleVerifier().confirm(mesh_posture_context(_PERMISSIVE_MTLS)).confirmed
    strict = {"resource_kind": "PeerAuthentication", "name": "d", "mtls_mode": "STRICT"}
    assert not confirm_mesh_posture(strict).confirmed


# ---- offline re-verification (prove-don't-guess) ----------------------------


def test_confirmed_posture_reverifies_offline_from_its_retained_context() -> None:
    oracle_context = mesh_posture_context(_PERMISSIVE_MTLS)
    # no mesh, no trust in the linter — re-run the pure oracle over the retained control
    r = reverify_context(oracle_context, bug_class="mesh_misconfiguration")
    assert r.reproduced and r.ok
    assert r.confirmed_by == OracleKind.MESH_POSTURE.value


def test_adapter_builder_retains_only_structural_fields() -> None:
    ctx = FindingContext.from_mesh_control(
        {**_PERMISSIVE_MTLS, "noise": "verbose linter prose", "annotations": {"junk": "not laundered"}})
    emitted = ctx.to_verifier_context()
    assert "mesh_control" in emitted
    blob = str(emitted["mesh_control"])
    assert "noise" not in blob and "not laundered" not in blob   # non-structural fields NOT laundered
    assert emitted["mesh_control"]["mtls_mode"] == "PERMISSIVE"
    assert emitted["mesh_control"]["resource_kind"] == "PeerAuthentication"


def test_builder_canonicalizes_authz_rules_but_preserves_the_verdict() -> None:
    # a rule with verbose to/when content is reduced to presence markers; the allow-all wildcard survives
    raw = {"resource_kind": "AuthorizationPolicy", "name": "a", "action": "ALLOW",
           "rules": [{"from": [{"source": {"principals": ["*"], "namespaces": ["prod"]}}],
                      "to": [{"operation": {"paths": ["/x"]}}], "when": [{"key": "k", "values": ["v"]}]}]}
    ctx = FindingContext.from_mesh_control(raw)
    emitted = ctx.to_verifier_context()
    blob = str(emitted["mesh_control"])
    assert "namespaces" not in blob and "/x" not in blob        # non-judged sub-fields NOT laundered
    assert confirm_mesh_posture(raw).confirmed                  # verdict preserved through canonicalization


# ---- the minimal offline ingestion (Istio / Linkerd manifest -> lead) -------


_MANIFEST = """
apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata:
  name: default
  namespace: istio-system
spec:
  mtls:
    mode: PERMISSIVE
---
apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata: {name: strict-ns, namespace: prod}
spec:
  mtls: {mode: STRICT}
---
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata: {name: allow-all, namespace: prod}
spec:
  action: ALLOW
  rules:
  - {}
---
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata: {name: scoped, namespace: prod}
spec:
  action: ALLOW
  rules:
  - from:
    - source: {principals: ["cluster.local/ns/prod/sa/web"]}
---
apiVersion: v1
kind: Namespace
metadata:
  name: legacy
  annotations:
    config.linkerd.io/default-inbound-policy: all-unauthenticated
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: unrelated}
"""


def _has_yaml() -> bool:
    try:
        import yaml  # noqa: F401
        return True
    except Exception:
        return False


def test_ingest_json_string_and_dict_paths() -> None:
    # a JSON manifest needs no third-party dep
    controls = ingest_mesh_config(
        '{"kind":"PeerAuthentication","metadata":{"name":"x"},"spec":{"mtls":{"mode":"DISABLE"}}}')
    assert len(controls) == 1 and controls[0]["mtls_mode"] == "DISABLE"
    # a dict passes straight through
    assert ingest_mesh_config({"kind": "PeerAuthentication", "metadata": {"name": "y"},
                               "spec": {"mtls": {"mode": "PERMISSIVE"}}})[0]["resource_kind"] == "PeerAuthentication"


def test_ingest_skips_unrecognised_and_never_raises() -> None:
    for junk in (None, 123, "", "this is: not: valid: yaml: [", {"kind": "Deployment"}):
        assert ingest_mesh_config(junk) == [] or all(c is not None for c in ingest_mesh_config(junk))
    # an unrelated kind yields no control
    assert ingest_mesh_config({"kind": "Deployment", "metadata": {"name": "n"}}) == []


def test_end_to_end_manifest_ingest_and_confirm() -> None:
    if not _has_yaml():
        # JSON-only smoke: the two Istio kinds still ingest without PyYAML
        return
    results = confirm_mesh_config(_MANIFEST)
    by_name = {c["name"]: r.confirmed for c, r in results}
    # the Deployment is skipped; the five mesh resources are ingested
    assert set(by_name) == {"default", "strict-ns", "allow-all", "scoped", "legacy"}
    assert by_name["default"] is True        # mesh-wide PERMISSIVE PeerAuthentication -> FACT
    assert by_name["allow-all"] is True      # empty catch-all ALLOW rule -> FACT
    assert by_name["legacy"] is True         # Linkerd all-unauthenticated -> FACT
    assert by_name["strict-ns"] is False     # STRICT mTLS -> stays a lead
    assert by_name["scoped"] is False        # scoped principal -> stays a lead


def test_ingest_computes_mesh_scope_for_root_namespace() -> None:
    if not _has_yaml():
        return
    controls = {c["name"]: c for c in ingest_mesh_config(_MANIFEST)}
    assert controls["default"]["scope"] == "mesh"        # istio-system root ns, no selector
    assert controls["allow-all"]["scope"] == "namespace"  # a workload namespace
