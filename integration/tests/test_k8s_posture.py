"""WAVE #4 A1 — the Kubernetes-posture VIGIL-direct FACT capability (K8S_POSTURE + K8S_WORKLOAD_POSTURE).

VIGIL parses the operator's OWN k8s posture ARTIFACTS — a kube-bench --json export and RBAC binding
manifests — and mints a signed FACT only when its OWN parse + the deterministic posture oracle PROVES a
concrete insecure control. A kube-bench FAIL / an RBAC binding is a PROPOSER; VIGIL's re-derivation is the
sole authority (criterion-6). Every FACT names the ARTIFACT, never the live cluster, and re-verifies offline.
No cluster is contacted and no external tool is installed or run.
"""
from __future__ import annotations

import hashlib
import json

import pytest

from vigil_integration.live.k8s_posture import (
    _extract_kube_bench_controls,
    _reduce_rbac_binding,
    ingest_k8s_rbac,
    k8s_posture_verify,
)
from vigil_integration.live.safe_parse import ParseBudget


# ---- fixtures ------------------------------------------------------------------------------------

def _kube_bench(results: list[dict]) -> str:
    """A kube-bench --json export wrapping the given result records in the real Controls/tests/results shape."""
    return json.dumps({
        "Controls": [{
            "id": "1", "text": "Control Plane Configuration",
            "tests": [{"section": "1.2", "desc": "API Server", "results": results}],
        }],
        "Totals": {"total_fail": sum(1 for r in results if r.get("status") == "FAIL")},
    })


_FAIL_ANON_AUTH = {"test_number": "1.2.1", "test_desc": "--anonymous-auth=false",
                   "status": "FAIL", "actual_value": "kube-apiserver --anonymous-auth=true --authorization-mode=RBAC"}
_PASS_CONTROL = {"test_number": "1.2.2", "test_desc": "--basic-auth-file not set",
                 "status": "PASS", "actual_value": "kube-apiserver --authorization-mode=RBAC"}
_FAIL_SECURE_VALUE = {"test_number": "1.2.1", "test_desc": "--anonymous-auth=false",
                      "status": "FAIL", "actual_value": "kube-apiserver --anonymous-auth=false"}
_WARN_CONTROL = {"test_number": "1.2.1", "test_desc": "manual review",
                 "status": "WARN", "actual_value": "kube-apiserver --anonymous-auth=true"}


def _rbac_doc(kind: str, name: str, role: str, role_kind: str, subjects: list[dict],
              *, namespace: str | None = None, apigroup: str = "rbac.authorization.k8s.io") -> str:
    doc = {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": kind,
        "metadata": {"name": name, **({"namespace": namespace} if namespace else {})},
        "roleRef": {"apiGroup": apigroup, "kind": role_kind, "name": role},
        "subjects": subjects,
    }
    return json.dumps(doc)   # JSON is valid YAML — a stable, dependency-free way to author a manifest doc


_ANON = {"kind": "Group", "name": "system:unauthenticated", "apiGroup": "rbac.authorization.k8s.io"}
_ANON_USER = {"kind": "User", "name": "system:anonymous", "apiGroup": "rbac.authorization.k8s.io"}
_NAMED = {"kind": "User", "name": "alice", "apiGroup": "rbac.authorization.k8s.io"}

# anon -> cluster-admin ClusterRoleBinding (FIRES)
_RBAC_ANON_CLUSTER_ADMIN = _rbac_doc("ClusterRoleBinding", "anon-ca", "cluster-admin", "ClusterRole",
                                     [_ANON, _NAMED])
# hardened: anon -> the benign built-in system:public-info-viewer (does NOT fire)
_RBAC_HARDENED_PUBLIC_INFO = _rbac_doc("ClusterRoleBinding", "public-info", "system:public-info-viewer",
                                       "ClusterRole", [_ANON])
# hardened: named user -> cluster-admin (no anonymous subject -> does NOT fire)
_RBAC_NAMED_CLUSTER_ADMIN = _rbac_doc("ClusterRoleBinding", "ops-ca", "cluster-admin", "ClusterRole", [_NAMED])
# DECEPTIVE: a namespaced Role NAMED "edit" bound to an anonymous subject. The name looks dangerous but the
# roleRef is a namespaced Role, NOT the built-in ClusterRole -> the oracle must NOT fire (near-zero-FP).
_RBAC_DECEPTIVE_NS_EDIT = _rbac_doc("RoleBinding", "ns-edit", "edit", "Role", [_ANON_USER], namespace="dev")
# DECEPTIVE: an anonymous subject bound to a CUSTOM ClusterRole (not a dangerous built-in) -> no fire.
_RBAC_DECEPTIVE_CUSTOM = _rbac_doc("ClusterRoleBinding", "anon-custom", "my-reader", "ClusterRole", [_ANON])


def _signers_and_trust():
    """One keypair → the governance signer + a matching single-authorizer trust root (verify offline)."""
    from vigil_core import AuthorizerKey, TrustRoot, generate_keypair
    kp = generate_keypair()
    signers = [("gov0", kp.private_key_b64)]
    tr = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="gov0", name="gov0", public_key_b64=kp.public_key_b64)])
    return signers, tr


# ---- pure parsers / reducers (sovereign-safe, no framework) --------------------------------------

def test_kube_bench_extraction_reduces_to_the_fields_the_oracle_judges():
    controls = _extract_kube_bench_controls(json.loads(_kube_bench([_FAIL_ANON_AUTH, _PASS_CONTROL])))
    assert len(controls) == 2
    c0 = controls[0]
    assert c0["check_id"] == "1.2.1" and c0["status"] == "FAIL"
    assert "--anonymous-auth=true" in c0["actual_value"] and c0["section"] == "1.2"
    # a record missing a status or an id is not a control (never inferred)
    assert _extract_kube_bench_controls({"Controls": [{"tests": [{"results": [{"status": "FAIL"}]}]}]}) == []
    # accepts a list of target-objects and a bare result list
    assert _extract_kube_bench_controls([json.loads(_kube_bench([_FAIL_ANON_AUTH]))])[0]["check_id"] == "1.2.1"


def test_rbac_reduction_carries_rolekind_and_apigroup_faithfully():
    r = _reduce_rbac_binding(json.loads(_RBAC_ANON_CLUSTER_ADMIN))
    assert r["role"] == "cluster-admin" and r["role_kind"] == "ClusterRole"
    assert r["role_apigroup"] == "rbac.authorization.k8s.io"
    # B3: a Group subject named system:unauthenticated stays BARE (it is the real anon principal, so the
    # oracle's anon-name check can fire); a non-anon User (alice) is KIND-QUALIFIED so a name-only match can
    # never launder it (or a same-named impostor of a different kind) into the anonymous principal.
    assert r["subjects"] == ["system:unauthenticated", "user::alice"]
    assert r["resource_kind"] == "clusterrolebinding"
    # a namespaced Role named "edit" is carried as role_kind=Role — NOT defaulted to ClusterRole
    d = _reduce_rbac_binding(json.loads(_RBAC_DECEPTIVE_NS_EDIT))
    assert d["role"] == "edit" and d["role_kind"] == "Role" and d["namespace"] == "dev"
    # a non-binding document is skipped
    assert _reduce_rbac_binding({"kind": "Deployment", "metadata": {"name": "x"}}) is None


# ---- kube-bench FACT path (K8S_POSTURE) ----------------------------------------------------------

def test_kube_bench_fail_anonymous_auth_mints_a_reverifiable_fact():
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
    from framework.v2.evidence.certify import verify_certificate

    signers, tr = _signers_and_trust()
    export = _kube_bench([_FAIL_ANON_AUTH])
    res = k8s_posture_verify(export, engagement_slug="acme", signers=signers)
    assert res.n_facts == 1, f"expected a FACT; leads={res.leads} inconclusive={res.inconclusive}"
    f = res.facts[0]
    ctx = res.contexts[f.finding_ref]
    # the FACT re-verifies offline end-to-end (authentic + bound + reproduced)
    assert verify_certificate(f.signed, oracle_context=ctx, trust_root=tr).ok is True
    # admission attributed the FACT to the ONE clean_capable:false branch, and the audit trail shows FACT
    assert res.admissions and all(a[0] == "k8s_posture.cis_control" for a in res.admissions)
    assert any(a[1] == "FACT" for a in res.admissions)
    assert res.family_verdict() == "FACT"
    # the certificate binds the ARTIFACT identity (D2): the exact bytes VIGIL parsed, marked partial
    bound = f.signed.certificate.bound_identity
    assert bound["artifact_sha256"] == hashlib.sha256(export.encode()).hexdigest()
    assert bound["completeness"] == "partial" and bound["capture_method"] == "artifact:kube-bench"


def test_kube_bench_hardened_and_deceptive_never_mint_a_fact_or_clean():
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
    signers, _ = _signers_and_trust()
    # hardened PASS, a FAIL whose value shows the SECURE flag (deceptive: scanner says FAIL, VIGIL refutes),
    # and a WARN all must NOT mint a FACT and must NOT leak CLEAN.
    for label, export in (
        ("all-pass", _kube_bench([_PASS_CONTROL])),
        ("fail-secure-value", _kube_bench([_FAIL_SECURE_VALUE])),
        ("warn", _kube_bench([_WARN_CONTROL])),
    ):
        res = k8s_posture_verify(export, engagement_slug="acme", signers=signers)
        assert res.n_facts == 0, f"{label}: minted a FACT it should not have"
        allr = res.facts + res.leads + res.inconclusive
        assert all(r.outcome != "clean" for r in allr), f"{label}: leaked a CLEAN outcome"
        assert res.family_verdict() != "CLEAN", f"{label}: family composed to CLEAN"


def test_kube_bench_incomplete_export_yields_facts_but_never_clean():
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
    signers, _ = _signers_and_trust()
    # one firing control beside one PASS — a PARTIAL export. The FACT stands; the PASS is INCONCLUSIVE (a
    # clean_capable:false branch cannot assert absence over a partial artifact), so no CLEAN anywhere.
    res = k8s_posture_verify(_kube_bench([_FAIL_ANON_AUTH, _PASS_CONTROL]), engagement_slug="acme",
                             signers=signers)
    assert res.n_facts == 1 and res.inconclusive, res.admissions
    assert all(r.outcome != "clean" for r in res.facts + res.leads + res.inconclusive)
    assert res.family_verdict() == "FACT"   # a FACT present -> family is FACT, but no branch cleared CLEAN
    assert {a[1] for a in res.admissions} == {"FACT", "INCONCLUSIVE"}


def test_kube_bench_no_control_is_inconclusive_never_clean():
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
    signers, _ = _signers_and_trust()
    res = k8s_posture_verify(_kube_bench([]), engagement_slug="acme", signers=signers)
    assert res.n_facts == 0 and res.admissions == []
    assert res.family_verdict() == "INCONCLUSIVE"   # nothing examined != CLEAN


# ---- RBAC FACT path (K8S_WORKLOAD_POSTURE) -------------------------------------------------------

def test_rbac_anonymous_cluster_admin_mints_a_reverifiable_fact():
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
    from framework.v2.evidence.certify import verify_certificate

    signers, tr = _signers_and_trust()
    res = ingest_k8s_rbac(_RBAC_ANON_CLUSTER_ADMIN, engagement_slug="acme", signers=signers)
    assert res.n_facts == 1, f"expected a FACT; leads={res.leads} inconclusive={res.inconclusive}"
    f = res.facts[0]
    ctx = res.contexts[f.finding_ref]
    assert verify_certificate(f.signed, oracle_context=ctx, trust_root=tr).ok is True
    assert res.admissions and all(a[0] == "k8s_workload_posture.rbac_binding" for a in res.admissions)
    assert any(a[1] == "FACT" for a in res.admissions)
    assert res.family_verdict() == "FACT"
    bound = f.signed.certificate.bound_identity
    assert bound["completeness"] == "partial" and bound["capture_method"] == "artifact:k8s-manifest"


def test_rbac_multidoc_stream_adjudicates_every_binding():
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
    signers, _ = _signers_and_trust()
    # a multi-document stream: one firing binding + one hardened + one deceptive namespaced Role
    stream = "\n---\n".join([_RBAC_ANON_CLUSTER_ADMIN, _RBAC_HARDENED_PUBLIC_INFO, _RBAC_DECEPTIVE_NS_EDIT])
    res = ingest_k8s_rbac(stream, engagement_slug="acme", signers=signers)
    assert res.controls == 3
    assert res.n_facts == 1, f"only the anon->cluster-admin binding should fire; got {res.admissions}"
    assert all(r.outcome != "clean" for r in res.facts + res.leads + res.inconclusive)
    assert res.family_verdict() == "FACT"


@pytest.mark.parametrize("label,manifest", [
    ("public-info-viewer", _RBAC_HARDENED_PUBLIC_INFO),
    ("named-user-cluster-admin", _RBAC_NAMED_CLUSTER_ADMIN),
    ("deceptive-ns-role-named-edit", _RBAC_DECEPTIVE_NS_EDIT),
    ("deceptive-custom-clusterrole", _RBAC_DECEPTIVE_CUSTOM),
])
def test_rbac_hardened_and_deceptive_never_mint_a_fact_or_clean(label, manifest):
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
    signers, _ = _signers_and_trust()
    res = ingest_k8s_rbac(manifest, engagement_slug="acme", signers=signers)
    assert res.n_facts == 0, f"{label}: minted a FACT it should not have"
    assert all(r.outcome != "clean" for r in res.facts + res.leads + res.inconclusive), f"{label}: leaked CLEAN"
    assert res.family_verdict() != "CLEAN", f"{label}: composed to CLEAN"


def test_rbac_no_binding_is_inconclusive_never_clean():
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
    signers, _ = _signers_and_trust()
    res = ingest_k8s_rbac(json.dumps({"kind": "ConfigMap", "metadata": {"name": "x"}}),
                          engagement_slug="acme", signers=signers)
    assert res.n_facts == 0 and res.admissions == []
    assert res.family_verdict() == "INCONCLUSIVE"


# ---- resource-governed parsing: a malformed / hostile artifact is a typed error, not a crash ------

def test_malformed_json_kube_bench_is_a_typed_parse_error_no_adjudication():
    signers, _ = _signers_and_trust()
    res = k8s_posture_verify("{not: valid json", engagement_slug="acme", signers=signers)
    assert res.parse_error == "malformed" and res.n_facts == 0 and res.admissions == []
    assert res.family_verdict() == "INCONCLUSIVE"


def test_malformed_yaml_rbac_is_a_typed_parse_error_no_adjudication():
    signers, _ = _signers_and_trust()
    res = ingest_k8s_rbac("kind: ClusterRoleBinding\n  bad: : indent", engagement_slug="acme", signers=signers)
    assert res.parse_error in ("malformed", "yaml_unavailable") and res.n_facts == 0
    assert res.admissions == [] and res.family_verdict() == "INCONCLUSIVE"


def test_unsafe_yaml_tag_is_refused_never_constructed():
    signers, _ = _signers_and_trust()
    res = ingest_k8s_rbac("!!python/object/apply:os.system ['echo pwned']",
                          engagement_slug="acme", signers=signers)
    assert res.parse_error in ("unsafe_tag", "yaml_unavailable") and res.n_facts == 0


def test_oversized_artifact_is_refused_before_parsing():
    signers, _ = _signers_and_trust()
    tiny = ParseBudget(max_bytes=32)
    res = k8s_posture_verify(_kube_bench([_FAIL_ANON_AUTH]), engagement_slug="acme", signers=signers,
                             budget=tiny)
    assert res.parse_error == "oversize" and res.n_facts == 0 and res.admissions == []


def test_incomplete_rolref_never_mints_a_false_workload_fact():
    """RED-PEN A1-MEDIUM: a RoleBinding whose roleRef OMITS kind AND apiGroup (a hand-authored/incomplete
    manifest) named 'edit' with an anonymous subject must NOT mint a K8S_WORKLOAD FACT — the workload oracle's
    empty-string tolerance would otherwise treat absent kind/apiGroup as the dangerous BUILT-IN ClusterRole.
    The reducer now carries a non-matching sentinel so the built-in check fails -> INCONCLUSIVE, no FACT. A
    complete binding still FACTs."""
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable in the sovereign env")
    import json
    signers, tr = _signers_and_trust()
    bad = json.dumps({"kind": "RoleBinding", "metadata": {"name": "x", "namespace": "dev"},
                      "roleRef": {"name": "edit"},
                      "subjects": [{"kind": "User", "name": "system:anonymous"}]})
    r = ingest_k8s_rbac(bad, engagement_slug="acme", signers=signers)
    assert r.n_facts == 0, "incomplete-roleRef anonymous binding minted a false built-in-ClusterRole FACT"
    good = json.dumps({"kind": "ClusterRoleBinding", "metadata": {"name": "y"},
                       "roleRef": {"kind": "ClusterRole", "apiGroup": "rbac.authorization.k8s.io",
                                   "name": "cluster-admin"},
                       "subjects": [{"kind": "User", "name": "system:anonymous"}]})
    r2 = ingest_k8s_rbac(good, engagement_slug="acme", signers=signers)
    assert r2.n_facts >= 1, "a complete anon->cluster-admin binding must still FACT"


def test_whitespace_rolref_never_mints_a_false_workload_fact():
    """RED-PEN re-attack (CRITICAL): the empty-roleRef guard tested byte-exact emptiness, but the oracle
    normalizes with .strip().lower() and tolerates empty — so a WHITESPACE-only roleRef.kind/apiGroup passed
    the guard, collapsed to '' at the oracle, and minted a signed false built-in-ClusterRole FACT. The
    reducer now treats .strip()-empty as absent."""
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable in the sovereign env")
    import json
    signers, tr = _signers_and_trust()
    for kind, ag in (("  ", "  "), ("ClusterRole", "  "), ("  ", "rbac.authorization.k8s.io"), ("\t", "\t")):
        m = json.dumps({"kind": "ClusterRoleBinding", "metadata": {"name": "y"},
                        "roleRef": {"kind": kind, "apiGroup": ag, "name": "cluster-admin"},
                        "subjects": [{"kind": "User", "name": "system:anonymous"}]})
        assert ingest_k8s_rbac(m, engagement_slug="a", signers=signers).n_facts == 0, \
            f"whitespace roleRef (kind={kind!r}, apiGroup={ag!r}) minted a false FACT"


def test_truncation_window_rolref_never_mints_a_false_workload_fact():
    """RED-PEN re-attack of the whitespace fix (CRITICAL, CONFIRMED): the reducer tested emptiness over the
    FULL string (`str(x).strip()`), but the oracle normalizes with `_coerce_text(x)[:4096].strip().lower()` —
    it TRUNCATES to 4096 chars BEFORE stripping. So a roleRef.kind/apiGroup of (" "*4096)+"x" is non-empty
    over the full string (kept verbatim) yet collapses to '' once the oracle truncates to the first 4096
    all-whitespace chars, re-entering the empty-string tolerance → signed false built-in-ClusterRole FACT
    (invariant-3: a mint-side normalization gate not mirrored at re-execution). The reducer now mirrors the
    oracle's truncate-then-strip via `_rolref_field_absent`."""
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable in the sovereign env")
    import json
    signers, tr = _signers_and_trust()
    poison = " " * 4096 + "x"
    for kind, ag in ((poison, poison), (poison, "rbac.authorization.k8s.io"), ("ClusterRole", poison),
                     ("\t" * 4096 + "x", "\t" * 4096 + "x"), (" " * 4096 + "clusterrole", " " * 4096 + "x")):
        m = json.dumps({"kind": "ClusterRoleBinding", "metadata": {"name": "y"},
                        "roleRef": {"kind": kind, "apiGroup": ag, "name": "cluster-admin"},
                        "subjects": [{"kind": "User", "name": "system:anonymous",
                                      "apiGroup": "rbac.authorization.k8s.io"}]})
        assert ingest_k8s_rbac(m, engagement_slug="a", signers=signers).n_facts == 0, \
            f"truncation-window roleRef (len(kind)={len(kind)}) minted a signed false FACT"


def test_dangerous_role_name_is_case_and_whitespace_exact():
    """RED-PEN re-attack (HIGH, CONFIRMED): the oracle normalized the roleRef NAME with _k8s_norm
    (`[:4096].strip().lower()`) before the dangerous-built-in membership test, but k8s RBAC role names are
    case- AND whitespace-SENSITIVE (ValidatePathSegmentName). So a binding to a DISTINCT custom role differing
    from a built-in only by case ('Cluster-Admin', 'CLUSTER-ADMIN') or surrounding whitespace ('cluster-admin ')
    was folded onto the built-in and minted a signed CRITICAL false 'anonymous cluster-admin' FACT — violating
    the near-zero-FP contract (a binding to any custom role stays a LEAD). The oracle + the verify_vf L3 port now
    match the built-in role NAME EXACTLY. Only the exact built-in names still FACT."""
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable in the sovereign env")
    import json
    signers, tr = _signers_and_trust()

    def rb(rolename):
        m = json.dumps({"kind": "ClusterRoleBinding", "metadata": {"name": "y"},
                        "roleRef": {"kind": "ClusterRole", "apiGroup": "rbac.authorization.k8s.io",
                                    "name": rolename},
                        "subjects": [{"kind": "User", "name": "system:anonymous",
                                      "apiGroup": "rbac.authorization.k8s.io"}]})
        return ingest_k8s_rbac(m, engagement_slug="a", signers=signers)

    for custom in ("Cluster-Admin", "CLUSTER-ADMIN", "cluster-admin ", " cluster-admin", "cluster_admin",
                   "clusteradmin", "Admin", "Edit"):
        assert rb(custom).n_facts == 0, f"custom role {custom!r} was laundered onto a built-in -> false FACT"
    for builtin in ("cluster-admin", "admin", "edit"):
        assert rb(builtin).n_facts >= 1, f"a binding to the built-in {builtin!r} must still FACT"


def test_kube_bench_finding_ref_collision_free_offline_reverify():
    """RED-PEN re-attack (MEDIUM, CONFIRMED): two DISTINCT firing CIS controls sharing a test_number but lacking
    node_type/text/id (target -> '-') collapsed to one finding_ref; res.contexts (last-writer-wins) then handed
    the first genuine FACT the second control's context, so it failed offline re-verification — breaking the
    module's 'every FACT re-verifies offline' promise. A content digest now disambiguates distinct controls
    (identical controls still coalesce)."""
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable in the sovereign env")
    import json
    from framework.v2.evidence.certify import verify_certificate
    signers, tr = _signers_and_trust()
    kb = json.dumps({"Controls": [{"tests": [{"section": "1.2", "results": [
        {"test_number": "1.2.1", "status": "FAIL", "actual_value": "--anonymous-auth=true"},
        {"test_number": "1.2.1", "status": "FAIL", "actual_value": "--insecure-port=8080"}]}]}]})
    r = k8s_posture_verify(kb, engagement_slug="a", signers=signers)
    refs = [f.finding_ref for f in r.facts]
    assert len(refs) == 2 and len(set(refs)) == 2, f"distinct controls collided on one finding_ref: {refs}"
    for f in r.facts:
        assert verify_certificate(f.signed, oracle_context=r.contexts[f.finding_ref], trust_root=tr).ok, \
            "a genuine kube-bench FACT failed offline re-verification (wrong retained context)"
    # two GENUINELY identical controls still coalesce to one ref (dedup, not a collision bug)
    kb2 = json.dumps({"Controls": [{"tests": [{"section": "1.2", "results": [
        {"test_number": "1.2.1", "status": "FAIL", "actual_value": "--anonymous-auth=true"},
        {"test_number": "1.2.1", "status": "FAIL", "actual_value": "--anonymous-auth=true"}]}]}]})
    r2 = k8s_posture_verify(kb2, engagement_slug="a", signers=signers)
    assert len(set(f.finding_ref for f in r2.facts)) == 1


def test_serviceaccount_named_system_anonymous_is_not_the_anonymous_principal():
    """RED-PEN B3: a ServiceAccount NAMED 'system:anonymous' is a different principal from the anonymous USER.
    Matching on name alone laundered it into the real anon principal → false FACT. The reducer now requires
    kind=User for system:anonymous (and kind=Group for system:unauthenticated)."""
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable in the sovereign env")
    import json
    signers, tr = _signers_and_trust()
    imposter = json.dumps({"kind": "ClusterRoleBinding", "metadata": {"name": "y"},
                           "roleRef": {"kind": "ClusterRole", "apiGroup": "rbac.authorization.k8s.io",
                                       "name": "cluster-admin"},
                           "subjects": [{"kind": "ServiceAccount", "name": "system:anonymous",
                                         "namespace": "default"}]})
    assert ingest_k8s_rbac(imposter, engagement_slug="a", signers=signers).n_facts == 0
    real = json.dumps({"kind": "ClusterRoleBinding", "metadata": {"name": "y"},
                       "roleRef": {"kind": "ClusterRole", "apiGroup": "rbac.authorization.k8s.io",
                                   "name": "cluster-admin"},
                       "subjects": [{"kind": "Group", "name": "system:unauthenticated"}]})
    assert ingest_k8s_rbac(real, engagement_slug="a", signers=signers).n_facts >= 1  # real Group anon FACTs
