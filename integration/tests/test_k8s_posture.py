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
    # BLOCK #3: subjects are TYPED {kind, name, namespace, api_group} — the oracle decides anon-ness from the
    # k8s TYPE (not a flattened/kind-qualified string), and requires the RBAC apiGroup before minting.
    assert r["subjects"] == [
        {"kind": "Group", "name": "system:unauthenticated", "namespace": "",
         "api_group": "rbac.authorization.k8s.io"},
        {"kind": "User", "name": "alice", "namespace": "", "api_group": "rbac.authorization.k8s.io"}]
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
    assert verify_certificate(f.signed, oracle_context=ctx, trust_root=tr, artifact_bytes=res.artifact_bytes).ok is True
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
    assert verify_certificate(f.signed, oracle_context=ctx, trust_root=tr, artifact_bytes=res.artifact_bytes).ok is True
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
                      "subjects": [{"kind": "User", "name": "system:anonymous",
                                    "apiGroup": "rbac.authorization.k8s.io"}]})
    r = ingest_k8s_rbac(bad, engagement_slug="acme", signers=signers)
    assert r.n_facts == 0, "incomplete-roleRef anonymous binding minted a false built-in-ClusterRole FACT"
    good = json.dumps({"kind": "ClusterRoleBinding", "metadata": {"name": "y"},
                       "roleRef": {"kind": "ClusterRole", "apiGroup": "rbac.authorization.k8s.io",
                                   "name": "cluster-admin"},
                       "subjects": [{"kind": "User", "name": "system:anonymous",
                                    "apiGroup": "rbac.authorization.k8s.io"}]})
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
                        "subjects": [{"kind": "User", "name": "system:anonymous",
                                    "apiGroup": "rbac.authorization.k8s.io"}]})
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


def test_rbac_subject_name_kind_apigroup_are_exact_not_folded():
    """RED-PEN BLOCK #3 re-attack (HIGH, CONFIRMED): _k8s_subject_is_anon .strip()+case-folded the subject —
    so a whitespace-padded name ('system:anonymous\\n'), a case-variant name ('System:Anonymous'), or a
    case-variant kind ('USER') matched the reserved principal (a DIFFERENT k8s object → false FACT). Kind,
    name AND apiGroup are now compared EXACTLY."""
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable in the sovereign env")
    import json
    signers, tr = _signers_and_trust()
    G = "rbac.authorization.k8s.io"

    def rb(subject):
        m = json.dumps({"kind": "ClusterRoleBinding", "metadata": {"name": "y"},
                        "roleRef": {"kind": "ClusterRole", "apiGroup": G, "name": "cluster-admin"},
                        "subjects": [subject]})
        return ingest_k8s_rbac(m, engagement_slug="a", signers=signers).n_facts

    # padded / case-variant name or kind or apiGroup must NOT mint (a different principal)
    for nm in ("system:anonymous\n", "system:anonymous ", " system:anonymous", "System:Anonymous", "SYSTEM:ANONYMOUS"):
        assert rb({"kind": "User", "name": nm, "apiGroup": G}) == 0, f"padded/case name {nm!r} minted a false FACT"
    for kd in ("USER", "user", " User ", "user "):
        assert rb({"kind": kd, "name": "system:anonymous", "apiGroup": G}) == 0, f"case/padded kind {kd!r} minted"
    assert rb({"kind": "User", "name": "system:anonymous", "apiGroup": "RBAC.Authorization.K8s.io"}) == 0
    # the exact canonical spellings still FACT
    assert rb({"kind": "User", "name": "system:anonymous", "apiGroup": G}) == 1
    assert rb({"kind": "Group", "name": "system:unauthenticated", "apiGroup": G}) == 1


def test_rbac_fact_evidence_is_scoped_to_the_binding_not_live_access():
    """RED-PEN BLOCK #3 re-attack (MEDIUM, CONFIRMED): the RBAC oracle evidence asserted present-tense LIVE
    access ('an unauthenticated caller HAS write/admin access') from a DECLARED, possibly-unapplied manifest —
    the same overclaim the kube-bench oracle was scoped away from. Evidence now names the BINDING (source-
    neutral: 'WHERE IN EFFECT'), and observed.claim_scope == 'binding'."""
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable in the sovereign env")
    from framework.v2.verify.oracles import k8s_workload_posture_oracle
    G = "rbac.authorization.k8s.io"
    sig = k8s_workload_posture_oracle({"achieved_state": {
        "subjects": [{"kind": "User", "name": "system:anonymous", "api_group": G}],
        "role": "cluster-admin", "role_kind": "ClusterRole", "role_apigroup": G}})
    assert sig.fired
    assert "has write/admin access" not in sig.evidence, f"present-tense live overclaim remains: {sig.evidence!r}"
    assert sig.observed.get("claim_scope") == "binding"
    assert "binds" in sig.evidence.lower() and "where in effect" in sig.evidence.lower()


def test_primary_artifact_recheck_one_byte_mutation_fails_verification():
    """REVIEWER BLOCK #3 (the MAIN shared blocker): a signed digest alone only proves the cert CONTAINS a
    digest; verification must RECOMPUTE sha256 over the raw artifact bytes and cross-check it, so swapping the
    artifact fails. The posture cert opts in (artifact_recheck_required); verify recomputes + gates .ok. A
    correct-bytes verify passes; a 1-byte mutation fails; and a verify WITHOUT the bytes fails CLOSED."""
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable in the sovereign env")
    import json
    from framework.v2.evidence.certify import verify_certificate
    signers, tr = _signers_and_trust()
    kb = json.dumps({"Controls": [{"tests": [{"section": "1.2", "results": [
        {"test_number": "1.2.1", "status": "FAIL", "actual_value": "--anonymous-auth=true"}]}]}]})
    r = k8s_posture_verify(kb, engagement_slug="a", signers=signers)
    f = r.facts[0]
    ctx = r.contexts[f.finding_ref]
    cert = f.signed.certificate
    assert cert.artifact_recheck_required is True and cert.artifact_encoding == "canonical_text"
    # correct bytes -> ok
    good = verify_certificate(f.signed, oracle_context=ctx, trust_root=tr, artifact_bytes=r.artifact_bytes)
    assert good.ok and good.primary_artifact_ok
    # a re-checkable cert verified WITHOUT the bytes fails CLOSED (never silently passes)
    noargs = verify_certificate(f.signed, oracle_context=ctx, trust_root=tr)
    assert noargs.ok is False and noargs.primary_artifact_ok is False
    # a 1-byte mutation of the artifact fails (the recomputed sha256 no longer matches the bound one)
    mutated = bytearray(r.artifact_bytes)
    mutated[len(mutated) // 2] ^= 0x01
    bad = verify_certificate(f.signed, oracle_context=ctx, trust_root=tr, artifact_bytes=bytes(mutated))
    assert bad.ok is False and bad.primary_artifact_ok is False
    # even a byte APPENDED (same prefix) fails — length/content are both covered by the digest
    appended = verify_certificate(f.signed, oracle_context=ctx, trust_root=tr,
                                  artifact_bytes=r.artifact_bytes + b" ")
    assert appended.ok is False


def test_primary_artifact_bytes_vs_canonical_text_encoding_is_explicit():
    """REVIEWER BLOCK #3: bytes are authoritative; a str input is UTF-8 canonical text (its original
    byte-encoding/BOM is not its identity). The cert records which, and the two digests differ for the same
    logical document, so a verifier knows what it recomputed over."""
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable in the sovereign env")
    import json
    from framework.v2.evidence.certify import verify_certificate
    signers, tr = _signers_and_trust()
    doc = {"Controls": [{"tests": [{"section": "1.2", "results": [
        {"test_number": "1.2.1", "status": "FAIL", "actual_value": "--anonymous-auth=true"}]}]}]}
    text = json.dumps(doc)
    r_text = k8s_posture_verify(text, engagement_slug="a", signers=signers)
    r_bytes = k8s_posture_verify(text.encode("utf-16"), engagement_slug="a", signers=signers)
    assert r_text.facts[0].signed.certificate.artifact_encoding == "canonical_text"
    assert r_bytes.facts[0].signed.certificate.artifact_encoding == "bytes"
    # a UTF-16 byte input has a DIFFERENT digest than the UTF-8 canonical text of the same logical doc
    assert r_text.facts[0].signed.certificate.artifact_sha256 != r_bytes.facts[0].signed.certificate.artifact_sha256
    # each re-verifies only against ITS OWN retained bytes
    for r in (r_text, r_bytes):
        f = r.facts[0]
        assert verify_certificate(f.signed, oracle_context=r.contexts[f.finding_ref], trust_root=tr,
                                  artifact_bytes=r.artifact_bytes).ok


def test_rbac_typed_subjects_require_the_rbac_apigroup_before_minting():
    """REVIEWER BLOCK #3: subjects are TYPED {kind,name,api_group}; anon-ness is decided from the k8s TYPE and
    the RBAC apiGroup is REQUIRED before minting (an unapplied manifest that omits it is not API-validated, so
    it stays a lead — near-zero-FP for declared manifests). A well-formed subject fires; missing/empty/wrong
    apiGroup does not; and a name-collision impostor of the wrong kind never fires."""
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable in the sovereign env")
    import json
    signers, tr = _signers_and_trust()

    def rb(subject):
        m = json.dumps({"kind": "ClusterRoleBinding", "metadata": {"name": "y"},
                        "roleRef": {"kind": "ClusterRole", "apiGroup": "rbac.authorization.k8s.io",
                                    "name": "cluster-admin"},
                        "subjects": [subject]})
        return ingest_k8s_rbac(m, engagement_slug="a", signers=signers).n_facts

    G = "rbac.authorization.k8s.io"
    # well-formed anon User / Group -> FACT
    assert rb({"kind": "User", "name": "system:anonymous", "apiGroup": G}) == 1
    assert rb({"kind": "Group", "name": "system:unauthenticated", "apiGroup": G}) == 1
    # apiGroup REQUIRED: missing / empty / wrong -> no FACT (stays a lead)
    assert rb({"kind": "User", "name": "system:anonymous"}) == 0
    assert rb({"kind": "User", "name": "system:anonymous", "apiGroup": ""}) == 0
    assert rb({"kind": "User", "name": "system:anonymous", "apiGroup": "example.com"}) == 0
    # typed-kind discipline: name collisions of the WRONG kind never fire
    assert rb({"kind": "ServiceAccount", "name": "system:anonymous", "apiGroup": ""}) == 0
    assert rb({"kind": "User", "name": "system:unauthenticated", "apiGroup": G}) == 0   # Group's name on a User
    assert rb({"kind": "Group", "name": "system:anonymous", "apiGroup": G}) == 0        # User's name on a Group


def test_kube_bench_fact_subject_is_the_report_not_the_cluster():
    """REVIEWER BLOCK #3: kube-bench is an EXTERNAL scanner; the signed FACT must be scoped to the
    authenticated REPORT ('the report declares control X failed'), never an independent assertion about the
    live cluster. The oracle's evidence/observed must name the report as the subject, AND a genuine end-to-end
    kube-bench FACT must still mint + re-verify (subject-scoped, not downgraded)."""
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable in the sovereign env")
    import json
    from framework.v2.verify.oracles import k8s_posture_oracle
    signers, tr = _signers_and_trust()
    sig = k8s_posture_oracle({"check_id": "1.2.1", "status": "FAIL", "actual_value": "--anonymous-auth=true"})
    assert sig.fired, "a kube-bench control declaring a dangerous flag must still fire"
    assert sig.observed.get("subject") == "kube_bench_report", f"subject not scoped to the report: {sig.observed}"
    ev = sig.evidence.lower()
    assert "report" in ev and "not an independent" in ev and "live cluster" in ev, \
        f"kube-bench evidence must name the report (not a live-cluster observation): {sig.evidence[:200]!r}"
    # and the full path still mints a subject-scoped FACT that re-verifies offline
    kb = json.dumps({"Controls": [{"tests": [{"section": "1.2", "results": [
        {"test_number": "1.2.1", "status": "FAIL", "actual_value": "--anonymous-auth=true"}]}]}]})
    r = k8s_posture_verify(kb, engagement_slug="a", signers=signers)
    assert r.n_facts == 1


def test_rbac_finding_ref_collision_free_offline_reverify():
    """RED-PEN re-attack (MEDIUM, CONFIRMED): the RBAC finding_ref k8s:rbac:{check_id} collided for two UNNAMED
    ClusterRoleBindings (both -> 'clusterrolebinding'), and res.contexts (last-writer-wins) handed the first
    genuine FACT the second's context, so it failed offline re-verify — the SAME class the CIS path closed.
    A content digest disambiguates + context is retained only for facts."""
    pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable in the sovereign env")
    import json
    from framework.v2.evidence.certify import verify_certificate
    signers, tr = _signers_and_trust()
    two = "\n---\n".join([
        json.dumps({"kind": "ClusterRoleBinding",
                    "roleRef": {"kind": "ClusterRole", "apiGroup": "rbac.authorization.k8s.io",
                                "name": "cluster-admin"},
                    "subjects": [{"kind": "User", "name": "system:anonymous",
                                  "apiGroup": "rbac.authorization.k8s.io"}]}),
        json.dumps({"kind": "ClusterRoleBinding",
                    "roleRef": {"kind": "ClusterRole", "apiGroup": "rbac.authorization.k8s.io", "name": "admin"},
                    "subjects": [{"kind": "Group", "name": "system:unauthenticated",
                                  "apiGroup": "rbac.authorization.k8s.io"}]})])
    r = ingest_k8s_rbac(two, engagement_slug="a", signers=signers)
    refs = [f.finding_ref for f in r.facts]
    assert len(refs) == 2 and len(set(refs)) == 2, f"two unnamed bindings collided on one finding_ref: {refs}"
    for f in r.facts:
        assert verify_certificate(f.signed, oracle_context=r.contexts[f.finding_ref], trust_root=tr, artifact_bytes=r.artifact_bytes).ok, \
            "a genuine RBAC FACT failed offline re-verification (wrong retained context)"


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
    module's 'every FACT re-verifies offline' promise. The finding_ref now carries a full-sha256 canonical
    digest over the control's STRUCTURAL LOCATION (parse ordinal) + retained context, so distinct controls —
    AND two identical controls at DIFFERENT source positions (reviewer BLOCK #3) — get distinct refs, while a
    re-parse of the same bytes is order-stable."""
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
    # the digest component is a FULL sha256 (>=128 bits), not a short 48-bit prefix
    assert all(len(ref.rsplit("#", 1)[-1]) == 64 for ref in refs), f"finding_ref digest is not full sha256: {refs}"
    for f in r.facts:
        assert verify_certificate(f.signed, oracle_context=r.contexts[f.finding_ref], trust_root=tr, artifact_bytes=r.artifact_bytes).ok, \
            "a genuine kube-bench FACT failed offline re-verification (wrong retained context)"
    # two identical-CONTENT controls at DIFFERENT source positions are DISTINCT findings (reviewer BLOCK #3:
    # identical controls in different locations must NOT collapse into one finding).
    kb2 = json.dumps({"Controls": [{"tests": [{"section": "1.2", "results": [
        {"test_number": "1.2.1", "status": "FAIL", "actual_value": "--anonymous-auth=true"},
        {"test_number": "1.2.1", "status": "FAIL", "actual_value": "--anonymous-auth=true"}]}]}]})
    r2 = k8s_posture_verify(kb2, engagement_slug="a", signers=signers)
    assert len(set(f.finding_ref for f in r2.facts)) == 2, "same-content controls at different positions collapsed"
    # a re-parse of the SAME bytes yields the SAME finding_refs (order-stable -> offline re-verify is stable)
    r3 = k8s_posture_verify(kb2, engagement_slug="a", signers=signers)
    assert sorted(f.finding_ref for f in r2.facts) == sorted(f.finding_ref for f in r3.facts)


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
                       "subjects": [{"kind": "Group", "name": "system:unauthenticated",
                                     "apiGroup": "rbac.authorization.k8s.io"}]})
    assert ingest_k8s_rbac(real, engagement_slug="a", signers=signers).n_facts >= 1  # real Group anon FACTs
