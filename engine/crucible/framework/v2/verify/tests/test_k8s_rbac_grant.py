"""E4 TIER-2 — the K8s dangerous-VERB / default-SA RBAC verb-grant oracle and its near-zero-FP controls.

TIER-1 (`k8s_workload_posture_oracle`) only NAME-matches a built-in ClusterRole; TIER-2 PARSES the referenced
Role/ClusterRole's `rules`, so it also confirms an anonymous subject bound to a CUSTOM role whose rules are
dangerous — and it re-checks the roleRef->role_object identity JOIN rather than trusting the runner.

The soundness core is the SUBJECT-GATED FACT eligibility an adversarial design review made mandatory:

  * an ANONYMOUS subject may FACT on ANY dangerous shape (full-wildcard / secret-read / priv-esc);
  * the DEFAULT ServiceAccount and system:authenticated may FACT ONLY on a full-wildcard */*/* grant AND ONLY
    via a ClusterRoleBinding.

That gate exists because the built-in `admin` role LEGITIMATELY grants Secrets get/list/watch (which is why
k8s 1.24 stripped secret-read from `edit` but kept it in `admin`), and cluster-read backup/monitoring roles
(Velero, Prometheus) legitimately hold `*/*` get/list/watch. Without the gate, the single most common
legitimate RBAC delegations in real clusters would mint CRITICAL false FACTs. The A-FP1/A-FP2/A-FP3 controls
below pin exactly that, and each is MUTATION-VERIFIED: break one field -> LEAD, repair it -> FACT, so no
control can silently rot into a vacuous pass.
"""

from __future__ import annotations

import copy

from framework.v2.verify.models import OracleKind
from framework.v2.verify.oracles import k8s_rbac_verb_grant_oracle

_RBAC = "rbac.authorization.k8s.io"

_ANON_USER = {"kind": "User", "name": "system:anonymous", "namespace": "", "api_group": _RBAC}
_DEFAULT_SA = {"kind": "ServiceAccount", "name": "default", "namespace": "default", "api_group": ""}
_ALL_AUTH = {"kind": "Group", "name": "system:authenticated", "namespace": "", "api_group": _RBAC}
_NAMED_SA = {"kind": "ServiceAccount", "name": "payments-api", "namespace": "default", "api_group": ""}

# rule shapes
_FULL_WILDCARD = {"verbs": ["*"], "resources": ["*"], "apiGroups": ["*"]}
_SECRET_READ = {"verbs": ["get", "list", "watch"], "resources": ["secrets"], "apiGroups": [""]}
_PRIV_ESC = {"verbs": ["escalate"], "resources": ["clusterroles"], "apiGroups": [_RBAC]}
_BENIGN = {"verbs": ["get", "list"], "resources": ["pods", "configmaps"], "apiGroups": [""]}
# the built-in `admin` role's real secret-read grant — the A-FP1 legitimate namespace-owner delegation.
_ADMIN_LIKE = {"verbs": ["get", "list", "watch", "create", "update", "delete"],
               "resources": ["secrets", "pods", "deployments"], "apiGroups": ["", "apps"]}
# a cluster-read backup/monitoring role (Velero / Prometheus) — A-FP2: broad READ, not full wildcard.
_CLUSTER_READ = {"verbs": ["get", "list", "watch"], "resources": ["*"], "apiGroups": ["*"]}


def _ctl(*, subjects, rules, bind_kind="ClusterRoleBinding", bind_ns="", role_kind="ClusterRole",
         role_ns="", role_name="dangerous-role", rules_source="live_clusterrole_get", agg=None) -> dict:
    """A retained TIER-2 control: a binding + the SEPARATELY-retained role_object its roleRef names."""
    ctl = {
        "check_id": f"{bind_kind.lower()}:{role_name}",
        "binding": {"kind": bind_kind, "namespace": bind_ns, "name": "b1", "subjects": list(subjects),
                    "role_ref": {"name": role_name, "kind": role_kind, "api_group": _RBAC}},
        "role_object": {"name": role_name, "kind": role_kind, "api_group": _RBAC, "namespace": role_ns,
                        "rules": list(rules), "rules_source": rules_source},
    }
    if agg is not None:
        ctl["role_object"]["aggregationRule"] = agg
    return ctl


def _fires(ctl) -> bool:
    return k8s_rbac_verb_grant_oracle(ctl).fired


# ---------------------------------------------------------------------------
# The FACT set — what TIER-2 is FOR.
# ---------------------------------------------------------------------------


def test_anonymous_bound_to_a_custom_role_with_secret_read_is_a_fact():
    # TIER-2's genuine delta over TIER-1: the role is CUSTOM (no built-in name to match), but its PARSED
    # rules grant secret-read to an anonymous subject.
    s = k8s_rbac_verb_grant_oracle(_ctl(subjects=[_ANON_USER], rules=[_SECRET_READ],
                                        role_name="custom-reader"))
    assert s.fired is True and s.confidence == 0.9
    assert s.kind == OracleKind.K8S_RBAC_VERB_GRANT
    assert s.observed["subject_class"] == "anon"
    assert "secret_read" in s.observed["dangerous_shapes"]


def test_anonymous_may_fact_on_every_dangerous_shape():
    for rule, shape in ((_FULL_WILDCARD, "full_wildcard"), (_SECRET_READ, "secret_read"),
                        (_PRIV_ESC, "priv_esc")):
        s = k8s_rbac_verb_grant_oracle(_ctl(subjects=[_ANON_USER], rules=[rule]))
        assert s.fired is True, shape
        assert shape in s.observed["dangerous_shapes"]


def test_default_sa_on_a_full_wildcard_clusterrolebinding_is_a_fact_with_an_honest_occupancy_note():
    s = k8s_rbac_verb_grant_oracle(_ctl(subjects=[_DEFAULT_SA], rules=[_FULL_WILDCARD]))
    assert s.fired is True and s.observed["subject_class"] == "default_sa"
    assert s.observed["claim_scope"] == "cluster"
    # the claim must be worded as the BINDING GRANT + an explicit occupancy caveat (a binding's existence is
    # NOT proof a pod runs as that SA) — honesty the review required.
    assert "occupancy" in s.evidence.lower() and "assumption" in s.evidence.lower()


def test_all_authenticated_on_a_full_wildcard_clusterrolebinding_is_a_fact():
    s = k8s_rbac_verb_grant_oracle(_ctl(subjects=[_ALL_AUTH], rules=[_FULL_WILDCARD]))
    assert s.fired is True and s.observed["subject_class"] == "all_auth"


# ---------------------------------------------------------------------------
# THE MANDATORY NEAR-ZERO-FP CONTROLS (A.4). Each is MUTATION-VERIFIED: the legitimate configuration is a
# LEAD, and a single repair that makes it genuinely unambiguous flips it to FACT — proving the control is
# load-bearing rather than a vacuous always-LEAD path.
# ---------------------------------------------------------------------------


def test_A_FP1_default_sa_bound_to_an_admin_like_role_in_a_namespace_stays_a_lead():
    # THE headline false-FACT the review caught: "let this app own its namespace" — a RoleBinding of
    # default:default to a role whose rules include Secrets get/list/watch (exactly what the built-in `admin`
    # grants). This is the MOST COMMON legitimate delegation in real clusters and MUST stay a LEAD.
    legit = _ctl(subjects=[_DEFAULT_SA], rules=[_ADMIN_LIKE], bind_kind="RoleBinding", bind_ns="default",
                 role_kind="ClusterRole", role_ns="", role_name="admin")
    assert _fires(legit) is False, "default:default x admin secret-read in a namespace must NOT be a FACT"

    # REPAIR 1 — the same rules bound to an ANONYMOUS subject IS unambiguous -> FACT.
    anon = copy.deepcopy(legit)
    anon["binding"]["subjects"] = [_ANON_USER]
    assert _fires(anon) is True

    # REPAIR 2 — default:default on a genuine */*/* ClusterRoleBinding IS unambiguous -> FACT.
    wild = _ctl(subjects=[_DEFAULT_SA], rules=[_FULL_WILDCARD])
    assert _fires(wild) is True


def test_A_FP2_cluster_read_backup_role_bound_to_authenticated_stays_a_lead():
    # Velero / Prometheus / external-secrets pattern: cluster-wide READ (`*` resources, get/list/watch) — a
    # (b)-shaped grant, NOT a full wildcard. A default/authenticated subject may not FACT on it.
    legit = _ctl(subjects=[_ALL_AUTH], rules=[_CLUSTER_READ])
    assert _fires(legit) is False, "a cluster-read backup role bound to system:authenticated must stay a LEAD"

    # REPAIR — widen the verbs to a genuine `*` (cluster-admin-equivalent) -> FACT.
    wild = copy.deepcopy(legit)
    wild["role_object"]["rules"] = [_FULL_WILDCARD]
    assert _fires(wild) is True


def test_A_FP3_authenticated_on_priv_esc_or_secret_read_stays_a_lead():
    # system:authenticated is the weakest member of S: it may FACT ONLY on full-wildcard-at-cluster-scope.
    for rule in (_SECRET_READ, _PRIV_ESC):
        legit = _ctl(subjects=[_ALL_AUTH], rules=[rule])
        assert _fires(legit) is False, f"all_auth must not FACT on {rule['verbs']}"
        # REPAIR — the same rule bound to an ANONYMOUS subject -> FACT.
        anon = copy.deepcopy(legit)
        anon["binding"]["subjects"] = [_ANON_USER]
        assert _fires(anon) is True


def test_default_sa_full_wildcard_via_a_NAMESPACED_rolebinding_stays_a_lead():
    # The scope half of A.4: even a full-wildcard grant to default:default is only a FACT at CLUSTER scope.
    ns_scoped = _ctl(subjects=[_DEFAULT_SA], rules=[_FULL_WILDCARD], bind_kind="RoleBinding",
                     bind_ns="default", role_kind="Role", role_ns="default", role_name="ns-wild",
                     rules_source="live_role_get")
    assert _fires(ns_scoped) is False, "a namespaced RoleBinding is not cluster scope"
    # REPAIR — the same subject+rules via a ClusterRoleBinding -> FACT.
    assert _fires(_ctl(subjects=[_DEFAULT_SA], rules=[_FULL_WILDCARD])) is True


def test_a_named_service_account_is_not_in_the_occupiable_set():
    named = _ctl(subjects=[_NAMED_SA], rules=[_FULL_WILDCARD])
    assert _fires(named) is False, "a NAMED SA is not attacker-occupiable by default"
    # REPAIR — the same binding to default:default -> FACT.
    repaired = copy.deepcopy(named)
    repaired["binding"]["subjects"] = [_DEFAULT_SA]
    assert _fires(repaired) is True


# ---------------------------------------------------------------------------
# Rule-parsing precision + the identity-linkage and authoritativeness gates.
# ---------------------------------------------------------------------------


def test_a_custom_role_merely_NAMED_admin_with_harmless_rules_stays_a_lead():
    # The direct inverse of TIER-1's name-match: TIER-2 IGNORES the name and parses the rules.
    benign = _ctl(subjects=[_ANON_USER], rules=[_BENIGN], role_name="admin")
    assert _fires(benign) is False
    # REPAIR — give the same role genuinely dangerous rules -> FACT.
    dangerous = copy.deepcopy(benign)
    dangerous["role_object"]["rules"] = [_SECRET_READ]
    assert _fires(dangerous) is True


def test_a_CRD_named_secrets_in_a_non_core_apigroup_stays_a_lead():
    crd = _ctl(subjects=[_ANON_USER],
               rules=[{"verbs": ["get", "list"], "resources": ["secrets"], "apiGroups": ["example.com"]}])
    assert _fires(crd) is False, "a CRD `secrets` in a custom apiGroup is not the core Secret"
    # REPAIR — the core apiGroup -> FACT.
    core = copy.deepcopy(crd)
    core["role_object"]["rules"][0]["apiGroups"] = [""]
    assert _fires(core) is True


def test_a_resourcenames_scoped_single_secret_get_stays_a_lead_but_list_still_facts():
    scoped = _ctl(subjects=[_ANON_USER],
                  rules=[{"verbs": ["get"], "resources": ["secrets"], "apiGroups": [""],
                          "resourceNames": ["public-ca-bundle"]}])
    assert _fires(scoped) is False, "a get on ONE named secret is not a secret-read grant"
    # REPAIR — list/watch IGNORE resourceNames in k8s, so widening to list -> FACT.
    listed = copy.deepcopy(scoped)
    listed["role_object"]["rules"][0]["verbs"] = ["get", "list"]
    assert _fires(listed) is True


def test_identity_linkage_breaks_stay_leads_each_mutation_verified():
    good = _ctl(subjects=[_ANON_USER], rules=[_FULL_WILDCARD])
    assert _fires(good) is True

    # roleRef.name != role_object.name — the runner paired a benign binding with a dangerous role object.
    bad_name = copy.deepcopy(good)
    bad_name["binding"]["role_ref"]["name"] = "some-other-role"
    assert _fires(bad_name) is False

    # kind mismatch
    bad_kind = copy.deepcopy(good)
    bad_kind["role_object"]["kind"] = "Role"
    assert _fires(bad_kind) is False

    # apiGroup not exactly the RBAC group (TIER-2 grants NO empty-string tolerance)
    bad_group = copy.deepcopy(good)
    bad_group["binding"]["role_ref"]["api_group"] = ""
    assert _fires(bad_group) is False

    # a ClusterRole role_object carrying a namespace is malformed
    bad_ns = copy.deepcopy(good)
    bad_ns["role_object"]["namespace"] = "default"
    assert _fires(bad_ns) is False

    # a namespaced Role referenced from a different namespace than the RoleBinding
    cross_ns = _ctl(subjects=[_ANON_USER], rules=[_FULL_WILDCARD], bind_kind="RoleBinding", bind_ns="prod",
                    role_kind="Role", role_ns="default", rules_source="live_role_get")
    assert _fires(cross_ns) is False
    same_ns = copy.deepcopy(cross_ns)
    same_ns["role_object"]["namespace"] = "prod"
    assert _fires(same_ns) is True   # repaired -> FACT (the linkage control is load-bearing)


def test_non_authoritative_rules_stay_leads_mutation_verified():
    # An AGGREGATED ClusterRole's effective rules are filled in by the controller, so a STATIC manifest of it
    # does not carry them — the capture cannot prove what the role really grants.
    agg = _ctl(subjects=[_ANON_USER], rules=[_FULL_WILDCARD], rules_source="static_manifest",
               agg={"clusterRoleSelectors": [{"matchLabels": {"rbac.example/aggregate": "true"}}]})
    assert _fires(agg) is False, "aggregated + static_manifest rules are not authoritative"
    # REPAIR 1 — a LIVE API GET returns the controller-computed effective rules -> FACT.
    live = copy.deepcopy(agg)
    live["role_object"]["rules_source"] = "live_clusterrole_get"
    assert _fires(live) is True
    # REPAIR 2 — a static manifest of a NON-aggregated role is authoritative -> FACT.
    plain = copy.deepcopy(agg)
    del plain["role_object"]["aggregationRule"]
    assert _fires(plain) is True

    # an ABSENT rules_source is never authoritative
    unknown = copy.deepcopy(agg)
    del unknown["role_object"]["aggregationRule"]
    unknown["role_object"]["rules_source"] = ""
    assert _fires(unknown) is False


def test_no_dangerous_rule_and_malformed_evidence_never_fire_or_raise():
    assert _fires(_ctl(subjects=[_ANON_USER], rules=[_BENIGN])) is False
    assert _fires(_ctl(subjects=[_ANON_USER], rules=[])) is False
    for bad in (None, "x", 123, [], {}, {"binding": {}}, {"role_object": {}},
                {"binding": {"kind": "ClusterRoleBinding"}, "role_object": {"rules": "not-a-list"}}):
        s = k8s_rbac_verb_grant_oracle(bad)
        assert s.fired is False, f"malformed evidence must never fire: {bad!r}"
        assert s.confidence == 0.0
