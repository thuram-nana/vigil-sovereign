"""
Phase C2 · GCP — LIVE read-only GCP posture collector (sensors.gcp_live).

Recorded google-cloud read-only response shapes -> the native inventory -> the EXISTING provider-agnostic
cloud oracles. Near-zero-FP (the AWS lessons, corrected after a BLOCK):
  * a public GCS bucket is a FACT only when an UNCONDITIONED anon binding is present AND the bucket does not
    enforce PAP AND the EFFECTIVE org-policy PAP is read and NOT enforcing (the two-scope rule);
  * a Condition-narrowed anon binding is NEVER promoted;
  * a project-IAM anon binding is an auditable signal, not a promoted FACT.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace

from framework.v2.sensors.cloud import (
    cloud_observations,
    confirm_cloud_posture_facts,
    normalize_cloud_export,
)
from framework.v2.sensors.gcp_live import (
    GcpLiveSensor,
    bucket_resource,
    gcp_inventory_from_responses,
    org_pap_enforced_from_policy,
)


def _bucket(name, members, *, pap="inherited", conditioned=False, labels=None):
    return {"name": name, "iam_bindings": [{"members": members, "conditioned": conditioned}],
            "public_access_prevention": pap, "labels": labels or {}}


# --- the org-policy PAP parser -------------------------------------------------


def test_org_pap_parser():
    P = org_pap_enforced_from_policy
    assert P({"spec": {"rules": [{"enforce": True}]}}) is True
    assert P({"spec": {"rules": [{"enforce": False}]}}) is False
    assert P({"spec": {"rules": []}}) is None                                     # no rule → unknown
    assert P("garbage") is None                                                   # total
    # safety-critical direction (return OPEN while the org enforces) must be unreachable:
    assert P({"spec": {"rules": [{"enforce": False}, {"enforce": True}]}}) is True   # order-independent
    assert P({"spec": {"rules": [{"enforce": True}, {"enforce": False}]}}) is True
    for spoof in ("false", "true", 0, 1, None):
        assert P({"spec": {"rules": [{"enforce": spoof}]}}) is None               # non-bool never spoofs OPEN
    # a CONDITIONED rule is indeterminate — never read as OPEN (defence-in-depth)
    assert P({"spec": {"rules": [{"enforce": False, "condition": {"expression": "x"}}]}}) is None
    assert P({"spec": {"rules": [{"enforce": False, "condition": {"e": "x"}}, {"enforce": True}]}}) is True


# --- bucket public: the two-scope PAP rule + conditions ------------------------


def test_public_bucket_only_when_both_scopes_open():
    b = _bucket("acme-public", ["allUsers"], pap="inherited")
    # org unknown → NOT confirmed (conservative, err to false-negative)
    r0 = bucket_resource(b, org_pap_enforced=None)
    assert "public" not in r0 and r0["iam_public"] is True
    # org enforces → NOT public (org blocks it even though bucket is 'inherited')
    r1 = bucket_resource(b, org_pap_enforced=True)
    assert "public" not in r1
    # bucket 'inherited' + org NOT enforcing + unconditioned anon → CONFIRMED public
    r2 = bucket_resource(b, org_pap_enforced=False)
    assert r2["public"] is True and any(g["principal"] == "allUsers" for g in r2["grants"])


def test_bucket_pap_enforced_never_public():
    r = bucket_resource(_bucket("acme-enforced", ["allUsers"], pap="enforced"), org_pap_enforced=False)
    assert "public" not in r and r["iam_public"] is True   # bucket enforces → not public even if org is open


def test_conditioned_anon_binding_is_not_public():
    # BLOCK regression: a Condition-narrowed anon binding must NOT be promoted, even with both scopes open
    r = bucket_resource(_bucket("acme-cond", ["allUsers"], pap="inherited", conditioned=True),
                        org_pap_enforced=False)
    assert "public" not in r and "iam_public" not in r
    assert r["conditioned_public"] is True                 # retained as an audit signal only


def test_non_anon_and_labels_and_totality():
    r = bucket_resource(_bucket("acme-private", ["user:a@b.com"], labels={"data-classification": "confidential"}),
                        org_pap_enforced=False)
    assert "public" not in r and r["sensitive"] is True
    assert bucket_resource({"name": ""}) is None and bucket_resource(7) is None
    assert bucket_resource({"name": "b", "iam_bindings": "x", "public_access_prevention": 5}) == {
        "id": "b", "kind": "datastore"}
    # totality of the assembler on non-iterables (LOW regression)
    assert gcp_inventory_from_responses(buckets=1)["resources"] == []
    assert gcp_inventory_from_responses(project_iam={"project": "p", "bindings": {"members": 5}})["resources"] == []


# --- the existing cloud oracles fire only on the confirmed cell ----------------


def test_oracle_fires_only_on_confirmed_public_bucket():
    buckets = [_bucket("open", ["allUsers"], pap="inherited"),          # + org open → confirmed
               _bucket("enforced", ["allUsers"], pap="enforced"),       # bucket enforces → no
               _bucket("cond", ["allUsers"], pap="inherited", conditioned=True),   # conditioned → no
               _bucket("private", ["user:a@b"])]                        # not anon → no
    inv = gcp_inventory_from_responses(buckets=buckets, org_pap_enforced=False, project="p")
    reached = {f["resource"] for f in confirm_cloud_posture_facts(inv) if f["lead_class"] == "public_exposure"}
    assert reached == {"open"}                                          # exactly the confirmed one


def test_org_unknown_promotes_no_bucket_fact():
    inv = gcp_inventory_from_responses(buckets=[_bucket("open", ["allUsers"])], org_pap_enforced=None, project="p")
    assert not [f for f in confirm_cloud_posture_facts(inv) if f["lead_class"] == "public_exposure"]


def test_project_iam_anon_is_a_signal_not_a_fact():
    project_iam = {"project": "acme-prod", "bindings": [
        {"role": "roles/viewer", "members": ["allUsers"], "conditioned": False},   # unconditioned anon
        {"role": "roles/owner", "members": ["user:admin@acme.com"], "conditioned": False}]}
    inv = gcp_inventory_from_responses(project_iam=project_iam, org_pap_enforced=False, project="acme-prod")
    # recorded as an auditable signal, NOT promoted to a public FACT (DRS org-policy unresolved here)
    proj = [r for r in inv["resources"] if r["id"] == "projects/acme-prod"][0]
    assert proj.get("public_roles") and "public" not in proj
    assert not confirm_cloud_posture_facts(inv)
    assert any(p["id"] == "user:admin@acme.com" for p in inv["principals"])


def test_normalize_mints_a_lead_for_a_confirmed_public_bucket():
    inv = gcp_inventory_from_responses(buckets=[_bucket("open", ["allUsers"])], org_pap_enforced=False, project="p")
    obs = cloud_observations(normalize_cloud_export(inv), seq=1)
    assert any(getattr(o, "attrs", {}).get("lead_class") == "public_exposure" for o in obs)


# --- LIVE-collection seam: project-level public IAM grant surfaces as a public_roles signal -------------
#
# The pure `_project_iam_to_inventory` tests above hand-feed role-carrying bindings, so they passed even
# while the LIVE path was dead: `_bindings_from_policy` dropped the binding `role`, so `_collect_project_iam`
# produced role-less dicts and `public_roles` NEVER populated on live-collected data (the documented project
# signal never fired). These tests drive the ACTUAL reducer / collection seam, proving the capability is real.


def _sdk_binding(role, members, *, conditioned=False):
    """A google-cloud `getIamPolicy` binding object (``.role`` / ``.members`` / ``.condition``) — the SDK
    shape ``_bindings_from_policy`` reduces (an IAM Condition rides on ``.condition``)."""
    return SimpleNamespace(role=role, members=list(members),
                           condition=SimpleNamespace(expression="x") if conditioned else None)


def _sdk_policy(*bindings):
    return SimpleNamespace(bindings=list(bindings))


def test_bindings_from_policy_preserves_role_for_project_iam():
    # The exact dead-code regression guard: the reducer that fed project IAM used to DROP `role`.
    reduced = GcpLiveSensor._bindings_from_policy(_sdk_policy(
        _sdk_binding("roles/viewer", ["allUsers"]),
        _sdk_binding("roles/editor", ["user:a@b.com"], conditioned=True)))
    assert reduced == [
        {"members": ["allUsers"], "conditioned": False, "role": "roles/viewer"},
        {"members": ["user:a@b.com"], "conditioned": True, "role": "roles/editor"}]
    # a dict-shaped binding (the other branch) carries role too; a role-less binding degrades to "".
    assert GcpLiveSensor._bindings_from_policy(SimpleNamespace(bindings=[
        {"role": "roles/owner", "members": ["allUsers"], "condition": None},
        {"members": ["allUsers"]}])) == [
        {"members": ["allUsers"], "conditioned": False, "role": "roles/owner"},
        {"members": ["allUsers"], "conditioned": False, "role": ""}]


def test_live_collected_project_iam_surfaces_public_roles_signal_not_fact(monkeypatch):
    # Drive the real collection seam `_collect_project_iam` (which calls `_bindings_from_policy`) via a faked
    # `resourcemanager_v3` client returning an UNCONDITIONED `allUsers` grant on a real role at the project
    # level — exactly the public-exposure misconfiguration the module docstring says it records.
    import types

    policy = _sdk_policy(
        _sdk_binding("roles/viewer", ["allUsers", "user:ops@acme.com"]),   # unconditioned anon on a real role
        _sdk_binding("roles/owner", ["user:admin@acme.com"]))              # ordinary grant → a principal only

    class _ProjectsClient:
        def __init__(self, *, credentials=None, **kw):
            pass

        def get_iam_policy(self, *, resource=None):
            assert resource == "projects/acme-prod"
            return policy

    g_rm = types.ModuleType("google.cloud.resourcemanager_v3")
    g_rm.ProjectsClient = _ProjectsClient  # type: ignore[attr-defined]
    g_cloud = types.ModuleType("google.cloud")
    g_cloud.resourcemanager_v3 = g_rm  # type: ignore[attr-defined]
    g = types.ModuleType("google")
    g.cloud = g_cloud  # type: ignore[attr-defined]
    for name, mod in {"google": g, "google.cloud": g_cloud,
                      "google.cloud.resourcemanager_v3": g_rm}.items():
        monkeypatch.setitem(sys.modules, name, mod)

    collected = GcpLiveSensor()._collect_project_iam("acme-prod", credentials=object())
    # the LIVE reducer now carries role through, so the project response is complete...
    assert collected == {"project": "acme-prod", "bindings": [
        {"members": ["allUsers", "user:ops@acme.com"], "conditioned": False, "role": "roles/viewer"},
        {"members": ["user:admin@acme.com"], "conditioned": False, "role": "roles/owner"}]}

    inv = gcp_inventory_from_responses(project_iam=collected, org_pap_enforced=False, project="acme-prod")
    proj = [r for r in inv["resources"] if r["id"] == "projects/acme-prod"]
    # POSITIVE: the project-level public grant now SURFACES as an auditable public_roles signal...
    assert proj and proj[0]["public_roles"] == ["roles/viewer"]
    # ...carrying NO `public`/`grants` flag (the signal-not-FACT contract: deferred DRS-org-policy confirm)...
    assert "public" not in proj[0] and "grants" not in proj[0]
    # ...so the deterministic oracle records it as a signal and mints NO public-exposure FACT for it.
    assert not confirm_cloud_posture_facts(inv)
    # the ordinary (non-anon) members still land as topology principals, anon never does.
    pri = {p["id"] for p in inv["principals"]}
    assert pri == {"user:ops@acme.com", "user:admin@acme.com"}


def test_live_collected_conditioned_anon_project_grant_does_not_surface(monkeypatch):
    # NEGATIVE control: a Condition-narrowed anon project binding is NOT an unconditional public grant, so it
    # must NOT surface a public_roles signal (mirrors the bucket `conditioned` handling), even via the live path.
    import types

    policy = _sdk_policy(_sdk_binding("roles/viewer", ["allUsers"], conditioned=True))

    class _ProjectsClient:
        def __init__(self, *, credentials=None, **kw):
            pass

        def get_iam_policy(self, *, resource=None):
            return policy

    g_rm = types.ModuleType("google.cloud.resourcemanager_v3")
    g_rm.ProjectsClient = _ProjectsClient  # type: ignore[attr-defined]
    g_cloud = types.ModuleType("google.cloud")
    g_cloud.resourcemanager_v3 = g_rm  # type: ignore[attr-defined]
    g = types.ModuleType("google")
    g.cloud = g_cloud  # type: ignore[attr-defined]
    for name, mod in {"google": g, "google.cloud": g_cloud,
                      "google.cloud.resourcemanager_v3": g_rm}.items():
        monkeypatch.setitem(sys.modules, name, mod)

    collected = GcpLiveSensor()._collect_project_iam("acme-prod", credentials=object())
    assert collected["bindings"] == [
        {"members": ["allUsers"], "conditioned": True, "role": "roles/viewer"}]
    inv = gcp_inventory_from_responses(project_iam=collected, org_pap_enforced=False, project="acme-prod")
    # no projects/<id> resource at all (the only anon binding was condition-narrowed) and no FACT.
    assert not [r for r in inv["resources"] if r["id"] == "projects/acme-prod"]
    assert not confirm_cloud_posture_facts(inv)


def test_role_key_is_additive_bucket_path_unchanged():
    # The `role` key is threaded for BOTH consumers; the bucket consumer (`_anon_binding_kinds` via
    # `bucket_resource`) reads only members/conditioned, so an iam_binding now carrying `role` is byte-identical.
    with_role = _bucket("open", ["allUsers"], pap="inherited")
    with_role["iam_bindings"][0]["role"] = "roles/storage.objectViewer"   # the extra key the live reducer adds
    without_role = _bucket("open", ["allUsers"], pap="inherited")
    assert (bucket_resource(with_role, org_pap_enforced=False)
            == bucket_resource(without_role, org_pap_enforced=False))
    # and a conditioned bucket binding with a role is still never promoted.
    cond = _bucket("c", ["allUsers"], pap="inherited", conditioned=True)
    cond["iam_bindings"][0]["role"] = "roles/storage.admin"
    r = bucket_resource(cond, org_pap_enforced=False)
    assert "public" not in r and r["conditioned_public"] is True


# --- egress + fail-closed run + fusion wiring ----------------------------------


def test_egress_declares_google_hosts_incl_metadata():
    h = set(GcpLiveSensor().egress_hosts)
    assert {"storage.googleapis.com", "orgpolicy.googleapis.com", "oauth2.googleapis.com"} <= h
    assert "metadata.google.internal" in h and "169.254.169.254" in h    # ADC metadata egress declared


def test_run_fail_closed_without_google_auth(monkeypatch):
    import sys
    monkeypatch.setitem(sys.modules, "google.auth", None)
    monkeypatch.setitem(sys.modules, "google", None)
    r = GcpLiveSensor().run({}, SimpleNamespace())
    assert r.ok is False and "google-auth" in r.note and "fail-closed" in r.note.lower()


def test_gcp_live_wired_into_fusion():
    from framework.v2.engage_fusion import _LIVE_SENSORS, _fusion_registry
    from framework.v2.entitlement.models import Capability
    assert "gcp_live" in _LIVE_SENSORS
    s = _fusion_registry().get("gcp_live")
    assert isinstance(s, GcpLiveSensor) and s.tier == "T2" and s.capability == Capability.ACTIVE_RECON


def test_gcp_live_export_promotes_through_reverify():
    import json as _json

    from framework.v2.engage_fusion import FusionTask, _reverify
    from framework.v2.worldmodel.graph import WorldModel
    from framework.v2.worldmodel.models import EdgeKind

    export = _json.dumps(gcp_inventory_from_responses(
        buckets=[_bucket("open", ["allUsers"])], org_pap_enforced=False, project="p"))
    res = SimpleNamespace(ok=True, result=SimpleNamespace(output={"export": export, "format": "native"}))
    world = WorldModel()
    promoted = _reverify(world, FusionTask("gcp_live", {}), res, seq=5, slug="alpha")
    assert promoted == 1
    assert world.get_node("finding:policy_path:open") is not None
    assert world.get_edge("finding:policy_path:open", "datastore:open", EdgeKind.EVIDENCES) is not None
