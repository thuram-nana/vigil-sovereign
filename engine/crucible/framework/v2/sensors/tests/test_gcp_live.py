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
