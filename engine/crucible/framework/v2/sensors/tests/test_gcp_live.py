"""
Phase C2 · GCP — LIVE read-only GCP posture collector (sensors.gcp_live).

The GCP twin of test_cloud_live: recorded google-cloud read-only response shapes -> the native inventory
-> the EXISTING provider-agnostic cloud oracles FIRE (a public GCS bucket / public project-IAM binding
promotes to a public_exposure FACT exactly as AWS does). Includes the near-zero-FP negative controls: a
Public-Access-Prevention-enforced bucket and a PAP-unknown bucket must NOT promote. The live boto3-style
run() path is fail-closed without the SDK/ADC (the SDKs are optional).
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
)

# recorded read-only response shapes (reduced to what the collector gathers per bucket / for project IAM)
_PUBLIC_BUCKET = {"name": "acme-public", "iam_members": ["allUsers", "user:a@b.com"],
                  "public_access_prevention": "inherited", "labels": {}}
_ENFORCED_BUCKET = {"name": "acme-enforced", "iam_members": ["allUsers"],
                    "public_access_prevention": "enforced", "labels": {}}      # PAP blocks the public binding
_PAP_UNKNOWN_BUCKET = {"name": "acme-unknown", "iam_members": ["allAuthenticatedUsers"],
                       "public_access_prevention": None, "labels": {}}          # PAP unreadable → unconfirmed
_PRIVATE_BUCKET = {"name": "acme-private", "iam_members": ["user:a@b.com"],
                   "public_access_prevention": "inherited", "labels": {"data-classification": "confidential"}}

_PROJECT_IAM_PUBLIC = {"project": "acme-prod", "bindings": [
    {"role": "roles/viewer", "members": ["allUsers"]},                          # a PUBLIC project binding
    {"role": "roles/owner", "members": ["user:admin@acme.com"]}]}
_PROJECT_IAM_PRIVATE = {"project": "acme-prod", "bindings": [
    {"role": "roles/owner", "members": ["user:admin@acme.com"]}]}


# --- deterministic core: bucket public detection is PAP-aware -----------------


def test_public_bucket_via_anon_binding_when_pap_not_enforced():
    r = bucket_resource(_PUBLIC_BUCKET)
    assert r["public"] is True and any(g["principal"] == "allUsers" for g in r["grants"])
    assert r["iam_public"] is True and r["public_access_prevention"] == "inherited"


def test_pap_enforced_neutralises_a_public_binding():
    r = bucket_resource(_ENFORCED_BUCKET)
    assert "public" not in r                       # PAP enforced → not anonymously reachable
    assert r["iam_public"] is True                 # raw signal retained (auditable)


def test_pap_unknown_is_not_confirmed_public():
    r = bucket_resource(_PAP_UNKNOWN_BUCKET)        # PAP unreadable → cannot confirm
    assert "public" not in r
    assert r["iam_public"] is True and "public_access_prevention" not in r


def test_private_bucket_and_sensitivity_label():
    r = bucket_resource(_PRIVATE_BUCKET)
    assert "public" not in r and r["sensitive"] is True   # operator-labelled sensitive; not public


def test_bucket_resource_totality():
    assert bucket_resource({"name": ""}) is None and bucket_resource(7) is None
    r = bucket_resource({"name": "b", "iam_members": "nonsense", "public_access_prevention": 5, "labels": []})
    assert r == {"id": "b", "kind": "datastore"}   # nothing asserted from garbage
    assert gcp_inventory_from_responses(buckets=1)["resources"] == []   # non-iterable → total, no raise


# --- the existing cloud oracles fire over the translated GCP inventory --------


def test_oracles_fire_on_public_gcs_and_project_iam_not_on_safe():
    inv = gcp_inventory_from_responses(
        buckets=[_PUBLIC_BUCKET, _ENFORCED_BUCKET, _PAP_UNKNOWN_BUCKET, _PRIVATE_BUCKET],
        project_iam=_PROJECT_IAM_PUBLIC, project="acme-prod")
    assert inv["provider"] == "gcp"
    facts = confirm_cloud_posture_facts(inv)
    reached = {f["resource"] for f in facts if f["lead_class"] == "public_exposure"}
    assert "acme-public" in reached                        # public GCS bucket confirmed
    assert "projects/acme-prod" in reached                 # public project-IAM binding confirmed
    for safe in ("acme-enforced", "acme-unknown", "acme-private"):
        assert safe not in reached, f"false public FACT on {safe}"


def test_private_project_iam_promotes_nothing():
    inv = gcp_inventory_from_responses(buckets=[_PRIVATE_BUCKET], project_iam=_PROJECT_IAM_PRIVATE,
                                       project="acme-prod")
    facts = confirm_cloud_posture_facts(inv)
    assert not [f for f in facts if f["lead_class"] == "public_exposure"]
    # the named admin is a topology principal, not a public resource
    assert any(p["id"] == "user:admin@acme.com" for p in inv["principals"])


def test_normalize_mints_public_exposure_lead():
    inv = gcp_inventory_from_responses(buckets=[_PUBLIC_BUCKET], project="acme-prod")
    obs = cloud_observations(normalize_cloud_export(inv), seq=1)
    assert any(getattr(o, "attrs", {}).get("lead_class") == "public_exposure" for o in obs)


# --- fail-closed run + egress + fusion wiring --------------------------------


def test_egress_hosts_are_the_google_control_plane():
    h = set(GcpLiveSensor().egress_hosts)
    assert {"storage.googleapis.com", "cloudresourcemanager.googleapis.com", "oauth2.googleapis.com"} <= h


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

    export = _json.dumps(gcp_inventory_from_responses(buckets=[_PUBLIC_BUCKET], project="acme-prod"))
    res = SimpleNamespace(ok=True, result=SimpleNamespace(output={"export": export, "format": "native"}))
    world = WorldModel()
    promoted = _reverify(world, FusionTask("gcp_live", {}), res, seq=5, slug="alpha")
    assert promoted == 1
    finding = world.get_node("finding:policy_path:acme-public")
    assert finding is not None
    assert world.get_edge("finding:policy_path:acme-public", "datastore:acme-public", EdgeKind.EVIDENCES) is not None
