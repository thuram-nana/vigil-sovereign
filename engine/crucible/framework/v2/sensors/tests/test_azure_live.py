"""
Phase C2 · Azure — LIVE read-only Azure posture collector (sensors.azure_live).

Recorded azure-mgmt read-only response shapes -> the native inventory -> the EXISTING provider-agnostic
cloud oracles. Near-zero-FP (the AWS/GCP two-scope lesson): a blob container is a public FACT only when the
container's publicAccess is Blob/Container AND the storage account's allowBlobPublicAccess is enabled; the
account setting UNKNOWN → an un-promoted lead. Azure RBAC has no anonymous principal → topology only.
"""

from __future__ import annotations

from types import SimpleNamespace

from framework.v2.sensors.cloud import (
    cloud_observations,
    confirm_cloud_posture_facts,
    normalize_cloud_export,
)
from framework.v2.sensors.azure_live import (
    AzureLiveSensor,
    azure_inventory_from_responses,
    container_resource,
)


# --- the two-scope public rule -------------------------------------------------


def _open(c, **kw):
    kw.setdefault("account_allows_public", True)
    kw.setdefault("account_internet_open", True)
    return container_resource(c, **kw)


def test_container_public_only_when_all_three_scopes_open():
    c = {"id": "acct/data", "public_access": "Container"}
    assert "public" not in _open(c, account_allows_public=None)        # allow unknown → not confirmed
    assert "public" not in _open(c, account_allows_public=False)       # allow blocks → not public
    assert "public" not in _open(c, account_internet_open=None)        # network unknown → not confirmed
    assert "public" not in _open(c, account_internet_open=False)       # network firewalled → not public
    r = _open(c)                                                       # all three scopes open → CONFIRMED
    assert r["public"] is True and any(g["principal"] == "*" for g in r["grants"])
    assert r["container_public"] and r["account_allows_public"] and r["account_internet_open"]


def test_network_locked_account_is_not_internet_public():
    # BLOCK regression: publicAccess=Container + allowBlobPublicAccess=True but the account network is closed
    r = _open({"id": "locked/data", "public_access": "Container"}, account_internet_open=False)
    assert "public" not in r and r["container_public"] is True         # retained as a lead, not an internet FACT


def test_private_container_never_public():
    r = _open({"id": "acct/priv", "public_access": "None"})
    assert "public" not in r and "container_public" not in r           # publicAccess None → private
    assert _open({"id": "acct/blob", "public_access": "Blob"})["public"]


def test_sensitivity_tag_and_totality():
    r = _open({"id": "acct/secret", "public_access": "None", "tags": {"sensitive": "true"}})
    assert r["sensitive"] is True and "public" not in r
    assert container_resource({"id": ""}) is None and container_resource(7) is None
    assert azure_inventory_from_responses(containers=1)["resources"] == []       # non-iterable → total
    assert azure_inventory_from_responses(role_assignments="x")["principals"] == []


# --- the existing cloud oracles fire only on the confirmed cell ----------------


def test_oracle_fires_only_on_confirmed_public_container():
    containers = [{"id": "openacct/data", "public_access": "Container"},         # all three open → confirmed
                  {"id": "blockedacct/data", "public_access": "Container"},      # allowBlobPublicAccess off → no
                  {"id": "fwacct/data", "public_access": "Container"},           # network firewalled → no
                  {"id": "openacct/priv", "public_access": "None"}]              # private → no
    account_public = {"openacct": True, "blockedacct": False, "fwacct": True}
    account_net = {"openacct": True, "blockedacct": True, "fwacct": False}
    inv = azure_inventory_from_responses(containers=containers, account_public_by_id=account_public,
                                         account_internet_open_by_id=account_net, subscription="sub-1")
    assert inv["provider"] == "azure"
    reached = {f["resource"] for f in confirm_cloud_posture_facts(inv) if f["lead_class"] == "public_exposure"}
    assert reached == {"openacct/data"}                                          # exactly the confirmed one


def test_account_unknown_promotes_nothing():
    inv = azure_inventory_from_responses(containers=[{"id": "a/c", "public_access": "Blob"}],
                                         account_public_by_id={}, subscription="sub-1")   # both scopes unknown
    assert not [f for f in confirm_cloud_posture_facts(inv) if f["lead_class"] == "public_exposure"]


def test_rbac_is_topology_only_no_public():
    ra = [{"principal_id": "00000000-user"}, {"principal_id": "11111111-sp"}, {"principal_id": "00000000-user"}]
    inv = azure_inventory_from_responses(role_assignments=ra, subscription="sub-1")
    pids = {p["id"] for p in inv["principals"]}
    assert pids == {"00000000-user", "11111111-sp"}                             # de-duped principals
    assert not confirm_cloud_posture_facts(inv)                                 # RBAC has no anonymous public


def test_normalize_mints_lead_for_confirmed_public():
    inv = azure_inventory_from_responses(containers=[{"id": "a/c", "public_access": "Container"}],
                                         account_public_by_id={"a": True}, account_internet_open_by_id={"a": True},
                                         subscription="s")
    obs = cloud_observations(normalize_cloud_export(inv), seq=1)
    assert any(getattr(o, "attrs", {}).get("lead_class") == "public_exposure" for o in obs)


def test_account_internet_open_computation():
    # NOT internet-open iff publicNetworkAccess Disabled OR networkAcls.defaultAction Deny; absent → Azure
    # default (open).
    io = AzureLiveSensor._account_internet_open
    assert io(SimpleNamespace(public_network_access="Enabled",
                              network_rule_set=SimpleNamespace(default_action="Allow"))) is True
    assert io(SimpleNamespace(public_network_access="Disabled", network_rule_set=None)) is False
    assert io(SimpleNamespace(public_network_access="Enabled",
                              network_rule_set=SimpleNamespace(default_action="Deny"))) is False
    assert io(SimpleNamespace()) is True                              # absent fields → Azure default open


# --- egress + fail-closed run + fusion wiring ----------------------------------


def test_egress_declares_azure_control_plane_incl_imds_and_sovereign():
    h = set(AzureLiveSensor().egress_hosts)
    assert {"management.azure.com", "login.microsoftonline.com"} <= h            # commercial
    assert "169.254.169.254" in h                                               # IMDS (managed identity)
    assert {"management.usgovcloudapi.net", "management.chinacloudapi.cn"} <= h  # sovereign clouds


def test_run_fail_closed_without_azure_identity(monkeypatch):
    import sys
    monkeypatch.setitem(sys.modules, "azure.identity", None)
    monkeypatch.setitem(sys.modules, "azure", None)
    r = AzureLiveSensor(subscription="sub-1").run({}, SimpleNamespace())
    assert r.ok is False and "azure-identity" in r.note and "fail-closed" in r.note.lower()


def test_run_fail_closed_without_subscription():
    r = AzureLiveSensor(subscription="").run({}, SimpleNamespace())
    assert r.ok is False and "subscription" in r.note.lower()


def test_azure_live_wired_into_fusion():
    from framework.v2.engage_fusion import _LIVE_SENSORS, _fusion_registry
    from framework.v2.entitlement.models import Capability
    assert "azure_live" in _LIVE_SENSORS
    s = _fusion_registry().get("azure_live")
    assert isinstance(s, AzureLiveSensor) and s.tier == "T2" and s.capability == Capability.ACTIVE_RECON


def test_azure_live_export_promotes_through_reverify():
    import json as _json

    from framework.v2.engage_fusion import FusionTask, _reverify
    from framework.v2.worldmodel.graph import WorldModel
    from framework.v2.worldmodel.models import EdgeKind

    export = _json.dumps(azure_inventory_from_responses(
        containers=[{"id": "a/c", "public_access": "Container"}],
        account_public_by_id={"a": True}, account_internet_open_by_id={"a": True}, subscription="s"))
    res = SimpleNamespace(ok=True, result=SimpleNamespace(output={"export": export, "format": "native"}))
    world = WorldModel()
    promoted = _reverify(world, FusionTask("azure_live", {}), res, seq=5, slug="alpha")
    assert promoted == 1
    assert world.get_node("finding:policy_path:a/c") is not None
    assert world.get_edge("finding:policy_path:a/c", "datastore:a/c", EdgeKind.EVIDENCES) is not None
