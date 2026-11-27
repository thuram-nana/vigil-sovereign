"""
Phase C2 · Cloudflare — LIVE read-only Cloudflare posture collector (sensors.cloudflare_live).

The FOURTH live cloud collector. Recorded Cloudflare R2 read-only response shapes -> the native inventory ->
the EXISTING provider-agnostic cloud oracles (no new oracle). First ruleset, near-zero-FP by construction:
  * a public R2 bucket is a FACT only when its MANAGED *.r2.dev public-dev-URL is affirmatively ENABLED
    (anonymous internet read); managed disabled / UNKNOWN promotes nothing;
  * a CUSTOM-domain exposure (managed not enabled) is an auditable SIGNAL, never a promoted public FACT
    (a custom domain can sit behind Access / a firewall — conservative, err to false-negative).
"""

from __future__ import annotations

from types import SimpleNamespace

from framework.v2.sensors.cloud import (
    cloud_observations,
    confirm_cloud_posture_facts,
    normalize_cloud_export,
)
from framework.v2.sensors.cloudflare_live import (
    CloudflareLiveSensor,
    bucket_resource,
    cloudflare_inventory_from_responses,
)

ACCT = "0123456789abcdef0123456789abcdef"   # a 32-lowercase-hex Cloudflare account id


def _bucket(name, *, managed=None, customs=None):
    """A collected R2 bucket record. ``managed`` is the managed-domain (r2.dev) enabled bool (or None=unknown);
    ``customs`` is a list of (domain, enabled) for the bound custom domains."""
    entry = {"name": name}
    if managed is not None:
        entry["managed_public"] = {"enabled": managed}
    if customs is not None:
        entry["custom"] = {"domains": [{"domain": d, "enabled": en} for d, en in customs]}
    return entry


# --- bucket public: the managed r2.dev rule + custom-domain deferral -----------


def test_public_bucket_only_when_managed_dev_url_enabled():
    # managed r2.dev ENABLED -> CONFIRMED anonymous public (a promotable * read grant)
    r_open = bucket_resource(_bucket("open", managed=True), account=ACCT)
    assert r_open["id"] == f"{ACCT}/open" and r_open["public"] is True
    assert any(g["principal"] == "*" and g["access"] == "read" for g in r_open["grants"])
    assert r_open["r2_managed_public"] is True
    # managed DISABLED -> retained signal, NOT public
    r_priv = bucket_resource(_bucket("priv", managed=False), account=ACCT)
    assert "public" not in r_priv and r_priv["r2_managed_public"] is False
    # managed UNKNOWN (denied / not read) -> neither a signal value nor public (never guessed)
    r_unk = bucket_resource(_bucket("unk"), account=ACCT)
    assert "public" not in r_unk and "r2_managed_public" not in r_unk


def test_custom_domain_is_a_signal_not_a_promoted_fact():
    # a bound, enabled custom domain with the managed URL NOT enabled: retained as an audit signal only.
    r = bucket_resource(_bucket("cdn", managed=False, customs=[("cdn.acme.com", True), ("stale.acme.com", False)]),
                        account=ACCT)
    assert "public" not in r                                  # NOT promoted (anonymous reach not confirmed)
    assert r["r2_custom_domains"] == ["cdn.acme.com"]         # only the ENABLED domain, retained for audit
    # managed ENABLED still wins as the promotable fact even when a custom domain is also present
    r2 = bucket_resource(_bucket("both", managed=True, customs=[("cdn.acme.com", True)]), account=ACCT)
    assert r2["public"] is True and r2["r2_custom_domains"] == ["cdn.acme.com"]


def test_totality_and_assembler():
    assert bucket_resource({"name": ""}) is None and bucket_resource(7) is None
    # odd shapes degrade to the bare resource, never raise
    assert bucket_resource({"name": "b", "managed_public": 5, "custom": "x"}, account=ACCT) == {
        "id": f"{ACCT}/b", "kind": "datastore"}
    # the assembler is total on a non-iterable buckets arg
    assert cloudflare_inventory_from_responses(buckets=1, account=ACCT)["resources"] == []
    inv = cloudflare_inventory_from_responses(buckets=[_bucket("open", managed=True)], account=ACCT)
    assert inv["provider"] == "cloudflare" and inv["account"] == ACCT and inv["principals"] == []
    assert inv["resources"][0]["id"] == f"{ACCT}/open"


# --- the existing cloud oracle fires only on the confirmed-public bucket --------


def test_oracle_fires_only_on_confirmed_public_bucket():
    buckets = [_bucket("open", managed=True),                               # managed enabled -> confirmed
               _bucket("priv", managed=False),                              # managed disabled -> no
               _bucket("cdn", managed=False, customs=[("cdn.acme.com", True)]),  # custom only -> deferred
               _bucket("unk")]                                              # unknown -> no
    inv = cloudflare_inventory_from_responses(buckets=buckets, account=ACCT)
    reached = {f["resource"] for f in confirm_cloud_posture_facts(inv) if f["lead_class"] == "public_exposure"}
    assert reached == {f"{ACCT}/open"}                                      # exactly the confirmed one


def test_normalize_mints_a_lead_for_a_confirmed_public_bucket():
    inv = cloudflare_inventory_from_responses(buckets=[_bucket("open", managed=True)], account=ACCT)
    obs = cloud_observations(normalize_cloud_export(inv), seq=1)
    assert any(getattr(o, "attrs", {}).get("lead_class") == "public_exposure" for o in obs)


def test_custom_domain_bucket_promotes_no_fact():
    inv = cloudflare_inventory_from_responses(
        buckets=[_bucket("cdn", managed=False, customs=[("cdn.acme.com", True)])], account=ACCT)
    assert not [f for f in confirm_cloud_posture_facts(inv) if f["lead_class"] == "public_exposure"]


# --- egress + fail-closed run + fusion wiring ----------------------------------


def test_egress_declares_cloudflare_api_host_only():
    assert CloudflareLiveSensor().egress_hosts == ("api.cloudflare.com",)


def test_run_fail_closed_requires_injection():
    # require_injected + NO injected session -> REFUSE (Cloudflare has no ambient identity to fall back to).
    r = CloudflareLiveSensor(require_injected_credentials=True).run({}, SimpleNamespace())
    assert r.ok is False and "no identity substitution" in r.note.lower()
    assert (r.output or {}).get("missing_prerequisite") and (r.output or {}).get("assessed") is False


def test_run_no_injection_is_a_fail_closed_no_op():
    # no injection + not required: nothing to assess (no ambient Cloudflare identity) -> INCONCLUSIVE, never clean.
    r = CloudflareLiveSensor().run({}, SimpleNamespace())
    assert r.ok is False
    assert (r.output or {}).get("status") == "inconclusive" and (r.output or {}).get("assessed") is False


def test_cloudflare_live_wired_into_fusion():
    from framework.v2.engage_fusion import _LIVE_SENSORS, _fusion_registry
    from framework.v2.entitlement.models import Capability
    assert "cloudflare_live" in _LIVE_SENSORS
    s = _fusion_registry().get("cloudflare_live")
    assert isinstance(s, CloudflareLiveSensor) and s.tier == "T2" and s.capability == Capability.ACTIVE_RECON
    assert s.destructive is False


def test_cloudflare_live_export_promotes_through_reverify():
    import json as _json

    from framework.v2.engage_fusion import FusionTask, _reverify
    from framework.v2.worldmodel.graph import WorldModel
    from framework.v2.worldmodel.models import EdgeKind

    export = _json.dumps(cloudflare_inventory_from_responses(
        buckets=[_bucket("open", managed=True)], account=ACCT))
    res = SimpleNamespace(ok=True, result=SimpleNamespace(output={"export": export, "format": "native"}))
    world = WorldModel()
    promoted = _reverify(world, FusionTask("cloudflare_live", {}), res, seq=5, slug="alpha")
    assert promoted == 1
    assert world.get_node(f"finding:policy_path:{ACCT}/open") is not None
    assert world.get_edge(f"finding:policy_path:{ACCT}/open", f"datastore:{ACCT}/open", EdgeKind.EVIDENCES) is not None
