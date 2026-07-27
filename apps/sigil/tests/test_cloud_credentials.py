"""Cloud-credentials Settings plane (CC-1: AWS + Azure).

The load-bearing invariants (a false-green here would leak a cloud secret or make the plane a placebo):
  • a sealed cloud secret (access key / secret / session token / client secret) NEVER appears in the
    action return, the redacted status / cloud_providers view, or the append-only spine — only a
    fingerprint;
  • the per-provider view groups the FULL field set (secrets masked, config shown) so the operator has a
    place for every cloud credential; a bad/expired credential shows FAILING (the probe never false-oks);
  • fail-closed — an unknown cloud-config var, an unsafe value (line-injection), or a malformed
    endpoint/role ARN is refused; a cloud config + secret are DELIVERED to the offense engine so the
    collector's ambient chain discovers them.
"""
from __future__ import annotations

import json

import pytest

from sigil.governor.identity import ensure_owner_keypair
from sigil.spine.store import SpineStore
from sigil.ui import settings as smod

AWS_SECRET = "wJalrXUtnFEMI-TOPSECRET-do-not-leak-EXAMPLEKEY"
AZ_SECRET = "az~CLIENT~SECRET~do~not~leak~9999"


@pytest.fixture
def env(tmp_path, monkeypatch):
    from sigil.platform import secrets as secmod
    monkeypatch.setattr(smod, "SIGIL_HOME", tmp_path)
    monkeypatch.setattr(secmod, "SIGIL_HOME", tmp_path)
    orig_init = secmod.SecretStore.__init__

    def _no_kr(self):
        orig_init(self)
        self._kr = None                     # no OS keyring in tests → the envfile tier under tmp_path

    monkeypatch.setattr(secmod.SecretStore, "__init__", _no_kr)
    for var in (*smod.SECRET_NAMES, *smod.CLOUD_CONFIG_VARS, smod._CHOICE_ENV):
        monkeypatch.setenv(var, "")
        monkeypatch.delenv(var, raising=False)
    store = SpineStore(str(tmp_path / "spine.jsonl"))
    owner = ensure_owner_keypair()
    return store, owner, tmp_path


# --- the per-provider view -----------------------------------------------------


def test_cloud_providers_view_groups_full_field_set(env):
    st = smod.settings_status()
    provs = {p["id"]: p for p in st["cloud_providers"]}
    assert set(provs) == {"aws", "azure"}
    aws_fields = {f["env"]: f for f in provs["aws"]["fields"]}
    # the FULL AWS credential: keys (secret) + session token (secret) + region/role/endpoint (config)
    assert aws_fields["AWS_ACCESS_KEY_ID"]["kind"] == "secret"
    assert aws_fields["AWS_SESSION_TOKEN"]["kind"] == "secret"
    assert aws_fields["AWS_REGION"]["kind"] == "config"
    assert aws_fields["CRUCIBLE_AWS_ENDPOINT_URL"]["kind"] == "config"
    assert provs["aws"]["probe_env"] == "AWS_ACCESS_KEY_ID"
    az_fields = {f["env"]: f for f in provs["azure"]["fields"]}
    assert az_fields["AZURE_CLIENT_SECRET"]["kind"] == "secret"     # only the secret is masked
    assert az_fields["AZURE_TENANT_ID"]["kind"] == "config"         # ids are shown
    assert provs["azure"]["probe_env"] == "AZURE_CLIENT_SECRET"


def test_endpoint_override_carries_a_credential_warning(env):
    # LOW-1 mitigation: the custom-endpoint field warns that credentials are sent there.
    st = smod.settings_status()
    aws = [p for p in st["cloud_providers"] if p["id"] == "aws"][0]
    ep = [f for f in aws["fields"] if f["env"] == "CRUCIBLE_AWS_ENDPOINT_URL"][0]
    assert ep["kind"] == "config" and "credentials" in ep["warn"].lower()


def test_sealed_cloud_secret_is_redacted_in_the_view(env):
    store, owner, _ = env
    smod.set_secret("AZURE_CLIENT_SECRET", AZ_SECRET, store=store, owner_key=owner)
    st = smod.settings_status()
    az = [p for p in st["cloud_providers"] if p["id"] == "azure"][0]
    f = [x for x in az["fields"] if x["env"] == "AZURE_CLIENT_SECRET"][0]
    assert f["set"] is True and f["fingerprint"].startswith("sha256:")
    assert AZ_SECRET not in json.dumps(st)                          # never in the redacted view
    assert "value" not in f                                         # a SECRET field never carries its value


def test_sealed_cloud_secret_never_on_the_spine_or_return(env):
    store, owner, _ = env
    out = smod.set_secret("AWS_SESSION_TOKEN", AWS_SECRET, store=store, owner_key=owner)
    assert AWS_SECRET not in json.dumps(out) and out["fingerprint"].startswith("sha256:")
    rec = store.get(out["recorded_seq"])
    assert rec is not None and AWS_SECRET not in json.dumps(rec.payload)   # spine holds only the fingerprint
    assert AWS_SECRET not in json.dumps(rec.payload) and rec.payload.get("fp") == out["fingerprint"]


# --- non-secret config: persisted, shown, delivered, fail-closed ---------------


def test_set_cloud_config_persists_shows_and_delivers(env):
    store, owner, _ = env
    smod.set_cloud_config("AWS_REGION", "eu-west-1", store=store, owner_key=owner)
    st = smod.settings_status()
    aws = [p for p in st["cloud_providers"] if p["id"] == "aws"][0]
    region = [f for f in aws["fields"] if f["env"] == "AWS_REGION"][0]
    assert region["kind"] == "config" and region["value"] == "eu-west-1"
    # delivered to the keyless offense engine (where boto3's ambient chain reads it)
    assert smod.export_runtime_env().get("AWS_REGION") == "eu-west-1"


def test_cloud_secret_and_config_delivered_to_offense(env):
    store, owner, _ = env
    smod.set_secret("AWS_ACCESS_KEY_ID", "AKIA-EXAMPLE", store=store, owner_key=owner)
    smod.set_secret("AWS_SECRET_ACCESS_KEY", AWS_SECRET, store=store, owner_key=owner)
    smod.set_cloud_config("CRUCIBLE_AWS_ENDPOINT_URL", "http://localhost:4566", store=store, owner_key=owner)
    delivered = smod.export_runtime_env(include_secrets=True)
    assert delivered.get("AWS_ACCESS_KEY_ID") == "AKIA-EXAMPLE"
    assert delivered.get("AWS_SECRET_ACCESS_KEY") == AWS_SECRET     # the collector needs it (bridged)
    assert delivered.get("CRUCIBLE_AWS_ENDPOINT_URL") == "http://localhost:4566"
    # the destruction owner key is NEVER delivered to offense (unchanged invariant)
    assert "VIGIL_DESTRUCTION_OWNER_KEY" not in delivered


def test_unknown_cloud_config_var_refused(env):
    store, owner, _ = env
    with pytest.raises(ValueError):
        smod.set_cloud_config("EVIL_VAR", "x", store=store, owner_key=owner)


@pytest.mark.parametrize("envk,val", [
    ("CRUCIBLE_AWS_ENDPOINT_URL", "ftp://nope"),        # not http(s)
    ("AWS_ROLE_ARN", "not-an-arn"),                     # not an ARN
    ("AWS_REGION", "us-east-1\nVIGIL_DESTRUCTION_OWNER_KEY=evil"),   # envfile line-injection
])
def test_invalid_cloud_config_value_refused(env, envk, val):
    store, owner, _ = env
    with pytest.raises(ValueError):
        smod.set_cloud_config(envk, val, store=store, owner_key=owner)


# --- live probe: honest, never a false ok, never leaks the secret --------------


def test_azure_probe_without_ids_is_unknown_not_ok(env):
    store, owner, _ = env
    smod.set_secret("AZURE_CLIENT_SECRET", AZ_SECRET, store=store, owner_key=owner)
    out = smod.check_secret("AZURE_CLIENT_SECRET", store=store, owner_key=owner)
    assert out["status"] in ("unknown", "fail")        # no tenant/client (or SDK absent) → never a false ok
    assert AZ_SECRET not in json.dumps(out)             # the secret never appears in the verdict/spine


def test_aws_probe_without_secret_is_unknown(env):
    store, owner, _ = env
    smod.set_secret("AWS_ACCESS_KEY_ID", "AKIA-EXAMPLE", store=store, owner_key=owner)
    out = smod.check_secret("AWS_ACCESS_KEY_ID", store=store, owner_key=owner)
    assert out["status"] in ("unknown", "fail")        # missing secret half / no boto3 → not ok


# --- the offense bridge carries the cloud creds, but never the destruction key -------------------


def test_offense_bridge_allowlist_covers_cloud_creds():
    # every cloud secret + config the collectors need must be on the offense-env allowlist, or `vigil up`
    # would silently DROP it at the bridge and the live collector would fail-closed with no creds.
    from vigil_integration.uiproxy import _OFFENSE_ENV_ALLOWLIST
    for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AZURE_CLIENT_SECRET",
                 *smod.CLOUD_CONFIG_VARS):
        assert name in _OFFENSE_ENV_ALLOWLIST, f"{name} not bridged to offense"
    assert "VIGIL_DESTRUCTION_OWNER_KEY" not in _OFFENSE_ENV_ALLOWLIST     # never bridged (unchanged)


def test_cloud_secrets_are_delivered_not_excluded():
    # the cloud secrets are in the offense-delivered set (not excluded like the destruction/voice keys)
    for name in ("AWS_SESSION_TOKEN", "AZURE_CLIENT_SECRET"):
        assert name in smod._OFFENSE_DELIVERED_SECRETS
        assert name not in smod._OFFENSE_EXCLUDED_SECRETS
