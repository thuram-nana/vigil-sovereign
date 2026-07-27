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
    assert {"aws", "azure"} <= set(provs)
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
                 "GOOGLE_APPLICATION_CREDENTIALS_JSON", "KUBECONFIG_CONTENT",
                 *smod.CLOUD_CONFIG_VARS):
        assert name in _OFFENSE_ENV_ALLOWLIST, f"{name} not bridged to offense"
    assert "VIGIL_DESTRUCTION_OWNER_KEY" not in _OFFENSE_ENV_ALLOWLIST     # never bridged (unchanged)


def test_cloud_secrets_are_delivered_not_excluded():
    # the cloud secrets are in the offense-delivered set (not excluded like the destruction/voice keys)
    for name in ("AWS_SESSION_TOKEN", "AZURE_CLIENT_SECRET"):
        assert name in smod._OFFENSE_DELIVERED_SECRETS
        assert name not in smod._OFFENSE_EXCLUDED_SECRETS


# --- CC-2: GCP + Kubernetes file-content credentials (base64 seal + materialisation) --------------

import base64  # noqa: E402
import json as _json  # noqa: E402

_SA_JSON = _json.dumps({"type": "service_account", "project_id": "p",
                        "private_key": "PRIVKEY-do-not-leak", "client_email": "a@b.iam"})
_KUBECONFIG = "apiVersion: v1\nkind: Config\nclusters: []\ncurrent-context: c\nusers:\n- name: u\n  user:\n    token: TOKEN-do-not-leak\n"


def test_gcp_and_k8s_providers_use_file_inputs(env):
    st = smod.settings_status()
    provs = {p["id"]: p for p in st["cloud_providers"]}
    assert {"gcp", "kubernetes"} <= set(provs)
    gcp = {f["env"]: f for f in provs["gcp"]["fields"]}
    assert gcp["GOOGLE_APPLICATION_CREDENTIALS_JSON"]["kind"] == "secret"
    assert gcp["GOOGLE_APPLICATION_CREDENTIALS_JSON"]["input"] == "file"   # UI renders a textarea
    assert gcp["GOOGLE_CLOUD_PROJECT"]["kind"] == "config"
    k = {f["env"]: f for f in provs["kubernetes"]["fields"]}
    assert k["KUBECONFIG_CONTENT"]["input"] == "file"


def test_set_cloud_file_secret_seals_base64_and_redacts(env):
    store, owner, _ = env
    out = smod.set_cloud_file_secret("GOOGLE_APPLICATION_CREDENTIALS_JSON", _SA_JSON,
                                     store=store, owner_key=owner)
    assert out["ok"] and out["fingerprint"].startswith("sha256:")
    assert "PRIVKEY-do-not-leak" not in json.dumps(out)              # content never in the return
    from sigil.platform.secrets import SecretStore
    stored = SecretStore().get("GOOGLE_APPLICATION_CREDENTIALS_JSON")
    assert "\n" not in stored                                        # sealed BASE64 (single line — injection-safe)
    assert base64.b64decode(stored).decode() == _SA_JSON             # round-trips to the pasted content
    st = smod.settings_status()
    assert "PRIVKEY-do-not-leak" not in json.dumps(st)               # never in the redacted view


def test_set_cloud_file_secret_fail_closed(env):
    store, owner, _ = env
    with pytest.raises(ValueError):                                  # unknown name
        smod.set_cloud_file_secret("EVIL", _SA_JSON, store=store, owner_key=owner)
    with pytest.raises(ValueError):                                  # wrong kind (not a service account)
        smod.set_cloud_file_secret("GOOGLE_APPLICATION_CREDENTIALS_JSON", '{"type":"user"}',
                                   store=store, owner_key=owner)
    with pytest.raises(ValueError):                                  # oversized
        smod.set_cloud_file_secret("KUBECONFIG_CONTENT", "apiVersion: v1 clusters " + "x" * 9000,
                                   store=store, owner_key=owner)


def test_kubeconfig_seals_and_probe_is_honest(env):
    store, owner, _ = env
    smod.set_cloud_file_secret("KUBECONFIG_CONTENT", _KUBECONFIG, store=store, owner_key=owner)
    out = smod.check_secret("KUBECONFIG_CONTENT", store=store, owner_key=owner)
    assert out["status"] in ("unknown", "fail")                     # SDK absent / unreachable → never false ok
    assert "TOKEN-do-not-leak" not in json.dumps(out)               # kubeconfig never in the verdict


def test_bridge_materialises_file_creds_to_0600_and_drops_raw_content(tmp_path):
    # the offense bridge writes the base64 content to a FIXED-name 0600 file and hands the child only the
    # PATH — the raw content var never reaches an offense child as an env var.
    from vigil_integration.uiproxy import _materialise_file_secrets
    env_in = {"GOOGLE_APPLICATION_CREDENTIALS_JSON": base64.b64encode(_SA_JSON.encode()).decode(),
              "KUBECONFIG_CONTENT": base64.b64encode(_KUBECONFIG.encode()).decode(),
              "AWS_REGION": "us-east-1"}
    out = _materialise_file_secrets(dict(env_in), tmp_path)
    assert "GOOGLE_APPLICATION_CREDENTIALS_JSON" not in out and "KUBECONFIG_CONTENT" not in out
    g = out["GOOGLE_APPLICATION_CREDENTIALS"]
    assert g.endswith("/creds/gcp-sa.json")                         # FIXED name — no operator-controlled path
    import stat
    assert stat.S_IMODE(__import__("os").stat(g).st_mode) == 0o600
    assert open(g, encoding="utf-8").read() == _SA_JSON
    # no runtime dir → content dropped, no path set (collector then fails closed with no cloud identity)
    out2 = _materialise_file_secrets(dict(env_in), None)
    assert "GOOGLE_APPLICATION_CREDENTIALS" not in out2 and "GOOGLE_APPLICATION_CREDENTIALS_JSON" not in out2
    # a non-base64 value is dropped, never crashes
    out3 = _materialise_file_secrets({"KUBECONFIG_CONTENT": "!!!not-base64!!!"}, tmp_path)
    assert "KUBECONFIG" not in out3
