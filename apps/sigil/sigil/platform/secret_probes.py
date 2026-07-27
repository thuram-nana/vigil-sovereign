"""secret_probes — LIVE per-secret health checks for the Settings / API-keys plane (Phase A1).

A sealed secret being PRESENT is not the same as it WORKING: an expired / revoked / typo'd key still shows
"set". This module runs a minimal, side-effect-free LIVE probe per provider and returns a verdict
(``ok`` | ``fail`` | ``unknown``) + a short reason — **never the secret value**. It is sovereign-side (reads
``SecretStore`` directly); egress is HOST-PINNED per provider, short-timeout, and fail-closed (any error →
``fail``/``unknown``, never ``ok``). The only operator-influenced URL (Azure endpoint) is shape-validated to a
``*.openai.azure.com`` https host to keep the probe SSRF-safe.

Verdicts are cached in a 0600, **value-free** file so the UI + the top-bar "keys failing" badge reflect the
last check across restarts without re-hitting the provider on every render.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlparse

from ..config import SIGIL_HOME
from .secrets import SecretStore

_TIMEOUT_S = 8.0
_HEALTH_CACHE: Path = SIGIL_HOME / "secret-health.json"     # 0600, value-free verdict cache

OK, FAIL, UNKNOWN = "ok", "fail", "unknown"


# --- HTTP core (host-pinned, minimal, fail-closed, NO cross-host redirect) --------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect. A 3xx would otherwise be auto-followed WITH the auth header attached, which
    would relay the API key to the redirect target (a second SSRF/exfil path). Returning None stops the
    follow; the 3xx is then reported as a non-2xx ⇒ fail."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _do_open(req, timeout):
    """Single open point (redirect-blocking opener) — also the test seam."""
    return _OPENER.open(req, timeout=timeout)   # noqa: S310 — https + host-pinned/validated by callers


def _http_probe(url: str, headers: dict, *, ok_codes: tuple = (200,)) -> "tuple[str, str]":
    """A minimal authenticated GET to a PINNED provider URL. Sends only the auth header(s) — no target data.
    2xx ⇒ ok; 401/403 ⇒ fail (bad/expired key); 3xx/other/network/timeout ⇒ fail. Never follows a redirect
    (would relay the key); never raises."""
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with _do_open(req, timeout=_TIMEOUT_S) as resp:
            code = resp.getcode()
            return (OK, f"reachable (HTTP {code})") if code in ok_codes else (FAIL, f"HTTP {code}")
    except urllib.error.HTTPError as e:
        if e.code in ok_codes:
            return OK, f"reachable (HTTP {e.code})"
        if e.code in (401, 403):
            return FAIL, f"rejected (HTTP {e.code}) — key invalid, expired, or lacks permission"
        return FAIL, f"HTTP {e.code}"
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return FAIL, f"unreachable: {type(e).__name__}"
    except Exception as e:  # noqa: BLE001 — fail-closed on anything unexpected
        return FAIL, f"probe error: {type(e).__name__}"


# --- per-provider probes: run(value, store, ctx) -> (status, reason) --------------------------------

def _probe_anthropic(value: str, store: SecretStore, ctx: dict) -> "tuple[str, str]":
    return _http_probe("https://api.anthropic.com/v1/models",
                       {"x-api-key": value, "anthropic-version": "2023-06-01"})


def _probe_github(value: str, store: SecretStore, ctx: dict) -> "tuple[str, str]":
    return _http_probe("https://api.github.com/user",
                       {"Authorization": f"Bearer {value}", "User-Agent": "vigil-key-check",
                        "Accept": "application/vnd.github+json"})


def _probe_mistral(value: str, store: SecretStore, ctx: dict) -> "tuple[str, str]":
    return _http_probe("https://api.mistral.ai/v1/models", {"Authorization": f"Bearer {value}"})


def _probe_openai(value: str, store: SecretStore, ctx: dict) -> "tuple[str, str]":
    return _http_probe("https://api.openai.com/v1/models", {"Authorization": f"Bearer {value}"})


def _probe_perplexity(value: str, store: SecretStore, ctx: dict) -> "tuple[str, str]":
    # Perplexity returns 401 on a bad key even for a HEAD-ish GET; a 200/400 both mean the key was accepted.
    return _http_probe("https://api.perplexity.ai/models", {"Authorization": f"Bearer {value}"},
                       ok_codes=(200, 400))


def _probe_elevenlabs(value: str, store: SecretStore, ctx: dict) -> "tuple[str, str]":
    return _http_probe("https://api.elevenlabs.io/v1/user", {"xi-api-key": value})


def _probe_azure_openai(value: str, store: SecretStore, ctx: dict) -> "tuple[str, str]":
    endpoint = str(ctx.get("AZURE_OPENAI_ENDPOINT", "") or "").strip().rstrip("/")
    if not endpoint:
        return UNKNOWN, "set the Azure endpoint (in Models) to enable this check"
    # SSRF guard: the endpoint is the ONE operator-supplied URL, so parse it and validate the HOSTNAME (not a
    # substring — `https://evil/.openai.azure.com`, `https://x.openai.azure.com.evil`, and userinfo tricks all
    # defeat a substring check). Then rebuild the base URL from ONLY scheme+host(+port) so no path/query the
    # operator smuggled in survives. The auth key is only ever sent to a real *.openai.azure.com host.
    u = urlparse(endpoint)
    host = (u.hostname or "").lower()
    if u.scheme != "https" or u.username or u.password or "@" in endpoint or not host.endswith(".openai.azure.com"):
        return FAIL, "endpoint must be https://<resource>.openai.azure.com"
    base = f"https://{host}" + (f":{u.port}" if u.port else "")
    return _http_probe(f"{base}/openai/models?api-version=2024-02-01", {"api-key": value})


def _probe_aws(value: str, store: SecretStore, ctx: dict) -> "tuple[str, str]":
    # value = AWS_ACCESS_KEY_ID; the companion secret + optional session token are read from the store
    # (never passed via ctx). boto3 is optional — absent ⇒ unknown (honest), never a false ok. STS
    # get-caller-identity validates without touching any resource; an endpoint override (LocalStack/self-
    # hosted) is honoured so the check hits the same endpoint the collector will.
    secret = str(store.get("AWS_SECRET_ACCESS_KEY") or "").strip()
    if not secret:
        return UNKNOWN, "also set AWS_SECRET_ACCESS_KEY to validate"
    token = str(store.get("AWS_SESSION_TOKEN") or "").strip()
    region = str(ctx.get("AWS_REGION", "") or ctx.get("CRUCIBLE_BEDROCK_REGION", "") or "us-east-1")
    endpoint = str(ctx.get("CRUCIBLE_AWS_ENDPOINT_URL", "") or "").strip()
    try:
        import boto3  # optional dependency
    except Exception:  # noqa: BLE001
        return UNKNOWN, "install boto3 to validate AWS credentials"
    kwargs: dict = {"aws_access_key_id": value, "aws_secret_access_key": secret, "region_name": region}
    if token:
        kwargs["aws_session_token"] = token
    if endpoint:
        kwargs["endpoint_url"] = endpoint
    try:
        ident = boto3.client("sts", **kwargs).get_caller_identity()
        acct = str(ident.get("Account", "")) if isinstance(ident, dict) else ""
        return (OK, f"STS ok (account {acct[:6]}…)") if acct else (OK, "STS get-caller-identity ok")
    except Exception as e:  # noqa: BLE001 — fail-closed; never leak the secret in the message
        return FAIL, f"AWS rejected credentials: {type(e).__name__}"


def _probe_azure(value: str, store: SecretStore, ctx: dict) -> "tuple[str, str]":
    # value = AZURE_CLIENT_SECRET; tenant + client id are NON-secret config (from ctx). azure-identity is
    # optional — absent ⇒ unknown (honest). A management-scope AAD token validates the service principal
    # without touching any resource. Any error ⇒ fail; the secret never appears in the message.
    tenant = str(ctx.get("AZURE_TENANT_ID", "") or "").strip()
    client = str(ctx.get("AZURE_CLIENT_ID", "") or "").strip()
    if not (tenant and client):
        return UNKNOWN, "also set AZURE_TENANT_ID and AZURE_CLIENT_ID to validate"
    try:
        from azure.identity import ClientSecretCredential  # optional dependency
    except Exception:  # noqa: BLE001
        return UNKNOWN, "install azure-identity to validate Azure credentials"
    try:
        cred = ClientSecretCredential(tenant_id=tenant, client_id=client, client_secret=value)
        tok = cred.get_token("https://management.azure.com/.default")
        return (OK, "AAD token ok") if (tok and getattr(tok, "token", "")) else (FAIL, "Azure returned no token")
    except Exception as e:  # noqa: BLE001 — fail-closed; never leak the secret
        return FAIL, f"Azure rejected credentials: {type(e).__name__}"


def _decode_b64(value: str) -> "str | None":
    """Decode a BASE64-sealed file-content secret back to text; None if it is not valid base64/UTF-8."""
    import base64
    try:
        return base64.b64decode(value, validate=True).decode("utf-8")
    except Exception:  # noqa: BLE001
        return None


def _probe_gcp(value: str, store: SecretStore, ctx: dict) -> "tuple[str, str]":
    # value = BASE64(service-account JSON). google-auth is optional — absent ⇒ unknown (honest). Minting an
    # access token validates the key WITHOUT touching any resource; the request goes to Google's fixed OAuth
    # token endpoint. Any error ⇒ fail; the key material never appears in the verdict.
    content = _decode_b64(value)
    if not content:
        return UNKNOWN, "stored GCP credential is not decodable — re-seal the service-account JSON"
    try:
        import json as _json
        from google.oauth2 import service_account  # optional dependency
        from google.auth.transport.requests import Request  # optional dependency
    except Exception:  # noqa: BLE001
        return UNKNOWN, "install google-auth to validate GCP credentials"
    try:
        info = _json.loads(content)
        creds = service_account.Credentials.from_service_account_info(
            info, scopes=["https://www.googleapis.com/auth/cloud-platform.read-only"])
        creds.refresh(Request())
        return (OK, "GCP access token ok") if creds.token else (FAIL, "GCP returned no token")
    except Exception as e:  # noqa: BLE001 — fail-closed; never leak the key
        return FAIL, f"GCP rejected credentials: {type(e).__name__}"


def _probe_kubernetes(value: str, store: SecretStore, ctx: dict) -> "tuple[str, str]":
    # value = BASE64(kubeconfig). The kubernetes client is optional — absent ⇒ unknown (honest). A read-only
    # GET /version validates reachability + auth; the apiserver host is pinned by the operator's kubeconfig,
    # short-timeout, fail-closed. Any error ⇒ fail; the kubeconfig never appears in the verdict.
    content = _decode_b64(value)
    if not content:
        return UNKNOWN, "stored kubeconfig is not decodable — re-seal it"
    try:
        import yaml  # optional dependency (pulled in by the kubernetes client)
        from kubernetes import client as _kclient  # optional dependency
        from kubernetes import config as _kconfig
    except Exception:  # noqa: BLE001
        return UNKNOWN, "install the kubernetes client to validate a kubeconfig"
    try:
        cfg = yaml.safe_load(content)
        api = _kclient.ApiClient()
        context = str(ctx.get("KUBE_CONTEXT", "") or "").strip() or None
        _kconfig.load_kube_config_from_dict(cfg, context=context, client_configuration=api.configuration)
        code = _kclient.VersionApi(api).get_code(_request_timeout=_TIMEOUT_S)
        ver = getattr(code, "git_version", "") or ""
        return OK, (f"cluster reachable ({ver})" if ver else "cluster /version ok")
    except Exception as e:  # noqa: BLE001 — fail-closed; never leak the kubeconfig
        return FAIL, f"Kubernetes check failed: {type(e).__name__}"


# name → probe. A secret NOT listed here has no live check (verdict = unknown, "no live check").
_PROBES: "dict[str, Callable[[str, SecretStore, dict], tuple[str, str]]]" = {
    "ANTHROPIC_API_KEY": _probe_anthropic,
    "GITHUB_TOKEN": _probe_github,
    "MISTRAL_API_KEY": _probe_mistral,
    "OPENAI_API_KEY": _probe_openai,
    "PERPLEXITY_API_KEY": _probe_perplexity,
    "ELEVENLABS_API_KEY": _probe_elevenlabs,
    "AZURE_OPENAI_API_KEY": _probe_azure_openai,
    "AWS_ACCESS_KEY_ID": _probe_aws,
    "AZURE_CLIENT_SECRET": _probe_azure,
    "GOOGLE_APPLICATION_CREDENTIALS_JSON": _probe_gcp,
    "KUBECONFIG_CONTENT": _probe_kubernetes,
}


def has_probe(name: str) -> bool:
    return name in _PROBES


def _probe_ctx() -> dict:
    """NON-secret companion config the probes read (endpoints / regions / ids) — from the process env only."""
    return {k: os.environ.get(k, "") for k in
            ("AZURE_OPENAI_ENDPOINT", "CRUCIBLE_BEDROCK_REGION", "AWS_REGION",
             "CRUCIBLE_AWS_ENDPOINT_URL", "AWS_ROLE_ARN",
             "AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_SUBSCRIPTION_ID",
             "GOOGLE_CLOUD_PROJECT", "KUBE_CONTEXT")}


# --- verdict cache (0600, value-free) --------------------------------------------------------------

def _read_cache() -> dict:
    try:
        data = json.loads(_HEALTH_CACHE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_cache(name: str, rec: dict) -> None:
    data = _read_cache()
    data[str(name)] = rec
    _HEALTH_CACHE.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(_HEALTH_CACHE), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    try:
        os.chmod(str(_HEALTH_CACHE), 0o600)      # unconditional 0600 even if the file pre-existed
    except OSError:
        pass


def cached_health(name: str) -> Optional[dict]:
    """The last cached verdict for ``name`` ({status, reason, checked_at}) or None if never checked."""
    rec = _read_cache().get(str(name))
    return rec if isinstance(rec, dict) else None


# --- the public probe runner -----------------------------------------------------------------------

def check_secret_health(name: str, *, store: Optional[SecretStore] = None) -> dict:
    """Run the live probe for one secret and cache the verdict. Returns {name, status, reason, checked_at}.
    Never returns/logs the secret value. An unset secret ⇒ unknown; a secret with no probe ⇒ unknown."""
    store = store or SecretStore()
    value = str(store.get(name) or "")
    if not value:
        status, reason = UNKNOWN, "not set"
    elif name not in _PROBES:
        status, reason = UNKNOWN, "no live check available for this secret"
    else:
        try:
            status, reason = _PROBES[name](value, store, _probe_ctx())
        except Exception as e:  # noqa: BLE001 — fail-closed; a probe bug is never a green key
            status, reason = FAIL, f"probe error: {type(e).__name__}"
    rec = {"status": status, "reason": reason, "checked_at": int(time.time())}
    _write_cache(name, rec)
    return {"name": name, **rec}


def check_all(names, *, store: Optional[SecretStore] = None) -> list:
    """Probe every SET secret in ``names`` (skip the unset — they stay 'not set'); return the verdict list."""
    store = store or SecretStore()
    out = []
    for n in names:
        if str(store.get(n) or ""):
            out.append(check_secret_health(n, store=store))
    return out
