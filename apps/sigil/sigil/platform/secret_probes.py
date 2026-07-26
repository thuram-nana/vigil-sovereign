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

from ..config import SIGIL_HOME
from .secrets import SecretStore

_TIMEOUT_S = 8.0
_HEALTH_CACHE: Path = SIGIL_HOME / "secret-health.json"     # 0600, value-free verdict cache

OK, FAIL, UNKNOWN = "ok", "fail", "unknown"


# --- HTTP core (host-pinned, minimal, fail-closed) --------------------------------------------------

def _http_probe(url: str, headers: dict, *, ok_codes: tuple = (200,)) -> "tuple[str, str]":
    """A minimal authenticated GET to a PINNED provider URL. Sends only the auth header(s) — no target data.
    2xx ⇒ ok; 401/403 ⇒ fail (bad/expired key); other status/network/timeout ⇒ fail. Never raises."""
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:   # noqa: S310 — https, host-pinned below
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


def _require_https(url: str) -> bool:
    return isinstance(url, str) and url.startswith("https://")


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
    # SSRF guard: the endpoint is operator-supplied, so pin it to a real Azure OpenAI host over https.
    if not _require_https(endpoint) or ".openai.azure.com" not in endpoint:
        return FAIL, "endpoint must be https://<resource>.openai.azure.com"
    return _http_probe(f"{endpoint}/openai/models?api-version=2024-02-01", {"api-key": value})


def _probe_aws(value: str, store: SecretStore, ctx: dict) -> "tuple[str, str]":
    # value = AWS_ACCESS_KEY_ID; the companion secret is read from the store (never passed via ctx). boto3 is
    # optional — absent ⇒ unknown (honest), never a false ok. STS get-caller-identity validates without
    # touching Bedrock or any resource.
    secret = str(store.get("AWS_SECRET_ACCESS_KEY") or "").strip()
    if not secret:
        return UNKNOWN, "also set AWS_SECRET_ACCESS_KEY to validate"
    region = str(ctx.get("CRUCIBLE_BEDROCK_REGION", "") or ctx.get("AWS_REGION", "") or "us-east-1")
    try:
        import boto3  # optional dependency
    except Exception:  # noqa: BLE001
        return UNKNOWN, "install boto3 to validate AWS credentials"
    try:
        sts = boto3.client("sts", aws_access_key_id=value, aws_secret_access_key=secret, region_name=region)
        ident = sts.get_caller_identity()
        acct = str(ident.get("Account", "")) if isinstance(ident, dict) else ""
        return OK, f"STS ok (account {acct[:6]}…)" if acct else (OK, "STS get-caller-identity ok")
    except Exception as e:  # noqa: BLE001 — fail-closed; never leak the secret in the message
        return FAIL, f"AWS rejected credentials: {type(e).__name__}"


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
}


def has_probe(name: str) -> bool:
    return name in _PROBES


def _probe_ctx() -> dict:
    """NON-secret companion config the probes read (endpoints / regions) — from the process env only."""
    return {k: os.environ.get(k, "") for k in
            ("AZURE_OPENAI_ENDPOINT", "CRUCIBLE_BEDROCK_REGION", "AWS_REGION")}


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
