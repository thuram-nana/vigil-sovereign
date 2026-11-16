"""metered — is THIS engine process running a METERED customer run? (PRICING M1c-2, design §5.1)

A metered customer run never holds the provider key: the sovereign plane mints an owner-signed model grant for its
launch, and the offense worker scopes it into the run's environment — ``VIGIL_MODEL_GRANT`` (the grant token: a
bearer credential the gateway spends against the launch's prepaid allowance) and ``ANTHROPIC_BASE_URL`` (the loopback
model gateway in the sovereign cockpit). While ``VIGIL_MODEL_GRANT`` is set, every model call of the engine must go
through that gateway with that token, or not happen at all:

  * the Anthropic backend sends the grant to the gateway only — never the persisted provider key, never another host
    (:func:`gateway_base` is ``None`` unless the base URL is exactly a loopback gateway URL, and the backend then
    refuses to build a client);
  * no other backend is selected, constructed or failed over to (Bedrock / Vertex / Mistral / Azure / self-hosted /
    Ollama / Claude Code / dry-run would each reach a model OUTSIDE the meter, or fabricate output for a paid run);
  * model-tier routing is off (the gateway refuses every model but the grant's).

With ``VIGIL_MODEL_GRANT`` unset (every flat run, every operator run) nothing here changes any behaviour: each guard
asks :func:`metered_mode` first. Stdlib only at import (FATAL-2 clean); ``vigil_core`` is read lazily, and a metered
run without it fails closed.
"""

from __future__ import annotations

import os
from typing import Optional

GRANT_ENV = "VIGIL_MODEL_GRANT"
BASE_URL_ENV = "ANTHROPIC_BASE_URL"


def model_grant() -> Optional[str]:
    """The grant token this run spends through the gateway (``VIGIL_MODEL_GRANT``), or None for an unmetered run."""
    token = (os.environ.get(GRANT_ENV) or "").strip()
    return token or None


def metered_mode() -> bool:
    """True while this process runs a metered customer run (a model grant is in its environment)."""
    return model_grant() is not None


def gateway_base() -> Optional[str]:
    """The model gateway's base URL (``ANTHROPIC_BASE_URL``) when it is exactly a loopback gateway URL
    (``vigil_core.model_grant.gateway_url``: ``http://<loopback>:<port>``), else None — the grant is a bearer
    token, so a metered client is never pointed anywhere else. None too when ``vigil_core`` cannot be imported."""
    try:
        from vigil_core.model_grant import gateway_url
    except ImportError:
        return None
    return gateway_url(os.environ.get(BASE_URL_ENV))


def stop_reason(exc: BaseException) -> Optional[str]:
    """Why the model gateway STOPPED this run, from the refusal's ``x-vigil-stop`` header
    (``vigil_core.model_grant.STOP_HEADER``), or None (not a gateway stop, or no ``vigil_core``). Never raises."""
    try:
        from vigil_core.model_grant import STOP_HEADER
        headers = getattr(getattr(exc, "response", None), "headers", None)
        if headers is None:
            return None
        value = headers.get(STOP_HEADER)
    except Exception:  # noqa: BLE001 — a classifier must never break the error path it inspects
        return None
    if value is None:
        return None
    return str(value).strip() or None
