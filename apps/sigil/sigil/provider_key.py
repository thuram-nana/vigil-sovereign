"""The ONE provider key the sovereign model gateway sends upstream — from the environment, or from AWS SSM.

Default (``VIGIL_ANTHROPIC_KEY_SSM_PARAMETER`` unset): the key is ``SIGIL_ANTHROPIC_API_KEY`` or
``ANTHROPIC_API_KEY``, exactly as before.

With ``VIGIL_ANTHROPIC_KEY_SSM_PARAMETER`` set to a parameter name (e.g. ``/vigil/anthropic-api-key``) the key is read
from that AWS SSM Parameter Store SecureString, in ``VIGIL_AWS_REGION``, with the instance role's credentials, through
the ``aws`` CLI (:mod:`vigil_core.aws_ssm`). SSM is then the ONLY source: a key also present in the environment or in
``sigil.env`` is ignored, and any failure (no region, no CLI, no permission, a plain String parameter, an unusable
value) refuses with :class:`ProviderKeyError` — the gateway does not start and metered runs fail closed; nothing is
ever billed against a key the owner did not put in SSM.

The key is read once, when the gateway starts (rotate it in SSM, then restart the process that runs the gateway).
It is never logged, never on a process's argv, and never in an error message.

SOVEREIGN plane: imports ``vigil_core`` only.
"""
from __future__ import annotations

import os
from typing import Mapping, Optional

from .reuse import assert_no_offense

assert_no_offense()

from vigil_core import model_metering as _mm  # noqa: E402
from vigil_core.aws_ssm import SsmParameterError, read_secure_string  # noqa: E402
from vigil_core.kek_backends import AwsRunner  # noqa: E402

SSM_PARAMETER_ENV = "VIGIL_ANTHROPIC_KEY_SSM_PARAMETER"
REGION_ENV = "VIGIL_AWS_REGION"
_ENV_KEYS = ("SIGIL_ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY")


class ProviderKeyError(ValueError):
    """The provider key could not be obtained (fail-closed). The message never contains a key."""


def ssm_parameter(env: Optional[Mapping[str, str]] = None) -> str:
    """The configured SSM parameter name, or ``""`` when the key comes from the environment (the default)."""
    e = os.environ if env is None else env
    return (e.get(SSM_PARAMETER_ENV) or "").strip()


def key_source(env: Optional[Mapping[str, str]] = None) -> str:
    """Where the gateway's key comes from — ``"ssm"``, ``"env"``, or ``""`` (no key configured). Never the value."""
    e = os.environ if env is None else env
    if ssm_parameter(e):
        return "ssm"
    return "env" if any((e.get(k) or "").strip() for k in _ENV_KEYS) else ""


def provider_key(env: Optional[Mapping[str, str]] = None, *, runner: Optional[AwsRunner] = None) -> str:
    """The provider key. Raises :class:`ProviderKeyError` when it cannot be obtained (see the module docstring)."""
    e = os.environ if env is None else env
    name = ssm_parameter(e)
    if not name:
        key = (e.get("SIGIL_ANTHROPIC_API_KEY") or e.get("ANTHROPIC_API_KEY") or "").strip()
        if not key:
            raise ProviderKeyError("the model gateway needs the provider key (SIGIL_ANTHROPIC_API_KEY or "
                                   "ANTHROPIC_API_KEY)")
        return key
    region = (e.get(REGION_ENV) or "").strip()
    try:
        return read_secure_string(region, name, runner=runner)
    except SsmParameterError as exc:          # its message names the parameter only, never the CLI's output
        raise ProviderKeyError(f"the model gateway's provider key ({SSM_PARAMETER_ENV}): {exc}") from None


def pool_accounts(env: Optional[Mapping[str, str]] = None) -> "list[dict[str, str]]":
    """PRICING G1 — the provider-account POOL, with each account's KEY resolved. Reads the ``VIGIL_GATEWAY_POOL``
    spec (``vigil_core.model_metering.gateway_pool_spec``, which validates the shape), then resolves each account's
    ``key_env`` to its actual key from this environment. Returns a list of
    ``{"id", "key", "workspace_id", "upstream", "kind"}``; ``[]`` when the pool is unset (the gateway then runs the
    single default account from :func:`provider_key`). Fail-closed: a ``key_env`` that names no non-empty variable
    raises :class:`ProviderKeyError`, so the gateway never starts an account with no key. The key VALUES are never
    logged or put in an error message."""
    e = os.environ if env is None else env
    try:
        spec = _mm.gateway_pool_spec(e)
    except _mm.MeteringError as exc:
        raise ProviderKeyError(str(exc)) from None
    out: "list[dict[str, str]]" = []
    for account in spec:
        key = (e.get(account["key_env"]) or "").strip()
        if not key:
            raise ProviderKeyError(f"the G1 pool account {account['id']!r} has no key: its key_env "
                                   f"{account['key_env']!r} is empty or unset")
        out.append({"id": account["id"], "key": key, "workspace_id": account["workspace_id"],
                    "upstream": account["upstream"], "kind": account["kind"]})
    return out
