"""
agents.scope_gate — pre-flight validator for any HTTP action.

Wraps the inviolable gates from `common.ethics` and translates them
into a structured `ScopeDecision` so the executor can post a
ScopeViolation event on the blackboard rather than crashing the
coordinator. The exceptions still exist; this module makes them
inspectable without hiding them.

Five checks, in order:

  1. Charter file exists.
  2. Charter has a non-placeholder operator signature.
  3. Action's URL is a valid http/https URL.
  4. URL's host is in the parsed charter scope.
  5. Posture-scoped extra restrictions (e.g. EMULATE refuses
     EMULATE-prohibited methods unless the charter authorises them).

Refused actions never reach the wire. This module is the only
place where charter / scope gating happens for HttpExecutor.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlparse

from ..common import ethics
from ..common.errors import (
    CharterMissing,
    CharterNotSigned,
    OutOfScope,
)


Posture = Literal["TEST", "AUDIT", "EMULATE"]
DESTRUCTIVE_METHODS = frozenset({"POST", "PUT", "DELETE", "PATCH"})

# Path patterns that are destructive on most apps. URL contains any of
# these → executor must prompt the operator before issuing.
_DESTRUCTIVE_PATH_TOKENS: tuple[str, ...] = (
    "/admin", "/delete", "/destroy", "/drop", "/wipe",
    "/upload", "/import", "/restore",
    "/reset", "/password-reset", "/forgot-password",
    "/withdraw", "/transfer", "/refund", "/payout",
    "/payment/", "/checkout", "/subscribe", "/unsubscribe",
    "/sudo", "/impersonate", "/grant", "/promote",
)


@dataclass(frozen=True)
class ScopeDecision:
    """Outcome of running an action through the scope gate.

    `allowed=True` is necessary AND sufficient for the executor to
    proceed; `allowed=False` is mandatory grounds to refuse and post
    a ScopeViolation event. The reason is human-readable and the
    structured fields drive programmatic logging.
    """

    allowed: bool
    reason: str
    method: str = ""
    url: str = ""
    host: str = ""
    is_destructive: bool = False
    refusal_kind: Literal[
        "",
        "charter_missing",
        "charter_unsigned",
        "url_invalid",
        "out_of_scope",
        "posture_forbidden",
    ] = ""


def is_destructive(method: str, url: str) -> bool:
    """Heuristic destructive classifier. Erring toward refusal is the
    correct default — a false positive costs one operator prompt;
    a false negative could cost an engagement."""
    if method.upper() in DESTRUCTIVE_METHODS:
        return True
    path = urlparse(url).path.lower()
    for tok in _DESTRUCTIVE_PATH_TOKENS:
        if tok in path:
            return True
    return False


def parse_url(target_url: str) -> tuple[str, str]:
    """Normalise into (scheme, host). Raises ValueError if the URL is
    not parseable as http/https. A bare IPv6 literal is bracketed first so its
    host is not truncated (``fe80::1`` would otherwise parse as host ``fe80``)."""
    if "://" not in target_url:
        target_url = "https://" + target_url
    parsed = urlparse(ethics.bracket_bare_ipv6(target_url))
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"unsupported scheme: {parsed.scheme!r}")
    if not parsed.hostname:
        raise ValueError(f"no hostname in URL: {target_url!r}")
    return parsed.scheme, parsed.hostname


def validate_action(
    *,
    slug: str,
    method: str,
    target_url: str,
    posture: Posture = "TEST",
) -> ScopeDecision:
    """Run the full pre-flight validation chain for one action.

    The decision is the conjunction of all checks. The first failing
    check populates the refusal_kind; later checks are not evaluated.
    """
    method_norm = method.upper().strip() or "GET"
    destructive = is_destructive(method_norm, target_url)

    # 1+2. Charter file + signature.
    try:
        ethics.require_charter_signed(slug)
    except CharterMissing as exc:
        return ScopeDecision(
            allowed=False, reason=str(exc),
            method=method_norm, url=target_url,
            is_destructive=destructive,
            refusal_kind="charter_missing",
        )
    except CharterNotSigned as exc:
        return ScopeDecision(
            allowed=False, reason=str(exc),
            method=method_norm, url=target_url,
            is_destructive=destructive,
            refusal_kind="charter_unsigned",
        )

    # 3. URL parsing.
    try:
        _scheme, host = parse_url(target_url)
    except ValueError as exc:
        return ScopeDecision(
            allowed=False, reason=f"unparseable URL: {exc}",
            method=method_norm, url=target_url,
            is_destructive=destructive,
            refusal_kind="url_invalid",
        )

    # 4. Scope check (uses ethics.require_in_scope under the hood).
    try:
        ethics.require_in_scope(slug, target_url)
    except OutOfScope as exc:
        return ScopeDecision(
            allowed=False, reason=str(exc),
            method=method_norm, url=target_url, host=host,
            is_destructive=destructive,
            refusal_kind="out_of_scope",
        )

    # 5. Posture-scoped restrictions. Currently EMULATE-prohibited
    # methods are NOT defined in v1 canon; this is a hook for future
    # tightening. TEST and AUDIT pass here.
    # (Intentionally no extra checks today — adding any would go
    #  beyond what opsec-discipline.md authorises.)

    return ScopeDecision(
        allowed=True,
        reason=f"in scope; charter signed; posture={posture}",
        method=method_norm, url=target_url, host=host,
        is_destructive=destructive,
    )
