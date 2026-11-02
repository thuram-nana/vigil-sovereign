"""Slice E2/E3 — the customer-plane IdentityProvider seam.

A provisioner-side abstraction that unifies the customer authentication methods — password today, Google
OIDC (E2) and WebAuthn passkey (E3) next — behind one ``verify(...) -> CustomerIdentity`` contract, so the
Provisioner has a SINGLE login tail: ``finish_login(identity) -> {username, orgs}`` -> the keyless edge's
``custui._mint``. Mirrors the capability-light, injectable ``governor.billing.BillingProvider`` ABC.

DOCTRINE — identity != authority (the ``ui/oidc.py`` rule, made general). A provider proves WHO a request is;
it NEVER decides a role. ``CustomerIdentity`` therefore carries no role and no org. The Provisioner resolves
the username from the owner-signed ``CustomerRegistry`` and the role/orgs from the owner-signed ``OrgRegistry``
membership (``admit_customer``) — never from a claim or an assertion. A verified identity that maps to no
ACTIVE customer is REFUSED, mirroring the operator OIDC callback's "no owner-signed account -> refuse".

This module runs PROVISIONER-SIDE (the owner-key-holding process): ``verify()`` reads the sovereign
registries and, for OIDC, bears the client secret + the egress. The keyless customer edge never imports it —
it hops to the Provisioner. FATAL-2: sovereign-only, ``assert_no_offense()`` at import; no framework/strix.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Optional

from ..reuse import assert_no_offense

assert_no_offense()

# The customer authentication methods. A CustomerIdentity.method is exactly one of these.
METHOD_PASSWORD = "password"
METHOD_GOOGLE_OIDC = "google-oidc"
METHOD_PASSKEY = "passkey"
_METHODS = frozenset({METHOD_PASSWORD, METHOD_GOOGLE_OIDC, METHOD_PASSKEY})


class IdentityRefused(Exception):
    """A provider could not verify the presented credential (fail-closed). The Provisioner maps it to a
    generic denial, so the endpoint never distinguishes 'no such identity' from 'bad credential' to a caller
    (timing + response stay uniform, as the constant-time password decoy already ensures)."""


@dataclass(frozen=True)
class CustomerIdentity:
    """A provider-verified customer identity — proof of WHO, never a role/org.

    Exactly one resolution key is meaningful per method: ``email`` (password; and, pre-link, the OIDC email
    hint), the STABLE ``(federated_iss, federated_sub)`` pair (the OIDC binding), or ``credential_id``
    (passkey). ``email_verified`` is True ONLY when the method itself established mailbox control — a password
    customer proved it at signup; an OIDC identity must carry ``email_verified`` strictly true. The Provisioner
    turns this into ``{username, orgs}`` via ``finish_login``; nothing here is authority."""

    method: str
    email: Optional[str] = None
    email_verified: bool = False
    federated_iss: Optional[str] = None
    federated_sub: Optional[str] = None
    credential_id: Optional[str] = None

    def __post_init__(self) -> None:
        if self.method not in _METHODS:
            raise ValueError(f"unknown identity method {self.method!r}")


class IdentityProvider(ABC):
    """One customer authentication method. ``begin`` yields the start material the edge needs (an authorize
    URL for OIDC, a WebAuthn challenge for passkey, nothing for password); ``verify`` turns the presented
    response into a ``CustomerIdentity`` or raises ``IdentityRefused``. A small injectable adapter, like
    ``BillingProvider`` — pure verification, no owner key, no session mint (the Provisioner owns both)."""

    method: str = ""

    def begin(self, **ctx: Any) -> dict:
        """Start material for the edge. Default: nothing (password needs no begin step)."""
        return {}

    @abstractmethod
    def verify(self, **ctx: Any) -> CustomerIdentity:
        """Verify the presented credential; return the identity, or raise ``IdentityRefused`` (fail-closed).
        Returns identity ONLY — never a role; the Provisioner resolves authority downstream."""
        raise NotImplementedError


class PasswordIdentityProvider(IdentityProvider):
    """Email + password, wrapping the constant-time ``CustomerRegistry.verify_login`` (its scrypt decoy keeps
    an unknown email / passwordless customer timing-indistinguishable). ``customers`` is any object exposing
    ``verify_login(email, password) -> account | None`` — the owner-signed ``CustomerRegistry``."""

    method = METHOD_PASSWORD

    def __init__(self, customers: Any) -> None:
        self._customers = customers

    def verify(self, *, email: str, password: str, **_ctx: Any) -> CustomerIdentity:
        acct = self._customers.verify_login(email, password)
        if acct is None:
            raise IdentityRefused("invalid email or password")
        # Mailbox control was proven at signup (the single-use verify token); a password customer's email is
        # verified by construction.
        return CustomerIdentity(method=METHOD_PASSWORD, email=acct.email, email_verified=True)
