"""Sovereign entry for a customer-cloud-posture run: turn a VERIFIED connection into a SHORT-LIVED read-only session
the engine collector consumes — behind the SAME owner go-live gate as any live customer engagement.

Doctrine held here (see cloud_connect.py / the audit):
  * A connected cloud account authorizes NOTHING. This resolves the owner-signed grant, enforces the owner gate, and
    re-mints a short-lived read-only session. The engine still runs every collector API call under
    ``build_offense_gate`` -> ``conjunctive_decide``; this is the mint + owner-gate step, not an authorization.
  * FATAL-2 boundary: the grant read and the credential mint stay SOVEREIGN; only the ``MintedSession`` (plain data)
    crosses to the offense plane. This module imports no framework/strix and no engine code.
  * FAIL-CLOSED, in strict order: default-deny grant -> owner gate -> re-mintable provider -> mint.

Cloudflare is refused on purpose: a Cloudflare grant stores only the token's PUBLIC id + a sha256 (the secret bearer
token is never kept), so a posture run cannot re-mint from the grant — it supplies a fresh customer token per run
instead. ``assume_target`` returns a NON-None target for Cloudflare (cloudflare is verifiable), which is exactly the
seam trap this module closes before any mint is attempted.
"""
from __future__ import annotations

from typing import Any, Callable, Optional

from vigil_core.cloud_session import MINTABLE_PROVIDERS, MintedSession
from vigil_core.posture import customer_prod_execution_enabled

from ..reuse import assert_no_offense

# FATAL-2 tripwire (the same import-time guard every sovereign governor sibling arms): refuse to be loaded in
# a process that has imported the offense engine (framework.*/strix.*). The grant read + credential mint stay
# sovereign; only the MintedSession (plain data) ever crosses to the offense plane.
assert_no_offense()


class PostureDenied(Exception):
    """A customer-cloud-posture session was refused (fail-closed). The message is customer-safe (no internals)."""


def open_posture_session(*, registry: Any, mint_fetcher: "Callable[[str], Any]",
                         org_id: str, provider: str, account_id: str, now: float,
                         env: "Optional[dict]" = None) -> MintedSession:
    """Resolve a verified connection into a short-lived read-only ``MintedSession`` for a posture run, or raise
    ``PostureDenied``.

    ``registry`` is a ``CloudConnectRegistry`` (build it ``owner_key=None`` — a pure read; the owner key is never
    touched). ``mint_fetcher(provider)`` returns the trusted sovereign fetcher for that provider (the same objects the
    connect flow uses), or ``None`` when that provider's connector is not provisioned.
    """
    prov = str(provider or "").strip().lower()

    # 1. default-deny grant: no ACTIVE, UNEXPIRED, owner-signed grant for exactly (org, provider, account) -> refuse.
    target = registry.assume_target(org_id, prov, account_id, now=now)
    if target is None:
        raise PostureDenied("no active read-only connection for this account — connect it (or reconnect if the grant "
                            "expired) before requesting an assessment")

    # 2. owner gate: a LIVE customer cloud account is the live-customer-target class; same go-live bar (default OFF).
    if not customer_prod_execution_enabled(env):
        raise PostureDenied("customer cloud assessments are not enabled on this deployment")

    # 3. re-mintable provider. Cloudflare's secret is never stored -> a stored grant cannot re-credential it.
    if prov == "cloudflare":
        raise PostureDenied("a Cloudflare assessment needs a fresh read-only API token for this run — the connect "
                            "token is verified and never stored, so it cannot be reused")
    if prov not in MINTABLE_PROVIDERS:
        raise PostureDenied(f"cloud assessment for {prov!r} is not available yet")

    fetcher = mint_fetcher(prov)
    if fetcher is None:
        raise PostureDenied(f"the {prov} connector is not provisioned on this deployment")

    # 4. mint a fresh short-lived read-only session under VIGIL's connector identity, scoped to the customer's role.
    try:
        session = fetcher.mint_read_only_session(target, now=now)
    except Exception as e:  # noqa: BLE001 — the fetcher's CloudFetchError str() is customer-safe (.detail is audit-only)
        safe = str(e) if hasattr(e, "detail") else "the assessment session could not be established — try again shortly"
        raise PostureDenied(safe) from None

    if not isinstance(session, MintedSession) or not session.has_credential() or not session.is_fresh(now):
        raise PostureDenied("the assessment session could not be established — reconnect the account and try again")
    return session
