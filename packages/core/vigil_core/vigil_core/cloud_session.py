"""vigil_core.cloud_session — a SHORT-LIVED, read-only cloud session RE-MINTED from a verified cloud-connect grant,
for a later customer-cloud-posture collector.

This object is DATA, not authority. Holding a ``MintedSession`` authorizes NOTHING: the posture run that consumes it
is a distinct engagement that must itself pass the gate chain (``build_offense_gate`` -> ``conjunctive_decide``) and
the ``VIGIL_CUSTOMER_PROD_EXECUTION`` owner gate. The secret fields are kept out of ``repr`` so a session never
renders in a log, trace or error; it is handed to the collector IN-PROCESS, never via argv / spine / env.

It lives in ``vigil_core`` (the shared integrity substrate) ON PURPOSE: the SOVEREIGN mint side (``apps/sigil``,
``ui.cloud_fetch.*.mint_read_only_session``) and the ENGINE collector side (``engine/crucible`` sensors) share one
shape WITHOUT the engine importing the governor/ui — the FATAL-2 boundary. The grant read and the credential mint
stay sovereign; only this plain data object crosses to the offense plane.

Cloudflare is deliberately absent: a Cloudflare grant stores only the token's PUBLIC id + a sha256 (the secret
bearer token is never kept), so a Cloudflare posture run CANNOT re-mint from the grant — it supplies a fresh
customer token per run instead (never stored), and a collector must refuse a stored-grant-only Cloudflare target.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field

#: The providers a session can be re-minted for from a stored grant (Cloudflare is excluded by design — see above).
MINTABLE_PROVIDERS = ("aws", "gcp", "azure")


@dataclass(frozen=True)
class MintedSession:
    """A short-lived read-only session scoped to exactly one customer cloud account/project/tenant.

    * AWS — ``access_key_id`` / ``secret_access_key`` / ``session_token`` (STS temporary credentials from a fresh
      ``sts:AssumeRole`` of the customer's read-only role under VIGIL's connector principal).
    * GCP / Azure — ``bearer_token`` (a short-lived OAuth2 / AAD access token).

    ``expires_at`` is epoch seconds; a collector MUST refuse to start a run past it (default-deny).
    """

    provider: str
    account_id: str
    expires_at: float = 0.0
    region: str = ""
    access_key_id: str = field(default="", repr=False)
    secret_access_key: str = field(default="", repr=False)
    session_token: str = field(default="", repr=False)
    bearer_token: str = field(default="", repr=False)

    def __post_init__(self) -> None:
        if self.provider not in MINTABLE_PROVIDERS:
            raise ValueError(f"MintedSession.provider must be one of {MINTABLE_PROVIDERS}, not {self.provider!r}")
        if not self.account_id:
            raise ValueError("MintedSession.account_id is required")

    def is_fresh(self, now: float) -> bool:
        """True iff the session has not expired at ``now``. Default-deny: a non-positive expiry — or a
        non-finite ``expires_at`` / ``now`` (NaN, ±inf) — is NEVER fresh. An unbounded or undefined lifetime
        cannot satisfy the time-boxed read-only contract, so it fails closed rather than reading as 'fresh
        forever'."""
        exp = float(self.expires_at)
        n = float(now)
        if not (math.isfinite(exp) and math.isfinite(n)):
            return False
        return exp > 0.0 and n < exp

    def has_credential(self) -> bool:
        """True iff the session actually carries a usable credential for its provider (fail-closed check a collector
        runs before any API call — a session minted without a secret is inert, never 'clean')."""
        if self.provider == "aws":
            return bool(self.access_key_id and self.secret_access_key and self.session_token)
        return bool(self.bearer_token)
