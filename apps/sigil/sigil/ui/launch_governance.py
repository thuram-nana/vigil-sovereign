"""launch_governance — provision the per-launch owner-signed OFFENSE_GOVERNANCE_ROLE delegation (K4-5d, A).

When a customer launch is started (the owner-signed ``CreditLaunchLease`` is published to the seam), the
keyless offense worker will — after the run — cross the run's confirmed FACTs and emit a governance-signed
``EngagementCompletion`` to settle the lease. BOTH of those are verified by the SOVEREIGN drains
(``inbound.finding_receiver`` / ``inbound.completion_spool``) against an OWNER-SIGNED
``OFFENSE_GOVERNANCE_ROLE`` delegation scoped to this launch's ``cust_`` slug. This module mints that
delegation at launch time — the one sovereign (owner-keyed) half of the completion seam.

The offense-governance signer is the STABLE per-``base_dir`` key (``governance_identity`` — one key across
runs, so one delegation covers it durably). The owner delegates to its PUBLIC key only; the private key is
used solely by the keyless worker (``jobs.engage_worker``) to sign. The delegation's ``not_after`` is set to
the lease window end plus a settle grace, so it lapses with the launch — the K4-5b per-drain re-verify then
stops settling under a stale delegation (defence in depth; the ``cust_`` scope is the tight bound).

SOVEREIGN plane: holds the owner key (``delegate_offense_governance`` is ``governor.identity``); imports the
vigil_core-only ``governance_identity`` seam for the gov PUBKEY (never ``framework``/offense — the heavy
``live.wiring`` is deliberately NOT imported). ``assert_no_offense`` at import enforces it. MOCK-FIRST note:
in the shared-``base_dir`` dev model the sovereign step loads-or-creates the gov key under ``base_dir`` and
uses only its pubkey; a production plane-split would publish the gov pubkey to the sovereign side instead.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Optional

from ..reuse import assert_no_offense

assert_no_offense()  # SOVEREIGN: minting the owner delegation must never pull the offense engine (FATAL-2)

#: the per-slug delegation filename (the sovereign drains load it as a DelegationCert JSON)
LAUNCH_GOVERNANCE_DELEG_FILE = "offense-governance.deleg.json"

#: a settle grace added to the lease window end so the delegation outlives run + settle latency (bounded, not
#: indefinite — the K4-5b per-drain re-verify stops settling once it lapses).
LAUNCH_DELEGATION_GRACE_SECONDS = 7 * 24 * 3600

_SAFE_SLUG = re.compile(r"^cust_[0-9a-f]{1,64}$")


def _deleg_path(base: str, slug: str) -> Path:
    return Path(base) / slug / LAUNCH_GOVERNANCE_DELEG_FILE


def provision_launch_governance(*, slug: str, not_after: int, base_dir: Optional[str] = None,
                                owner_key: Any = None, vault: Any = None) -> str:
    """Mint + persist the per-``slug`` owner-signed OFFENSE_GOVERNANCE_ROLE delegation over the stable
    offense-governance key, scoped to ``slug`` with the given ``not_after`` (unix seconds). Returns the written
    delegation path. Idempotent per slug (re-provisioning re-writes a fresh delegation over the same key).
    Fail-closed: an unsafe slug or a missing owner key raises, so a launch never publishes a delegation it
    cannot bind. ``base_dir`` defaults to the same seam base the lease is written to (READ==WRITE parity)."""
    if not _SAFE_SLUG.match(str(slug)):
        raise ValueError(f"refusing to provision a launch delegation for an unsafe slug: {slug!r}")
    from .target_authorization import _base_dir
    from ..governor.identity import ensure_owner_keypair
    from vigil_core import AuthorizerKey
    from vigil_integration.live.governance_identity import (
        DEFAULT_GOVERNANCE_KEY_FILE, GOVERNANCE_KEY_ID, load_or_create_governance_keypair,
    )

    base = str(base_dir) if base_dir is not None else _base_dir()
    owner = owner_key if owner_key is not None else ensure_owner_keypair()
    if owner is None:
        raise ValueError("provisioning a launch delegation requires the owner key")
    gov_kp = load_or_create_governance_keypair(
        path=str(Path(base) / DEFAULT_GOVERNANCE_KEY_FILE), vault=vault)
    from ..governor.identity import delegate_offense_governance
    cert = delegate_offense_governance(
        owner, scope=str(slug), not_after=int(not_after), threshold=1,
        authorizers=[AuthorizerKey(key_id=GOVERNANCE_KEY_ID, name=GOVERNANCE_KEY_ID,
                                   public_key_b64=gov_kp.public_key_b64)])
    path = _deleg_path(base, str(slug))
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(cert.model_dump_json(), encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)        # atomic publish (never a half-written delegation the drain might read)
    return str(path)
