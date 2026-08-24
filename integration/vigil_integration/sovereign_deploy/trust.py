"""
sovereign_deploy.trust — the trust anchor is CUSTOMER-controlled; there is NO vendor kill switch (W13-8).

Property 2 of the sovereign / air-gapped deployment slice (#501): whether a deployment is OPERATIONAL is a
function of the CUSTOMER's own trust anchor verifying the CUSTOMER's own bundle — and NOTHING a vendor holds
can disable it. No hard-coded vendor public key, no phone-home licence/entitlement check, no remote
revocation authority sits on the operational path.

FACADE, NOT A SECOND MECHANISM. The trust anchor is the same :class:`vigil_core.models.TrustRoot` the signed
build manifest already verifies against, loaded from a file the CUSTOMER controls and ships inside their
bundle (``sovereign_deploy.bundle``). This module adds no crypto; it states — and makes falsifiable — the
SOVEREIGNTY invariant over that reused mechanism.

THE INVARIANT (falsifiable, pinned by tests).

  * :func:`deployment_operational` is a PURE function of the bundle's verification result under the CUSTOMER
    trust root. It takes NO vendor input of any kind. So a would-be vendor "revocation" / "kill" signal —
    an env var, a flag, a remote call — cannot change its verdict: there is nowhere to feed one in.
  * :data:`SOLE_OPERATIONAL_AUTHORITY` names the ONE authority that governs operation
    (``"customer-trust-root"``). :func:`operational_authorities` returns exactly the customer trust root's
    own authoriser key_ids — the set of keys that gate this deployment — and NEVER a vendor key.
  * The negative control that proves the invariant is not vacuous: a deployment whose CUSTOMER bundle fails
    to verify (tampered / unsigned / signed by a NON-customer key) is NOT operational. The customer's own
    keys genuinely gate operation, so "customer-controlled" is a real dependency, not a no-op.

The straw-man a real kill switch would look like (``customer_ok AND vendor_allows``) lives only in the test,
so the contrast — vendor_allows=False leaves :func:`deployment_operational` operational while the straw-man
goes dark — is demonstrated, not asserted.

Import-clean (FATAL-2): stdlib + ``vigil_core`` + the sibling ``bundle`` facade only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from vigil_core.models import TrustRoot

from .bundle import BundleInstallResult

__all__ = [
    "SOLE_OPERATIONAL_AUTHORITY",
    "OperationalStatus",
    "deployment_operational",
    "operational_authorities",
    "vendor_key_is_powerless",
]

#: The ONE authority that governs whether a sovereign deployment operates. It is the customer's own trust
#: root — never a vendor. Stated here as a single, testable constant so a reviewer can confirm no second
#: (vendor) authority was ever introduced.
SOLE_OPERATIONAL_AUTHORITY: str = "customer-trust-root"


@dataclass(frozen=True)
class OperationalStatus:
    """Whether the deployment may operate, and under WHOSE authority. ``authority`` is always
    :data:`SOLE_OPERATIONAL_AUTHORITY` — the customer's trust root — so the record itself shows no vendor
    authority was consulted."""

    operational: bool
    authority: str
    reason: str
    build_id: str = ""

    def to_dict(self) -> dict:
        return {
            "operational": self.operational,
            "authority": self.authority,
            "reason": self.reason,
            "build_id": self.build_id,
        }


def deployment_operational(bundle_result: BundleInstallResult) -> OperationalStatus:
    """Decide whether the deployment may operate — from the CUSTOMER bundle's verification result ALONE.

    Operational IFF ``bundle_result.installed`` (the bundle VERIFIED under the pinned customer trust root and
    every artifact matches). This function DELIBERATELY accepts no vendor argument, reads no vendor env var,
    and makes no remote call — there is no lever by which a vendor could flip the verdict. That absence is
    the "no vendor kill switch" property; it is enforced structurally (nothing to feed a kill signal into),
    not by a runtime check that could itself be a hidden dependency.

    Total: a non-``BundleInstallResult`` (or one that does not verify) is simply NOT operational — never a
    crash, never an optimistic default."""
    installed = bool(getattr(bundle_result, "installed", False))
    build_id = str(getattr(bundle_result, "build_id", "") or "")
    if installed:
        return OperationalStatus(
            operational=True,
            authority=SOLE_OPERATIONAL_AUTHORITY,
            reason="the customer-signed bundle verifies under the customer's own trust anchor",
            build_id=build_id,
        )
    detail = str(getattr(bundle_result, "detail", "") or "bundle did not verify under the customer trust root")
    return OperationalStatus(
        operational=False,
        authority=SOLE_OPERATIONAL_AUTHORITY,
        reason=f"the customer bundle does not verify under the customer trust anchor: {detail}",
        build_id=build_id,
    )


def operational_authorities(trust_root: TrustRoot) -> "tuple[str, ...]":
    """The key_ids that GATE this deployment's operation — exactly the CUSTOMER trust root's own authorisers,
    and nothing else. A reviewer/test compares this against the set of vendor-held key_ids and finds them
    disjoint: no vendor key is among the operational authorities. Total: a malformed trust root yields ``()``."""
    try:
        return tuple(a.key_id for a in trust_root.authorizers)
    except Exception:  # noqa: BLE001 — a malformed trust root gates nothing here (its verification fails elsewhere)
        return ()


def vendor_key_is_powerless(trust_root: TrustRoot, vendor_key_ids: Iterable[str]) -> bool:
    """True IFF NONE of ``vendor_key_ids`` is among the operational authorities of ``trust_root`` — i.e. a
    vendor holds no key that participates in the authority that gates this deployment. This is the crisp,
    falsifiable statement of "no vendor-held anchor can disable a deployment": a customer trust root that
    contains no vendor key returns True; the moment a vendor key appeared in the customer's own authoriser
    set it would return False (and a test would catch it). Total on malformed input."""
    anchors = set(operational_authorities(trust_root))
    try:
        vendors = {str(v) for v in vendor_key_ids}
    except Exception:  # noqa: BLE001
        return True
    return anchors.isdisjoint(vendors)
