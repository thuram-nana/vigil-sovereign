"""target_classification — a target-class taxonomy + a registered-asset store where UNKNOWN is NEVER
AUTHORIZED (W13-4, #497).

Before this module, "authorized" was a single bit: a target was either in the charter scope or it was not.
That is not enough to *safely default* an unclassified target — a target the engagement has never heard of
looks exactly like an out-of-scope one to a boolean, and a boolean has no room to record WHAT a target is.
This module adds the missing dimension: every target resolves to a :class:`TargetClass`, and an
``UNKNOWN`` (unresolvable / never-classified) target is refused rather than defaulted to authorized.

Design constraints this module holds (the programme's anti-pattern is a SECOND policy engine):

  * It is NOT a parallel authorization decision point. The *source of truth* for "is this authorized?"
    remains the signed charter scope — supplied here as an ``in_scope`` predicate the caller derives from
    the EXISTING ``framework...host_matches_scope`` over the signed authority. This module only *classifies*
    (reads the scope + the asset store) and reports whether the class it resolved is an authorized one; the
    actual gate composition (:mod:`vigil_integration.sovereign_bridge`) still runs the real authority /
    WARDEN / sovereignty / entitlement legs. Classification can only ever ADD a denial (an UNKNOWN or an
    explicitly out-of-scope class), never invent an ALLOW the charter would not also grant.

  * It fails closed on every axis. An empty/unparseable target is ``UNKNOWN``. A target that is neither
    registered NOR in the charter scope is ``UNKNOWN``. ``UNKNOWN`` and every non-authorized class are
    refused by :func:`is_authorized`. There is no flag that turns classification off.

Two-env boundary (FATAL-2): this is a stdlib-only leaf (plus the sibling ``hard_guardrail.normalize_domain``,
itself stdlib-only), exactly like :mod:`vigil_core.gate`, so BOTH the offense and the sovereign process load
it without dragging ``framework`` / ``strix`` / ``sigil`` across the boundary.

Durability note (blocking_work): :class:`RegisteredAssetStore` is an in-memory store built from an explicit
list of registrations (e.g. hydrated from the signed charter's scope + a deployment's asset manifest). A
DURABLE, signed-and-hash-chained on-disk asset store is tracked as follow-up work; the classifier + the
UNKNOWN-deny decision over the existing scope gate — the safety-critical half — are implemented here now.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Optional

from .hard_guardrail import normalize_domain

__all__ = [
    "TargetClass",
    "DeploymentMode",
    "AUTHORIZED_CLASSES",
    "RegisteredAsset",
    "RegisteredAssetStore",
    "ClassificationResult",
    "normalize_target",
    "classify_target",
    "is_authorized",
]


class TargetClass(str, Enum):
    """What a target *is*, from most-contained to least. Ordering is documentation only — the authorization
    decision is set-membership in :data:`AUTHORIZED_CLASSES`, never an ordinal comparison."""

    LOOPBACK = "loopback"                            # 127.0.0.0/8, ::1, localhost — the operator's own box
    PRIVATE_NETWORK = "private_network"              # RFC1918 / ULA — the operator's own lab network
    OWN_INFRA = "own_infra"                          # in the signed charter scope (operator-owned)
    AUTHORIZED_THIRD_PARTY = "authorized_third_party"  # a third party the charter explicitly authorized
    PUBLIC_INTERNET = "public_internet"             # a public target NOT covered by the charter
    CRITICAL_INFRASTRUCTURE = "critical_infrastructure"  # explicitly flagged high-blast — never auto-run
    OUT_OF_SCOPE = "out_of_scope"                    # explicitly classified as forbidden
    UNKNOWN = "unknown"                              # unresolvable / never classified — NEVER authorized


class DeploymentMode(str, Enum):
    """Where VIGIL is running. This governs how authorization is *automated* (e.g. a LOCAL_LAB asset store
    makes owned targets fast) — it NEVER disables a gate. Enumerated so a deployment declares its mode
    explicitly instead of inferring it."""

    LOCAL_OFFLINE = "local_offline"    # air-gapped workstation; no egress at all
    LOCAL_LAB = "local_lab"            # operator's own lab/loopback; asset store automates owned targets
    STAGING = "staging"                # pre-production shared environment
    PRODUCTION = "production"          # production deployment; strictest posture
    REVIEWER = "reviewer"             # read-only review/audit deployment


# The ONLY classes that authorize. UNKNOWN, PUBLIC_INTERNET, CRITICAL_INFRASTRUCTURE and OUT_OF_SCOPE are
# deliberately NOT here: an unknown/public/critical/forbidden target is never *defaulted* to authorized.
# A frozenset so the predicate is one auditable membership test, not scattered conditionals.
AUTHORIZED_CLASSES: frozenset[TargetClass] = frozenset(
    {
        TargetClass.LOOPBACK,
        TargetClass.PRIVATE_NETWORK,
        TargetClass.OWN_INFRA,
        TargetClass.AUTHORIZED_THIRD_PARTY,
    }
)


def is_authorized(target_class: TargetClass) -> bool:
    """A class authorizes ONLY if it is an explicitly authorized class. Anything else — including
    ``UNKNOWN`` — is refused (fail-closed). This is the categorical half of the guardrail; the charter
    scope gate remains the source of truth for the concrete allow."""
    return target_class in AUTHORIZED_CLASSES


def normalize_target(target: object) -> str:
    """Normalize a target (URL or bare ``host[:port]``) to a canonical host key: the WHATWG host reading
    (via :func:`vigil_core.hard_guardrail.normalize_domain` — the same host extraction the categorical
    hard-guardrail uses), with IP literals canonicalized (``fe80:0:0:0:0:0:0:1`` and ``fe80::1`` collapse
    to one key). Returns ``""`` when no host can be extracted — which the classifier maps to ``UNKNOWN``."""
    if not isinstance(target, str):
        return ""
    host = normalize_domain(target)
    if not host:
        return ""
    try:
        return ipaddress.ip_address(host).compressed
    except ValueError:
        return host


@dataclass(frozen=True)
class RegisteredAsset:
    """One registered target: a normalized host key + the class it was registered as + an optional note.
    The store keys on ``normalized`` so ``https://Host:8080/x`` and ``host`` are the same asset."""

    normalized: str
    target_class: TargetClass
    note: str = ""


@dataclass(frozen=True)
class ClassificationResult:
    """The classifier's finding: the resolved class, whether it authorizes, the normalized key it resolved,
    and a human reason. ``authorized`` is derived from :func:`is_authorized` — never set independently."""

    target_class: TargetClass
    authorized: bool
    normalized: str
    reason: str


class RegisteredAssetStore:
    """An in-memory registry of classified assets, keyed by normalized target. Registration is the way a
    deployment *automates* authorization (a LOCAL_LAB registers its owned hosts once, and every later
    lookup is O(1)) — it does not bypass any gate: the classifier's verdict still flows into the existing
    gate composition, which runs the charter/WARDEN/sovereignty/entitlement legs unchanged.

    A registration with an unparseable target is refused (it could never be looked up, so silently
    dropping it would let a caller believe a target was registered when it was not — fail-closed)."""

    def __init__(self, assets: Optional[list[RegisteredAsset]] = None) -> None:
        self._by_host: dict[str, RegisteredAsset] = {}
        for asset in assets or []:
            self._put(asset)

    def _put(self, asset: RegisteredAsset) -> None:
        if not asset.normalized:
            raise ValueError("cannot register an asset with an empty normalized target (fail-closed)")
        self._by_host[asset.normalized] = asset

    def register(self, target: str, target_class: TargetClass, *, note: str = "") -> RegisteredAsset:
        """Register (or re-classify) a target. The target is normalized on the way in, so callers register
        with any form (URL / host / host:port) and lookups match regardless of form. An unparseable target
        is refused."""
        normalized = normalize_target(target)
        if not normalized:
            raise ValueError(f"cannot register an unparseable target {target!r} (fail-closed)")
        asset = RegisteredAsset(normalized=normalized, target_class=target_class, note=note)
        self._put(asset)
        return asset

    def lookup(self, target: str) -> Optional[RegisteredAsset]:
        """Return the registered asset for a target, or ``None`` if it was never registered. ``None`` is the
        signal the classifier uses to fall back to the charter scope — it is NEVER read as 'authorized'."""
        normalized = normalize_target(target)
        if not normalized:
            return None
        return self._by_host.get(normalized)

    def __len__(self) -> int:
        return len(self._by_host)

    def __contains__(self, target: object) -> bool:
        return isinstance(target, str) and self.lookup(target) is not None


def _network_class(normalized: str) -> TargetClass:
    """Classify an in-scope target by what network it is on. An IP literal is read structurally (loopback /
    RFC1918-or-ULA private / otherwise a public IP that the charter has nonetheless scoped in ⇒ own infra).
    ``localhost`` is loopback. A hostname the charter scoped in is own infra."""
    if normalized == "localhost":
        return TargetClass.LOOPBACK
    try:
        ip = ipaddress.ip_address(normalized)
    except ValueError:
        return TargetClass.OWN_INFRA  # a hostname the charter scoped in is operator-owned infrastructure
    if ip.is_loopback:
        return TargetClass.LOOPBACK
    if ip.is_private:
        return TargetClass.PRIVATE_NETWORK
    return TargetClass.OWN_INFRA  # a public IP the charter explicitly scoped in is owned/authorized


def classify_target(
    target: object,
    *,
    store: Optional[RegisteredAssetStore] = None,
    in_scope: Optional[Callable[[str], bool]] = None,
) -> ClassificationResult:
    """Resolve a target to a :class:`TargetClass`, fail-closed, in this order:

      1. Unparseable / empty target                       → ``UNKNOWN`` (denied).
      2. Explicitly registered in the asset store          → the REGISTERED class (this is how a caller
         records a forbidden target as ``OUT_OF_SCOPE`` or a high-blast one as
         ``CRITICAL_INFRASTRUCTURE`` — a registration can DENY as well as authorize).
      3. In the signed charter scope (``in_scope(host)``)  → a network-derived owned/authorized class.
      4. Otherwise                                          → ``UNKNOWN`` (denied — never defaulted in).

    The charter scope predicate (step 3) is the SOURCE OF TRUTH for the concrete allow; this function
    never re-decides scope — it calls the predicate the caller derived from the signed authority. The
    returned ``authorized`` is :func:`is_authorized` of the resolved class, so an UNKNOWN — or an
    explicitly out-of-scope / critical — target is refused."""
    normalized = normalize_target(target)
    if not normalized:
        return ClassificationResult(
            TargetClass.UNKNOWN, False, "",
            "target is empty or unparseable — cannot be classified (fail-closed)",
        )

    if store is not None:
        asset = store.lookup(normalized)
        if asset is not None:
            tc = asset.target_class
            return ClassificationResult(
                tc, is_authorized(tc), normalized,
                f"registered asset classified {tc.value!r}"
                + (f": {asset.note}" if asset.note else ""),
            )

    if in_scope is not None:
        try:
            scoped = bool(in_scope(normalized))
        except Exception as exc:  # noqa: BLE001 — a scope predicate that raises is a DENY, never a pass
            return ClassificationResult(
                TargetClass.UNKNOWN, False, normalized,
                f"charter scope check raised (fail-closed): {type(exc).__name__}: {exc}",
            )
        if scoped:
            tc = _network_class(normalized)
            return ClassificationResult(
                tc, is_authorized(tc), normalized,
                f"in charter scope; classified {tc.value!r}",
            )

    return ClassificationResult(
        TargetClass.UNKNOWN, False, normalized,
        "target is neither a registered asset nor in the charter scope — UNKNOWN is never authorized",
    )
