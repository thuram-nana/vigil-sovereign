"""
intel.refs — EntityRef, the pre-resolution atom the whole engine keys on.

An `EntityRef` names one asset by (kind, canonical key). Its `node_id` is EXACTLY the
world-model node id (`kind:key`), so an Observation projects onto the graph with no
translation layer. `canonicalize()` normalises raw strings so `API.Acme.COM`,
`api.acme.com.`, and the punycode form collapse to one ref — the precondition for
entity resolution to work at all.

The asset/owner tier split is the single most important correctness property: ASNs,
netblocks, and organisations are OWNERS that *link to* assets (via ASSET_OWNS); they
must never be merged INTO an asset cluster.
"""

from __future__ import annotations

import enum
import ipaddress
import re

from pydantic import BaseModel, ConfigDict, Field

from ..worldmodel.models import NodeKind


class ArtifactTier(str, enum.Enum):
    ASSET = "asset"    # a thing you attack (host/domain/cert/service/app/endpoint/webapp)
    OWNER = "owner"    # a thing that OWNS assets (asn/netblock/org/identity)


_ASSET_TIER = frozenset({
    NodeKind.HOST, NodeKind.SERVICE, NodeKind.DOMAIN, NodeKind.CERTIFICATE,
    NodeKind.APPLICATION, NodeKind.WEBAPP, NodeKind.ENDPOINT, NodeKind.PACKAGE,
})
_OWNER_TIER = frozenset({
    NodeKind.ASN, NodeKind.NETBLOCK, NodeKind.ORGANIZATION, NodeKind.IDENTITY,
})


class EntityRef(BaseModel):
    """A canonical (kind, key) reference. Frozen → hashable → usable as a dict key
    and in a union-find. ``key`` is assumed already canonical (via `canonicalize`)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: NodeKind
    key: str = Field(min_length=1)

    @property
    def node_id(self) -> str:
        """The world-model node id this ref projects onto — no translation."""
        return f"{self.kind.value}:{self.key}"

    @property
    def tier(self) -> ArtifactTier:
        return ArtifactTier.OWNER if self.kind in _OWNER_TIER else ArtifactTier.ASSET

    @property
    def is_asset_tier(self) -> bool:
        return self.kind in _ASSET_TIER


_AS_RE = re.compile(r"^\s*as[n]?\s*[:#]?\s*(\d+)\s*$", re.IGNORECASE)
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def canonicalize(kind: NodeKind, raw: str) -> EntityRef:
    """Normalise a raw value into a canonical EntityRef. Deterministic + total: an
    unparseable value falls back to a trimmed/lowercased key rather than raising, so a
    collector's messy output never crashes ingestion."""
    s = (raw or "").strip()
    if kind is NodeKind.DOMAIN:
        key = s.rstrip(".").lower()
        try:
            key = key.encode("idna").decode("ascii")  # punycode fold
        except Exception:
            pass
        return EntityRef(kind=kind, key=key or s.lower())
    if kind is NodeKind.HOST:
        try:
            return EntityRef(kind=kind, key=str(ipaddress.ip_address(s)))  # canonical IP
        except ValueError:
            return EntityRef(kind=kind, key=s.rstrip(".").lower())          # hostname
    if kind is NodeKind.NETBLOCK:
        try:
            return EntityRef(kind=kind, key=str(ipaddress.ip_network(s, strict=False)))
        except ValueError:
            return EntityRef(kind=kind, key=s.lower())
    if kind is NodeKind.ASN:
        m = _AS_RE.match(s)
        return EntityRef(kind=kind, key=f"AS{m.group(1)}" if m else s.upper())
    if kind is NodeKind.CERTIFICATE:
        low = s.lower().replace(":", "").replace(" ", "")
        return EntityRef(kind=kind, key=low if _SHA256_RE.match(low) else low)
    if kind is NodeKind.SERVICE:
        return EntityRef(kind=kind, key=s.lower())  # host:port/proto
    if kind is NodeKind.VULNERABILITY:
        # advisory ids (CVE-…, GHSA-…, OSV-…) are conventionally upper-cased; fold to one form so
        # the same CVE from two feeds collapses to one node.
        return EntityRef(kind=kind, key=s.upper() if s else "?")
    if kind is NodeKind.INDICATOR:
        # an atomic IOC carried as "<type>:<value>" (e.g. "sha256:ab…"); hashes/values are lower-cased.
        return EntityRef(kind=kind, key=s.lower() if s else "?")
    return EntityRef(kind=kind, key=s.lower() if s else "?")
