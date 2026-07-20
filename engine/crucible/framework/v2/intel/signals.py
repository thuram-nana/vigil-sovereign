"""
intel.signals — the evidence that two asset references are ONE asset.

Fellegi-Sunter style: each signal contributes a log-likelihood-ratio (in bits) toward
"same asset". Weights are data (tune without code change). The crucial nuance is
FANOUT: a certificate presented by 2 hosts is strong co-reference evidence; a wildcard
cert on 500 hosts, or a shared-hosting IP serving 500 domains, is weak — so a signal's
LLR is discounted by the fanout of the artifact that links the pair. That single rule
is what stops shared infrastructure from catastrophically merging unrelated assets.
"""

from __future__ import annotations

import enum
import math

from pydantic import BaseModel, ConfigDict, Field

from .refs import EntityRef


class SignalKind(str, enum.Enum):
    SHARED_CERT = "shared_cert"       # two refs present the same certificate
    PRESENTS_CERT = "presents_cert"   # a ref presents a certificate (member link)
    RESOLVES_TO = "resolves_to"       # a domain resolves to a host
    CNAME = "cname"                   # a domain is a CNAME alias of another
    SHARED_IP = "shared_ip"           # two domains resolve to the same host
    SAME_NETBLOCK = "same_netblock"   # two hosts in the same netblock


# base LLR (bits) at fanout 1 — the strength of each signal for a DEDICATED artifact.
_BASE_LLR_BITS: dict[SignalKind, float] = {
    SignalKind.CNAME: 7.0,
    SignalKind.SHARED_CERT: 6.0,
    SignalKind.PRESENTS_CERT: 4.5,
    SignalKind.RESOLVES_TO: 3.5,
    SignalKind.SHARED_IP: 2.5,
    SignalKind.SAME_NETBLOCK: 0.6,
}


def signal_llr(kind: SignalKind, *, fanout: int = 1) -> float:
    """The bits of evidence a signal contributes, discounted by the linking artifact's
    fanout: a cert/IP shared by ``fanout`` refs splits its weight by log2(fanout+1), so
    a dedicated artifact (fanout≈1) keeps full strength and a shared one (large fanout)
    collapses toward 0 — the anti-catastrophe rule."""
    base = _BASE_LLR_BITS.get(kind, 0.0)
    return base / (1.0 + math.log2(max(1, fanout)))


class SignalHit(BaseModel):
    """One piece of co-reference evidence between two asset refs, with its bits and the
    artifact that produced it — so every merge can cite exactly why it happened."""

    model_config = ConfigDict(extra="forbid")

    kind: SignalKind
    a: EntityRef
    b: EntityRef
    llr_bits: float = Field(ge=0.0)
    via: str = ""       # the linking artifact (cert fingerprint, ip, cname target)
    fanout: int = 1
