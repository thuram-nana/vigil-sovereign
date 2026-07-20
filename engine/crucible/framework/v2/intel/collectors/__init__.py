"""
intel.collectors — passive recon sources, each a pure Observation factory.

A collector answers exactly one question about one subject ("what does DNS say
about api.company.com?", "what certs has this domain logged?") by asking its
injected `Transport` for a `RawRecord` and parsing it into `Observation`s — the
one currency that enters the engine. Collectors NEVER talk to the network
directly, never write to the graph or the store (that is `IntelIngest`'s single-
writer job), and never exploit. They are transport-injected so the whole suite
runs offline against fixtures, deterministically.

Every collector also carries planner metadata (`tpr`/`fpr`/`cost`) so the
`ReconPlanner` can value it by expected information gain, and an `enumerative`
flag so temporal reasoning knows whether the source's silence about an asset is
meaningful (a complete-list source like CT) or not (a point query like a single
DNS lookup).

All four bundled collectors are passive: DNS, Certificate Transparency, RDAP/WHOIS,
and ASN/BGP. None of them touch the target — they query third-party registries and
logs about it.
"""

from .base import Collector, DEFAULT_COLLECTORS, collector_for_subject
from .dns import DnsCollector
from .cert_transparency import CertTransparencyCollector
from .rdap import RdapCollector
from .asn_bgp import AsnBgpCollector

__all__ = [
    "Collector", "DEFAULT_COLLECTORS", "collector_for_subject",
    "DnsCollector", "CertTransparencyCollector", "RdapCollector", "AsnBgpCollector",
]
