"""sigil.inbound — the sovereign-side ingest of data crossing INTO the personal core.

The only thing that crosses from the offense side is an inert, signed finding (P10). This package
imports NO offense-engine module (``framework.*`` / ``strix.*``) — it treats an incoming finding as
opaque signed DATA, verified with the shared integrity core alone."""

from .finding_receiver import FindingReceiver, ingest_finding

__all__ = ["FindingReceiver", "ingest_finding"]
