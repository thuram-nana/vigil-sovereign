"""
api — the LOOPBACK-ONLY, GATED external API / daemon (Wave 6 platformization).

A programmatic seam over CRUCIBLE for an operator to drive/observe it: enumerate
engagements, read the world-model / findings / governance state (READ-first, the safe
core), and trigger GATED actions — every action through the SAME fail-closed
authority/entitlement/scope/egress chain as a local action (``agents.tools.invoke_tool``).

It EXTENDS the Ops Console's security posture (loopback-only, default-safe, same-origin
POST guard), never a riskier new server. It is DEFAULT-SAFE: nothing runs unless the
operator starts it (``python3 -m framework.v2 api``), it binds loopback only, and it
exposes NO ungated capability.

Public surface:

    from framework.v2.api import serve            # create the loopback server (does not block)
    from framework.v2.api import actions, reads    # the gated action + read providers
"""

from __future__ import annotations

from .server import serve

__all__ = ["serve"]
