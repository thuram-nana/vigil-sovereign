"""
repeater — a GATED intercepting repeater for AUTHORIZED web testing (Wave 4.D).

The Burp-Repeater equivalent, framed DEFENSIVELY: capture a base HTTP request to an in-scope
target, edit it, and REPLAY it — but never through a raw socket. Every replay is routed through
the existing fail-closed gate chain (``agents.tools.invoke_tool`` -> ``HttpRepeaterTool`` ->
``agents.http_executor.HttpExecutor.gated_fetch``), so it is:

  * ENTITLEMENT-GATED (Tier-2): a replay requires the offensive-tier ``EXPLOIT_EXECUTION`` grant.
  * SCOPE-GATED: the target is charter-scope-validated at BOTH the invoker and the executor; an
    out-of-scope target is refused and NOTHING is sent.
  * FAIL-CLOSED: a tripped kill-switch, a missing entitlement, an out-of-scope target, or a
    declined destructive-confirm refuses the replay — and every refusal is recorded as evidence.
  * CORRELATABLE, NOT EVASIVE: the executor's recognizable OBSIDIAN User-Agent is forced (any
    operator-supplied UA is stripped); no identity rotation, no proxy-chaining, no stealth.
  * PROVE-DON'T-GUESS: a captured response is a provenance-labelled OBSERVATION, never a fact —
    it becomes a finding only when a deterministic oracle re-verifies it
    (``RepeaterExchange.oracle_context_with``).

This package is OFF the scanner-benchmark path and imported by nothing in the default engage/scan
flow — it is an opt-in operator/engine capability.

Public surface:

    from framework.v2.repeater import (
        Repeater, RepeaterRequest, RepeaterExchange, mutate,
        HttpRepeaterTool, build_repeater_registry,
    )
"""

from __future__ import annotations

from .models import RepeaterExchange, RepeaterRequest, mutate, normalize_headers
from .repeater import Repeater, build_repeater_registry
from .tool import HttpRepeaterTool, base_url_of

__all__ = [
    "Repeater",
    "RepeaterRequest",
    "RepeaterExchange",
    "mutate",
    "normalize_headers",
    "HttpRepeaterTool",
    "base_url_of",
    "build_repeater_registry",
]
