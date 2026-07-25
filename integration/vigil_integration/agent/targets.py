"""Canonical target extraction — the ONE helper that reads the declared target host/url from a tool's
args (audit G4). Shared by the proposal-triage path (``agent.react``), the authoritative gate
(``tools.governance``), and the executor's loopback pin (``live.executor``) so the three can never drift
on WHICH arg keys name the target — a per-path copy is exactly the "guard the whole class at one helper"
trap.

This returns the LLM's PROPOSAL. It is NOT the authority: the sovereign decision (scope / egress / the
m-of-n destruction bind) is made on the EXECUTOR-VALIDATED target — the getaddrinfo-resolved, signed-scope-
checked host (loopback-only when no scope is threaded) — not on this string. See
``live.executor._resolve_scoped_target`` and the ``resolved_target`` parameter of
``tools.governance.authorize_tool_call``.
"""
from __future__ import annotations

from typing import Any

# The arg keys, in priority order, that may name a tool's target. Kept here ONCE (was copied verbatim in
# three places). A new alias is added here and every path sees it.
TARGET_KEYS = ("target", "url", "target_url", "host", "domain")


def extract_target(tool_args: Any) -> str:
    """The declared target host/url from a tool-args dict, or ``""`` — the first non-empty string under
    the known keys. Total: a non-dict / all-missing / non-string value yields ``""``."""
    if not isinstance(tool_args, dict):
        return ""
    for k in TARGET_KEYS:
        v = tool_args.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""
