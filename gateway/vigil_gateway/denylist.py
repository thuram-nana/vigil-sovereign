"""
denylist — backward-compatible re-export of the shared egress denylist primitive.

The classification logic used to live here; it now lives in ``vigil_core.egress_denylist`` — the
shared substrate present in EVERY environment — so the engine's own egress floor
(``framework.v2.common.egress_pin``) can re-use the SAME primitive without depending on this
offense-side gateway package (the "CRUCIBLE core on vigil_core" CI leg installs vigil_core but
NOT the gateway). SINGLE SOURCE: the ranges and ``is_egress_denied`` / ``is_hard_denied`` logic
live ONLY in ``vigil_core.egress_denylist``; this module re-exports them verbatim and never
duplicates them, so ``vigil_gateway.denylist.<name>`` keeps resolving for every caller
(nftables renderer, forward proxy, integration re-drive paths, tests) unchanged.

The re-export is EXPLICIT for every public AND private name any caller references (``import *``
would skip the underscore-prefixed helpers/constants), so attribute access such as
``denylist._coerce_allowed`` or ``denylist._HOST_BACKSTOP_V4`` continues to work.
"""

from __future__ import annotations

from vigil_core import egress_denylist as _src

# --- public API (single source: vigil_core.egress_denylist) ---------------------------------------
hard_deny_cidrs = _src.hard_deny_cidrs
host_backstop_cidrs = _src.host_backstop_cidrs
private_cidrs = _src.private_cidrs
is_egress_denied = _src.is_egress_denied
is_hard_denied = _src.is_hard_denied

# --- private helpers referenced by attribute elsewhere in the tree / kept for compatibility -------
_coerce_allowed = _src._coerce_allowed
_embedded_ipv4 = _src._embedded_ipv4
_candidates = _src._candidates
_in_any = _src._in_any

# --- module-level range constants (kept re-exported so any ``denylist.<CONST>`` reference resolves)
_ALWAYS_DENY_V4 = _src._ALWAYS_DENY_V4
_ALWAYS_DENY_V6 = _src._ALWAYS_DENY_V6
_PRIVATE_V4 = _src._PRIVATE_V4
_PRIVATE_V6 = _src._PRIVATE_V6
_ALWAYS_DENY_NETS = _src._ALWAYS_DENY_NETS
_PRIVATE_NETS = _src._PRIVATE_NETS
_LOOPBACK_NETS = _src._LOOPBACK_NETS
_ALWAYS_DENY_NONLOOPBACK_NETS = _src._ALWAYS_DENY_NONLOOPBACK_NETS
_NAT64 = _src._NAT64
_NAT64_LOCAL = _src._NAT64_LOCAL
_IPV4_COMPAT = _src._IPV4_COMPAT
_V6_UNSPEC = _src._V6_UNSPEC
_V6_LOOPBACK = _src._V6_LOOPBACK
_HOST_BACKSTOP_V4 = _src._HOST_BACKSTOP_V4
_HOST_BACKSTOP_V6 = _src._HOST_BACKSTOP_V6

__all__ = [
    "hard_deny_cidrs",
    "host_backstop_cidrs",
    "private_cidrs",
    "is_egress_denied",
    "is_hard_denied",
]
