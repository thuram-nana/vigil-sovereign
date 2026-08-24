"""vigil_core.hopauth — the ONE construction of the proxy→offense per-request role assertion.

The `vigil up` reverse proxy is the per-user authentication boundary: it resolves the caller against
the sovereign owner-signed accounts spine and then STAMPS the resolved identity (`X-VIGIL-Principal` /
`X-VIGIL-Role`) on the loopback hop to an offense backend. Because the offense session TOKEN is SHARED
between the proxy and the backend, token-presence alone cannot distinguish a genuine proxy hop from a
direct loopback client that also holds the token — so the proxy binds the stamped identity under a
DISTINCT per-run hop secret (`VIGIL_CONSOLE_HOP_KEY`, random per `vigil up`, handed to the offense
child at spawn, never to the browser). Only a request carrying a VALID, FRESH HMAC over EXACTLY
``principal\\nrole\\nmethod\\npath\\nts`` under that key has its stamped ``X-VIGIL-Role`` trusted for
per-action RBAC.

This module is the SINGLE definition of that message + MAC so the STAMP side (the proxy, integration/)
and BOTH VERIFY sides (the offense console AND the offense gated api, framework/) cannot drift: a header
set one side signs is exactly what the other checks. It is namespace-pure (pure stdlib — ``hmac`` /
``hashlib`` / ``base64`` / ``time``, no crypto/spine/framework/strix/sigil), so it can be imported from
either trust domain without dragging a dependency across the boundary — the same load-bearing property
``vigil_core.rbac`` has.

FAIL-CLOSED: no hop key (nothing to verify with), an incomplete assertion, a non-numeric/stale ``ts``, or
a mismatching MAC all make :func:`verify_hop_assertion` return False. Binding the METHOD and the
backend-side PATH stops a captured header set from being re-aimed at another verb/route; binding ``ts``
(with the freshness window) stops replay.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import time
from typing import Optional

# A stamped assertion older/newer than this many seconds is refused (the replay window is closed). This
# is the window BOTH the proxy's clock and the backend's clock must agree within — the console has always
# used 30 s and the api adopts the same value from here so the two verify sites never diverge.
DEFAULT_HOP_MAX_SKEW_S = 30.0


def hop_message(principal: str, role: str, method: str, path: str, ts: str) -> bytes:
    """The EXACT bytes signed/verified: ``principal\\nrole\\nmethod\\npath\\nts`` (UTF-8). ``ts`` is a
    STRING (the proxy stamps ``str(int(time.time()))``) and is signed verbatim, so verification recomputes
    the MAC over the same string the stamp used — no float re-formatting can desync the two sides."""
    return f"{principal}\n{role}\n{method}\n{path}\n{ts}".encode("utf-8")


def stamp_hop_assertion(hop_key: str, principal: str, role: str, method: str, path: str, ts: str) -> str:
    """The base64 HMAC-SHA256 signature the proxy stamps as ``X-VIGIL-Role-Sig`` (with ``ts`` as
    ``X-VIGIL-Role-Ts``). The caller supplies ``ts`` (so it appears identically in the header and the MAC).
    Requires a non-empty ``hop_key`` — a blank key means "no role assertion is stamped" (the caller must
    not call this), never a signature under an empty secret."""
    return base64.b64encode(
        hmac.new(hop_key.encode("utf-8"), hop_message(principal, role, method, path, ts),
                 hashlib.sha256).digest()).decode("ascii")


def verify_hop_assertion(hop_key: str, principal: str, role: str, method: str, path: str, ts: str,
                         sig: str, *, now: Optional[float] = None,
                         max_skew_s: float = DEFAULT_HOP_MAX_SKEW_S) -> bool:
    """Constant-time verification of a stamped role assertion. Returns True iff a non-empty ``hop_key`` is
    configured AND the assertion is complete (role, ts, sig all present) AND ``ts`` is numeric and within
    ``max_skew_s`` of ``now`` (default: the wall clock) AND the recomputed HMAC equals ``sig``.

    Fail-closed at every branch: a blank hop key (nothing to verify with), a missing field, a
    non-numeric/stale ``ts``, or a mismatching MAC each return False. This is the SAME predicate the
    offense console has always used — lifted here verbatim so the offense api verifies byte-identically."""
    if not (hop_key and role and ts and sig):
        return False
    try:
        ts_f = float(ts)
    except (TypeError, ValueError):
        return False
    reference = time.time() if now is None else now
    if abs(reference - ts_f) > max_skew_s:
        return False
    expected = stamp_hop_assertion(hop_key, principal, role, method, path, ts)
    return hmac.compare_digest(expected, sig)
