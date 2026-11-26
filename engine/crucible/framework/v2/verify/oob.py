"""
verify.oob — the offense engine's view of the out-of-band interaction receiver.

AS-28 (closure + image, D34) relocated the receiver PRIMITIVE out of this (deny-listed) offense submodule
into the offense-free shared layer, ``framework.v2.common.oob_receiver``, so the AEGIS DEFENSIVE gateway's
passive OOB canary correlator can use it WITHOUT the defense serve path importing anything under the denied
``verify.*`` offense namespace (plan §1 defect #9 — "offense code in the defense runtime").

This module is now a THIN RE-EXPORT: the public surface and behaviour are byte-for-byte unchanged, so every
offense call site keeps ``from framework.v2.verify.oob import OOBReceiver, OOBHit, sign_oob_receipt,
verify_oob_receipt`` exactly as before, and ``framework.v2.verify``'s lazy ``__getattr__`` re-export still
resolves these names here. ``verify.oob`` STAYS on the AEGIS deny list (it is the offense engine's binding to
the primitive); the NEUTRAL primitive lives in ``common`` and is what the defense imports.

See ``framework/v2/common/oob_receiver.py`` for the implementation and the loopback-only hard constraints.
"""

from __future__ import annotations

from ..common.oob_receiver import (  # noqa: F401  (re-export; the underscore names preserve full compat)
    _OOB_RECEIPT_DOMAIN,
    _OOBHTTPServer,
    _OOBRequestHandler,
    _receipt_core,
    _receipt_signing_bytes,
    _token_of,
    OOBHit,
    OOBReceiver,
    sign_oob_receipt,
    verify_oob_receipt,
)

__all__ = [
    "OOBHit",
    "OOBReceiver",
    "sign_oob_receipt",
    "verify_oob_receipt",
]
