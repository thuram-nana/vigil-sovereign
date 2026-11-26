"""FLIP FIXTURE (never imported): a FUNCTION-LOCAL PEP 562 SYMBOL offense import in an AEGIS serving module.

``from framework.v2.verify import OOBReceiver`` inside a ``def`` loads the deny-listed ``verify.oob`` at
SERVE time: ``verify/__init__``'s ``__getattr__`` + ``_LAZY_SYMBOLS`` resolve ``OOBReceiver`` to the ``oob``
submodule on first access. A literal ``is_denied("framework.v2.verify")`` is clean (the package itself is
not denied), so the overlay must apply the SAME PEP 562 shim resolution the module-level walk uses —
``OOBReceiver`` -> ``verify.oob`` — before the deny check, or this symbol form evades the gate.
"""
from __future__ import annotations


def _enable_oob() -> object:
    from framework.v2.verify import OOBReceiver  # PEP 562 lazy -> deny-listed framework.v2.verify.oob

    return OOBReceiver()
