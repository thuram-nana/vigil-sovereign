"""FLIP FIXTURE (never imported): a MODULE-LEVEL PEP 562 lazy re-export of an offense symbol.

``OOBReceiver`` is re-exported by ``framework.v2.verify``'s ``__getattr__`` from the deny-listed
``verify.oob`` submodule, so importing it AT MODULE SCOPE is a real import-time edge to ``verify.oob``.
A SOUND analyzer must follow the shim and flag ``framework.v2.verify.oob`` as denied-reachable.
"""
from __future__ import annotations

from framework.v2.verify import OOBReceiver  # noqa: F401  (PEP 562 lazy -> framework.v2.verify.oob)
