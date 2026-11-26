"""FLIP FIXTURE (never imported): a FUNCTION-LOCAL symbol import from an OPAQUE PEP 562 shim.

``framework.v2.tools`` defines a module-level ``__getattr__`` but NO statically-readable ``_LAZY_SYMBOLS`` /
``_SUBMODULES`` map, so the analyzer cannot prove which submodule (if any) ``AnyOpaqueSymbol`` pulls — it
could be a denied one. The overlay must therefore FAIL CLOSED on this symbol form (same posture as the
module-level walk, which enqueues the unresolvable candidate), not wave it through.
"""
from __future__ import annotations


def _enable() -> object:
    from framework.v2.tools import AnyOpaqueSymbol  # opaque shim -> cannot prove not denied -> fail closed

    return AnyOpaqueSymbol
